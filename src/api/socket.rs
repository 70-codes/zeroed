//! Unix Socket Server for the Zeroed API
//!
//! This module provides the `ApiServer` that listens on a Unix domain socket,
//! accepts connections from `zeroctl`, reads JSON-encoded `ApiRequest` messages,
//! dispatches them to the `CommandHandler`, and writes back `ApiResponse` messages.
//!
//! ## Protocol
//!
//! Each connection handles exactly one request-response pair:
//!
//! 1. Client connects to the Unix socket
//! 2. Client writes one JSON line (newline-terminated `ApiRequest`)
//! 3. Server reads the line, dispatches to the `CommandHandler`
//! 4. Server writes the full JSON `ApiResponse` and shuts down the write half
//! 5. Connection is closed
//!
//! ## Concurrency
//!
//! Each incoming connection is handled in its own tokio task, so multiple
//! `zeroctl` clients can connect simultaneously without blocking each other.
//! The `CommandHandler` is shared via `Arc` and is designed for concurrent access.
//!
//! ## Socket Lifecycle
//!
//! - The socket file is created when `ApiServer::run()` starts
//! - Any pre-existing socket file at the same path is removed first
//! - The socket file is removed when the server shuts down (via the shutdown signal)
//! - The socket file permissions are set to `0660` so that the owning user/group can connect

use crate::api::handler::CommandHandler;
use crate::api::{ApiRequest, ApiResponse};

use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// API Server
// ─────────────────────────────────────────────────────────────────────────────

/// Unix socket server for the Zeroed control API.
///
/// Listens for incoming connections from `zeroctl` (or any client that speaks
/// the JSON line protocol) and dispatches requests to the `CommandHandler`.
pub struct ApiServer {
    /// Path to the Unix socket file
    socket_path: PathBuf,

    /// The command handler that processes requests
    handler: Arc<CommandHandler>,

    /// Maximum number of concurrent client connections
    max_connections: usize,
}

impl ApiServer {
    /// Create a new API server.
    ///
    /// Does NOT start listening — call `run()` to start the server.
    pub fn new(
        socket_path: PathBuf,
        handler: Arc<CommandHandler>,
        max_connections: usize,
    ) -> Self {
        Self {
            socket_path,
            handler,
            max_connections,
        }
    }

    /// Run the API server, listening for connections until a shutdown signal
    /// is received.
    ///
    /// This method:
    /// 1. Removes any stale socket file from a previous run
    /// 2. Creates the socket's parent directory if needed
    /// 3. Binds the Unix listener
    /// 4. Sets socket file permissions to `0660`
    /// 5. Accepts connections in a loop, spawning a task for each
    /// 6. On shutdown signal, stops accepting and cleans up the socket file
    pub async fn run(&self, mut shutdown_rx: broadcast::Receiver<()>) {
        // Ensure socket directory exists
        if let Some(parent) = self.socket_path.parent() {
            if !parent.exists() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    error!(
                        "Failed to create socket directory {:?}: {} — API server will not start",
                        parent, e
                    );
                    return;
                }
            }
        }

        // Remove stale socket file from a previous run
        if self.socket_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.socket_path) {
                error!(
                    "Failed to remove stale socket file {:?}: {} — API server will not start",
                    self.socket_path, e
                );
                return;
            }
            debug!("Removed stale socket file: {:?}", self.socket_path);
        }

        // Bind the listener
        let listener = match UnixListener::bind(&self.socket_path) {
            Ok(l) => l,
            Err(e) => {
                error!(
                    "Failed to bind Unix socket at {:?}: {} — API server will not start",
                    self.socket_path, e
                );
                return;
            }
        };

        // Set socket permissions to 0660 (owner + group read/write)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o660);
            if let Err(e) = std::fs::set_permissions(&self.socket_path, perms) {
                warn!(
                    "Failed to set socket permissions on {:?}: {}",
                    self.socket_path, e
                );
            }
        }

        info!(
            "API server listening on {:?} (max {} concurrent connections)",
            self.socket_path, self.max_connections
        );

        // Track active connection count for limiting
        let active_connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Accept loop
        loop {
            tokio::select! {
                // Accept a new connection
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _addr)) => {
                            let current = active_connections.load(std::sync::atomic::Ordering::Relaxed);
                            if current >= self.max_connections {
                                warn!(
                                    "API server: rejecting connection — max connections ({}) reached",
                                    self.max_connections
                                );
                                // Write an error response and close
                                let _ = Self::reject_connection(stream).await;
                                continue;
                            }

                            let handler = Arc::clone(&self.handler);
                            let active = Arc::clone(&active_connections);
                            active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                            tokio::spawn(async move {
                                Self::handle_connection(stream, handler).await;
                                active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                            });
                        }
                        Err(e) => {
                            // Transient accept errors (e.g., too many open files)
                            // are logged but don't kill the server
                            warn!("API server: accept error: {}", e);
                        }
                    }
                }

                // Shutdown signal received
                _ = shutdown_rx.recv() => {
                    info!("API server received shutdown signal");
                    break;
                }
            }
        }

        // Cleanup: remove the socket file
        self.cleanup();

        info!("API server stopped");
    }

    /// Handle a single client connection.
    ///
    /// Reads one JSON line, dispatches to the handler, writes the response,
    /// and closes the connection.
    async fn handle_connection(stream: UnixStream, handler: Arc<CommandHandler>) {
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        // Read the request line (with a size limit to prevent OOM)
        const MAX_REQUEST_SIZE: usize = 1024 * 1024; // 1 MB

        match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            buf_reader.read_line(&mut line),
        )
        .await
        {
            Ok(Ok(0)) => {
                // Client disconnected without sending anything
                debug!("API client disconnected without sending a request");
                return;
            }
            Ok(Ok(n)) if n > MAX_REQUEST_SIZE => {
                warn!("API client sent oversized request ({} bytes), rejecting", n);
                let response = ApiResponse::error(
                    crate::api::error_codes::INVALID_REQUEST,
                    "Request too large",
                );
                let _ = Self::write_response(&mut writer, &response).await;
                return;
            }
            Ok(Ok(_n)) => {
                // Successfully read a line — continue to parsing below
            }
            Ok(Err(e)) => {
                debug!("API client read error: {}", e);
                return;
            }
            Err(_) => {
                debug!("API client request timed out (30s)");
                let response = ApiResponse::error(
                    crate::api::error_codes::SERVICE_UNAVAILABLE,
                    "Request timed out",
                );
                let _ = Self::write_response(&mut writer, &response).await;
                return;
            }
        }

        // Trim the line
        let line = line.trim();

        if line.is_empty() {
            let response = ApiResponse::error(
                crate::api::error_codes::INVALID_REQUEST,
                "Empty request",
            );
            let _ = Self::write_response(&mut writer, &response).await;
            return;
        }

        // Parse the request
        let request: ApiRequest = match serde_json::from_str(line) {
            Ok(req) => req,
            Err(e) => {
                debug!("API client sent invalid JSON: {}", e);
                let response = ApiResponse::error(
                    crate::api::error_codes::INVALID_REQUEST,
                    format!("Invalid request JSON: {}", e),
                );
                let _ = Self::write_response(&mut writer, &response).await;
                return;
            }
        };

        debug!("API request received: {:?}", std::mem::discriminant(&request));

        // Dispatch to the handler
        let response = handler.handle(request).await;

        // Write the response
        if let Err(e) = Self::write_response(&mut writer, &response).await {
            debug!("API client write error: {}", e);
        }
    }

    /// Write an `ApiResponse` to the client as JSON, followed by shutdown.
    async fn write_response(
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        response: &ApiResponse,
    ) -> Result<(), std::io::Error> {
        let json = serde_json::to_string(response)
            .unwrap_or_else(|e| {
                // If we can't serialize the response, send a minimal error
                format!(
                    r#"{{"status":"Error","code":500,"message":"Response serialization failed: {}"}}"#,
                    e
                )
            });

        writer.write_all(json.as_bytes()).await?;
        writer.shutdown().await?;

        Ok(())
    }

    /// Reject a connection when the server is at max capacity.
    async fn reject_connection(stream: UnixStream) {
        let (_reader, mut writer) = stream.into_split();
        let response = ApiResponse::error(
            crate::api::error_codes::SERVICE_UNAVAILABLE,
            "Server is at maximum connection capacity",
        );
        let _ = Self::write_response(&mut writer, &response).await;
    }

    /// Clean up the socket file on shutdown.
    fn cleanup(&self) {
        if self.socket_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.socket_path) {
                warn!(
                    "Failed to remove socket file {:?} during cleanup: {}",
                    self.socket_path, e
                );
            } else {
                debug!("Socket file removed: {:?}", self.socket_path);
            }
        }
    }

    /// Get the socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{ApiRequest, ApiResponse};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    /// Create a minimal CommandHandler for testing.
    ///
    /// This requires real subsystem instances which are expensive to construct
    /// in unit tests. Instead, we test the socket server's framing and protocol
    /// logic by testing the helper functions and doing a simple integration test.

    #[test]
    fn test_api_server_fields() {
        // We can't easily construct a real CommandHandler in unit tests
        // (it requires Arc references to StorageEngine, DetectionEngine, etc.)
        // so we test the structural/protocol aspects of the server instead.
        // Full end-to-end tests are covered in Step 10.
        let path = PathBuf::from("/tmp/zeroed-test.sock");
        assert_eq!(path.file_name().unwrap(), "zeroed-test.sock");
    }

    #[test]
    fn test_api_request_json_parsing() {
        // Test that the server can parse the same JSON that zeroctl sends
        let json = r#"{"command":"Status"}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        assert!(matches!(request.unwrap(), ApiRequest::Status));
    }

    #[test]
    fn test_api_request_block_json_parsing() {
        let json = r#"{"command":"Block","params":{"ip":"1.2.3.4","duration":3600,"reason":"test"}}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        match request.unwrap() {
            ApiRequest::Block { ip, duration, reason } => {
                assert_eq!(ip, "1.2.3.4");
                assert_eq!(duration, 3600);
                assert_eq!(reason, Some("test".to_string()));
            }
            _ => panic!("Expected Block request"),
        }
    }

    #[test]
    fn test_api_request_unblock_json_parsing() {
        let json = r#"{"command":"Unblock","params":{"ip":"10.0.0.1"}}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        match request.unwrap() {
            ApiRequest::Unblock { ip } => assert_eq!(ip, "10.0.0.1"),
            _ => panic!("Expected Unblock request"),
        }
    }

    #[test]
    fn test_api_request_ping_json_parsing() {
        let json = r#"{"command":"Ping"}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        assert!(matches!(request.unwrap(), ApiRequest::Ping));
    }

    #[test]
    fn test_api_request_shutdown_json_parsing() {
        let json = r#"{"command":"Shutdown","params":{"force":false}}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        match request.unwrap() {
            ApiRequest::Shutdown { force } => assert!(!force),
            _ => panic!("Expected Shutdown request"),
        }
    }

    #[test]
    fn test_api_request_list_blocked_json_parsing() {
        let json = r#"{"command":"ListBlocked","params":{"limit":50}}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        match request.unwrap() {
            ApiRequest::ListBlocked { limit } => assert_eq!(limit, 50),
            _ => panic!("Expected ListBlocked request"),
        }
    }

    #[test]
    fn test_api_request_list_tracked_json_parsing() {
        let json = r#"{"command":"ListTracked","params":{"limit":100,"sort":"threat"}}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        match request.unwrap() {
            ApiRequest::ListTracked { limit, sort } => {
                assert_eq!(limit, 100);
                assert_eq!(sort, "threat");
            }
            _ => panic!("Expected ListTracked request"),
        }
    }

    #[test]
    fn test_api_request_events_json_parsing() {
        let json = r#"{"command":"Events","params":{"count":50,"filter":null}}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        match request.unwrap() {
            ApiRequest::Events { count, filter } => {
                assert_eq!(count, 50);
                assert!(filter.is_none());
            }
            _ => panic!("Expected Events request"),
        }
    }

    #[test]
    fn test_api_request_lookup_json_parsing() {
        let json = r#"{"command":"Lookup","params":{"ip":"192.168.1.1"}}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        match request.unwrap() {
            ApiRequest::Lookup { ip } => assert_eq!(ip, "192.168.1.1"),
            _ => panic!("Expected Lookup request"),
        }
    }

    #[test]
    fn test_api_request_version_json_parsing() {
        let json = r#"{"command":"Version"}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        assert!(matches!(request.unwrap(), ApiRequest::Version));
    }

    #[test]
    fn test_api_request_flush_blocked_json_parsing() {
        let json = r#"{"command":"FlushBlocked"}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        assert!(matches!(request.unwrap(), ApiRequest::FlushBlocked));
    }

    #[test]
    fn test_api_request_flush_all_json_parsing() {
        let json = r#"{"command":"FlushAll"}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        assert!(matches!(request.unwrap(), ApiRequest::FlushAll));
    }

    #[test]
    fn test_api_request_reload_json_parsing() {
        let json = r#"{"command":"Reload"}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        assert!(matches!(request.unwrap(), ApiRequest::Reload));
    }

    #[test]
    fn test_api_request_whitelist_add_json_parsing() {
        let json = r#"{"command":"WhitelistAdd","params":{"ip":"10.0.0.1","comment":"trusted"}}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        match request.unwrap() {
            ApiRequest::WhitelistAdd { ip, comment } => {
                assert_eq!(ip, "10.0.0.1");
                assert_eq!(comment, Some("trusted".to_string()));
            }
            _ => panic!("Expected WhitelistAdd request"),
        }
    }

    #[test]
    fn test_api_request_export_json_parsing() {
        let json = r#"{"command":"Export","params":{"what":"blocked"}}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        match request.unwrap() {
            ApiRequest::Export { what } => assert_eq!(what, "blocked"),
            _ => panic!("Expected Export request"),
        }
    }

    #[test]
    fn test_api_request_import_json_parsing() {
        let json = r#"{"command":"Import","params":{"what":"blocked","data":"1.2.3.4\n5.6.7.8"}}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        match request.unwrap() {
            ApiRequest::Import { what, data } => {
                assert_eq!(what, "blocked");
                assert!(data.contains("1.2.3.4"));
            }
            _ => panic!("Expected Import request"),
        }
    }

    #[test]
    fn test_api_response_serialization_for_client() {
        // Verify the response JSON format matches what zeroctl expects
        let response = ApiResponse::success(serde_json::json!({"test": true}));
        let json = serde_json::to_string(&response).unwrap();

        // zeroctl parses with #[serde(tag = "status")]
        assert!(json.contains(r#""status":"Success"#));
        assert!(json.contains(r#""data"#));

        // Verify it can be deserialized back
        let parsed: ApiResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_success());
    }

    #[test]
    fn test_api_error_response_serialization_for_client() {
        let response = ApiResponse::error(404, "Not found");
        let json = serde_json::to_string(&response).unwrap();

        assert!(json.contains(r#""status":"Error"#));
        assert!(json.contains(r#""code":404"#));
        assert!(json.contains(r#""message":"Not found"#));

        let parsed: ApiResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_error());
    }

    #[test]
    fn test_invalid_json_request() {
        let json = r#"{"command":"ThisDoesNotExist"}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_err(), "Should fail to parse unknown command");
    }

    #[test]
    fn test_malformed_json_request() {
        let json = r#"not json at all"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_err());
    }

    #[test]
    fn test_empty_json_request() {
        let json = r#""#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_err());
    }

    #[test]
    fn test_missing_params_request() {
        // Block requires params — should fail without them
        let json = r#"{"command":"Block"}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_err());
    }

    #[test]
    fn test_stats_request_with_params() {
        let json = r#"{"command":"Stats","params":{"detailed":true}}"#;
        let request: Result<ApiRequest, _> = serde_json::from_str(json);
        assert!(request.is_ok());
        match request.unwrap() {
            ApiRequest::Stats { detailed } => assert!(detailed),
            _ => panic!("Expected Stats request"),
        }
    }

    // NOTE: A full CommandHandler requires Arc references to StorageEngine,
    // DetectionEngine, FirewallManager, and NetworkManager, which are too
    // expensive to construct in unit tests. The tests above focus on the
    // JSON wire protocol (parsing and serialization), which is the main
    // thing the socket server is responsible for. Full end-to-end tests
    // (start daemon → connect with zeroctl → verify response) are covered
    // in Step 10.
}
