//! GeoIP module for geographic source identification
//!
//! This module provides functionality for looking up the geographic location
//! of IP addresses using MaxMind GeoLite2/GeoIP2 databases via the `maxminddb` crate.
//!
//! ## Features
//!
//! - Look up country code, country name, city, and coordinates for any IP
//! - Check whether an IP belongs to a blocked country
//! - Check whether an IP belongs to an allowed country (allowlist mode)
//! - Thread-safe: the `maxminddb::Reader` is `Send + Sync`
//!
//! ## Database
//!
//! Requires a MaxMind GeoLite2-City or GeoIP2-City database file (`.mmdb`).
//! Download from: <https://dev.maxmind.com/geoip/geolite2-free-geolocation-data>
//!
//! If the database file is not found at startup, the service initializes in
//! disabled mode — all lookups return `None` and country checks return `false`.
//! This allows the daemon to function without GeoIP data.

use maxminddb::{self, geoip2};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// GeoLocation
// ─────────────────────────────────────────────────────────────────────────────

/// Geographic location information for an IP address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoLocation {
    /// ISO 3166-1 alpha-2 country code (e.g. "US", "DE", "JP")
    pub country_code: Option<String>,
    /// Country name in English (e.g. "United States", "Germany")
    pub country_name: Option<String>,
    /// City name in English
    pub city: Option<String>,
    /// Region/subdivision name (e.g. state, province)
    pub region: Option<String>,
    /// Latitude
    pub latitude: Option<f64>,
    /// Longitude
    pub longitude: Option<f64>,
    /// Autonomous System Number
    pub asn: Option<u32>,
    /// Organization/ISP name
    pub org: Option<String>,
}

impl GeoLocation {
    /// Check if we have at least a country code.
    pub fn has_country(&self) -> bool {
        self.country_code.is_some()
    }

    /// Get a short summary string (e.g. "US / New York" or "DE" or "Unknown")
    pub fn summary(&self) -> String {
        match (&self.country_code, &self.city) {
            (Some(cc), Some(city)) => format!("{} / {}", cc, city),
            (Some(cc), None) => cc.clone(),
            _ => "Unknown".to_string(),
        }
    }
}

impl std::fmt::Display for GeoLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GeoIpError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur during GeoIP operations.
#[derive(Debug, thiserror::Error)]
pub enum GeoIpError {
    #[error("Database not found: {0}")]
    DatabaseNotFound(String),

    #[error("Failed to load database: {0}")]
    LoadError(String),

    #[error("Lookup failed for {ip}: {message}")]
    LookupError { ip: String, message: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// GeoIpService
// ─────────────────────────────────────────────────────────────────────────────

/// GeoIP lookup service backed by a MaxMind `.mmdb` database.
///
/// If the database file is not found or fails to load, the service operates
/// in disabled mode where all lookups return `None` and all country checks
/// return `false`.
///
/// ## Thread Safety
///
/// This struct is `Send + Sync` and can be shared across threads via `Arc`.
/// The underlying `maxminddb::Reader` uses memory-mapped I/O and is safe
/// for concurrent reads.
pub struct GeoIpService {
    /// The MaxMind database reader (None if database is unavailable)
    reader: Option<maxminddb::Reader<Vec<u8>>>,

    /// Whether the service is enabled
    enabled: bool,

    /// Path to the database file (for logging/diagnostics)
    db_path: PathBuf,

    /// Set of blocked country codes (ISO 3166-1 alpha-2, uppercase)
    blocked_countries: HashSet<String>,

    /// Set of allowed country codes (if non-empty, only these are allowed)
    allowed_countries: HashSet<String>,

    /// Set of suspicious regions requiring extra scrutiny
    suspicious_regions: HashSet<String>,

    /// Total lookups performed (for stats)
    lookups_performed: std::sync::atomic::AtomicU64,

    /// Total lookups that returned a result
    lookups_found: std::sync::atomic::AtomicU64,
}

impl GeoIpService {
    /// Create a new GeoIP service from a database file path.
    ///
    /// If the database file does not exist or cannot be loaded, the service
    /// is created in disabled mode with a warning. This is intentional — the
    /// daemon should not fail to start just because the GeoIP database is
    /// missing.
    pub fn new(db_path: &Path) -> Result<Self, GeoIpError> {
        Self::with_config(db_path, HashSet::new(), HashSet::new(), HashSet::new())
    }

    /// Create a new GeoIP service with full configuration.
    pub fn with_config(
        db_path: &Path,
        blocked_countries: HashSet<String>,
        allowed_countries: HashSet<String>,
        suspicious_regions: HashSet<String>,
    ) -> Result<Self, GeoIpError> {
        // Normalize country codes to uppercase
        let blocked: HashSet<String> = blocked_countries
            .into_iter()
            .map(|c| c.to_uppercase())
            .collect();
        let allowed: HashSet<String> = allowed_countries
            .into_iter()
            .map(|c| c.to_uppercase())
            .collect();
        let suspicious: HashSet<String> = suspicious_regions
            .into_iter()
            .map(|c| c.to_uppercase())
            .collect();

        if !db_path.exists() {
            warn!(
                "GeoIP database not found at {:?} — GeoIP lookups will be disabled. \
                 Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data",
                db_path
            );
            return Ok(Self {
                reader: None,
                enabled: false,
                db_path: db_path.to_path_buf(),
                blocked_countries: blocked,
                allowed_countries: allowed,
                suspicious_regions: suspicious,
                lookups_performed: std::sync::atomic::AtomicU64::new(0),
                lookups_found: std::sync::atomic::AtomicU64::new(0),
            });
        }

        match maxminddb::Reader::open_readfile(db_path) {
            Ok(reader) => {
                info!(
                    "GeoIP database loaded: {:?} ({} blocked countries, {} allowed countries)",
                    db_path,
                    blocked.len(),
                    allowed.len(),
                );
                Ok(Self {
                    reader: Some(reader),
                    enabled: true,
                    db_path: db_path.to_path_buf(),
                    blocked_countries: blocked,
                    allowed_countries: allowed,
                    suspicious_regions: suspicious,
                    lookups_performed: std::sync::atomic::AtomicU64::new(0),
                    lookups_found: std::sync::atomic::AtomicU64::new(0),
                })
            }
            Err(e) => {
                warn!(
                    "Failed to load GeoIP database {:?}: {} — GeoIP lookups will be disabled",
                    db_path, e
                );
                Ok(Self {
                    reader: None,
                    enabled: false,
                    db_path: db_path.to_path_buf(),
                    blocked_countries: blocked,
                    allowed_countries: allowed,
                    suspicious_regions: suspicious,
                    lookups_performed: std::sync::atomic::AtomicU64::new(0),
                    lookups_found: std::sync::atomic::AtomicU64::new(0),
                })
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Lookups
    // ─────────────────────────────────────────────────────────────────────

    /// Look up geographic information for an IP address.
    ///
    /// Returns `None` if:
    /// - The service is disabled (no database loaded)
    /// - The IP address is not found in the database
    /// - The IP is a private/reserved address (not in MaxMind's data)
    pub fn lookup(&self, ip: &IpAddr) -> Option<GeoLocation> {
        self.lookups_performed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let reader = self.reader.as_ref()?;

        // Try City lookup first (includes country data)
        match reader.lookup::<geoip2::City>(*ip) {
            Ok(city_result) => {
                self.lookups_found
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let mut geo = GeoLocation::default();

                // Extract country info
                if let Some(country) = &city_result.country {
                    geo.country_code = country.iso_code.map(String::from);
                    if let Some(names) = &country.names {
                        geo.country_name = names.get("en").map(|s| s.to_string());
                    }
                }

                // Extract city info
                if let Some(city) = &city_result.city {
                    if let Some(names) = &city.names {
                        geo.city = names.get("en").map(|s| s.to_string());
                    }
                }

                // Extract region/subdivision info
                if let Some(subdivisions) = &city_result.subdivisions {
                    if let Some(first) = subdivisions.first() {
                        if let Some(names) = &first.names {
                            geo.region = names.get("en").map(|s| s.to_string());
                        }
                    }
                }

                // Extract coordinates
                if let Some(location) = &city_result.location {
                    geo.latitude = location.latitude;
                    geo.longitude = location.longitude;
                }

                debug!(
                    "GeoIP lookup: {} → {}",
                    ip,
                    geo.summary()
                );

                Some(geo)
            }
            Err(maxminddb::MaxMindDBError::AddressNotFoundError(_)) => {
                // Not in the database — common for private IPs
                debug!("GeoIP lookup: {} → not found in database", ip);
                None
            }
            Err(e) => {
                debug!("GeoIP lookup error for {}: {}", ip, e);
                None
            }
        }
    }

    /// Look up only the country code for an IP address.
    ///
    /// This is faster than `lookup()` because it only extracts the country
    /// code, not the full city/region/coordinate data.
    pub fn lookup_country_code(&self, ip: &IpAddr) -> Option<String> {
        let reader = self.reader.as_ref()?;

        match reader.lookup::<geoip2::Country>(*ip) {
            Ok(result) => result
                .country
                .and_then(|c| c.iso_code)
                .map(String::from),
            Err(_) => None,
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Country Checks
    // ─────────────────────────────────────────────────────────────────────

    /// Check if an IP's country is in the blocked list.
    ///
    /// Returns `true` if:
    /// - GeoIP is enabled AND
    /// - The IP resolves to a country AND
    /// - That country code is in `blocked_countries`
    ///
    /// Returns `false` if:
    /// - GeoIP is disabled
    /// - The IP can't be resolved
    /// - The blocked list is empty
    /// - The country is not in the blocked list
    pub fn is_country_blocked(&self, ip: &IpAddr) -> bool {
        if !self.enabled || self.blocked_countries.is_empty() {
            return false;
        }

        if let Some(cc) = self.lookup_country_code(ip) {
            let cc_upper = cc.to_uppercase();
            let blocked = self.blocked_countries.contains(&cc_upper);
            if blocked {
                debug!("GeoIP: {} is from blocked country {}", ip, cc_upper);
            }
            blocked
        } else {
            false
        }
    }

    /// Check if an IP's country is allowed.
    ///
    /// If `allowed_countries` is empty, all countries are allowed (returns `true`).
    /// If `allowed_countries` is non-empty, only IPs from those countries are allowed.
    ///
    /// Returns `true` if:
    /// - The allowed list is empty (no restriction)
    /// - GeoIP is disabled (can't determine, so allow)
    /// - The IP resolves to an allowed country
    ///
    /// Returns `false` if:
    /// - The allowed list is non-empty AND
    /// - The IP resolves to a country NOT in the allowed list
    /// - The IP resolves to a country NOT in the database (ambiguous — denied)
    pub fn is_country_allowed(&self, ip: &IpAddr) -> bool {
        if self.allowed_countries.is_empty() {
            return true; // No allowlist restriction
        }

        if !self.enabled {
            return true; // Can't check, allow by default
        }

        if let Some(cc) = self.lookup_country_code(ip) {
            let cc_upper = cc.to_uppercase();
            self.allowed_countries.contains(&cc_upper)
        } else {
            // IP not in database — when an allowlist is active, deny unknowns
            false
        }
    }

    /// Check if an IP's country is in the suspicious regions list.
    ///
    /// IPs from suspicious regions may warrant extra scrutiny (lower thresholds).
    pub fn is_suspicious_region(&self, ip: &IpAddr) -> bool {
        if !self.enabled || self.suspicious_regions.is_empty() {
            return false;
        }

        if let Some(cc) = self.lookup_country_code(ip) {
            self.suspicious_regions.contains(&cc.to_uppercase())
        } else {
            false
        }
    }

    /// Perform a full check: is the IP allowed based on geo policy?
    ///
    /// Returns `false` (deny) if:
    /// - The IP is from a blocked country, OR
    /// - An allowlist is configured and the IP is NOT from an allowed country
    ///
    /// Returns `true` (allow) otherwise.
    pub fn is_allowed_by_policy(&self, ip: &IpAddr) -> bool {
        if self.is_country_blocked(ip) {
            return false;
        }
        self.is_country_allowed(ip)
    }

    // ─────────────────────────────────────────────────────────────────────
    // Status / Configuration
    // ─────────────────────────────────────────────────────────────────────

    /// Check whether the GeoIP service is enabled (database loaded).
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the path to the database file.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    /// Get the set of blocked country codes.
    pub fn blocked_countries(&self) -> &HashSet<String> {
        &self.blocked_countries
    }

    /// Get the set of allowed country codes.
    pub fn allowed_countries(&self) -> &HashSet<String> {
        &self.allowed_countries
    }

    /// Get the set of suspicious region codes.
    pub fn suspicious_regions(&self) -> &HashSet<String> {
        &self.suspicious_regions
    }

    /// Get lookup statistics.
    pub fn stats(&self) -> GeoIpStats {
        GeoIpStats {
            enabled: self.enabled,
            db_path: self.db_path.to_string_lossy().to_string(),
            lookups_performed: self
                .lookups_performed
                .load(std::sync::atomic::Ordering::Relaxed),
            lookups_found: self
                .lookups_found
                .load(std::sync::atomic::Ordering::Relaxed),
            blocked_countries_count: self.blocked_countries.len(),
            allowed_countries_count: self.allowed_countries.len(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Statistics
// ─────────────────────────────────────────────────────────────────────────────

/// GeoIP service statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpStats {
    pub enabled: bool,
    pub db_path: String,
    pub lookups_performed: u64,
    pub lookups_found: u64,
    pub blocked_countries_count: usize,
    pub allowed_countries_count: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ── GeoLocation Tests ──────────────────────────────────────────────

    #[test]
    fn test_geo_location_default() {
        let geo = GeoLocation::default();
        assert!(geo.country_code.is_none());
        assert!(geo.country_name.is_none());
        assert!(geo.city.is_none());
        assert!(!geo.has_country());
        assert_eq!(geo.summary(), "Unknown");
    }

    #[test]
    fn test_geo_location_with_country() {
        let geo = GeoLocation {
            country_code: Some("US".to_string()),
            country_name: Some("United States".to_string()),
            ..Default::default()
        };
        assert!(geo.has_country());
        assert_eq!(geo.summary(), "US");
        assert_eq!(format!("{}", geo), "US");
    }

    #[test]
    fn test_geo_location_with_city() {
        let geo = GeoLocation {
            country_code: Some("DE".to_string()),
            country_name: Some("Germany".to_string()),
            city: Some("Berlin".to_string()),
            ..Default::default()
        };
        assert_eq!(geo.summary(), "DE / Berlin");
    }

    #[test]
    fn test_geo_location_serialization() {
        let geo = GeoLocation {
            country_code: Some("JP".to_string()),
            country_name: Some("Japan".to_string()),
            city: Some("Tokyo".to_string()),
            region: Some("Tokyo".to_string()),
            latitude: Some(35.6762),
            longitude: Some(139.6503),
            asn: Some(2497),
            org: Some("IIJ".to_string()),
        };

        let json = serde_json::to_string(&geo).unwrap();
        let deserialized: GeoLocation = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.country_code, Some("JP".to_string()));
        assert_eq!(deserialized.city, Some("Tokyo".to_string()));
        assert_eq!(deserialized.asn, Some(2497));
    }

    // ── GeoIpService Tests (without database) ──────────────────────────

    #[test]
    fn test_service_without_database() {
        // Should succeed even without a database file
        let service = GeoIpService::new(Path::new("/nonexistent/GeoLite2-City.mmdb")).unwrap();
        assert!(!service.is_enabled());
        assert_eq!(service.db_path(), Path::new("/nonexistent/GeoLite2-City.mmdb"));
    }

    #[test]
    fn test_lookup_disabled() {
        let service = GeoIpService::new(Path::new("/nonexistent/db.mmdb")).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(service.lookup(&ip).is_none());
    }

    #[test]
    fn test_country_blocked_disabled() {
        let service = GeoIpService::new(Path::new("/nonexistent/db.mmdb")).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!service.is_country_blocked(&ip));
    }

    #[test]
    fn test_country_allowed_disabled() {
        let service = GeoIpService::new(Path::new("/nonexistent/db.mmdb")).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(service.is_country_allowed(&ip)); // disabled = allow all
    }

    #[test]
    fn test_suspicious_region_disabled() {
        let service = GeoIpService::new(Path::new("/nonexistent/db.mmdb")).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!service.is_suspicious_region(&ip));
    }

    #[test]
    fn test_policy_check_disabled() {
        let service = GeoIpService::new(Path::new("/nonexistent/db.mmdb")).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(service.is_allowed_by_policy(&ip)); // disabled = allow
    }

    // ── Config Tests ───────────────────────────────────────────────────

    #[test]
    fn test_service_with_config() {
        let mut blocked = HashSet::new();
        blocked.insert("CN".to_string());
        blocked.insert("ru".to_string()); // lowercase should be normalized

        let mut allowed = HashSet::new();
        allowed.insert("us".to_string());

        let service = GeoIpService::with_config(
            Path::new("/nonexistent/db.mmdb"),
            blocked,
            allowed,
            HashSet::new(),
        )
        .unwrap();

        assert!(!service.is_enabled());
        // Verify normalization
        assert!(service.blocked_countries().contains("CN"));
        assert!(service.blocked_countries().contains("RU"));
        assert!(service.allowed_countries().contains("US"));
    }

    #[test]
    fn test_stats() {
        let service = GeoIpService::new(Path::new("/nonexistent/db.mmdb")).unwrap();
        let stats = service.stats();

        assert!(!stats.enabled);
        assert_eq!(stats.lookups_performed, 0);
        assert_eq!(stats.lookups_found, 0);
        assert_eq!(stats.blocked_countries_count, 0);
    }

    #[test]
    fn test_stats_after_lookups() {
        let service = GeoIpService::new(Path::new("/nonexistent/db.mmdb")).unwrap();

        // Perform some lookups (they'll all return None since disabled)
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        service.lookup(&ip);
        service.lookup(&ip);
        service.lookup(&ip);

        let stats = service.stats();
        assert_eq!(stats.lookups_performed, 3);
        assert_eq!(stats.lookups_found, 0); // no database, no results
    }

    #[test]
    fn test_stats_serialization() {
        let stats = GeoIpStats {
            enabled: true,
            db_path: "/var/lib/zeroed/GeoLite2-City.mmdb".to_string(),
            lookups_performed: 1000,
            lookups_found: 950,
            blocked_countries_count: 3,
            allowed_countries_count: 0,
        };

        let json = serde_json::to_string(&stats).unwrap();
        let deserialized: GeoIpStats = serde_json::from_str(&json).unwrap();

        assert!(deserialized.enabled);
        assert_eq!(deserialized.lookups_performed, 1000);
        assert_eq!(deserialized.lookups_found, 950);
    }

    // ── Country Check Logic Tests ──────────────────────────────────────
    // These test the policy logic even though the database is not loaded.
    // The actual database-backed tests would require a .mmdb file in the
    // test environment — covered in Step 10 (integration tests).

    #[test]
    fn test_empty_blocked_list_allows_all() {
        let service = GeoIpService::with_config(
            Path::new("/nonexistent/db.mmdb"),
            HashSet::new(), // no blocked countries
            HashSet::new(),
            HashSet::new(),
        )
        .unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(!service.is_country_blocked(&ip)); // empty blocklist = nothing blocked
    }

    #[test]
    fn test_empty_allowed_list_allows_all() {
        let service = GeoIpService::with_config(
            Path::new("/nonexistent/db.mmdb"),
            HashSet::new(),
            HashSet::new(), // no allowlist = allow all
            HashSet::new(),
        )
        .unwrap();

        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert!(service.is_country_allowed(&ip));
    }

    #[test]
    fn test_lookup_country_code_disabled() {
        let service = GeoIpService::new(Path::new("/nonexistent/db.mmdb")).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(service.lookup_country_code(&ip).is_none());
    }

    // ── GeoIpError Tests ───────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let err = GeoIpError::DatabaseNotFound("/path/to/db.mmdb".to_string());
        assert!(format!("{}", err).contains("/path/to/db.mmdb"));

        let err = GeoIpError::LoadError("invalid format".to_string());
        assert!(format!("{}", err).contains("invalid format"));

        let err = GeoIpError::LookupError {
            ip: "1.2.3.4".to_string(),
            message: "not found".to_string(),
        };
        assert!(format!("{}", err).contains("1.2.3.4"));
        assert!(format!("{}", err).contains("not found"));
    }
}
