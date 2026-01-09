//! Rate limiter implementations for DoS protection
//!
//! This module provides various rate limiting algorithms used by the
//! detection engine to identify and mitigate DoS attacks.
//!
//! ## Algorithms
//!
//! - **Token Bucket**: Classic token bucket algorithm for smooth rate limiting
//! - **Sliding Window**: Sliding window counter for accurate rate measurement
//! - **Leaky Bucket**: Leaky bucket for traffic shaping

use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// Token Bucket Rate Limiter
// ─────────────────────────────────────────────────────────────────────────────

/// Token bucket rate limiter
///
/// Allows bursts up to `burst_size` tokens, with tokens refilling at
/// `rate` tokens per second.
#[derive(Debug)]
pub struct TokenBucket {
    /// Maximum tokens (burst capacity)
    burst_size: f64,
    /// Token refill rate (tokens per second)
    refill_rate: f64,
    /// Current token count
    tokens: RwLock<f64>,
    /// Last refill timestamp
    last_refill: RwLock<Instant>,
}

impl TokenBucket {
    /// Create a new token bucket
    ///
    /// # Arguments
    /// * `rate` - Tokens per second (sustained rate)
    /// * `burst_size` - Maximum tokens (burst capacity)
    pub fn new(rate: f64, burst_size: f64) -> Self {
        Self {
            burst_size,
            refill_rate: rate,
            tokens: RwLock::new(burst_size),
            last_refill: RwLock::new(Instant::now()),
        }
    }

    /// Try to consume tokens
    ///
    /// Returns `true` if tokens were available, `false` otherwise.
    pub fn try_consume(&self, tokens: f64) -> bool {
        self.refill();

        let mut current = self.tokens.write();
        if *current >= tokens {
            *current -= tokens;
            true
        } else {
            false
        }
    }

    /// Check if tokens are available without consuming them
    pub fn check(&self, tokens: f64) -> bool {
        self.refill();
        *self.tokens.read() >= tokens
    }

    /// Get current token count
    pub fn available_tokens(&self) -> f64 {
        self.refill();
        *self.tokens.read()
    }

    /// Refill tokens based on elapsed time
    fn refill(&self) {
        let now = Instant::now();
        let mut last = self.last_refill.write();
        let elapsed = now.duration_since(*last).as_secs_f64();

        if elapsed > 0.0 {
            let mut tokens = self.tokens.write();
            let new_tokens = *tokens + elapsed * self.refill_rate;
            *tokens = new_tokens.min(self.burst_size);
            *last = now;
        }
    }

    /// Reset the bucket to full
    pub fn reset(&self) {
        *self.tokens.write() = self.burst_size;
        *self.last_refill.write() = Instant::now();
    }
}

impl Clone for TokenBucket {
    fn clone(&self) -> Self {
        Self {
            burst_size: self.burst_size,
            refill_rate: self.refill_rate,
            tokens: RwLock::new(*self.tokens.read()),
            last_refill: RwLock::new(*self.last_refill.read()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sliding Window Rate Limiter
// ─────────────────────────────────────────────────────────────────────────────

/// Sliding window rate limiter
///
/// Tracks request timestamps within a sliding window to provide
/// accurate rate measurement.
#[derive(Debug)]
pub struct SlidingWindowLimiter {
    /// Window duration
    window: Duration,
    /// Maximum requests allowed in window
    max_requests: u64,
    /// Request timestamps
    timestamps: RwLock<VecDeque<Instant>>,
}

impl SlidingWindowLimiter {
    /// Create a new sliding window limiter
    pub fn new(window: Duration, max_requests: u64) -> Self {
        Self {
            window,
            max_requests,
            timestamps: RwLock::new(VecDeque::with_capacity(max_requests as usize)),
        }
    }

    /// Record a request and check if it's allowed
    pub fn check_and_record(&self) -> bool {
        let now = Instant::now();
        let mut timestamps = self.timestamps.write();

        // Remove expired timestamps
        let cutoff = now - self.window;
        while let Some(&front) = timestamps.front() {
            if front < cutoff {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        // Check if we're under the limit
        if timestamps.len() < self.max_requests as usize {
            timestamps.push_back(now);
            true
        } else {
            false
        }
    }

    /// Get current request count in window
    pub fn current_count(&self) -> u64 {
        let now = Instant::now();
        let mut timestamps = self.timestamps.write();

        // Remove expired timestamps
        let cutoff = now - self.window;
        while let Some(&front) = timestamps.front() {
            if front < cutoff {
                timestamps.pop_front();
            } else {
                break;
            }
        }

        timestamps.len() as u64
    }

    /// Get current rate (requests per second)
    pub fn current_rate(&self) -> f64 {
        let count = self.current_count();
        count as f64 / self.window.as_secs_f64()
    }

    /// Check if rate exceeds threshold
    pub fn exceeds_rate(&self, threshold: f64) -> bool {
        self.current_rate() > threshold
    }

    /// Reset the limiter
    pub fn reset(&self) {
        self.timestamps.write().clear();
    }
}

impl Clone for SlidingWindowLimiter {
    fn clone(&self) -> Self {
        Self {
            window: self.window,
            max_requests: self.max_requests,
            timestamps: RwLock::new(self.timestamps.read().clone()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-IP Rate Limiter
// ─────────────────────────────────────────────────────────────────────────────

/// Rate limiter with per-IP tracking
pub struct RateLimiter {
    /// Alert threshold (requests per second)
    alert_threshold: f64,
    /// Block threshold (requests per second)
    block_threshold: f64,
    /// Per-IP sliding windows
    ip_windows: DashMap<IpAddr, SlidingWindowLimiter>,
    /// Window duration
    window: Duration,
    /// Global request counter
    total_requests: AtomicU64,
    /// Global blocked counter
    total_blocked: AtomicU64,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(alert_threshold: f64, block_threshold: f64) -> Self {
        Self {
            alert_threshold,
            block_threshold,
            ip_windows: DashMap::new(),
            window: Duration::from_secs(60),
            total_requests: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
        }
    }

    /// Create with custom window duration
    pub fn with_window(alert_threshold: f64, block_threshold: f64, window: Duration) -> Self {
        Self {
            alert_threshold,
            block_threshold,
            ip_windows: DashMap::new(),
            window,
            total_requests: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
        }
    }

    /// Check rate limit for an IP
    ///
    /// Returns `RateLimitResult` indicating whether to allow, alert, or block.
    pub fn check(&self, ip: IpAddr) -> RateLimitResult {
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        // Get or create limiter for this IP
        let limiter = self.ip_windows.entry(ip).or_insert_with(|| {
            // Calculate max requests based on block threshold and window
            let max_requests = (self.block_threshold * self.window.as_secs_f64()) as u64;
            SlidingWindowLimiter::new(self.window, max_requests)
        });

        // Record the request
        let allowed = limiter.check_and_record();
        let rate = limiter.current_rate();

        drop(limiter);

        if !allowed || rate > self.block_threshold {
            self.total_blocked.fetch_add(1, Ordering::Relaxed);
            RateLimitResult::Block { rate }
        } else if rate > self.alert_threshold {
            RateLimitResult::Alert { rate }
        } else {
            RateLimitResult::Allow { rate }
        }
    }

    /// Get current rate for an IP
    pub fn get_rate(&self, ip: &IpAddr) -> Option<f64> {
        self.ip_windows.get(ip).map(|w| w.current_rate())
    }

    /// Get request count for an IP
    pub fn get_count(&self, ip: &IpAddr) -> Option<u64> {
        self.ip_windows.get(ip).map(|w| w.current_count())
    }

    /// Clear rate limit state for an IP
    pub fn clear_ip(&self, ip: &IpAddr) {
        self.ip_windows.remove(ip);
    }

    /// Clear all rate limit state
    pub fn clear_all(&self) {
        self.ip_windows.clear();
    }

    /// Get number of tracked IPs
    pub fn tracked_ip_count(&self) -> usize {
        self.ip_windows.len()
    }

    /// Get total requests processed
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Get total requests blocked
    pub fn total_blocked(&self) -> u64 {
        self.total_blocked.load(Ordering::Relaxed)
    }

    /// Cleanup expired entries
    pub fn cleanup(&self) -> usize {
        let mut removed = 0;

        self.ip_windows.retain(|_, limiter| {
            let count = limiter.current_count();
            if count == 0 {
                removed += 1;
                false
            } else {
                true
            }
        });

        removed
    }

    /// Get statistics
    pub fn stats(&self) -> RateLimiterStats {
        RateLimiterStats {
            tracked_ips: self.tracked_ip_count(),
            total_requests: self.total_requests(),
            total_blocked: self.total_blocked(),
            alert_threshold: self.alert_threshold,
            block_threshold: self.block_threshold,
            window_secs: self.window.as_secs(),
        }
    }
}

/// Result of a rate limit check
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RateLimitResult {
    /// Request allowed
    Allow { rate: f64 },
    /// Request allowed but rate is elevated (alert)
    Alert { rate: f64 },
    /// Request should be blocked
    Block { rate: f64 },
}

impl RateLimitResult {
    /// Check if this result indicates the request should be allowed
    pub fn is_allowed(&self) -> bool {
        matches!(
            self,
            RateLimitResult::Allow { .. } | RateLimitResult::Alert { .. }
        )
    }

    /// Check if this result indicates blocking
    pub fn is_blocked(&self) -> bool {
        matches!(self, RateLimitResult::Block { .. })
    }

    /// Check if this result is an alert
    pub fn is_alert(&self) -> bool {
        matches!(self, RateLimitResult::Alert { .. })
    }

    /// Get the rate
    pub fn rate(&self) -> f64 {
        match self {
            RateLimitResult::Allow { rate }
            | RateLimitResult::Alert { rate }
            | RateLimitResult::Block { rate } => *rate,
        }
    }
}

/// Rate limiter statistics
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    pub tracked_ips: usize,
    pub total_requests: u64,
    pub total_blocked: u64,
    pub alert_threshold: f64,
    pub block_threshold: f64,
    pub window_secs: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Leaky Bucket Rate Limiter
// ─────────────────────────────────────────────────────────────────────────────

/// Leaky bucket rate limiter for traffic shaping
#[derive(Debug)]
pub struct LeakyBucket {
    /// Bucket capacity
    capacity: f64,
    /// Leak rate (units per second)
    leak_rate: f64,
    /// Current fill level
    level: RwLock<f64>,
    /// Last update time
    last_update: RwLock<Instant>,
}

impl LeakyBucket {
    /// Create a new leaky bucket
    pub fn new(capacity: f64, leak_rate: f64) -> Self {
        Self {
            capacity,
            leak_rate,
            level: RwLock::new(0.0),
            last_update: RwLock::new(Instant::now()),
        }
    }

    /// Add to the bucket, returns true if successful (not overflowing)
    pub fn add(&self, amount: f64) -> bool {
        self.leak();

        let mut level = self.level.write();
        let new_level = *level + amount;

        if new_level <= self.capacity {
            *level = new_level;
            true
        } else {
            false
        }
    }

    /// Get current fill level
    pub fn current_level(&self) -> f64 {
        self.leak();
        *self.level.read()
    }

    /// Get fill ratio (0.0 to 1.0)
    pub fn fill_ratio(&self) -> f64 {
        self.current_level() / self.capacity
    }

    /// Leak water from the bucket
    fn leak(&self) {
        let now = Instant::now();
        let mut last = self.last_update.write();
        let elapsed = now.duration_since(*last).as_secs_f64();

        if elapsed > 0.0 {
            let mut level = self.level.write();
            let leaked = elapsed * self.leak_rate;
            *level = (*level - leaked).max(0.0);
            *last = now;
        }
    }

    /// Reset the bucket to empty
    pub fn reset(&self) {
        *self.level.write() = 0.0;
        *self.last_update.write() = Instant::now();
    }
}

impl Clone for LeakyBucket {
    fn clone(&self) -> Self {
        Self {
            capacity: self.capacity,
            leak_rate: self.leak_rate,
            level: RwLock::new(*self.level.read()),
            last_update: RwLock::new(*self.last_update.read()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread::sleep;

    #[test]
    fn test_token_bucket() {
        let bucket = TokenBucket::new(10.0, 5.0); // 10 tokens/sec, burst of 5

        // Should have 5 tokens initially
        assert!(bucket.try_consume(5.0));

        // Should be empty now
        assert!(!bucket.try_consume(1.0));
    }

    #[test]
    fn test_token_bucket_refill() {
        let bucket = TokenBucket::new(100.0, 10.0); // 100 tokens/sec, burst of 10

        // Consume all tokens
        bucket.try_consume(10.0);

        // Wait for refill
        sleep(Duration::from_millis(50));

        // Should have some tokens now
        assert!(bucket.available_tokens() > 0.0);
    }

    #[test]
    fn test_sliding_window() {
        let limiter = SlidingWindowLimiter::new(Duration::from_secs(1), 5);

        // Should allow 5 requests
        for _ in 0..5 {
            assert!(limiter.check_and_record());
        }

        // 6th request should fail
        assert!(!limiter.check_and_record());
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(10.0, 100.0);
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First request should be allowed
        let result = limiter.check(ip);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_rate_limit_result() {
        let allow = RateLimitResult::Allow { rate: 5.0 };
        assert!(allow.is_allowed());
        assert!(!allow.is_blocked());
        assert_eq!(allow.rate(), 5.0);

        let block = RateLimitResult::Block { rate: 150.0 };
        assert!(block.is_blocked());
        assert!(!block.is_allowed());
    }

    #[test]
    fn test_leaky_bucket() {
        let bucket = LeakyBucket::new(10.0, 5.0); // Capacity 10, leak 5/sec

        // Add 5 units
        assert!(bucket.add(5.0));
        assert!(bucket.fill_ratio() > 0.0);

        // Add more - should still fit
        assert!(bucket.add(5.0));

        // Overflow
        assert!(!bucket.add(1.0));
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let limiter = RateLimiter::with_window(10.0, 100.0, Duration::from_millis(100));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        limiter.check(ip);
        assert_eq!(limiter.tracked_ip_count(), 1);

        // Wait for window to expire
        sleep(Duration::from_millis(150));

        // Cleanup should remove the entry
        let removed = limiter.cleanup();
        assert_eq!(removed, 1);
        assert_eq!(limiter.tracked_ip_count(), 0);
    }
}
