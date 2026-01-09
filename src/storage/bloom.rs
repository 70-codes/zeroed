//! Bloom filter implementation for efficient probabilistic IP lookup
//!
//! This module provides a space-efficient probabilistic data structure for
//! testing whether an IP address or MAC address has been seen before.
//! Bloom filters have no false negatives but may have false positives.
//!
//! ## Usage
//!
//! ```ignore
//! use zeroed::storage::bloom::BloomFilter;
//!
//! let mut filter = BloomFilter::new(1_000_000, 0.01);
//! filter.insert("192.168.1.1");
//!
//! assert!(filter.contains("192.168.1.1"));  // Definitely seen
//! assert!(!filter.contains("10.0.0.1"));    // Probably not seen
//! ```

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::fs::{File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Magic number for bloom filter files
const BLOOM_MAGIC: [u8; 4] = [0x42, 0x4C, 0x4D, 0x46]; // "BLMF"

/// Current bloom filter format version
const BLOOM_VERSION: u8 = 1;

// ─────────────────────────────────────────────────────────────────────────────
// Bloom Filter Implementation
// ─────────────────────────────────────────────────────────────────────────────

/// A probabilistic data structure for set membership testing
///
/// Bloom filters are space-efficient but allow for false positives.
/// The false positive rate is configurable at creation time.
#[derive(Debug)]
pub struct BloomFilter {
    /// Bit vector
    bits: RwLock<Vec<u64>>,
    /// Number of bits in the filter
    num_bits: usize,
    /// Number of hash functions to use
    num_hashes: usize,
    /// Number of items inserted
    items_inserted: AtomicU64,
    /// False positive rate
    fp_rate: f64,
}

impl BloomFilter {
    /// Create a new bloom filter
    ///
    /// # Arguments
    /// * `expected_items` - Expected number of items to insert
    /// * `fp_rate` - Desired false positive rate (0.0 to 1.0)
    ///
    /// # Panics
    /// Panics if `fp_rate` is not between 0.0 and 1.0 (exclusive)
    pub fn new(expected_items: usize, fp_rate: f64) -> Self {
        assert!(
            fp_rate > 0.0 && fp_rate < 1.0,
            "fp_rate must be between 0 and 1"
        );
        assert!(expected_items > 0, "expected_items must be greater than 0");

        // Calculate optimal number of bits: m = -n * ln(p) / (ln(2)^2)
        let ln2_squared = std::f64::consts::LN_2 * std::f64::consts::LN_2;
        let num_bits = (-(expected_items as f64) * fp_rate.ln() / ln2_squared).ceil() as usize;

        // Calculate optimal number of hash functions: k = (m/n) * ln(2)
        let num_hashes =
            ((num_bits as f64 / expected_items as f64) * std::f64::consts::LN_2).ceil() as usize;
        let num_hashes = num_hashes.max(1).min(20); // Clamp between 1 and 20

        // Round up to nearest 64 bits
        let num_words = (num_bits + 63) / 64;
        let actual_bits = num_words * 64;

        Self {
            bits: RwLock::new(vec![0u64; num_words]),
            num_bits: actual_bits,
            num_hashes,
            items_inserted: AtomicU64::new(0),
            fp_rate,
        }
    }

    /// Create a bloom filter with specific parameters
    pub fn with_params(num_bits: usize, num_hashes: usize) -> Self {
        let num_words = (num_bits + 63) / 64;
        let actual_bits = num_words * 64;

        Self {
            bits: RwLock::new(vec![0u64; num_words]),
            num_bits: actual_bits,
            num_hashes: num_hashes.max(1).min(20),
            items_inserted: AtomicU64::new(0),
            fp_rate: 0.01, // Default assumption
        }
    }

    /// Insert an item into the bloom filter
    pub fn insert<T: Hash>(&self, item: &T) {
        let hashes = self.get_hashes(item);
        let mut bits = self.bits.write();

        for hash in hashes {
            let idx = (hash as usize) % self.num_bits;
            let word_idx = idx / 64;
            let bit_idx = idx % 64;
            bits[word_idx] |= 1u64 << bit_idx;
        }

        self.items_inserted.fetch_add(1, Ordering::Relaxed);
    }

    /// Insert a string item (convenience method for IP addresses)
    pub fn insert_str(&self, item: &str) {
        self.insert(&item.to_string());
    }

    /// Check if an item might be in the filter
    ///
    /// Returns `true` if the item might be present (with false positive rate),
    /// or `false` if the item is definitely not present.
    pub fn contains<T: Hash>(&self, item: &T) -> bool {
        let hashes = self.get_hashes(item);
        let bits = self.bits.read();

        for hash in hashes {
            let idx = (hash as usize) % self.num_bits;
            let word_idx = idx / 64;
            let bit_idx = idx % 64;

            if bits[word_idx] & (1u64 << bit_idx) == 0 {
                return false;
            }
        }

        true
    }

    /// Check if a string item might be in the filter
    pub fn contains_str(&self, item: &str) -> bool {
        self.contains(&item.to_string())
    }

    /// Generate hash values for an item
    fn get_hashes<T: Hash>(&self, item: &T) -> Vec<u64> {
        // Use double hashing technique: h(i) = h1 + i * h2
        let mut hasher1 = DefaultHasher::new();
        item.hash(&mut hasher1);
        let h1 = hasher1.finish();

        // Create second hash by hashing with a different seed
        let mut hasher2 = DefaultHasher::new();
        h1.hash(&mut hasher2);
        item.hash(&mut hasher2);
        let h2 = hasher2.finish();

        (0..self.num_hashes)
            .map(|i| h1.wrapping_add((i as u64).wrapping_mul(h2)))
            .collect()
    }

    /// Get the number of items inserted
    pub fn count(&self) -> u64 {
        self.items_inserted.load(Ordering::Relaxed)
    }

    /// Get the number of bits in the filter
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    /// Get the number of hash functions
    pub fn num_hashes(&self) -> usize {
        self.num_hashes
    }

    /// Calculate the current false positive probability
    ///
    /// This uses the formula: (1 - e^(-kn/m))^k
    /// where k = number of hash functions, n = items inserted, m = number of bits
    pub fn current_fp_rate(&self) -> f64 {
        let k = self.num_hashes as f64;
        let n = self.items_inserted.load(Ordering::Relaxed) as f64;
        let m = self.num_bits as f64;

        if n == 0.0 {
            return 0.0;
        }

        let exponent = -k * n / m;
        (1.0 - exponent.exp()).powf(k)
    }

    /// Get the fill ratio (percentage of bits set)
    pub fn fill_ratio(&self) -> f64 {
        let bits = self.bits.read();
        let set_bits: usize = bits.iter().map(|w| w.count_ones() as usize).sum();
        set_bits as f64 / self.num_bits as f64
    }

    /// Check if the filter is getting too full
    ///
    /// Returns true if fill ratio exceeds 50% (typically means FP rate is degraded)
    pub fn is_saturated(&self) -> bool {
        self.fill_ratio() > 0.5
    }

    /// Clear all bits in the filter
    pub fn clear(&self) {
        let mut bits = self.bits.write();
        for word in bits.iter_mut() {
            *word = 0;
        }
        self.items_inserted.store(0, Ordering::Relaxed);
    }

    /// Get memory usage in bytes
    pub fn memory_usage(&self) -> usize {
        self.num_bits / 8 + std::mem::size_of::<Self>()
    }

    /// Merge another bloom filter into this one (union operation)
    pub fn merge(&self, other: &BloomFilter) -> Result<(), BloomFilterError> {
        if self.num_bits != other.num_bits || self.num_hashes != other.num_hashes {
            return Err(BloomFilterError::IncompatibleFilters);
        }

        let mut our_bits = self.bits.write();
        let their_bits = other.bits.read();

        for (our_word, their_word) in our_bits.iter_mut().zip(their_bits.iter()) {
            *our_word |= *their_word;
        }

        Ok(())
    }

    /// Save the bloom filter to a file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), BloomFilterError> {
        let serializable = SerializableBloomFilter {
            magic: BLOOM_MAGIC,
            version: BLOOM_VERSION,
            num_bits: self.num_bits,
            num_hashes: self.num_hashes,
            items_inserted: self.items_inserted.load(Ordering::Relaxed),
            fp_rate: self.fp_rate,
            bits: self.bits.read().clone(),
        };

        let encoded = bincode::serialize(&serializable)
            .map_err(|e| BloomFilterError::SerializationError(e.to_string()))?;

        let mut file = File::create(path)?;
        file.write_all(&encoded)?;
        file.sync_all()?;

        Ok(())
    }

    /// Load a bloom filter from a file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, BloomFilterError> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        let serializable: SerializableBloomFilter = bincode::deserialize(&data)
            .map_err(|e| BloomFilterError::DeserializationError(e.to_string()))?;

        // Validate magic number
        if serializable.magic != BLOOM_MAGIC {
            return Err(BloomFilterError::InvalidMagic);
        }

        // Validate version
        if serializable.version > BLOOM_VERSION {
            return Err(BloomFilterError::UnsupportedVersion(serializable.version));
        }

        Ok(Self {
            bits: RwLock::new(serializable.bits),
            num_bits: serializable.num_bits,
            num_hashes: serializable.num_hashes,
            items_inserted: AtomicU64::new(serializable.items_inserted),
            fp_rate: serializable.fp_rate,
        })
    }

    /// Get statistics about the bloom filter
    pub fn stats(&self) -> BloomFilterStats {
        BloomFilterStats {
            num_bits: self.num_bits,
            num_hashes: self.num_hashes,
            items_inserted: self.count(),
            fill_ratio: self.fill_ratio(),
            current_fp_rate: self.current_fp_rate(),
            target_fp_rate: self.fp_rate,
            memory_bytes: self.memory_usage(),
            is_saturated: self.is_saturated(),
        }
    }
}

impl Clone for BloomFilter {
    fn clone(&self) -> Self {
        Self {
            bits: RwLock::new(self.bits.read().clone()),
            num_bits: self.num_bits,
            num_hashes: self.num_hashes,
            items_inserted: AtomicU64::new(self.items_inserted.load(Ordering::Relaxed)),
            fp_rate: self.fp_rate,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Serialization Support
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct SerializableBloomFilter {
    magic: [u8; 4],
    version: u8,
    num_bits: usize,
    num_hashes: usize,
    items_inserted: u64,
    fp_rate: f64,
    bits: Vec<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Statistics
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics about a bloom filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomFilterStats {
    /// Total number of bits
    pub num_bits: usize,
    /// Number of hash functions
    pub num_hashes: usize,
    /// Number of items inserted
    pub items_inserted: u64,
    /// Current fill ratio (0.0 to 1.0)
    pub fill_ratio: f64,
    /// Current estimated false positive rate
    pub current_fp_rate: f64,
    /// Target false positive rate
    pub target_fp_rate: f64,
    /// Memory usage in bytes
    pub memory_bytes: usize,
    /// Whether the filter is saturated
    pub is_saturated: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Error Types
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can occur with bloom filter operations
#[derive(Debug, thiserror::Error)]
pub enum BloomFilterError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Invalid magic number - not a bloom filter file")]
    InvalidMagic,

    #[error("Unsupported bloom filter version: {0}")]
    UnsupportedVersion(u8),

    #[error("Cannot merge incompatible bloom filters")]
    IncompatibleFilters,
}

// ─────────────────────────────────────────────────────────────────────────────
// Counting Bloom Filter
// ─────────────────────────────────────────────────────────────────────────────

/// A counting bloom filter that supports deletion
///
/// Uses 4-bit counters instead of single bits, allowing items to be removed.
/// Note: Still probabilistic and can have false positives.
#[derive(Debug)]
pub struct CountingBloomFilter {
    /// Counter array (4 bits per counter, packed into u64)
    counters: RwLock<Vec<u64>>,
    /// Number of counters
    num_counters: usize,
    /// Number of hash functions
    num_hashes: usize,
    /// Items currently in filter
    items_count: AtomicU64,
}

impl CountingBloomFilter {
    /// Maximum counter value (4 bits = 15)
    const MAX_COUNTER: u64 = 15;
    /// Counters per u64 word (64 / 4 = 16)
    const COUNTERS_PER_WORD: usize = 16;

    /// Create a new counting bloom filter
    pub fn new(expected_items: usize, fp_rate: f64) -> Self {
        assert!(
            fp_rate > 0.0 && fp_rate < 1.0,
            "fp_rate must be between 0 and 1"
        );

        // Same calculation as regular bloom filter
        let ln2_squared = std::f64::consts::LN_2 * std::f64::consts::LN_2;
        let num_counters = (-(expected_items as f64) * fp_rate.ln() / ln2_squared).ceil() as usize;
        let num_hashes = ((num_counters as f64 / expected_items as f64) * std::f64::consts::LN_2)
            .ceil() as usize;
        let num_hashes = num_hashes.max(1).min(20);

        let num_words = (num_counters + Self::COUNTERS_PER_WORD - 1) / Self::COUNTERS_PER_WORD;

        Self {
            counters: RwLock::new(vec![0u64; num_words]),
            num_counters,
            num_hashes,
            items_count: AtomicU64::new(0),
        }
    }

    /// Insert an item
    pub fn insert<T: Hash>(&self, item: &T) {
        let hashes = self.get_hashes(item);
        let mut counters = self.counters.write();

        for hash in hashes {
            let idx = (hash as usize) % self.num_counters;
            let word_idx = idx / Self::COUNTERS_PER_WORD;
            let counter_idx = idx % Self::COUNTERS_PER_WORD;
            let shift = counter_idx * 4;

            let current = (counters[word_idx] >> shift) & 0xF;
            if current < Self::MAX_COUNTER {
                counters[word_idx] += 1u64 << shift;
            }
        }

        self.items_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Remove an item
    pub fn remove<T: Hash>(&self, item: &T) -> bool {
        if !self.contains(item) {
            return false;
        }

        let hashes = self.get_hashes(item);
        let mut counters = self.counters.write();

        for hash in hashes {
            let idx = (hash as usize) % self.num_counters;
            let word_idx = idx / Self::COUNTERS_PER_WORD;
            let counter_idx = idx % Self::COUNTERS_PER_WORD;
            let shift = counter_idx * 4;

            let current = (counters[word_idx] >> shift) & 0xF;
            if current > 0 {
                counters[word_idx] -= 1u64 << shift;
            }
        }

        self.items_count.fetch_sub(1, Ordering::Relaxed);
        true
    }

    /// Check if an item might be present
    pub fn contains<T: Hash>(&self, item: &T) -> bool {
        let hashes = self.get_hashes(item);
        let counters = self.counters.read();

        for hash in hashes {
            let idx = (hash as usize) % self.num_counters;
            let word_idx = idx / Self::COUNTERS_PER_WORD;
            let counter_idx = idx % Self::COUNTERS_PER_WORD;
            let shift = counter_idx * 4;

            let current = (counters[word_idx] >> shift) & 0xF;
            if current == 0 {
                return false;
            }
        }

        true
    }

    /// Generate hash values
    fn get_hashes<T: Hash>(&self, item: &T) -> Vec<u64> {
        let mut hasher1 = DefaultHasher::new();
        item.hash(&mut hasher1);
        let h1 = hasher1.finish();

        let mut hasher2 = DefaultHasher::new();
        h1.hash(&mut hasher2);
        item.hash(&mut hasher2);
        let h2 = hasher2.finish();

        (0..self.num_hashes)
            .map(|i| h1.wrapping_add((i as u64).wrapping_mul(h2)))
            .collect()
    }

    /// Get count of items
    pub fn count(&self) -> u64 {
        self.items_count.load(Ordering::Relaxed)
    }

    /// Clear the filter
    pub fn clear(&self) {
        let mut counters = self.counters.write();
        for counter in counters.iter_mut() {
            *counter = 0;
        }
        self.items_count.store(0, Ordering::Relaxed);
    }

    /// Get memory usage in bytes
    pub fn memory_usage(&self) -> usize {
        self.counters.read().len() * 8 + std::mem::size_of::<Self>()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scalable Bloom Filter
// ─────────────────────────────────────────────────────────────────────────────

/// A scalable bloom filter that grows as items are added
///
/// Automatically adds new filter slices when the current one becomes saturated,
/// maintaining the target false positive rate.
#[derive(Debug)]
pub struct ScalableBloomFilter {
    /// Filter slices
    slices: RwLock<Vec<BloomFilter>>,
    /// Initial capacity per slice
    initial_capacity: usize,
    /// Target false positive rate
    fp_rate: f64,
    /// Growth ratio for each new slice
    growth_ratio: f64,
    /// FP rate tightening ratio
    fp_tightening_ratio: f64,
}

impl ScalableBloomFilter {
    /// Default growth ratio
    const DEFAULT_GROWTH_RATIO: f64 = 2.0;
    /// Default FP tightening ratio (each slice has tighter FP rate)
    const DEFAULT_FP_TIGHTENING: f64 = 0.5;

    /// Create a new scalable bloom filter
    pub fn new(initial_capacity: usize, fp_rate: f64) -> Self {
        let first_slice = BloomFilter::new(initial_capacity, fp_rate * Self::DEFAULT_FP_TIGHTENING);

        Self {
            slices: RwLock::new(vec![first_slice]),
            initial_capacity,
            fp_rate,
            growth_ratio: Self::DEFAULT_GROWTH_RATIO,
            fp_tightening_ratio: Self::DEFAULT_FP_TIGHTENING,
        }
    }

    /// Insert an item
    pub fn insert<T: Hash + Clone>(&self, item: &T) {
        // Check if we need a new slice
        {
            let slices = self.slices.read();
            if let Some(last) = slices.last() {
                if !last.is_saturated() {
                    last.insert(item);
                    return;
                }
            }
        }

        // Need to add a new slice
        let mut slices = self.slices.write();

        // Double-check after acquiring write lock
        if let Some(last) = slices.last() {
            if !last.is_saturated() {
                last.insert(item);
                return;
            }
        }

        // Create new slice with larger capacity and tighter FP rate
        let slice_num = slices.len();
        let capacity =
            (self.initial_capacity as f64 * self.growth_ratio.powi(slice_num as i32)) as usize;
        let fp = self.fp_rate * self.fp_tightening_ratio.powi((slice_num + 1) as i32);

        let new_slice = BloomFilter::new(capacity, fp.max(0.0001));
        new_slice.insert(item);
        slices.push(new_slice);
    }

    /// Check if an item might be present
    pub fn contains<T: Hash>(&self, item: &T) -> bool {
        let slices = self.slices.read();
        slices.iter().any(|s| s.contains(item))
    }

    /// Get total count of items inserted
    pub fn count(&self) -> u64 {
        self.slices.read().iter().map(|s| s.count()).sum()
    }

    /// Get number of slices
    pub fn num_slices(&self) -> usize {
        self.slices.read().len()
    }

    /// Get total memory usage
    pub fn memory_usage(&self) -> usize {
        self.slices.read().iter().map(|s| s.memory_usage()).sum()
    }

    /// Clear all slices
    pub fn clear(&self) {
        let mut slices = self.slices.write();
        slices.clear();
        slices.push(BloomFilter::new(
            self.initial_capacity,
            self.fp_rate * self.fp_tightening_ratio,
        ));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_basic() {
        let filter = BloomFilter::new(1000, 0.01);

        filter.insert(&"192.168.1.1");
        filter.insert(&"10.0.0.1");
        filter.insert(&"172.16.0.1");

        assert!(filter.contains(&"192.168.1.1"));
        assert!(filter.contains(&"10.0.0.1"));
        assert!(filter.contains(&"172.16.0.1"));
        assert!(!filter.contains(&"8.8.8.8")); // Probably not present
    }

    #[test]
    fn test_bloom_filter_fp_rate() {
        let filter = BloomFilter::new(10000, 0.01);

        // Insert 10000 items
        for i in 0..10000 {
            filter.insert(&format!("item_{}", i));
        }

        // Check false positive rate
        let mut false_positives = 0;
        for i in 10000..20000 {
            if filter.contains(&format!("item_{}", i)) {
                false_positives += 1;
            }
        }

        let actual_fp_rate = false_positives as f64 / 10000.0;
        assert!(actual_fp_rate < 0.02, "FP rate {} too high", actual_fp_rate);
    }

    #[test]
    fn test_counting_bloom_filter() {
        let filter = CountingBloomFilter::new(1000, 0.01);

        filter.insert(&"test1");
        filter.insert(&"test2");
        assert!(filter.contains(&"test1"));
        assert!(filter.contains(&"test2"));

        filter.remove(&"test1");
        assert!(!filter.contains(&"test1"));
        assert!(filter.contains(&"test2"));
    }

    #[test]
    fn test_scalable_bloom_filter() {
        let filter = ScalableBloomFilter::new(100, 0.01);

        // Insert more than initial capacity
        for i in 0..500 {
            filter.insert(&format!("item_{}", i));
        }

        assert!(filter.num_slices() > 1);
        assert!(filter.contains(&"item_0"));
        assert!(filter.contains(&"item_499"));
    }

    #[test]
    fn test_bloom_filter_stats() {
        let filter = BloomFilter::new(1000, 0.01);

        for i in 0..100 {
            filter.insert(&i);
        }

        let stats = filter.stats();
        assert_eq!(stats.items_inserted, 100);
        assert!(stats.fill_ratio > 0.0);
        assert!(!stats.is_saturated);
    }

    #[test]
    fn test_bloom_filter_merge() {
        let filter1 = BloomFilter::new(1000, 0.01);
        let filter2 = BloomFilter::new(1000, 0.01);

        filter1.insert(&"a");
        filter2.insert(&"b");

        filter1.merge(&filter2).unwrap();

        assert!(filter1.contains(&"a"));
        assert!(filter1.contains(&"b"));
    }

    #[test]
    fn test_save_load() {
        let filter = BloomFilter::new(1000, 0.01);
        filter.insert(&"test_item");

        let temp_path = std::env::temp_dir().join("test_bloom.bin");
        filter.save(&temp_path).unwrap();

        let loaded = BloomFilter::load(&temp_path).unwrap();
        assert!(loaded.contains(&"test_item"));

        std::fs::remove_file(temp_path).ok();
    }
}
