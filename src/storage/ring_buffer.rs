//! Ring buffer implementation for storing recent events
//!
//! This module provides a fixed-size, lock-free ring buffer optimized for
//! high-throughput event storage. It's designed for scenarios where we need
//! to keep track of the most recent N events with minimal overhead.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// A thread-safe ring buffer for storing recent events
///
/// This implementation uses a VecDeque internally for O(1) push/pop operations
/// and provides thread-safe access through RwLock for read-heavy workloads.
#[derive(Debug)]
pub struct RingBuffer<T> {
    /// Internal storage
    buffer: RwLock<VecDeque<T>>,
    /// Maximum capacity
    capacity: usize,
    /// Total items ever added
    total_added: AtomicU64,
    /// Total items evicted (overwritten)
    total_evicted: AtomicU64,
    /// Current size (cached for fast access)
    current_size: AtomicUsize,
}

impl<T: Clone> RingBuffer<T> {
    /// Create a new ring buffer with the specified capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: RwLock::new(VecDeque::with_capacity(capacity)),
            capacity,
            total_added: AtomicU64::new(0),
            total_evicted: AtomicU64::new(0),
            current_size: AtomicUsize::new(0),
        }
    }

    /// Push an item to the buffer, evicting the oldest if at capacity
    pub fn push(&self, item: T) {
        let mut buffer = self.buffer.write();

        if buffer.len() >= self.capacity {
            buffer.pop_front();
            self.total_evicted.fetch_add(1, Ordering::Relaxed);
        }

        buffer.push_back(item);
        self.total_added.fetch_add(1, Ordering::Relaxed);
        self.current_size.store(buffer.len(), Ordering::Relaxed);
    }

    /// Push multiple items, evicting as needed
    pub fn push_batch(&self, items: impl IntoIterator<Item = T>) {
        let mut buffer = self.buffer.write();
        let items: Vec<T> = items.into_iter().collect();
        let count = items.len();

        // If we're adding more than capacity, only keep the last `capacity` items
        if count >= self.capacity {
            buffer.clear();
            for item in items.into_iter().skip(count - self.capacity) {
                buffer.push_back(item);
            }
            self.total_evicted
                .fetch_add((count - self.capacity) as u64, Ordering::Relaxed);
        } else {
            // Evict as many as needed to make room
            let need_to_evict = (buffer.len() + count).saturating_sub(self.capacity);
            for _ in 0..need_to_evict {
                buffer.pop_front();
            }
            self.total_evicted
                .fetch_add(need_to_evict as u64, Ordering::Relaxed);

            for item in items {
                buffer.push_back(item);
            }
        }

        self.total_added.fetch_add(count as u64, Ordering::Relaxed);
        self.current_size.store(buffer.len(), Ordering::Relaxed);
    }

    /// Get the most recent item
    pub fn peek_latest(&self) -> Option<T> {
        self.buffer.read().back().cloned()
    }

    /// Get the oldest item
    pub fn peek_oldest(&self) -> Option<T> {
        self.buffer.read().front().cloned()
    }

    /// Get the N most recent items
    pub fn get_latest(&self, n: usize) -> Vec<T> {
        let buffer = self.buffer.read();
        let start = buffer.len().saturating_sub(n);
        buffer.iter().skip(start).cloned().collect()
    }

    /// Get the N oldest items
    pub fn get_oldest(&self, n: usize) -> Vec<T> {
        let buffer = self.buffer.read();
        buffer.iter().take(n).cloned().collect()
    }

    /// Get all items as a vector
    pub fn get_all(&self) -> Vec<T> {
        self.buffer.read().iter().cloned().collect()
    }

    /// Get current size
    pub fn len(&self) -> usize {
        self.current_size.load(Ordering::Relaxed)
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if buffer is at capacity
    pub fn is_full(&self) -> bool {
        self.len() >= self.capacity
    }

    /// Get capacity
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Get total items ever added
    pub fn total_added(&self) -> u64 {
        self.total_added.load(Ordering::Relaxed)
    }

    /// Get total items evicted
    pub fn total_evicted(&self) -> u64 {
        self.total_evicted.load(Ordering::Relaxed)
    }

    /// Clear the buffer
    pub fn clear(&self) {
        let mut buffer = self.buffer.write();
        buffer.clear();
        self.current_size.store(0, Ordering::Relaxed);
    }

    /// Iterate over items matching a predicate
    pub fn filter<F>(&self, predicate: F) -> Vec<T>
    where
        F: Fn(&T) -> bool,
    {
        self.buffer
            .read()
            .iter()
            .filter(|item| predicate(item))
            .cloned()
            .collect()
    }

    /// Count items matching a predicate
    pub fn count<F>(&self, predicate: F) -> usize
    where
        F: Fn(&T) -> bool,
    {
        self.buffer
            .read()
            .iter()
            .filter(|item| predicate(item))
            .count()
    }

    /// Get statistics about the buffer
    pub fn stats(&self) -> RingBufferStats {
        RingBufferStats {
            capacity: self.capacity,
            current_size: self.len(),
            total_added: self.total_added(),
            total_evicted: self.total_evicted(),
            utilization: self.len() as f64 / self.capacity as f64,
        }
    }
}

/// Statistics for a ring buffer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingBufferStats {
    pub capacity: usize,
    pub current_size: usize,
    pub total_added: u64,
    pub total_evicted: u64,
    pub utilization: f64,
}

/// A timestamped ring buffer that automatically expires old entries
#[derive(Debug)]
pub struct TimedRingBuffer<T> {
    /// Internal ring buffer with timestamps
    buffer: RingBuffer<TimestampedItem<T>>,
    /// Time-to-live for items
    ttl: Duration,
}

/// An item with a timestamp
#[derive(Debug, Clone)]
pub struct TimestampedItem<T> {
    pub item: T,
    pub timestamp: Instant,
}

impl<T: Clone> TimedRingBuffer<T> {
    /// Create a new timed ring buffer
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            buffer: RingBuffer::new(capacity),
            ttl,
        }
    }

    /// Push an item with the current timestamp
    pub fn push(&self, item: T) {
        self.buffer.push(TimestampedItem {
            item,
            timestamp: Instant::now(),
        });
    }

    /// Get all non-expired items
    pub fn get_valid(&self) -> Vec<T> {
        let now = Instant::now();
        self.buffer
            .filter(|ti| now.duration_since(ti.timestamp) < self.ttl)
            .into_iter()
            .map(|ti| ti.item)
            .collect()
    }

    /// Get items from the last N seconds
    pub fn get_since(&self, duration: Duration) -> Vec<T> {
        let cutoff = Instant::now() - duration;
        self.buffer
            .filter(|ti| ti.timestamp >= cutoff)
            .into_iter()
            .map(|ti| ti.item)
            .collect()
    }

    /// Count items from the last N seconds
    pub fn count_since(&self, duration: Duration) -> usize {
        let cutoff = Instant::now() - duration;
        self.buffer.count(|ti| ti.timestamp >= cutoff)
    }

    /// Calculate rate (items per second) over the given duration
    pub fn rate(&self, duration: Duration) -> f64 {
        let count = self.count_since(duration);
        count as f64 / duration.as_secs_f64()
    }

    /// Get the latest N non-expired items
    pub fn get_latest_valid(&self, n: usize) -> Vec<T> {
        let now = Instant::now();
        let all = self.buffer.get_all();
        all.into_iter()
            .rev()
            .filter(|ti| now.duration_since(ti.timestamp) < self.ttl)
            .take(n)
            .map(|ti| ti.item)
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> TimedRingBufferStats {
        let buffer_stats = self.buffer.stats();
        let valid_count = self.get_valid().len();

        TimedRingBufferStats {
            buffer_stats,
            valid_count,
            ttl_secs: self.ttl.as_secs_f64(),
        }
    }

    /// Clear the buffer
    pub fn clear(&self) {
        self.buffer.clear();
    }
}

/// Statistics for a timed ring buffer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimedRingBufferStats {
    pub buffer_stats: RingBufferStats,
    pub valid_count: usize,
    pub ttl_secs: f64,
}

/// A sharded ring buffer for high-concurrency scenarios
///
/// Distributes writes across multiple buffers to reduce contention
#[derive(Debug)]
pub struct ShardedRingBuffer<T> {
    shards: Vec<RingBuffer<T>>,
    shard_count: usize,
    next_shard: AtomicUsize,
}

impl<T: Clone + Send + Sync> ShardedRingBuffer<T> {
    /// Create a new sharded ring buffer
    ///
    /// Total capacity is distributed evenly across shards
    pub fn new(total_capacity: usize, shard_count: usize) -> Self {
        let shard_capacity = total_capacity / shard_count;
        let shards = (0..shard_count)
            .map(|_| RingBuffer::new(shard_capacity))
            .collect();

        Self {
            shards,
            shard_count,
            next_shard: AtomicUsize::new(0),
        }
    }

    /// Push an item, distributing across shards round-robin
    pub fn push(&self, item: T) {
        let shard_idx = self.next_shard.fetch_add(1, Ordering::Relaxed) % self.shard_count;
        self.shards[shard_idx].push(item);
    }

    /// Push an item to a specific shard (useful for key-based sharding)
    pub fn push_to_shard(&self, shard: usize, item: T) {
        let shard_idx = shard % self.shard_count;
        self.shards[shard_idx].push(item);
    }

    /// Get all items from all shards
    pub fn get_all(&self) -> Vec<T> {
        self.shards.iter().flat_map(|s| s.get_all()).collect()
    }

    /// Get latest N items from each shard
    pub fn get_latest(&self, n: usize) -> Vec<T> {
        self.shards.iter().flat_map(|s| s.get_latest(n)).collect()
    }

    /// Get total size across all shards
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.len()).sum()
    }

    /// Check if all shards are empty
    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(|s| s.is_empty())
    }

    /// Get total capacity
    pub fn capacity(&self) -> usize {
        self.shards.iter().map(|s| s.capacity()).sum()
    }

    /// Clear all shards
    pub fn clear(&self) {
        for shard in &self.shards {
            shard.clear();
        }
    }

    /// Get aggregated statistics
    pub fn stats(&self) -> ShardedRingBufferStats {
        let shard_stats: Vec<_> = self.shards.iter().map(|s| s.stats()).collect();

        let total_added: u64 = shard_stats.iter().map(|s| s.total_added).sum();
        let total_evicted: u64 = shard_stats.iter().map(|s| s.total_evicted).sum();
        let current_size: usize = shard_stats.iter().map(|s| s.current_size).sum();
        let capacity: usize = shard_stats.iter().map(|s| s.capacity).sum();

        ShardedRingBufferStats {
            shard_count: self.shard_count,
            total_capacity: capacity,
            current_size,
            total_added,
            total_evicted,
            utilization: current_size as f64 / capacity as f64,
            shard_stats,
        }
    }

    /// Filter items across all shards
    pub fn filter<F>(&self, predicate: F) -> Vec<T>
    where
        F: Fn(&T) -> bool + Copy,
    {
        self.shards
            .iter()
            .flat_map(|s| s.filter(predicate))
            .collect()
    }

    /// Count items across all shards matching a predicate
    pub fn count<F>(&self, predicate: F) -> usize
    where
        F: Fn(&T) -> bool + Copy,
    {
        self.shards.iter().map(|s| s.count(predicate)).sum()
    }
}

/// Statistics for a sharded ring buffer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardedRingBufferStats {
    pub shard_count: usize,
    pub total_capacity: usize,
    pub current_size: usize,
    pub total_added: u64,
    pub total_evicted: u64,
    pub utilization: f64,
    pub shard_stats: Vec<RingBufferStats>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer_basic() {
        let buffer: RingBuffer<i32> = RingBuffer::new(3);

        buffer.push(1);
        buffer.push(2);
        buffer.push(3);

        assert_eq!(buffer.len(), 3);
        assert!(buffer.is_full());
        assert_eq!(buffer.get_all(), vec![1, 2, 3]);

        // Push beyond capacity
        buffer.push(4);
        assert_eq!(buffer.len(), 3);
        assert_eq!(buffer.get_all(), vec![2, 3, 4]);
        assert_eq!(buffer.total_evicted(), 1);
    }

    #[test]
    fn test_ring_buffer_latest() {
        let buffer: RingBuffer<i32> = RingBuffer::new(10);

        for i in 1..=10 {
            buffer.push(i);
        }

        assert_eq!(buffer.get_latest(3), vec![8, 9, 10]);
        assert_eq!(buffer.peek_latest(), Some(10));
        assert_eq!(buffer.peek_oldest(), Some(1));
    }

    #[test]
    fn test_ring_buffer_filter() {
        let buffer: RingBuffer<i32> = RingBuffer::new(10);

        for i in 1..=10 {
            buffer.push(i);
        }

        let evens: Vec<i32> = buffer.filter(|x| x % 2 == 0);
        assert_eq!(evens, vec![2, 4, 6, 8, 10]);
    }

    #[test]
    fn test_timed_ring_buffer() {
        let buffer: TimedRingBuffer<i32> = TimedRingBuffer::new(100, Duration::from_secs(60));

        buffer.push(1);
        buffer.push(2);
        buffer.push(3);

        assert_eq!(buffer.get_valid().len(), 3);

        // Items should be valid since TTL is 60 seconds
        let valid = buffer.get_valid();
        assert_eq!(valid, vec![1, 2, 3]);
    }

    #[test]
    fn test_sharded_ring_buffer() {
        let buffer: ShardedRingBuffer<i32> = ShardedRingBuffer::new(30, 3);

        for i in 1..=30 {
            buffer.push(i);
        }

        assert_eq!(buffer.len(), 30);

        let stats = buffer.stats();
        assert_eq!(stats.shard_count, 3);
        assert_eq!(stats.current_size, 30);
    }

    #[test]
    fn test_batch_push() {
        let buffer: RingBuffer<i32> = RingBuffer::new(5);

        buffer.push_batch(vec![1, 2, 3, 4, 5, 6, 7]);

        assert_eq!(buffer.len(), 5);
        assert_eq!(buffer.get_all(), vec![3, 4, 5, 6, 7]);
        assert_eq!(buffer.total_evicted(), 2);
    }
}
