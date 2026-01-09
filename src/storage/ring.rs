//! Ring module - re-exports from ring_buffer for convenience
//!
//! This module provides a clean public API for ring buffer types,
//! re-exporting the core types from the ring_buffer module.

pub use super::ring_buffer::{
    RingBuffer, RingBufferStats, ShardedRingBuffer, ShardedRingBufferStats, TimedRingBuffer,
    TimedRingBufferStats, TimestampedItem,
};

/// Default capacity for ring buffers
pub const DEFAULT_CAPACITY: usize = 100_000;

/// Default shard count for sharded ring buffers
pub const DEFAULT_SHARD_COUNT: usize = 16;

/// Create a new ring buffer with default capacity
pub fn default_ring_buffer<T: Clone>() -> RingBuffer<T> {
    RingBuffer::new(DEFAULT_CAPACITY)
}

/// Create a new sharded ring buffer with default settings
pub fn default_sharded_buffer<T: Clone + Send + Sync>() -> ShardedRingBuffer<T> {
    ShardedRingBuffer::new(DEFAULT_CAPACITY, DEFAULT_SHARD_COUNT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_ring_buffer() {
        let buffer: RingBuffer<i32> = default_ring_buffer();
        assert_eq!(buffer.capacity(), DEFAULT_CAPACITY);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_default_sharded_buffer() {
        let buffer: ShardedRingBuffer<i32> = default_sharded_buffer();
        assert_eq!(buffer.capacity(), DEFAULT_CAPACITY);
        assert!(buffer.is_empty());
    }
}
