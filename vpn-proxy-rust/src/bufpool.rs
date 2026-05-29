//! Buffer pool for reuse of write buffers.
//!
//! Analogous to Go's `sync.Pool` for `bufio.Writer` buffers in the tunnel module.
//! Uses `thread_local!` with `RefCell` for per-thread buffer reuse,
//! reducing allocations and GC pressure during high-throughput relay operations.
//!
//! Each buffer is pre-sized to [`BUF_SIZE`] (128 KB), matching the Go-side
//! `PipeBufSize` / `DrainThreshold` constant.

use std::cell::RefCell;

/// Buffer size constant: 128 KB, matching `DrainThreshold` in the Go tunnel code.
pub const BUF_SIZE: usize = 128 * 1024;

thread_local! {
    /// Per-thread pool of reusable byte buffers (`Vec<u8>`).
    ///
    /// `RefCell` provides interior mutability so the pool can be mutated
    /// through a shared reference, matching the semantics of Go's `sync.Pool`.
    static POOL: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

/// A pool of reusable byte buffers for write operations.
///
/// This is a zero-sized type; all buffer storage is thread-local. The struct
/// serves as an API handle with `get_buffer()` / `put_buffer()` semantics
/// replicating Go's `sync.Pool` pattern for byte buffers.
///
/// # Example
///
/// ```ignore
/// use bufpool::BufPool;
///
/// let pool = BufPool::new();
/// let mut buf = pool.get_buffer();
/// buf.extend_from_slice(b"relay data");
/// // ... use buf ...
/// pool.put_buffer(buf);
/// ```
pub struct BufPool;

impl BufPool {
    /// Creates a new `BufPool`.
    ///
    /// The pool is stateless — all buffer storage is thread-local,
    /// so construction is a no-op.
    pub const fn new() -> Self {
        Self
    }

    /// Retrieves a buffer from the pool, or allocates a new one if the pool is empty.
    ///
    /// Returned buffers are cleared (`len = 0`) but retain their pre-allocated
    /// capacity, so subsequent writes start from index 0 with zero reallocation
    /// for writes up to [`BUF_SIZE`].
    pub fn get_buffer(&self) -> Vec<u8> {
        POOL.with(|pool| {
            let mut pool = pool.borrow_mut();
            if let Some(mut buf) = pool.pop() {
                buf.clear();
                buf
            } else {
                Vec::with_capacity(BUF_SIZE)
            }
        })
    }

    /// Returns a buffer to the pool for reuse.
    ///
    /// To prevent memory bloat from oversized buffers (e.g. after writing a large
    /// payload), any buffer whose capacity exceeds `2 * BUF_SIZE` is discarded
    /// and replaced with a fresh empty buffer of the standard size.
    pub fn put_buffer(&self, buf: Vec<u8>) {
        POOL.with(|pool| {
            let mut pool = pool.borrow_mut();
            if buf.capacity() > BUF_SIZE * 2 {
                // Discard oversized buffer; push a standard-sized replacement
                // to avoid unbounded memory growth in long-lived threads.
                pool.push(Vec::with_capacity(BUF_SIZE));
            } else {
                pool.push(buf);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_buffer_returns_cleared_buffer() {
        let pool = BufPool::new();
        let buf = pool.get_buffer();
        assert!(buf.is_empty());
        assert!(buf.capacity() >= BUF_SIZE);
    }

    #[test]
    fn test_put_and_get_reuses_buffer() {
        let pool = BufPool::new();
        let mut buf = pool.get_buffer();
        buf.extend_from_slice(b"hello world");
        pool.put_buffer(buf);

        // Get another buffer — should be from the pool (cleared)
        let buf2 = pool.get_buffer();
        assert!(buf2.is_empty());
        // Capacity should be at least BUF_SIZE
        assert!(buf2.capacity() >= BUF_SIZE);
    }

    #[test]
    fn test_put_oversized_buffer_is_replaced() {
        let pool = BufPool::new();
        // Create a buffer larger than 2 * BUF_SIZE
        let oversized = vec![0u8; BUF_SIZE * 3];
        pool.put_buffer(oversized);

        // Should get a standard-sized buffer back
        let buf = pool.get_buffer();
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), BUF_SIZE);
    }

    #[test]
    fn test_get_buffer_allocates_when_empty() {
        let pool = BufPool::new();
        // Thread-local pool is empty for this test thread
        let buf = pool.get_buffer();
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), BUF_SIZE);
    }

    #[test]
    fn test_multiple_buffers_pooled() {
        let pool = BufPool::new();
        let buf1 = pool.get_buffer();
        let buf2 = pool.get_buffer();
        let buf3 = pool.get_buffer();

        pool.put_buffer(buf1);
        pool.put_buffer(buf2);
        pool.put_buffer(buf3);

        // All three returned buffers should be reusable
        for _ in 0..3 {
            let b = pool.get_buffer();
            assert!(b.is_empty());
            assert!(b.capacity() >= BUF_SIZE);
        }
    }

    #[test]
    fn test_buf_size_constant() {
        assert_eq!(BUF_SIZE, 131_072);
        assert_eq!(BUF_SIZE, 128 * 1024);
    }

    #[test]
    fn test_pool_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<BufPool>();
    }

    #[test]
    fn test_pool_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<BufPool>();
    }
}
