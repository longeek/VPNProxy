//! A FIFO TCP connection pool with batch refill.
//!
//! Maintains a set of reusable [`TcpStream`] connections to amortize
//! connection setup latency. Connections are popped from the front
//! (oldest first) and returned to the back. When the pool is empty,
//! `get()` creates a batch of new connections at once.
//!
//! # Thread safety
//!
//! All mutable state is protected by `tokio::sync::Mutex`, making the pool
//! safe to share across async tasks via `Arc<Pool>`. Concurrent batch
//! refills on an empty pool are prevented by capping at `max_size` when
//! storing extra connections — if another task already refilled, extras
//! are silently closed.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// A pooled connection with its creation timestamp.
struct PooledConn {
    stream: TcpStream,
    created_at: Instant,
}

/// Mutable inner state behind `Pool.inner`.
struct PoolInner {
    conns: VecDeque<PooledConn>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// A FIFO connection pool for [`TcpStream`].
///
/// Connections are acquired with [`Pool::get`] and returned with
/// [`Pool::put`]. When the pool is empty, a batch of up to `max_size`
/// connections is created at once to amortize setup latency.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
/// use vpn_proxy::pool::Pool;
///
/// # async fn example() {
/// let pool = Pool::new("127.0.0.1:8080".into(), 8, Duration::from_secs(30));
/// let mut stream = pool.get().await.unwrap();
/// // ... use the stream ...
/// pool.put(stream).await;
/// # }
/// ```
pub struct Pool {
    inner: Mutex<PoolInner>,
    addr: String,
    max_size: usize,
    idle_timeout: Duration,
}

impl Pool {
    /// Create a new connection pool wrapped in [`Arc`].
    ///
    /// * `addr` — the `host:port` to connect to (e.g. `"127.0.0.1:8080"`)
    /// * `max_size` — maximum number of idle connections to retain
    /// * `idle_timeout` — max age of an idle connection; expired
    ///   connections are discarded on the next `get()`
    pub fn new(addr: String, max_size: usize, idle_timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(PoolInner {
                conns: VecDeque::new(),
            }),
            addr,
            max_size,
            idle_timeout,
        })
    }

    /// Acquire a [`TcpStream`] from the pool.
    ///
    /// Pops the oldest **valid** connection (FIFO). If the pool is empty
    /// or all cached connections have expired, a batch of up to
    /// `max_size` new connections is created and one is returned
    /// immediately (the rest are parked in the pool for future calls).
    pub async fn get(&self) -> std::io::Result<TcpStream> {
        // Fast path — drain expired and return first valid connection.
        {
            let mut inner = self.inner.lock().await;
            while let Some(pc) = inner.conns.pop_front() {
                if pc.created_at.elapsed() < self.idle_timeout {
                    return Ok(pc.stream);
                }
                // Expired: drop closes the underlying stream.
            }
        }

        // Pool empty or all expired — batch-create new connections.
        self.batch_refill().await
    }

    /// Return a [`TcpStream`] to the pool for reuse.
    ///
    /// If the pool already holds `max_size` idle connections, the stream
    /// is closed instead (the oldest entries are kept).
    pub async fn put(&self, stream: TcpStream) {
        let mut inner = self.inner.lock().await;
        if inner.conns.len() < self.max_size {
            inner.conns.push_back(PooledConn {
                stream,
                created_at: Instant::now(),
            });
        }
        // else: drop closes the stream
    }

    /// Release (close) a [`TcpStream`] without returning it to the pool.
    ///
    /// Use this when the connection encountered an error and should not
    /// be reused.
    pub async fn release(&self, stream: TcpStream) {
        drop(stream);
    }

    /// Number of idle connections currently in the pool.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.conns.len()
    }

    /// Returns `true` if the pool holds no idle connections.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Batch-create up to `max_size` new connections.
    ///
    /// Returns one connection to the caller and stores the rest in the pool.
    /// If *no* connections could be made, returns the last I/O error.
    ///
    /// Storing is capped at `self.max_size` to gracefully handle concurrent
    /// batch refills from multiple tasks (thundering herd): if another task
    /// already refilled the pool, excess connections are silently closed.
    async fn batch_refill(&self) -> std::io::Result<TcpStream> {
        let batch_size = self.max_size.max(1);
        let mut fresh: Vec<TcpStream> = Vec::with_capacity(batch_size);

        for _ in 0..batch_size {
            match TcpStream::connect(&self.addr).await {
                Ok(s) => fresh.push(s),
                Err(e) => {
                    // Return error only if we couldn't make *any* connection.
                    if fresh.is_empty() {
                        return Err(e);
                    }
                    break;
                }
            }
        }

        // First connection goes to the caller.
        let first = fresh.remove(0);
        Self::set_socket_opts(&first);

        // Remaining connections go into the pool (capped at max_size).
        {
            let mut inner = self.inner.lock().await;
            for s in fresh {
                if inner.conns.len() < self.max_size {
                    Self::set_socket_opts(&s);
                    inner.conns.push_back(PooledConn {
                        stream: s,
                        created_at: Instant::now(),
                    });
                }
                // else: drop closes the extra connection
            }
        }

        Ok(first)
    }

    /// Apply standard socket options (nodelay, large buffers).
    fn set_socket_opts(stream: &TcpStream) {
        use socket2::SockRef;
        let sock = SockRef::from(stream);
        let _ = sock.set_nodelay(true);
        // 256 KB buffers match the existing project constants.
        let _ = sock.set_recv_buffer_size(256 * 1024);
        let _ = sock.set_send_buffer_size(256 * 1024);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Bind a test echo server on a dynamic port.
    /// Returns (port, shutdown_tx) — drop the sender to stop the server.
    async fn start_echo_server() -> (u16, tokio::sync::oneshot::Sender<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut rx => break,
                    result = listener.accept() => {
                        if let Ok((mut stream, _)) = result {
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                loop {
                                    match stream.read(&mut buf).await {
                                        Ok(0) => break,
                                        Ok(n) => {
                                            if stream.write_all(&buf[..n]).await.is_err() { break; }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });
                        }
                    }
                }
            }
        });

        (port, tx)
    }

    // -----------------------------------------------------------------------
    // Basic get / put round-trip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_get_put_roundtrip() {
        let (port, _shutdown) = start_echo_server().await;
        let addr = format!("127.0.0.1:{port}");
        let pool = Pool::new(addr, 1, Duration::from_secs(60));

        assert!(pool.is_empty().await);

        // max_size=1 so batch creates 1 connection, stores 0, returns 1.
        let mut stream = pool.get().await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let mut buf = vec![0u8; 5];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // put it back — pool now has 1 idle.
        pool.put(stream).await;
        assert_eq!(pool.len().await, 1);
    }

    // -----------------------------------------------------------------------
    // FIFO ordering (VecDeque pop_front / push_back)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_fifo_ordering() {
        let (port, _shutdown) = start_echo_server().await;
        let addr = format!("127.0.0.1:{port}");
        let pool = Pool::new(addr, 2, Duration::from_secs(60));

        // get() on empty creates batch of 2, stores 1, returns 1.
        let s1 = pool.get().await.unwrap();
        // At this point the pool has 1 idle from s1's batch. We get it.
        let s2 = pool.get().await.unwrap();

        // Both connections should be usable.
        pool.put(s1).await;
        pool.put(s2).await;
        // max_size=2 so both are retained.
        assert_eq!(pool.len().await, 2);

        // Both should still be retrievable and valid.
        let _r1 = pool.get().await.unwrap();
        let _r2 = pool.get().await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Max-size enforcement in put()
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_max_size_respected() {
        let (port, _shutdown) = start_echo_server().await;
        let addr = format!("127.0.0.1:{port}");
        let pool = Pool::new(addr, 2, Duration::from_secs(60));

        // Batch logic: each get() on empty creates 2 conns, stores 1.
        let s1 = pool.get().await.unwrap(); // pool now has 1 idle
        let s2 = pool.get().await.unwrap(); // pool now has 1 idle
        let s3 = pool.get().await.unwrap(); // pool now has 1 idle

        pool.put(s1).await; // pool: 2 (full)
        pool.put(s2).await; // dropped — pool at capacity
        pool.put(s3).await; // dropped — pool at capacity

        assert_eq!(pool.len().await, 2);
    }

    // -----------------------------------------------------------------------
    // Idle timeout eviction
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_idle_timeout_eviction() {
        let (port, _shutdown) = start_echo_server().await;
        let addr = format!("127.0.0.1:{port}");
        // Very short timeout so connections expire quickly.
        let pool = Pool::new(addr, 1, Duration::from_millis(10));

        // max_size=1: get() creates 1, stores 0, put() adds 1.
        let s1 = pool.get().await.unwrap();
        pool.put(s1).await;
        assert_eq!(pool.len().await, 1);

        // Wait past the idle timeout.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // get() should expire the pooled connection and create a new one.
        let _s2 = pool.get().await.unwrap();
        // max_size=1 → batch creates 1, stores 0.
        assert_eq!(pool.len().await, 0);
    }

    // -----------------------------------------------------------------------
    // release() does not return connection to pool
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_release_closes() {
        let (port, _shutdown) = start_echo_server().await;
        let addr = format!("127.0.0.1:{port}");
        let pool = Pool::new(addr, 1, Duration::from_secs(60));

        // max_size=1: get() creates 1, stores 0.
        let s1 = pool.get().await.unwrap();
        assert_eq!(pool.len().await, 0);

        pool.release(s1).await; // should close, not return to pool
        assert_eq!(pool.len().await, 0);
    }

    // -----------------------------------------------------------------------
    // Batch refill on empty pool
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_batch_refill_empty_pool() {
        let (port, _shutdown) = start_echo_server().await;
        let addr = format!("127.0.0.1:{port}");
        let pool = Pool::new(addr, 8, Duration::from_secs(60));

        // Pool is empty. get() should batch-create 8 connections.
        let _s = pool.get().await.unwrap();
        // 7 should remain in the pool (8 created - 1 returned).
        assert_eq!(pool.len().await, 7);
    }

    // -----------------------------------------------------------------------
    // All expired → batch refill
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_get_after_all_expired() {
        let (port, _shutdown) = start_echo_server().await;
        let addr = format!("127.0.0.1:{port}");
        let pool = Pool::new(addr, 2, Duration::from_millis(10));

        // Fill pool to max_size=2.
        // Each get() creates 2, stores 1; put() adds back = 2 total.
        let s1 = pool.get().await.unwrap(); // pool: [a]
        let s2 = pool.get().await.unwrap(); // pool: [b]
        pool.put(s1).await; // pool: [b, s1]
        pool.put(s2).await; // pool: [b, s1, s2] capped at 2 → [s1, s2]
        assert_eq!(pool.len().await, 2);

        // Wait for all to expire.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // get() discards both expired, batch-creates 2 fresh, stores 1.
        let _s = pool.get().await.unwrap();
        assert_eq!(pool.len().await, 1);
    }

    // -----------------------------------------------------------------------
    // Concurrent access — functional correctness
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_concurrent_access() {
        let (port, _shutdown) = start_echo_server().await;
        let addr = format!("127.0.0.1:{port}");
        let pool = Pool::new(addr, 4, Duration::from_secs(60));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let p = pool.clone();
            handles.push(tokio::spawn(async move {
                let mut s = p.get().await.unwrap();
                s.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                s.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
                p.put(s).await;
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Pool should have no more than max_size idle connections.
        assert!(
            pool.len().await <= 4,
            "pool len {} exceeds max_size 4",
            pool.len().await
        );
    }
}
