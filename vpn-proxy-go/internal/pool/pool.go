// Package pool provides a pre-warmed TLS connection pool that reduces tunnel
// setup latency by avoiding full TLS handshakes on cache hits.
//
// Architecture:
//   - Lazy fill: starts empty; connections are created on-demand after Acquire
//   - Each Acquire that pops a warm connection triggers async refill of one
//   - A background eviction loop removes stale entries (prevents goroutine leak)
//   - FIFO eviction ensures connections age evenly through the pool
//
// Key difference from a naive pool:
//   - Warm connections are raw TLS sockets (not full bootstrapped tunnels)
//   - Each Acquire sends the target bootstrap + waits for OK (one RTT)
//   - Pool hit saves the full TLS handshake (~2 RTTs) compared to tunnel.Open
//
// Start optimization:
//   - Start() launches the eviction loop and returns immediately
//   - No eager pre-warming — avoids wasted connections when idle
//   - Pool fills naturally during active use
package pool

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"vpn-proxy-go/internal/tunnel"
)

// entry represents a single pooled connection with its creation timestamp.
// TTL is checked on Acquire() and during the eviction loop.
// If reuse=true, the connection is in tunnel-reuse mode: subsequent
// bootstraps must use the chunk protocol instead of raw JSON.
type entry struct {
	conn    net.Conn
	reuse   bool
	created time.Time
}

// Pool is a lazy-fill TLS connection pool.
//
// The pool starts empty. After each Acquire that pops a warm connection,
// one replacement is created asynchronously to maintain up to maxSize
// connections during active use. A background eviction loop removes
// expired entries that were never acquired.
type Pool struct {
	mu      sync.Mutex
	entries []entry
	cfg     *tunnel.Config
	maxSize int           // maximum number of warm connections to maintain
	ttl     time.Duration // max age of a pooled connection before eviction
	hits    uint64        // total pool hits (for diagnostics)
	filling int32         // number of in-flight fill operations
	closed  bool

	// dialFn creates a raw TLS connection for pool warming.
	// Override in tests to avoid real network calls.
	dialFn func(context.Context, *tunnel.Config) (net.Conn, error)
	// openFn creates a fully-bootstrapped tunnel (fallback on pool miss).
	// Override in tests to avoid real network calls.
	openFn func(context.Context, *tunnel.Config, string, uint16, string) (net.Conn, error)
}

// New creates a new Pool. Call Start() to begin the eviction loop.
// dialFn and openFn default to tunnel.DialTunnel and tunnel.Open respectively;
// they are exposed as fields so tests can supply mocks.
func New(cfg *tunnel.Config, maxSize int, ttl time.Duration) *Pool {
	return &Pool{
		cfg:     cfg,
		maxSize: maxSize,
		ttl:     ttl,
		dialFn:  tunnel.DialTunnel,
		openFn:  tunnel.Open,
	}
}

// Start launches the background eviction loop and returns immediately.
// No connections are pre-warmed; the pool fills on demand during active use.
func (p *Pool) Start(ctx context.Context) {
	p.mu.Lock()
	p.closed = false
	p.mu.Unlock()

	go p.evictLoop(ctx)
}

// evictLoop runs periodically to remove expired entries.
// Unlike a traditional fill loop, it never creates new connections —
// filling happens on-demand after Acquire.
func (p *Pool) evictLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}
		now := time.Now()
		n := 0
		for i := 0; i < len(p.entries); i++ {
			if now.Sub(p.entries[i].created) < p.ttl {
				p.entries[n] = p.entries[i]
				n++
			} else {
				p.entries[i].conn.Close()
			}
		}
		p.entries = p.entries[:n]
		p.mu.Unlock()
	}
}

// fillOne creates a single raw TLS connection and adds it to the pool.
// Uses an atomic counter to prevent more than maxSize concurrent fills.
func (p *Pool) fillOne(ctx context.Context) {
	if atomic.AddInt32(&p.filling, 1) > int32(p.maxSize) {
		atomic.AddInt32(&p.filling, -1)
		return
	}
	defer atomic.AddInt32(&p.filling, -1)

	conn, err := p.dialFn(ctx, p.cfg)
	if err != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		conn.Close()
		return
	}
	// Don't exceed maxSize
	if len(p.entries) >= p.maxSize {
		conn.Close()
		return
	}
	p.entries = append(p.entries, entry{conn: conn, created: time.Now()})
}

// bootstrapReuse sends a bootstrap chunk on a reused connection and waits
// for the server's OK chunk. Used for pool entries that have been returned
// via ReleaseReuse.
func (p *Pool) bootstrapReuse(conn net.Conn, targetHost string, targetPort uint16, proto string) error {
	rt := tunnel.NewReusableTunnel(conn)
	payload := tunnel.BootstrapInfo{
		Auth:  p.cfg.Token,
		Host:  targetHost,
		Port:  targetPort,
		Proto: proto,
		Reuse: true,
	}
	if proto == "tcp" {
		payload.Proto = ""
	}
	bs, _ := json.Marshal(payload)
	if err := rt.WriteBootstrapChunk(bs); err != nil {
		return err
	}
	ok, err := rt.ReadOKChunk()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("server refused reuse bootstrap")
	}
	return nil
}

// Acquire pops a warm TLS connection from the pool, sends a bootstrap to
// assign the real target, waits for the server's OK, and returns the
// connection ready for relay.
//
// For reuse-mode entries (returned via ReleaseReuse), the bootstrap is sent
// as a chunk (BOOTSTRAP type). For fresh entries, it is sent as raw JSON.
//
// After each attempt (hit or miss), one async fill is triggered to maintain
// pool depth during active use. This ensures the pool naturally fills up to
// maxSize after the first few requests.
//
// If the pool is empty or all candidates fail (expired TTL, bootstrap
// failure), falls through to tunnel.Open() which establishes a fresh
// fully-bootstrapped connection.
func (p *Pool) Acquire(ctx context.Context, targetHost string, targetPort uint16, proto string) (net.Conn, error) {
	for {
		candidate := p.popEntry()
		if candidate == nil {
			break
		}
		if time.Since(candidate.created) >= p.ttl {
			candidate.conn.Close()
			go p.fillOne(ctx)
			continue
		}
		var berr error
		if candidate.reuse {
			berr = p.bootstrapReuse(candidate.conn, targetHost, targetPort, proto)
		} else {
			berr = p.bootstrap(candidate.conn, targetHost, targetPort, proto)
		}
		if berr != nil {
			candidate.conn.Close()
			go p.fillOne(ctx)
			continue
		}
		// Successful hit — trigger async replacement
		go p.fillOne(ctx)
		atomic.AddUint64(&p.hits, 1)
		n := atomic.LoadUint64(&p.hits)
		log.Printf("pool HIT #%d for %s:%d (reuse=%v)", n, targetHost, targetPort, candidate.reuse)
		return candidate.conn, nil
	}

	log.Printf("pool MISS for %s:%d (size=%d)", targetHost, targetPort, len(p.entries))
	// Trigger async fill on miss so next request might hit
	go p.fillOne(ctx)
	return p.openFn(ctx, p.cfg, targetHost, targetPort, proto)
}

// popEntry removes and returns the oldest entry (FIFO) from the pool.
// Returns nil if the pool is empty.
func (p *Pool) popEntry() *entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.entries) == 0 {
		return nil
	}
	e := p.entries[0]
	p.entries = p.entries[1:]
	return &e
}

// bootstrap sends the target info on a warm TLS connection, waits for
// the server's OK response, and returns nil on success.
func (p *Pool) bootstrap(conn net.Conn, targetHost string, targetPort uint16, proto string) error {
	payload := tunnel.BootstrapInfo{
		Auth:  p.cfg.Token,
		Host:  targetHost,
		Port:  targetPort,
		Proto: proto,
		Reuse: p.cfg.Reuse,
	}
	if proto == "tcp" {
		payload.Proto = ""
	}
	bs, _ := json.Marshal(payload)
	bs = append(bs, '\n')
	if _, err := conn.Write(bs); err != nil {
		return err
	}
	// Read exact status line (terminated by \n).
	// IMPORTANT: do NOT use conn.Read(buf) with a large buffer — the server
	// may send relay data (chunk headers) immediately after "OK\n" and a
	// buffered read would consume those bytes, corrupting the stream.
	statusLine, err := readLine(conn)
	if err != nil {
		return err
	}
	if statusLine == "OK" {
		return nil
	}
	return fmt.Errorf("server refused: %s", statusLine)
}

// Release returns a used connection back to the pool for potential reuse.
// The connection should have completed its relay (not in reuse mode) and
// be ready for a new bootstrap. If the pool is at maxSize or closed, the
// connection is closed immediately.
func (p *Pool) Release(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		conn.Close()
		return
	}
	if len(p.entries) >= p.maxSize {
		conn.Close()
		return
	}
	p.entries = append(p.entries, entry{conn: conn, created: time.Now()})
}

// ReleaseReuse returns a reuse-mode connection back to the pool after a
// chunk-protocol relay. The connection is stored with reuse=true so that a
// subsequent Acquire will use the chunk-based bootstrap (BOOTSTRAP chunk)
// instead of the raw JSON bootstrap.
func (p *Pool) ReleaseReuse(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		conn.Close()
		return
	}
	if len(p.entries) >= p.maxSize {
		conn.Close()
		return
	}
	p.entries = append(p.entries, entry{conn: conn, reuse: true, created: time.Now()})
}

// PoolStats returns the cumulative pool hit count.
func (p *Pool) PoolStats() uint64 {
	return atomic.LoadUint64(&p.hits)
}

// readLine reads from r byte-by-byte until '\n'. This ensures we never
// consume more bytes than the status line itself — critical because the
// server may send relay data immediately after "OK\n".
func readLine(r io.Reader) (string, error) {
	var line []byte
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, one); err != nil {
			return "", err
		}
		if one[0] == '\n' {
			return string(line), nil
		}
		line = append(line, one[0])
	}
}

// Stop closes all pooled connections and stops the eviction loop.
func (p *Pool) Stop() {
	p.mu.Lock()
	p.closed = true
	for _, e := range p.entries {
		e.conn.Close()
	}
	p.entries = nil
	p.mu.Unlock()
}
