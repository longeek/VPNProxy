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
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vpn-proxy-go/internal/tunnel"
)

// entry represents a single pooled connection with its creation timestamp.
// TTL is checked on Acquire() and during the eviction loop.
type entry struct {
	conn    net.Conn
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

// Acquire pops a warm TLS connection from the pool, sends a bootstrap to
// assign the real target, waits for the server's OK, and returns the
// connection ready for relay.
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
			// Trigger async fill after discarding expired entry
			go p.fillOne(ctx)
			continue
		}
		if err := p.bootstrap(candidate.conn, targetHost, targetPort, proto); err != nil {
			candidate.conn.Close()
			// Trigger async fill after failed bootstrap
			go p.fillOne(ctx)
			continue
		}
		// Successful hit — trigger async replacement
		go p.fillOne(ctx)
		atomic.AddUint64(&p.hits, 1)
		n := atomic.LoadUint64(&p.hits)
		log.Printf("pool HIT #%d for %s:%d", n, targetHost, targetPort)
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
	}
	if proto == "tcp" {
		payload.Proto = ""
	}
	bs, _ := json.Marshal(payload)
	bs = append(bs, '\n')
	if _, err := conn.Write(bs); err != nil {
		return err
	}
	statusBuf := make([]byte, 128)
	n, err := conn.Read(statusBuf)
	if err != nil {
		return err
	}
	status := string(statusBuf[:n])
	if strings.HasPrefix(status, "OK") {
		return nil
	}
	return fmt.Errorf("server refused: %s", strings.TrimSpace(status))
}

// PoolStats returns the cumulative pool hit count.
func (p *Pool) PoolStats() uint64 {
	return atomic.LoadUint64(&p.hits)
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
