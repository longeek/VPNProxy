// Package pool provides a pre-warmed TLS connection pool that reduces tunnel
// setup latency by avoiding full TLS handshakes on cache hits.
//
// Architecture:
//   - Pre-establishes connections to a dummy target ("0.0.0.0:1") on Start()
//   - On Acquire(), re-bootstraps a pooled connection with the real target
//   - A background refill loop evicts expired entries (TTL) and replenishes
//   - FIFO eviction ensures connections age evenly through the pool
package pool

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vpn-proxy-go/internal/tunnel"
)

// entry represents a single pooled connection with its creation timestamp.
// TTL is checked on Acquire() and during refill loop eviction.
type entry struct {
	conn    net.Conn
	created time.Time
}

// Pool is a pre-warmed TLS connection pool.
//
// The pool maintains a set of connections to the proxy server using a
// dummy target. When a real target is requested via Acquire(), the
// connection is re-bootstrapped with the actual target, avoiding the
// cost of a new TLS handshake.
type Pool struct {
	mu      sync.Mutex
	entries []entry
	cfg     *tunnel.Config
	maxSize int          // maximum number of warm connections to maintain
	ttl     time.Duration // max age of a pooled connection before eviction
	hits    uint64       // total pool hits (for diagnostics)
	closed  bool
}

// New creates a new Pool but does not start it. Call Start() to begin
// pre-warming connections and the background refill loop.
func New(cfg *tunnel.Config, maxSize int, ttl time.Duration) *Pool {
	return &Pool{
		cfg:     cfg,
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// Start pre-warms maxSize connections to the dummy target "0.0.0.0:1" and
// launches the background refill goroutine. Blocks until all initial
// connections are established (or fail, in which case the pool starts
// partially filled).
func (p *Pool) Start(ctx context.Context) {
	p.mu.Lock()
	p.closed = false
	p.mu.Unlock()

	// Concurrently establish all warm connections
	var wg sync.WaitGroup
	var localMu sync.Mutex
	var localEntries []entry
	for i := 0; i < p.maxSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := tunnel.Open(ctx, p.cfg, "0.0.0.0", 1, "tcp")
			if err == nil {
				localMu.Lock()
				localEntries = append(localEntries, entry{conn: conn, created: time.Now()})
				localMu.Unlock()
			}
		}()
	}
	wg.Wait()

	p.mu.Lock()
	p.entries = localEntries
	p.mu.Unlock()
	go p.refillLoop(ctx)
}

// refillLoop runs in a background goroutine, ticking every 300ms to:
//  1. Evict entries whose TTL has expired
//  2. Replenish up to maxSize connections (batch creates all missing at once)
//
// Uses batch creation rather than single-connection per cycle to avoid
// slow ramp-up when the pool is completely empty.
func (p *Pool) refillLoop(ctx context.Context) {
	ticker := time.NewTicker(300 * time.Millisecond)
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

		// In-place compaction: keep non-expired entries, close expired ones.
		// This avoids allocating a new slice on every tick.
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
		need := p.maxSize - len(p.entries)
		p.mu.Unlock()

		if need <= 0 {
			continue
		}

		// Batch-create all needed connections (faster than 1-per-cycle)
		var fresh []entry
		for i := 0; i < need; i++ {
			conn, err := tunnel.Open(ctx, p.cfg, "0.0.0.0", 1, "tcp")
			if err != nil {
				break
			}
			fresh = append(fresh, entry{conn: conn, created: time.Now()})
		}
		if len(fresh) > 0 {
			p.mu.Lock()
			p.entries = append(p.entries, fresh...)
			p.mu.Unlock()
		}
	}
}

// Acquire pops a warm connection from the pool, re-bootstraps it to the
// requested target, and returns it. If the pool is empty or all candidates
// fail (expired TTL, bootstrap failure), falls through to tunnel.Open()
// which establishes a fresh connection.
func (p *Pool) Acquire(ctx context.Context, targetHost string, targetPort uint16, proto string) (net.Conn, error) {
	for {
		candidate := p.popEntry()
		if candidate == nil {
			break
		}
		if time.Since(candidate.created) >= p.ttl {
			candidate.conn.Close()
			continue
		}
		result, err := p.bootstrap(candidate.conn, targetHost, targetPort, proto)
		if err != nil {
			candidate.conn.Close()
			continue
		}
		if result {
			atomic.AddUint64(&p.hits, 1)
			return candidate.conn, nil
		}
		candidate.conn.Close()
	}

	return tunnel.Open(ctx, p.cfg, targetHost, targetPort, proto)
}

// popEntry removes and returns the oldest entry (FIFO) from the pool.
// Returns nil if the pool is empty.
//
// FIFO ordering ensures connections age evenly: older connections are
// consumed first, preventing long-lived unused entries at the front
// of the slice.
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

// bootstrap sends the actual target info over a warm connection and
// waits for the server's OK response. Returns true if the server
// accepted the re-bootstrap, false+error otherwise.
func (p *Pool) bootstrap(conn net.Conn, targetHost string, targetPort uint16, proto string) (bool, error) {
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
		return false, err
	}
	statusBuf := make([]byte, 128)
	n, err := conn.Read(statusBuf)
	if err != nil {
		return false, err
	}
	status := string(statusBuf[:n])
	if strings.HasPrefix(status, "OK") {
		return true, nil
	}
	return false, fmt.Errorf("server refused: %s", strings.TrimSpace(status))
}

// Stop closes all pooled connections and stops the refill loop.
// Safe to call multiple times.
func (p *Pool) Stop() {
	p.mu.Lock()
	p.closed = true
	for _, e := range p.entries {
		e.conn.Close()
	}
	p.entries = nil
	p.mu.Unlock()
}
