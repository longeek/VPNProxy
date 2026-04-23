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

type entry struct {
	conn    net.Conn
	created time.Time
}

type Pool struct {
	mu       sync.Mutex
	entries  []entry
	cfg      *tunnel.Config
	maxSize  int
	ttl      time.Duration
	hits     uint64
	closed   bool
}

func New(cfg *tunnel.Config, maxSize int, ttl time.Duration) *Pool {
	return &Pool{
		cfg:     cfg,
		maxSize: maxSize,
		ttl:     ttl,
	}
}

func (p *Pool) Start(ctx context.Context) {
	p.mu.Lock()
	p.closed = false
	p.mu.Unlock()

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

func (p *Pool) refillLoop(ctx context.Context) {
	for {
		select {
		case <-time.After(300 * time.Millisecond):
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
		need := p.maxSize - len(p.entries)
		p.mu.Unlock()

		if need > 0 {
			conn, err := tunnel.Open(ctx, p.cfg, "0.0.0.0", 1, "tcp")
			if err == nil {
				p.mu.Lock()
				p.entries = append(p.entries, entry{conn: conn, created: time.Now()})
				p.mu.Unlock()
			}
		}
	}
}

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

func (p *Pool) popEntry() *entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.entries) == 0 {
		return nil
	}
	e := p.entries[len(p.entries)-1]
	p.entries = p.entries[:len(p.entries)-1]
	return &e
}

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

func (p *Pool) Stop() {
	p.mu.Lock()
	p.closed = true
	for _, e := range p.entries {
		e.conn.Close()
	}
	p.entries = nil
	p.mu.Unlock()
}