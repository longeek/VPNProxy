package pool

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
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
	for i := 0; i < p.maxSize; i++ {
		conn, err := tunnel.Open(ctx, p.cfg, "0.0.0.0", 1, "tcp")
		if err != nil {
			break
		}
		p.mu.Lock()
		p.entries = append(p.entries, entry{conn: conn, created: time.Now()})
		p.mu.Unlock()
	}
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
		fresh := make([]entry, 0, len(p.entries))
		for _, e := range p.entries {
			if now.Sub(e.created) < p.ttl {
				fresh = append(fresh, e)
			} else {
				e.conn.Close()
			}
		}
		p.entries = fresh
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
	p.mu.Lock()
	now := time.Now()
	for len(p.entries) > 0 {
		e := p.entries[len(p.entries)-1]
		p.entries = p.entries[:len(p.entries)-1]
		if now.Sub(e.created) < p.ttl {
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
			if _, err := e.conn.Write(bs); err != nil {
				e.conn.Close()
				continue
			}
			statusBuf := make([]byte, 64)
			n, readErr := e.conn.Read(statusBuf)
			if readErr != nil {
				e.conn.Close()
				continue
			}
			status := string(statusBuf[:n])
			if strings.HasPrefix(status, "OK") {
				p.hits++
				p.mu.Unlock()
				return e.conn, nil
			}
			e.conn.Close()
			continue
		}
		e.conn.Close()
	}
	p.mu.Unlock()

	return tunnel.Open(ctx, p.cfg, targetHost, targetPort, proto)
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