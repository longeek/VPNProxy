package pool

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"vpn-proxy-go/internal/tunnel"
)

// ---------------------------------------------------------------------------
// helpers for reuse tests
// ---------------------------------------------------------------------------

// pipeConnReuse returns a connected pipe pair that simulates a server that
// responds to chunk-based bootstrap.
func pipeConnReuse(respOK bool) net.Conn {
	client, server := net.Pipe()
	go func() {
		// Read bootstrap chunk (4-byte len + type + data)
		// We need to read chunk header, parse it, and respond
		lenBuf := make([]byte, 4)
		_, err := server.Read(lenBuf)
		if err != nil {
			return
		}
		_ = lenBuf // chunk length (we consume it)
		// Read type + payload
		typeBuf := make([]byte, 1)
		server.Read(typeBuf)
		// Read rest of chunk
		payloadLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
		if payloadLen > 1 {
			payload := make([]byte, payloadLen-1)
			server.Read(payload)
		}
		_ = typeBuf // bootstrap type

		if respOK {
			// Write OK chunk: [len=1][typeOK]
			okChunk := []byte{0, 0, 0, 1, tunnel.TypeOK}
			server.Write(okChunk)
		} else {
			// Write ERR chunk: [len=1+err_len][typeOK][err_msg]
			errPayload := []byte{tunnel.TypeOK, 'E', 'R', 'R'}
			errLen := make([]byte, 4)
			errLen[3] = byte(len(errPayload))
			server.Write(errLen)
			server.Write(errPayload)
		}
		server.Close()
	}()
	return client
}

// mockDialFnReuse returns a mock dial function that creates reusable tunnels.
func mockDialFnReuse(respOK bool) func(context.Context, *tunnel.Config) (net.Conn, error) {
	return func(_ context.Context, _ *tunnel.Config) (net.Conn, error) {
		return pipeConnReuse(respOK), nil
	}
}

// mockOpenFnReuse returns a mock open function for reuse mode.
func mockOpenFnReuse(respOK bool) func(context.Context, *tunnel.Config, string, uint16, string) (net.Conn, error) {
	return func(_ context.Context, _ *tunnel.Config, _ string, _ uint16, _ string) (net.Conn, error) {
		if !respOK {
			return nil, net.ErrClosed
		}
		return pipeConnReuse(true), nil
	}
}

// ---------------------------------------------------------------------------
// Release tests
// ---------------------------------------------------------------------------

func TestRelease_basic(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()

	// Release a mock connection
	c1, _ := net.Pipe()
	defer c1.Close()
	p.Release(c1)

	// Pool should have 1 entry
	if sz := p.poolSize(); sz != 1 {
		t.Errorf("pool size after Release = %d, want 1", sz)
	}
}

func TestRelease_respectsMaxSize(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 2, time.Minute)
	defer p.Stop()

	// Fill to max
	c1, _ := net.Pipe()
	c2, _ := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	p.mu.Lock()
	p.entries = []entry{
		{conn: c1, created: time.Now()},
		{conn: c2, created: time.Now()},
	}
	p.mu.Unlock()

	// Try to release another
	c3, _ := net.Pipe()
	c3.Close()
	p.Release(c3)

	if sz := p.poolSize(); sz != 2 {
		t.Errorf("pool size = %d, want 2 (maxSize)", sz)
	}
}

func TestRelease_closedPool(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	p.Stop()

	c, _ := net.Pipe()
	c.Close()
	p.Release(c)

	if sz := p.poolSize(); sz != 0 {
		t.Errorf("pool size after Release on closed = %d, want 0", sz)
	}
}

func TestRelease_thenAcquire(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()
	p.dialFn = mockDialFn("OK\n")
	p.openFn = mockOpenFn("OK\n")

	// Release a connection
	c := pipeConn("OK\n")
	p.Release(c)

	// Acquire should get it
	conn, err := p.Acquire(context.Background(), "h", 80, "tcp")
	if err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
	conn.Close()

	if atomic.LoadUint64(&p.hits) != 1 {
		t.Errorf("hits = %d, want 1", atomic.LoadUint64(&p.hits))
	}
}

func TestRelease_multiple(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()
	p.dialFn = mockDialFn("OK\n")
	p.openFn = mockOpenFn("OK\n")

	// Release 3 connections
	for i := 0; i < 3; i++ {
		c := pipeConn("OK\n")
		p.Release(c)
	}

	if sz := p.poolSize(); sz != 3 {
		t.Errorf("pool size after 3 releases = %d, want 3", sz)
	}

	// Acquire all 3 (should get hits)
	for i := 0; i < 3; i++ {
		conn, err := p.Acquire(context.Background(), "h", 80, "tcp")
		if err != nil {
			t.Fatalf("Acquire #%d: %v", i, err)
		}
		conn.Close()
	}

	if hits := atomic.LoadUint64(&p.hits); hits != 3 {
		t.Errorf("hits = %d, want 3", hits)
	}

	// 4th acquire: may hit or miss (async fillOne may have added a replacement)
	conn, err := p.Acquire(context.Background(), "h", 80, "tcp")
	if err != nil {
		t.Fatalf("Acquire after pool empty: %v", err)
	}
	conn.Close()

	hits := atomic.LoadUint64(&p.hits)
	if hits < 3 {
		t.Errorf("hits = %d, want at least 3 (the 3 released conns)", hits)
	}
}

// ---------------------------------------------------------------------------
// Concurrent Release and Acquire
// ---------------------------------------------------------------------------

func TestConcurrentReleaseAndAcquire(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()
	p.dialFn = mockDialFn("OK\n")
	p.openFn = mockOpenFn("OK\n")

	// Concurrently release and acquire
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10; i++ {
			c := pipeConn("OK\n")
			p.Release(c)
			time.Sleep(5 * time.Millisecond)
		}
		close(done)
	}()

	for i := 0; i < 10; i++ {
		conn, err := p.Acquire(context.Background(), "h", 80, "tcp")
		if err != nil {
			t.Logf("Acquire #%d miss (expected under contention): %v", i, err)
		} else {
			conn.Close()
		}
	}
	<-done
}
