package pool

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vpn-proxy-go/internal/tunnel"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// pipeConn returns a connected pipe pair. The "server" goroutine reads one
// bootstap line then writes `resp` (typically "OK\n"). After that the caller
// gets the client end as the "connection".
func pipeConn(resp string) net.Conn {
	client, server := net.Pipe()
	go func() {
		// Drain the bootstrap line the pool will send
		buf := make([]byte, 4096)
		server.Read(buf)
		server.Write([]byte(resp))
		server.Close()
	}()
	return client
}

// closedPipeConn returns a pipe whose server side closes immediately.
func closedPipeConn() net.Conn {
	client, server := net.Pipe()
	server.Close()
	return client
}

// mockDialFn returns a function that creates a mock "TLS" connection.
// If resp is "" the connection returned is a closed pipe (dial failure sim).
func mockDialFn(resp string) func(context.Context, *tunnel.Config) (net.Conn, error) {
	return func(_ context.Context, _ *tunnel.Config) (net.Conn, error) {
		if resp == "" {
			return closedPipeConn(), nil
		}
		return pipeConn(resp), nil
	}
}

// mockOpenFn returns a function that creates a mock fully-bootstrapped tunnel.
func mockOpenFn(resp string) func(context.Context, *tunnel.Config, string, uint16, string) (net.Conn, error) {
	return func(_ context.Context, _ *tunnel.Config, host string, port uint16, _ string) (net.Conn, error) {
		if resp == "" {
			return nil, net.ErrClosed
		}
		return pipeConn(resp), nil
	}
}

// countDialFn counts how many times dialFn was called.
func countDialFn(t *testing.T, inner func(context.Context, *tunnel.Config) (net.Conn, error)) (func(context.Context, *tunnel.Config) (net.Conn, error), *int32) {
	t.Helper()
	var n int32
	return func(ctx context.Context, cfg *tunnel.Config) (net.Conn, error) {
		atomic.AddInt32(&n, 1)
		return inner(ctx, cfg)
	}, &n
}

// poolSize returns the current number of entries under lock.
func (p *Pool) poolSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// ---------------------------------------------------------------------------
// New / Stop
// ---------------------------------------------------------------------------

func TestNew(t *testing.T) {
	cfg := &tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}
	p := New(cfg, 5, 30*time.Second)
	if p == nil {
		t.Fatal("New returned nil")
	}
	if p.maxSize != 5 {
		t.Errorf("maxSize = %d, want 5", p.maxSize)
	}
	if p.ttl != 30*time.Second {
		t.Errorf("ttl = %v, want 30s", p.ttl)
	}
	// Default function pointers
	if p.dialFn == nil {
		t.Error("dialFn should not be nil")
	}
	if p.openFn == nil {
		t.Error("openFn should not be nil")
	}
}

func TestStop_unstarted(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	p.Stop() // must not panic
}

func TestStop_withEntries(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()

	// Manually insert two mock connections
	c1, _ := net.Pipe()
	c2, _ := net.Pipe()
	p.mu.Lock()
	p.entries = append(p.entries, entry{conn: c1, created: time.Now()}, entry{conn: c2, created: time.Now()})
	p.mu.Unlock()

	p.Stop()

	p.mu.Lock()
	if len(p.entries) != 0 {
		t.Errorf("entries after Stop = %d, want 0", len(p.entries))
	}
	if !p.closed {
		t.Error("closed flag should be true")
	}
	p.mu.Unlock()

	// Verify pipes are closed
	if _, err := c1.Write([]byte("x")); err == nil {
		t.Error("expected closed conn to return error on write")
	}
}

// ---------------------------------------------------------------------------
// popEntry
// ---------------------------------------------------------------------------

func TestPopEntry_empty(t *testing.T) {
	p := New(&tunnel.Config{}, 5, time.Minute)
	if e := p.popEntry(); e != nil {
		t.Error("expected nil for empty pool")
	}
}

func TestPopEntry_fifo(t *testing.T) {
	p := New(&tunnel.Config{}, 5, time.Minute)
	defer p.Stop()

	now := time.Now()
	c1, _ := net.Pipe()
	c2, _ := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	p.mu.Lock()
	p.entries = []entry{
		{conn: c1, created: now},
		{conn: c2, created: now.Add(time.Second)},
	}
	p.mu.Unlock()

	e1 := p.popEntry()
	if e1 == nil || e1.conn != c1 {
		t.Error("first pop should return c1 (FIFO)")
	}
	e2 := p.popEntry()
	if e2 == nil || e2.conn != c2 {
		t.Error("second pop should return c2 (FIFO)")
	}
	if e := p.popEntry(); e != nil {
		t.Error("third pop should return nil")
	}
}

// ---------------------------------------------------------------------------
// Acquire
// ---------------------------------------------------------------------------

func TestAcquire_emptyPool_fallsThrough(t *testing.T) {
	openCount := 0
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()
	p.openFn = func(_ context.Context, _ *tunnel.Config, _ string, _ uint16, _ string) (net.Conn, error) {
		openCount++
		return pipeConn("OK\n"), nil
	}
	p.dialFn = mockDialFn("OK\n")

	conn, err := p.Acquire(context.Background(), "h", 80, "tcp")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	conn.Close()

	if openCount != 1 {
		t.Errorf("openFn called %d times, want 1 (pool empty -> fall through)", openCount)
	}
}

func TestAcquire_hit(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()
	p.dialFn = mockDialFn("OK\n")
	p.openFn = mockOpenFn("OK\n")

	// Pre-populate one entry with a conn that has a server goroutine
	// that will respond "OK\n" to the bootstrap.
	c := pipeConn("OK\n")
	p.mu.Lock()
	p.entries = []entry{{conn: c, created: time.Now()}}
	p.mu.Unlock()

	conn, err := p.Acquire(context.Background(), "h", 80, "tcp")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	conn.Close()

	if atomic.LoadUint64(&p.hits) != 1 {
		t.Errorf("hits = %d, want 1", atomic.LoadUint64(&p.hits))
	}
}

func TestAcquire_expiredEntry_skipped(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, 100*time.Millisecond)
	defer p.Stop()
	p.dialFn = mockDialFn("OK\n")
	p.openFn = mockOpenFn("OK\n")

	// Insert an entry that is already expired
	c, _ := net.Pipe()
	p.mu.Lock()
	p.entries = []entry{{conn: c, created: time.Now().Add(-time.Hour)}}
	p.mu.Unlock()

	conn, err := p.Acquire(context.Background(), "h", 80, "tcp")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	conn.Close()

	h := atomic.LoadUint64(&p.hits)
	// The fillOne goroutine triggered by the expired entry may complete before
	// the next pop, turning the fallthrough into a HIT. Accept both 0 and 1.
	if h != 0 && h != 1 {
		t.Errorf("hits = %d, want 0 or 1 (race: fillOne may add entry before next pop)", h)
	}
}

func TestAcquire_bootstrapFail_skipped(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()
	p.dialFn = mockDialFn("OK\n")
	p.openFn = mockOpenFn("OK\n")

	// Entry with a server that returns ERR (bootstrap will fail)
	c := pipeConn("ERR bad\n")
	p.mu.Lock()
	p.entries = []entry{{conn: c, created: time.Now()}}
	p.mu.Unlock()

	conn, err := p.Acquire(context.Background(), "h", 80, "tcp")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	conn.Close()

	if atomic.LoadUint64(&p.hits) != 0 {
		t.Errorf("hits = %d, want 0 (bootstrap failed, entry discarded)", atomic.LoadUint64(&p.hits))
	}
}

func TestAcquire_multipleEntries_triesAll(t *testing.T) {
	// Two entries: first expired, second valid -> should succeed on second
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()
	p.dialFn = mockDialFn("OK\n")
	p.openFn = mockOpenFn("OK\n")

	c1, _ := net.Pipe()
	c2 := pipeConn("OK\n")
	p.mu.Lock()
	p.entries = []entry{
		{conn: c1, created: time.Now().Add(-time.Hour)}, // expired
		{conn: c2, created: time.Now()},                  // valid
	}
	p.mu.Unlock()

	conn, err := p.Acquire(context.Background(), "h", 80, "tcp")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	conn.Close()

	if atomic.LoadUint64(&p.hits) != 1 {
		t.Errorf("hits = %d, want 1", atomic.LoadUint64(&p.hits))
	}
}

// ---------------------------------------------------------------------------
// fillOne
// ---------------------------------------------------------------------------

func TestFillOne_addsEntry(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()
	p.dialFn = mockDialFn("OK\n")

	p.fillOne(context.Background())
	// fillOne runs synchronously because we didn't call it with "go"
	time.Sleep(50 * time.Millisecond) // just in case of async

	if sz := p.poolSize(); sz != 1 {
		t.Errorf("pool size = %d, want 1", sz)
	}
}

func TestFillOne_respectsMaxSize(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 2, time.Minute)
	defer p.Stop()
	p.dialFn = mockDialFn("OK\n")

	// Fill to max
	c1, _ := net.Pipe()
	c2, _ := net.Pipe()
	p.mu.Lock()
	p.entries = []entry{
		{conn: c1, created: time.Now()},
		{conn: c2, created: time.Now()},
	}
	p.mu.Unlock()

	p.fillOne(context.Background())

	if sz := p.poolSize(); sz != 2 {
		t.Errorf("pool size = %d, want 2 (should not exceed maxSize)", sz)
	}
}

func TestFillOne_closedPool_noop(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	p.dialFn = mockDialFn("OK\n")
	p.Stop()
	p.fillOne(context.Background())

	if sz := p.poolSize(); sz != 0 {
		t.Errorf("pool size = %d, want 0 (closed pool)", sz)
	}
}

func TestFillOne_dialFail_noop(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()
	// dial returns an error (connection refused, timeout, etc.)
	p.dialFn = func(_ context.Context, _ *tunnel.Config) (net.Conn, error) {
		return nil, net.ErrClosed
	}

	p.fillOne(context.Background())
	time.Sleep(50 * time.Millisecond)

	if sz := p.poolSize(); sz != 0 {
		t.Errorf("pool size = %d, want 0 (dial failed, nothing added)", sz)
	}
}

// ---------------------------------------------------------------------------
// Acquire triggers fillOne
// ---------------------------------------------------------------------------

func TestAcquire_triggersFillOnMiss(t *testing.T) {
	dial, dialCount := countDialFn(t, mockDialFn("OK\n"))
	openCount := 0
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()
	p.dialFn = dial
	p.openFn = func(_ context.Context, _ *tunnel.Config, _ string, _ uint16, _ string) (net.Conn, error) {
		openCount++
		return pipeConn("OK\n"), nil
	}

	// First Acquire should miss (pool empty) -> triggers fillOne
	conn, err := p.Acquire(context.Background(), "h", 80, "tcp")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	conn.Close()

	if openCount != 1 {
		t.Errorf("openFn called %d times, want 1", openCount)
	}

	// fillOne runs asynchronously; give it a moment
	time.Sleep(200 * time.Millisecond)

	if *dialCount == 0 {
		t.Error("expected dialFn to be called (async fillOne on miss)")
	}
}

func TestAcquire_triggersFillOnHit(t *testing.T) {
	dial, dialCount := countDialFn(t, mockDialFn("OK\n"))
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()
	p.dialFn = dial
	p.openFn = mockOpenFn("OK\n")

	// Pre-populate a valid entry
	c := pipeConn("OK\n")
	p.mu.Lock()
	p.entries = []entry{{conn: c, created: time.Now()}}
	p.mu.Unlock()

	conn, err := p.Acquire(context.Background(), "h", 80, "tcp")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	conn.Close()

	time.Sleep(200 * time.Millisecond)
	if *dialCount == 0 {
		t.Error("expected dialFn to be called (async fillOne on hit)")
	}
}

// ---------------------------------------------------------------------------
// evictLoop
// ---------------------------------------------------------------------------

func TestEvictLoop_removesExpired(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)

	c1, _ := net.Pipe()
	c2, _ := net.Pipe()
	// Insert one entry that is already past the 1-hour TTL and one fresh.
	old := time.Now().Add(-2 * time.Hour)
	fresh := time.Now()
	p.mu.Lock()
	p.entries = []entry{
		{conn: c1, created: old},
		{conn: c2, created: fresh},
	}
	p.mu.Unlock()

	// Wait for at least one eviction tick (1s interval)
	time.Sleep(1500 * time.Millisecond)

	if sz := p.poolSize(); sz != 1 {
		t.Fatalf("pool size = %d, want 1 (only the fresh entry remains)", sz)
	}

	// The expired conn (c1) should have been closed by the eviction loop.
	// After Close(), Write returns an error.
	if _, err := c1.Write([]byte("x")); err == nil {
		t.Error("expired connection should have been closed")
	}
}

func TestEvictLoop_doesNotRemoveFresh(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)

	c, _ := net.Pipe()
	p.mu.Lock()
	p.entries = []entry{{conn: c, created: time.Now()}}
	p.mu.Unlock()

	time.Sleep(1500 * time.Millisecond)

	if sz := p.poolSize(); sz != 1 {
		t.Errorf("pool size = %d, want 1 (fresh entry should remain)", sz)
	}
}

func TestEvictLoop_withProductionTTL(t *testing.T) {
	// Production TTL is 60 seconds. Verify entries survive at least 3 eviction
	// ticks (3 seconds) without being removed.
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, 60*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)

	c, _ := net.Pipe()
	p.mu.Lock()
	p.entries = []entry{{conn: c, created: time.Now()}}
	p.mu.Unlock()

	// Wait for 3 eviction ticks
	time.Sleep(3500 * time.Millisecond)

	if sz := p.poolSize(); sz != 1 {
		t.Errorf("pool size = %d, want 1 (60s TTL entry should survive 3 ticks)", sz)
	}
}

func TestEvictLoop_stopsOnContextCancel(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	p.Start(ctx)

	// Insert a conn
	c, _ := net.Pipe()
	p.mu.Lock()
	p.entries = []entry{{conn: c, created: time.Now().Add(-time.Hour)}}
	p.mu.Unlock()

	cancel()
	time.Sleep(200 * time.Millisecond) // let the loop exit

	// Pool still has entries (eviction stopped)
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if !closed {
		t.Log("evict loop stopped but pool not marked closed; expected (Stop wasn't called)")
	}
	c.Close()
}

// ---------------------------------------------------------------------------
// Concurrent safety (race detector)
// ---------------------------------------------------------------------------

func TestConcurrentAcquire(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 8, time.Minute)
	p.dialFn = mockDialFn("OK\n")
	p.openFn = mockOpenFn("OK\n")

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := p.Acquire(context.Background(), "h", 80, "tcp")
			if err == nil {
				conn.Close()
			}
		}()
	}
	wg.Wait()
	p.Stop()
}

func TestConcurrentFillAndAcquire(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 8, time.Minute)
	p.dialFn = mockDialFn("OK\n")
	p.openFn = mockOpenFn("OK\n")

	var wg sync.WaitGroup
	// Start fill goroutines
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.fillOne(context.Background())
		}()
	}
	// Meanwhile, acquire
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := p.Acquire(context.Background(), "h", 80, "tcp")
			if err == nil {
				conn.Close()
			}
		}()
	}
	wg.Wait()
	p.Stop()
}

func TestConcurrentPopAndFill(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 8, time.Minute)
	defer p.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.popEntry()
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			c1, c2 := net.Pipe()
			c2.Close()
			p.mu.Lock()
			p.entries = append(p.entries, entry{conn: c1, created: time.Now()})
			p.mu.Unlock()
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// PoolStats
// ---------------------------------------------------------------------------

func TestPoolStats(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()
	p.dialFn = mockDialFn("OK\n")
	p.openFn = mockOpenFn("OK\n")

	if s := p.PoolStats(); s != 0 {
		t.Errorf("initial stats = %d, want 0", s)
	}

	// Insert a valid entry and acquire it to get a hit
	c := pipeConn("OK\n")
	p.mu.Lock()
	p.entries = []entry{{conn: c, created: time.Now()}}
	p.mu.Unlock()

	conn, err := p.Acquire(context.Background(), "h", 80, "tcp")
	if err != nil {
		t.Fatalf("Acquire: %v", err)
	}
	conn.Close()

	if s := p.PoolStats(); s != 1 {
		t.Errorf("stats = %d, want 1", s)
	}
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestAcquire_contextCancelled(t *testing.T) {
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()
	p.dialFn = mockDialFn("OK\n")
	p.openFn = func(_ context.Context, _ *tunnel.Config, _ string, _ uint16, _ string) (net.Conn, error) {
		return nil, context.Canceled
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.Acquire(ctx, "h", 80, "tcp")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestAcquire_udpProto(t *testing.T) {
	// UDP bootstrap should work too (proto set to "udp")
	p := New(&tunnel.Config{Server: "x", ServerPort: 443, Token: "t"}, 5, time.Minute)
	defer p.Stop()
	p.dialFn = mockDialFn("OK\n")
	p.openFn = mockOpenFn("OK\n")

	c := pipeConn("OK\n")
	p.mu.Lock()
	p.entries = []entry{{conn: c, created: time.Now()}}
	p.mu.Unlock()

	conn, err := p.Acquire(context.Background(), "h", 80, "udp")
	if err != nil {
		t.Fatalf("Acquire for UDP: %v", err)
	}
	conn.Close()

	if atomic.LoadUint64(&p.hits) != 1 {
		t.Errorf("hits = %d, want 1", atomic.LoadUint64(&p.hits))
	}
}
