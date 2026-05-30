package selector

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"vpn-proxy-go/internal/tunnel"
)

// ---------------------------------------------------------------------------
// benchmark pipe helpers
// ---------------------------------------------------------------------------

// benchmarkPipeConn returns a net.Conn backed by a goroutine that simulates
// the server side of probeViaTunnel: reads bootstrap JSON, waits the given
// delay, writes the response (typically "OK\n"), reads an HTTP request,
// then writes one response byte.
func benchmarkPipeConn(delay time.Duration, response string) net.Conn {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buf := make([]byte, 4096)

		n, err := server.Read(buf)
		if err != nil {
			return
		}
		// Validate that the probe sent valid bootstrap JSON
		if err := json.Unmarshal(buf[:n], &tunnel.BootstrapInfo{}); err != nil {
			return
		}

		// Simulate network/server latency
		time.Sleep(delay)

		if _, err := server.Write([]byte(response)); err != nil {
			return
		}

		// Read HTTP request
		if _, err := server.Read(buf); err != nil {
			return
		}

		// Write first byte of response data
		server.Write([]byte("H"))
	}()
	return client
}

// failDialConn returns a conn that closes immediately — simulates a
// server that fails during TLS handshake or is unreachable.
func failDialConn() net.Conn {
	client, server := net.Pipe()
	server.Close()
	return client
}

// dropAfterBootstrapConn reads bootstrap then closes without writing
// OK — simulates a server crashing mid-handshake.
func dropAfterBootstrapConn() net.Conn {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buf := make([]byte, 4096)
		server.Read(buf)
		// Close without writing anything
	}()
	return client
}

// mockDialFn returns a function that routes to different pipe conns based on port.
// It returns the conn for serverPort; if not found, returns a closed pipe.
type mockEntry struct {
	port uint16
	conn net.Conn
}

func mockDialFn(entries ...mockEntry) func(context.Context, *tunnel.Config) (net.Conn, error) {
	table := make(map[uint16]net.Conn)
	for _, e := range entries {
		table[e.port] = e.conn
	}
	return func(_ context.Context, cfg *tunnel.Config) (net.Conn, error) {
		if c, ok := table[cfg.ServerPort]; ok {
			return c, nil
		}
		return failDialConn(), nil
	}
}

// ---------------------------------------------------------------------------
// SelectByBenchmark
// ---------------------------------------------------------------------------

func TestSelectByBenchmark_choosesFastest(t *testing.T) {
	// Two servers: port 1 has 100ms delay, port 2 has 10ms delay.
	// The function should pick the faster one (port 2).
	orig := dialTunnelFn
	defer func() { dialTunnelFn = orig }()

	dialTunnelFn = mockDialFn(
		mockEntry{port: 1, conn: benchmarkPipeConn(100*time.Millisecond, "OK\n")},
		mockEntry{port: 2, conn: benchmarkPipeConn(10*time.Millisecond, "OK\n")},
	)

	servers := []Server{
		{Host: "slow.test", Port: 1},
		{Host: "fast.test", Port: 2},
	}

	best, latency, err := SelectByBenchmark(context.Background(), servers, "token", true)
	if err != nil {
		t.Fatalf("SelectByBenchmark failed: %v", err)
	}
	if best.Port != 2 {
		t.Errorf("expected fast server (port 2), got %s (port %d)", best.Addr(), best.Port)
	}
	if latency < 1*time.Millisecond || latency > 500*time.Millisecond {
		t.Errorf("latency %v seems unreasonable (expected ~10-100ms)", latency)
	}
}

func TestSelectByBenchmark_allFail(t *testing.T) {
	orig := dialTunnelFn
	defer func() { dialTunnelFn = orig }()

	// Both servers will return a closed pipe (dial "failure")
	dialTunnelFn = mockDialFn(
		mockEntry{port: 1, conn: failDialConn()},
		mockEntry{port: 2, conn: failDialConn()},
	)

	servers := []Server{
		{Host: "dead1.test", Port: 1},
		{Host: "dead2.test", Port: 2},
	}

	_, _, err := SelectByBenchmark(context.Background(), servers, "token", true)
	if err == nil {
		t.Fatal("expected error when all servers fail")
	}
}

func TestSelectByBenchmark_oneSucceeds(t *testing.T) {
	orig := dialTunnelFn
	defer func() { dialTunnelFn = orig }()

	// Port 1 fails, port 2 succeeds
	dialTunnelFn = mockDialFn(
		mockEntry{port: 1, conn: failDialConn()},
		mockEntry{port: 2, conn: benchmarkPipeConn(20*time.Millisecond, "OK\n")},
	)

	servers := []Server{
		{Host: "dead.test", Port: 1},
		{Host: "alive.test", Port: 2},
	}

	best, _, err := SelectByBenchmark(context.Background(), servers, "token", true)
	if err != nil {
		t.Fatalf("expected success for one alive server, got: %v", err)
	}
	if best.Port != 2 {
		t.Errorf("expected port 2 (alive), got port %d", best.Port)
	}
}

func TestSelectByBenchmark_serverRejects(t *testing.T) {
	orig := dialTunnelFn
	defer func() { dialTunnelFn = orig }()

	// Server responds with "ERR" instead of "OK"
	dialTunnelFn = mockDialFn(
		mockEntry{port: 1, conn: benchmarkPipeConn(5*time.Millisecond, "ERR bad token\n")},
	)

	servers := []Server{
		{Host: "reject.test", Port: 1},
	}

	_, _, err := SelectByBenchmark(context.Background(), servers, "token", true)
	if err == nil {
		t.Fatal("expected error when server rejects bootstrap")
	}
}

func TestSelectByBenchmark_serverDrops(t *testing.T) {
	orig := dialTunnelFn
	defer func() { dialTunnelFn = orig }()

	// Server reads bootstrap then hangs up without writing anything
	dialTunnelFn = mockDialFn(
		mockEntry{port: 1, conn: dropAfterBootstrapConn()},
	)

	servers := []Server{
		{Host: "drop.test", Port: 1},
	}

	_, _, err := SelectByBenchmark(context.Background(), servers, "token", true)
	if err == nil {
		t.Fatal("expected error when server drops connection after bootstrap")
	}
}

func TestSelectByBenchmark_emptyServers(t *testing.T) {
	_, _, err := SelectByBenchmark(context.Background(), nil, "token", true)
	if err == nil {
		t.Fatal("expected error for empty server list")
	}
}

func TestSelectByBenchmark_singleServer(t *testing.T) {
	orig := dialTunnelFn
	defer func() { dialTunnelFn = orig }()

	dialTunnelFn = mockDialFn(
		mockEntry{port: 1, conn: benchmarkPipeConn(15*time.Millisecond, "OK\n")},
	)

	servers := []Server{
		{Host: "single.test", Port: 1},
	}

	best, latency, err := SelectByBenchmark(context.Background(), servers, "token", true)
	if err != nil {
		t.Fatalf("SelectByBenchmark failed: %v", err)
	}
	if best.Port != 1 {
		t.Errorf("expected port 1, got port %d", best.Port)
	}
	if latency < 1*time.Millisecond || latency > 500*time.Millisecond {
		t.Errorf("latency %v seems unreasonable", latency)
	}
}

// ---------------------------------------------------------------------------
// SelectFastest (existing, regression)
// ---------------------------------------------------------------------------

func TestSelectFastest_choosesFastest(t *testing.T) {
	// Create two local listeners. Both accept and close immediately.
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln1.Close()

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()

	// Both listeners accept and close immediately
	go func() {
		conn, err := ln1.Accept()
		if err == nil {
			conn.Close()
		}
	}()
	go func() {
		conn, err := ln2.Accept()
		if err == nil {
			conn.Close()
		}
	}()

	_, port1, _ := net.SplitHostPort(ln1.Addr().String())
	_, port2, _ := net.SplitHostPort(ln2.Addr().String())

	var p1, p2 uint16
	_, err = fmt.Sscanf(port1, "%d", &p1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fmt.Sscanf(port2, "%d", &p2)
	if err != nil {
		t.Fatal(err)
	}

	servers := []Server{
		{Host: "127.0.0.1", Port: p1},
		{Host: "127.0.0.1", Port: p2},
	}

	best, _, err := SelectFastest(context.Background(), servers)
	if err != nil {
		t.Fatalf("SelectFastest failed: %v", err)
	}
	// Both should be reachable; on localhost RTTs are similar, so any
	// result is acceptable as long as it returned one of the two servers.
	if best.Port != p1 && best.Port != p2 {
		t.Errorf("expected one of listener ports (%d or %d), got port %d", p1, p2, best.Port)
	}
}

func TestSelectFastest_emptyServers(t *testing.T) {
	_, _, err := SelectFastest(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for empty server list")
	}
}

func TestSelectFastest_allFail(t *testing.T) {
	servers := []Server{
		{Host: "127.0.0.1", Port: 1},
		{Host: "127.0.0.1", Port: 2},
	}
	_, _, err := SelectFastest(context.Background(), servers)
	if err == nil {
		t.Fatal("expected error when all servers unreachable")
	}
}
