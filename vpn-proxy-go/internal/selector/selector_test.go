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
	return benchmarkPipeConnWithData(delay, response, "H")
}

// benchmarkPipeConnWithData is like benchmarkPipeConn but writes extraData
// after the first byte, for bandwidth measurement tests. Writes up to
// maxBytes of data in 64KB chunks, sleeping chunkDelay between each.
func benchmarkPipeConnWithData(delay time.Duration, response, extraData string) net.Conn {
	return benchmarkPipeConnChunked(delay, response, extraData, 0, 0)
}

// benchmarkPipeConnChunked writes response + up to maxBytes of repeated
// payload data in chunkSize-byte chunks, with chunkDelay between each.
// Used to simulate a target that serves a large response.
func benchmarkPipeConnChunked(delay time.Duration, response, chunkPayload string, maxBytes int, chunkDelay time.Duration) net.Conn {
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

		// Write additional data for bandwidth measurement
		remaining := maxBytes
		for remaining > 0 {
			writeSize := len(chunkPayload)
			if writeSize > remaining {
				writeSize = remaining
			}
			if _, err := server.Write([]byte(chunkPayload[:writeSize])); err != nil {
				return
			}
			remaining -= writeSize
			if chunkDelay > 0 {
				time.Sleep(chunkDelay)
			}
		}
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
		mockEntry{port: 2, conn: bandwidthPipeConn(15*time.Millisecond, 500*1024, 0)},
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

// ---------------------------------------------------------------------------
// SelectByBandwidth
// ---------------------------------------------------------------------------

// bandwidthPipeConn returns a pipe that writes up to maxBytes of data after
// the first response byte, then closes. When chunkDelay > 0, each 64KB chunk
// is followed by chunkDelay to simulate a slower connection.
func bandwidthPipeConn(latency time.Duration, maxBytes int, chunkDelay time.Duration) net.Conn {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buf := make([]byte, 4096)

		n, err := server.Read(buf)
		if err != nil {
			return
		}
		if err := json.Unmarshal(buf[:n], &tunnel.BootstrapInfo{}); err != nil {
			return
		}

		time.Sleep(latency)
		server.Write([]byte("OK\n"))

		if _, err := server.Read(buf); err != nil {
			return
		}

		// Write first byte
		server.Write([]byte("H"))

		// Write remaining data in 64KB chunks with optional delay
		chunk := make([]byte, 65536)
		for i := range chunk {
			chunk[i] = 'x'
		}
		written := 0
		for written < maxBytes {
			n := len(chunk)
			if written+n > maxBytes {
				n = maxBytes - written
			}
			if _, err := server.Write(chunk[:n]); err != nil {
				return
			}
			written += n
			if chunkDelay > 0 {
				time.Sleep(chunkDelay)
			}
		}
	}()
	return client
}

func TestSelectByBandwidth_choosesHigherBandwidth(t *testing.T) {
	orig := dialTunnelFn
	defer func() { dialTunnelFn = orig }()

	// Port 1: 80ms latency, 200KB with 40ms/64KB chunk delay → ~1250 KB/s
	// Port 2: 100ms latency, 800KB with 5ms/64KB chunk delay → ~12308 KB/s
	//
	// Bandwidth scoring should prefer port 2 despite its higher latency:
	//   port1 score ≈ 80 + 102400/1250 ≈ 162
	//   port2 score ≈ 100 + 102400/12308 ≈ 108
	dialTunnelFn = mockDialFn(
		mockEntry{port: 1, conn: bandwidthPipeConn(80*time.Millisecond, 200*1024, 40*time.Millisecond)},
		mockEntry{port: 2, conn: bandwidthPipeConn(100*time.Millisecond, 800*1024, 5*time.Millisecond)},
	)

	servers := []Server{
		{Host: "low-bw.test", Port: 1},
		{Host: "high-bw.test", Port: 2},
	}

	best, latency, bw, err := SelectByBandwidth(context.Background(), servers, "token", true)
	if err != nil {
		t.Fatalf("SelectByBandwidth failed: %v", err)
	}
	if best.Port != 2 {
		t.Errorf("expected high-bandwidth server (port 2), got %s (port %d)", best.Addr(), best.Port)
	}
	if latency < 80*time.Millisecond || latency > 500*time.Millisecond {
		t.Errorf("latency %v seems unreasonable", latency)
	}
	if bw <= 0 {
		t.Errorf("expected non-zero bandwidth, got %.0f KB/s", bw)
	}
}

func TestSelectByBandwidth_allFail(t *testing.T) {
	orig := dialTunnelFn
	defer func() { dialTunnelFn = orig }()

	dialTunnelFn = mockDialFn(
		mockEntry{port: 1, conn: failDialConn()},
		mockEntry{port: 2, conn: failDialConn()},
	)

	servers := []Server{
		{Host: "dead1.test", Port: 1},
		{Host: "dead2.test", Port: 2},
	}

	_, _, _, err := SelectByBandwidth(context.Background(), servers, "token", true)
	if err == nil {
		t.Fatal("expected error when all servers fail")
	}
}

func TestSelectByBandwidth_oneSucceeds(t *testing.T) {
	orig := dialTunnelFn
	defer func() { dialTunnelFn = orig }()
	oldMinMs := MinBandwidthProbeMs
	MinBandwidthProbeMs = 0
	defer func() { MinBandwidthProbeMs = oldMinMs }()

	dialTunnelFn = mockDialFn(
		mockEntry{port: 1, conn: failDialConn()},
		mockEntry{port: 2, conn: bandwidthPipeConn(15*time.Millisecond, 500*1024, 0)},
	)

	servers := []Server{
		{Host: "dead.test", Port: 1},
		{Host: "alive.test", Port: 2},
	}

	best, _, _, err := SelectByBandwidth(context.Background(), servers, "token", true)
	if err != nil {
		t.Fatalf("expected success for one alive server, got: %v", err)
	}
	if best.Port != 2 {
		t.Errorf("expected port 2 (alive), got port %d", best.Port)
	}
}

func TestSelectByBandwidth_emptyServers(t *testing.T) {
	_, _, _, err := SelectByBandwidth(context.Background(), nil, "token", true)
	if err == nil {
		t.Fatal("expected error for empty server list")
	}
}

func TestBandwidthScore(t *testing.T) {
	tests := []struct {
		latency   time.Duration
		bandwidth float64
		wantMin   float64
		wantMax   float64
	}{
		{latency: 100 * time.Millisecond, bandwidth: 1000, wantMin: 200, wantMax: 204}, // 100 + 102
		{latency: 100 * time.Millisecond, bandwidth: 100, wantMin: 1100, wantMax: 1200}, // 100 + 1024
		{latency: 100 * time.Millisecond, bandwidth: 42, wantMin: 2500, wantMax: 2600},  // 100 + 2438
	}
	for _, tc := range tests {
		r := benchmarkResult{latency: tc.latency, bandwidth: tc.bandwidth}
		score := bandwidthScore(r)
		if score < tc.wantMin || score > tc.wantMax {
			t.Errorf("bandwidthScore(%v, %.0f KB/s) = %.1f, want between %.1f and %.1f",
				tc.latency, tc.bandwidth, score, tc.wantMin, tc.wantMax)
		}
	}
}
