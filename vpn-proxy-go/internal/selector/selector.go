// Package selector probes multiple proxy servers and selects the fastest
// based on TCP connection latency, real tunnel throughput, or a combined
// benchmark that measures both latency and bandwidth.
//
// SelectFastest uses TCP RTT for quick latency comparison.
// SelectByBenchmark creates a full TLS tunnel to each server and measures
// end-to-end response time to a target URL.
// SelectByBandwidth extends the latency probe with bandwidth measurement
// (reads up to 2MB through the tunnel) and selects via weighted score.
package selector

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"vpn-proxy-go/internal/tunnel"
)

// dialTunnelFn is the function used by probeViaTunnel to establish a raw
// TLS connection. Defaults to tunnel.DialTunnel; overridden in tests.
var dialTunnelFn = tunnel.DialTunnel

// Server represents a remote proxy server candidate.
type Server struct {
	Host string
	Port uint16
}

// Addr returns the "host:port" string for the server.
func (s Server) Addr() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// probeResult holds the outcome of probing a single server.
type probeResult struct {
	server  Server
	latency time.Duration
	err     error
}

// probeTCP measures TCP connection RTT to a server.
// Uses a short dial timeout (3s) and no retries — if the server is
// unreachable, we fail fast and let the caller try another candidate.
func probeTCP(ctx context.Context, addr string) (time.Duration, error) {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	conn.Close()
	return time.Since(start), nil
}

// ---------------------------------------------------------------------------
// SelectFastest — probe via TCP RTT
// ---------------------------------------------------------------------------

// SelectFastest probes all servers in parallel using TCP RTT and returns
// the one with the lowest latency.
func SelectFastest(ctx context.Context, servers []Server) (Server, time.Duration, error) {
	if len(servers) == 0 {
		return Server{}, 0, fmt.Errorf("no servers to probe")
	}

	ch := make(chan probeResult, len(servers))

	for _, s := range servers {
		s := s
		go func() {
			lat, err := probeTCP(ctx, s.Addr())
			ch <- probeResult{server: s, latency: lat, err: err}
		}()
	}

	var results []probeResult
	for i := 0; i < len(servers); i++ {
		r := <-ch
		results = append(results, r)
	}

	var reachable []probeResult
	for _, r := range results {
		if r.err == nil {
			reachable = append(reachable, r)
		}
	}

	if len(reachable) == 0 {
		for _, r := range results {
			if r.err != nil {
				return Server{}, 0, fmt.Errorf("all servers unreachable (e.g. %s: %v)", r.server.Addr(), r.err)
			}
		}
		return Server{}, 0, fmt.Errorf("all servers unreachable")
	}

	sort.Slice(reachable, func(i, j int) bool {
		return reachable[i].latency < reachable[j].latency
	})

	best := reachable[0]
	return best.server, best.latency, nil
}

// ---------------------------------------------------------------------------
// SelectByBenchmark — probe via real tunnel (latency only)
// ---------------------------------------------------------------------------

// benchmarkResult holds the outcome of benchmarking a single server.
type benchmarkResult struct {
	server    Server
	latency   time.Duration
	bandwidth float64 // KB/s measured during bandwidth probe; 0 if not available
	err       error
}

// SelectByBenchmark probes servers in parallel by creating a real TLS
// tunnel through each, bootstrapping to a probe target, and measuring
// the time to receive the first byte of response data.
func SelectByBenchmark(ctx context.Context, servers []Server, token string, insecure bool) (Server, time.Duration, error) {
	if len(servers) == 0 {
		return Server{}, 0, fmt.Errorf("no servers to benchmark")
	}

	ch := make(chan benchmarkResult, len(servers))

	for _, s := range servers {
		s := s
		go func() {
			lat, _, err := probeViaTunnel(ctx, s, token, insecure, "www.google.com", 80, false)
			ch <- benchmarkResult{server: s, latency: lat, err: err}
		}()
	}

	var results []benchmarkResult
	for i := 0; i < len(servers); i++ {
		r := <-ch
		results = append(results, r)
	}

	var reachable []benchmarkResult
	for _, r := range results {
		if r.err == nil {
			reachable = append(reachable, r)
		}
	}

	if len(reachable) == 0 {
		for _, r := range results {
			if r.err != nil {
				return Server{}, 0, fmt.Errorf("all servers unreachable (e.g. %s: %v)", r.server.Addr(), r.err)
			}
		}
		return Server{}, 0, fmt.Errorf("all servers unreachable")
	}

	sort.Slice(reachable, func(i, j int) bool {
		return reachable[i].latency < reachable[j].latency
	})

	best := reachable[0]
	return best.server, best.latency, nil
}

// ---------------------------------------------------------------------------
// SelectByBandwidth — probe with latency + bandwidth scoring
// ---------------------------------------------------------------------------

const (
	// MaxBandwidthProbeBytes limits how much data is downloaded per server
	// during a bandwidth probe (2MB).
	MaxBandwidthProbeBytes = 2 * 1024 * 1024
	// MaxBandwidthProbeDuration limits how long the bandwidth probe runs (3s).
	MaxBandwidthProbeDuration = 3 * time.Second
)

// SelectByBandwidth probes servers by measuring both latency (first-byte TTFB)
// and throughput (KB/s downloaded through the tunnel). Servers are ranked
// using a weighted score: lower is better.
//
// Scoring formula: score = latency_ms + (100 * 1024 / bandwidth_kbps)
// This normalises a 100KB/s tunnel to ~1000ms of "cost", making bandwidth
// the dominant factor when latency differences are small.
func SelectByBandwidth(ctx context.Context, servers []Server, token string, insecure bool) (Server, time.Duration, float64, error) {
	if len(servers) == 0 {
		return Server{}, 0, 0, fmt.Errorf("no servers to benchmark")
	}

	ch := make(chan benchmarkResult, len(servers))

	for _, s := range servers {
		s := s
		go func() {
			lat, bw, err := probeViaTunnel(ctx, s, token, insecure, "www.google.com", 80, true)
			ch <- benchmarkResult{server: s, latency: lat, bandwidth: bw, err: err}
		}()
	}

	var results []benchmarkResult
	for i := 0; i < len(servers); i++ {
		r := <-ch
		results = append(results, r)
	}

	var reachable []benchmarkResult
	for _, r := range results {
		if r.err == nil {
			reachable = append(reachable, r)
		}
	}

	if len(reachable) == 0 {
		for _, r := range results {
			if r.err != nil {
				return Server{}, 0, 0, fmt.Errorf("all servers unreachable (e.g. %s: %v)", r.server.Addr(), r.err)
			}
		}
		return Server{}, 0, 0, fmt.Errorf("all servers unreachable")
	}

	sort.Slice(reachable, func(i, j int) bool {
		return bandwidthScore(reachable[i]) < bandwidthScore(reachable[j])
	})

	best := reachable[0]
	return best.server, best.latency, best.bandwidth, nil
}

// bandwidthScore computes a combined score where lower is better.
// Formula: latency_ms + (100 * 1024 / bandwidth_kbps)
// This normalises bandwidth to an equivalent latency cost:
//   - 1000 KB/s → 102ms equivalent
//   - 100 KB/s  → 1024ms equivalent (dominant factor)
//   - 42 KB/s   → 2438ms equivalent
func bandwidthScore(r benchmarkResult) float64 {
	bw := r.bandwidth
	if bw <= 1 {
		bw = 1 // avoid division by zero
	}
	return float64(r.latency.Milliseconds()) + (100*1024)/bw
}

// ---------------------------------------------------------------------------
// probeViaTunnel — shared probe for all tunnel-based selectors
// ---------------------------------------------------------------------------

// probeViaTunnel establishes a TLS tunnel through the given server,
// bootstraps to targetHost:targetPort, sends an HTTP GET request,
// measures latency to the first response byte, and optionally measures
// bandwidth by continuing to read up to 2MB / 3s of data.
//
// When measureBandwidth is false, the function returns after the first
// byte and bandwidth will be 0.
//
// minBandwidthProbeMs controls how long (in ms) the bandwidth phase must
// last before the measurement is considered valid. Shorter probes produce
// unreliable bandwidth estimates. Exported as a variable so tests can
// override it.
var MinBandwidthProbeMs = 50 // milliseconds
func probeViaTunnel(ctx context.Context, server Server, token string, insecure bool, targetHost string, targetPort uint16, measureBandwidth bool) (latency time.Duration, bandwidth float64, err error) {
	start := time.Now()

	cfg := &tunnel.Config{
		Server:     server.Host,
		ServerPort: server.Port,
		Token:      token,
		Insecure:   insecure,
		Retries:    0,
		RetryDelay: 0.5,
	}

	conn, err := dialTunnelFn(ctx, cfg)
	if err != nil {
		return 0, 0, fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	payload := tunnel.BootstrapInfo{
		Auth:  token,
		Host:  targetHost,
		Port:  targetPort,
		Proto: "tcp",
	}
	bs, _ := json.Marshal(payload)
	bs = append(bs, '\n')
	if _, err := conn.Write(bs); err != nil {
		return 0, 0, fmt.Errorf("bootstrap write: %w", err)
	}

	statusBuf := make([]byte, 128)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(statusBuf)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		return 0, 0, fmt.Errorf("bootstrap read: %w", err)
	}
	status := string(statusBuf[:n])
	if !strings.HasPrefix(status, "OK") {
		return 0, 0, fmt.Errorf("server refused: %s", strings.TrimSpace(status))
	}

	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", targetHost)
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, 0, fmt.Errorf("http write: %w", err)
	}

	oneByte := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(oneByte); err != nil {
		return 0, 0, fmt.Errorf("http read first byte: %w", err)
	}
	latency = time.Since(start)

	if !measureBandwidth {
		conn.SetReadDeadline(time.Time{})
		return latency, 0, nil
	}

	// Bandwidth phase: read up to 2MB or 3s
	totalBytes := int64(1) // includes the one byte already read
	bandwidthDeadline := time.Now().Add(MaxBandwidthProbeDuration)
	buf := make([]byte, 65536)

	conn.SetReadDeadline(bandwidthDeadline)
	for totalBytes < MaxBandwidthProbeBytes {
		n, rErr := conn.Read(buf)
		if n > 0 {
			totalBytes += int64(n)
		}
		if rErr != nil {
			break
		}
		if time.Now().After(bandwidthDeadline) {
			break
		}
	}
	conn.SetReadDeadline(time.Time{})

	// Compute bandwidth: exclude the first-byte time to isolate throughput
	bwElapsed := time.Since(start) - latency
	if bwElapsed > time.Duration(MinBandwidthProbeMs)*time.Millisecond && totalBytes > 1 {
		bandwidth = float64(totalBytes-1) / bwElapsed.Seconds() / 1024
	}

	return latency, bandwidth, nil
}
