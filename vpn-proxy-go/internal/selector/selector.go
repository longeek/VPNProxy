// Package selector probes multiple proxy servers and selects the fastest
// based on TCP connection latency or real tunnel throughput.
//
// SelectFastest uses TCP RTT for quick latency comparison.
// SelectByBenchmark creates a full TLS tunnel to each server and measures
// end-to-end response time to a target URL, accounting for both
// client→server and server→target latency.
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
//
// All servers are probed concurrently with individual 3s timeouts.
// If no server is reachable, an error is returned. The first reachable
// server error is included in the message for diagnostics.
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
// SelectByBenchmark — probe via real tunnel throughput
// ---------------------------------------------------------------------------

// benchmarkResult holds the outcome of benchmarking a single server.
type benchmarkResult struct {
	server  Server
	latency time.Duration
	err     error
}

// SelectByBenchmark probes servers in parallel by creating a real TLS
// tunnel through each, bootstrapping to a probe target, and measuring
// the time to receive the first byte of response data.
//
// This is slower than SelectFastest (adds TLS + bootstrap + target RTT)
// but provides a more accurate ranking when the bottleneck is
// server-to-target latency rather than client-to-server RTT.
// The probe target is www.google.com:80 (HTTP avoids extra TLS inside
// the tunnel); the target's response (even a redirect) is sufficient
// for timing.
func SelectByBenchmark(ctx context.Context, servers []Server, token string, insecure bool) (Server, time.Duration, error) {
	if len(servers) == 0 {
		return Server{}, 0, fmt.Errorf("no servers to benchmark")
	}

	ch := make(chan benchmarkResult, len(servers))

	for _, s := range servers {
		s := s
		go func() {
			lat, err := probeViaTunnel(ctx, s, token, insecure, "www.google.com", 80)
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

// probeViaTunnel establishes a TLS tunnel through the given server,
// bootstraps to targetHost:targetPort, sends an HTTP GET request, and
// measures the time from dial start to the first byte of the response.
func probeViaTunnel(ctx context.Context, server Server, token string, insecure bool, targetHost string, targetPort uint16) (time.Duration, error) {
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
		return 0, fmt.Errorf("tls dial: %w", err)
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
		return 0, fmt.Errorf("bootstrap write: %w", err)
	}

	statusBuf := make([]byte, 128)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(statusBuf)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		return 0, fmt.Errorf("bootstrap read: %w", err)
	}
	status := string(statusBuf[:n])
	if !strings.HasPrefix(status, "OK") {
		return 0, fmt.Errorf("server refused: %s", strings.TrimSpace(status))
	}

	req := fmt.Sprintf("GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", targetHost)
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, fmt.Errorf("http write: %w", err)
	}

	oneByte := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(oneByte); err != nil {
		return 0, fmt.Errorf("http read first byte: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	return time.Since(start), nil
}
