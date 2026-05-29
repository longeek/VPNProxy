// Package server implements the VPN proxy server.
//
// The server listens for TLS connections from clients, authenticates via
// shared token, and forwards TCP/UDP traffic to backend targets.
//
// Performance features:
//   - Token-bucket rate limiter (default 100 req/s, burst 20)
//   - DNS cache with positive + negative caching (TTL 30s)
//   - TLS session cache (128-entry LRU)
//   - TCP keepalive (30s) to detect half-open connections
//   - Graceful shutdown with SIGTERM/SIGINT handling
//   - Optional semaphore-based concurrency limiting
package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vpn-proxy-go/internal/frame"
	"vpn-proxy-go/internal/tunnel"
)

// rateLimiter implements a token-bucket rate limiter.
//
// Tokens are refilled continuously based on elapsed time since the last
// check. The bucket has a maximum capacity (burst) and refills at a
// configurable rate per second. This is the same algorithm used by the
// Rust server implementation for cross-language consistency.
type rateLimiter struct {
	mu         sync.Mutex
	tokens     int
	maxTokens  int
	refillRate float64 // tokens per second
	lastRefill time.Time
}

func newRateLimiter(ratePerSec float64, burst int) *rateLimiter {
	return &rateLimiter{
		tokens:     burst,
		maxTokens:  burst,
		refillRate: ratePerSec,
		lastRefill: time.Now(),
	}
}

// Allow checks if a request fits within the rate limit. Returns true if
// the request is allowed, false if rate limited. Thread-safe.
func (r *rateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	newTokens := int(elapsed * r.refillRate)
	if newTokens > 0 {
		r.tokens += newTokens
		if r.tokens > r.maxTokens {
			r.tokens = r.maxTokens
		}
		r.lastRefill = now
	}

	if r.tokens > 0 {
		r.tokens--
		return true
	}
	return false
}

// connLimiter is the global rate limiter. Default: 100 requests/second, burst 20.
var connLimiter = newRateLimiter(100, 20)

const (
	recvBufSize    = 256 * 1024
	pipeBufSize    = 131072
	drainThreshold = 128 * 1024
)

var sessionCounter uint64

const hexTable = "0123456789abcdef"

// nextSessionID generates an 8-character hex session identifier using an
// atomic counter. This is faster than UUID generation and provides
// human-readable short IDs for log correlation.
func nextSessionID() string {
	id := atomic.AddUint64(&sessionCounter, 1)
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = hexTable[id&0xf]
		id >>= 4
	}
	return string(b)
}

// BootstrapRequest is the JSON structure sent by the client in the first line.
// Fields use pointers to distinguish missing vs zero-value for validation.
type BootstrapRequest struct {
	Auth  string `json:"auth"`
	Host  string `json:"host"`
	Port  uint16 `json:"port"`
	Proto string `json:"proto,omitempty"`
}

// ParseBootstrapJSON unmarshals the raw JSON line into a BootstrapRequest.
// Separated from validation for testability and reuse.
func ParseBootstrapJSON(line string) (*BootstrapRequest, error) {
	var req BootstrapRequest
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}
	if req.Auth == "" {
		return nil, fmt.Errorf("missing auth")
	}
	if req.Host == "" {
		return nil, fmt.Errorf("missing host")
	}
	if req.Proto == "" {
		req.Proto = "tcp"
	}
	return &req, nil
}

// ValidateBootstrapRequest checks authentication, protocol, and port constraints.
// Returns "ERR auth" for auth failures (wire protocol convention), generic errors otherwise.
func ValidateBootstrapRequest(req *BootstrapRequest, allowedTokens map[string]bool) error {
	if !allowedTokens[req.Auth] {
		return fmt.Errorf("ERR auth")
	}
	if req.Proto != "tcp" && req.Proto != "udp" {
		return fmt.Errorf("invalid proto")
	}
	if req.Proto == "tcp" && req.Port == 0 {
		return fmt.Errorf("invalid port")
	}
	return nil
}

// parseBootstrapLine is a convenience wrapper that calls ParseBootstrapJSON + ValidateBootstrapRequest.
// Kept for backward compatibility with existing callers.
func parseBootstrapLine(line string, allowedTokens map[string]bool) (host string, port uint16, proto string, err error) {
	req, err := ParseBootstrapJSON(line)
	if err != nil {
		return "", 0, "", err
	}
	if err := ValidateBootstrapRequest(req, allowedTokens); err != nil {
		return "", 0, "", err
	}
	return req.Host, req.Port, req.Proto, nil
}

// LoadAllowedTokens loads tokens from --token flag and/or --tokens-file.
// Tokens from both sources are merged into a single set for fast lookup.
func LoadAllowedTokens(token string, tokensFile string) map[string]bool {
	tokens := map[string]bool{}
	if token != "" {
		tokens[token] = true
	}
	if tokensFile != "" {
		f, err := os.Open(tokensFile)
		if err == nil {
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				trimmed := strings.TrimSpace(scanner.Text())
				if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
					tokens[trimmed] = true
				}
			}
			f.Close()
		}
	}
	return tokens
}

// ParseAllowCIDRs parses a comma-separated list of CIDR networks.
// Empty string returns nil (allow all). Invalid CIDRs are silently skipped.
func ParseAllowCIDRs(value string) []*net.IPNet {
	if value == "" {
		return nil
	}
	var nets []*net.IPNet
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		_, cidr, err := net.ParseCIDR(item)
		if err == nil {
			nets = append(nets, cidr)
		}
	}
	return nets
}

func peerAllowed(peerIP net.IP, networks []*net.IPNet) bool {
	if len(networks) == 0 {
		return true
	}
	for _, n := range networks {
		if n.Contains(peerIP) {
			return true
		}
	}
	return false
}

// AppError represents a structured application error with a code and message.
type AppError struct {
	Code    string
	Message string
	Err     error
}

func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *AppError) Unwrap() error {
	return e.Err
}

// AppConfig holds all server configuration. Passed to handleClient for
// each incoming connection.
type AppConfig struct {
	AllowedTokens    map[string]bool
	AllowNetworks    []*net.IPNet
	ConnectTimeout   time.Duration
	BootstrapTimeout time.Duration
	MaxConns         int // max concurrent connections (0 = unlimited)
}

// readBootstrapLine reads the first line (terminated by '\n') from the
// TLS connection within the given timeout. Supports CRLF line endings.
// The read deadline is reset after a complete line is received.
func readBootstrapLine(conn net.Conn, timeout time.Duration) (string, error) {
	lineBuf := make([]byte, 4096)
	total := 0
	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)
	for {
		if total >= len(lineBuf) {
			return "", fmt.Errorf("bootstrap line too long")
		}
		n, err := conn.Read(lineBuf[total:])
		if err != nil {
			return "", err
		}
		if n == 0 {
			return "", fmt.Errorf("connection closed")
		}
		prevTotal := total
		total += n
		idx := bytes.IndexByte(lineBuf[prevTotal:total], '\n')
		if idx >= 0 {
			line := string(bytes.TrimRight(lineBuf[:prevTotal+idx], "\r"))
			conn.SetReadDeadline(time.Time{})
			return line, nil
		}
	}
}

// dnsEntry holds a cached DNS result with expiration and negative flag.
type dnsEntry struct {
	ip       net.IP
	ts       time.Time
	negative bool // true if this entry represents a failed DNS lookup
}

var dnsCache sync.Map

const dnsCacheTTL = 30 * time.Second

// cachedLookupHost performs DNS resolution with caching.
//
// Caching strategy (same as Rust implementation):
//   - Successful lookups: cached for dnsCacheTTL (30s)
//   - Failed lookups (NXDOMAIN, timeout): cached for ~9s (30s * 0.3)
//
// Negative caching prevents repeated DNS failures from overwhelming
// the resolver during transient network issues.
func cachedLookupHost(host string) net.IP {
	now := time.Now()
	if v, ok := dnsCache.Load(host); ok {
		e := v.(*dnsEntry)
		if now.Sub(e.ts) < dnsCacheTTL {
			if e.negative {
				return nil
			}
			return e.ip
		}
		dnsCache.Delete(host)
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		dnsCache.Store(host, &dnsEntry{ip: nil, ts: now, negative: true})
		return nil
	}
	var ip net.IP
	for _, a := range addrs {
		p := net.ParseIP(a)
		if p != nil && p.To4() != nil {
			ip = p
			break
		}
	}
	if ip == nil {
		for _, a := range addrs {
			p := net.ParseIP(a)
			if p != nil {
				ip = p
				break
			}
		}
	}
	if ip != nil {
		dnsCache.Store(host, &dnsEntry{ip: ip, ts: now, negative: false})
	}
	return ip
}

func resolveHost(host string, port uint16) (string, error) {
	ip := cachedLookupHost(host)
	if ip == nil {
		return "", fmt.Errorf("no address found for %s", host)
	}
	return fmt.Sprintf("%s:%d", ip.String(), port), nil
}

// handleTCPRelay resolves the target host (using cached DNS), connects to
// the backend, and starts bidirectional relay with threshold-based flushing.
func handleTCPRelay(tlsConn net.Conn, host string, port uint16, stats *tunnel.SessionStats, sessionID string, connectTimeout time.Duration) {
	targetAddr, err := resolveHost(host, port)
	if err != nil {
		log.Printf("[sid=%s] DNS lookup failed for %s:%d: %v", sessionID, host, port, err)
		return
	}
	target, err := net.DialTimeout("tcp", targetAddr, connectTimeout)
	if err != nil {
		log.Printf("[sid=%s] backend connect failed to %s: %v", sessionID, targetAddr, err)
		return
	}
	if tcpConn, ok := target.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetReadBuffer(recvBufSize)
		tcpConn.SetWriteBuffer(recvBufSize)
	}

	tunnel.RelayTCPServer(tlsConn, target, stats)

	totalUp := stats.UploadBytes.Load()
	totalDown := stats.DownloadBytes.Load()
	log.Printf("[sid=%s] session closed (up=%d bytes, down=%d bytes)", sessionID, totalUp, totalDown)
}

// udpBufPool pools 64KB UDP receive buffers to reduce allocations.
var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535)
		return &b
	},
}

// handleUDPRelay implements UDP ASSOCIATE relay.
//
// UDP datagrams are framed over the TLS tunnel using the custom protocol:
//
//	ver(1) + rsv(1) + host_len(2) + host(UTF-8) + port(2) + payload_len(2) + payload
//
// Two modes:
//   - Fixed destination: all datagrams are sent to the bootstrap-specified host:port
//   - Framed (0.0.0.0:0): each datagram carries its own destination (SOCKS5 UDP ASSOCIATE)
func handleUDPRelay(tlsConn net.Conn, stats *tunnel.SessionStats, host string, port uint16, sessionID string) {
	udpSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
	if err != nil {
		log.Printf("[sid=%s] UDP bind failed: %v", sessionID, err)
		tlsConn.Write([]byte("ERR connect\n"))
		tlsConn.Close()
		return
	}

	fixedHost := ""
	fixedPort := uint16(0)
	if host != "0.0.0.0" || port != 0 {
		fixedHost = host
		fixedPort = port
	}

	tlsConn.Write([]byte("OK\n"))

	var tunnelWriteMu sync.Mutex
	bw := tunnel.GetBufWriter(tlsConn)
	defer tunnel.PutBufWriter(bw)
	pendingWrite := 0

	// Direction 1: TLS tunnel → UDP socket (incoming frames from client)
	go func() {
		for {
			f, err := frame.ReadFromStreamPooled(tlsConn)
			if err != nil {
				break
			}
			sendHost := f.Host
			sendPort := f.Port
			if fixedHost != "" {
				sendHost = fixedHost
				sendPort = fixedPort
			}
			targetIP := cachedLookupHost(sendHost)
			if targetIP == nil {
				continue
			}
			udpAddr := &net.UDPAddr{IP: targetIP, Port: int(sendPort)}
			udpSock.WriteToUDP(f.Data, udpAddr)
			stats.UploadBytes.Add(uint64(len(f.Data) + 4 + len(f.Host) + 4))
		}
	}()

	// Direction 2: UDP socket → TLS tunnel (incoming datagrams from network)
	buf := *udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(&buf)
	for {
		n, srcAddr, err := udpSock.ReadFromUDP(buf)
		if err != nil {
			break
		}
		srcHost := srcAddr.IP.String()
		srcPort := uint16(srcAddr.Port)

		tunnelWriteMu.Lock()
		packedLen, werr := frame.PackTo(bw, srcHost, srcPort, buf[:n])
		if werr != nil {
			tunnelWriteMu.Unlock()
			break
		}
		pendingWrite += packedLen
		if pendingWrite >= drainThreshold {
			bw.Flush()
			pendingWrite = 0
		}
		tunnelWriteMu.Unlock()

		stats.DownloadBytes.Add(uint64(packedLen))
	}

	if pendingWrite > 0 {
		bw.Flush()
	}
	udpSock.Close()
	tlsConn.Close()

	totalUp := stats.UploadBytes.Load()
	totalDown := stats.DownloadBytes.Load()
	log.Printf("[sid=%s] UDP session closed (up=%d bytes, down=%d bytes)", sessionID, totalUp, totalDown)
}

// setClientSocketOpts applies TCP optimization options to the client connection:
//   - TCP_NODELAY: disable Nagle's algorithm for low-latency forwarding
//   - Large socket buffers (256KB) for high-throughput transfers
//   - TCP keepalive (30s) to detect half-open connections from crashed clients
func setClientSocketOpts(tlsConn net.Conn) {
	if tc, ok := tlsConn.(*tls.Conn); ok {
		raw, ok := tc.NetConn().(*net.TCPConn)
		if ok {
			raw.SetNoDelay(true)
			raw.SetReadBuffer(recvBufSize)
			raw.SetWriteBuffer(recvBufSize)
			raw.SetKeepAlive(true)
			raw.SetKeepAlivePeriod(30 * time.Second)
		}
	}
}

// handleClient processes a single client connection.
//
// Workflow:
//  1. Rate limiting check
//  2. CIDR allowlist check
//  3. Read bootstrap line (JSON with auth + target)
//  4. Route to TCP relay (with DNS cache) or UDP relay
//
// The connection is always closed in the defer at the end.
func handleClient(tlsConn net.Conn, ctx *AppConfig) {
	sessionID := nextSessionID()
	defer tlsConn.Close()

	peer := tlsConn.RemoteAddr()
	stats := &tunnel.SessionStats{}

	if !connLimiter.Allow() {
		log.Printf("[sid=%s] connection rate limit exceeded from %v", sessionID, peer)
		tlsConn.Write([]byte("ERR rate limit\n"))
		return
	}

	setClientSocketOpts(tlsConn)

	if peer != nil {
		peerAddr, ok := peer.(*net.TCPAddr)
		if ok && !peerAllowed(peerAddr.IP, ctx.AllowNetworks) {
			log.Printf("[sid=%s] peer not in allow-cidrs: %s", sessionID, peer)
			tlsConn.Write([]byte("ERR connect\n"))
			return
		}
	}

	line, err := readBootstrapLine(tlsConn, ctx.BootstrapTimeout)
	if err != nil {
		log.Printf("[sid=%s] bootstrap read failed: %v", sessionID, err)
		return
	}

	host, port, proto, err := parseBootstrapLine(line, ctx.AllowedTokens)
	if err != nil {
		log.Printf("[sid=%s] bootstrap error from %s: %v", sessionID, peer, err)
		if err.Error() == "ERR auth" {
			tlsConn.Write([]byte("ERR auth\n"))
		} else {
			tlsConn.Write([]byte(fmt.Sprintf("ERR %v\n", err)))
		}
		return
	}

	log.Printf("[sid=%s] accepted tunnel from %s to %s:%d (%s)", sessionID, peer, host, port, proto)

	if proto == "udp" {
		handleUDPRelay(tlsConn, stats, host, port, sessionID)
	} else {
		tlsConn.Write([]byte("OK\n"))
		handleTCPRelay(tlsConn, host, port, stats, sessionID, ctx.ConnectTimeout)
	}
}

// Run starts the server with a background context (no graceful shutdown).
// See RunWithContext for signal-aware startup.
func Run(cfg *AppConfig, certPath, keyPath, listenAddr string) {
	RunWithContext(context.Background(), cfg, certPath, keyPath, listenAddr)
}

// activeConns tracks currently active connections for graceful shutdown.
// Each connection is stored with its session ID as key.
var activeConns sync.Map

// RunWithContext starts the TLS listener and accepts connections until the
// context is cancelled (triggering graceful shutdown).
//
// Concurrency limiting:
//   - If cfg.MaxConns > 0, a semaphore (buffered channel) limits concurrent
//     goroutines. When at capacity, Accept() blocks, providing backpressure
//     via the OS TCP backlog.
//
// Graceful shutdown:
//   - On ctx.Done(), the listener is closed immediately
//   - Active connections have up to 30s to complete before force-close
func RunWithContext(ctx context.Context, cfg *AppConfig, certPath, keyPath, listenAddr string) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("cannot load cert/key: %v", err)
	}

	tlsCfg := &tls.Config{
		Certificates:           []tls.Certificate{cert},
		MinVersion:             tls.VersionTLS12,
		CurvePreferences:       []tls.CurveID{tls.X25519, tls.CurveP256},
		ClientSessionCache:     tls.NewLRUClientSessionCache(128),
		SessionTicketsDisabled: false,
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("cannot bind %s: %v", listenAddr, err)
	}
	tlsLn := tls.NewListener(ln, tlsCfg)

	log.Printf("server started on %s", listenAddr)

	// Graceful shutdown goroutine: wait for ctx cancellation,
	// close the listener, then wait for active connections to drain.
	go func() {
		<-ctx.Done()
		log.Println("shutting down server...")
		tlsLn.Close()

		waitCh := make(chan struct{})
		go func() {
			activeConns.Range(func(_, _ interface{}) bool {
				return true
			})
			close(waitCh)
		}()

		select {
		case <-waitCh:
			log.Println("all connections closed")
		case <-time.After(30 * time.Second):
			log.Println("timeout waiting for connections to close")
		}
	}()

	// Semaphore-based concurrency limiter.
	// When full, Accept blocks (backpressure) instead of rejecting.
	var sem chan struct{}
	if cfg.MaxConns > 0 {
		sem = make(chan struct{}, cfg.MaxConns)
		log.Printf("max concurrent connections set to %d", cfg.MaxConns)
	}

	for {
		conn, err := tlsLn.Accept()
		if err != nil {
			if ctx.Err() != nil {
				log.Println("server stopped")
				return
			}
			log.Printf("TLS accept error: %v", err)
			continue
		}

		// Acquire semaphore slot (blocks if at capacity)
		if sem != nil {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				conn.Close()
				return
			}
		}

		id := nextSessionID()
		activeConns.Store(id, conn)
		go func(id string, conn net.Conn) {
			if sem != nil {
				defer func() { <-sem }()
			}
			defer activeConns.Delete(id)
			handleClient(conn, cfg)
		}(id, conn)
	}
}
