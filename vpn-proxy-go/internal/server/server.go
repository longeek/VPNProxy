package server

import (
	"bufio"
	"bytes"
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

const (
	recvBufSize    = 256 * 1024
	pipeBufSize    = 131072
	drainThreshold = 128 * 1024
)

var sessionCounter uint64

const hexTable = "0123456789abcdef"

func nextSessionID() string {
	id := atomic.AddUint64(&sessionCounter, 1)
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = hexTable[id&0xf]
		id >>= 4
	}
	return string(b)
}

func parseBootstrapLine(line string, allowedTokens map[string]bool) (host string, port uint16, proto string, err error) {
	var payload map[string]interface{}
	if e := json.Unmarshal([]byte(line), &payload); e != nil {
		return "", 0, "", fmt.Errorf("invalid json: %v", e)
	}
	authVal, ok := payload["auth"].(string)
	if !ok {
		return "", 0, "", fmt.Errorf("missing auth")
	}
	if !allowedTokens[authVal] {
		return "", 0, "", fmt.Errorf("ERR auth")
	}
	hostVal, ok := payload["host"].(string)
	if !ok || hostVal == "" {
		return "", 0, "", fmt.Errorf("missing host")
	}
	portVal, ok := payload["port"].(float64)
	if !ok || portVal < 0 || portVal > 65535 {
		return "", 0, "", fmt.Errorf("invalid port")
	}
	protoVal, _ := payload["proto"].(string)
	if protoVal == "" {
		protoVal = "tcp"
	}
	if protoVal != "tcp" && protoVal != "udp" {
		return "", 0, "", fmt.Errorf("invalid proto")
	}
	p := uint16(portVal)
	if protoVal == "tcp" && p == 0 {
		return "", 0, "", fmt.Errorf("invalid port")
	}
	return hostVal, p, protoVal, nil
}

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

type AppConfig struct {
	AllowedTokens    map[string]bool
	AllowNetworks    []*net.IPNet
	ConnectTimeout   time.Duration
	BootstrapTimeout time.Duration
}



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

type dnsEntry struct {
	ip net.IP
	ts time.Time
}

var dnsCache sync.Map

const dnsCacheTTL = 30 * time.Second

func cachedLookupHost(host string) net.IP {
	now := time.Now()
	if v, ok := dnsCache.Load(host); ok {
		e := v.(*dnsEntry)
		if now.Sub(e.ts) < dnsCacheTTL {
			return e.ip
		}
		dnsCache.Delete(host)
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
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
		dnsCache.Store(host, &dnsEntry{ip: ip, ts: now})
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

var udpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535)
		return &b
	},
}

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
	bw := bufio.NewWriterSize(tlsConn, pipeBufSize)
	pendingWrite := 0

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
			stats.UploadBytes.Add(uint64(len(f.Data)+4+len(f.Host)+4))
		}
	}()

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

func setClientSocketOpts(tlsConn net.Conn) {
	if tc, ok := tlsConn.(*tls.Conn); ok {
		raw, ok := tc.NetConn().(*net.TCPConn)
		if ok {
			raw.SetNoDelay(true)
			raw.SetReadBuffer(recvBufSize)
			raw.SetWriteBuffer(recvBufSize)
		}
	}
}

func handleClient(tlsConn net.Conn, ctx *AppConfig) {
	sessionID := nextSessionID()
	defer tlsConn.Close()

	peer := tlsConn.RemoteAddr()
	stats := &tunnel.SessionStats{}

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

func Run(cfg *AppConfig, certPath, keyPath, listenAddr string) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("cannot load cert/key: %v", err)
	}

	tlsCfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		ClientSessionCache: tls.NewLRUClientSessionCache(128),
		SessionTicketsDisabled: false,
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("cannot bind %s: %v", listenAddr, err)
	}
	tlsLn := tls.NewListener(ln, tlsCfg)

	log.Printf("server started on %s", listenAddr)

	for {
		conn, err := tlsLn.Accept()
		if err != nil {
			log.Printf("TLS accept error: %v", err)
			continue
		}
		go handleClient(conn, cfg)
	}
}