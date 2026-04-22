package server

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"vpn-proxy-go/internal/frame"
)

var sessionCounter uint64

func nextSessionID() string {
	id := atomic.AddUint64(&sessionCounter, 1)
	return fmt.Sprintf("%08x", id)
}

type BootstrapInfo struct {
	Auth  string `json:"auth"`
	Host  string `json:"host"`
	Port  uint16 `json:"port"`
	Proto string `json:"proto"`
}

func parseBootstrapLine(line string, allowedTokens []string) (host string, port uint16, proto string, err error) {
	var payload map[string]interface{}
	if e := json.Unmarshal([]byte(line), &payload); e != nil {
		return "", 0, "", fmt.Errorf("invalid json: %v", e)
	}
	authVal, ok := payload["auth"].(string)
	if !ok {
		return "", 0, "", fmt.Errorf("missing auth")
	}
	found := false
	for _, t := range allowedTokens {
		if t == authVal {
			found = true
			break
		}
	}
	if !found {
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

func LoadAllowedTokens(token string, tokensFile string) []string {
	tokens := []string{}
	if token != "" {
		tokens = append(tokens, token)
	}
	if tokensFile != "" {
		f, err := os.Open(tokensFile)
		if err == nil {
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				trimmed := strings.TrimSpace(scanner.Text())
				if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
					tokens = append(tokens, trimmed)
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
	AllowedTokens    []string
	AllowNetworks    []*net.IPNet
	ConnectTimeout   time.Duration
	BootstrapTimeout time.Duration
}

type SessionStats struct {
	uploadBytes   uint64
	downloadBytes uint64
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
		total += n
		for i := 0; i < total; i++ {
			if lineBuf[i] == '\n' {
				line := strings.TrimRight(string(lineBuf[:i]), "\r")
				conn.SetReadDeadline(time.Time{})
				return line, nil
			}
		}
	}
}

func resolveHost(host string, port uint16) (string, error) {
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip != nil && ip.To4() != nil {
			return fmt.Sprintf("%s:%d", a, port), nil
		}
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip != nil {
			return fmt.Sprintf("%s:%d", a, port), nil
		}
	}
	return "", fmt.Errorf("no address found for %s", host)
}

func handleTCPRelay(tlsConn net.Conn, targetAddr string, stats *SessionStats, sessionID string, connectTimeout time.Duration) {
	target, err := net.DialTimeout("tcp", targetAddr, connectTimeout)
	if err != nil {
		log.Printf("[sid=%s] backend connect failed to %s: %v", sessionID, targetAddr, err)
		return
	}
	if tcpConn, ok := target.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetReadBuffer(256 * 1024)
		tcpConn.SetWriteBuffer(256 * 1024)
	}

	var upBytes, downBytes uint64
	done := make(chan struct{}, 2)

	go func() {
		n, _ := io.Copy(target, tlsConn)
		upBytes = uint64(n)
		target.Close()
		done <- struct{}{}
	}()

	go func() {
		n, _ := io.Copy(tlsConn, target)
		downBytes = uint64(n)
		tlsConn.Close()
		done <- struct{}{}
	}()

	<-done
	<-done

	atomic.AddUint64(&stats.uploadBytes, upBytes)
	atomic.AddUint64(&stats.downloadBytes, downBytes)
	totalUp := atomic.LoadUint64(&stats.uploadBytes)
	totalDown := atomic.LoadUint64(&stats.downloadBytes)
	log.Printf("[sid=%s] session closed (up=%d bytes, down=%d bytes)", sessionID, totalUp, totalDown)
}

func handleUDPRelay(tlsConn net.Conn, stats *SessionStats, host string, port uint16, sessionID string) {
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

	go func() {
		for {
			f, err := frame.ReadFromStream(tlsConn)
			if err != nil {
				break
			}
			sendHost := f.Host
			sendPort := f.Port
			if fixedHost != "" {
				sendHost = fixedHost
				sendPort = fixedPort
			}
			addrs, err := net.LookupHost(sendHost)
			if err != nil {
				continue
			}
			var targetIP net.IP
			for _, a := range addrs {
				ip := net.ParseIP(a)
				if ip != nil {
					if ip.To4() != nil {
						targetIP = ip
						break
					}
					targetIP = ip
				}
			}
			if targetIP == nil {
				continue
			}
			udpAddr := &net.UDPAddr{IP: targetIP, Port: int(sendPort)}
			udpSock.WriteToUDP(f.Data, udpAddr)
			atomic.AddUint64(&stats.uploadBytes, uint64(len(f.Data)+4+len(f.Host)+4))
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, srcAddr, err := udpSock.ReadFromUDP(buf)
		if err != nil {
			break
		}
		srcHost := srcAddr.IP.String()
		srcPort := uint16(srcAddr.Port)
		packed := frame.Pack(srcHost, srcPort, buf[:n])

		tunnelWriteMu.Lock()
		tlsConn.Write(packed)
		tunnelWriteMu.Unlock()

		atomic.AddUint64(&stats.downloadBytes, uint64(len(packed)))
	}

	udpSock.Close()
	tlsConn.Close()

	totalUp := atomic.LoadUint64(&stats.uploadBytes)
	totalDown := atomic.LoadUint64(&stats.downloadBytes)
	log.Printf("[sid=%s] UDP session closed (up=%d bytes, down=%d bytes)", sessionID, totalUp, totalDown)
}

func handleClient(tlsConn net.Conn, ctx *AppConfig) {
	sessionID := nextSessionID()
	defer tlsConn.Close()

	peer := tlsConn.RemoteAddr()
	stats := &SessionStats{}

	if tcpConn, ok := tlsConn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

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
		targetAddr, err := resolveHost(host, port)
		if err != nil {
			log.Printf("[sid=%s] DNS lookup failed for %s:%d: %v", sessionID, host, port, err)
			return
		}
		tlsConn.Write([]byte("OK\n"))
		handleTCPRelay(tlsConn, targetAddr, stats, sessionID, ctx.ConnectTimeout)
	}
}

func Run(cfg *AppConfig, certPath, keyPath, listenAddr string) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("cannot load cert/key: %v", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
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