package httpproxy

import (
	"bytes"
	"context"
	"log"
	"net"

	"vpn-proxy-go/internal/frame"
	"vpn-proxy-go/internal/pool"
	"vpn-proxy-go/internal/tunnel"
)

type Handler struct {
	Cfg       *tunnel.Config
	Pool      *pool.Pool
	ProxyUser string
	ProxyPass string
}

func (h *Handler) openTunnel(ctx context.Context, host string, port uint16, proto string) (net.Conn, error) {
	if h.Pool != nil {
		conn, err := h.Pool.Acquire(ctx, host, port, proto)
		if err == nil {
			return conn, nil
		}
	}
	return tunnel.Open(ctx, h.Cfg, host, port, proto)
}

var resp407 = []byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"VPNProxy\"\r\nContent-Length: 0\r\n\r\n")
var resp400 = []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
var resp200 = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")

func (h *Handler) Handle(client net.Conn) {
	defer client.Close()
	setSocketOpts(client)

	headerBuf := make([]byte, 8192)
	total := 0
	for {
		if total >= len(headerBuf) {
			return
		}
		n, err := client.Read(headerBuf[total:])
		if err != nil || n == 0 {
			return
		}
		total += n
		if bytes.Contains(headerBuf[:total], []byte("\r\n\r\n")) {
			break
		}
	}

	if h.ProxyUser != "" && h.ProxyPass != "" {
		if !frame.CheckHTTPBasicAuth(headerBuf[:total], h.ProxyUser, h.ProxyPass) {
			client.Write(resp407)
			total = 0
			for {
				if total >= len(headerBuf) {
					return
				}
				n, err := client.Read(headerBuf[total:])
				if err != nil || n == 0 {
					return
				}
				total += n
				if bytes.Contains(headerBuf[:total], []byte("\r\n\r\n")) {
					break
				}
			}
			if !frame.CheckHTTPBasicAuth(headerBuf[:total], h.ProxyUser, h.ProxyPass) {
				client.Write(resp407)
				return
			}
		}
	}

	targetHost, targetPort, err := frame.ParseHTTPConnectTarget(headerBuf[:total])
	if err != nil {
		client.Write(resp400)
		return
	}

	log.Printf("HTTP CONNECT to %s:%d", targetHost, targetPort)

	tunnelConn, err := h.openTunnel(context.Background(), targetHost, targetPort, "tcp")
	if err != nil {
		client.Write(resp400)
		return
	}

	client.Write(resp200)
	log.Printf("HTTP CONNECT OK to %s:%d", targetHost, targetPort)
	tunnel.RelayBidirectional(client, tunnelConn)
}

func setSocketOpts(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetReadBuffer(256 * 1024)
		tcpConn.SetWriteBuffer(256 * 1024)
	}
}