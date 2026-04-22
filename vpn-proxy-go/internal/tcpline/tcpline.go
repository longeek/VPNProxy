package tcpline

import (
	"context"
	"fmt"
	"log"
	"net"

	"vpn-proxy-go/internal/frame"
	"vpn-proxy-go/internal/pool"
	"vpn-proxy-go/internal/tunnel"
)

type Handler struct {
	Cfg  *tunnel.Config
	Pool *pool.Pool
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

func (h *Handler) Handle(client net.Conn) {
	defer client.Close()
	setSocketOpts(client)

	lineBuf := make([]byte, 4096)
	total := 0
	for {
		if total >= len(lineBuf) {
			return
		}
		n, err := client.Read(lineBuf[total:])
		if err != nil || n == 0 {
			return
		}
		total += n
		if containsNewline(lineBuf[:total]) {
			break
		}
	}

	newlinePos := findNewline(lineBuf[:total])
	if newlinePos < 0 {
		newlinePos = total
	}
	line := lineBuf[:newlinePos]

	targetHost, targetPort, err := frame.ParseTCPLineTarget(line)
	if err != nil {
		log.Printf("TCP line parse failed: %v", err)
		client.Write([]byte(fmt.Sprintf("ERR %v\n", err)))
		return
	}

	log.Printf("TCP line target -> %s:%d", targetHost, targetPort)

	tunnelConn, err := h.openTunnel(context.Background(), targetHost, targetPort, "tcp")
	if err != nil {
		log.Printf("TCP line tunnel failed: %v", err)
		client.Write([]byte(fmt.Sprintf("ERR %v\n", err)))
		return
	}

	client.Write([]byte("OK\n"))
	log.Printf("TCP tunnel OK -> %s:%d", targetHost, targetPort)
	tunnel.RelayBidirectional(client, tunnelConn)
}

func containsNewline(buf []byte) bool {
	for _, b := range buf {
		if b == '\n' {
			return true
		}
	}
	return false
}

func findNewline(buf []byte) int {
	for i, b := range buf {
		if b == '\n' {
			return i
		}
	}
	return -1
}

func setSocketOpts(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetReadBuffer(256 * 1024)
		tcpConn.SetWriteBuffer(256 * 1024)
	}
}