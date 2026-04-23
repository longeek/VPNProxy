package socks

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"

	"vpn-proxy-go/internal/frame"
	"vpn-proxy-go/internal/pool"
	"vpn-proxy-go/internal/tunnel"
)

const Version = 5

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

func (h *Handler) Handle(client net.Conn) {
	defer client.Close()
	setSocketOpts(client)

	targetHost, targetPort, cmd, err := h.handshake(client)
	if err != nil {
		log.Printf("SOCKS handshake failed: %v", err)
		return
	}

	if cmd == 0x03 {
		h.handleUDP(client, targetHost, targetPort)
		return
	}

	log.Printf("SOCKS CONNECT to %s:%d", targetHost, targetPort)

	tunnelConn, err := h.openTunnel(context.Background(), targetHost, targetPort, "tcp")
	if err != nil {
		log.Printf("tunnel failed: %v", err)
		sendSocksReply(client, 0x01)
		return
	}

	sendSocksReply(client, 0x00)
	log.Printf("SOCKS CONNECT OK to %s:%d", targetHost, targetPort)
	tunnel.RelayBidirectional(client, tunnelConn, nil, nil)
}

func (h *Handler) handshake(client net.Conn) (host string, port uint16, cmd byte, err error) {
	header := make([]byte, 2)
	if _, err = io.ReadFull(client, header); err != nil {
		return "", 0, 0, err
	}
	if header[0] != Version {
		return "", 0, 0, fmt.Errorf("unsupported SOCKS version")
	}
	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err = io.ReadFull(client, methods); err != nil {
		return "", 0, 0, err
	}

	if h.ProxyUser != "" {
		if !containsMethod(methods, 0x02) {
			client.Write([]byte{Version, 0xFF})
			return "", 0, 0, fmt.Errorf("auth required")
		}
		client.Write([]byte{Version, 0x02})
		authVer := make([]byte, 1)
		if _, err = io.ReadFull(client, authVer); err != nil {
			return "", 0, 0, err
		}
		if authVer[0] != 0x01 {
			return "", 0, 0, fmt.Errorf("bad auth version")
		}
		ulen := make([]byte, 1)
		if _, err = io.ReadFull(client, ulen); err != nil {
			return "", 0, 0, err
		}
		username := make([]byte, ulen[0])
		if _, err = io.ReadFull(client, username); err != nil {
			return "", 0, 0, err
		}
		plen := make([]byte, 1)
		if _, err = io.ReadFull(client, plen); err != nil {
			return "", 0, 0, err
		}
		password := make([]byte, plen[0])
		if _, err = io.ReadFull(client, password); err != nil {
			return "", 0, 0, err
		}
		if string(username) != h.ProxyUser || string(password) != h.ProxyPass {
			client.Write([]byte{0x01, 0x01})
			return "", 0, 0, fmt.Errorf("auth failed")
		}
		client.Write([]byte{0x01, 0x00})
	} else {
		if !containsMethod(methods, 0x00) {
			client.Write([]byte{Version, 0xFF})
			return "", 0, 0, fmt.Errorf("no acceptable method")
		}
		client.Write([]byte{Version, 0x00})
	}

	req := make([]byte, 4)
	if _, err = io.ReadFull(client, req); err != nil {
		return "", 0, 0, err
	}
	cmd = req[1]
	atyp := req[3]
	if req[0] != Version || (cmd != 0x01 && cmd != 0x03) {
		return "", 0, 0, fmt.Errorf("unsupported command")
	}

	switch atyp {
	case 0x01:
		addr := make([]byte, 4)
		if _, err = io.ReadFull(client, addr); err != nil {
			return "", 0, 0, err
		}
		host = net.IP(addr).To4().String()
	case 0x03:
		lb := make([]byte, 1)
		if _, err = io.ReadFull(client, lb); err != nil {
			return "", 0, 0, err
		}
		hb := make([]byte, lb[0])
		if _, err = io.ReadFull(client, hb); err != nil {
			return "", 0, 0, err
		}
		host = string(hb)
	case 0x04:
		addr := make([]byte, 16)
		if _, err = io.ReadFull(client, addr); err != nil {
			return "", 0, 0, err
		}
		host = net.IP(addr).To16().String()
	default:
		return "", 0, 0, fmt.Errorf("unsupported ATYP")
	}

	pb := make([]byte, 2)
	if _, err = io.ReadFull(client, pb); err != nil {
		return "", 0, 0, err
	}
	port = binary.BigEndian.Uint16(pb)

	return host, port, cmd, nil
}

func (h *Handler) handleUDP(client net.Conn, targetHost string, targetPort uint16) {
	tunnelConn, err := h.openTunnel(context.Background(), "0.0.0.0", 0, "udp")
	if err != nil {
		log.Printf("UDP tunnel open failed: %v", err)
		sendSocksReply(client, 0x01)
		return
	}

	udpSock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		log.Printf("UDP bind failed: %v", err)
		tunnelConn.Close()
		sendSocksReply(client, 0x01)
		return
	}
	localAddr := udpSock.LocalAddr().(*net.UDPAddr)
	bindPort := localAddr.Port

	sendSocksReplyBound(client, 0x00, "127.0.0.1", bindPort)

	pendingMu := sync.Mutex{}
	pending := map[string][]net.UDPAddr{}

	var tunnelWriteMu sync.Mutex
	bw := bufio.NewWriterSize(tunnelConn, tunnel.PipeBufSize)
	pendingWrite := 0

	go func() {
		for {
			f, err := frame.ReadFromStreamPooled(tunnelConn)
			if err != nil {
				break
			}
			pkt := frame.SocksUdpBuildReply(f.Host, f.Port, f.Data)
			key := f.Host + ":" + strconv.Itoa(int(f.Port))
			pendingMu.Lock()
			entries, ok := pending[key]
			if ok && len(entries) > 0 {
				addr := entries[0]
				if len(entries) > 1 {
					pending[key] = entries[1:]
				} else {
					delete(pending, key)
				}
				pendingMu.Unlock()
				udpSock.WriteToUDP(pkt, &addr)
			} else {
				delete(pending, key)
				pendingMu.Unlock()
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, srcAddr, err := udpSock.ReadFromUDP(buf)
		if err != nil {
			break
		}
		h, p, payload, err := frame.SocksUdpParseRequest(buf[:n])
		if err != nil {
			continue
		}

		pendingMu.Lock()
		key := h + ":" + strconv.Itoa(int(p))
		pending[key] = append(pending[key], *srcAddr)
		pendingMu.Unlock()

		tunnelWriteMu.Lock()
		packedLen, werr := frame.PackTo(bw, h, p, payload)
		if werr != nil {
			tunnelWriteMu.Unlock()
			break
		}
		pendingWrite += packedLen
		if pendingWrite >= tunnel.DrainThreshold {
			bw.Flush()
			pendingWrite = 0
		}
		tunnelWriteMu.Unlock()
	}

	if pendingWrite > 0 {
		bw.Flush()
	}
	udpSock.Close()
	tunnelConn.Close()
}

func sendSocksReply(w net.Conn, rep byte) {
	w.Write([]byte{Version, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func sendSocksReplyBound(w net.Conn, rep byte, host string, port int) {
	ip := net.ParseIP(host)
	if v4 := ip.To4(); v4 != nil {
		reply := []byte{Version, rep, 0x00, 0x01}
		reply = append(reply, v4...)
		reply = append(reply, byte(port>>8), byte(port))
		w.Write(reply)
	} else {
		reply := []byte{Version, rep, 0x00, 0x04}
		reply = append(reply, ip.To16()...)
		reply = append(reply, byte(port>>8), byte(port))
		w.Write(reply)
	}
}

func containsMethod(methods []byte, m byte) bool {
	for _, v := range methods {
		if v == m {
			return true
		}
	}
	return false
}

func setSocketOpts(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		tcpConn.SetReadBuffer(256 * 1024)
		tcpConn.SetWriteBuffer(256 * 1024)
	}
}