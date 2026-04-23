package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	Server     string
	ServerPort uint16
	Token      string
	SNI        string
	Insecure   bool
	CACert     string
	Retries    uint32
	RetryDelay float64
	tlsCache   *tls.Config
}

type BootstrapInfo struct {
	Auth  string `json:"auth"`
	Host  string `json:"host"`
	Port  uint16 `json:"port"`
	Proto string `json:"proto,omitempty"`
}

func buildTLSConfig(cfg *Config) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.Insecure,
		ClientSessionCache: tls.NewLRUClientSessionCache(128),
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.CurveP256},
	}
	if cfg.SNI != "" {
		tlsCfg.ServerName = cfg.SNI
	} else {
		tlsCfg.ServerName = cfg.Server
	}
	return tlsCfg, nil
}

func (c *Config) cachedTLSConfig() (*tls.Config, error) {
	if c.tlsCache != nil {
		return c.tlsCache, nil
	}
	tlsCfg, err := buildTLSConfig(c)
	if err != nil {
		return nil, err
	}
	c.tlsCache = tlsCfg
	return tlsCfg, nil
}

func Open(ctx context.Context, cfg *Config, targetHost string, targetPort uint16, proto string) (net.Conn, error) {
	tlsCfg, err := cfg.cachedTLSConfig()
	if err != nil {
		return nil, err
	}
	addr := fmt.Sprintf("%s:%d", cfg.Server, cfg.ServerPort)

	var lastErr error
	for attempt := 0; attempt <= int(cfg.Retries); attempt++ {
		if attempt > 0 {
			delay := cfg.RetryDelay
			for j := 0; j < attempt-1; j++ {
				delay *= 2
			}
			select {
			case <-time.After(time.Duration(delay) * time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err != nil {
			lastErr = err
			continue
		}
		setTunnelSocketOpts(conn)

		payload := BootstrapInfo{
			Auth:  cfg.Token,
			Host:  targetHost,
			Port:  targetPort,
			Proto: proto,
		}
		if proto == "tcp" {
			payload.Proto = ""
		}
		bs, _ := json.Marshal(payload)
		bs = append(bs, '\n')

		if _, err := conn.Write(bs); err != nil {
			conn.Close()
			lastErr = err
			continue
		}

		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		statusBuf := make([]byte, 128)
		n, err := conn.Read(statusBuf)
		conn.SetReadDeadline(time.Time{})
		if err != nil {
			conn.Close()
			lastErr = err
			continue
		}
		status := string(statusBuf[:n])
		if strings.HasPrefix(status, "OK") {
			return conn, nil
		}
		conn.Close()
		lastErr = fmt.Errorf("server refused: %s", strings.TrimSpace(status))
	}

	return nil, fmt.Errorf("all retries exhausted: %v", lastErr)
}

const (
	PipeBufSize    = 131072
	DrainThreshold = 128 * 1024
	RecvBufSize    = 256 * 1024
)

var relayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, PipeBufSize)
		return &b
	},
}

func getRelayBuf() []byte {
	return *relayBufPool.Get().(*[]byte)
}

func putRelayBuf(b []byte) {
	relayBufPool.Put(&b)
}

func RelayBidirectional(client, tunnel net.Conn, upStats, downStats *uint64) {
	bufUp := getRelayBuf()
	bufDown := getRelayBuf()
	done := make(chan struct{}, 2)

	go func() {
		defer putRelayBuf(bufUp)
		bw := bufio.NewWriterSize(tunnel, PipeBufSize)
		pending := 0
		for {
			n, err := client.Read(bufUp)
			if n > 0 {
				if _, werr := bw.Write(bufUp[:n]); werr != nil {
					break
				}
				pending += n
				if upStats != nil {
					atomic.AddUint64(upStats, uint64(n))
				}
				if pending >= DrainThreshold {
					if bw.Flush() != nil {
						break
					}
					pending = 0
				}
			}
			if err != nil {
				break
			}
		}
		if pending > 0 {
			bw.Flush()
		}
		tunnel.Close()
		done <- struct{}{}
	}()

	go func() {
		defer putRelayBuf(bufDown)
		bw := bufio.NewWriterSize(client, PipeBufSize)
		pending := 0
		for {
			n, err := tunnel.Read(bufDown)
			if n > 0 {
				if _, werr := bw.Write(bufDown[:n]); werr != nil {
					break
				}
				pending += n
				if downStats != nil {
					atomic.AddUint64(downStats, uint64(n))
				}
				if pending >= DrainThreshold {
					if bw.Flush() != nil {
						break
					}
					pending = 0
				}
			}
			if err != nil {
				break
			}
		}
		if pending > 0 {
			bw.Flush()
		}
		client.Close()
		done <- struct{}{}
	}()

	<-done
	<-done
}

func RelayTCPServer(tlsConn, target net.Conn, stats *SessionStats) {
	bufUp := getRelayBuf()
	bufDown := getRelayBuf()
	done := make(chan struct{}, 2)

	go func() {
		defer putRelayBuf(bufUp)
		bw := bufio.NewWriterSize(target, PipeBufSize)
		pending := 0
		for {
			n, err := tlsConn.Read(bufUp)
			if n > 0 {
				if _, werr := bw.Write(bufUp[:n]); werr != nil {
					break
				}
				pending += n
				stats.UploadBytes.Add(uint64(n))
				if pending >= DrainThreshold {
					if bw.Flush() != nil {
						break
					}
					pending = 0
				}
			}
			if err != nil {
				break
			}
		}
		if pending > 0 {
			bw.Flush()
		}
		target.Close()
		done <- struct{}{}
	}()

	go func() {
		defer putRelayBuf(bufDown)
		bw := bufio.NewWriterSize(tlsConn, PipeBufSize)
		pending := 0
		for {
			n, err := target.Read(bufDown)
			if n > 0 {
				if _, werr := bw.Write(bufDown[:n]); werr != nil {
					break
				}
				pending += n
				stats.DownloadBytes.Add(uint64(n))
				if pending >= DrainThreshold {
					if bw.Flush() != nil {
						break
					}
					pending = 0
				}
			}
			if err != nil {
				break
			}
		}
		if pending > 0 {
			bw.Flush()
		}
		tlsConn.Close()
		done <- struct{}{}
	}()

	<-done
	<-done
}

type SessionStats struct {
	UploadBytes   atomic.Uint64
	DownloadBytes atomic.Uint64
}

func setTunnelSocketOpts(conn *tls.Conn) {
	raw, ok := conn.NetConn().(*net.TCPConn)
	if !ok {
		return
	}
	raw.SetNoDelay(true)
	raw.SetReadBuffer(RecvBufSize)
	raw.SetWriteBuffer(RecvBufSize)
}