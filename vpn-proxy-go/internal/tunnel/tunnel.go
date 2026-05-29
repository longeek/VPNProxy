// Package tunnel implements TLS tunnel connections and bidirectional relay.
//
// The tunnel module is the core transport layer used by both the client
// and server. It handles:
//   - TLS connection setup with configurable session caching and retries
//   - Bidirectional data relay using pooled buffers and buffered writers
//   - Session statistics tracking (upload/download bytes)
//
// Pooling strategy:
//   - relayBufPool: sync.Pool of 128KB relay buffers (reduces GC pressure)
//   - bufWriterPool: sync.Pool of bufio.Writer with 128KB internal buffer
package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Config holds connection parameters for the TLS tunnel.
type Config struct {
	Server     string
	ServerPort uint16
	Token      string
	SNI        string
	Insecure   bool
	CACert     string
	Retries    uint32
	RetryDelay float64
	tlsCache   *tls.Config // cached TLS config for session resumption
}

// BootstrapInfo is the JSON payload sent over a new tunnel connection
// to authenticate and specify the target. Serialized once per connection.
type BootstrapInfo struct {
	Auth  string `json:"auth"`
	Host  string `json:"host"`
	Port  uint16 `json:"port"`
	Proto string `json:"proto,omitempty"`
}

// buildTLSConfig creates a tls.Config with:
//   - LRU session cache (128 entries) for TLS session resumption
//   - P-256 and X25519 curve preferences for fast ECDHE
//   - SNI set to the server name or custom SNI override
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

// cachedTLSConfig returns the cached TLS config (built once, reused for
// session resumption across connections to the same server).
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

// Open establishes a TLS tunnel to the proxy server, authenticates with
// the token, and requests forwarding to the target host:port.
//
// Retry logic uses exponential backoff (base=RetryDelay, doubled each
// attempt). Context cancellation is respected between retries and during
// the TLS dial.
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

// Buffer and threshold constants:
//   - PipeBufSize:   128KB read/write chunk for relay
//   - DrainThreshold: flush buffered writer when pending >= this
//   - RecvBufSize:   256KB OS socket buffer (send/recv)
const (
	PipeBufSize    = 131072
	DrainThreshold = 128 * 1024
	RecvBufSize    = 256 * 1024
)

// relayBufPool pools 128KB relay buffers to reduce per-connection allocations.
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

// bufWriterPool pools bufio.Writer objects to reduce per-connection allocations.
// Each writer is pre-allocated with PipeBufSize internal buffer.
var bufWriterPool = sync.Pool{
	New: func() any {
		return bufio.NewWriterSize(nil, PipeBufSize)
	},
}

// GetBufWriter retrieves a pooled bufio.Writer and resets it to the given writer.
func GetBufWriter(w io.Writer) *bufio.Writer {
	bw := bufWriterPool.Get().(*bufio.Writer)
	bw.Reset(w)
	return bw
}

// PutBufWriter resets the writer to discard (safe nil-free reset) and returns it to the pool.
func PutBufWriter(bw *bufio.Writer) {
	bw.Reset(io.Discard)
	bufWriterPool.Put(bw)
}

// RelayBidirectional copies data in both directions between client and tunnel
// using two goroutines. On Linux, io.CopyBuffer may use splice(2) for zero-copy
// TCP-to-TCP transfers when both sides are *net.TCPConn.
//
// Stats counters are updated atomically after each direction completes.
func RelayBidirectional(client, tunnel net.Conn, upStats, downStats *uint64) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := getRelayBuf()
		defer putRelayBuf(buf)
		n, _ := io.CopyBuffer(tunnel, client, buf)
		tunnel.Close()
		if upStats != nil {
			atomic.AddUint64(upStats, uint64(n))
		}
	}()

	go func() {
		defer wg.Done()
		buf := getRelayBuf()
		defer putRelayBuf(buf)
		n, _ := io.CopyBuffer(client, tunnel, buf)
		client.Close()
		if downStats != nil {
			atomic.AddUint64(downStats, uint64(n))
		}
	}()

	wg.Wait()
}

// RelayTCPServer performs bidirectional TCP relay on the server side with
// threshold-based flushing to balance throughput and latency:
//   - Data is buffered via a pooled bufio.Writer (128KB internal buffer)
//   - Flush is triggered when pending data reaches DrainThreshold (128KB)
//   - This amortizes syscall overhead without introducing head-of-line blocking
//
// Both goroutines use pooled relay buffers and pooled buffered writers.
func RelayTCPServer(tlsConn, target net.Conn, stats *SessionStats) {
	bufUp := getRelayBuf()
	bufDown := getRelayBuf()
	done := make(chan struct{}, 2)

	// Upload: tlsConn → target (client data → backend server)
	go func() {
		defer putRelayBuf(bufUp)
		bw := GetBufWriter(target)
		defer PutBufWriter(bw)
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

	// Download: target → tlsConn (backend response → client)
	go func() {
		defer putRelayBuf(bufDown)
		bw := GetBufWriter(tlsConn)
		defer PutBufWriter(bw)
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

// SessionStats tracks bytes transferred in each direction for a session.
// Uses atomic counters for lock-free concurrent access from relay goroutines.
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
