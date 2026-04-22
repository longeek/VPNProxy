package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
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
	}
	if cfg.Insecure {
		if cfg.SNI != "" {
			tlsCfg.ServerName = cfg.SNI
		} else {
			tlsCfg.ServerName = cfg.Server
		}
		return tlsCfg, nil
	}
	if cfg.SNI != "" {
		tlsCfg.ServerName = cfg.SNI
	} else {
		tlsCfg.ServerName = cfg.Server
	}
	return tlsCfg, nil
}

type readResult struct {
	n   int
	err error
}

func Open(ctx context.Context, cfg *Config, targetHost string, targetPort uint16, proto string) (net.Conn, error) {
	tlsCfg, err := buildTLSConfig(cfg)
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

		statusBuf := make([]byte, 64)
		readCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		ch := make(chan readResult, 1)
		go func() {
			n, err := conn.Read(statusBuf)
			ch <- readResult{n: n, err: err}
		}()
		select {
		case r := <-ch:
			cancel()
			if r.err != nil {
				conn.Close()
				lastErr = r.err
				continue
			}
			status := string(statusBuf[:r.n])
			if strings.HasPrefix(status, "OK") {
				return conn, nil
			}
			conn.Close()
			lastErr = fmt.Errorf("server refused: %s", strings.TrimSpace(status))
			continue
		case <-readCtx.Done():
			cancel()
			conn.Close()
			lastErr = fmt.Errorf("bootstrap timeout")
			continue
		}
	}

	return nil, fmt.Errorf("all retries exhausted: %v", lastErr)
}

func RelayBidirectional(client, tunnel net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(tunnel, client)
		tunnel.Close()
		done <- struct{}{}
	}()

	go func() {
		io.Copy(client, tunnel)
		client.Close()
		done <- struct{}{}
	}()

	<-done
	<-done
}