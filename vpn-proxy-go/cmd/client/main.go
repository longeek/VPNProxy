package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"vpn-proxy-go/internal/httpproxy"
	"vpn-proxy-go/internal/pool"
	"vpn-proxy-go/internal/selector"
	"vpn-proxy-go/internal/socks"
	"vpn-proxy-go/internal/tcpline"
	"vpn-proxy-go/internal/tunnel"
)

func main() {
	listen := flag.String("listen", "127.0.0.1", "local listen address")
	listenPort := flag.Int("listen-port", 1080, "local SOCKS5 listen port")
	httpPort := flag.Int("http-port", 0, "local HTTP CONNECT listen port (0=disabled)")
	tcpLinePort := flag.Int("tcp-line-port", 0, "local TCP line listen port (0=disabled)")
	server := flag.String("server", "", "remote server host (ignored if --servers is set)")
	serverPort := flag.Int("server-port", 8443, "remote server port")
	servers := flag.String("servers", "", "comma-separated server list host:port,host:port for auto-select")
	probeTimeout := flag.Float64("probe-timeout", 5.0, "per-server probe timeout in seconds")
	bandwidth := flag.Bool("bandwidth", false, "measure tunnel throughput during server selection (adds ~3s per server)")
	token := flag.String("token", "", "shared auth token")
	sni := flag.String("sni", "", "TLS SNI override")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	caCert := flag.String("ca-cert", "", "CA certificate file")
	connectRetries := flag.Int("connect-retries", 2, "number of retries")
	retryDelay := flag.Float64("retry-delay", 0.8, "retry delay seconds")
	poolSize := flag.Int("pool-size", 8, "tunnel pool size (0=disabled)")
	poolTTL := flag.Float64("pool-ttl", 60.0, "tunnel pool TTL seconds")
	reuse := flag.Bool("reuse", false, "enable TCP tunnel reuse (keep connections alive across relays)")
	prefer := flag.String("prefer", "", "preferred server host (select this server if reachable, fallback to benchmark)")
	proxyUser := flag.String("proxy-user", "", "proxy auth username")
	proxyPass := flag.String("proxy-pass", "", "proxy auth password")

	flag.Parse()

	if *token == "" {
		fmt.Fprintln(os.Stderr, "missing --token")
		os.Exit(1)
	}
	if (*proxyUser != "") != (*proxyPass != "") {
		fmt.Fprintln(os.Stderr, "--proxy-user and --proxy-pass must be specified together")
		os.Exit(1)
	}

	cfg := &tunnel.Config{
		Token:      *token,
		SNI:        *sni,
		Insecure:   *insecure,
		CACert:     *caCert,
		Retries:    uint32(*connectRetries),
		RetryDelay: *retryDelay,
		Reuse:      *reuse,
	}

	// Server selection: --servers (multi, auto-probe) or --server/--server-port (single, backward compat)
	if *servers != "" {
		serverList := parseServers(*servers)
		if len(serverList) == 0 {
			fmt.Fprintln(os.Stderr, "invalid --servers format; expected host:port,host:port")
			os.Exit(1)
		}
		if len(serverList) == 1 {
			cfg.Server = serverList[0].Host
			cfg.ServerPort = serverList[0].Port
			log.Printf("single server from --servers: %s:%d", cfg.Server, cfg.ServerPort)
		} else {
			log.Printf("benchmarking %d servers (this may take a moment)...", len(serverList))
			// With --bandwidth, the probe includes a 3s bandwidth measurement per server
			bwFactor := 1.0
			if *bandwidth {
				bwFactor = 1.6 // ~3s bandwidth probe + 1s latency per server
			}
			probeCtx, cancel := context.WithTimeout(context.Background(),
				time.Duration(*probeTimeout*bwFactor*float64(len(serverList)))*time.Second)
			defer cancel()

			var best selector.Server
			var latency time.Duration
			var err error
			if *bandwidth {
				var bw float64
				best, latency, bw, err = selector.SelectByBandwidth(probeCtx, serverList, *token, *insecure)
				if err == nil {
					log.Printf("selected %s (latency=%dms, bandwidth=%.0f KB/s) from %d candidates",
						best.Addr(), latency.Milliseconds(), bw, len(serverList))
				}
			} else {
				best, latency, err = selector.SelectByBenchmark(probeCtx, serverList, *token, *insecure, *prefer)
				if err == nil {
					log.Printf("selected %s (benchmark=%dms) from %d candidates",
						best.Addr(), latency.Milliseconds(), len(serverList))
				}
			}
			if err != nil {
				log.Fatalf("server selection failed: %v", err)
			}
			cfg.Server = best.Host
			cfg.ServerPort = best.Port
		}
	} else {
		if *server == "" {
			fmt.Fprintln(os.Stderr, "missing --server (or use --servers for multi-server auto-select)")
			os.Exit(1)
		}
		cfg.Server = *server
		cfg.ServerPort = uint16(*serverPort)
		log.Printf("single server (legacy mode): %s:%d", cfg.Server, cfg.ServerPort)
	}

	var pl *pool.Pool
	if *poolSize > 0 {
		pl = pool.New(cfg, *poolSize, time.Duration(*poolTTL)*time.Second)
		pl.Start(context.Background())
		log.Printf("tunnel pool started (size=%d, ttl=%.1fs)", *poolSize, *poolTTL)
	}

	socksHandler := &socks.Handler{
		Cfg:       cfg,
		Pool:      pl,
		ProxyUser: *proxyUser,
		ProxyPass: *proxyPass,
	}

	httpHandler := &httpproxy.Handler{
		Cfg:       cfg,
		Pool:      pl,
		ProxyUser: *proxyUser,
		ProxyPass: *proxyPass,
	}

	tcpLineHandler := &tcpline.Handler{
		Cfg:  cfg,
		Pool: pl,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	startListener := func(addr string, handler func(net.Conn)) {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("cannot bind %s: %v", addr, err)
		}
		log.Printf("listening on %s", addr)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				conn, err := ln.Accept()
				if err != nil {
					select {
					case <-ctx.Done():
						return
					default:
						continue
					}
				}
				go handler(conn)
			}
		}()
	}

	socksAddr := fmt.Sprintf("%s:%d", *listen, *listenPort)
	startListener(socksAddr, socksHandler.Handle)

	if *httpPort > 0 {
		httpAddr := fmt.Sprintf("%s:%d", *listen, *httpPort)
		startListener(httpAddr, httpHandler.Handle)
	}

	if *tcpLinePort > 0 {
		tcpAddr := fmt.Sprintf("%s:%d", *listen, *tcpLinePort)
		startListener(tcpAddr, tcpLineHandler.Handle)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh
	log.Println("shutting down...")
	cancel()

	if pl != nil {
		pl.Stop()
	}
	wg.Wait()
}

// parseServers parses a comma-separated list of "host:port" entries
// into a slice of Server values for probing and selection.
func parseServers(input string) []selector.Server {
	parts := strings.Split(input, ",")
	var result []selector.Server
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		host, portStr, err := net.SplitHostPort(p)
		if err != nil {
			log.Printf("warning: skipping invalid server entry %q: %v", p, err)
			continue
		}
		portNum, err := net.LookupPort("tcp", portStr)
		if err != nil {
			log.Printf("warning: skipping invalid port in %q: %v", p, err)
			continue
		}
		result = append(result, selector.Server{Host: host, Port: uint16(portNum)})
	}
	return result
}
