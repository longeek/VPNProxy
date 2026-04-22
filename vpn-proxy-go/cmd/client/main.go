package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"vpn-proxy-go/internal/httpproxy"
	"vpn-proxy-go/internal/pool"
	"vpn-proxy-go/internal/socks"
	"vpn-proxy-go/internal/tcpline"
	"vpn-proxy-go/internal/tunnel"
)

func main() {
	listen := flag.String("listen", "127.0.0.1", "local listen address")
	listenPort := flag.Int("listen-port", 1080, "local SOCKS5 listen port")
	httpPort := flag.Int("http-port", 0, "local HTTP CONNECT listen port (0=disabled)")
	tcpLinePort := flag.Int("tcp-line-port", 0, "local TCP line listen port (0=disabled)")
	server := flag.String("server", "", "remote server host")
	serverPort := flag.Int("server-port", 8443, "remote server port")
	token := flag.String("token", "", "shared auth token")
	sni := flag.String("sni", "", "TLS SNI override")
	insecure := flag.Bool("insecure", false, "skip TLS certificate verification")
	caCert := flag.String("ca-cert", "", "CA certificate file")
	connectRetries := flag.Int("connect-retries", 2, "number of retries")
	retryDelay := flag.Float64("retry-delay", 0.8, "retry delay seconds")
	poolSize := flag.Int("pool-size", 0, "tunnel pool size (0=disabled)")
	poolTTL := flag.Float64("pool-ttl", 8.0, "tunnel pool TTL seconds")
	proxyUser := flag.String("proxy-user", "", "proxy auth username")
	proxyPass := flag.String("proxy-pass", "", "proxy auth password")

	flag.Parse()

	if *server == "" {
		fmt.Fprintln(os.Stderr, "missing --server")
		os.Exit(1)
	}
	if *token == "" {
		fmt.Fprintln(os.Stderr, "missing --token")
		os.Exit(1)
	}
	if (*proxyUser != "") != (*proxyPass != "") {
		fmt.Fprintln(os.Stderr, "--proxy-user and --proxy-pass must be specified together")
		os.Exit(1)
	}

	cfg := &tunnel.Config{
		Server:     *server,
		ServerPort: uint16(*serverPort),
		Token:      *token,
		SNI:        *sni,
		Insecure:   *insecure,
		CACert:     *caCert,
		Retries:    uint32(*connectRetries),
		RetryDelay: *retryDelay,
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