package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof" // register pprof handlers on default mux
	"os"
	"os/signal"
	"syscall"
	"time"

	"vpn-proxy-go/internal/server"
)

func main() {
	listen := flag.String("listen", "0.0.0.0", "listen address")
	port := flag.Int("port", 8443, "listen port")
	cert := flag.String("cert", "./certs/server.crt", "TLS certificate path")
	key := flag.String("key", "./certs/server.key", "TLS private key path")
	token := flag.String("token", "", "shared auth token")
	tokensFile := flag.String("tokens-file", "", "file with one token per line")
	allowCIDRs := flag.String("allow-cidrs", "", "comma-separated client IP CIDRs")
	connectTimeout := flag.Float64("connect-timeout", 8, "backend connect timeout seconds")
	bootstrapTimeout := flag.Float64("bootstrap-timeout", 30, "bootstrap line read timeout seconds")
	maxConns := flag.Int("max-conns", 0, "max concurrent connections (0 = unlimited)")
	pprofAddr := flag.String("pprof-addr", "", "pprof HTTP listen address (e.g. localhost:6060, empty=disabled)")

	flag.Parse()

	tokens := server.LoadAllowedTokens(*token, *tokensFile)
	if len(tokens) == 0 {
		fmt.Fprintln(os.Stderr, "missing token(s): set --token or --tokens-file")
		os.Exit(1)
	}

	allowNets := server.ParseAllowCIDRs(*allowCIDRs)
	if len(allowNets) > 0 {
		log.Printf("allow-cidrs enabled with %d network(s)", len(allowNets))
	}

	cfg := &server.AppConfig{
		AllowedTokens:    tokens,
		AllowNetworks:    allowNets,
		ConnectTimeout:   time.Duration(*connectTimeout) * time.Second,
		BootstrapTimeout: time.Duration(*bootstrapTimeout) * time.Second,
		MaxConns:         *maxConns,
	}

	listenAddr := fmt.Sprintf("%s:%d", *listen, *port)

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("shutting down...")
		cancel()
	}()

	// Start pprof HTTP server if address is provided
	if *pprofAddr != "" {
		pprofLn, err := net.Listen("tcp", *pprofAddr)
		if err != nil {
			log.Fatalf("pprof listen failed on %s: %v", *pprofAddr, err)
		}
		go func() {
			log.Printf("pprof listening on %s", pprofLn.Addr())
			if err := http.Serve(pprofLn, nil); err != nil {
				log.Printf("pprof server stopped: %v", err)
			}
		}()
		// Close pprof on shutdown
		go func() {
			<-ctx.Done()
			pprofLn.Close()
		}()
	}

	server.RunWithContext(ctx, cfg, *cert, *key, listenAddr)
}
