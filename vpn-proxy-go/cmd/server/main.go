package main

import (
	"flag"
	"fmt"
	"log"
	"os"
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
	}

	listenAddr := fmt.Sprintf("%s:%d", *listen, *port)
	server.Run(cfg, *cert, *key, listenAddr)
}