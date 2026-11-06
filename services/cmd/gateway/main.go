// Command gateway runs the pass-through AI gateway.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"ai-access/internal/gateway"
	"ai-access/internal/harden"
	"ai-access/internal/token"
)

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	must(harden.DisableCoreDumps())
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(os.Getenv("GATEWAY_CA_FILE"))
	must(err)
	if !pool.AppendCertsFromPEM(ca) {
		log.Fatal("no certificates in GATEWAY_CA_FILE")
	}
	cert, err := tls.LoadX509KeyPair(os.Getenv("GATEWAY_CLIENT_CERT"), os.Getenv("GATEWAY_CLIENT_KEY"))
	must(err)
	transport := &http.Transport{
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{cert}},
		ResponseHeaderTimeout: 5 * time.Minute,
		IdleConnTimeout:       90 * time.Second,
	}
	jwksClient := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: harden.NoRedirect,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}},
	}
	jwksURL := os.Getenv("GATEWAY_STS_JWKS_URL")
	if err := harden.RequireHTTPS(jwksURL); err != nil {
		log.Fatal("GATEWAY_STS_JWKS_URL: ", err)
	}
	v := token.NewVerifier(jwksURL, os.Getenv("GATEWAY_STS_ISSUER"), os.Getenv("GATEWAY_AUDIENCE"), jwksClient)
	cfg := gateway.Config{UpstreamURL: os.Getenv("GATEWAY_UPSTREAM_URL"), BatchServiceURL: os.Getenv("GATEWAY_BATCH_URL")}
	if s := os.Getenv("GATEWAY_MAX_BODY_BYTES"); s != "" {
		cfg.MaxBodyBytes, err = strconv.ParseInt(s, 10, 64)
		must(err)
	}
	addr := os.Getenv("GATEWAY_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	h, err := gateway.NewHandler(cfg, v, transport, os.Stdout)
	must(err)
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	log.Fatal(harden.ServeTLS(srv, os.Getenv("GATEWAY_TLS_CERT"), os.Getenv("GATEWAY_TLS_KEY")))
}
