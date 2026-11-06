// Command sts runs the security token service.
package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"ai-access/internal/harden"
	"ai-access/internal/sts"
	"ai-access/internal/token"
)

func main() {
	if err := harden.DisableCoreDumps(); err != nil {
		log.Fatal(err)
	}
	cfgPath := os.Getenv("STS_CONFIG")
	cfg, err := sts.LoadConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := token.NewSigner(strings.Split(os.Getenv("STS_SIGNING_KEYS"), ","), os.Getenv("STS_ISSUER"))
	if err != nil {
		log.Fatal(err)
	}
	pool, err := harden.LoadPool(os.Getenv("STS_CA_FILE"))
	if err != nil {
		log.Fatal("STS_CA_FILE: ", err)
	}
	lookup, err := sts.NewLDAPLookup(cfg.Directory, pool)
	if err != nil {
		log.Fatal(err)
	}
	jwksClient := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: harden.NoRedirect,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}},
	}
	verifiers := map[string]*token.Verifier{}
	for _, i := range cfg.Issuers {
		if err := harden.RequireHTTPS(i.JWKSURL); err != nil {
			log.Fatal("issuer jwks_url: ", err)
		}
		verifiers[i.URL] = token.NewVerifier(i.JWKSURL, i.URL, i.Audience, jwksClient)
	}
	addr := os.Getenv("STS_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           sts.NewHandler(cfg, verifiers, signer, lookup, os.Stdout),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Fatal(harden.ServeTLS(srv, os.Getenv("STS_TLS_CERT"), os.Getenv("STS_TLS_KEY")))
}
