// Command sts runs the security token service.
package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"ai-access/internal/sts"
	"ai-access/internal/token"
)

func main() {
	cfgPath := os.Getenv("STS_CONFIG")
	cfg, err := sts.LoadConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := token.NewSigner(strings.Split(os.Getenv("STS_SIGNING_KEYS"), ","), os.Getenv("STS_ISSUER"))
	if err != nil {
		log.Fatal(err)
	}
	lookup, err := sts.NewLDAPLookup(cfg.Directory)
	if err != nil {
		log.Fatal(err)
	}
	verifiers := map[string]*token.Verifier{}
	for _, i := range cfg.Issuers {
		verifiers[i.URL] = token.NewVerifier(i.JWKSURL, i.URL, i.Audience, nil)
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
	log.Fatal(srv.ListenAndServe())
}
