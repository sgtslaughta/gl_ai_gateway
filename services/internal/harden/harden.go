// Package harden holds process hardening helpers.
package harden

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"os"
	"syscall"
)

// DisableCoreDumps sets the core file size limit to zero.
func DisableCoreDumps() error {
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}

// RequireHTTPS returns an error unless raw is an absolute https URL.
func RequireHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("url must be an absolute https URL")
	}
	return nil
}

// LoadPool reads a PEM CA bundle into a new pool.
func LoadPool(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(b) {
		return nil, errors.New("no certificates in " + path)
	}
	return p, nil
}

// ServeTLS serves srv over TLS 1.2+ using the cert and key files. Both must be set.
func ServeTLS(srv *http.Server, certFile, keyFile string) error {
	if certFile == "" || keyFile == "" {
		return errors.New("TLS cert and key are required")
	}
	srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return srv.ListenAndServeTLS(certFile, keyFile)
}
