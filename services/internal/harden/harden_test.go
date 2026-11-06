package harden

import (
	"net/http"
	"syscall"
	"testing"
)

func TestDisableCoreDumps(t *testing.T) {
	if err := DisableCoreDumps(); err != nil {
		t.Fatal(err)
	}
	var l syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &l); err != nil || l.Cur != 0 {
		t.Fatal(l, err)
	}
}

func TestRequireHTTPS(t *testing.T) {
	for _, u := range []string{"http://sts.example.internal/x", "", "sts", "https://", "ftp://a"} {
		if RequireHTTPS(u) == nil {
			t.Errorf("accepted %q", u)
		}
	}
	if err := RequireHTTPS("https://sts.example.internal/.well-known/jwks.json"); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPoolAndServeTLSRequired(t *testing.T) {
	if _, err := LoadPool("/nonexistent"); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := ServeTLS(&http.Server{}, "", ""); err == nil {
		t.Fatal("missing cert accepted")
	}
}
