package harden

import (
	"net/http"
	"net/http/httptest"
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

func TestNoRedirect(t *testing.T) {
	var hits int
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer dst.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dst.URL, http.StatusFound)
	}))
	defer src.Close()
	c := &http.Client{CheckRedirect: NoRedirect}
	resp, err := c.Get(src.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits != 0 || resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect followed: hits=%d status=%d", hits, resp.StatusCode)
	}
}
