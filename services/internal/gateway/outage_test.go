package gateway

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ai-access/internal/token"
)

func TestKeySourceOutageIsLogged(t *testing.T) {
	f := newFixture(t)
	dead := httptest.NewServer(nil)
	dead.Close()
	f.ver = token.NewVerifier(dead.URL, "https://sts.example.internal", gwAud, nil)
	up := httptest.NewTLSServer(http.NotFoundHandler())
	defer up.Close()
	h := f.handler(up, &bytes.Buffer{})
	logs := &bytes.Buffer{}
	h.(*handler).opLog = logs
	tok := f.token(t, nil)
	w := do(h, "POST", "/v1/messages", "", map[string]string{"Authorization": "Bearer " + tok})
	if w.Code != 401 || strings.TrimSpace(w.Body.String()) != "unauthorized" {
		t.Fatal(w.Code, w.Body.String())
	}
	if logs.String() != "gateway: outage category=jwks_unreachable\n" {
		t.Fatalf("log %q", logs.String())
	}
	if strings.Contains(logs.String(), strings.Split(tok, ".")[1]) {
		t.Fatal("log leaks token")
	}
}

func TestBadTokenIsNotAnOutage(t *testing.T) {
	f := newFixture(t)
	up := httptest.NewTLSServer(http.NotFoundHandler())
	defer up.Close()
	h := f.handler(up, &bytes.Buffer{})
	logs := &bytes.Buffer{}
	h.(*handler).opLog = logs
	if w := do(h, "POST", "/v1/messages", "", map[string]string{"Authorization": "Bearer junk"}); w.Code != 401 || logs.Len() != 0 {
		t.Fatal(w.Code, logs.String())
	}
}
