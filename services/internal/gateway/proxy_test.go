package gateway

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ai-access/internal/token"

	"github.com/golang-jwt/jwt/v5"
)

const gwAud = "gateway"

type fixture struct {
	signer *token.Signer
	ver    *token.Verifier
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	kf := filepath.Join(t.TempDir(), "k.pem")
	os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0o600)
	s, err := token.NewSigner([]string{kf}, "https://sts.example.internal")
	if err != nil {
		t.Fatal(err)
	}
	js := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(s.JWKS()) }))
	t.Cleanup(js.Close)
	return &fixture{s, token.NewVerifier(js.URL, "https://sts.example.internal", gwAud, nil)}
}

func (f *fixture) token(t *testing.T, mod func(*token.Claims)) string {
	t.Helper()
	c := token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Audience: jwt.ClaimStrings{gwAud}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))},
		DN:               "cn=alice,dc=example,dc=internal", UserLogin: "alice", ProjectPath: "g/p", Ref: "main",
		SHA: "abc", PipelineID: "100", JobID: "200", RunnerID: 7,
	}
	if mod != nil {
		mod(&c)
	}
	s, err := f.signer.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *fixture) handler(up *httptest.Server, audit io.Writer) http.Handler {
	h, err := NewHandler(Config{UpstreamURL: up.URL, MaxBodyBytes: 1024, BatchServiceURL: "https://batch.example.internal"}, f.ver, up.Client().Transport, audit)
	if err != nil {
		panic(err)
	}
	return h
}

func do(h http.Handler, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestValidRequestsReachUpstream(t *testing.T) {
	f := newFixture(t)
	var mu sync.Mutex
	var gotEntity, gotBody, gotAuth string
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotEntity, gotBody, gotAuth = r.Header.Get("X-Proxied-Entity"), string(b), r.Header.Get("Authorization")+r.Header.Get("x-api-key")
		mu.Unlock()
		w.Write([]byte("ok"))
	}))
	defer up.Close()
	h := f.handler(up, &bytes.Buffer{})
	tok := f.token(t, nil)
	for _, hdr := range []map[string]string{{"Authorization": "Bearer " + tok}, {"x-api-key": tok}} {
		w := do(h, "POST", "/v1/chat/completions", `{"a":1}`, hdr)
		mu.Lock()
		if w.Code != 200 || gotEntity != "cn=alice,dc=example,dc=internal" || gotBody != `{"a":1}` || gotAuth != "" {
			t.Fatal(w.Code, gotEntity, gotBody, gotAuth)
		}
		mu.Unlock()
	}
}

func TestRejections(t *testing.T) {
	f := newFixture(t)
	hits := 0
	var mu sync.Mutex
	up := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { mu.Lock(); hits++; mu.Unlock() }))
	defer up.Close()
	h := f.handler(up, &bytes.Buffer{})
	good := map[string]string{"Authorization": "Bearer " + f.token(t, nil)}
	other := f.token(t, func(c *token.Claims) { c.Audience = jwt.ClaimStrings{"other"} })
	cases := []struct {
		name         string
		method, path string
		body         string
		hdr          map[string]string
		want         int
	}{
		{"garbage token", "POST", "/v1/messages", "", map[string]string{"Authorization": "Bearer junk"}, 401},
		{"no token", "POST", "/v1/messages", "", nil, 401},
		{"wrong aud", "POST", "/v1/messages", "", map[string]string{"Authorization": "Bearer " + other}, 401},
		{"empty dn", "POST", "/v1/messages", "", bearer(f.token(t, func(c *token.Claims) { c.DN = "" })), 401},
		{"ctl dn", "POST", "/v1/messages", "", bearer(f.token(t, func(c *token.Claims) { c.DN = "cn=a\r\nX: y" })), 401},
		{"blocked route", "POST", "/v1/batches", "", good, 403},
		{"blocked method", "GET", "/v1/messages", "", good, 403},
		{"too big", "POST", "/v1/messages", strings.Repeat("a", 2000), good, 413},
	}
	for _, c := range cases {
		w := do(h, c.method, c.path, c.body, c.hdr)
		if w.Code != c.want {
			t.Errorf("%s: %d", c.name, w.Code)
		}
		if c.want == 403 && !strings.Contains(w.Body.String(), "https://batch.example.internal") {
			t.Errorf("%s: no batch url: %s", c.name, w.Body.String())
		}
	}
	mu.Lock()
	n := hits
	mu.Unlock()
	if n != 0 {
		t.Fatalf("upstream hit %d times", n)
	}
}

func TestChunkedOverLimit(t *testing.T) {
	f := newFixture(t)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body) }))
	defer up.Close()
	h := f.handler(up, &bytes.Buffer{})
	r := httptest.NewRequest("POST", "/v1/messages", io.MultiReader(strings.NewReader(strings.Repeat("a", 2000))))
	r.ContentLength = -1
	r.Header.Set("Authorization", "Bearer "+f.token(t, nil))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatal(w.Code)
	}
}

func bearer(t string) map[string]string { return map[string]string{"Authorization": "Bearer " + t} }

func TestStreamingUnbuffered(t *testing.T) {
	f := newFixture(t)
	release := make(chan struct{})
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: one\n\n"))
		w.(http.Flusher).Flush()
		<-release
	}))
	defer up.Close()
	defer close(release)
	gw := httptest.NewServer(f.handler(up, &bytes.Buffer{}))
	defer gw.Close()
	req, _ := http.NewRequest("POST", gw.URL+"/v1/messages", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+f.token(t, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got := make(chan string, 1)
	go func() {
		b := make([]byte, 11)
		io.ReadFull(resp.Body, b)
		got <- string(b)
	}()
	select {
	case s := <-got:
		if s != "data: one\n\n" {
			t.Fatal(s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("chunk not delivered before upstream finished")
	}
}

func TestClientDisconnectCancelsUpstream(t *testing.T) {
	f := newFixture(t)
	started, cancelled := make(chan struct{}), make(chan struct{})
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("x"))
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer up.Close()
	gw := httptest.NewServer(f.handler(up, &bytes.Buffer{}))
	defer gw.Close()
	req, _ := http.NewRequest("POST", gw.URL+"/v1/messages", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+f.token(t, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	resp.Body.Close()
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream not cancelled")
	}
}

func TestAuditMetadataOnly(t *testing.T) {
	f := newFixture(t)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("x-litellm-call-id", "call-123")
		w.Write([]byte("SECRET-PROMPT reply"))
	}))
	defer up.Close()
	var buf bytes.Buffer
	tok := f.token(t, nil)
	w := do(f.handler(up, &buf), "POST", "/v1/messages", "SECRET-PROMPT body", bearer(tok))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	out := buf.String()
	if strings.Contains(out, "SECRET-PROMPT") || strings.Contains(out, tok) || strings.Count(out, "\n") != 1 {
		t.Fatal("leak or shape:", out)
	}
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"user": "alice", "dn": "cn=alice,dc=example,dc=internal", "project": "g/p", "ref": "main", "sha": "abc",
		"pipeline": "100", "job": "200", "runner": float64(7), "path": "/v1/messages", "status": float64(200),
		"bytes_in": float64(18), "bytes_out": float64(19), "call_id": "call-123",
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("%s = %v, want %v", k, rec[k], v)
		}
	}
	if _, ok := rec["duration_ms"]; !ok {
		t.Error("no duration_ms")
	}
}

func TestUpstreamErrorHidesDetails(t *testing.T) {
	f := newFixture(t)
	up := httptest.NewTLSServer(http.NotFoundHandler())
	h := f.handler(up, &bytes.Buffer{})
	up.Close()
	w := do(h, "POST", "/v1/messages", "{}", bearer(f.token(t, nil)))
	if w.Code != 502 || strings.Contains(w.Body.String(), "127.0.0.1") || strings.Contains(w.Body.String(), "refused") {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestNewHandlerValidation(t *testing.T) {
	f := newFixture(t)
	tr := http.DefaultTransport
	for name, c := range map[string]struct {
		url string
		tr  http.RoundTripper
	}{
		"empty": {"", tr}, "http": {"http://up.example.internal", tr}, "unparseable": {"https://%zz", tr},
		"nohost": {"https://", tr}, "nil transport": {"https://up.example.internal", nil},
	} {
		if h, err := NewHandler(Config{UpstreamURL: c.url}, f.ver, c.tr, nil); err == nil || h != nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := NewHandler(Config{UpstreamURL: "https://up.example.internal"}, f.ver, tr, nil); err != nil {
		t.Fatal(err)
	}
}

func TestUpgradeRejected(t *testing.T) {
	f := newFixture(t)
	hit := false
	up := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer up.Close()
	hdr := bearer(f.token(t, nil))
	hdr["Upgrade"] = "websocket"
	hdr["Connection"] = "Upgrade"
	if w := do(f.handler(up, &bytes.Buffer{}), "POST", "/v1/messages", "{}", hdr); w.Code != 400 || hit {
		t.Fatal(w.Code, hit)
	}
}

func TestSpoofedHeadersRewritten(t *testing.T) {
	f := newFixture(t)
	got := make(chan http.Header, 1)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- r.Header.Clone() }))
	defer up.Close()
	hdr := bearer(f.token(t, nil))
	for k, v := range map[string]string{
		"X-Proxied-Entity": "cn=evil", "Connection": "X-Proxied-Entity", "x-litellm-api-key": "evil",
		"x-litellm-spend-logs-metadata": `{"job_id":"evil"}`, "X-CI-Job": "evil", "X-CI-Extra": "evil",
		"X_Proxied_Entity": "cn=evil", "Cookie": "s=1",
	} {
		hdr[k] = v
	}
	if w := do(f.handler(up, &bytes.Buffer{}), "POST", "/v1/messages", "{}", hdr); w.Code != 200 {
		t.Fatal(w.Code)
	}
	h := <-got
	if v := h.Values("X-Proxied-Entity"); len(v) != 1 || v[0] != "cn=alice,dc=example,dc=internal" {
		t.Fatal(v)
	}
	if h.Get("x-litellm-api-key") != "" || h.Get("X-CI-Extra") != "" || h.Get("X-CI-Job") != "200" || h.Get("Cookie") != "" ||
		h.Get("X_Proxied_Entity") != "" || !strings.Contains(h.Get("x-litellm-spend-logs-metadata"), `"job_id":"200"`) {
		t.Fatal(h)
	}
}

func TestEncodedPathDenied(t *testing.T) {
	f := newFixture(t)
	hit := false
	up := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer up.Close()
	if w := do(f.handler(up, &bytes.Buffer{}), "GET", "/v1/%6dodels", "", bearer(f.token(t, nil))); w.Code != 403 || hit {
		t.Fatal(w.Code, hit)
	}
}
