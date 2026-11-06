package sts

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ai-access/internal/token"

	"github.com/golang-jwt/jwt/v5"
)

const issuer = "https://gitlab.example.internal"

type env struct {
	idKey *rsa.PrivateKey
	audit *bytes.Buffer
	sts   http.Handler
	now   time.Time
}

func newEnv(t *testing.T, lookup LookupFunc) *env {
	t.Helper()
	idKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1",
			"n": base64.RawURLEncoding.EncodeToString(idKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(idKey.E)).Bytes()),
		}}})
	}))
	t.Cleanup(jwksSrv.Close)
	stsKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kf := filepath.Join(t.TempDir(), "k.pem")
	os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(stsKey)}), 0o600)
	signer, err := token.NewSigner([]string{kf}, "https://sts.example.internal")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{RunnerIDs: []int64{7}, GatewayAudience: "gateway", TokenTTL: 20 * time.Minute}
	e := &env{idKey: idKey, audit: &bytes.Buffer{}, now: time.Now()}
	hh := NewHandler(cfg, map[string]*token.Verifier{issuer: token.NewVerifier(jwksSrv.URL, issuer, "sts", nil)}, signer, lookup, e.audit)
	e.sts = hh
	return e
}

func (e *env) idToken(t *testing.T, mod func(m jwt.MapClaims)) string {
	m := jwt.MapClaims{
		"iss": issuer, "aud": "sts", "exp": time.Now().Add(time.Hour).Unix(),
		"user_email": "a@example.internal", "user_id": "42", "user_login": "alice",
		"project_path": "g/p", "ref": "main", "ref_protected": "true", "sha": "abc",
		"pipeline_id": "100", "pipeline_source": "push", "job_id": "200", "runner_id": 7,
	}
	if mod != nil {
		mod(m)
	}
	tk := jwt.NewWithClaims(jwt.SigningMethodRS256, m)
	tk.Header["kid"] = "k1"
	s, err := tk.SignedString(e.idKey)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (e *env) post(form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	e.sts.ServeHTTP(w, r)
	return w
}

func exchange(tok string) url.Values {
	return url.Values{"grant_type": {grantType}, "subject_token": {tok}, "subject_token_type": {jwtType}}
}

func okLookup(_ context.Context, _ string) (string, error) {
	return "cn=alice,dc=example,dc=internal", nil
}

func parseOut(t *testing.T, e *env, w *httptest.ResponseRecorder) (token.Claims, map[string]any) {
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	var set struct{ Keys []map[string]string }
	jw := httptest.NewRecorder()
	e.sts.ServeHTTP(jw, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	json.Unmarshal(jw.Body.Bytes(), &set)
	n, _ := base64.RawURLEncoding.DecodeString(set.Keys[0]["n"])
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}
	var c token.Claims
	_, err := jwt.ParseWithClaims(resp["access_token"].(string), &c, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithAudience("gateway"), jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatal(err)
	}
	return c, resp
}

func TestValidExchange(t *testing.T) {
	e := newEnv(t, okLookup)
	tok := e.idToken(t, nil)
	w := e.post(exchange(tok))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	c, resp := parseOut(t, e, w)
	if c.DN != "cn=alice,dc=example,dc=internal" || c.ProjectPath != "g/p" || c.Ref != "main" || c.SHA != "abc" ||
		c.PipelineID != "100" || c.JobID != "200" || c.RunnerID != 7 || c.UserLogin != "alice" {
		t.Fatalf("%+v", c)
	}
	if resp["token_type"] != "Bearer" || resp["expires_in"].(float64) != 1200 {
		t.Fatal(resp)
	}
	if got := c.ExpiresAt.Sub(c.IssuedAt.Time); got != 20*time.Minute {
		t.Fatal(got)
	}
	var rec map[string]any
	if err := json.Unmarshal(e.audit.Bytes(), &rec); err != nil || rec["status"].(float64) != 200 ||
		rec["user"] != "alice" || rec["user_id"] != "42" || rec["dn"] == "" {
		t.Fatal(err, e.audit.String())
	}
	if strings.Count(e.audit.String(), "\n") != 1 || strings.Contains(e.audit.String(), tok) {
		t.Fatal("audit shape or leak")
	}
}

func TestExpCappedByIDToken(t *testing.T) {
	e := newEnv(t, okLookup)
	w := e.post(exchange(e.idToken(t, func(m jwt.MapClaims) { m["exp"] = time.Now().Add(5 * time.Minute).Unix() })))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	c, _ := parseOut(t, e, w)
	if d := time.Until(c.ExpiresAt.Time); d > 5*time.Minute || d < 4*time.Minute {
		t.Fatal(d)
	}
}

func TestBadRequests(t *testing.T) {
	e := newEnv(t, okLookup)
	tok := e.idToken(t, nil)
	f := exchange(tok)
	f.Set("grant_type", "x")
	if w := e.post(f); w.Code != 400 {
		t.Fatal(w.Code)
	}
	f = exchange(tok)
	f.Set("subject_token_type", "x")
	if w := e.post(f); w.Code != 400 {
		t.Fatal(w.Code)
	}
}

func TestBodyLimit(t *testing.T) {
	e := newEnv(t, okLookup)
	if w := e.post(exchange(strings.Repeat("a", 70<<10))); w.Code != 400 {
		t.Fatal(w.Code)
	}
}

func TestDenials(t *testing.T) {
	cases := []struct {
		name   string
		mod    func(jwt.MapClaims)
		lookup LookupFunc
		code   int
		reason string
	}{
		{"runner", func(m jwt.MapClaims) { m["runner_id"] = 9 }, okLookup, 403, "runner_not_allowed"},
		{"schedule", func(m jwt.MapClaims) { m["pipeline_source"] = "schedule"; m["ref_protected"] = "false" }, okLookup, 403, "schedule_ref_not_protected"},
		{"unmapped", nil, func(context.Context, string) (string, error) { return "", context.Canceled }, 403, "identity_not_mapped"},
		{"nil lookup", nil, nil, 403, "identity_not_mapped"},
		{"wrong aud", func(m jwt.MapClaims) { m["aud"] = "other" }, okLookup, 401, "invalid_token"},
		{"expired", func(m jwt.MapClaims) { m["exp"] = time.Now().Add(-time.Hour).Unix() }, okLookup, 401, "invalid_token"},
		{"unknown issuer", func(m jwt.MapClaims) { m["iss"] = "https://evil.example.internal" }, okLookup, 401, "invalid_token"},
	}
	for _, tc := range cases {
		e := newEnv(t, tc.lookup)
		tok := e.idToken(t, tc.mod)
		w := e.post(exchange(tok))
		if w.Code != tc.code || !strings.Contains(w.Body.String(), tc.reason) {
			t.Errorf("%s: %d %s", tc.name, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), tok) || strings.Contains(e.audit.String(), tok) ||
			!strings.Contains(e.audit.String(), tc.reason) {
			t.Errorf("%s: leak or missing reason: %s", tc.name, e.audit.String())
		}
	}
	if w := newEnv(t, okLookup).post(exchange("garbage")); w.Code != 401 {
		t.Fatal(w.Code)
	}
}

func TestLoadConfigRejectsLongTTL(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	body := `{"issuers":[{"url":"u","audience":"a","jwks_url":"j"}],"runner_ids":[1],"gateway_audience":"g","token_ttl":"31m","directory":{}}`
	os.WriteFile(p, []byte(body), 0o600)
	if _, err := LoadConfig(p); err == nil {
		t.Fatal("accepted")
	}
	os.WriteFile(p, []byte(strings.Replace(body, "31m", "30m", 1)), 0o600)
	if _, err := LoadConfig(p); err != nil {
		t.Fatal(err)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestAuditFailureFailsClosed(t *testing.T) {
	e := newEnv(t, okLookup)
	e.sts.(*Handler).audit = failWriter{}
	w := e.post(exchange(e.idToken(t, nil)))
	if w.Code != 500 || !strings.Contains(w.Body.String(), "audit_failed") || strings.Contains(w.Body.String(), "access_token") {
		t.Fatal(w.Code, w.Body.String())
	}
}
