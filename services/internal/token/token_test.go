package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const iss, aud = "https://sts.example.internal", "gateway.example.internal"

func writeKey(t *testing.T, dir, name string) (string, *rsa.PrivateKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	b := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p, k
}

type env struct {
	s     *Signer
	srv   *httptest.Server
	v     *Verifier
	key   *rsa.PrivateKey
	fetch *atomic.Int32
}

func setup(t *testing.T) *env {
	t.Helper()
	p, k := writeKey(t, t.TempDir(), "a.pem")
	s, err := NewSigner([]string{p}, iss)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{s: s, key: k, fetch: new(atomic.Int32)}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.fetch.Add(1)
		w.Write(e.s.JWKS())
	}))
	t.Cleanup(e.srv.Close)
	e.v = NewVerifier(e.srv.URL, iss, aud, e.srv.Client())
	return e
}

func goodClaims() Claims {
	now := time.Now()
	return Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "u",
			Audience:  jwt.ClaimStrings{aud},
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
		},
		DN: "cn=x", UserLogin: "alice", ProjectPath: "g/p", Ref: "main", SHA: "abc",
		PipelineID: "1", JobID: "2", RunnerID: 7,
	}
}

func TestVerifyValid(t *testing.T) {
	e := setup(t)
	raw, err := e.s.Sign(goodClaims())
	if err != nil {
		t.Fatal(err)
	}
	var got Claims
	if err := e.v.Verify(context.Background(), raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.UserLogin != "alice" || got.RunnerID != 7 || got.DN != "cn=x" || got.Issuer != iss {
		t.Fatalf("claims not populated: %+v", got)
	}
}

func TestVerifyRejects(t *testing.T) {
	e := setup(t)
	kid := e.s.kids[0]
	signRS := func(mut func(*Claims)) string {
		c := goodClaims()
		c.Issuer = iss
		mut(&c)
		tk := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
		tk.Header["kid"] = kid
		s, _ := tk.SignedString(e.key)
		return s
	}
	valid, _ := e.s.Sign(goodClaims())
	parts := strings.Split(valid, ".")
	tampered := parts[0] + "." + strings.Replace(parts[1], parts[1][:4], "AAAA", 1) + "." + parts[2]
	if tampered == valid {
		tampered = parts[0] + ".AAAA." + parts[2]
	}
	none := func() string {
		c := goodClaims()
		c.Issuer = iss
		tk := jwt.NewWithClaims(jwt.SigningMethodNone, c)
		tk.Header["kid"] = kid
		s, _ := tk.SignedString(jwt.UnsafeAllowNoneSignatureType)
		return s
	}()
	hs := func() string {
		c := goodClaims()
		c.Issuer = iss
		tk := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
		tk.Header["kid"] = kid
		s, _ := tk.SignedString(x509.MarshalPKCS1PublicKey(&e.key.PublicKey))
		return s
	}()
	cases := map[string]string{
		"expired":  signRS(func(c *Claims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour)) }),
		"nbf":      signRS(func(c *Claims) { c.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Hour)) }),
		"noexp":    signRS(func(c *Claims) { c.ExpiresAt = nil }),
		"wrongiss": signRS(func(c *Claims) { c.Issuer = "https://evil.example.internal" }),
		"wrongaud": signRS(func(c *Claims) { c.Audience = jwt.ClaimStrings{"other"} }),
		"none":     none,
		"hs256":    hs,
		"tampered": tampered,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			var c Claims
			if err := e.v.Verify(context.Background(), raw, &c); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestUnknownKidRefreshesOnce(t *testing.T) {
	e := setup(t)
	old, _ := e.s.Sign(goodClaims())
	if err := e.v.Verify(context.Background(), old, &Claims{}); err != nil {
		t.Fatal(err)
	}
	if e.fetch.Load() != 1 {
		t.Fatalf("fetches=%d", e.fetch.Load())
	}
	// rotate: new signer with new key published
	p, _ := writeKey(t, t.TempDir(), "b.pem")
	e.s, _ = NewSigner([]string{p}, iss)
	now := time.Now()
	e.v.now = func() time.Time { return now.Add(2 * successInterval) }
	fresh, _ := e.s.Sign(goodClaims())
	if err := e.v.Verify(context.Background(), fresh, &Claims{}); err != nil {
		t.Fatal(err)
	}
	if e.fetch.Load() != 2 {
		t.Fatalf("fetches=%d", e.fetch.Load())
	}
	// unknown kids within a minute: no more fetches
	for i := 0; i < 5; i++ {
		p, _ := writeKey(t, t.TempDir(), "c.pem")
		s, _ := NewSigner([]string{p}, iss)
		raw, _ := s.Sign(goodClaims())
		if err := e.v.Verify(context.Background(), raw, &Claims{}); err == nil {
			t.Fatal("unknown kid accepted")
		}
	}
	if e.fetch.Load() != 2 {
		t.Fatalf("fetches=%d, want 2 (rate limited)", e.fetch.Load())
	}
}

func TestCachedKeysSurviveOutage(t *testing.T) {
	e := setup(t)
	raw, _ := e.s.Sign(goodClaims())
	if err := e.v.Verify(context.Background(), raw, &Claims{}); err != nil {
		t.Fatal(err)
	}
	e.srv.Close()
	e.v.now = func() time.Time { return time.Now().Add(time.Hour) }
	if err := e.v.Verify(context.Background(), raw, &Claims{}); err != nil {
		t.Fatalf("cached key should verify: %v", err)
	}
	// a failed refresh must not drop cached keys
	p, _ := writeKey(t, t.TempDir(), "z.pem")
	s, _ := NewSigner([]string{p}, iss)
	other, _ := s.Sign(goodClaims())
	_ = e.v.Verify(context.Background(), other, &Claims{})
	if err := e.v.Verify(context.Background(), raw, &Claims{}); err != nil {
		t.Fatalf("cache lost after failed refresh: %v", err)
	}
}

func TestErrorsOmitToken(t *testing.T) {
	e := setup(t)
	c := goodClaims()
	c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	expired, _ := e.s.Sign(c)
	valid, _ := e.s.Sign(goodClaims())
	p := strings.Split(valid, ".")
	for _, raw := range []string{expired, p[0] + "." + p[1] + ".AAAA", valid + "x.y", "garbage"} {
		err := e.v.Verify(context.Background(), raw, &Claims{})
		if err == nil {
			t.Fatal("expected error")
		}
		for _, part := range strings.Split(raw, ".") {
			if len(part) > 3 && strings.Contains(err.Error(), part) {
				t.Fatalf("error leaks token part: %v", err)
			}
		}
	}
}

func TestSignerPublishesAllKeys(t *testing.T) {
	dir := t.TempDir()
	pa, ka := writeKey(t, dir, "a.pem")
	pb, _ := writeKey(t, dir, "b.pem")
	s, err := NewSigner([]string{pa, pb}, iss)
	if err != nil {
		t.Fatal(err)
	}
	var set jwks
	if err := jsonUnmarshal(s.JWKS(), &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 2 || set.Keys[0].Kid != s.kids[0] || set.Keys[1].Kid != s.kids[1] {
		t.Fatalf("jwks: %+v", set)
	}
	raw, _ := s.Sign(goodClaims())
	tk, _, err := jwt.NewParser().ParseUnverified(raw, &Claims{})
	if err != nil || tk.Header["kid"] != s.kids[0] {
		t.Fatalf("not signed with first key: %v", err)
	}
	if _, err := jwt.Parse(raw, func(*jwt.Token) (any, error) { return &ka.PublicKey, nil }); err != nil {
		t.Fatalf("first key does not verify: %v", err)
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func TestConcurrentColdStart(t *testing.T) {
	e := setup(t)
	raw, _ := e.s.Sign(goodClaims())
	const n = 20
	errs := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			<-start
			errs <- e.v.Verify(context.Background(), raw, &Claims{})
		}()
	}
	close(start)
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("spurious rejection: %v", err)
		}
	}
	if got := e.fetch.Load(); got != 1 {
		t.Fatalf("fetches=%d, want 1", got)
	}
}
