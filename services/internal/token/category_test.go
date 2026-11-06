package token

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCategory(t *testing.T) {
	c := newCtl(t)
	raw, _ := c.s.Sign(goodClaims())
	secret := strings.Split(raw, ".")[1]
	check := func(name string, err error, want string) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		if got := Category(err); got != want {
			t.Errorf("%s: category %q, want %q", name, got, want)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: error leaks token", name)
		}
	}

	dead := newCtl(t)
	dead.srv.Close()
	check("unreachable", dead.verify(raw), "jwks_unreachable")

	bad500 := newCtl(t)
	bad500.status.Store(500)
	check("status", bad500.verify(raw), "jwks_unreachable")

	// TLS server the default client does not trust (wrong CA).
	tlsSrv := httptest.NewTLSServer(nil)
	defer tlsSrv.Close()
	vt := NewVerifier(tlsSrv.URL, iss, aud, nil)
	check("wrong CA", vt.Verify(context.Background(), raw, &Claims{}), "jwks_tls")

	// Cached keys older than the maximum age.
	st := newCtl(t)
	raw, _ = st.s.Sign(goodClaims())
	if err := st.verify(raw); err != nil {
		t.Fatal(err)
	}
	st.status.Store(500)
	st.clock = st.clock.Add(jwksMaxStale + time.Hour)
	check("stale", st.verify(raw), "jwks_stale")
}

func TestCategoryEmptyForCallerFaults(t *testing.T) {
	c := newCtl(t)
	if Category(nil) != "" {
		t.Fatal("nil error has category")
	}
	raw, _ := c.s.Sign(goodClaims())
	if err := c.verify(raw[:len(raw)-4] + "AAAA"); err == nil || Category(err) != "" {
		t.Fatalf("tampered token: err=%v category=%q", err, Category(err))
	}
	if err := c.verify("garbage"); err == nil || Category(err) != "" {
		t.Fatal("malformed token categorized")
	}
	exp := goodClaims()
	exp.ExpiresAt.Time = time.Now().Add(-time.Hour)
	old, _ := c.s.Sign(exp)
	if err := c.verify(old); err == nil || Category(err) != "" {
		t.Fatal("expired token categorized")
	}
}

func TestSignerRequiresIssuer(t *testing.T) {
	p, _ := writeKey(t, t.TempDir(), "a.pem")
	if _, err := NewSigner([]string{p}, ""); err == nil {
		t.Fatal("empty issuer accepted")
	}
}
