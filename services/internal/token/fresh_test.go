package token

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ctl is a JWKS server whose response can be changed per test.
type ctl struct {
	body   atomic.Value // []byte
	status atomic.Int32
	delay  atomic.Int64 // ns
	hits   atomic.Int32
	srv    *httptest.Server
	v      *Verifier
	s      *Signer
	clock  time.Time
}

func newCtl(t *testing.T) *ctl {
	t.Helper()
	p, _ := writeKey(t, t.TempDir(), "a.pem")
	s, err := NewSigner([]string{p}, iss)
	if err != nil {
		t.Fatal(err)
	}
	c := &ctl{s: s, clock: time.Now()}
	c.body.Store(s.JWKS())
	c.status.Store(200)
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.hits.Add(1)
		time.Sleep(time.Duration(c.delay.Load()))
		w.WriteHeader(int(c.status.Load()))
		w.Write(c.body.Load().([]byte))
	}))
	t.Cleanup(c.srv.Close)
	c.v = NewVerifier(c.srv.URL, iss, aud, c.srv.Client())
	c.v.now = func() time.Time { return c.clock }
	return c
}

func (c *ctl) verify(raw string) error {
	return c.v.Verify(context.Background(), raw, &Claims{})
}

func TestMultiAudienceRejected(t *testing.T) {
	c := newCtl(t)
	cl := goodClaims()
	cl.Audience = jwt.ClaimStrings{aud, "other.example.internal"}
	raw, _ := c.s.Sign(cl)
	if err := c.verify(raw); err == nil {
		t.Fatal("multi-audience token accepted")
	}
	ok, _ := c.s.Sign(goodClaims())
	if err := c.verify(ok); err != nil {
		t.Fatal(err)
	}
}

func TestCancelledCallerDoesNotBlockRefresh(t *testing.T) {
	c := newCtl(t)
	c.delay.Store(int64(150 * time.Millisecond))
	raw, _ := c.s.Sign(goodClaims())
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	_ = c.v.Verify(ctx, raw, &Claims{}) // outcome of the cancelled caller is irrelevant
	if err := c.verify(raw); err != nil {
		t.Fatalf("later valid token rejected: %v", err)
	}
	if c.hits.Load() != 1 {
		t.Fatalf("hits=%d, want 1", c.hits.Load())
	}
}

func TestFailureBackoffShorterThanSuccess(t *testing.T) {
	c := newCtl(t)
	c.status.Store(500)
	raw, _ := c.s.Sign(goodClaims())
	_ = c.verify(raw)
	c.clock = c.clock.Add(3 * time.Second)
	_ = c.verify(raw)
	if c.hits.Load() != 1 {
		t.Fatalf("hits=%d, want 1 within failure backoff", c.hits.Load())
	}
	c.status.Store(200)
	c.clock = c.clock.Add(3 * time.Second) // 6s since failure
	if err := c.verify(raw); err != nil {
		t.Fatalf("retry after 5s failed: %v", err)
	}
	if c.hits.Load() != 2 {
		t.Fatalf("hits=%d, want 2", c.hits.Load())
	}
	// success backoff is still a minute: unknown kid 6s later does not fetch
	p, _ := writeKey(t, t.TempDir(), "u.pem")
	us, _ := NewSigner([]string{p}, iss)
	unk, _ := us.Sign(goodClaims())
	c.clock = c.clock.Add(6 * time.Second)
	_ = c.verify(unk)
	if c.hits.Load() != 2 {
		t.Fatalf("hits=%d, want 2 within success backoff", c.hits.Load())
	}
}

func TestWithdrawnKeyStopsVerifying(t *testing.T) {
	c := newCtl(t)
	old, _ := c.s.Sign(goodClaims())
	if err := c.verify(old); err != nil {
		t.Fatal(err)
	}
	p, _ := writeKey(t, t.TempDir(), "n.pem")
	ns, _ := NewSigner([]string{p}, iss)
	c.body.Store(ns.JWKS())
	c.clock = c.clock.Add(jwksRefreshAfter + time.Minute)
	if err := c.verify(old); err == nil {
		t.Fatal("withdrawn key still verifies")
	}
	fresh, _ := ns.Sign(goodClaims())
	if err := c.verify(fresh); err != nil {
		t.Fatal(err)
	}
}

func TestOutageUnderMaxStaleVerifies(t *testing.T) {
	c := newCtl(t)
	raw, _ := c.s.Sign(goodClaims())
	if err := c.verify(raw); err != nil {
		t.Fatal(err)
	}
	c.status.Store(500)
	c.clock = c.clock.Add(jwksMaxStale - time.Hour)
	if err := c.verify(raw); err != nil {
		t.Fatalf("cached key rejected during outage: %v", err)
	}
}

func TestOutagePastMaxStaleFails(t *testing.T) {
	c := newCtl(t)
	raw, _ := c.s.Sign(goodClaims())
	if err := c.verify(raw); err != nil {
		t.Fatal(err)
	}
	c.status.Store(500)
	c.clock = c.clock.Add(jwksMaxStale + time.Hour)
	err := c.verify(raw)
	if err == nil {
		t.Fatal("stale cache accepted")
	}
	if strings.Contains(err.Error(), strings.Split(raw, ".")[1]) {
		t.Fatal("error leaks token")
	}
	// recovers once the JWKS is reachable again
	c.status.Store(200)
	c.clock = c.clock.Add(time.Minute)
	if err := c.verify(raw); err != nil {
		t.Fatalf("no recovery: %v", err)
	}
}

func TestEmptyKeySetKeepsCache(t *testing.T) {
	c := newCtl(t)
	raw, _ := c.s.Sign(goodClaims())
	if err := c.verify(raw); err != nil {
		t.Fatal(err)
	}
	c.body.Store([]byte(`{"keys":[]}`))
	c.clock = c.clock.Add(jwksRefreshAfter + time.Minute)
	if err := c.verify(raw); err != nil {
		t.Fatalf("empty set replaced cache: %v", err)
	}
	if c.hits.Load() != 2 {
		t.Fatalf("hits=%d, want a refresh attempt", c.hits.Load())
	}
}
