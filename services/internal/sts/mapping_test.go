package sts

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func lk(dn string, err error, called *bool) LookupFunc {
	return func(_ context.Context, email string) (string, error) {
		if called != nil {
			*called = true
		}
		return dn, err
	}
}

func TestLookupByEmail(t *testing.T) {
	var got string
	f := func(_ context.Context, e string) (string, error) { got = e; return "cn=a,dc=x", nil }
	dn, err := MapDN(context.Background(), GitLabClaims{UserEmail: "a@example.internal"}, f)
	if err != nil || dn != "cn=a,dc=x" || got != "a@example.internal" {
		t.Fatal(dn, err, got)
	}
}

func TestMissingEmailDenied(t *testing.T) {
	called := false
	if _, err := MapDN(context.Background(), GitLabClaims{}, lk("x", nil, &called)); err == nil || called {
		t.Fatal("expected deny without lookup")
	}
}

func TestMapDNDenials(t *testing.T) {
	c := GitLabClaims{UserEmail: "bot@example.internal"}
	for name, f := range map[string]LookupFunc{
		"nil":       nil,
		"no match":  lk("", errors.New("none"), nil),
		"bot":       lk("", errors.New("no entry"), nil),
		"ambiguous": lk("", errors.New("expected 1 directory entry, got 2"), nil),
		"empty dn":  lk("", nil, nil),
		"CR":        lk("cn=a\r,dc=x", nil, nil),
		"LF":        lk("cn=a\n,dc=x", nil, nil),
		"NUL":       lk("cn=a\x00,dc=x", nil, nil),
	} {
		if _, err := MapDN(context.Background(), c, f); !errors.Is(err, ErrIdentityNotMapped) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

type stubConn struct {
	entries []*ldap.Entry
	filter  string
	bound   bool
	timeout time.Duration
}

func (s *stubConn) Bind(u, p string) error { s.bound = p == "pw"; return nil }
func (s *stubConn) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	s.filter = r.Filter
	return &ldap.SearchResult{Entries: s.entries}, nil
}
func (s *stubConn) Close() error               { return nil }
func (s *stubConn) SetTimeout(d time.Duration) { s.timeout = d }

func TestLDAPLookupExactlyOne(t *testing.T) {
	e := func(dn string) *ldap.Entry { return &ldap.Entry{DN: dn} }
	for n, tc := range map[string]struct {
		entries []*ldap.Entry
		ok      bool
	}{"zero": {nil, false}, "one": {[]*ldap.Entry{e("cn=a")}, true}, "two": {[]*ldap.Entry{e("cn=a"), e("cn=b")}, false}} {
		s := &stubConn{entries: tc.entries}
		f := newLookup(DirectoryConfig{}, func() (ldapConn, error) { return s, nil }, func() (string, error) { return "pw", nil })
		dn, err := f(context.Background(), "a)(uid=*@example.internal")
		if (err == nil) != tc.ok || (tc.ok && dn != "cn=a") || !s.bound {
			t.Errorf("%s: %q %v", n, dn, err)
		}
		if s.filter != `(mail=a\29\28uid=\2a@example.internal)` {
			t.Errorf("%s: filter %q", n, s.filter)
		}
	}
}

func TestLDAPSOnly(t *testing.T) {
	if _, err := NewLDAPLookup(DirectoryConfig{URL: "ldap://x.example.internal"}); err == nil {
		t.Fatal("plain ldap accepted")
	}
}

func TestDirTLSConfig(t *testing.T) {
	c := dirTLSConfig()
	if c.InsecureSkipVerify || c.MinVersion < tls.VersionTLS12 {
		t.Fatalf("%+v", c)
	}
}

func TestLDAPTimeoutFromContext(t *testing.T) {
	s := &stubConn{entries: []*ldap.Entry{{DN: "cn=a"}}}
	f := newLookup(DirectoryConfig{}, func() (ldapConn, error) { return s, nil }, func() (string, error) { return "pw", nil })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := f(ctx, "a@example.internal"); err != nil || s.timeout <= 0 || s.timeout > 2*time.Second {
		t.Fatal(err, s.timeout)
	}
	done, c2 := context.WithCancel(context.Background())
	c2()
	if _, err := f(done, "a@example.internal"); err == nil {
		t.Fatal("cancelled ctx accepted")
	}
}
