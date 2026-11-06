package sts

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"ai-access/internal/token"

	"github.com/go-ldap/ldap/v3"
	"github.com/golang-jwt/jwt/v5"
)

func opLog(e *env) *bytes.Buffer {
	b := &bytes.Buffer{}
	e.sts.(*Handler).opLog = b
	return b
}

func TestJWKSOutageIsLogged(t *testing.T) {
	e := newEnv(t, okLookup)
	logs := opLog(e)
	dead := httptest.NewServer(nil)
	dead.Close()
	e.sts.(*Handler).verifiers[issuer] = token.NewVerifier(dead.URL, issuer, "sts", nil)
	tok := e.idToken(t, nil)
	w := e.post(exchange(tok))
	if w.Code != 401 || !strings.Contains(w.Body.String(), "invalid_token") {
		t.Fatal(w.Code, w.Body.String())
	}
	if !strings.Contains(logs.String(), "sts: outage category=jwks_unreachable") {
		t.Fatalf("log: %q", logs.String())
	}
	if strings.Contains(logs.String(), strings.Split(tok, ".")[1]) || strings.Contains(logs.String(), "example.internal") {
		t.Fatal("log leaks token content")
	}
}

func TestBadTokenIsNotAnOutage(t *testing.T) {
	e := newEnv(t, okLookup)
	logs := opLog(e)
	w := e.post(exchange(e.idToken(t, func(m jwt.MapClaims) { m["aud"] = "other" })))
	if w.Code != 401 || logs.Len() != 0 {
		t.Fatal(w.Code, logs.String())
	}
}

func TestDirectoryOutagesAreLogged(t *testing.T) {
	for cat, cause := range map[string]error{
		"directory_unreachable": ErrDirUnreachable,
		"directory_tls":         ErrDirTLS,
		"directory_bind_failed": ErrDirBind,
		"directory_error":       ErrDirOther,
	} {
		e := newEnv(t, func(context.Context, string) (string, error) { return "", cause })
		logs := opLog(e)
		w := e.post(exchange(e.idToken(t, nil)))
		if w.Code != 403 || !strings.Contains(w.Body.String(), "identity_not_mapped") {
			t.Fatal(cat, w.Code, w.Body.String())
		}
		if got := logs.String(); got != "sts: outage category="+cat+"\n" {
			t.Errorf("%s: log %q", cat, got)
		}
	}
}

func TestNoMatchIsNotAnOutage(t *testing.T) {
	e := newEnv(t, func(context.Context, string) (string, error) {
		return "", errors.New("expected 1 directory entry, got 0")
	})
	logs := opLog(e)
	if w := e.post(exchange(e.idToken(t, nil))); w.Code != 403 || logs.Len() != 0 {
		t.Fatal(w.Code, logs.String())
	}
}

func TestLDAPLookupErrorKinds(t *testing.T) {
	pw := func() (string, error) { return "pw", nil }
	f := newLookup(DirectoryConfig{}, func() (ldapConn, error) { return nil, errors.New("dial tcp: refused") }, pw)
	if _, err := f(context.Background(), "a@example.internal"); !errors.Is(err, ErrDirUnreachable) {
		t.Fatal(err)
	}
	g := newLookup(DirectoryConfig{}, func() (ldapConn, error) { return &failBind{}, nil }, pw)
	if _, err := g(context.Background(), "a@example.internal"); !errors.Is(err, ErrDirBind) {
		t.Fatal(err)
	}
}

type failBind struct{ stubConn }

func (*failBind) Bind(string, string) error {
	return &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials}
}
