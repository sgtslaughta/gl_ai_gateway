package sts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ldapConn is the subset of the LDAP client the lookup needs.
type ldapConn interface {
	Bind(user, pass string) error
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	SetTimeout(time.Duration)
	Close() error
}

// dirTLSConfig is the TLS config for directory connections: verification on.
// roots is the trusted CA pool; nil means system roots.
func dirTLSConfig(roots *x509.CertPool) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
}

const (
	dialTimeout = 5 * time.Second
	opTimeout   = 10 * time.Second
)

// NewLDAPLookup returns a LookupFunc backed by the configured LDAPS
// directory. The bind password is read from BindPasswordFile on each call.
func NewLDAPLookup(d DirectoryConfig, roots *x509.CertPool) (LookupFunc, error) {
	if !strings.HasPrefix(d.URL, "ldaps://") {
		return nil, errors.New("directory url must use ldaps://")
	}
	dial := func() (ldapConn, error) {
		return ldap.DialURL(d.URL,
			ldap.DialWithDialer(&net.Dialer{Timeout: dialTimeout}),
			ldap.DialWithTLSConfig(dirTLSConfig(roots)))
	}
	return newLookup(d, dial, func() (string, error) {
		b, err := os.ReadFile(d.BindPasswordFile)
		return strings.TrimRight(string(b), "\r\n"), err
	}), nil
}

func newLookup(d DirectoryConfig, dial func() (ldapConn, error), password func() (string, error)) LookupFunc {
	attr := d.EmailAttribute
	if attr == "" {
		attr = "mail"
	}
	return func(ctx context.Context, email string) (string, error) {
		timeout := opTimeout
		if dl, ok := ctx.Deadline(); ok {
			timeout = time.Until(dl)
		}
		if timeout <= 0 || ctx.Err() != nil {
			return "", errors.New("directory deadline exceeded")
		}
		pw, err := password()
		if err != nil {
			return "", errors.New("directory password unavailable")
		}
		conn, err := dial()
		if err != nil {
			return "", errors.New("directory unreachable")
		}
		defer conn.Close()
		conn.SetTimeout(timeout)
		if err := conn.Bind(d.BindDN, pw); err != nil {
			return "", errors.New("directory bind failed")
		}
		req := ldap.NewSearchRequest(d.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			2, 10, false,
			fmt.Sprintf("(%s=%s)", attr, ldap.EscapeFilter(email)),
			[]string{"dn"}, nil)
		res, err := conn.Search(req)
		if err != nil {
			return "", errors.New("directory search failed")
		}
		if len(res.Entries) != 1 {
			return "", fmt.Errorf("expected 1 directory entry, got %d", len(res.Entries))
		}
		return res.Entries[0].DN, nil
	}
}
