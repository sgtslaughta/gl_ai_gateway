package sts

import (
	"context"
	"errors"
	"strings"
)

// LookupFunc resolves an email to exactly one directory DN.
type LookupFunc func(ctx context.Context, email string) (string, error)

// ErrIdentityNotMapped is the denial for any mapping failure.
var ErrIdentityNotMapped = errors.New("identity_not_mapped")

// isControl matches C0 controls and DEL, the same rule as the gateway's
// claim check, so a DN the gateway would refuse never gets a token.
func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// MapDN maps the signed user_email to a directory DN. Any failure denies.
func MapDN(ctx context.Context, c GitLabClaims, lookup LookupFunc) (string, error) {
	if lookup == nil || c.UserEmail == "" {
		return "", ErrIdentityNotMapped
	}
	dn, err := lookup(ctx, c.UserEmail)
	if err != nil || dn == "" || strings.ContainsFunc(dn, isControl) {
		return "", ErrIdentityNotMapped
	}
	return dn, nil
}
