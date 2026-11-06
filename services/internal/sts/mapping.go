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

// MapDN maps the signed user_email to a directory DN. Any failure denies.
func MapDN(ctx context.Context, c GitLabClaims, lookup LookupFunc) (string, error) {
	if lookup == nil || c.UserEmail == "" {
		return "", ErrIdentityNotMapped
	}
	dn, err := lookup(ctx, c.UserEmail)
	if err != nil || dn == "" || strings.ContainsAny(dn, "\r\n\x00") {
		return "", ErrIdentityNotMapped
	}
	return dn, nil
}
