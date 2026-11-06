// Package token provides RS256 JWT signing and verification with JWKS.
package token

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims are the STS token claims.
type Claims struct {
	jwt.RegisteredClaims
	DN             string `json:"dn"`
	UserLogin      string `json:"user_login"`
	ProjectPath    string `json:"project_path"`
	JobProjectPath string `json:"job_project_path"`
	Ref            string `json:"ref"`
	SHA            string `json:"sha"`
	PipelineID     string `json:"pipeline_id"`
	JobID          string `json:"job_id"`
	RunnerID       int64  `json:"runner_id"`
}

const (
	successInterval  = time.Minute
	failureInterval  = 5 * time.Second
	fetchTimeout     = 10 * time.Second
	jwksRefreshAfter = 10 * time.Minute
	jwksMaxStale     = 24 * time.Hour
)

// Sentinels for key-source failures. They are wrapped into the errors from
// Verify so operators can tell an outage from a bad token (see Category).
var (
	ErrJWKSUnreachable = errors.New("jwks unreachable")
	ErrJWKSTLS         = errors.New("jwks tls verification failed")
	ErrJWKSStale       = errors.New("jwks too stale")
)

// Category returns a fixed operator-facing label if err was caused by the
// key source rather than the presented token, or "" otherwise.
func Category(err error) string {
	switch {
	case errors.Is(err, ErrJWKSStale):
		return "jwks_stale"
	case errors.Is(err, ErrJWKSTLS):
		return "jwks_tls"
	case errors.Is(err, ErrJWKSUnreachable):
		return "jwks_unreachable"
	}
	return ""
}

// Verifier verifies RS256 JWTs against a remote JWKS.
type Verifier struct {
	url    string
	client *http.Client
	parser *jwt.Parser

	mu     sync.RWMutex // guards keys, lastOK; never held across HTTP
	keys   map[string]*rsa.PublicKey
	lastOK time.Time // last successful fetch

	fetchMu sync.Mutex // serializes refreshes; guards nextTry
	nextTry time.Time
	aud     string
	now     func() time.Time
}

// NewVerifier builds a Verifier. Keys are fetched lazily and cached.
func NewVerifier(jwksURL, issuer, audience string, client *http.Client) *Verifier {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Verifier{
		url:    jwksURL,
		aud:    audience,
		client: client,
		keys:   map[string]*rsa.PublicKey{},
		now:    time.Now,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{"RS256"}),
			jwt.WithIssuer(issuer),
			jwt.WithAudience(audience),
			jwt.WithExpirationRequired(),
		),
	}
}

// Verify validates raw and decodes its claims into into. Errors never
// contain the raw token.
func (v *Verifier) Verify(ctx context.Context, raw string, into jwt.Claims) error {
	_, err := v.parser.ParseWithClaims(raw, into, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		return v.key(ctx, kid)
	})
	if err != nil {
		for _, e := range []error{ErrJWKSStale, ErrJWKSTLS, ErrJWKSUnreachable} {
			if errors.Is(err, e) {
				return fmt.Errorf("token invalid: %s: %w", sanitize(err), e)
			}
		}
		return fmt.Errorf("token invalid: %s", sanitize(err))
	}
	// Require exactly one audience, equal to ours.
	if aud, err := into.GetAudience(); err != nil || len(aud) != 1 || aud[0] != v.aud {
		return errors.New("token invalid: bad audience")
	}
	return nil
}

// sanitize reduces an error to a fixed category so it cannot echo input.
func sanitize(err error) string {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return "expired"
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return "not yet valid"
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return "bad issuer"
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return "bad audience"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return "bad signature"
	case errors.Is(err, jwt.ErrTokenMalformed):
		return "malformed"
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		return "unknown key"
	default:
		return "rejected"
	}
}

func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if age, ok := v.keyAge(); ok && age > jwksRefreshAfter {
		// Failure keeps the cache unless it is too old to trust.
		err := v.refresh(ctx, func() bool {
			a, ok := v.keyAge()
			return ok && a <= jwksRefreshAfter
		})
		if a, _ := v.keyAge(); err != nil && a > jwksMaxStale {
			return nil, ErrJWKSStale
		}
	}
	if k, ok := v.lookup(kid); ok {
		return k, nil
	}
	if err := v.refresh(ctx, func() bool { _, ok := v.lookup(kid); return ok }); err != nil {
		return nil, err
	}
	if k, ok := v.lookup(kid); ok {
		return k, nil
	}
	return nil, errors.New("unknown kid")
}

// keyAge is the time since the last successful fetch; ok is false if none.
func (v *Verifier) keyAge() (time.Duration, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.lastOK.IsZero() {
		return 0, false
	}
	return v.now().Sub(v.lastOK), true
}

func (v *Verifier) lookup(kid string) (*rsa.PublicKey, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	k, ok := v.keys[kid]
	return k, ok
}

// refresh fetches the JWKS unless satisfied() already holds once the fetch
// lock is acquired. Attempts are spaced by successInterval after a success
// and failureInterval after a failure. Cached keys survive failures.
func (v *Verifier) refresh(ctx context.Context, satisfied func() bool) error {
	v.fetchMu.Lock()
	defer v.fetchMu.Unlock()
	if satisfied() {
		return nil
	}
	if v.now().Before(v.nextTry) {
		return errors.New("jwks refresh rate limited")
	}
	keys, err := v.fetch(ctx)
	if err != nil {
		v.nextTry = v.now().Add(failureInterval)
		return err
	}
	v.nextTry = v.now().Add(successInterval)
	v.mu.Lock()
	v.keys, v.lastOK = keys, v.now()
	v.mu.Unlock()
	return nil
}

// fetch runs detached from the caller's cancellation so a client cannot
// abort a refresh and burn the rate limit.
func (v *Verifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.url, nil)
	if err != nil {
		return nil, ErrJWKSUnreachable
	}
	resp, err := v.client.Do(req)
	if err != nil {
		var cv *tls.CertificateVerificationError
		if errors.As(err, &cv) {
			return nil, ErrJWKSTLS
		}
		return nil, ErrJWKSUnreachable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrJWKSUnreachable
	}
	var set jwks
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, ErrJWKSUnreachable
	}
	keys := map[string]*rsa.PublicKey{}
	for _, j := range set.Keys {
		if pk, err := j.publicKey(); err == nil {
			keys[j.Kid] = pk
		}
	}
	if len(keys) == 0 {
		return nil, ErrJWKSUnreachable
	}
	return keys, nil
}
