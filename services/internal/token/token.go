// Package token provides RS256 JWT signing and verification with JWKS.
package token

import (
	"context"
	"crypto/rsa"
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
	DN          string `json:"dn"`
	UserLogin   string `json:"user_login"`
	ProjectPath string `json:"project_path"`
	Ref         string `json:"ref"`
	SHA         string `json:"sha"`
	PipelineID  string `json:"pipeline_id"`
	JobID       string `json:"job_id"`
	RunnerID    int64  `json:"runner_id"`
}

const refreshInterval = time.Minute

// Verifier verifies RS256 JWTs against a remote JWKS.
type Verifier struct {
	url    string
	client *http.Client
	parser *jwt.Parser

	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	lastTry time.Time
	now     func() time.Time
}

// NewVerifier builds a Verifier. Keys are fetched lazily and cached.
func NewVerifier(jwksURL, issuer, audience string, client *http.Client) *Verifier {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Verifier{
		url:    jwksURL,
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
		return fmt.Errorf("token invalid: %s", sanitize(err))
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
	v.mu.RLock()
	k, ok := v.keys[kid]
	v.mu.RUnlock()
	if ok {
		return k, nil
	}
	if err := v.refresh(ctx); err != nil {
		return nil, err
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("unknown kid")
}

// refresh fetches the JWKS, at most once per refreshInterval. Cached keys
// are kept when a fetch fails.
func (v *Verifier) refresh(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.lastTry.IsZero() && v.now().Sub(v.lastTry) < refreshInterval {
		return errors.New("jwks refresh rate limited")
	}
	v.lastTry = v.now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.url, nil)
	if err != nil {
		return errors.New("jwks request failed")
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return errors.New("jwks fetch failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch status %d", resp.StatusCode)
	}
	var set jwks
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return errors.New("jwks decode failed")
	}
	keys := map[string]*rsa.PublicKey{}
	for _, j := range set.Keys {
		if pk, err := j.publicKey(); err == nil {
			keys[j.Kid] = pk
		}
	}
	v.keys = keys
	return nil
}
