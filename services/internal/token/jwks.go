package token

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func (j jwk) publicKey() (*rsa.PublicKey, error) {
	if j.Kty != "RSA" || j.Kid == "" {
		return nil, errors.New("unsupported jwk")
	}
	n, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, err
	}
	e, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, err
	}
	ei := new(big.Int).SetBytes(e)
	if !ei.IsInt64() || ei.Int64() < 3 {
		return nil, errors.New("bad exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(ei.Int64())}, nil
}

func toJWK(pub *rsa.PublicKey) jwk {
	der := x509.MarshalPKCS1PublicKey(pub)
	sum := sha256.Sum256(der)
	return jwk{
		Kty: "RSA", Use: "sig", Alg: "RS256",
		Kid: base64.RawURLEncoding.EncodeToString(sum[:]),
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// Signer signs tokens with the first key and publishes all keys.
type Signer struct {
	issuer string
	keys   []*rsa.PrivateKey
	kids   []string
	jwks   []byte
}

// NewSigner loads PEM private keys (PKCS#1 or PKCS#8). The first signs.
func NewSigner(keyFiles []string, issuer string) (*Signer, error) {
	if len(keyFiles) == 0 {
		return nil, errors.New("no signing keys")
	}
	if issuer == "" {
		return nil, errors.New("signer issuer is required")
	}
	s := &Signer{issuer: issuer}
	var set jwks
	for _, f := range keyFiles {
		pemBytes, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read key %s: %w", f, err)
		}
		k, err := parseKey(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("parse key %s: %w", f, err)
		}
		j := toJWK(&k.PublicKey)
		s.keys = append(s.keys, k)
		s.kids = append(s.kids, j.Kid)
		set.Keys = append(set.Keys, j)
	}
	s.jwks, _ = json.Marshal(set)
	return s, nil
}

func parseKey(b []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("unsupported key format")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return rk, nil
}

// Sign signs c with the first key, setting the issuer.
func (s *Signer) Sign(c Claims) (string, error) {
	c.Issuer = s.issuer
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	t.Header["kid"] = s.kids[0]
	return t.SignedString(s.keys[0])
}

// JWKS returns the published key set as JSON.
func (s *Signer) JWKS() []byte { return s.jwks }
