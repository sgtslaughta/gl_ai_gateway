package sts

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// MaxTokenTTL is the hard cap on issued token lifetime.
const MaxTokenTTL = 30 * time.Minute

// IssuerConfig describes one allowlisted ID token issuer.
type IssuerConfig struct {
	URL      string `json:"url"`
	Audience string `json:"audience"`
	JWKSURL  string `json:"jwks_url"`
}

// DirectoryConfig describes the LDAPS directory used for identity lookup.
type DirectoryConfig struct {
	URL              string `json:"url"`
	BaseDN           string `json:"base_dn"`
	BindDN           string `json:"bind_dn"`
	BindPasswordFile string `json:"bind_password_file"`
	EmailAttribute   string `json:"email_attribute"`
}

// Config is the STS configuration. TokenTTL is a Go duration string in JSON.
type Config struct {
	Issuers         []IssuerConfig
	RunnerIDs       []int64
	GatewayAudience string
	TokenTTL        time.Duration
	Directory       DirectoryConfig
}

type configJSON struct {
	Issuers         []IssuerConfig  `json:"issuers"`
	RunnerIDs       []int64         `json:"runner_ids"`
	GatewayAudience string          `json:"gateway_audience"`
	TokenTTL        string          `json:"token_ttl"`
	Directory       DirectoryConfig `json:"directory"`
}

// LoadConfig reads and validates the JSON config at path.
func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var j configJSON
	if err := json.Unmarshal(b, &j); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	ttl, err := time.ParseDuration(j.TokenTTL)
	if err != nil {
		return Config{}, errors.New("config: invalid token_ttl")
	}
	c := Config{j.Issuers, j.RunnerIDs, j.GatewayAudience, ttl, j.Directory}
	return c, c.Validate()
}

// Validate checks required fields and the TTL cap.
func (c Config) Validate() error {
	switch {
	case c.TokenTTL <= 0 || c.TokenTTL > MaxTokenTTL:
		return errors.New("config: token_ttl must be in (0, 30m]")
	case c.GatewayAudience == "":
		return errors.New("config: gateway_audience required")
	case len(c.Issuers) == 0:
		return errors.New("config: at least one issuer required")
	}
	for _, i := range c.Issuers {
		if i.URL == "" || i.Audience == "" || i.JWKSURL == "" {
			return errors.New("config: issuer needs url, audience, jwks_url")
		}
	}
	return nil
}
