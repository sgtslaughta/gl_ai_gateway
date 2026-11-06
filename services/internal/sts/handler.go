package sts

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"ai-access/internal/token"

	"github.com/golang-jwt/jwt/v5"
)

const (
	grantType   = "urn:ietf:params:oauth:grant-type:token-exchange"
	jwtType     = "urn:ietf:params:oauth:token-type:jwt"
	maxBodySize = 64 << 10
)

// Handler serves the STS HTTP API.
type Handler struct {
	cfg       Config
	verifiers map[string]*token.Verifier // keyed by issuer URL
	signer    *token.Signer
	lookup    LookupFunc
	now       func() time.Time

	auditMu sync.Mutex
	audit   io.Writer
}

// NewHandler builds the STS http.Handler. verifiers is keyed by issuer URL.
func NewHandler(cfg Config, verifiers map[string]*token.Verifier, signer *token.Signer, lookup LookupFunc, audit io.Writer) http.Handler {
	h := &Handler{cfg: cfg, verifiers: verifiers, signer: signer, lookup: lookup, audit: audit, now: time.Now}
	return h.routes()
}

func (h *Handler) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", h.exchange)
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(h.signer.JWKS())
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	return mux
}

type auditRecord struct {
	Time     string `json:"time"`
	User     string `json:"user"`
	UserID   string `json:"user_id"`
	DN       string `json:"dn"`
	Project  string `json:"project"`
	Ref      string `json:"ref"`
	SHA      string `json:"sha"`
	Pipeline string `json:"pipeline"`
	Job      string `json:"job"`
	Runner   int64  `json:"runner"`
	Status   int    `json:"status"`
	Reason   string `json:"reason"`
}

func (h *Handler) decide(w http.ResponseWriter, c GitLabClaims, dn string, status int, reason string, resp any) {
	rec := auditRecord{h.now().UTC().Format(time.RFC3339), c.UserLogin, c.UserID, dn, c.ProjectPath,
		c.Ref, c.SHA, c.PipelineID, c.JobID, c.RunnerID, status, reason}
	if b, err := json.Marshal(rec); err == nil && h.audit != nil {
		h.auditMu.Lock()
		h.audit.Write(append(b, '\n'))
		h.auditMu.Unlock()
	}
	if resp == nil {
		resp = map[string]string{"error": reason}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) exchange(w http.ResponseWriter, r *http.Request) {
	var none GitLabClaims
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := r.ParseForm(); err != nil {
		h.decide(w, none, "", http.StatusBadRequest, "invalid_request", nil)
		return
	}
	raw := r.PostForm.Get("subject_token")
	if r.PostForm.Get("grant_type") != grantType || r.PostForm.Get("subject_token_type") != jwtType || raw == "" {
		h.decide(w, none, "", http.StatusBadRequest, "invalid_request", nil)
		return
	}
	v := h.verifierFor(raw)
	var c GitLabClaims
	if v == nil || v.Verify(r.Context(), raw, &c) != nil {
		h.decide(w, none, "", http.StatusUnauthorized, "invalid_token", nil)
		return
	}
	if err := CheckPolicy(c, h.cfg); err != nil {
		h.decide(w, c, "", http.StatusForbidden, err.Error(), nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	dn, err := MapDN(ctx, c, h.lookup)
	if err != nil {
		h.decide(w, c, "", http.StatusForbidden, err.Error(), nil)
		return
	}
	now := h.now()
	exp := now.Add(h.cfg.TokenTTL)
	if c.ExpiresAt != nil && c.ExpiresAt.Time.Before(exp) {
		exp = c.ExpiresAt.Time
	}
	if !exp.After(now) {
		h.decide(w, c, dn, http.StatusUnauthorized, "invalid_token", nil)
		return
	}
	signed, err := h.signer.Sign(token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{h.cfg.GatewayAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		DN: dn, UserLogin: c.UserLogin, ProjectPath: c.ProjectPath, Ref: c.Ref, SHA: c.SHA,
		PipelineID: c.PipelineID, JobID: c.JobID, RunnerID: c.RunnerID,
	})
	if err != nil {
		h.decide(w, c, dn, http.StatusInternalServerError, "sign_failed", nil)
		return
	}
	h.decide(w, c, dn, http.StatusOK, "ok", map[string]any{
		"access_token":      signed,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        "Bearer",
		"expires_in":        int(exp.Sub(now).Seconds()),
	})
}

// verifierFor picks the verifier by the unverified iss claim. The chosen
// verifier then checks the issuer and signature, so this is only routing.
func (h *Handler) verifierFor(raw string) *token.Verifier {
	var rc jwt.RegisteredClaims
	if _, _, err := jwt.NewParser().ParseUnverified(raw, &rc); err != nil {
		return nil
	}
	return h.verifiers[rc.Issuer]
}
