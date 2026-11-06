// Package gateway implements the pass-through AI gateway.
package gateway

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"ai-access/internal/token"
)

var errNoToken = errors.New("missing or invalid credentials")

// ExtractToken returns the bearer token from Authorization or x-api-key.
// If both are present they must match.
func ExtractToken(h http.Header) (string, error) {
	var bearer string
	if a := h.Get("Authorization"); a != "" {
		scheme, v, ok := strings.Cut(a, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			return "", errNoToken
		}
		bearer = strings.TrimSpace(v)
	}
	key := strings.TrimSpace(h.Get("x-api-key"))
	switch {
	case bearer != "" && key != "":
		if subtle.ConstantTimeCompare([]byte(bearer), []byte(key)) != 1 {
			return "", errNoToken
		}
		return bearer, nil
	case bearer != "":
		return bearer, nil
	case key != "":
		return key, nil
	}
	return "", errNoToken
}

var allowedRoutes = map[string]bool{
	"POST /v1/chat/completions":      true,
	"POST /v1/messages":              true,
	"POST /v1/messages/count_tokens": true,
	"POST /v1/embeddings":            true,
	"GET /v1/models":                 true,
}

// RouteAllowed matches the exact escaped path; no normalizing is done.
func RouteAllowed(method, escapedPath string) bool {
	return allowedRoutes[method+" "+escapedPath]
}

var allowedExact = map[string]bool{
	"content-type": true, "accept": true, "accept-encoding": true, "user-agent": true, "idempotency-key": true,
}

var allowedPrefix = []string{"anthropic-", "openai-", "x-stainless-"}

func forwardable(name string) bool {
	l := strings.ToLower(name)
	if allowedExact[l] {
		return true
	}
	for _, p := range allowedPrefix {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// RewriteHeaders drops every client header not on the forwarding allowlist,
// then sets identity from the verified token claims.
func RewriteHeaders(h http.Header, c token.Claims) {
	for k := range h {
		if !forwardable(k) {
			delete(h, k)
		}
	}
	h.Set("X-Proxied-Entity", c.DN)
	meta, _ := json.Marshal(map[string]string{
		"project_path": c.ProjectPath, "pipeline_id": c.PipelineID, "job_id": c.JobID,
	})
	h.Set("x-litellm-spend-logs-metadata", string(meta))
	h.Set("X-CI-Project", c.ProjectPath)
	h.Set("X-CI-Pipeline", c.PipelineID)
	h.Set("X-CI-Job", c.JobID)
}
