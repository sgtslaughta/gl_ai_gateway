package main_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ai-access/internal/gateway"
	"ai-access/internal/sts"
	"ai-access/internal/token"

	"github.com/golang-jwt/jwt/v5"
)

const glIssuer = "https://gitlab.example.internal"

type stack struct {
	gw, sts *httptest.Server
	idToken func(aud string) string
	seen    chan http.Header
	signer  *token.Signer
}

func newStack(t *testing.T) *stack {
	t.Helper()
	idKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	glJWKS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1",
			"n": base64.RawURLEncoding.EncodeToString(idKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(idKey.E)).Bytes()),
		}}})
	}))
	stsKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	kf := filepath.Join(t.TempDir(), "k.pem")
	os.WriteFile(kf, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(stsKey)}), 0o600)
	signer, err := token.NewSigner([]string{kf}, "https://sts.example.internal")
	if err != nil {
		t.Fatal(err)
	}
	cfg := sts.Config{RunnerIDs: []int64{7}, GatewayAudience: "gateway", TokenTTL: 20 * time.Minute}
	lookup := func(context.Context, string) (string, error) { return "cn=alice,dc=example,dc=internal", nil }
	s := &stack{seen: make(chan http.Header, 8), signer: signer}
	s.sts = httptest.NewServer(sts.NewHandler(cfg,
		map[string]*token.Verifier{glIssuer: token.NewVerifier(glJWKS.URL, glIssuer, "sts", nil)}, signer, lookup, &bytes.Buffer{}))
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.seen <- r.Header.Clone()
		io.Copy(io.Discard, r.Body)
		if strings.Contains(r.Header.Get("Accept"), "event-stream") {
			w.Header().Set("Content-Type", "text/event-stream")
			for _, c := range []string{"data: a\n\n", "data: b\n\n"} {
				w.Write([]byte(c))
				w.(http.Flusher).Flush()
			}
			return
		}
		w.Header().Set("x-litellm-call-id", "c1")
		w.Write([]byte(`{"ok":true}`))
	}))
	v := token.NewVerifier(s.sts.URL+"/.well-known/jwks.json", "https://sts.example.internal", "gateway", nil)
	gh, err := gateway.NewHandler(gateway.Config{UpstreamURL: up.URL, BatchServiceURL: "https://batch.example.internal"}, v, up.Client().Transport, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	s.gw = httptest.NewServer(gh)
	t.Cleanup(func() { s.gw.Close(); s.sts.Close(); up.Close(); glJWKS.Close() })
	s.idToken = func(aud string) string {
		tk := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": glIssuer, "aud": aud, "exp": time.Now().Add(time.Hour).Unix(),
			"user_email": "a@example.internal", "user_id": "42", "user_login": "alice",
			"project_path": "g/p", "ref": "main", "ref_protected": "true", "sha": "abc",
			"pipeline_id": "100", "pipeline_source": "push", "job_id": "200", "runner_id": 7,
		})
		tk.Header["kid"] = "k1"
		out, err := tk.SignedString(idKey)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	return s
}

func (s *stack) exchange(t *testing.T, id string) string {
	t.Helper()
	resp, err := http.PostForm(s.sts.URL+"/token", url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":      {id},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != 200 || out.AccessToken == "" {
		t.Fatal("exchange failed", resp.StatusCode)
	}
	return out.AccessToken
}

func (s *stack) call(t *testing.T, path string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", s.gw.URL+path, strings.NewReader(`{"m":1}`))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestEndToEnd(t *testing.T) {
	s := newStack(t)
	at := s.exchange(t, s.idToken("sts"))
	cases := []struct {
		name, path string
		hdr        map[string]string
		want       string
	}{
		{"openai", "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + at}, `{"ok":true}`},
		{"anthropic", "/v1/messages", map[string]string{"x-api-key": at, "anthropic-version": "2023-06-01"}, `{"ok":true}`},
		{"openai stream", "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + at, "Accept": "text/event-stream"}, "data: a\n\ndata: b\n\n"},
		{"anthropic stream", "/v1/messages", map[string]string{"x-api-key": at, "Accept": "text/event-stream"}, "data: a\n\ndata: b\n\n"},
	}
	for _, c := range cases {
		code, body := s.call(t, c.path, c.hdr)
		if code != 200 || body != c.want {
			t.Errorf("%s: %d %q", c.name, code, body)
		}
		h := <-s.seen
		if h.Get("X-Proxied-Entity") != "cn=alice,dc=example,dc=internal" || h.Get("Authorization") != "" || h.Get("x-api-key") != "" {
			t.Errorf("%s: upstream headers %v", c.name, h)
		}
	}
}

func TestGatewayRejectsWrongTokens(t *testing.T) {
	s := newStack(t)
	other := mintOther(t, s)
	for name, tok := range map[string]string{"raw gitlab id token": s.idToken("sts"), "other audience": other} {
		if code, _ := s.call(t, "/v1/messages", map[string]string{"Authorization": "Bearer " + tok}); code != 401 {
			t.Errorf("%s: %d", name, code)
		}
	}
	select {
	case <-s.seen:
		t.Fatal("rejected token reached upstream")
	default:
	}
}

// mintOther returns a token signed by the real STS key for another audience.
func mintOther(t *testing.T, s *stack) string {
	t.Helper()
	out, err := s.signer.Sign(token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{Audience: jwt.ClaimStrings{"other"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))},
		DN:               "cn=alice,dc=example,dc=internal",
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}
