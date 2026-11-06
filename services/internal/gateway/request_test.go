package gateway

import (
	"encoding/json"
	"net/http"
	"testing"

	"ai-access/internal/token"
)

func TestExtractToken(t *testing.T) {
	cases := []struct {
		name string
		h    map[string]string
		want string
		ok   bool
	}{
		{"bearer", map[string]string{"Authorization": "Bearer x"}, "x", true},
		{"apikey", map[string]string{"x-api-key": "x"}, "x", true},
		{"both same", map[string]string{"Authorization": "Bearer x", "x-api-key": "x"}, "x", true},
		{"both differ", map[string]string{"Authorization": "Bearer x", "x-api-key": "y"}, "", false},
		{"neither", map[string]string{}, "", false},
		{"basic", map[string]string{"Authorization": "Basic x"}, "", false},
		{"empty bearer", map[string]string{"Authorization": "Bearer "}, "", false},
	}
	for _, c := range cases {
		h := http.Header{}
		for k, v := range c.h {
			h.Set(k, v)
		}
		got, err := ExtractToken(h)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("%s: got %q, %v", c.name, got, err)
		}
	}
}

func TestRouteAllowed(t *testing.T) {
	yes := [][2]string{
		{"POST", "/v1/chat/completions"}, {"POST", "/v1/messages"}, {"POST", "/v1/messages/count_tokens"},
		{"POST", "/v1/embeddings"}, {"GET", "/v1/models"},
	}
	for _, c := range yes {
		if !RouteAllowed(c[0], c[1]) {
			t.Errorf("want allowed: %v", c)
		}
	}
	no := [][2]string{
		{"POST", "/v1/batches"}, {"POST", "/v1/files"}, {"POST", "/key/generate"}, {"POST", "/v1/responses"},
		{"POST", "/v1/../key"}, {"POST", "/v1/chat/completions/"}, {"GET", "/V1/models"},
		{"GET", "/v1/%6dodels"}, {"GET", "/v1/messages"}, {"POST", "/v1/models"}, {"GET", "/v1/chat/completions"},
	}
	for _, c := range no {
		if RouteAllowed(c[0], c[1]) {
			t.Errorf("want denied: %v", c)
		}
	}
}

func TestRewriteHeaders(t *testing.T) {
	h := http.Header{}
	for k, v := range map[string]string{
		"X-Proxied-Entity": "cn=evil", "Authorization": "Bearer t", "x-api-key": "t", "api-key": "t",
		"x-litellm-api-key": "t", "x-litellm-spend-logs-metadata": `{"job_id":"evil"}`,
		"x-litellm-other": "z", "X-CI-Job": "evil", "X-CI-Extra": "e", "Cookie": "c=1", "x-goog-api-key": "g", "X-Remote-User": "r", "X_Proxied_Entity": "u", "X-Forwarded-User": "f", "Upgrade": "websocket", "Content-Type": "application/json", "anthropic-version": "2023-06-01",
	} {
		h.Set(k, v)
	}
	RewriteHeaders(h, token.Claims{DN: "cn=alice", ProjectPath: "g/p", PipelineID: "1", JobID: "2"})
	if got := h.Values("X-Proxied-Entity"); len(got) != 1 || got[0] != "cn=alice" {
		t.Fatal(got)
	}
	for _, k := range []string{"Authorization", "x-api-key", "api-key", "x-litellm-api-key", "x-litellm-other", "X-CI-Extra", "Cookie", "x-goog-api-key", "X-Remote-User", "X_Proxied_Entity", "X-Forwarded-User", "Upgrade"} {
		if h.Get(k) != "" {
			t.Errorf("%s survived", k)
		}
	}
	if h.Get("Content-Type") != "application/json" {
		t.Error("content-type dropped")
	}
	if h.Get("anthropic-version") != "2023-06-01" {
		t.Error("anthropic-version dropped")
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(h.Get("x-litellm-spend-logs-metadata")), &m); err != nil ||
		m["project_path"] != "g/p" || m["pipeline_id"] != "1" || m["job_id"] != "2" {
		t.Fatal(m, err)
	}
	if h.Get("X-CI-Project") != "g/p" || h.Get("X-CI-Pipeline") != "1" || h.Get("X-CI-Job") != "2" {
		t.Fatal(h)
	}
}
