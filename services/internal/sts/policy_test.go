package sts

import "testing"

func TestCheckPolicy(t *testing.T) {
	cfg := Config{RunnerIDs: []int64{7}}
	cases := []struct {
		name string
		c    GitLabClaims
		want error
	}{
		{"bad runner", GitLabClaims{ProjectPath: "g/p", JobProjectPath: "g/p", RunnerID: 8, PipelineSource: "push"}, ErrRunnerNotAllowed},
		{"schedule unprotected", GitLabClaims{ProjectPath: "g/p", JobProjectPath: "g/p", RunnerID: 7, PipelineSource: "schedule", RefProtected: "false"}, ErrRefNotProtected},
		{"push ok", GitLabClaims{ProjectPath: "g/p", JobProjectPath: "g/p", RunnerID: 7, PipelineSource: "push", RefProtected: "false"}, nil},
		{"schedule protected ok", GitLabClaims{ProjectPath: "g/p", JobProjectPath: "g/p", RunnerID: 7, PipelineSource: "schedule", RefProtected: "true"}, nil},
	}
	for _, tc := range cases {
		if got := CheckPolicy(tc.c, cfg); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestConfigTTLCap(t *testing.T) {
	c := Config{GatewayAudience: "gw", Issuers: []IssuerConfig{{"a", "b", "c"}}, TokenTTL: 31 * 60e9}
	if c.Validate() == nil {
		t.Fatal("ttl above 30m accepted")
	}
	c.TokenTTL = 30 * 60e9
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRefProtectionBySource(t *testing.T) {
	cfg := Config{RunnerIDs: []int64{7}}
	check := func(src, prot string) error {
		return CheckPolicy(GitLabClaims{ProjectPath: "g/p", JobProjectPath: "g/p", RunnerID: 7, PipelineSource: src, RefProtected: prot}, cfg)
	}
	for _, s := range []string{"push", "web", "merge_request_event"} {
		if err := check(s, "false"); err != nil {
			t.Errorf("%s unprotected: %v", s, err)
		}
	}
	for _, s := range []string{"schedule", "trigger", "pipeline", "parent_pipeline", "api", "bogus", ""} {
		if err := check(s, "false"); err != ErrRefNotProtected {
			t.Errorf("%q unprotected: %v", s, err)
		}
		if err := check(s, "true"); err != nil {
			t.Errorf("%q protected: %v", s, err)
		}
	}
	for _, p := range []string{"", "True", "1", "yes"} {
		if check("schedule", p) != ErrRefNotProtected {
			t.Errorf("ref_protected %q treated as protected", p)
		}
	}
}

func TestForkPipelineDenied(t *testing.T) {
	cfg := Config{RunnerIDs: []int64{7}}
	for _, prot := range []string{"true", "false"} {
		for job, want := range map[string]error{"g/p": nil, "fork/p": ErrForkPipelineDenied, "": ErrForkPipelineDenied} {
			c := GitLabClaims{RunnerID: 7, PipelineSource: "push", RefProtected: prot, ProjectPath: "g/p", JobProjectPath: job}
			if got := CheckPolicy(c, cfg); got != want {
				t.Errorf("prot=%s job=%q: %v", prot, job, got)
			}
		}
	}
}
