package sts

import "testing"

func TestCheckPolicy(t *testing.T) {
	cfg := Config{RunnerIDs: []int64{7}}
	cases := []struct {
		name string
		c    GitLabClaims
		want error
	}{
		{"bad runner", GitLabClaims{RunnerID: 8, PipelineSource: "push"}, ErrRunnerNotAllowed},
		{"schedule unprotected", GitLabClaims{RunnerID: 7, PipelineSource: "schedule", RefProtected: "false"}, ErrScheduleRefNotProtected},
		{"push ok", GitLabClaims{RunnerID: 7, PipelineSource: "push", RefProtected: "false"}, nil},
		{"schedule protected ok", GitLabClaims{RunnerID: 7, PipelineSource: "schedule", RefProtected: "true"}, nil},
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
