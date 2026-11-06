// Package sts implements the security token service.
package sts

import (
	"errors"
	"slices"
)

// GitLabClaims are the GitLab ID token claims the STS uses.
type GitLabClaims struct {
	jwtRegistered
	UserEmail      string `json:"user_email"`
	UserID         string `json:"user_id"`
	UserLogin      string `json:"user_login"`
	ProjectPath    string `json:"project_path"`
	JobProjectPath string `json:"job_project_path"`
	Ref            string `json:"ref"`
	RefProtected   string `json:"ref_protected"`
	SHA            string `json:"sha"`
	PipelineID     string `json:"pipeline_id"`
	PipelineSource string `json:"pipeline_source"`
	JobID          string `json:"job_id"`
	RunnerID       int64  `json:"runner_id"`
}

// Policy denial errors; Error() is the short reason code.
var (
	ErrRunnerNotAllowed   = errors.New("runner_not_allowed")
	ErrRefNotProtected    = errors.New("ref_not_protected")
	ErrForkPipelineDenied = errors.New("fork_pipeline_denied")
)

// CheckPolicy applies the policy rules, all required: the runner is on the
// allowlist, the job ran in the project the token names (no fork pipelines),
// and sources other than push, web and merge_request_event use protected refs.
func CheckPolicy(c GitLabClaims, cfg Config) error {
	if !slices.Contains(cfg.RunnerIDs, c.RunnerID) {
		return ErrRunnerNotAllowed
	}
	if c.JobProjectPath == "" || c.JobProjectPath != c.ProjectPath {
		return ErrForkPipelineDenied
	}
	if !unprotectedOK(c.PipelineSource) && c.RefProtected != "true" {
		return ErrRefNotProtected
	}
	return nil
}

// unprotectedOK is the exact allowlist of sources a person starts directly.
// Every other source (schedule, trigger, pipeline, parent_pipeline, api,
// unknown or empty) needs a protected ref.
func unprotectedOK(source string) bool {
	switch source {
	case "push", "web", "merge_request_event":
		return true
	}
	return false
}
