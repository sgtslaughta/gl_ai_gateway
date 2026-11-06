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
	ErrRunnerNotAllowed        = errors.New("runner_not_allowed")
	ErrScheduleRefNotProtected = errors.New("schedule_ref_not_protected")
)

// CheckPolicy applies the runner and schedule rules.
func CheckPolicy(c GitLabClaims, cfg Config) error {
	if !slices.Contains(cfg.RunnerIDs, c.RunnerID) {
		return ErrRunnerNotAllowed
	}
	if c.PipelineSource == "schedule" && c.RefProtected != "true" {
		return ErrScheduleRefNotProtected
	}
	return nil
}
