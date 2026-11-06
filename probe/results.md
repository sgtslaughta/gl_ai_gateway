# Phase 0 results

Record names of claims, not sensitive values. Commit this only if it holds nothing sensitive.

**Date:** ____  **Tester:** ____

Record the GitLab version and tier privately, not in this repo.

| Item | Result | Notes |
|---|---|---|
| `identity-mapping` | | `user_email` present? |
| Directory lookup returns one entry per email | | Which attribute? |
| Directory DN matches certificate DN | | Any transform needed? Shape only, no real DNs |
| Regular user can't change email | | |
| `job_project_path` in token, equal to `project_path` on a normal job | | Required by STS's fork rule |
| Token claim names present | | |
| `token-lifetime` | | Seconds, against job timeout |
| OIDC discovery and signing key | | |
| Runner reaches registry, GitLab | | |
| Enclave reaches GitLab OIDC, directory, provider | | |
| Runner reaches enclave ingress | | |
| Instance runner: admin answer | | Yes, no or pending |
| Approved base image, package mirror, helper image | | |

## Trigger test

| Trigger | `user_login` as expected? | Notes |
|---|---|---|
| Push | | |
| MR pipeline | | |
| Retry | | |
| Manual | | |
| Schedule, protected | | |
| Schedule, unprotected | | |
| Trigger token | | |
| Bot | | |

## Decision

Deployment can start: yes / no. Directory attribute and DN transform: ____
