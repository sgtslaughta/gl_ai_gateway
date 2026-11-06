# Phase 0 results

Record names of claims, not sensitive values. Commit this only if it holds nothing sensitive.

**Date:** ____  **Tester:** ____  **GitLab version:** ____  **Tier:** ____

| Item | Result | Notes |
|---|---|---|
| `identity-mapping` (the gate) | | DN in token, or email lookup? |
| Provider with the DN, in `user_identities` | | Which provider name? |
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

Build can start: yes / no. Mapping method: ____
