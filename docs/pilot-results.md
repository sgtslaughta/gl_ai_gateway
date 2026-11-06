# Pilot results

**NOTHING HAS BEEN RUN YET.** This is an empty template. The services have
not been deployed, and no pilot job has run. Every result cell is blank. Do not
treat anything here as evidence until it is filled in with real run data.

Fill in: result (PASS, FAIL or N/A), date, who ran it, job or pipeline link,
and notes. A single FAIL blocks Phase 2 until fixed.

Environment: Date ____  Operator ____
Record the GitLab version and tier privately, not in this public repo. Write only "recorded privately" here.

## Section 14 acceptance tests

| # | Test | Result | Date | Evidence | Notes |
|---|---|---|---|---|---|
| 1 | Forged token rejected by STS and gateway | | | | |
| 2 | Expired token rejected by STS and gateway | | | | |
| 3 | Wrong-`aud` token rejected by STS and gateway | | | | |
| 4 | Unlisted runner gets no token | | | | |
| 5 | Scheduled pipeline, unprotected ref: no token | | | | |
| 6 | Trigger pipeline, unprotected ref: no token | | | | |
| 7 | Child pipeline, unprotected ref: no token | | | | |
| 8 | Unmapped user: no token | | | | |
| 9 | Bot user: no token | | | | |
| 10 | Non-allowlisted image: job refused | | | | |
| 11 | Job-supplied `X-Proxied-Entity` is overwritten | | | | |
| 12 | Blocked destination unreachable from AI job | | | | |
| 13 | Blocked path rejected, including `/v1/batches` | | | | |
| 14 | LiteLLM admin routes rejected | | | | |
| 15 | Oversized request rejected | | | | |
| 16 | Client `x-litellm-*`, `x-api-key`, `Authorization` never reach LiteLLM | | | | |
| 17 | Spoofed `user` or `metadata` body value does not change identity or attribution | | | | |
| 18 | Spoofed body value does not change limits | | | | |
| 19 | OpenAI-style call, non-streaming, right user | | | | |
| 20 | OpenAI-style call, streaming, right user | | | | |
| 21 | Anthropic-style call, non-streaming, right user | | | | |
| 22 | Anthropic-style call, streaming, right user | | | | |
| 23 | Provider applies the proxied user's permissions, not the gateway's | | | | |
| 24 | Audit record links each gateway request to its user and job | | | | |
| 25 | Join to provider records by request ID (does not block Phase 2) | | | | |
| 26 | No body content in STS, gateway or runner logs | | | | |
| 27 | Code review on test MR shows findings with no write credential present | | | | |
| 28 | `ai-base`: review and token exchange run as non-root | | | | |
| 29 | `ai-base`: no package manager, no setuid binaries. Note: `dpkg` is kept on purpose, a deviation from the design. See `accreditor-package.md` | | | | |
| 30 | `ai-base`: no secrets | | | | |
| 31 | `ai-base`: passing scan | | | | |
| 32 | `ai-base`: SBOM produced | | | | |
| 33 | Job requesting root refused, or runs without root | | | | |
| 34 | Option 2 only: runner by group Owner but not on list gets no token | | | | |
| 35 | Option 3 only: other `ci_config_ref_uri` gets no token; users cannot run own YAML | | | | |

Extra checks from the pilot plan:

| # | Test | Result | Date | Evidence | Notes |
|---|---|---|---|---|---|
| E1 | Fork MR pipeline in the parent project denied (`fork_pipeline_denied`) | | | | |
| E2 | `CI_DEBUG_TRACE` on: search log for token material | | | | |
| E3 | Forcing `CI_DEBUG_TRACE` off via runner `environment` | | | | |
| E4 | Real tokens carry `job_project_path` (working assumption 9) | | | | |
| E5 | `dpkg` present in image, `apt` and `apt-get` absent | | | | |

## Step 4 measures

| Measure | Value | Date | Notes |
|---|---|---|---|
| Review latency (median, slowest) | | | |
| LLM load per review (calls, tokens) | | | |
| False failures (jobs failed for reasons not in the design) | | | |
| Code quality diff annotations shown on this tier? | | | |
| CI context in provider records: metadata method seen? | | | |
| CI context in provider records: plain headers method seen? | | | |
| Method kept; method dropped | | | |
| `x-litellm-call-id` reaches gateway and joins to spend logs? | | | |
| Sizing data for about 100 simultaneous jobs (runner CPU, memory, STS and gateway load) | | | |

## Section 13.1 working assumptions, once checked

| # | Assumption | Confirmed? | Notes |
|---|---|---|---|
| 1 | `mail` lookup returns exactly one entry per user | | |
| 2 | Directory DN equals certificate DN | | |
| 3 | Provider accepts that DN in `X-Proxied-Entity` | | |
| 4 | Regular users cannot change their email | | |
| 5 | Trigger table holds; bots have no directory entry | | |
| 6 | Network paths exist | | |
| 7 | Read-only directory account over LDAPS | | |
| 8 | Go 1.26, module mirror, base image, package mirror exist | | |
| 9 | Real tokens carry `job_project_path` | | |
| 10 | License below Ultimate | | |

## Open items and failures
(none recorded, because nothing has been run)
