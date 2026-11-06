# GitLab Runner AI Access Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let GitLab CI jobs use the AI provider under the triggering user's identity, with no user certificates on runners, proven through a very small pilot of read-only AI code review.

**Architecture:** A job swaps its GitLab ID token at STS for a short-lived token. A pass-through gateway verifies that token and calls the provider with its own mTLS certificate plus `X-Proxied-Entity`. Hard controls live in STS, the gateway, and your runner and network configuration, while CI templates only provide convenience.

**Tech Stack:** Go standard library plus `github.com/golang-jwt/jwt/v5` for STS and gateway and `github.com/go-ldap/ldap/v3` for STS's directory lookup (planner's choice, for its streaming proxy and single static binary; spec 13.1 assumes the toolchain and module mirror exist). Python 3 standard library and POSIX shell for image tools. GitLab Runner Kubernetes executor, Kubernetes NetworkPolicy.

**Spec:** `docs/superpowers/specs/2026-11-05-gitlab-runner-ai-access-design.md`. Read sections 3, 5, 6, 8 and 9 before starting.

**Scope:** Phases 0 and 1 only. Phase 2 (production), Phase 3 (MR comments), Phase 4 (agent fixes) and access option 3 need their own plans after the pilot.

## Global Constraints

- No user private keys or passwords on runners or in any new service.
- Never store or log prompts or responses. No body logging, and core dumps disabled.
- Never accept identity from a CI variable, job input or unsigned source. No match means deny, with no fallback.
- Never print tokens, including in errors.
- STS token: `aud` is the gateway only, at most 30 minutes, and never beyond the ID token's `exp`.
- Runner: tag `ai`, Run untagged off, maximum job timeout 1800 seconds.
- Allowed gateway routes: `POST /v1/chat/completions`, `POST /v1/messages`, `POST /v1/messages/count_tokens`, `POST /v1/embeddings`, `GET /v1/models`. Deny everything else.
- Pilot uses non-sensitive test projects only. HA and autoscaling are not required, but no security control is relaxed.
- Files stay under 500 lines. Commits use semantic messages. Any versioned artifact uses semantic versions.
- Examples use `*.example.internal`. Real values come from config, never from code.

## Review Focus

1. A token signed with `alg: none` or HS256 using the public key as the secret must be rejected. Test in Task 2.
2. A DN or claim containing CR, LF or other control characters must be denied, never placed in a header. Test in Task 3.
3. A client disconnecting mid-stream must cancel the upstream call, and streamed chunks must arrive unbuffered. Test in Task 5.
4. A signing key rotation or a short GitLab outage must not break valid tokens: an unknown `kid` refreshes once within a rate limit, and cached keys keep working. Test in Task 2.
5. An empty diff, an oversized diff, or malformed model output must produce a valid report or a clean failure, never a broken artifact or printed content. Test in Task 7.

---

## Phase 0: Validate

### Task 1: Run the probe and record results

**Owner's decision, 2026-11-06:** Tasks 2 to 9 and the Task 10 docs proceed now on spec section 13.1's working assumptions. Steps 2 to 5 here, and Task 10's pilot runs, stay open and must finish before any deployment. The probe already exists and its unit tests pass: `probe/phase0_probe.py`, `probe/phase0-probe.gitlab-ci.yml`, `probe/README.md`, `probe/results.md`. This task needs a person with access to the network.

**Files:**
- Modify: `probe/results.md`

- [ ] **Step 1: Initialize the repo and commit the existing docs and probe**

```bash
git init && git add .gitignore docs probe && git commit -m "docs: add AI access design, plan and Phase 0 probe"
```

- [ ] **Step 2: Run the probe in a private test project, following `probe/README.md`**

Expected: job log shows `identity-mapping` as `PASS` or `WARN`.

- [ ] **Step 3: Run the trigger test and enclave network test, and record everything in `probe/results.md`**

- [ ] **Step 4: Ask GitLab admins about an instance runner, and registry owners about the approved base, mirror and helper image. Record the answers**

- [ ] **Step 5: Apply the gate**

If `identity-mapping` is `FAIL`, or the directory DN doesn't match the certificate DN, stop and agree a fix with the owner. Otherwise record the directory attribute and any DN transform. Task 3 depends on them.

- [ ] **Step 6: Commit**

```bash
git add probe/results.md && git commit -m "docs: record Phase 0 probe results"
```

---

## Phase 1: Pilot

### Task 2: Shared token package

**Files:**
- Create: `services/go.mod` (module `ai-access`), `services/internal/token/token.go`, `services/internal/token/jwks.go`
- Test: `services/internal/token/token_test.go`

**Interfaces:**
- Produces:
  - `type Claims struct { jwt.RegisteredClaims; DN, UserLogin, ProjectPath, Ref, SHA, PipelineID, JobID string; RunnerID int64 }` with JSON names `dn`, `user_login`, `project_path`, `ref`, `sha`, `pipeline_id`, `job_id`, `runner_id`.
  - `type Verifier struct` and `NewVerifier(jwksURL, issuer, audience string, client *http.Client) *Verifier`.
  - `func (v *Verifier) Verify(ctx context.Context, raw string, into jwt.Claims) error`.
  - `type Signer struct` and `NewSigner(keyFiles []string, issuer string) (*Signer, error)`. The first key signs, and all are published.
  - `func (s *Signer) Sign(c Claims) (string, error)` and `func (s *Signer) JWKS() []byte`.

- [ ] **Step 1: Write failing tests**

Using a local RSA key and `httptest` JWKS server, assert `Verify` returns an error for: expired token, future `nbf`, wrong `iss`, wrong `aud`, `alg: none`, HS256 signed with the public key bytes, and tampered payload. Also assert:
- `TestVerifyValid`: valid token populates `into`.
- `TestUnknownKidRefreshesOnce`: a rotated key verifies after one refresh, and repeated unknown `kid` values make at most one JWKS fetch per minute.
- `TestCachedKeysSurviveOutage`: after the JWKS server closes, a token with a cached `kid` still verifies.
- `TestErrorsOmitToken`: no error string contains the raw token.
- `TestSignerPublishesAllKeys`: `JWKS()` contains every key, and `Sign` uses the first.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd services && go test ./internal/token/`
Expected: FAIL, undefined symbols.

- [ ] **Step 3: Implement**

Use `jwt.WithValidMethods([]string{"RS256"})`, `WithIssuer`, `WithAudience`, `WithExpirationRequired`. Keep a key map guarded by `sync.RWMutex`. Signer keys load from mounted PEM files.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd services && go test ./internal/token/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services && git commit -m "feat(token): add JWT verifier and signer"
```

### Task 3: STS service

**Files:**
- Create: `services/internal/sts/policy.go`, `mapping.go`, `handler.go`, `services/cmd/sts/main.go`
- Test: `services/internal/sts/policy_test.go`, `mapping_test.go`, `handler_test.go`

**Interfaces:**
- Consumes: `token.Verifier`, `token.Signer`, `token.Claims`.
- Produces:
  - `type GitLabClaims struct` with the ID token fields, including `UserEmail string`, `UserID string`, `RefProtected string`, `PipelineSource string`, and `RunnerID int64`.
  - `type IssuerConfig struct { URL, Audience, JWKSURL string }` and `type Config struct { Issuers []IssuerConfig; RunnerIDs []int64; GatewayAudience string; TokenTTL time.Duration; Directory DirectoryConfig }` with `type DirectoryConfig struct { URL, BaseDN, BindDN, BindPasswordFile, EmailAttribute string }`, loaded from JSON at `STS_CONFIG`. Only GitLab is listed in v1.
  - `func CheckPolicy(c GitLabClaims, cfg Config) error`.
  - `func MapDN(ctx context.Context, c GitLabClaims, lookup LookupFunc) (string, error)` with `type LookupFunc func(ctx context.Context, email string) (string, error)`.
  - HTTP: `POST /token`, RFC 8693 form fields `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token`, `subject_token_type=urn:ietf:params:oauth:token-type:jwt`. Returns JSON `access_token`, `issued_token_type`, `token_type: Bearer`, `expires_in`.
  - HTTP: `GET /.well-known/jwks.json`, `GET /healthz`.

- [ ] **Step 1: Write failing policy tests**

`CheckPolicy` returns an error for a `runner_id` not in `RunnerIDs`, and for `pipeline_source == "schedule"` with `ref_protected != "true"`. It passes for a listed runner on a push, and for a schedule on a protected ref.

- [ ] **Step 2: Write failing mapping tests**

- `TestLookupByEmail`: calls `lookup` with `user_email` and returns its DN.
- `TestMissingEmailDenied`: an empty `user_email` returns an error without calling `lookup`.
- `TestNoMatchDenied`: lookup miss returns an error.
- `TestNilLookupDenied`: nil lookup returns an error.
- `TestBotDenied`: a bot user with no directory match returns an error.
- `TestControlCharsDenied`: a DN containing `\r`, `\n` or `\x00` returns an error.
- `TestAmbiguousDenied`: a lookup error for several matching entries returns an error.

- [ ] **Step 3: Write failing handler tests**

- Valid exchange returns a token whose `aud` is `GatewayAudience`, and whose claims hold DN, project, ref, SHA, pipeline, job and runner.
- `exp` is `min(now+TokenTTL, idToken.exp)`, including a case where the ID token expires in 5 minutes.
- `TokenTTL` above 30 minutes is rejected at config load.
- Wrong `grant_type` or `subject_token_type` returns 400.
- Invalid token returns 401. Policy or mapping denial returns 403 with a short reason code such as `runner_not_allowed`, `schedule_ref_not_protected` or `identity_not_mapped`.
- Log output and responses never contain the subject token.
- Each decision writes one JSON audit line: user, `user_id`, DN, project, ref, SHA, pipeline, job, runner, status, reason.

- [ ] **Step 4: Run tests to verify they fail**

Run: `cd services && go test ./internal/sts/`
Expected: FAIL, undefined symbols.

- [ ] **Step 5: Implement**

Add an LDAP `LookupFunc` using `go-ldap` and `Config.Directory`, with no DN transform (spec 13.1). It escapes the email in the filter and returns an error unless exactly one entry matches. Test it against a stub interface only here. `main.go` verifies against the GitLab issuer, and sets a body limit of 64 KiB on `/token`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd services && go test ./internal/sts/`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add services && git commit -m "feat(sts): add token exchange with policy and identity mapping"
```

### Task 4: Gateway request handling

**Files:**
- Create: `services/internal/gateway/request.go`
- Test: `services/internal/gateway/request_test.go`

**Interfaces:**
- Consumes: `token.Verifier`, `token.Claims`.
- Produces:
  - `func ExtractToken(h http.Header) (string, error)`.
  - `func RouteAllowed(method, escapedPath string) bool`.
  - `func RewriteHeaders(h http.Header, c token.Claims)`.

- [ ] **Step 1: Write failing tests**

- `ExtractToken`: accepts `Authorization: Bearer x` and `x-api-key: x`. Same value in both is fine. Different values, neither, or a non-Bearer scheme return an error.
- `RouteAllowed`: true only for the five routes in Global Constraints with their methods. False for `/v1/batches`, `/v1/files`, `/key/generate`, `/v1/responses`, `/v1/../key`, `/v1/chat/completions/`, `/V1/models`, `/v1/%6dodels`, and `GET /v1/messages`.
- `RewriteHeaders`, starting from client headers that include `X-Proxied-Entity: cn=evil`, `Authorization`, `x-api-key`, `api-key`, `x-litellm-api-key`, `x-litellm-spend-logs-metadata: {"job_id":"evil"}`, `X-CI-Job: evil`, and `anthropic-version`:
  - `X-Proxied-Entity` equals only the token's DN.
  - All client credentials and client `x-litellm-*` and `X-CI-*` values are gone.
  - `anthropic-version` is kept.
  - `x-litellm-spend-logs-metadata` holds JSON with `project_path`, `pipeline_id`, `job_id` from the token.
  - `X-CI-Project`, `X-CI-Pipeline`, `X-CI-Job` hold the same values, per the owner's "both for now" decision.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd services && go test ./internal/gateway/`
Expected: FAIL, undefined symbols.

- [ ] **Step 3: Implement**

Match `RouteAllowed` against the exact escaped path, using an exact-match map, with no path normalizing.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd services && go test ./internal/gateway/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add services && git commit -m "feat(gateway): add token extraction, route allowlist and header rewrite"
```

### Task 5: Gateway proxy and audit

**Files:**
- Create: `services/internal/gateway/proxy.go`, `services/cmd/gateway/main.go`
- Test: `services/internal/gateway/proxy_test.go`

**Interfaces:**
- Consumes: Task 4 functions, `token.Verifier`.
- Produces: `type Config struct { UpstreamURL string; MaxBodyBytes int64; BatchServiceURL string }` and `func NewHandler(cfg Config, v *token.Verifier, transport http.RoundTripper, audit io.Writer) http.Handler`. Default `MaxBodyBytes` is 10 MiB (planner's choice, tune in pilot). `main.go` builds a transport with the gateway's mTLS client certificate from mounted files, and the internal CA.

- [ ] **Step 1: Write failing tests**

Use a fake upstream `httptest` server. Assert:
- Valid request with a Bearer token and with `x-api-key` both reach upstream, with `X-Proxied-Entity` set and the original body unchanged.
- Invalid token returns 401 and never reaches upstream.
- Blocked route returns 403, with a message that names `BatchServiceURL`, and never reaches upstream.
- Over-limit body returns 413.
- `TestStreamingUnbuffered`: upstream sends an SSE chunk then blocks. The client receives that chunk before upstream finishes.
- `TestClientDisconnectCancelsUpstream`: closing the client request cancels the upstream request context.
- `TestAuditMetadataOnly`: with a body and response containing `SECRET-PROMPT`, the audit output holds user, DN, project, ref, SHA, pipeline, job, runner, path, status, bytes, duration and the upstream's `x-litellm-call-id`, and does not contain `SECRET-PROMPT` or the token.
- `TestUpstreamErrorHidesDetails`: an upstream connection failure returns 502 with no internal address in the body.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd services && go test ./internal/gateway/`
Expected: FAIL.

- [ ] **Step 3: Implement**

Use `httputil.ReverseProxy` with `Rewrite`, `FlushInterval: -1`, `http.MaxBytesReader`, and `ModifyResponse` to capture `x-litellm-call-id`. Count bytes with wrappers, not by reading into buffers. Write audit JSON lines to stdout in `main.go`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd services && go test ./internal/gateway/`
Expected: PASS.

- [ ] **Step 5: Add an end-to-end test**

In `services/e2e_test.go`, run a fake GitLab issuer, STS, gateway and fake upstream in one process. Exchange a token, and call the gateway in both the OpenAI and Anthropic styles, streaming and non-streaming. Also assert that an STS token for another audience and a raw GitLab ID token are both rejected by the gateway.

Run: `cd services && go test ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add services && git commit -m "feat(gateway): add streaming proxy with metadata audit"
```

### Task 6: Hardened image and token script

**Files:**
- Create: `image/Dockerfile`, `image/ai-token`, `image/.gitlab-ci.yml`
- Test: `image/tests/test_ai_token.py`, `image/tests/smoke.sh`

**Interfaces:**
- Produces:
  - `ai-token`, sourced as `. ai-token`. Reads `AI_ID_TOKEN`, `AI_STS_URL`, `AI_GATEWAY_URL`. Exports `OPENAI_BASE_URL=$AI_GATEWAY_URL/v1`, `OPENAI_API_KEY`, `ANTHROPIC_BASE_URL=$AI_GATEWAY_URL`, `ANTHROPIC_API_KEY`. Unsets `AI_ID_TOKEN`.
  - Image `ai-hardened/ai-base:<semver>` with the tools in spec section 8.2.

- [ ] **Step 1: Write failing `ai-token` tests**

Use `unittest` with a local stub STS, running `sh -c '. ./ai-token && env'`. Assert:
- The four variables are set, and `AI_ID_TOKEN` is unset afterward.
- The subject token is sent in the POST body, read from stdin rather than on the command line.
- A 403 with reason `runner_not_allowed` returns non-zero and prints the reason.
- An unreachable STS returns non-zero with a clear message.
- In no case does output contain the ID token or the issued token.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest discover image/tests`
Expected: FAIL.

- [ ] **Step 3: Implement `ai-token`**

POSIX `sh`, `curl --data-urlencode subject_token@-`, `jq`. Use `return`, not `exit`, because it is sourced.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest discover image/tests`
Expected: PASS.

- [ ] **Step 5: Write `image/Dockerfile` and `image/tests/smoke.sh`**

Follow the build sketch in spec section 8.2, with base and package names from `probe/results.md`, and UID `10001`. `smoke.sh` asserts:
- `id -u` is non-zero.
- `bash`, `curl`, `jq`, `git`, `python3`, `ai-token` are present. Task 7 adds `ai-review` to this list.
- No `apt`, `dnf`, `apk`, `pip`, `gcc`, `ssh`, `nc`, `wget`, `sudo`, `docker`, `kubectl`.
- `find / -xdev -perm /6000 -type f` is empty.
- No files with key or token names under `/etc` or `/home`.

- [ ] **Step 6: Write `image/.gitlab-ci.yml`**

On protected branches only: build, run `smoke.sh`, generate SBOM, run the approved vulnerability scan with release blocked on the agreed threshold, sign if tooling exists, and push an immutable semantic version tag. Also mirror the runner helper image to `ai-hardened/`.

- [ ] **Step 7: Run the image pipeline**

Expected: pipeline passes, and the versioned image and helper image are in the registry.

- [ ] **Step 8: Commit**

```bash
git add image && git commit -m "feat(image): add hardened AI base image and token script"
```

### Task 7: `ai-review` tool

**Files:**
- Create: `image/ai_review.py` (installed as `/usr/local/bin/ai-review`)
- Modify: `image/Dockerfile` (add the `COPY`), `image/tests/smoke.sh` (assert `ai-review` is present)
- Test: `image/tests/test_ai_review.py`

**Interfaces:**
- Consumes: `OPENAI_BASE_URL`, `OPENAI_API_KEY`, `AI_REVIEW_MODEL`, `CI_MERGE_REQUEST_DIFF_BASE_SHA`.
- Produces: CLI `ai-review --diff-only --format codequality`, writing a code quality JSON array to stdout. Each item has `description`, `check_name: ai-review`, `fingerprint`, `severity`, and `location.path`, `location.lines.begin`. Allowed severities: `info`, `minor`, `major`, `critical`, `blocker`.

Python standard library only. Calls `POST /v1/chat/completions`.

- [ ] **Step 1: Write failing tests**

Use a temp git repo and a stub API server.
- Valid response becomes valid code quality JSON.
- `TestEmptyDiff`: writes `[]`, and makes no API call.
- `TestOversizedDiff`: over 200 KiB (planner's choice) writes one `info` finding saying the diff is too large, and makes no API call.
- `TestMalformedModelOutput`: non-JSON output exits non-zero, with no model text in stdout or stderr.
- `TestFindingOutsideDiffDropped`: paths not in the diff are dropped.
- `TestInvalidFieldsDropped`: bad severity or a non-positive line is dropped.
- `TestFingerprintStable`: same finding on two runs gives the same fingerprint.
- `TestDiffNotPrinted`: diff content and API key never appear in stderr, including on HTTP 500.
- `TestSecretPreCheck`: a diff containing a PEM private key header or `glpat-` token makes no API call, and writes one `info` finding that names the file but not the match. This is the spec's optional accident check, and `AI_REVIEW_SKIP_SECRET_CHECK=true` turns it off.
- `TestDiffIsDelimitedAsData`: the system prompt says MR content is untrusted data, and the diff is sent in a separate user message within delimiters.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest discover image/tests`
Expected: FAIL.

- [ ] **Step 3: Implement**

Get the diff using `git diff $CI_MERGE_REQUEST_DIFF_BASE_SHA...HEAD`. Build the fingerprint as a SHA-256 of path, description and line. Holds no write credential and makes no GitLab API calls.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest discover image/tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add image && git commit -m "feat(review): add code quality review tool"
```

### Task 8: CI templates

**Files:**
- Create: `templates/ai-access.yml`, `templates/ai-code-review.yml`
- Test: `templates/tests/test_templates.py`

**Interfaces:**
- Consumes: `ai-token`, `ai-review`.
- Produces: hidden job `.ai-access`, and job `ai-review`. Users include from the template project using a version tag. Use `include:project`, unless Phase 0 shows components are preferable.

- [ ] **Step 1: Write failing tests**

Parse the YAML with PyYAML, as a test-only dependency on the developer's machine. The pilot also validates with GitLab's CI Lint API. Assert:
- `.ai-access` has `tags: [ai]`, a pinned non-`latest` image from `ai-hardened/`, `id_tokens.AI_ID_TOKEN.aud` set to the STS audience, and `before_script` running `. ai-token`.
- `ai-review` has `interruptible: true`, `allow_failure: true`, `GIT_DEPTH: "0"`, and `artifacts.reports.codequality: review.json`.
- The first rule skips when `$CI_MERGE_REQUEST_SOURCE_PROJECT_ID != $CI_MERGE_REQUEST_PROJECT_ID`, and the second runs on `merge_request_event`.
- No template contains a credential or sets `CI_DEBUG_TRACE`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest discover templates/tests`
Expected: FAIL.

- [ ] **Step 3: Implement both templates**

Comment each with how to switch to manual, and that docs for bulk work point to the batch service.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest discover templates/tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add templates && git commit -m "feat(templates): add AI access and code review templates"
```

### Task 9: Deployment and runner configuration

**Files:**
- Create: `deploy/runner/config.toml.example`, `deploy/runner/networkpolicy.yaml`, `deploy/runner/namespace.yaml`, `deploy/services/sts.yaml`, `deploy/services/gateway.yaml`, `services/Dockerfile`

**Interfaces:**
- Consumes: images from Tasks 3, 5 and 6.
- Produces: pilot deployment.

- [ ] **Step 1: Write `config.toml.example`**

Using values from spec section 8: `allowed_images` and `allowed_services` for `registry.example.internal/ai-hardened/*`, `allowed_pull_policies = ["always"]`, `helper_image` from the mirror, `privileged = false`, `allow_privilege_escalation = false`, `automount_service_account_token = false`, `run_as_non_root` and `allowed_users`, `limit` and `concurrent` set low for the pilot. No shared cache.

- [ ] **Step 2: Write `networkpolicy.yaml`**

Deny all ingress and egress by default for job pods. Allow egress only to GitLab, registry, STS, gateway and DNS.

- [ ] **Step 3: Write service manifests**

One replica each for the pilot, separate deployments, separate secrets and service accounts. Non-root, read-only root filesystem, resource limits, and core dumps disabled. Keys come from mounted secrets, or HSM or Vault if available.

- [ ] **Step 4: Validate**

Run: `kubectl apply --dry-run=server -f deploy/runner/ -f deploy/services/`
Expected: no errors.

- [ ] **Step 5: Deploy, then create a group runner**

In a group you own, create the runner with tag `ai`, Run untagged off and maximum timeout 1800. Add its ID to the STS config, register it, and roll out STS.

- [ ] **Step 6: Commit**

```bash
git add deploy services/Dockerfile && git commit -m "feat(deploy): add pilot runner and service manifests"
```

### Task 10: Pilot acceptance and docs

**Files:**
- Create: `tests/pilot/.gitlab-ci.yml`, `tests/pilot/README.md`, `docs/user-guide.md`, `docs/operator-runbook.md`, `docs/admin-request.md`, `docs/accreditor-package.md`, `docs/pilot-results.md`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Write the pilot test project**

Jobs in `tests/pilot/.gitlab-ci.yml`, run in a non-sensitive test project:
- Set `PROBE_BLOCKED` and run the probe on the `ai` runner.
- Non-allowlisted image: job must be refused.
- Job requesting root: refused or runs without it.
- `CI_DEBUG_TRACE` set, then search the log for token material. Try forcing it off with runner `environment`.
- Spoofed `X-Proxied-Entity` and spoofed `user` and `metadata` body fields: attribution and limits are unchanged in provider records.
- `/v1/batches`, a LiteLLM admin route, and oversized requests: all rejected.
- Scheduled pipeline on an unprotected ref: no token.
- Job on an unlisted runner: no token.
- OpenAI and Anthropic-style calls, streaming and non-streaming, attributed to the right user.

- [ ] **Step 2: Run every item in spec section 14 and record each in `docs/pilot-results.md`**

Expected: all pass. Any failure blocks Phase 2 until fixed.

- [ ] **Step 3: Run review on a test MR**

Expected: findings appear on the MR with no write credential present. Record whether diff annotations appear on your tier. If not, use the report artifact, per spec section 13.

- [ ] **Step 4: Measure and record**

Record review latency, LLM load, false failures, and whether both CI context methods appear in provider records. Drop the one not needed, and record the join result for `x-litellm-call-id`.

- [ ] **Step 5: Write the docs**

- `user-guide.md`: one-include setup, custom jobs, schedules on protected branches, error reason codes, and when to use the batch service. States that users can't choose another identity, and what not to log.
- `operator-runbook.md`: key and certificate rotation, runner list changes with old and new IDs together, image release and retirement, cutover, incident response, and limits of metadata-only audit.
- `admin-request.md`: the three-step instance runner request from spec section 8, ready to send.
- `accreditor-package.md`: limits from spec section 3 and the sign-off list from section 12, in plain language, with pilot evidence. States clearly that this is attribution, not non-repudiation.

- [ ] **Step 6: Commit**

```bash
git add tests docs && git commit -m "docs: add pilot acceptance results and operating guides"
```

- [ ] **Step 7: Hand off**

Report results, sizing data for about 100 simultaneous jobs, and open items. Phase 2 needs written accreditor sign-off and its own plan.
