# Peer technical brief: GitLab runner AI access

**For:** engineers reviewing the design.
**Status, 2026-11-06:** Design approved. Initial code written and tested locally, with mapping and fork rules set. Baseline probe passed. Nothing is deployed: the remaining probe tests and working assumptions must be confirmed first.
**Sources:** [design](../superpowers/specs/2026-11-05-gitlab-runner-ai-access-design.md), [plan](../superpowers/plans/2026-11-05-gitlab-runner-ai-access.md), [probe](../../probe/README.md), [deployment](../../deploy/README.md), [runbook](../operator-runbook.md).
**Code:** `services/` (STS, gateway), `image/` (`ai-token`, `ai-review`), `templates/`, `deploy/`, `tests/pilot/`.

## Design in brief

A job swaps its GitLab ID token at STS for a short-lived token. A pass-through gateway verifies that token, then calls the LLM API gateway with its own mTLS certificate and `X-Proxied-Entity: <DN>`. The provider applies that user's permissions.

![Reference architecture](diagrams/png/02-reference-architecture.png)

![Token exchange sequence](diagrams/png/03-token-exchange-sequence.png)

## Controls

Hard controls sit outside the job. Templates are convenience, and users may write their own jobs under options 1 and 2.

```text
Not on an AI runner  → STS refuses a token (signed runner_id)
Image not allowed    → runner refuses the job (allowed_images)
On an allowed image  → NetworkPolicy limits connections
```

![STS and gateway controls](diagrams/png/08-sts-and-gateway-controls.png)

![Runner and image hardening](diagrams/png/07-runner-and-image-hardening.png)

## Key values

| Item | Value |
|---|---|
| **STS token** | `aud` is the gateway only, 30 minutes at most, never past the ID token's `exp` |
| **Runner** | Tag `ai`, Run untagged off, maximum timeout 1800 s |
| **Allowed routes** | `POST /v1/chat/completions`, `/v1/messages`, `/v1/messages/count_tokens`, `/v1/embeddings`. `GET /v1/models` |
| **Token headers accepted** | `Authorization: Bearer` or `x-api-key` |
| **Client headers forwarded** | Allowlist only: `Content-Type`, `Accept`, `Accept-Encoding`, `User-Agent`, `Idempotency-Key`, `anthropic-*`, `openai-*`, `x-stainless-*`. Everything else is dropped |
| **Protected ref rule** | Required unless `pipeline_source` is `push`, `web` or `merge_request_event`. Stops a schedule or trigger running code from an unprotected branch as its owner |
| **Fork rule** | `job_project_path` must equal `project_path`, so fork code in a parent pipeline gets no token |
| **Transport** | STS and gateway serve TLS only. Ingress verifies them. JWKS URLs must be https, and clients refuse redirects |
| **Key cache** | Refresh after 10 minutes, keep through outages, fail closed after 24 hours. Restart to clear in an emergency |
| **Mapping** | Directory lookup by `user_email`, using the directory's DN. Anything but exactly one match means deny. `user_id` goes in the audit log |
| **v1 output** | Code quality artifact. No write credential in the job |

**Why a code quality artifact:** `CI_JOB_TOKEN` can't post MR notes, protected variables don't reach normal MR pipelines, and the MR author can read unprotected ones. So v1 uses a native report that needs no write credential.

## Implementation choices open to challenge

- **Go with `golang-jwt` for STS and gateway:** chosen for its streaming proxy and single static binary. An existing reverse proxy is also allowed by the design. Needs a Go toolchain and module mirror on our network.
- **10 MiB request cap and 200 KiB review diff limit:** to tune in the pilot.
- **Route allowlist:** blocks `/v1/responses` because its stored state may conflict with the no-capture rule.
- **`allow_failure: true` on review:** an AI outage must not block merges.
- **Protected ref rule:** tightens the design's schedule-only rule, so API and child pipelines on unprotected branches can't use AI.
- **Header allowlist:** safer than a denylist, but a new SDK header stays dropped until added.
- **`dpkg` kept in the image:** SBOM and scanners need it. This deviates from "remove the package manager".

## Known limits

- Poisoned code runs as whoever triggers it, for up to the token lifetime.
- Retrying someone else's commit runs their code under your identity. Logs record the SHA so an audit can separate the two.
- The gateway certificate and STS signing key can each claim to be any user.
- GitLab admins are in the trust boundary. Admin-side runner changes aren't monitored in v1.
- Mapping depends on GitLab's email lock. An admin who changes a user's email redirects their attribution. `user_id` in the audit log makes that detectable.
- No content inspection. Injection defense relies on limiting what a job can do.
- Audit is metadata only. Nobody can later show what was sent, by design.
- Hardening the image is not a boundary, since a job can still run what is in its checkout.

## Still to prove

| Assumption | How it gets tested |
|---|---|
| Token has `user_email` and `user_id`, audience and lifetime are right, OIDC checks pass | **Confirmed** by the baseline probe |
| Token has `job_project_path` | Updated probe |
| Directory returns one entry per email, and its DN matches the certificate (**the deployment gate**) | Phase 0 directory test |
| `user_login` matches expectations for push, MR, retry, manual, schedule, trigger token and bot | Phase 0 trigger test |
| `exp` tracks job timeout | Phase 0 probe |
| Runners reach the enclave; STS reaches JWKS and the directory | Phase 0 network test |
| `X-Proxied-Entity` format is a DN | Pilot gateway test |
| OpenAI and Anthropic clients work with the STS token as API key, including streaming | Pilot gateway test |
| Code quality widget is available on our tier | Test MR |
| Tokens and prompts stay out of logs with `CI_DEBUG_TRACE` on | Pilot test |
| Option 3: ID token names the triggering user | Test before building option 3 |

## What we want from reviewers

1. Ways to get a token for another user, or to reach the provider without going through STS.
2. Claims or assumptions that may not hold on our GitLab version.
3. Gaps in the acceptance tests (design section 14).
4. Whether an existing reverse proxy would be better than building the gateway.
