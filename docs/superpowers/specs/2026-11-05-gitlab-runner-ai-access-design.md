# GitLab Runner AI Access: Design

**Date:** 2026-11-05
**Status:** Approved by owner, 2026-11-06. Build proceeds on the working assumptions in section 13.1, also by owner's decision.

Decisions are the owner's unless marked **(designer's call)**. Those are open to override.

## 1. Intent

The network is air-gapped and the AI provider's API requires each user's mTLS certificate. Users want AI in GitLab CI jobs, but mounting personal `.p12` files on runners exposes those keys.

This design lets a CI job use AI under the identity of the person behind the pipeline, with no user certificate or password stored anywhere. It must be easy for average users: they add a CI template and do not handle certificates.

**Primary v1 use case:** automated AI code review as static feedback on merge requests.
**Secondary use case:** small general AI work (summarize, small embeddings) and scheduled automation, for users who have nowhere else to run cron.

## 2. Goals, non-goals, anti-goals

**Goals**
- No user private keys or passwords on runners or in any new service.
- Every AI call is attributed to a real user, project, commit, pipeline and job.
- Provider permissions, model access and rate limits apply per user, as they do today.
- One CI `include` is enough for a typical user.
- Lowest blast radius in v1: AI jobs produce reports and change nothing.
- Handles continuous demand through stateless, horizontally scaled services. Initial production target: about 100 simultaneous AI jobs at peak.

**Non-goals for v1**
- Agents that push branches or open MRs (Phase 4).
- MR comments posted through a write-capable service (Phase 3).
- Non-GitLab identity sources. STS supports them later through its issuer list, but only GitLab ships.
- Bulk workloads. A separate batch service exists for these.
- Service or shared identities. Every token maps to a real person.

**Anti-goals: failure even if it technically works**
- Calling this cryptographic non-repudiation. It provides attribution (see section 3).
- Storing prompts or responses in any new component, including debug logs.
- Accepting a user identity from a CI variable, job input or any unsigned source.
- Escrowing user keys. A service holding every key could have made any signature.
- Treating templates as a security boundary.

## 3. Security properties and accepted limits

**Attribution, not non-repudiation.** GitLab vouches for the user. The user's private key signs nothing. This must be stated plainly to the accreditor.

Known limits, all to be covered by sign-off (section 12):
- **Identity follows who triggered the job, not who wrote the code.** If Bob retries Alice's commit, Bob's identity runs Alice's code. Logs record the SHA so an audit can separate the two.
- **Poisoned code runs as the victim.** A malicious commit or dependency can use the identity of whoever triggers it, for up to the token lifetime.
- **GitLab admins are in the trust boundary and are outside the owner's team.** They can likely act as other users and change GitLab-side runner settings.
- **The gateway certificate can claim to be any user.** Same for the STS signing key.
- **Identity mapping depends on GitLab's email lock.** Users can't change their email, but a GitLab admin can, which would redirect that user's attribution. The audit log records the unchanging `user_id`, so such a change can be detected afterward.
- **Further trust depends on the access option.** Group Owners under option 2, central project Maintainers under option 3 (section 8.1).
- **No content controls exist.** Neither this gateway nor the LLM API gateway screens prompts. Injection defense relies entirely on limiting what a job can do.
- **Audit shows who, when and where, not what.** After an incident, nobody can show what was sent, by design.

**Data handling:** AI use is capped at GitLab's classification level. The owner states that engineers and admins with node access have incidental exposure protection, so node-level admin access is not a concern in this design.

## 4. Architecture

```
Job on AI runner
  ├─ GitLab ID token (aud = STS) ─> STS
  │     verify signature/iss/aud/exp, apply policy, map user to DN
  │     <─ short-lived STS token (aud = gateway)
  └─ STS token ─> AI gateway ── gateway mTLS + X-Proxied-Entity: <DN> ─> LLM API gateway
```

| Component | Owner | Location |
|---|---|---|
| STS | Platform team (HA, k8s) | Provider enclave |
| AI gateway | Platform team (HA, k8s) | Provider enclave, explicitly trusted by provider |
| AI runners | Owner's team (own k8s) | Isolated namespace and nodes |
| Hardened images, CI templates | Owner's team | Internal registry and GitLab project |
| LLM API gateway | Existing provider | Enforces permissions, model access and rate limits by user |

STS and gateway are separate deployments with separate keys. The gateway handles large volumes of untrusted traffic, and a bug there must not expose the key that future services would trust.

### Trust relationships

GitLab trust is one relationship: an allowlisted issuer URL, its signing keys (JWKS), and the internal CA used to fetch them. GitLab's TLS certificate does **not** authenticate jobs, because jobs connect from runners. The signed ID token is the proof of identity. Trust the CA rather than pinning GitLab's leaf certificate, so rotation does not cause an outage.

## 5. STS

**Interface:** RFC 8693-style token exchange. Input is the GitLab ID token; output is a signed JWT.

**Validation, all required, failing closed:**
1. Signature valid against JWKS for an allowlisted issuer.
2. `aud` is exactly the STS audience. `exp` and `nbf` valid.
3. `runner_id` is in the configured AI runner list.
4. If `pipeline_source` is `schedule`, then `ref_protected` must be true.
5. User maps to a real directory entry.

**Identity mapping:** users sign in to GitLab through the same directory as their certificates. STS looks up the signed `user_email` in the directory and uses the DN the directory returns. Exactly one entry must match. No match or several means deny, with no fallback identity. STS doesn't use `user_identities`, because that claim needs an opt-in preference from each user (owner's decision, 2026-11-06). Bot users (project and group access tokens) therefore fail to map and are denied.

**Issued token:**
- `aud`: the gateway only.
- Lifetime: at most 30 minutes, and never beyond the ID token's `exp`.
- Claims: DN, `user_login`, `project_path`, `ref`, `sha`, `pipeline_id`, `job_id`, `runner_id`.

**Runner list** is config, not code, and rolls out without downtime. List old and new runner IDs together during cutover, then remove the old ones **(designer's call)**.

**Issuer config** is a list, so later issuers need config rather than code. Each new issuer needs its own security review, because it can vouch for users.

**Keys:** publish STS public keys for the gateway; support rotation. Use an HSM or Vault if available.

## 6. AI gateway

**Behavior:**
- Verify STS token (signature, issuer, `aud`, `exp`).
- Accept the STS token from either `Authorization: Bearer` (OpenAI clients) or `x-api-key` (Anthropic clients).
- **Delete any incoming `X-Proxied-Entity`**, then set it from the token's DN.
- Delete `Authorization`, `x-api-key`, `api-key` and all `x-litellm-*` headers from the client, so the STS token never goes upstream and clients can't set LiteLLM options.
- Call the LLM API gateway using the gateway's own mTLS certificate. The provider must honor `X-Proxied-Entity` only from this certificate.
- Stream requests and responses without buffering.
- Log the `x-litellm-call-id` response header. It is available without reading bodies, including on streams.
- Send project, pipeline and job IDs upstream, so provider records carry CI context. Send both `x-litellm-spend-logs-metadata` and plain HTTP headers for now, as the owner decided. Header names are left to the builder. The gateway always sets these values and removes any supplied by the client.

**Pass-through only:** no body parsing, no body logging, and no body in debug logs or core dumps. Disable core dumps.

**Usage shaping, no content inspection:**
- Deny all API paths by default. Allow only `/v1/chat/completions`, `/v1/messages`, `/v1/messages/count_tokens`, `/v1/embeddings` and `/v1/models` **(designer's call)**.
- This blocks bulk routes (`/v1/batches`, `/v1/files`), LiteLLM admin and key routes (`/key`, `/user`, `/team`, `/model`, `/spend`, `/config`), pass-through routes, and `/v1/responses`, whose stored state may conflict with the no-capture rule. Add a route only after review.
- Cap request size.
- Rejection messages point users to the batch service.

**Certificate:** store in an HSM or Vault if possible. Plan rotation.

### 6.1 LiteLLM integration

The provider serves OpenAI-style and Anthropic-style APIs through LiteLLM. Most existing tools need only a base URL and API key, so no custom client is needed.

**Provider facts, as stated by the owner:**
- The provider does not log prompts or responses.
- A separate auth service in front of LiteLLM handles authentication. It is trusted and assumed to work, so this design doesn't specify or test its internals.
- The provider will accept CI metadata.

**Confirmed with the provider, as stated by the owner:**
- The gateway certificate will be trusted, and `X-Proxied-Entity` honored from it.
- Client-controlled body fields such as `user` and `metadata` will not change identity.
- Client-supplied credentials and API base are not used.
- CI context is sent both as metadata and as plain HTTP headers for now.

LiteLLM also offers optional secret detection and PII guardrails. They aren't used in v1, but if the accreditor later wants content screening, the provider could enable it without adding content handling to this gateway.

## 7. Audit

STS and gateway emit metadata to the SIEM: user, DN, project, ref, SHA, pipeline, job, runner, path, status, bytes, duration, request ID. No prompts or responses. STS also records the token's `user_id`. Retention follows existing policy.

**Designer's call:** the owner approved logging model and token usage, but a pass-through gateway cannot read them without parsing bodies. Join them from provider records using `x-litellm-call-id` instead, along with the CI context set by the gateway. If the provider cannot supply those records, fall back to request count and bytes.

Alert on unusually high usage per job, and handle it by contacting the user.

## 8. AI runners

**Scope:** the pilot uses a group runner. Production uses one or more of the options in section 8.1. For an instance runner, request once from a GitLab admin:
1. Create an instance runner with tag `ai` and **Run untagged** off.
2. Set maximum job timeout to 1800 seconds.
3. Hand over the runner authentication token securely.

This is an external dependency on a team outside the owner's control, so the plan should request it early. Admin-side changes are not monitored in v1 and are covered by sign-off **(designer's call)**.

The owner's team keeps `config.toml` and the k8s configuration. Runner IDs change at cutover, so update the STS list then.

**Single pool:** tag `ai` only. Bulk work belongs on the batch service.

**Hard controls:**
- `allowed_images` and `allowed_services` restricted to `registry.example.internal/ai-hardened/*`, with `allowed_pull_policies = ["always"]`.
- `privileged = false`, `allow_privilege_escalation = false`, `automount_service_account_token = false`, non-root.
- Ephemeral pods, CPU and memory limits, dedicated namespace and nodes, separate from STS and gateway.
- `NetworkPolicy` deny by default, allowing only GitLab, the registry, STS, gateway and DNS.
- `limit` and `concurrent` set from pilot load data.
- No cache shared between projects **(designer's call)**.

**Registry:** immutable tags and restricted push rights on `ai-hardened/`.

**Protect** the runner authentication token, since holding it allows picking up users' jobs and their ID tokens. Review `config.toml` changes as security policy changes.

**Instance runner exposure:** any GitLab user can run code on this cluster, whether or not they have AI entitlement. The controls above must be in place before the runner opens up.

### 8.1 Access options

All three options are supported. STS, the gateway and the LLM API gateway are the same in each. The options differ in how a job reaches your runner and who controls what that job runs.

- **Option 1, instance runner:** a tag-only runner available to all projects. A GitLab admin creates it.
- **Option 2, group runners:** one runner per top-level group, all on the same cluster and config. A group Owner creates each one.
- **Option 3, central template pipeline:** a template in the user's project triggers a pipeline in a central project you own, running on a protected group runner in your group. Only that central YAML gets an AI token.

| Trade-off | 1. Instance runner | 2. Group runners | 3. Central template pipeline |
|---|---|---|---|
| **Reach** | All projects, unless turned off for a project or group | Only onboarded groups. Personal namespaces are excluded | Users with pipeline rights on the central project |
| **Outside help needed** | One GitLab admin action | Each group Owner, once | None for the runner. Membership and job-token access need setup |
| **User setup** | One template | One template, after group onboarding | One template, plus access grant |
| **Rollout speed** | All at once, on the admin's schedule | Gradual, group by group | Fast for the first users, grows with membership management |
| **Ongoing operations** | Lowest: one runner ID | One runner ID per group. Can be scripted, but Owners must act | One runner, plus access and central pipeline upkeep |
| **Who controls job YAML** | Each user | Each user | **You** |
| **Users can write custom AI jobs** | Yes | Yes | **No**, only inputs you accept |
| **Protection from a poisoned commit in the user's project** | Weak: its jobs can request a token | Weak: its jobs can request a token | **Stronger**: that code doesn't run with an AI token, unless the job checks it out and runs it. Its text still reaches the model |
| **Injection blast radius** | Job's permissions | Job's permissions | Central job's permissions, which you set |
| **Identity** | Signed user claim. Tested in Phase 0 | Same as option 1 | **Unverified:** docs confirm the trigger needs rights downstream, not that the ID token names that user. Must be tested |
| **Trust added beyond GitLab admins** | None | **Each group Owner** can edit or pause their runner | Central project Maintainers can change what all users run |
| **Rogue runner risk** | STS rejects unlisted IDs | STS rejects unlisted IDs | STS rejects unlisted IDs, and can also require the central `ci_config_ref_uri` |
| **Who can reach your cluster** | **Any GitLab user** | Members of onboarded groups | Protected runner runs only protected-branch code, so users can't run arbitrary jobs |
| **Data location** | Each source project | Each source project | **Concentrated** in the central project unless handled carefully |
| **Need-to-know** | Follows existing project access | Follows existing project access | **Risk:** members may see each other's logs and reports |
| **MR display** | Native code quality report | Native code quality report | **Likely not on the source MR**, so review is weaker. Test before relying on it |
| **Source code access** | Job's own checkout | Job's own checkout | Needs job-token allowlist on each source project, or equivalent. Test |
| **Inputs** | Not applicable | Not applicable | Trigger variables are user-controlled and untrusted. Role limits on pipeline variables may apply |
| **Scheduled automation** | Protected-branch rule in section 5 | Same as option 1 | Runs central code on a protected ref, so that rule doesn't protect the source project. Limit to central tasks and test |
| **Flexibility for general AI use** | **Highest** | **High** | **Lowest**: each new task needs central support |

**Recommended order (designer's call):**
1. Pilot on option 2 in a group you own.
2. Request option 1 for production, since it best fits "any user".
3. If refused, roll out option 2.
4. Use option 3 where users must not control job YAML, such as a high-risk project, or if option 2 stalls.

Options can run together. STS needs per-runner policy for this, so option 3's runner IDs can also require the central `ci_config_ref_uri`. Build option 3 only when one of those cases arises **(designer's call)**.

**Rejected:**
- **Project runners:** enabling one needs Maintainer on both projects, and anyone who can edit it from an enabled project changes tags and description for all.
- **Existing shared runners:** they remove your image, network and isolation controls.

### 8.2 Hardened image plan

One image, `ai-hardened/ai-base`, used by all access options. It holds only what the review tool, token exchange and small AI scripts need. **Hardening reduces convenience and attack surface, but it isn't a security boundary:** a job can still run what is in its checkout. NetworkPolicy and the pod settings in section 8 are the hard controls. Contents and tools below are **designer's calls**.

**Included**

| Tool | Why |
|---|---|
| `bash`, coreutils | Run CI job scripts |
| `ca-certificates` with internal CA | Trust STS, gateway and GitLab |
| `curl` | Token exchange and direct API calls |
| `jq` | Read tokens and build or parse JSON in scripts |
| `git` | Produce the MR diff |
| `python3`, standard library only | Run `ai-review` and small user scripts, such as summarize or small embeddings |
| `ai-review` | Code review tool (section 10) |
| `ai-token` | Small exchange script used by `.ai-access` |

**Excluded**
- Package managers at runtime (`apt`, `dnf`, `apk`, `pip`), since jobs have no route to install from anyway.
- Compilers, language toolchains and build tools. Review reads diffs and doesn't build code.
- `ssh`, `scp`, `nc`, `wget`, `sudo`, `docker`, `kubectl`.
- Setuid and setgid binaries.
- AI SDKs. The provider's OpenAI and Anthropic-style APIs work over plain HTTP. Users who want an SDK use a reviewed derived image.
- Secrets, tokens and environment-specific URLs. The template supplies URLs.

**Runtime settings**
- Fixed non-root UID, with a writable `HOME` and `/builds` on `emptyDir`.
- Try a read-only root filesystem on all build pod containers in the pilot, using `read_only_root_filesystem` in the runner's security contexts. Keep it if jobs and `git` still work.
- Set `allowed_users` and `run_as_non_root` on the runner so jobs can't request root.
- Mirror the runner **helper image** to the internal registry and set `helper_image`. It handles clone and artifact steps, and `allowed_images` doesn't govern it. Treat it as part of this image's supply chain.

**Build sketch (illustrative; base and package names depend on the approved distro)**
```dockerfile
FROM registry.example.internal/approved/minimal-base@sha256:<digest>
COPY internal-ca.crt /usr/local/share/ca-certificates/
RUN <install bash curl jq git python3 ca-certificates from internal mirror> \
 && update-ca-certificates \
 && <remove package manager and caches> \
 && find / -xdev -perm /6000 -type f -exec chmod a-s {} +
COPY ai-review ai-token /usr/local/bin/
USER 10001:10001
```

**Build and release**
1. Build from a protected branch of an image project owned by your team, with a pinned base digest and packages from the internal mirror.
2. Generate an SBOM and run a vulnerability scan, using approved tools available on the network. Failing the agreed severity threshold blocks release.
3. Sign the image if signing tooling exists on the network. Verifying signatures at admission is a later addition.
4. Push to `ai-hardened/ai-base` with an immutable semantic version tag. Only this pipeline can push.
5. Templates pin a version, so an image upgrade ships as a template release.

**Maintenance**
- Rebuild monthly and for critical CVEs.
- Remove old versions after a published window, so unpatched images can't keep running. Removal breaks jobs pinned to them, so announce it first.
- Pre-pull on runner nodes to reduce job start time. `always` pull policy still checks for the current image.

**Requests for more tools:** add to `ai-base` only if most users need it. Otherwise, a reviewed derived image under `ai-hardened/` goes through the same pipeline. Users can't push their own, because `allowed_images` and registry rights block it.

**Git diffs:** default shallow clones may lack the MR target branch. `ai-review` or the template must fetch what it needs and work with the runner's checkout ownership. Test this in the pilot.

## 9. Enforcement model

Hard controls sit outside the job:
```
Not on an AI runner  → STS refuses a token (signed runner_id)
Image not allowed    → runner refuses the job (allowed_images)
On an allowed image  → NetworkPolicy limits connections
```

Templates are convenience and safe defaults. Under options 1 and 2 (section 8.1), users may write their own AI jobs on these runners and stay inside the hard controls. Under option 3, the central pipeline is enforced by STS and the protected runner. Pipeline execution policies are optional: the owner believes the tier is Ultimate (confirm in Phase 0), but they also need group ownership, and the owner does not administer GitLab. Nothing in v1 depends on them. For high-risk projects, STS can additionally require an approved `ci_config_ref_uri`; not built in v1.

## 10. CI templates

Published from a semantically versioned project that all users can read. Use components or `include` according to the GitLab version found in Phase 0 **(designer's call)**.

These templates apply to options 1 and 2. Option 3 instead uses a small trigger template and central pipeline, specified when that option is built.

**`.ai-access` (base):** sets `tags: [ai]` and the hardened image, requests an ID token with the STS audience, exchanges it, and sets `OPENAI_BASE_URL`, `OPENAI_API_KEY`, `ANTHROPIC_BASE_URL` and `ANTHROPIC_API_KEY`, using the STS token as the key. OpenAI clients expect the base URL to include `/v1`, and Anthropic clients expect it without. On failure, prints a clear error without printing tokens. Prompts and responses are not printed, and artifact expiry is short by default.

**Optional secret pre-check:** catches accidents and is not a defense against attackers.

**`ai-code-review` (v1):**
```yaml
ai-review:
  extends: .ai-access
  interruptible: true
  allow_failure: true    # designer's call: AI outage must not block merges
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - ai-review --diff-only --format codequality > review.json
  artifacts:
    reports:
      codequality: review.json
```
Runs automatically once included. Projects can switch to manual.

**Fork MRs (designer's call):** the template skips pipelines that run fork code in the parent project, because that code would run under the identity of the Maintainer who started it. No STS role check in v1. Because users can write their own jobs, this is a default rather than a hard control, and it falls under the "poisoned code runs as the victim" limit in section 3.

**The `ai-review` tool** ships in the hardened image and is built by this project. It uses the Python standard library to call `/v1/chat/completions` **(designer's call)**, with the model set by a template input. It sends only the MR diff, treats MR content as data rather than instructions, and validates model output against the code quality schema before writing it. It holds no write credential.

Add further templates only when the pilot shows demand. Do not create one template per use case.

### Why code quality artifacts

`CI_JOB_TOKEN` cannot post MR notes. Protected variables do not reach MR pipelines from normal branches. Unprotected variables can be read by the MR author, who controls the branch's CI YAML. So v1 uses a native report that needs no write credential. It gives short line-level findings, not threaded comments.

## 11. Automation and bulk work

**Scheduled automation:** use native GitLab pipeline schedules, with no custom scheduler. Schedules run as their owner, go inactive if the owner is blocked or removed, and move attribution when a Maintainer takes ownership. They must run on protected branches (section 5).

**Discouraging bulk use:** 30-minute job limit, gateway path and size limits, existing per-user rate limits, docs and error messages pointing to the batch service, and usage alerts. These discourage bulk work and do not fully prevent it.

## 12. Rollout and gates

**Phase 0: Validate.** Resolve every item in section 13, including the approved base image and internal package mirror. The provider's trust in the gateway is confirmed by the owner. **Gate:** nothing is deployed until identity mapping is confirmed. The owner chose to build on the working assumptions in section 13.1 before then, so a false assumption means rework, not exposure.

**Phase 1: Pilot.** A very small proof of concept, using **non-sensitive test projects only** until accreditor sign-off. Group runner in a group the owner controls, STS, gateway, `.ai-access`, and `ai-code-review`. Use test code resembling real projects. Prove the controls with the section 14 tests, and measure review latency, LLM load and false failures. HA and autoscaling are not required at this stage **(designer's call)**, but no security control is relaxed.

**Phase 2: Production.** Roll out using the order in section 8.1, with HA STS and gateway, sized for about 100 simultaneous jobs and adjusted from pilot data.
**Gate: written accreditor sign-off**, currently pending, covering:
- attribution rather than non-repudiation;
- GitLab admins in the trust boundary, including identity mapping's dependence on the email lock;
- shared runner nodes and need-to-know;
- extra trust for the chosen access option (group Owners, central project Maintainers, or concentrated data);
- no content inspection and metadata-only audit.

If refused, high-risk projects need signed delegation: users sign a time-limited grant with their own certificate, which STS requires. This adds certificate handling for those users, so it is not built unless required. It would be an extra STS check, not a redesign **(designer's call)**.

**Phase 3: MR comments.** Small service holding the write token. Accepts only STS tokens, and posts only to the project and MR named in the token. Build if users need more than code quality findings.

**Phase 4: Agent fixes.** Requires GitLab 18.4+. Opt-in per project, manually triggered, limited to new `ai/*` branches targeting the MR's branch. Job-token pushes trigger no pipeline, which prevents loops. Before starting:
- STS denies tokens when the `ref` claim matches `ai/*`.
- Turn on prevent-approval settings for MR creators and committers.
- Accept that job-token push covers every job in the project, so job separation becomes weaker there.
- Treat `review.json` as untrusted input.
- Reviewers read the diff, especially CI files, before running a pipeline on an agent branch.

## 13. Assumptions to test in Phase 0

| Assumption | Test | If false |
|---|---|---|
| GitLab version supports `id_tokens`; version recorded | Test job printing token claims and `CI_SERVER_VERSION` | Redesign identity source |
| Token contains `user_email` and `user_id` | Inspect claims. Confirmed by the baseline probe | Agree a mapping source |
| Directory lookup by email returns one entry, and its DN matches the user's certificate | Compare for several users | Transform the DN, or agree another mapping source |
| Regular users can't change their GitLab email | Try with a regular test account | Agree another mapping source |
| `exp` tracks job timeout | Inspect `iat`, `exp` | Reassess token lifetime |
| Trigger table holds: push, MR, manual, retry, schedule, trigger token | Run each and record `user_login` | Update attribution docs |
| `X-Proxied-Entity` value format is a DN | Test call through the gateway | Agree the format with the provider |
| OpenAI and Anthropic clients work with the STS token as API key, including streaming | Call both styles through a gateway prototype | Fix gateway handling, or add a thin client to the template |
| CI context appears in provider records, by metadata or plain headers | Send a test call. Drop whichever method isn't needed | Use the `x-litellm-call-id` join only |
| `x-litellm-call-id` reaches the gateway and joins to spend logs | Test call and ask provider | Use count and bytes only |
| Runners reach enclave ingress; STS reaches GitLab JWKS and directory | Network test | Sync JWKS with a rotation runbook |
| Code quality widget and annotations are available on this tier | Test MR | Link to report artifact instead |
| An approved minimal base, internal package mirror and mirrored helper image exist | Ask registry owners, run a test build | Agree a base and mirror before the pilot |
| Instance runner availability | Ask GitLab admins early | Use option 2 or 3 (section 8.1) |
| Option 3 only: ID token names the triggering user; source code is reachable; findings can reach the source MR; pipeline variable role limits | Test before building option 3 | Do not use option 3 for that purpose |
| Tokens and prompts stay out of logs, with `CI_DEBUG_TRACE` on | Pilot test; try forcing it off via runner `environment` | Document risk; raise to accreditor |

### 13.1 Working assumptions

Owner's decision, 2026-11-06: write the initial implementation assuming these hold. None is verified yet. Each must be confirmed or corrected before the pilot is deployed, and a false one means changing what's noted.

| # | Assumption | If false, change |
|---|---|---|
| 1 | Looking up `mail` returns exactly one entry per user | `EmailAttribute` setting, or the mapping source |
| 2 | The directory's DN matches the certificate DN exactly, so no transform is needed | Add a transform to the LDAP lookup |
| 3 | The provider accepts that DN in `X-Proxied-Entity` as it stands | Same transform, agreed with the provider |
| 4 | Regular users can't change their GitLab email | The mapping source |
| 5 | The trigger table holds, and bot users have no directory entry | Attribution docs, or add a deny rule |
| 6 | The enclave reaches GitLab OIDC, the directory and the provider, and runners reach enclave ingress | Network paths, or JWKS sync |
| 7 | A read-only directory service account is available to STS over LDAPS | Directory access for STS |
| 8 | Go 1.26, a module mirror, an approved base image and a package mirror exist on the network | Build pipeline and image base |
| 9 | The license is below Ultimate, so review findings appear only as the MR code quality report | Nothing required. Ultimate adds line-level findings |

Confirmed by the baseline probe, so not assumptions: `user_email`, `user_id` and the other required claims are present, the audience matches, token lifetime tracks the job timeout, and OIDC discovery, issuer and signing key checks pass from the runner.

## 14. Acceptance tests

Must pass before Phase 2:
- Forged, expired or wrong-`aud` tokens are rejected by STS and gateway.
- Unlisted runner: no token.
- Scheduled pipeline on an unprotected ref: no token.
- Unmapped user or bot: no token.
- Non-allowlisted image: job refused.
- Job-supplied `X-Proxied-Entity` is overwritten.
- Blocked destination is unreachable from an AI job.
- Blocked path and oversized request are rejected, including `/v1/batches` and LiteLLM admin routes.
- Client-supplied `x-litellm-*`, `x-api-key` and `Authorization` values never reach LiteLLM.
- A spoofed `user` or `metadata` value in a request body doesn't change identity or attribution. The provider has confirmed this; the test verifies it end to end, and also checks limits.
- OpenAI-style and Anthropic-style calls both work, streaming and non-streaming, and both are attributed to the right user.
- Provider applies the proxied user's permissions, not the gateway's.
- Audit record links each gateway request to its user and job. Joining to provider records by request ID is used where available and does not block Phase 2 **(designer's call)**.
- No body content appears in any STS, gateway or runner logs.
- A code review on a test MR shows findings with no write credential present.
- `ai-base` runs the review and token exchange as non-root, has no package manager or setuid binaries, contains no secrets, and has a passing scan and an SBOM.
- A job requesting root is refused or runs without it.
- Option 2, if used: a runner created by a group Owner but not on the list gets no token.
- Option 3, if used: a pipeline with any other `ci_config_ref_uri` gets no token, and users can't run their own YAML on the protected runner.

## 15. Left to the builder

Implementation language and frameworks, or reuse of an existing reverse proxy; k8s manifests; autoscaling settings; JWKS caching details; exact JWT format; SIEM schema; choice of approved minimal base and scan tools; review prompt design; template file layout.
