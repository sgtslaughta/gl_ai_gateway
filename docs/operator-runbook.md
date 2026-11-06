# Operator runbook

Status: draft. Nothing has been deployed. Every procedure here is untested
until the pilot runs. Hosts are placeholders (`*.example.internal`).

Components: STS (token exchange), gateway (pass-through to the provider), AI
runners, hardened image `ai-base`. Deployment details are in `deploy/README.md`.

## Daily facts
- STS and gateway serve TLS only.
- STS audit records and gateway audit records are metadata only: user, DN, project, ref, commit, pipeline, job, runner, status, sizes. Never content.
- The STS audit record includes `user_id` and `job_project_path`.

## JWKS caching and outages
STS (for GitLab keys) and the gateway (for STS keys) cache signing keys.
- They refresh every 10 minutes when the source is healthy.
- If the source is down, or publishes an empty key set, they keep the cached keys for up to 24 hours. After that, verification fails and all exchanges or calls are denied.

What this means:
- A short GitLab outage does not stop AI jobs that already have a valid token. New exchanges still need a valid GitLab ID token, so jobs fail only if GitLab itself is down.
- A key revoked at the source stays trusted here for up to 24 hours.

**Emergency: clear cached keys.** If a GitLab or STS signing key is
compromised, restart the service so it drops its cache and fetches fresh keys.
- Compromised GitLab signing key: restart STS.
- Compromised STS signing key: replace it with a fresh key (see rotation), then restart STS and the gateway. Do not just delete the file. `STS_SIGNING_KEYS` lists both `current.pem` and `next.pem`, and a missing file stops STS from starting.
- Restart with the normal rollout tool for the pod. Check pod readiness and run one test job afterwards.
- Restart only after the source publishes the corrected key set. A restart clears the cache, so while the source is down or empty the service starts with no keys and denies everything.

## Audit failures
STS must write an audit record for every decision. If the write fails, STS
returns **HTTP 500 `audit_failed`** and issues no token. Users see this as
AI jobs failing.
- Check the audit sink: disk full, log shipper stopped, permissions.
- Fix the sink. Do not weaken this behavior.
- The gateway cannot undo a response already streaming, so a failed gateway audit write is reported to the process error output as `gateway: audit write failed`. Alert on that line.

## Signing key rotation (STS)
Secret `sts-signing-keys` holds `current.pem` and `next.pem`.
1. Generate a new key. Put it in `next.pem`. Keep `current.pem`. Roll out STS. Both keys are published.
2. Wait until the gateway has fetched the new key. Only key publication matters here. A token with an unknown key ID makes the gateway refresh on demand, limited to once a minute, so the wait is short. Confirm with a test job.
3. Promote: swap so the new key is `current.pem`. Roll out STS.
4. After 30 more minutes (old tokens expired), put a fresh key in `next.pem`.
5. If the old key was compromised, skip waiting: promote, roll out, then restart STS and the gateway to clear caches.
Use an HSM or Vault if one exists. Record each rotation date.

## TLS and client certificates
- STS and gateway serving certificates need SANs for `<svc>.ai-services.svc` and the `*.example.internal` host.
- `gateway-ca` must trust the STS serving certificate. `sts-ca` must trust GitLab and the LDAP server.
- The gateway client certificate (`gateway-client-cert`) is what the provider trusts. It can claim any user, so guard it like the most sensitive secret. Rotate on the provider's schedule and agree overlap with the provider first.
- Rotate a serving certificate by updating the secret and restarting the pod. Check expiry dates monthly.
- Startup fails if TLS files are missing or a JWKS URL is not https.
- Directory access uses LDAPS with a read-only bind account (`sts-directory-bind`). Rotate its password in the secret and restart STS.

## Runner list changes
The STS runner list (`runner_ids`) is config.
- Adding or replacing a runner (cutover): add the new ID **together with** the old one. Roll out. Move jobs to the new runner. Remove the old ID later, and roll out again.
- Never remove the old ID first. Jobs on the old runner would be denied with `runner_not_allowed`.
- Runner IDs change when an instance, group or central runner is re-created. Ask the admin or group Owner to tell you the new ID.
- Review `config.toml` changes as security changes. Keep the runner token out of the repo.
- Raise `limit` and `concurrent` only from measured load.

## Image release and retirement
- Image `ai-base` is built from a protected branch with a pinned base digest. Version tag is semantic and immutable.
- Release steps: build, SBOM, scan, sign if tooling exists, push, then publish a template release that pins the new tag.
- Rebuild monthly and for critical CVEs.
- Retire old tags after a published notice. Removal breaks pinned jobs, so announce first.
- Mirror the runner helper image and set `helper_image`. Treat it as part of the supply chain.
- Note: `dpkg` is left in the image so SBOM and vulnerability scanners can read the package list. `apt` and `apt-get` are removed. This differs from the design, which says to remove the package manager. See `accreditor-package.md`.

## Cutover (pilot to production)
1. Confirm written accreditor sign-off exists. If not, stop.
2. Create the production runner. Add its ID next to the pilot ID in the STS list.
3. Update template defaults and publish a template release.
4. Watch denials by reason for a week.
5. Remove the pilot ID.
Sizing: target about 100 simultaneous jobs. Use pilot measures, not guesses.

## Incident response
Triage first by reading audit records for the user, project, commit, pipeline and job.
- Suspected stolen gateway token: lifetime is 30 minutes. Wait it out, or rotate the STS key.
- Suspected misuse by a user: block in the provider (they own limits) and disable the user in GitLab. Use the SHA in the record to tell who wrote the code from who triggered it.
- Suspected bad email mapping: compare `user_id` over time in the audit log. The same `user_id` with a different DN is a warning sign (audit records hold the DN, not the email).
- Suspected compromised signing key or client certificate: rotate now, restart, tell the provider.
- Suspected runner token leak: ask the admin or Owner to reset it, then update the secret.
- Always record: time, who, what you changed.

## Limits of metadata-only audit
- No prompts or responses are stored. You cannot prove what was sent or answered.
- Records show attribution (GitLab said this user triggered the job). They do not prove the user authored the request.
- Joining gateway records to provider records uses `x-litellm-call-id`. Whether that join works is untested.
- Admin changes to GitLab or runner settings are not monitored.
