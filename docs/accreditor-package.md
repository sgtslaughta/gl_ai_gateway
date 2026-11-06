# Accreditor package: AI access from GitLab CI

## Evidence status: PENDING
The system has not been deployed. No pilot test has run. Every statement below
describes the design and the written code. None is proven by testing yet.
Pilot evidence goes in `pilot-results.md`, which is blank today. This package
should be re-issued with that evidence before sign-off is requested.

## What it does
A GitLab CI job reaches the AI provider under the identity of the person who
started the pipeline. No user certificate, key or password is on the runner
or in any new service. A token service (STS) swaps GitLab's signed job token
for a short-lived token. A gateway then forwards the call to the provider
using its own certificate and names the user in a header.

## Plain statement: attribution, not non-repudiation
GitLab vouches for the user. The user's private key signs nothing. The system
can show that GitLab said a user triggered a job. It cannot prove the user
wrote or approved the request. Do not rely on it as non-repudiation.

## Accepted limits (design section 3)
1. **Identity follows the trigger, not the author.** If Bob retries Alice's commit, Bob's identity runs Alice's code. Logs record the commit SHA so an audit can separate them.
2. **Poisoned code runs as the victim.** A malicious commit or dependency can use the identity of whoever triggers it, for up to the token lifetime (30 minutes at most).
3. **GitLab admins are in the trust boundary** and are outside the owner's team. They can likely act as other users and change runner settings.
4. **The gateway certificate can claim any user.** So can the STS signing key.
5. **Identity mapping depends on GitLab's email lock.** STS looks up the signed `user_email` in the directory and uses the DN returned. Anything but exactly one match is denied. Users cannot change their email, but a GitLab admin can, which would redirect that user's attribution. The audit log records the unchanging `user_id` and `job_project_path`, so such a change can be found afterward.
6. **Extra trust depends on the access option:** group Owners under option 2, central project Maintainers under option 3.
7. **No content controls exist.** Neither this gateway nor the LLM API gateway screens prompts. Injection defense relies only on limiting what a job can do.
8. **Audit shows who, when and where, not what.** After an incident, nobody can show what was sent. This is by design.

**Data handling:** AI use is capped at GitLab's classification level. The owner states that engineers and admins with node access have incidental exposure protection, so node-level admin access is not a concern in this design.

## Sign-off list (design section 12)
Written sign-off is requested on these points. Status: **pending**.
1. Attribution rather than non-repudiation.
2. GitLab admins in the trust boundary, including identity mapping's dependence on the email lock.
3. Shared runner nodes and need-to-know.
4. Extra trust for the chosen access option.
5. No content inspection, and metadata-only audit.

If sign-off is refused, high-risk projects need signed delegation (users sign
a time-limited grant with their own certificate). That is not built.

## Controls in the code (written, not yet shown to work)
- STS checks: valid GitLab signature, exact audience, runner on the allowlist, job project equals token project (denies fork code in the parent), and a protected ref for every pipeline source except push, web and merge request events.
- Denial reasons: `runner_not_allowed`, `ref_not_protected`, `fork_pipeline_denied`, `identity_not_mapped`, plus `invalid_token`, `invalid_request`, `sign_failed`, `audit_failed`.
- STS writes an audit record for each decision. If it cannot, it returns 500 and issues nothing.
- Tokens last 30 minutes at most and never past the ID token's expiry.
- Gateway allows five routes only. It forwards only an allowlist of client headers: `Content-Type`, `Accept`, `Accept-Encoding`, `User-Agent`, `Idempotency-Key`, and prefixes `anthropic-`, `openai-`, `x-stainless-`. It sets the user header itself.
- Key caches: STS and the gateway refresh keys every 10 minutes. If the source is down or empty, they keep cached keys for up to 24 hours. A revoked key can stay trusted that long unless the service is restarted.
- Audit holds metadata only. No prompts or responses are stored in any new component.
- Runners: no privileged mode, non-root, ephemeral pods, network policy deny by default, images only from the hardened registry path.
- Open channels, disclosed: DNS is allowed from job pods to the cluster resolver and is an open channel (names can carry data out). Job egress to the shared ingress address reaches every host served on that ingress IP, not only STS and the gateway, because the network policy filters by address and port, not by host name.
- Owner decision before production: the ingress-nginx project announced its retirement (March 2026, no security fixes afterwards; confirm the current status). Decide whether to keep it, replace it with a supported controller or the Gateway API, and who patches it.

## Deviation from the design: package tooling in the image
The design says to remove the package manager from `ai-base`. The image
removes `apt`, `apt-get` and related commands but **keeps `dpkg`**, so SBOM and
vulnerability scanners can read the installed package list. `dpkg` can unpack
local `.deb` files but the job has no route to fetch packages and cannot write
system paths as non-root. The accreditor should accept or reject this.
Hardening of the image is not a security boundary. The network policy and pod
settings are.

## Working assumptions (design section 13.1): UNVERIFIED
The initial code was written assuming these. None is verified. Each must be
confirmed before the pilot is deployed. A false one means changing the noted
part and possibly rework.

| # | Assumption | If false, change |
|---|---|---|
| 1 | Looking up `mail` returns exactly one entry per user | `EmailAttribute` setting, or the mapping source |
| 2 | The directory's DN matches the certificate DN exactly | Add a transform to the LDAP lookup |
| 3 | The provider accepts that DN in `X-Proxied-Entity` as it stands | Same transform, agreed with the provider |
| 4 | Regular users cannot change their GitLab email | The mapping source |
| 5 | The trigger table holds, and bot users have no directory entry | Attribution docs, or add a deny rule |
| 6 | The enclave reaches GitLab OIDC, the directory and the provider, and runners reach ingress | Network paths, or JWKS sync |
| 7 | A read-only directory service account is available to STS over LDAPS | Directory access for STS |
| 8 | Go 1.26, a module mirror, an approved base image and a package mirror exist | Build pipeline and image base |
| 9 | Real tokens carry `job_project_path` | STS fork rule, which otherwise denies every exchange |
| 10 | The license is below Ultimate, so findings show only as the code quality report | Nothing required |

## Open items
- Pilot not run. Fill `pilot-results.md`.
- Provider confirmations (header format, spoofed body fields, call ID join) are not yet tested end to end.
- Admin-side changes to GitLab or runners are not monitored in v1.
- Sign-off is pending. Phase 2 (production) does not start without it.
