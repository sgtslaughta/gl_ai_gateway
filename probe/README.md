# Phase 0 probe

Checks the design's riskiest assumptions from a real GitLab CI job, before any service is built. It uses only the Python standard library.

**Safety:**
- It never prints the token, and it masks user details unless `PROBE_SHOW_VALUES=true`.
- It doesn't verify the token signature. It only reads claims and checks the signing key ID exists.
- It sends plain GET requests to the targets you list, with no credentials, and never calls an AI API.
- It stops if `CI_DEBUG_TRACE` is on, because the log may already hold tokens. Delete that job log.

## Run it

1. Create a **private** test project, and copy in `phase0_probe.py` and `phase0-probe.gitlab-ci.yml` (as `.gitlab-ci.yml`).
2. Replace the `*.example.internal` values, runner tag and image. The image needs `python3` and your internal CA.
3. Add to `PROBE_REACH` every target this runner should reach, as `name=url` pairs. Use `tcp://host:port` for non-HTTP targets.
4. Push. Results appear in the job log, and any `FAIL` fails the job.
5. Record results in `results.md`.

## Trigger test

This confirms who each trigger attributes the run to. Set `PROBE_SHOW_VALUES` to `"true"` for this test only, then run each trigger with **two different users** where the table says so. Compare `user_login` to who you expected:

| Trigger | How | Expected `user_login` |
|---|---|---|
| Push | User A pushes | A |
| MR pipeline | User A opens an MR | A |
| Retry | User B retries User A's job | B |
| Manual | User B clicks **Run pipeline** | B |
| Schedule | User A owns a schedule on a protected branch | A |
| Schedule, unprotected | Same, on an unprotected branch | A, with `ref_protected = false` |
| Trigger token | Call the trigger API with User A's token | A |
| Bot | Push with a project access token | Bot user, which must fail mapping later |

Set it back to `"false"` and delete those job logs afterward.

## Network tests from the enclave

The probe can test paths that don't start on a runner. Run it from a pod in the enclave, with no token needed:

```shell
PROBE_REACH="gitlab-oidc=https://gitlab.example.internal/.well-known/openid-configuration,directory=tcp://ldap.example.internal:636,provider=https://llm.example.internal/" \
  python3 phase0_probe.py --network-only
```

Set `SSL_CERT_FILE` to your internal CA bundle if it isn't in the system store. For the provider, a TLS rejection still counts as reached, since it needs a client certificate you aren't sending.

## Directory test

STS uses the DN the directory returns for `user_email`, so compare it with the certificate for several users. Don't put real DNs in the repo:

```shell
openssl pkcs12 -in your.p12 -nokeys -clcerts | openssl x509 -noout -subject -nameopt RFC2253
ldapsearch -x -LLL -o ldif-wrap=no -H ldaps://ldap.example.internal:636 -D "<bind-dn>" -W -b "<base-dn>" "(mail=<email>)" dn
```

Each email must return exactly one entry, with the same DN as the certificate. Any other result blocks the build until a fix is agreed. Also confirm that a regular test account can't change its email.

## Reading results

| Check | If it fails or warns |
|---|---|
| `identity-mapping` | **Part of the gate to build.** `PASS` means the token has `user_email` for STS's directory lookup. `FAIL` means agree another mapping source |
| `gitlab-version` | `FAIL` below 15.7 means redesigning the identity source. `WARN` below 18.4 only affects Phase 4 |
| `claim:*` | A missing required claim breaks an STS policy check, so review the design for it |
| `token-lifetime` | `WARN` means expiry doesn't track job timeout, so reassess the token lifetime |
| `oidc-*` | STS can't validate tokens from this location without fixing this |
| `reachable:*` | `tls-untrusted` means fix the CA. `dns-failure` or `unreachable` means fix the network path |
| `blocked:*` | Use on the hardened runner in the pilot. `FAIL` means NetworkPolicy isn't blocking that target |

## What this doesn't test

Calling the provider through a gateway, `X-Proxied-Entity`, the code quality widget, and streaming all need the pilot gateway. The implementation plan covers them.

## Tests

```shell
cd probe && python3 -m unittest test_phase0_probe -v
```
