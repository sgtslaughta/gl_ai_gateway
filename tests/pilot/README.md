# Pilot acceptance project

Status: written, NOT RUN. Nothing here has been deployed or tested. No result
in this folder is evidence yet.

These jobs check the controls in spec section 14. Use a private, non-sensitive
test project only, until the accreditor signs off.

## Setup
1. Copy `.gitlab-ci.yml` and `child.yml` to the root of the test project, keeping the path `tests/pilot/child.yml`.
2. Fix the `include` project, ref and file to your template project and tag.
3. Set CI/CD variables: `PROBE_BLOCKED` (a destination that must be blocked) and `PILOT_MODEL`.
4. Use a group runner tagged `ai`, on the STS runner list.
5. Keep one protected branch (`main`) and one unprotected branch (`pilot-unprotected`).

## How to run each test

| Test (spec section 14) | How | Pass looks like |
|---|---|---|
| Blocked destination | Run pipeline from web on `main` | `blocked-destination` prints PASS |
| Non-allowlisted image | Run from web | `disallowed-image` is refused by the runner and never starts |
| Job requests root | Run from web | `request-root` is refused, or prints PASS with a non-zero uid |
| `CI_DEBUG_TRACE` | Run from web with `CI_DEBUG_TRACE=true`. Then repeat with the runner `environment` forcing it off | Search the full log for the token, see below |
| Spoofed identity | Run `spoofed-identity`, then check provider records for this job ID | Provider shows the real user, project and limits, not the spoofed values |
| Forged headers | Run `forged-headers`, ask the provider what arrived | No `forged` value present |
| Rejected routes and size | Run `rejected-routes` | PASS: no 2xx on listed routes, 413 on oversize |
| OpenAI and Anthropic styles | Run `client-openai`, `client-anthropic` | All four calls return 200 and attribute to the right user |
| Schedule on unprotected ref | Create a schedule on `pilot-unprotected`, run it | `schedule-unprotected` PASS |
| Trigger token on unprotected ref | Call the trigger API with `ref=pilot-unprotected` | `trigger-unprotected` PASS |
| Child pipeline on unprotected ref | Push to `pilot-unprotected` | `child-expect-no-token` PASS |
| Unlisted runner | Register a second runner NOT on the list, run any token job on it | Exchange is denied with `runner_not_allowed` |

Also run the remaining section 14 items that are not jobs here (forged or expired
tokens, unmapped user, bot user, fork pipeline, provider permissions, audit link,
log content, image scan and SBOM). Record all of them in `docs/pilot-results.md`.

## Searching the debug log for tokens
Download the raw job log. Search for the first 20 characters of the ID token
and of the gateway token (print them in a throwaway job, never in a real one),
and for the strings `eyJ` and `Bearer`. Any hit is a FAIL. Delete the log
afterwards.

## Notes
- Run with a test account that has a directory entry. For the unmapped test, use a project access token.
- Spoof and forged-header jobs send small prompts only. Do not put real content in them.
- For fork pipelines, open an MR from a fork and check the exchange is denied with `fork_pipeline_denied`.
