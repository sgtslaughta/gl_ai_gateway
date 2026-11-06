# Pilot acceptance project

Status: written, NOT RUN. Nothing here has been deployed or tested. No result
in this folder is evidence yet.

These jobs check the controls in spec section 14. Use a private, non-sensitive
test project only, until the accreditor signs off.

## Rule for reading results
A job counts as a pass only if its log contains `PILOT-RESULT: PASS`.
A green job without that line is not a pass. `PILOT-RESULT: CALL-OK` means the
call worked, and the control is proved only by the provider record (below).
Denial jobs pass only on the exact HTTP status and reason code, so a network
error or wrong error cannot pass.

## Setup
1. Copy `.gitlab-ci.yml` and `child.yml` to the test project, keeping the path `tests/pilot/child.yml`.
2. Fix the `include` project, ref and file to your template project and tag.
3. Set CI/CD variables: `PROBE_BLOCKED`, `PILOT_MODEL`, and optionally `PILOT_UNLISTED_TAG`, `PILOT_DEBUG_TRACE`.
4. Use a group runner tagged `ai`, on the STS runner list.
5. Keep one protected branch (`main`) and one unprotected branch (`pilot-unprotected`).

Variable rules:
- `PROBE_BLOCKED` must be a target you KNOWN to be reachable from outside the runner network (test it from your laptop first). Otherwise a timeout proves nothing.
- `PILOT_MODEL` must be a real model. Jobs that call the provider fail if it is still `example-model`.

## Positive controls
A denial means something only if the same setup issues tokens when it should.
Run these on the same runner in the same session:
- `control-web-protected` (web run on `main`) must pass.
- `control-push-unprotected` (push to `pilot-unprotected`) must pass. It shows an unprotected ref still works for push, so later denials are because of the pipeline source.
- `blocked-destination` also checks that the gateway is reachable from its own job.

If a control fails, discard the denial results from that session.

## How to run each test

| Test (spec section 14) | How | Pass looks like |
|---|---|---|
| Blocked destination | Web run on `main` | `blocked-destination`: PASS with curl exit 7 or 28. Other curl codes (such as 6, DNS) are a FAIL |
| Non-allowlisted image | Web run | `disallowed-image` FAILS (orange, allowed to fail) with the runner's image-not-allowed message, and no `PILOT-RESULT: FAIL` line |
| Job requests root | Web run | `request-root` is refused by the runner, or prints PASS with a non-zero uid. A `PILOT-RESULT: FAIL` line is a FAIL |
| `CI_DEBUG_TRACE` | See next section | No token material in the log |
| Spoofed identity | Run `spoofed-identity` | CALL-OK, then provider record shows the real user, project and limits |
| Forged headers | Run `forged-headers` | CALL-OK, then provider record has no `forged` value |
| Rejected routes and size | Run `rejected-routes` | PASS: 403 on every listed route, 413 on oversize. 401 or 000 fail |
| OpenAI and Anthropic styles | Run `client-openai`, `client-anthropic` | 200 on all four calls, then provider confirms the right user |
| Schedule, unprotected ref | Create a schedule on `pilot-unprotected` | `schedule-unprotected` PASS (403, `ref_not_protected`) |
| Trigger token, unprotected ref | Trigger API with `ref=pilot-unprotected` | `trigger-unprotected` PASS (403, `ref_not_protected`) |
| Child pipeline, unprotected ref | Push to `pilot-unprotected` | `child-expect-no-token` PASS (403, `ref_not_protected`) |
| Unlisted runner | Register a runner NOT on the list. Set `PILOT_UNLISTED_TAG` to its tag. Web run | `unlisted-runner` PASS (403, `runner_not_allowed`) |

Also run the section 14 items that are not jobs here (forged or expired tokens,
unmapped user, bot user, fork pipeline, provider permissions, audit link, log
content, image scan and SBOM). For fork pipelines, open an MR from a fork and
expect `fork_pipeline_denied`. Record everything in `docs/pilot-results.md`.

## Provider confirmation
`spoofed-identity`, `forged-headers` and the client jobs prove nothing alone.
Ask the provider to confirm that a record exists for each job ID. Only then
does the absence of forged values count. If no record exists, the result is
"not proven", not a pass.

## CI_DEBUG_TRACE test
Only the `debug-trace-log` job sets `CI_DEBUG_TRACE`. It runs only on a web run
with the variable `PILOT_DEBUG_TRACE=true`. Never set `CI_DEBUG_TRACE` project-wide.

1. Run it. Download the raw log.
2. Search the log for the first 20 characters of the ID token and the gateway token, and for `eyJ` and `Bearer`. Any hit is a FAIL.
3. Repeat with the runner `environment` forcing `CI_DEBUG_TRACE=false`, and record whether it was honored.
4. Delete the job log in GitLab afterwards, and delete your downloaded copy.
5. Treat the log as holding live secrets. Do not share it until the token lifetime (30 minutes) has passed, or the key is revoked.
6. Unset `PILOT_DEBUG_TRACE` when finished.

## Notes
- Use a test account that has a directory entry. For the unmapped test, use a project access token.
- Spoof and forged-header jobs send small prompts only. Do not put real content in them.
