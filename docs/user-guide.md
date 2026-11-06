# AI in GitLab CI: user guide

Status: draft. The service has not been deployed yet. Names and URLs below are
placeholders (`*.example.internal`) until rollout.

## What you get
A CI job can call the AI provider as you, the person who started the pipeline.
You do not handle certificates, keys or passwords.

You cannot choose another identity. The identity comes from GitLab's signed
token and nothing in your YAML, variables or request can change it.

## Quick start
Add one include to `.gitlab-ci.yml`. Pin a version tag.

```yaml
include:
  - project: platform/ai-ci-templates
    ref: v1.0.0
    file:
      - templates/ai-access.yml
      - templates/ai-code-review.yml
```

With `ai-code-review.yml`, merge requests get an automated review. It runs on
merge request pipelines and does not block merging if the AI is down.
Findings show in the merge request code quality report. Line-level notes may
not appear on your GitLab tier. If they do not, open the `review.json` artifact.

## Custom jobs
Extend `.ai-access`. It sets the runner tag, the image, the ID token and the
token exchange. It exports these variables:

- `OPENAI_BASE_URL` and `OPENAI_API_KEY`
- `ANTHROPIC_BASE_URL` and `ANTHROPIC_API_KEY`

```yaml
summarize:
  extends: .ai-access
  script:
    - 'curl -sS "$OPENAI_BASE_URL/chat/completions" -H "Authorization: Bearer $OPENAI_API_KEY" -H "Content-Type: application/json" -d @request.json'
```

The key is a short-lived token (30 minutes at most, never longer than the job's
own ID token). Do not save it, print it or put it in an artifact.

Allowed gateway routes: `POST /v1/chat/completions`, `POST /v1/messages`,
`POST /v1/messages/count_tokens`, `POST /v1/embeddings`, `GET /v1/models`.
Everything else is rejected, including `/v1/batches` and admin routes.

The gateway passes on only these client headers: `Content-Type`, `Accept`,
`Accept-Encoding`, `User-Agent`, `Idempotency-Key`, and any starting with
`anthropic-`, `openai-` or `x-stainless-`. All others are dropped. A `user` or
`metadata` field in your request body does not change who you are.

## Limits of the image
The job image has bash, curl, jq, git and python3 (standard library only). No
package installs, compilers or AI SDKs. You cannot use another image. Ask for a
reviewed derived image if you need more.

## Schedules, triggers and other automatic pipelines
Pipelines you start yourself by push, web or merge request work on any branch.

Every other pipeline source needs a **protected ref**. That covers:
- schedules
- trigger tokens
- child pipelines
- multi-project (downstream) pipelines
- the pipelines API

On an unprotected branch these get no token. Run schedules on a protected
branch such as `main`.

Fork merge request pipelines that run in the parent project are denied.
Review forked changes by other means.

Remember: the job runs as whoever started it. A retry by someone else runs
under their identity. Bot users (project and group access tokens) have no
directory entry and are denied.

## Error reason codes
When the token exchange fails, the job log shows `ai-token: token exchange denied (HTTP nnn): <reason>`.

| Reason | HTTP | Meaning | What to do |
|---|---|---|---|
| `runner_not_allowed` | 403 | The job did not run on an approved AI runner | Use the `ai` tag and `.ai-access` |
| `ref_not_protected` | 403 | Source needs a protected ref and yours is not | Run from a protected branch or tag |
| `fork_pipeline_denied` | 403 | Job project differs from the token's project (fork code in the parent) | Do not run AI jobs on fork pipelines |
| `identity_not_mapped` | 403 | Your email did not match exactly one directory entry. Also shown if the directory is unreachable | Check your email in GitLab. Bots cannot use AI. If it persists, contact the operators |
| `invalid_token` | 401 | The ID token is bad, expired or from an unknown issuer, or the audience is wrong | Re-run the job. Check `id_tokens` audience |
| `invalid_request` | 400 | The exchange request was malformed | Use the template. Do not call STS by hand |
| `sign_failed` | 500 | The service could not sign a token | Retry. Tell the operators if it repeats |
| `audit_failed` | 500 | The service could not write its audit record, so it issues nothing | Retry. Tell the operators if it repeats |

Gateway errors are plain text: `401 unauthorized` (bad or expired token),
`403 route not allowed`, `413 request body too large`, `502 bad gateway`
(provider unreachable).

## What not to log
- Never print `AI_ID_TOKEN`, `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.
- Never run AI jobs with `CI_DEBUG_TRACE` on. The runner itself prints variables before your script starts, so the template cannot fully protect you.
- Do not turn on `set -x` around token use.
- Do not put prompts or responses in logs or long-lived artifacts if the content is sensitive. The AI services keep no prompts or responses, but your job logs and artifacts do.
- Artifacts from AI jobs expire after one day by default.

## What is recorded
Each exchange and gateway call is logged: who, project, ref, commit,
pipeline, job, route, status and sizes. Not the content.

## Batch and bulk work
Jobs here stop at 30 minutes and are for small calls. For large or long work
(many documents, big embeddings runs) use the batch service. The gateway tells
you its address when you hit a rejected route.
