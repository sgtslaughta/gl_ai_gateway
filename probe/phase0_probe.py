#!/usr/bin/env python3
"""Phase 0 probe: checks design assumptions from a GitLab CI job.

Uses the standard library only and sends no prompts or credentials to any target.
Never prints the token. Sensitive claim values are masked unless
PROBE_SHOW_VALUES=true. See probe/README.md.
"""
import base64
import collections
import json
import os
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
Result = collections.namedtuple("Result", "level name detail")
Reach = collections.namedtuple("Reach", "category detail")

MIN_ID_TOKENS = (15, 7)
MIN_JOB_TOKEN_PUSH = (18, 4)
LIFETIME_TOLERANCE_SECONDS = 600
TIMEOUT_SECONDS = 5

REQUIRED_CLAIMS = ("iss", "aud", "exp", "iat", "user_login", "runner_id", "pipeline_source",
                   "ref_protected", "project_path", "sha", "pipeline_id", "job_id", "user_id",
                   "job_project_path")
OPTIONAL_CLAIMS = ("ref", "ci_config_ref_uri",
                   "runner_environment", "user_access_level")
# ponytail: allowlist, so a new GitLab claim stays masked by default.
SAFE_TO_PRINT = ("iss", "aud", "iat", "exp", "nbf", "runner_id", "runner_environment",
                 "pipeline_source", "ref_protected", "ref_type")


class ProbeError(Exception):
    pass


def _decode_segment(segment):
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def decode_token(token):
    """Return (header, claims) without verifying. Errors never include the token."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ProbeError("token is not a three-part JWT")
    try:
        return _decode_segment(parts[0]), _decode_segment(parts[1])
    except ValueError:
        raise ProbeError("token segments are not valid base64 JSON") from None


def parse_version(text):
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(n) for n in match.groups()) if match else None


def check_version(text):
    version = parse_version(text)
    if version is None:
        return Result(WARN, "gitlab-version", f"could not parse {text!r}")
    if version[:2] < MIN_ID_TOKENS:
        return Result(FAIL, "gitlab-version", f"{text} is older than 15.7, so no id_tokens")
    if version[:2] < MIN_JOB_TOKEN_PUSH:
        return Result(WARN, "gitlab-version", f"{text} works for v1, but Phase 4 needs 18.4+")
    return Result(PASS, "gitlab-version", text)


def _check_mapping(claims):
    if claims.get("user_email"):
        return Result(PASS, "identity-mapping", "user_email present for directory lookup")
    return Result(FAIL, "identity-mapping", "no user_email to look up")


def _check_lifetime(claims, job_timeout):
    if not isinstance(claims.get("exp"), int) or not isinstance(claims.get("iat"), int):
        return Result(WARN, "token-lifetime", "exp or iat missing")
    lifetime = claims["exp"] - claims["iat"]
    if not str(job_timeout).isdigit():
        return Result(WARN, "token-lifetime", f"{lifetime}s; CI_JOB_TIMEOUT unavailable")
    gap = abs(lifetime - int(job_timeout))
    detail = f"{lifetime}s against job timeout {job_timeout}s"
    if gap > LIFETIME_TOLERANCE_SECONDS:
        return Result(WARN, "token-lifetime", detail + "; does not track, so reassess lifetime")
    return Result(PASS, "token-lifetime", detail)


def check_claims(claims, expected_aud, job_timeout):
    results = [Result(FAIL, f"claim:{c}", "missing") for c in REQUIRED_CLAIMS if c not in claims]
    results += [Result(WARN, f"claim:{c}", "missing") for c in OPTIONAL_CLAIMS if c not in claims]
    aud_ok = claims.get("aud") == expected_aud
    results.append(Result(PASS if aud_ok else FAIL, "audience",
                          "matches PROBE_AUD" if aud_ok else "does not match PROBE_AUD"))
    results.append(_check_mapping(claims))
    results.append(_check_lifetime(claims, job_timeout))
    return results


def format_context(claims, show_values):
    lines = [f"Claim names: {sorted(claims)}"]
    for name in sorted(claims):
        if name in SAFE_TO_PRINT or show_values:
            lines.append(f"  {name} = {claims[name]}")
        else:
            lines.append(f"  {name} = <masked>")
    return "\n".join(lines)


def _opener():
    # ponytail: no proxy, so results reflect the pod's direct network path.
    context = ssl.create_default_context()  # honors SSL_CERT_FILE
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                       urllib.request.HTTPSHandler(context=context))


def _classify(error):
    reason = getattr(error, "reason", error)
    if isinstance(reason, socket.gaierror):
        return Reach("dns-failure", str(reason))
    if isinstance(reason, ssl.SSLCertVerificationError):
        return Reach("tls-untrusted", "server certificate not trusted; check internal CA")
    if isinstance(reason, ssl.SSLError):
        return Reach("reached", "TLS rejected us, so the host is up; may require a client cert")
    return Reach("unreachable", str(reason))


def reach(url):
    """Connect only. HTTP error statuses still prove the network path works."""
    parsed = urllib.parse.urlsplit(url)
    try:
        if parsed.scheme == "tcp":
            socket.create_connection((parsed.hostname, parsed.port), TIMEOUT_SECONDS).close()
            return Reach("reached", "TCP connected")
        with _opener().open(url, timeout=TIMEOUT_SECONDS) as response:
            return Reach("reached", f"HTTP {response.status}")
    except urllib.error.HTTPError as error:
        error.close()
        return Reach("reached", f"HTTP {error.code}")
    except (OSError, ValueError) as error:
        return _classify(error)


def check_targets(spec, must_reach):
    """spec is 'name=url,name=url'. must_reach=False means the target should be blocked."""
    results = []
    for item in filter(None, (part.strip() for part in spec.split(","))):
        name, separator, url = item.partition("=")
        if not separator or not url:
            results.append(Result(FAIL, f"target:{item}", "expected name=url"))
            continue
        outcome = reach(url)
        reached = outcome.category == "reached"
        ok = reached if must_reach else not reached
        expectation = "reachable" if must_reach else "blocked"
        results.append(Result(PASS if ok else FAIL, f"{expectation}:{name}",
                              f"{outcome.category}: {outcome.detail}"))
    return results


def _fetch_json(url):
    with _opener().open(url, timeout=TIMEOUT_SECONDS) as response:
        return json.load(response)


def check_oidc(server_url, token_iss, kid):
    try:
        config = _fetch_json(server_url.rstrip("/") + "/.well-known/openid-configuration")
    except (OSError, ValueError) as error:
        return [Result(FAIL, "oidc-discovery", _classify(error).category)]
    results = [Result(PASS, "oidc-discovery", "reachable")]
    issuer_ok = config.get("issuer") == token_iss
    results.append(Result(PASS if issuer_ok else FAIL, "oidc-issuer",
                          f"discovery {config.get('issuer')!r}, token {token_iss!r}"))
    try:
        keys = _fetch_json(config["jwks_uri"]).get("keys", [])
    except (OSError, ValueError, KeyError) as error:
        return results + [Result(FAIL, "oidc-signing-key", f"JWKS fetch failed: {error}")]
    found = any(key.get("kid") == kid for key in keys)
    results.append(Result(PASS if found else FAIL, "oidc-signing-key",
                          "token kid is in JWKS" if found else "token kid is not in JWKS"))
    return results


def _token_results(env):
    token = env.get("AI_ID_TOKEN", "")
    if not token:
        return [Result(FAIL, "AI_ID_TOKEN", "not set; does the job declare id_tokens?")], None
    try:
        header, claims = decode_token(token)
    except ProbeError as error:
        return [Result(FAIL, "AI_ID_TOKEN", str(error))], None
    results = check_claims(claims, env.get("PROBE_AUD", ""), env.get("CI_JOB_TIMEOUT", ""))
    if env.get("PROBE_SKIP_OIDC") != "true":
        results += check_oidc(env.get("CI_SERVER_URL", ""), claims.get("iss"), header.get("kid"))
    return results, claims


def main(argv):
    env = os.environ
    results = []
    network_only = "--network-only" in argv
    if env.get("CI_DEBUG_TRACE", "").lower() == "true":
        print("[FAIL] CI_DEBUG_TRACE: on. Variables, including tokens, may be in this log. "
              "Delete the log, and turn tracing off.")
        return 1
    if not network_only:
        token_results, claims = _token_results(env)
        results += token_results
        results.append(check_version(env.get("CI_SERVER_VERSION", "")))
        if claims is not None:
            print(format_context(claims, env.get("PROBE_SHOW_VALUES") == "true"))
    results += check_targets(env.get("PROBE_REACH", ""), must_reach=True)
    results += check_targets(env.get("PROBE_BLOCKED", ""), must_reach=False)
    for result in results:
        print(f"[{result.level}] {result.name}: {result.detail}")
    failures = sum(r.level == FAIL for r in results)
    warnings = sum(r.level == WARN for r in results)
    print(f"Summary: {failures} failed, {warnings} warnings, {len(results)} checks")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
