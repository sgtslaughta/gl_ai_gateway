"""Run: python3 -m unittest test_phase0_probe -v (from the probe directory)."""
import base64
import contextlib
import http.server
import io
import json
import os
import socket
import threading
import unittest
from unittest import mock

import phase0_probe as probe

SECRET_SIGNATURE = "SIGNATURE-MUST-NOT-LEAK"


def b64(obj):
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_token(claims, kid="key-1"):
    return f"{b64({'alg': 'RS256', 'kid': kid})}.{b64(claims)}.{SECRET_SIGNATURE}"


def good_claims(**overrides):
    claims = {
        "iss": "https://gitlab.example.internal",
        "aud": "https://sts.example.internal",
        "sub": "project_path:g/p:ref_type:branch:ref:main",
        "iat": 1000,
        "exp": 1000 + 3900,
        "user_login": "alice",
        "user_email": "alice@example.internal",
        "user_identities": [
            {"provider": "ldapmain", "extern_uid": "cn=Alice Secret,ou=people,dc=example"}
        ],
        "project_path": "g/p",
        "ref": "main",
        "ref_protected": "true",
        "sha": "abc",
        "pipeline_id": "1",
        "pipeline_source": "push",
        "job_id": "2",
        "runner_id": 7,
        "ci_config_ref_uri": "gitlab.example.internal/g/p//.gitlab-ci.yml@refs/heads/main",
    }
    claims.update(overrides)
    return claims


def levels(results):
    return {r.name: r.level for r in results}


class DecodeTests(unittest.TestCase):
    def test_decodes_header_and_claims(self):
        header, claims = probe.decode_token(make_token({"a": 1}))
        self.assertEqual(header["kid"], "key-1")
        self.assertEqual(claims, {"a": 1})

    def test_malformed_token_error_does_not_echo_token(self):
        with self.assertRaises(probe.ProbeError) as ctx:
            probe.decode_token("not-a-jwt-" + SECRET_SIGNATURE)
        self.assertNotIn(SECRET_SIGNATURE, str(ctx.exception))


class VersionTests(unittest.TestCase):
    def test_parses_edition_suffix(self):
        self.assertEqual(probe.parse_version("18.4.1-ee"), (18, 4, 1))

    def test_too_old_for_id_tokens_fails(self):
        self.assertEqual(probe.check_version("15.6.0").level, probe.FAIL)

    def test_supported_but_before_job_token_push_warns(self):
        self.assertEqual(probe.check_version("17.0.0").level, probe.WARN)

    def test_current_version_passes(self):
        self.assertEqual(probe.check_version("18.4.0-ee").level, probe.PASS)

    def test_unparsable_version_warns(self):
        self.assertEqual(probe.check_version("").level, probe.WARN)


class ClaimTests(unittest.TestCase):
    def check(self, claims, timeout="3600", aud="https://sts.example.internal"):
        return probe.check_claims(claims, expected_aud=aud, job_timeout=timeout)

    def test_good_claims_have_no_failures(self):
        self.assertNotIn(probe.FAIL, levels(self.check(good_claims())).values())

    def test_wrong_audience_fails(self):
        self.assertEqual(levels(self.check(good_claims(aud="other")))["audience"], probe.FAIL)

    def test_missing_runner_id_fails(self):
        claims = good_claims()
        del claims["runner_id"]
        self.assertEqual(levels(self.check(claims))["claim:runner_id"], probe.FAIL)

    def test_missing_optional_claim_warns(self):
        claims = good_claims()
        del claims["ci_config_ref_uri"]
        self.assertEqual(levels(self.check(claims))["claim:ci_config_ref_uri"], probe.WARN)

    def test_dn_in_identities_passes_without_exposing_value(self):
        results = self.check(good_claims())
        mapping = next(r for r in results if r.name == "identity-mapping")
        self.assertEqual(mapping.level, probe.PASS)
        self.assertNotIn("Alice Secret", mapping.detail)
        self.assertIn("ldapmain", mapping.detail)

    def test_email_only_mapping_warns(self):
        results = self.check(good_claims(user_identities=[]))
        self.assertEqual(levels(results)["identity-mapping"], probe.WARN)

    def test_no_mapping_key_fails(self):
        claims = good_claims(user_identities=[])
        del claims["user_email"]
        self.assertEqual(levels(self.check(claims))["identity-mapping"], probe.FAIL)

    def test_lifetime_tracking_job_timeout_passes(self):
        self.assertEqual(levels(self.check(good_claims()))["token-lifetime"], probe.PASS)

    def test_lifetime_far_from_job_timeout_warns(self):
        results = self.check(good_claims(exp=1000 + 86400))
        self.assertEqual(levels(results)["token-lifetime"], probe.WARN)

    def test_missing_job_timeout_warns(self):
        self.assertEqual(levels(self.check(good_claims(), timeout=""))["token-lifetime"], probe.WARN)


class ContextTests(unittest.TestCase):
    def test_sensitive_values_masked_by_default(self):
        text = probe.format_context(good_claims(), show_values=False)
        self.assertIn("pipeline_source = push", text)
        self.assertNotIn("alice", text)
        self.assertNotIn("Alice Secret", text)

    def test_show_values_reveals_user_for_attribution_testing(self):
        self.assertIn("alice", probe.format_context(good_claims(), show_values=True))


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        host = f"http://127.0.0.1:{self.server.server_port}"
        routes = {
            "/.well-known/openid-configuration": {"issuer": host, "jwks_uri": f"{host}/jwks"},
            "/jwks": {"keys": [{"kid": "key-1"}]},
        }
        body = routes.get(self.path)
        self.send_response(200 if body else 403)
        self.end_headers()
        self.wfile.write(json.dumps(body or {}).encode())

    def log_message(self, *args):
        pass


class NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def closed_port(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def test_http_error_status_still_counts_as_reached(self):
        self.assertEqual(probe.reach(f"{self.base}/forbidden").category, "reached")

    def test_refused_connection(self):
        self.assertEqual(
            probe.reach(f"http://127.0.0.1:{self.closed_port()}/").category, "unreachable"
        )

    def test_dns_failure(self):
        self.assertEqual(probe.reach("http://no-such-host.invalid/").category, "dns-failure")

    def test_tcp_scheme_reaches_open_port(self):
        port = self.server.server_port
        self.assertEqual(probe.reach(f"tcp://127.0.0.1:{port}").category, "reached")

    def test_required_target_unreachable_fails(self):
        results = probe.check_targets(f"x=http://127.0.0.1:{self.closed_port()}/", must_reach=True)
        self.assertEqual(results[0].level, probe.FAIL)

    def test_blocked_target_reached_fails(self):
        results = probe.check_targets(f"x={self.base}/", must_reach=False)
        self.assertEqual(results[0].level, probe.FAIL)

    def test_blocked_target_unreachable_passes(self):
        results = probe.check_targets(
            f"x=http://127.0.0.1:{self.closed_port()}/", must_reach=False
        )
        self.assertEqual(results[0].level, probe.PASS)

    def test_malformed_target_fails(self):
        self.assertEqual(probe.check_targets("no-equals", must_reach=True)[0].level, probe.FAIL)

    def test_oidc_passes_when_issuer_and_kid_match(self):
        results = probe.check_oidc(self.base, self.base, "key-1")
        self.assertEqual(set(levels(results).values()), {probe.PASS})

    def test_oidc_issuer_mismatch_fails(self):
        results = probe.check_oidc(self.base, "https://other", "key-1")
        self.assertEqual(levels(results)["oidc-issuer"], probe.FAIL)

    def test_oidc_unknown_kid_fails(self):
        results = probe.check_oidc(self.base, self.base, "rotated")
        self.assertEqual(levels(results)["oidc-signing-key"], probe.FAIL)

    def test_oidc_unreachable_fails(self):
        results = probe.check_oidc(f"http://127.0.0.1:{self.closed_port()}", "x", "key-1")
        self.assertEqual(levels(results)["oidc-discovery"], probe.FAIL)


class MainTests(unittest.TestCase):
    def run_main(self, env, argv=()):
        out = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(out):
            code = probe.main(list(argv))
        return code, out.getvalue()

    def token_env(self, claims=None, **extra):
        env = {
            "AI_ID_TOKEN": make_token(claims or good_claims()),
            "PROBE_AUD": "https://sts.example.internal",
            "CI_JOB_TIMEOUT": "3600",
            "CI_SERVER_VERSION": "18.4.0",
            "PROBE_SKIP_OIDC": "true",
        }
        env.update(extra)
        return env

    def test_success_never_prints_token_material(self):
        code, output = self.run_main(self.token_env())
        self.assertEqual(code, 0)
        self.assertNotIn(SECRET_SIGNATURE, output)
        self.assertNotIn("Alice Secret", output)

    def test_any_failure_exits_nonzero(self):
        code, _ = self.run_main(self.token_env(good_claims(aud="other")))
        self.assertEqual(code, 1)

    def test_missing_token_fails(self):
        code, output = self.run_main({"PROBE_AUD": "x"})
        self.assertEqual(code, 1)
        self.assertIn("AI_ID_TOKEN", output)

    def test_debug_trace_on_fails_and_stops_before_token_checks(self):
        code, output = self.run_main(self.token_env(CI_DEBUG_TRACE="true"))
        self.assertEqual(code, 1)
        self.assertIn("CI_DEBUG_TRACE", output)
        self.assertNotIn("identity-mapping", output)

    def test_network_only_mode_needs_no_token(self):
        code, output = self.run_main({}, ["--network-only"])
        self.assertEqual(code, 0)
        self.assertNotIn("AI_ID_TOKEN", output)


if __name__ == "__main__":
    unittest.main()
