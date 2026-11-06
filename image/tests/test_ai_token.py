import http.server
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "ai-token")
ID_TOKEN = "idtok.SECRET-ID-TOKEN.sig"
ISSUED = "issued.SECRET-ISSUED-TOKEN.sig"


class Stub(http.server.BaseHTTPRequestHandler):
    seen = {}

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode()
        Stub.seen = {"path": self.path, "body": parse_qs(body)}
        if Stub.mode == "deny":
            code, out = 403, b'{"error":"runner_not_allowed"}'
        elif Stub.mode == "500":
            code, out = 500, b"internal ISSUED-LEAK"
        elif Stub.mode == "html502":
            code, out = 502, b"<html><body>Bad Gateway</body></html>"
        elif Stub.mode == "noaccess":
            code, out = 200, b'{"expires_in":1}'
        elif Stub.mode == "nonjson":
            code, out = 200, b"<html>oops</html>"
        else:
            code, out = 200, ('{"access_token":"%s","expires_in":1800}' % ISSUED).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


class TestAIToken(unittest.TestCase):
    def setUp(self):
        Stub.mode = "ok"
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), Stub)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = "http://127.0.0.1:%d" % self.srv.server_port

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def run_script(self, sts=None, cmd=". ./ai-token && env", path=None, shell="sh"):
        env = {
            "PATH": path or os.environ["PATH"],
            "AI_ID_TOKEN": ID_TOKEN,
            "AI_STS_URL": sts or self.url,
            "AI_GATEWAY_URL": "https://gw.example.internal",
        }
        return subprocess.run(shell.split() + ["-c", cmd], cwd=os.path.dirname(SCRIPT),
                              env=env, capture_output=True, text=True, timeout=30)

    def test_exports_and_unsets(self):
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        e = dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)
        self.assertEqual(e["OPENAI_BASE_URL"], "https://gw.example.internal/v1")
        self.assertEqual(e["ANTHROPIC_BASE_URL"], "https://gw.example.internal")
        self.assertEqual(e["OPENAI_API_KEY"], ISSUED)
        self.assertEqual(e["ANTHROPIC_API_KEY"], ISSUED)
        self.assertNotIn("AI_ID_TOKEN", e)
        self.assertNotIn(ID_TOKEN, r.stderr)

    def test_request_shape_and_stdin(self):
        r = self.run_script(cmd=". ./ai-token && true")
        self.assertEqual(r.returncode, 0, r.stderr)
        b = Stub.seen["body"]
        self.assertEqual(Stub.seen["path"], "/token")
        self.assertEqual(b["subject_token"], [ID_TOKEN])
        self.assertEqual(b["grant_type"], ["urn:ietf:params:oauth:grant-type:token-exchange"])
        self.assertEqual(b["subject_token_type"], ["urn:ietf:params:oauth:token-type:jwt"])

    def test_token_not_on_command_line(self):
        d = tempfile.mkdtemp()
        log = os.path.join(d, "argv")
        real = shutil.which("curl")
        stub = os.path.join(d, "curl")
        with open(stub, "w") as f:
            f.write('#!/bin/sh\nprintf "%%s\\n" "$@" >> %s\nexec %s "$@"\n' % (log, real))
        os.chmod(stub, 0o755)
        r = self.run_script(path=d + ":" + os.environ["PATH"])
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(log) as f:
            argv = f.read()
        self.assertIn("subject_token@-", argv)
        self.assertNotIn(ID_TOKEN, argv)
        shutil.rmtree(d)

    def test_trace_does_not_leak(self):
        r = self.run_script(cmd=". ./ai-token; echo done", shell="sh -x")
        self.assertIn("done", r.stdout)
        for t in (ID_TOKEN, ISSUED):
            self.assertNotIn(t, r.stdout + r.stderr)

    def test_denied(self):
        Stub.mode = "deny"
        r = self.run_script(cmd=". ./ai-token; echo rc=$?")
        self.assertIn("rc=1", r.stdout)
        self.assertIn("runner_not_allowed", r.stdout + r.stderr)
        for t in (ID_TOKEN, ISSUED):
            self.assertNotIn(t, r.stdout + r.stderr)

    def test_unreachable(self):
        r = self.run_script(sts="http://127.0.0.1:1", cmd=". ./ai-token; echo rc=$?")
        self.assertIn("rc=1", r.stdout)
        self.assertRegex(r.stderr, "unreachable|cannot reach|failed")
        self.assertNotIn(ID_TOKEN, r.stdout + r.stderr)

    def test_failure_modes(self):
        for mode in ("500", "noaccess", "nonjson", "deny"):
            Stub.mode = mode
            r = self.run_script(cmd=". ./ai-token; echo rc=$? id=${AI_ID_TOKEN:-unset} key=${OPENAI_API_KEY:-unset}")
            self.assertIn("rc=1", r.stdout, mode)
            self.assertIn("id=unset", r.stdout, mode)
            self.assertIn("key=unset", r.stdout, mode)
            self.assertNotIn("LEAK", r.stdout + r.stderr, mode)
            self.assertNotIn(ID_TOKEN, r.stdout + r.stderr, mode)

    def test_html_502_under_errexit_pipefail(self):
        # GitLab runner scripts run with set -eo pipefail: a jq failure on an
        # HTML error page must not exit silently.
        Stub.mode = "html502"
        r = self.run_script(shell="bash",
                            cmd="set -eo pipefail; trap 'echo id=${AI_ID_TOKEN:-unset}' EXIT; . ./ai-token; echo not-reached")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("not-reached", r.stdout)
        self.assertIn("token exchange denied (HTTP 502)", r.stderr)
        self.assertIn("id=unset", r.stdout)
        self.assertNotIn(ID_TOKEN, r.stdout + r.stderr)

    def test_errexit_with_trace_restores_trace(self):
        Stub.mode = "html502"
        r = self.run_script(shell="bash",
                            cmd="set -eox pipefail; . ./ai-token || true; case $- in *x*) echo traced;; esac")
        self.assertIn("traced", r.stdout)
        self.assertNotIn(ID_TOKEN, r.stdout + r.stderr)

    def test_id_token_unset_on_unreachable(self):
        r = self.run_script(sts="http://127.0.0.1:1", cmd=". ./ai-token; echo id=${AI_ID_TOKEN:-unset}")
        self.assertIn("id=unset", r.stdout)

    def test_missing_vars(self):
        r = subprocess.run(["sh", "-c", ". ./ai-token; echo rc=$?"], cwd=os.path.dirname(SCRIPT),
                           env={"PATH": os.environ["PATH"]}, capture_output=True, text=True)
        self.assertIn("rc=1", r.stdout)
        self.assertIn("AI_ID_TOKEN", r.stderr)


if __name__ == "__main__":
    unittest.main()
