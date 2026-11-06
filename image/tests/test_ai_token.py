import http.server
import os
import subprocess
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

    def run_script(self, sts=None, cmd=". ./ai-token && env"):
        env = {
            "PATH": os.environ["PATH"],
            "AI_ID_TOKEN": ID_TOKEN,
            "AI_STS_URL": sts or self.url,
            "AI_GATEWAY_URL": "https://gw.example.internal",
        }
        return subprocess.run(["sh", "-c", cmd], cwd=os.path.dirname(SCRIPT),
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
        with open(SCRIPT) as f:
            src = f.read()
        self.assertIn("subject_token@-", src)
        self.assertNotIn("subject_token=", src)

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

    def test_missing_vars(self):
        r = subprocess.run(["sh", "-c", ". ./ai-token; echo rc=$?"], cwd=os.path.dirname(SCRIPT),
                           env={"PATH": os.environ["PATH"]}, capture_output=True, text=True)
        self.assertIn("rc=1", r.stdout)
        self.assertIn("AI_ID_TOKEN", r.stderr)


if __name__ == "__main__":
    unittest.main()
