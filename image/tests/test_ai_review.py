import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ai_review.py")
KEY = "sk-TESTKEY-must-not-leak"
MARK = "UNIQUE_DIFF_MARKER_12345"


class Stub(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        Stub.calls.append({"path": self.path, "auth": self.headers.get("Authorization"),
                           "body": json.loads(self.rfile.read(n))})
        code, out = Stub.reply
        if code == 302:
            Stub.loc_sent = True
        out = out if isinstance(out, bytes) else out.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(out)))
        if code == 302:
            self.send_header("Location", Stub.location)
        self.end_headers()
        self.wfile.write(out)


def chat(content):
    return (200, json.dumps({"choices": [{"message": {"content": content}}]}))


def git(repo, *a):
    subprocess.run(["git", "-C", repo, "-c", "user.name=t", "-c", "user.email=t@e.internal", *a],
                   check=True, capture_output=True)


class Base(unittest.TestCase):
    content = "print('%s')\n" % MARK
    fname = "app.py"
    base_content = None

    def setUp(self):
        Stub.calls, Stub.reply = [], chat("[]")
        self.srv = http.server.HTTPServer(("127.0.0.1", 0), Stub)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = self.tmp.name
        git(self.repo, "init", "-q")
        with open(os.path.join(self.repo, "base.txt"), "w") as f:
            f.write("base\n")
        if self.base_content is not None:
            with open(os.path.join(self.repo, self.fname), "w", newline="") as f:
                f.write(self.base_content)
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "base")
        self.base = subprocess.run(["git", "-C", self.repo, "rev-parse", "HEAD"],
                                   capture_output=True, text=True).stdout.strip()
        if self.content is not None:
            with open(os.path.join(self.repo, self.fname), "w", newline="") as f:
                f.write(self.content)
            git(self.repo, "add", ".")
            git(self.repo, "commit", "-qm", "change")

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.tmp.cleanup()

    def run_tool(self, **extra):
        env = {"PATH": os.environ["PATH"], "HOME": self.repo,
               "OPENAI_BASE_URL": "http://127.0.0.1:%d/v1" % self.srv.server_port,
               "OPENAI_API_KEY": KEY, "AI_REVIEW_MODEL": "m-test",
               "CI_MERGE_REQUEST_DIFF_BASE_SHA": self.base}
        env.update(extra)
        env = {k: v for k, v in env.items() if v is not None}
        return subprocess.run([sys.executable, SCRIPT, "--diff-only", "--format", "codequality"],
                              cwd=self.repo, env=env, capture_output=True, text=True, timeout=30)

    def assertNoLeak(self, r):
        for s in (KEY, MARK):
            self.assertNotIn(s, r.stderr)


def finding(**kw):
    d = {"path": "app.py", "line": 1, "severity": "minor", "description": "problem"}
    d.update(kw)
    return d


class TestValid(Base):
    def test_valid_response(self):
        Stub.reply = chat(json.dumps([finding(severity="major")]))
        r = self.run_tool()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(len(out), 1)
        f = out[0]
        self.assertEqual(f["check_name"], "ai-review")
        self.assertEqual(f["severity"], "major")
        self.assertEqual(f["location"], {"path": "app.py", "lines": {"begin": 1}})
        self.assertEqual(len(f["fingerprint"]), 64)
        self.assertEqual(Stub.calls[0]["path"], "/v1/chat/completions")
        self.assertEqual(Stub.calls[0]["auth"], "Bearer " + KEY)
        self.assertEqual(Stub.calls[0]["body"]["model"], "m-test")

    def test_model_required(self):
        r = self.run_tool(AI_REVIEW_MODEL=None)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("AI_REVIEW_MODEL", r.stderr)
        self.assertEqual(Stub.calls, [])


class TestEmptyDiff(Base):
    content = None

    def test_empty(self):
        r = self.run_tool()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout), [])
        self.assertEqual(Stub.calls, [])


class TestOversizedDiff(Base):
    content = ("x = 1  # %s\n" % MARK) * 20000

    def test_oversized(self):
        r = self.run_tool()
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "info")
        self.assertIn("too large", out[0]["description"])
        self.assertEqual(Stub.calls, [])


class TestMalformedModelOutput(Base):
    def test_malformed(self):
        Stub.reply = chat("SECRET_MODEL_TEXT not json")
        r = self.run_tool()
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("SECRET_MODEL_TEXT", r.stdout + r.stderr)
        self.assertNoLeak(r)


class TestFiltering(Base):
    def test_outside_diff_dropped(self):
        Stub.reply = chat(json.dumps([finding(path="other.py"), finding(path="../etc/passwd"),
                                      finding()]))
        out = json.loads(self.run_tool().stdout)
        self.assertEqual([f["location"]["path"] for f in out], ["app.py"])

    def test_invalid_fields_dropped(self):
        Stub.reply = chat(json.dumps([
            finding(severity="urgent"), finding(line=0), finding(line=-3), finding(line="1"),
            finding(line=True), finding(description=""), finding(description=5), "junk", finding()]))
        out = json.loads(self.run_tool().stdout)
        self.assertEqual(len(out), 1)

    def test_fingerprint_stable(self):
        Stub.reply = chat(json.dumps([finding()]))
        a = json.loads(self.run_tool().stdout)[0]["fingerprint"]
        b = json.loads(self.run_tool().stdout)[0]["fingerprint"]
        self.assertEqual(a, b)


class TestDiffNotPrinted(Base):
    def test_http_500(self):
        Stub.reply = (500, "boom " + MARK + KEY)
        r = self.run_tool()
        self.assertNotEqual(r.returncode, 0)
        self.assertNoLeak(r)
        self.assertNotIn(MARK, r.stdout)

    def test_success(self):
        r = self.run_tool()
        self.assertNoLeak(r)


class Other(http.server.BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        Other.hits.append(self.headers.get("Authorization"))
        self.send_response(200)
        self.end_headers()

    do_GET = do_POST


class TestNoRedirect(Base):
    def test_redirect_is_failure(self):
        other = http.server.HTTPServer(("127.0.0.1", 0), Other)
        threading.Thread(target=other.serve_forever, daemon=True).start()
        Other.hits = []
        Stub.location = "http://127.0.0.1:%d/x" % other.server_port
        Stub.reply = (302, "")
        r = self.run_tool()
        other.shutdown()
        other.server_close()
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(Other.hits, [])
        self.assertNoLeak(r)


class TestOddFilename(Base):
    fname = "caf\u00e9 notes.txt"
    content = "-----BEGIN PRIVATE KEY-----\n"

    def test_no_api_call(self):
        r = self.run_tool()
        self.assertEqual(Stub.calls, [])
        out = json.loads(r.stdout)
        self.assertEqual(out[0]["severity"], "info")
        self.assertEqual(out[0]["location"]["path"], self.fname)


class TestQuotedFilename(Base):
    fname = 'we"ird.txt'
    content = "-----BEGIN PRIVATE KEY-----\n"

    def test_unparseable_fails_closed(self):
        r = self.run_tool()
        self.assertEqual(Stub.calls, [])
        self.assertEqual(json.loads(r.stdout)[0]["severity"], "info")


PEM = "-----BEGIN PRIVATE KEY-----"


class SecretNoCall(Base):
    def test_no_call(self):
        if type(self) is SecretNoCall:
            return
        r = self.run_tool()
        self.assertEqual(Stub.calls, [])
        out = json.loads(r.stdout)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "info")
        self.assertNotIn("PRIVATE KEY", r.stdout + r.stderr)


class TestRemovedLine(SecretNoCall):
    base_content = PEM + "\nkeep\n"
    content = "keep\n"


class TestContextLine(SecretNoCall):
    base_content = "a\n" + PEM + "\nz\n"
    content = "a\n" + PEM + "\nz\nnew\n"


class TestFormFeed(SecretNoCall):
    content = "a\x0c" + PEM + "\n"


class TestVerticalTab(SecretNoCall):
    content = "a\x0b" + PEM + "\n"


class TestUnicodeLineSep(SecretNoCall):
    content = "a\u2028" + PEM + "\n"


class TestNel(SecretNoCall):
    content = "a\x85" + PEM + "\n"


class TestUnattributable(SecretNoCall):
    """Key text only in a rename header: no hunk line carries it."""
    fname = "old.txt"
    base_content = "some text here\n"
    content = None

    def setUp(self):
        super().setUp()
        git(self.repo, "mv", "--", "old.txt", "x " + PEM + ".txt")
        git(self.repo, "commit", "-qm", "rename")


class TestSecretPreCheck(Base):
    fname = "conf.txt"
    content = "-----BEGIN RSA PRIVATE KEY-----\nabc\n"

    def test_pem(self):
        r = self.run_tool()
        out = json.loads(r.stdout)
        self.assertEqual(Stub.calls, [])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "info")
        self.assertEqual(out[0]["location"]["path"], "conf.txt")
        self.assertNotIn("PRIVATE KEY", r.stdout)

    def test_skip(self):
        r = self.run_tool(AI_REVIEW_SKIP_SECRET_CHECK="true")
        self.assertEqual(len(Stub.calls), 1)
        self.assertEqual(json.loads(r.stdout), [])


class TestGlpat(Base):
    fname = "ci.txt"
    content = "token = glpat-abcdefghij0123456789\n"

    def test_glpat(self):
        r = self.run_tool()
        self.assertEqual(Stub.calls, [])
        self.assertNotIn("glpat-", r.stdout + r.stderr)
        self.assertEqual(json.loads(r.stdout)[0]["location"]["path"], "ci.txt")


class TestDiffIsDelimitedAsData(Base):
    def test_messages(self):
        self.run_tool()
        msgs = Stub.calls[0]["body"]["messages"]
        self.assertEqual([m["role"] for m in msgs], ["system", "user"])
        self.assertIn("untrusted", msgs[0]["content"].lower())
        self.assertNotIn(MARK, msgs[0]["content"])
        self.assertIn(MARK, msgs[1]["content"])
        self.assertRegex(msgs[1]["content"], r"(?s)^.*<<<.*DIFF.*>>>")


if __name__ == "__main__":
    unittest.main()
