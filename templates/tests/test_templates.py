import pathlib
import re
import unittest

import yaml

T = pathlib.Path(__file__).resolve().parent.parent


def load(name):
    return yaml.safe_load((T / name).read_text())


class TemplateTests(unittest.TestCase):
    def test_base(self):
        j = load("ai-access.yml")[".ai-access"]
        self.assertEqual(j["tags"], ["ai"])
        self.assertIn("ai-hardened/", j["image"])
        self.assertFalse(j["image"].endswith(":latest"))
        self.assertIn(":", j["image"].rsplit("/", 1)[1])
        self.assertTrue(j["id_tokens"]["AI_ID_TOKEN"]["aud"])
        self.assertIn(". ai-token", j["before_script"])

    def test_review(self):
        j = load("ai-code-review.yml")["ai-review"]
        self.assertEqual(j["extends"], ".ai-access")
        self.assertIs(j["interruptible"], True)
        self.assertIs(j["allow_failure"], True)
        self.assertEqual(j["variables"]["GIT_DEPTH"], "0")
        self.assertIn("AI_REVIEW_MODEL", j["variables"])
        self.assertEqual(j["artifacts"]["reports"]["codequality"], "review.json")
        self.assertTrue(j["artifacts"]["expire_in"])
        self.assertIn("ai-review --diff-only --format codequality > review.json", j["script"])
        r = j["rules"]
        self.assertEqual(r[0]["if"], "$CI_MERGE_REQUEST_SOURCE_PROJECT_ID != $CI_MERGE_REQUEST_PROJECT_ID")
        self.assertEqual(r[0]["when"], "never")
        self.assertIn("merge_request_event", r[1]["if"])

    def test_no_secrets(self):
        for n in ("ai-access.yml", "ai-code-review.yml"):
            s = (T / n).read_text()
            self.assertNotIn("CI_DEBUG_TRACE", s)
            self.assertIsNone(re.search(r"(?i)(sk-[a-z0-9]{8,}|password\s*:|eyJ[A-Za-z0-9_-]{10,})", s))


if __name__ == "__main__":
    unittest.main()
