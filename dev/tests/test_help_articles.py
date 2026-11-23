"""The Help articles (ui/help-articles.json) stay consistent: unique ids, links that resolve, plain wording."""
import json
import os
import re
import unittest

import campaign_api

UI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui")
DATA = json.load(open(os.path.join(UI, "help-articles.json"), encoding="utf-8"))["articles"]
BY_ID = {a["id"]: a for a in DATA}
BANNED = re.compile(r"\b(simply|just|easily|leverage|seamless\w*|robust|delve|crucial|utilize)\b", re.I)
LIMITS = {"workflow": 700, "tool": 500, "note": 450}


class TestHelpArticles(unittest.TestCase):
    def test_shape_and_unique_ids(self):
        self.assertEqual(len(BY_ID), len(DATA))
        for a in DATA:
            self.assertEqual(set(a), {"id", "kind", "title", "summary", "keywords", "where", "related", "body"}, a["id"])
            self.assertIn(a["kind"], LIMITS)
            self.assertLess(len(a["summary"]), 160, a["id"])
            self.assertGreaterEqual(len(a["keywords"]), 6, a["id"])

    def test_the_planned_set_exists(self):
        want = {"build-a-capture", "import-and-validate-a-pcap", "replay-a-capture", "build-a-campaign",
                "lab-import-pcap", "lab-recipes", "lab-sensor-pushes", "lab-modules"}
        self.assertTrue(want <= set(BY_ID))

    def test_links_resolve(self):
        for a in DATA:
            ids = list(a["related"]) + re.findall(r"\[\[([a-z0-9-]+)(?:\|[^\]]+)?\]\]", a["body"])
            for i in ids:
                self.assertIn(i, BY_ID, "%s links to a missing article %s" % (a["id"], i))
            self.assertNotIn(a["id"], a["related"])

    def test_tools_tie_back_to_a_workflow_and_are_not_workflows(self):
        for a in DATA:
            if a["kind"] == "tool":
                self.assertTrue(any(BY_ID[i]["kind"] == "workflow" for i in a["related"]), a["id"])
                self.assertFalse(re.search(r"^1\. ", a["body"], re.M), "%s has numbered steps" % a["id"])
            if a["kind"] == "workflow":
                self.assertTrue(re.search(r"^1\. ", a["body"], re.M), a["id"])

    def test_plain_wording_and_length(self):
        for a in DATA:
            text = a["title"] + " " + a["summary"] + " " + a["body"]
            self.assertNotIn("\u2014", text, a["id"])
            self.assertIsNone(BANNED.search(text), "%s: %s" % (a["id"], BANNED.search(text)))
            self.assertLessEqual(len(a["body"].split()), LIMITS[a["kind"]], a["id"])
            self.assertNotRegex(text, r"/(Users|home)/|[A-Z]:\\\\", a["id"])

    def test_served(self):
        for name in ("help.js", "help.css", "help-articles.json"):
            status, body, _, _ = campaign_api.static_file(name, UI)
            self.assertEqual(status, 200, name)


if __name__ == "__main__":
    unittest.main()
