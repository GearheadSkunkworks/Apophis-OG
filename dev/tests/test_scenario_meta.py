"""Scenario metadata: the data file, the loader, and its additive merge into /api/modules.

Run from dev/:  python -m unittest tests.test_scenario_meta
"""
import http.client
import json
import os
import re
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
sys.path.insert(0, DEV)

import scenario_meta  # noqa: E402
import server  # noqa: E402
from netgen import incidents as INC  # noqa: E402

with open(scenario_meta.PATH, encoding="utf-8") as _f:
    DOC = json.load(_f)
ENTRIES = DOC["scenarios"]
BY_ID = {e["id"]: e for e in ENTRIES}
# registry prefix -> the family name the UI shows (branding.CATEGORIES tags)
FAMILY_OF = {"NDR": "SEC", "NPM": "PERF", "CRP": "CRYP", "IR": "REPLAY", "CUSTOM": "CUSTOM", "CAMPAIGN": "CAMPAIGN"}
TEXT_KEYS = ("title", "category", "expected_observation", "steps", "protocols", "hosts", "zone_path", "notes")
CLOCK = re.compile(r"\b\d{1,2}:\d{2}\b")
TZ = re.compile(r"\b(UTC|GMT|PST|PDT|EST|EDT|CST|CDT|MST|MDT|CET|CEST|BST)\b|[A-Z][a-z]+/[A-Z][a-z]+")
PATHS = re.compile("/" + "Users/|/home/|/pri" + "vate/|/tmp/|[A-Za-z]:\\\\|~/")


def _strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, list):
        for x in v:
            yield from _strings(x)


class DataFile(unittest.TestCase):
    def test_status_and_schema(self):
        self.assertEqual(DOC["status"], "draft-unverified")
        self.assertEqual(DOC["schema"], "1")

    def test_ids_match_registry_exactly_once(self):
        ids = [e["id"] for e in ENTRIES]
        self.assertEqual(len(ids), len(set(ids)), "duplicate ids")
        self.assertEqual(set(ids), set(INC.REGISTRY), "entries and registry ids differ")

    def test_family_matches_registry(self):
        for e in ENTRIES:
            self.assertEqual(e["family"], FAMILY_OF[INC.REGISTRY[e["id"]].prefix], e["id"])

    def test_steps(self):
        for e in ENTRIES:
            self.assertEqual(len(e["steps"]), 4, e["id"])
            for s in e["steps"]:
                self.assertTrue(isinstance(s, str) and s.strip(), e["id"])

    def test_category_in_taxonomy(self):
        tax = scenario_meta.taxonomy()
        for e in ENTRIES:
            self.assertIn(e["category"], tax[e["family"]], e["id"])
            for c in e.get("also_categories", []):
                self.assertIn(c, tax[e["family"]], e["id"])
            if e["family"] == "REPLAY":
                self.assertEqual(e["category"], "Incident replay")
            if INC.REGISTRY[e["id"]].prefix in ("CUSTOM", "CAMPAIGN"):
                self.assertEqual(e["category"], "Custom recipe")

    def test_confidence(self):
        for e in ENTRIES:
            self.assertIn(e["confidence"], ("high", "medium", "low"), e["id"])

    def test_lists_of_strings(self):
        for e in ENTRIES:
            for k in ("protocols", "hosts", "zone_path"):
                self.assertIsInstance(e[k], list, (e["id"], k))
                for s in e[k]:
                    self.assertIsInstance(s, str, (e["id"], k))
            for s in e["zone_path"]:
                self.assertIn(s, ("user", "server", "edge", "ot"), e["id"])

    def test_no_clock_times_zones_or_local_paths(self):
        for e in ENTRIES:
            for k in TEXT_KEYS:
                for s in _strings(e.get(k, "")):
                    self.assertIsNone(CLOCK.search(s), (e["id"], k, s))
                    self.assertIsNone(TZ.search(s), (e["id"], k, s))
            for k in e:
                for s in _strings(e[k]):
                    if k == "sources":
                        self.assertTrue(s.startswith("dev/"), (e["id"], s))   # repo-relative only
                    self.assertIsNone(PATHS.search(s), (e["id"], k, s))


class Loader(unittest.TestCase):
    def tearDown(self):
        scenario_meta.reset()

    def test_missing_file(self):
        r = scenario_meta.load(os.path.join(tempfile.gettempdir(), "no-such-scenario-meta.json"))
        self.assertEqual(r, {"status": "", "by_id": {}})

    def test_malformed_file(self):
        for body in ("{not json", "[]", '{"scenarios": 5}', '{"scenarios": [1, null, {"id": 3}]}', ""):
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                f.write(body)
            try:
                r = scenario_meta.load(f.name)
                self.assertEqual(r["by_id"], {}, body)
            finally:
                os.unlink(f.name)

    def test_get_hides_provenance_and_unknown_is_none(self):
        m = scenario_meta.get("ndr-recon")
        self.assertNotIn("sources", m)
        self.assertNotIn("notes", m)
        self.assertEqual(len(m["steps"]), 4)
        self.assertIsNone(scenario_meta.get("baseline-mcp"))
        self.assertIsNone(scenario_meta.get("nope"))
        self.assertEqual(scenario_meta.status(), "draft-unverified")

    def test_missing_file_means_no_meta_in_modules(self):
        scenario_meta._cache = scenario_meta.load(os.path.join(tempfile.gettempdir(), "no-such-scenario-meta.json"))
        mods = server.get_modules()
        self.assertTrue(mods)
        self.assertTrue(all("meta" not in m for m in mods))


class Api(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        c = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=30)
        c.request("GET", "/api/modules")
        r = c.getresponse()
        cls.status = r.status
        cls.body = json.loads(r.read())
        c.close()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_meta_on_every_registry_scenario(self):
        self.assertEqual(self.status, 200)
        by = {m["name"]: m for m in self.body["modules"]}
        for n in INC.REGISTRY:
            self.assertIn("meta", by[n], n)
            self.assertNotIn("sources", by[n]["meta"])
        shown = [m for m in self.body["modules"] if not m.get("pinned") and not m.get("recipe_driven")
                 and not m.get("ot_only")]
        self.assertEqual(len(shown), 58)
        self.assertTrue(all("meta" in m for m in shown))

    def test_pinned_baseline_has_no_meta(self):
        pinned = [m for m in self.body["modules"] if m.get("pinned")]
        self.assertTrue(pinned)
        self.assertTrue(all("meta" not in m for m in pinned))

    def test_taxonomy_key(self):
        t = self.body["scenario_taxonomy"]
        self.assertEqual(t["meta_status"], "draft-unverified")
        self.assertEqual(t["families"]["SEC"][0], "Initial access")
        self.assertEqual(t["families"]["REPLAY"], ["Incident replay"])
        self.assertIn("categories", self.body)          # pre-existing key untouched
        self.assertIsInstance(self.body["categories"], list)

    def test_existing_fields_unchanged(self):
        def rel(lo, hi, s=300):
            def off(m):
                m = int(m) - s
                if m < 60:
                    return "+%dm" % m
                h, mm = divmod(m, 60)
                return "+%dh" % h if mm == 0 else "+%d:%02d" % (h, mm)
            return "Start %s → %s" % (off(lo), off(hi))
        ot = getattr(INC, "OT_SCENARIOS", set())
        deps = getattr(INC, "SCENARIO_DEPENDENCIES", {})
        expected = []
        for n, i in INC.REGISTRY.items():
            (h1, m1), (h2, m2) = i.window
            expected.append({"name": n, "prefix": i.prefix, "title": i.title, "note": i.note,
                             "window": rel(h1 * 60 + m1, h2 * 60 + m2), "pinned": False,
                             "recipe_driven": i.prefix in ("CUSTOM", "CAMPAIGN"),
                             "ot_only": n in ot, "requires": deps.get(n)})
        expected += INC.baseline_modules()
        got = [{k: v for k, v in m.items() if k != "meta"} for m in self.body["modules"]]
        self.assertEqual(got, expected)
        for k in ("default_out", "default_pcap", "pcap_name", "stix_name", "default_nets", "industries", "categories"):
            self.assertIn(k, self.body)


class ProtocolsCheckTests(unittest.TestCase):
    E = {"protocols": ["A", "B", "C"]}

    def test_mapping(self):
        pc = scenario_meta.protocols_check
        r = {"verdict": "pass", "verified": ["A", "B", "C"], "carrier_only": [], "missing": [], "unverifiable": []}
        self.assertEqual(pc(self.E, r), {"status": "checked", "checked": ["A", "B", "C"],
                                         "carrier_only": [], "unverified": []})
        r2 = dict(r, verified=["A"], carrier_only=["B"], unverifiable=["C"])
        self.assertEqual(pc(self.E, r2), {"status": "partial", "checked": ["A"],
                                          "carrier_only": ["B"], "unverified": ["C"]})
        for bad in ({"verdict": "fail", "missing": ["A"]}, {"verdict": "inconclusive"}, None, "junk"):
            self.assertEqual(pc(self.E, bad), {"status": "unchecked", "checked": [], "carrier_only": [],
                                               "unverified": ["A", "B", "C"]})

    def test_missing_or_corrupt_file_degrades(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "v.json")
            self.assertEqual(scenario_meta.load_verification(bad), {})
            with open(bad, "w") as f:
                f.write("{not json")
            self.assertEqual(scenario_meta.load_verification(bad), {})
            with open(bad, "w") as f:
                json.dump({"results": {"x": {"verdict": "pass"}, "y": 3}}, f)
            self.assertEqual(list(scenario_meta.load_verification(bad)), ["x"])

    def test_served(self):
        scenario_meta.reset()
        m = scenario_meta.get("ndr-recon")
        self.assertIn("protocols_check", m)
        self.assertEqual(m["protocols_check"]["status"], "checked")
        scenario_meta.reset()


if __name__ == "__main__":
    unittest.main()


class ScaleProfileTests(unittest.TestCase):
    A = [0.004, 0.02, 0.1, 0.5, 1.0]

    def test_fixed_and_scaling_rows(self):
        fixed = scenario_meta.scale_profile({"packets": [100] * 5, "bytes": [5] * 5}, self.A)
        grows = scenario_meta.scale_profile({"packets": [100, 100, 150, 400, 900], "bytes": [1, 1, 2, 3, 4]}, self.A)
        self.assertEqual(fixed["behaviour"], "fixed")
        self.assertEqual(grows["behaviour"], "scales")
        self.assertEqual(grows["points"][-1], [1.0, 900, 4])

    def test_bad_rows_degrade_to_none(self):
        for row in ({"packets": [1, None, 1, 1, 1], "bytes": [1] * 5}, {"packets": [1] * 5, "bytes": [1] * 5, "errors": ["x"]},
                    {"packets": [1, 2], "bytes": [1, 2]}, {}, None):
            self.assertIsNone(scenario_meta.scale_profile(row, self.A))

    def test_missing_file_is_empty(self):
        self.assertEqual(scenario_meta.load_scale("/nonexistent/scenario_scale.json"), {})

    def test_every_catalogue_scenario_has_a_profile(self):
        prof = scenario_meta.load_scale()
        missing = [i for i in scenario_meta.ids() if i not in prof and i not in ("campaign", "custom-import")]
        self.assertEqual(missing, [], "run tools/measure_scenario_scale.py")
