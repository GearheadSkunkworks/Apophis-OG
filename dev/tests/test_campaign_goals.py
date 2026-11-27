"""Goal modes, starter templates and the CSV / MISP exports (dev/netgen/campaign/goals.py, exports.py)."""
import csv
import io
import json
import os
import sys
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if DEV not in sys.path:
    sys.path.insert(0, DEV)

import campaign_api                                    # noqa: E402 - sys.path is set up before the import
from intel import parsers                              # noqa: E402 - sys.path is set up before the import
from netgen.campaign import compiler, exports, goals, schema    # noqa: E402 - sys.path is set up before the import


def _build(tid):
    t = goals.TEMPLATES[tid]
    return compiler.compile_campaign(t["iocs"], options=goals.goal_options(t["goal"]), name=t["title"])


def _crep(camp, ok_indexes):
    entries = [{"stage": "s1", "action": "https_beacon", "ioc": [i], "status": "ok", "packets": 5, "bytes": 500,
                "techniques": ["T1071.001"], "params": {}} for i in ok_indexes]
    return {"id": camp["meta"]["id"], "entries": entries, "stages": [], "errors": [],
            "iocs": [{"index": i, "value": x["value"], "type": x["type"], "role": x["role"], "address": x["value"]}
                     for i, x in enumerate(camp["iocs"])]}


class Goals(unittest.TestCase):
    def test_every_goal_is_valid_options(self):
        for gid in goals.GOALS:
            opts, errs = schema.normalise_options(goals.goal_options(gid))
            self.assertEqual(errs, [], gid)

    def test_goal_changes_the_stages(self):
        t = goals.TEMPLATES["ransomware-precursor"]
        plain = compiler.compile_campaign(t["iocs"])
        rans = _build("ransomware-precursor")
        self.assertIn("Impact", [s["name"] for s in rans["stages"]])
        self.assertNotIn("Impact", [s["name"] for s in plain["stages"]])

    def test_templates_compile_valid_and_put_every_indicator_on_the_wire(self):
        for tid in goals.TEMPLATES:
            with self.subTest(template=tid):
                camp = _build(tid)
                self.assertEqual(schema.validate(camp), [])
                self.assertTrue(all(o["observable"] for o in compiler.observability(camp)), tid)
                self.assertIn(goals.TEMPLATES[tid]["goal"], goals.GOALS)

    def test_templates_use_only_reserved_names(self):
        for t in goals.TEMPLATES.values():
            for i in t["iocs"]:
                if i["type"] == "ipv4":
                    self.assertTrue(i["value"].startswith(("203.0.113.", "198.51.100.")), i["value"])
                elif i["type"] in ("domain", "url"):
                    self.assertRegex(i["value"], r"\.example\.(net|org|com)\b")

    def test_unknown_goal(self):
        with self.assertRaises(ValueError):
            goals.goal_options("nope")

    def test_api_goal_and_override(self):
        iocs = goals.TEMPLATES["beacon-only"]["iocs"]
        _s, res = campaign_api.campaign_compile({"iocs": iocs, "goal": "c2-beaconing"})
        self.assertEqual(res["campaign"]["options"]["beacons_per_c2"], 12)
        _s, res = campaign_api.campaign_compile({"iocs": iocs, "goal": "c2-beaconing", "options": {"beacons_per_c2": 2}})
        self.assertEqual(res["campaign"]["options"]["beacons_per_c2"], 2)
        with self.assertRaises(campaign_api.ApiError) as cm:
            campaign_api.campaign_compile({"iocs": iocs, "goal": "nope"})
        self.assertEqual(cm.exception.status, 400)

    def test_api_catalog(self):
        status, body = campaign_api.campaign_templates()
        self.assertEqual(status, 200)
        self.assertEqual({g["id"] for g in body["goals"]}, set(goals.GOALS))
        self.assertEqual({t["id"] for t in body["templates"]}, set(goals.TEMPLATES))


class Exports(unittest.TestCase):
    def setUp(self):
        self.camp = _build("ransomware-precursor")
        self.crep = _crep(self.camp, [0, 1, 2])           # the URL (index 3) was not emitted

    def test_csv_rows_and_flag(self):
        rows = list(csv.DictReader(io.StringIO(exports.indicators_csv(self.camp, self.crep))))
        self.assertEqual(len(rows), 4)
        self.assertEqual([r["on_the_wire"] for r in rows], ["yes", "yes", "yes", "no"])

    def test_csv_blocks_formulas(self):
        camp = json.loads(json.dumps(self.camp))
        camp["iocs"][0]["source"] = "=HYPERLINK(1)"
        rows = list(csv.DictReader(io.StringIO(exports.indicators_csv(camp, self.crep))))
        self.assertEqual(rows[0]["source"], "'=HYPERLINK(1)")

    def test_misp_event_only_wire_indicators_and_round_trip(self):
        ev = exports.misp_event(self.camp, self.crep)
        vals = sorted(a["value"] for a in ev["Event"]["Attribute"])
        self.assertEqual(vals, ["198.51.100.20", "203.0.113.10", "update-check.example.net"])
        back = parsers.parse_misp(json.dumps(ev))
        self.assertEqual(sorted(i["value"] for i in back), vals)
        self.assertEqual(json.dumps(ev, sort_keys=True), json.dumps(exports.misp_event(self.camp, self.crep), sort_keys=True))

    def test_write_all_includes_new_files(self):
        with tempfile.TemporaryDirectory() as d:
            paths = exports.write_all(self.camp, self.crep, os.path.join(d, "x"))
            for k in ("csv", "misp"):
                self.assertTrue(os.path.isfile(paths[k]), k)


if __name__ == "__main__":
    unittest.main()
