"""Timeline slider, server side: /api/modules carries the numbers behind each window, /api/generate checks
shifts and passes them on only when set, and saved sessions keep them."""
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import server  # noqa: E402
import sessions_api  # noqa: E402
from tests.test_campaign_api import ApiCase, FakeRun  # noqa: E402


class Modules(unittest.TestCase):
    def test_numbers_match_the_window_text_and_limits_are_sane(self):
        mods = [m for m in server.get_modules() if "start_min" in m]
        self.assertGreater(len(mods), 50)
        for m in mods:
            self.assertLess(m["start_min"], m["end_min"], m["name"])
            lim = m["shift_limits"]
            if lim is not None:
                self.assertLessEqual(lim[0], 0)
                self.assertGreaterEqual(lim[1], 0)
                self.assertGreaterEqual(m["start_min"] + lim[0], 2)            # inside the capture, minutes after 05:00
                self.assertLessEqual(m["end_min"] + lim[1], 16 * 60)
        by = {m["name"]: m for m in mods}
        self.assertIsNone(by["ndr-ot-sanctioned-writes"]["shift_limits"])
        self.assertEqual(by["npm-fw-update"]["shift_partner"], "ndr-edge-exploit")

    def test_js_window_text_matches_the_server(self):
        mods = [m for m in server.get_modules() if "start_min" in m]
        js = ("const C=require(%r);const m=JSON.parse(process.argv[1]);"
              "console.log(JSON.stringify(m.map(x=>C.formatWindow(x.start_min,x.end_min))))"
              % os.path.join(DEV, "ui", "scenario-cards.js"))
        out = subprocess.run(["node", "-e", js, json.dumps([{"start_min": m["start_min"], "end_min": m["end_min"]} for m in mods])],
                             capture_output=True, text=True, check=True).stdout
        self.assertEqual(json.loads(out), [m["window"] for m in mods])


class Generate(ApiCase):
    def run_gen(self, body):
        fake = FakeRun()
        with mock.patch.object(server, "run_generator", fake):
            s, d = self.post("/api/generate", body)
            if s == 200:
                self.assertTrue(fake.ev.wait(5))
        return s, d, fake

    def test_valid_shifts_are_passed_on_as_a_keyword(self):
        s, d, fake = self.run_gen({"out_dir": self.tmp, "modules": ["npm-fw-update", "ndr-edge-exploit"], "shifts": {"npm-fw-update": 30}})
        self.assertEqual(s, 200, d)
        a, kw = fake.calls[0]
        self.assertEqual(len(a), 13)
        self.assertEqual(kw, {"shifts": {"npm-fw-update": 30, "ndr-edge-exploit": 30}})     # the linked partner rides along

    def test_no_shifts_changes_nothing(self):
        for body in ({"modules": []}, {"modules": [], "shifts": {}}, {"modules": ["npm-http-errors"], "shifts": {"npm-http-errors": 0}}):
            s, d, fake = self.run_gen(dict(body, out_dir=self.tmp))
            self.assertEqual(s, 200, d)
            self.assertEqual(fake.calls[0][1], {})

    def test_bad_shifts_are_a_400_and_nothing_starts(self):
        for shifts in ({"npm-http-errors": 99999}, {"npm-http-errors": 1.5}, {"npm-http-errors": True}, {"ndr-recon": 5},
                       {"nope": 5}, ["x"], "x", {"ndr-ot-sanctioned-writes": 5}):
            s, d, fake = self.run_gen({"out_dir": self.tmp, "modules": ["npm-http-errors"], "shifts": shifts})
            self.assertEqual(s, 400, shifts)
            self.assertIn("error", d)
            self.assertEqual(fake.calls, [], shifts)


class Sessions(unittest.TestCase):
    def test_shifts_survive_the_session_round_trip_and_are_cleaned(self):
        st = sessions_api.clean_state({"controls": {"scale": 1}, "shifts": {"a": 5, "b": 0, "c": 1.5, "d": True, "e": "9", 7: 3, "f": -40}})
        self.assertEqual(st["shifts"], {"a": 5, "f": -40})
        self.assertEqual(sessions_api.clean_state({"controls": {"scale": 1}})["shifts"], {})     # old sessions load unchanged


if __name__ == "__main__":
    unittest.main()
