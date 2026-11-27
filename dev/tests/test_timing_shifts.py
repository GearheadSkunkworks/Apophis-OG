"""Timeline slider, engine side: shifts are validated, clamped, linked, and move a scenario as a block.

Unit checks need no build. The build checks run one small day three ways (default, shifted, shifted
differently) and assert: the default is untouched, a shifted scenario starts exactly D later with the
same packet count, a linked pair moves together, the manifest records the shift, and the rest of the
day barely changes between two different shifts (the per-flow random isolation)."""
import json
import os
import shutil
import sys
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import opengenerator_build as OGB  # noqa: E402 - sys.path is set up before the import

INC = OGB.INC
NAMES = ["npm-http-errors", "npm-sql1-service-failure", "npm-fw-update", "ndr-edge-exploit"]


class Validation(unittest.TestCase):
    def test_empty_and_zero_are_the_default(self):
        self.assertEqual(INC.normalize_shifts(None, NAMES), {})
        self.assertEqual(INC.normalize_shifts({}, NAMES), {})
        self.assertEqual(INC.normalize_shifts({"npm-http-errors": 0}, NAMES), {})

    def test_rejects_bad_shapes(self):
        for bad in ([], "x", {"npm-http-errors": 1.5}, {"npm-http-errors": True}, {"npm-http-errors": "5"}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                INC.normalize_shifts(bad, NAMES)

    def test_rejects_unknown_unselected_and_locked(self):
        with self.assertRaises(ValueError):
            INC.normalize_shifts({"no-such-scenario": 5}, NAMES)
        with self.assertRaises(ValueError):
            INC.normalize_shifts({"ndr-recon": 5}, NAMES)                  # real, but not selected
        with self.assertRaises(ValueError):
            INC.normalize_shifts({"ndr-ot-sanctioned-writes": 5}, ["ndr-ot-sanctioned-writes"])
        self.assertIsNone(INC.shift_limits("custom-import"))

    def test_limits_keep_every_scenario_inside_the_capture(self):
        for name in INC.REGISTRY:
            lim = INC.shift_limits(name)
            if lim is None:
                continue
            lo, hi = INC._window_min(name)
            self.assertGreaterEqual(lo + lim[0], 5 * 60, name)
            self.assertLessEqual(hi + lim[1], 21 * 60, name)
            self.assertLessEqual(lim[0], 0)
            self.assertGreaterEqual(lim[1], 0)

    def test_out_of_range_is_refused_not_clamped(self):
        lo, hi = INC.shift_limits("npm-http-errors")
        INC.normalize_shifts({"npm-http-errors": hi}, NAMES)
        with self.assertRaises(ValueError):
            INC.normalize_shifts({"npm-http-errors": hi + 1}, NAMES)
        with self.assertRaises(ValueError):
            INC.normalize_shifts({"npm-http-errors": lo - 1}, NAMES)

    def test_limited_scenarios_are_tighter_than_the_capture(self):
        for name in ("crp-weak-tls", "crp-expired-cert", "crp-plaintext-creds", "npm-nightly-backup"):
            lim = INC.shift_limits(name)
            self.assertLessEqual(lim[1] - lim[0], 150, name)
        self.assertEqual(INC.shift_limits("ndr-volt-typhoon")[0], -158)    # 12h50 window: little room either way

    def test_linked_pairs_move_together(self):
        for a, b in INC.SHIFT_PAIRS:
            self.assertEqual(INC.normalize_shifts({a: 10}, [a, b]), {a: 10, b: 10})
            self.assertEqual(INC.normalize_shifts({b: -10}, [a, b]), {a: -10, b: -10})
            self.assertEqual(INC.normalize_shifts({a: 10}, [a]), {a: 10})       # partner not selected: alone
            with self.assertRaises(ValueError):
                INC.normalize_shifts({a: 10, b: 20}, [a, b])

    def test_window_for_applies_the_shift(self):
        lo0, hi0 = INC.window_for("npm-http-errors", {})
        lo1, hi1 = INC.window_for("npm-http-errors", {"npm-http-errors": 7})
        self.assertEqual((lo1 - lo0, hi1 - hi0), (420, 420))
        INC.set_shifts({"npm-http-errors": 7})
        try:
            self.assertEqual(INC.window_for("npm-http-errors"), (lo1, hi1))
        finally:
            INC.set_shifts({})
        self.assertEqual(INC.window_for("npm-http-errors"), (lo0, hi0))


class FollowTheWindow(unittest.TestCase):
    """Two bits of scenario content that quoted a clock time now follow the scenario's window."""

    def test_anonymous_ftp_syslog_login_follows_the_first_session(self):
        from netgen import ftpfiles
        from netgen.model import local
        try:
            self.assertIn(b"08:17:00", ftpfiles.syslog_latest_log())             # the default is what it always was
            ftpfiles.set_first_login(local(9, 5, 30))
            log = ftpfiles.syslog_latest_log()
            self.assertIn(b"Mar  2 09:05:30", log)
            self.assertNotIn(b"08:17:00", log)
        finally:
            ftpfiles.set_first_login(None)
        self.assertIn(b"08:17:00", ftpfiles.syslog_latest_log())

    def test_campaign_is_not_moved_by_the_slider(self):
        self.assertIsNone(INC.shift_limits("campaign"))
        with self.assertRaises(ValueError):
            INC.normalize_shifts({"campaign": 5}, ["campaign"])


class Builds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="og-shift-")
        cls.runs = {k: cls._build(k, s) for k, s in (
            ("base", None),
            ("a", {"npm-http-errors": 120, "npm-sql1-service-failure": 60, "npm-fw-update": 30}),
            ("b", {"npm-http-errors": 60, "npm-sql1-service-failure": 60, "npm-fw-update": 30}))}

    @classmethod
    def _build(cls, key, shifts):
        out = os.path.join(cls.d, key + ".pcap")
        s = OGB.build(scale=0.004, out=out, keylog=os.path.join(cls.d, key + ".keys"),
                      inventory=os.path.join(DEV, "inventory.json"), certs_dir=None, iocs_prefix=None,
                      modules=NAMES, progress=False, shifts=shifts)
        with open(os.path.join(cls.d, s["manifest"])) as f:
            return s, json.load(f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_no_shift_leaks_between_runs(self):
        self.assertEqual(INC.SHIFTS, {})

    def test_shifted_scenarios_start_exactly_d_later(self):
        base, a = self.runs["base"][0]["by_scenario"], self.runs["a"][0]["by_scenario"]
        for n, d in (("npm-http-errors", 120), ("npm-sql1-service-failure", 60), ("npm-fw-update", 30),
                     ("ndr-edge-exploit", 30)):                           # the last one rides along with fw-update
            self.assertAlmostEqual(a[n]["first_ts"] - base[n]["first_ts"], d * 60, delta=0.01, msg=n)

    def test_scenario_content_is_the_same_size(self):
        # a shifted day draws from isolated streams, so counts drift a little from the default day (not from each other)
        base, a = self.runs["base"][0]["by_scenario"], self.runs["a"][0]["by_scenario"]
        for n in NAMES:
            self.assertAlmostEqual(a[n]["packets"], base[n]["packets"], delta=base[n]["packets"] * 0.15, msg=n)

    def test_same_shift_gives_the_same_content_whatever_else_moves(self):
        a, b = self.runs["a"][0]["by_scenario"], self.runs["b"][0]["by_scenario"]
        for n in ("npm-sql1-service-failure", "npm-fw-update", "ndr-edge-exploit"):      # shifted alike in both runs
            self.assertAlmostEqual(a[n]["packets"], b[n]["packets"], delta=a[n]["packets"] * 0.005, msg=n)

    def test_manifest_records_shift_and_uses_the_shifted_window(self):
        base, a = self.runs["base"][1], self.runs["a"][1]
        self.assertEqual(a["parameters"]["shifts"], self.runs["a"][0]["shifts"])
        self.assertEqual(base["parameters"]["shifts"], {})
        sc = {x["id"]: x for x in a["scenarios"]}
        b0 = {x["id"]: x for x in base["scenarios"]}
        self.assertEqual(sc["npm-http-errors"]["shift_min"], 120)
        self.assertNotIn("shift_min", b0["npm-http-errors"])
        self.assertEqual(sc["npm-http-errors"]["planned_window"]["start_min"],
                         b0["npm-http-errors"]["planned_window"]["start_min"] + 120)
        for x in a["scenarios"]:
            self.assertTrue(x["emitted_in_window"], x["id"])               # judged against the shifted window

    def test_the_rest_of_the_day_does_not_follow_the_shift(self):
        a, b = self.runs["a"][0]["by_scenario"], self.runs["b"][0]["by_scenario"]
        na, nb = a["normal-day"]["packets"], b["normal-day"]["packets"]
        self.assertLess(abs(na - nb), na * 0.003)


if __name__ == "__main__":
    unittest.main()
