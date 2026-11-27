"""Drift check: scenario_meta.json must still match the last run of tools/verify_scenario_meta.py.

Run from dev/:  python -m unittest tests.test_meta_verification_stays_true
Fails when metadata is edited (new scenario, new declared protocol) without re-running the tool.
"""
import json
import os
import sys
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import scenario_meta  # noqa: E402 - sys.path is set up before the import

with open(scenario_meta.PATH, encoding="utf-8") as _f:
    META = {e["id"]: e for e in json.load(_f)["scenarios"]}
with open(scenario_meta.VERIFY_PATH, encoding="utf-8") as _f:
    RESULTS = json.load(_f)["results"]

# Known exceptions: the scenario is recipe-driven
# and has nothing to build standalone (inconclusive). Their declared lists need not match a pass.
KNOWN_EXCEPTIONS = {"campaign", "custom-import"}


class MetaVerificationStaysTrue(unittest.TestCase):
    def test_every_result_has_an_entry(self):
        self.assertEqual(sorted(set(RESULTS) - set(META)), [])

    def test_every_entry_has_a_result(self):
        self.assertEqual(sorted(set(META) - set(RESULTS)), [])

    def test_declared_protocols_were_verified(self):
        for sid, r in RESULTS.items():
            if sid in KNOWN_EXCEPTIONS or r["verdict"] != "pass" or sid not in META:
                continue
            with self.subTest(sid):
                seen = set(r["verified"]) | set(r["carrier_only"]) | set(r["unverifiable"])
                self.assertEqual([p for p in META[sid]["protocols"] if p not in seen], [],
                                 "metadata changed since the last verify_scenario_meta.py run")

    def test_exceptions_are_still_exceptions(self):
        for sid in KNOWN_EXCEPTIONS:
            self.assertNotEqual(RESULTS[sid]["verdict"], "pass", sid)


if __name__ == "__main__":
    unittest.main()
