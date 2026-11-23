"""Fast fixed-seed fuzz run over the untrusted-input parsers (full harness: tools/fuzz.py).

Run from dev/:  python -m unittest tests.test_fuzz_parsers
A longer pass:  python tools/fuzz.py --iterations 20000 --seed 1

What is asserted (see tools/fuzz.py): no uncaught exception other than ValueError/CampaignError/FeedError/
ApiError, under 2 s per input, bounded memory, and IOC records that satisfy the section-1 contract with no
control characters in `value`. The run is deterministic for a given seed.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
for p in (DEV, os.path.join(DEV, "tools")):
    if p not in sys.path:
        sys.path.insert(0, p)

import fuzz                                            # noqa: E402


class ContractChecker(unittest.TestCase):
    def test_checker_accepts_a_good_record_and_flags_bad_ones(self):
        good = {"type": "ipv4", "value": "203.0.113.9", "role": "c2", "confidence": 80, "source": "t", "tags": [],
                "techniques": [], "first_seen": None, "note": "", "why": "x"}
        self.assertEqual(fuzz.contract_problems(good), [])
        for patch in ({"value": "203.0.113.9\x00"}, {"value": "a‮.com", "type": "domain"}, {"role": "boss"},
                      {"confidence": 101}, {"confidence": True}, {"tags": "x"}, {"type": "nope"}, {"note": "a\x01b"}):
            self.assertTrue(fuzz.contract_problems(dict(good, **patch)), patch)


class FastFuzz(unittest.TestCase):
    def test_hostile_subset(self):
        fails = fuzz.fuzz(0, 1, hostile=True, hostile_names=fuzz.FAST_HOSTILE, quiet=True)
        self.assertEqual(fails, [], "\n".join("%s %s %s" % (f["target"], f["input"], f["why"]) for f in fails))

    def test_seeded_mutations(self):
        fails = fuzz.fuzz(500, 20261120, hostile=False, quiet=True, trace_every=25)
        self.assertEqual(fails, [], "\n".join("%s %s %s" % (f["target"], f["input"], f["why"]) for f in fails))

    def test_fixtures_are_seeds(self):
        seeds = fuzz.load_seeds()
        self.assertTrue(any(k.startswith("intel/") for k in seeds))
        self.assertTrue(any(k.startswith("campaigns/") for k in seeds))


if __name__ == "__main__":
    unittest.main()
