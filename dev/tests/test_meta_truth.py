"""Every campaign-action display filter must match the traffic its action really emits (tshark, with the TLS key log).

Filters in ``NEEDS_ENV`` are exempt, each with its reason; keep that list empty unless a filter truly needs keys or
settings the example capture cannot supply.
"""
import os
import sys
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "tools"))
import meta_truth  # noqa: E402

# (token, filter label) -> reason. Nothing needs an exemption at the moment.
NEEDS_ENV = {}


@unittest.skipUnless(os.path.exists(meta_truth.TSHARK), "tshark is not installed")
class MetaTruth(unittest.TestCase):
    def test_filters_match_their_traffic(self):
        rows = meta_truth.run()
        self.assertGreater(len(rows), 100)
        bad = [r for r in rows if r["status"] != "match" and (r["token"], r["what"]) not in NEEDS_ENV]
        self.assertFalse(bad, "\n".join("%s / %s: %s %s [%s]" % (r["token"], r["what"], r["status"],
                                                               r["rendered"] or r["template"], r["detail"]) for r in bad))


if __name__ == "__main__":
    unittest.main()
