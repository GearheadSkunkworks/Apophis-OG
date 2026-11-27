"""Pure comparison / alias logic of tools/verify_scenario_meta.py (no builds).

Run from dev/:  python -m unittest tests.test_verify_scenario_meta
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
import verify_scenario_meta as V  # noqa: E402 - sys.path is set up before the import


class TestResolve(unittest.TestCase):
    def test_exact_and_parenthetical_labels(self):
        self.assertEqual(V.resolve("DCE/RPC (svcctl)")[1], ["DCE/RPC"])
        self.assertEqual(V.resolve("TDS (SQL Server)")[1], ["TDS"])
        self.assertEqual(V.resolve("SMB (named pipe)")[0], "carrier")   # full-label entry wins over the base

    def test_unknown_label(self):
        self.assertEqual(V.resolve("Quantum Frobnicator"), ("unknown", []))

    def test_every_alias_kind_is_valid(self):
        for k, (kind, _names) in V.ALIASES.items():
            self.assertIn(kind, ("direct", "carrier", "l4", "none"), k)
            self.assertEqual(k, k.lower())


class TestCompare(unittest.TestCase):
    obs = {"SMB2": 10, "LDAP": 5, "ICMP": 3, "ARP": 9, "HTTPS": 4}

    def test_alias_match(self):
        c = V.compare(["SMB", "LDAP", "DCE/RPC"], self.obs)
        self.assertEqual(c["verified"], ["SMB", "LDAP"])
        self.assertEqual(c["missing"], ["DCE/RPC"])

    def test_carrier_only(self):
        c = V.compare(["WebSocket upgrade"], self.obs)
        self.assertEqual(c["carrier_only"], ["WebSocket upgrade"])
        self.assertEqual(c["missing"], [])

    def test_l4_generic_label(self):
        self.assertEqual(V.compare(["TCP"], {}, {"tcp": 7})["verified"], ["TCP"])
        self.assertEqual(V.compare(["TCP"], {}, {"tcp": 0})["missing"], ["TCP"])

    def test_port_evidence_is_weaker(self):
        c = V.compare(["IPsec/IKE"], {"UDP-other": 3}, ports={"udp/4500": 3})
        self.assertEqual(c["carrier_only"], ["IPsec/IKE"])
        self.assertEqual(V.compare(["IPsec/IKE"], {"UDP-other": 3})["missing"], ["IPsec/IKE"])

    def test_unverifiable_and_unknown_never_missing(self):
        c = V.compare(["MPTCP", "Depends on the recipe", "Quantum Frobnicator"], self.obs)
        self.assertEqual(c["missing"], [])
        self.assertEqual(len(c["unverifiable"]), 3)

    def test_extra_excludes_explained_and_ambient(self):
        c = V.compare(["SMB"], self.obs)
        self.assertEqual(c["extra"], ["HTTPS", "ICMP", "LDAP"])      # ARP ambient, SMB2 explained

    def test_zero_count_is_absent(self):
        self.assertEqual(V.compare(["ICMP"], {"ICMP": 0})["missing"], ["ICMP"])


class TestVerdict(unittest.TestCase):
    def cmp(self, **kw):
        base = {"verified": [], "carrier_only": [], "missing": [], "unverifiable": [], "extra": []}
        base.update(kw)
        return base

    def test_pass(self):
        self.assertEqual(V.verdict(self.cmp(verified=["DNS"]), 10)[0], "pass")

    def test_fail_missing_and_no_packets(self):
        self.assertEqual(V.verdict(self.cmp(verified=["DNS"], missing=["SIP"]), 10)[0], "fail")
        self.assertEqual(V.verdict(self.cmp(verified=["DNS"]), 0)[0], "fail")

    def test_inconclusive_cases(self):
        self.assertEqual(V.verdict(self.cmp(), 10, recipe_driven=True)[0], "inconclusive")
        self.assertEqual(V.verdict(self.cmp(), 10, error="timeout")[0], "inconclusive")
        self.assertEqual(V.verdict(self.cmp(unverifiable=["MPTCP"]), 10)[0], "inconclusive")

    def test_carrier_only_counts_as_pass(self):
        self.assertEqual(V.verdict(self.cmp(carrier_only=["NTLM"]), 10)[0], "pass")


if __name__ == "__main__":
    unittest.main()
