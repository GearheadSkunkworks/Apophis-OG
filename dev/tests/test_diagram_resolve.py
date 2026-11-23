"""Plan-mode resolver against the real netgen.campaign.hosts resolver (M4b S1).

Run from dev/:  python -m unittest tests.test_diagram_resolve
"""
import copy
import unittest

import make_diagram as M
from netgen.campaign import hosts as HS
from diagrams.campaign import resolve as R
from tests.test_actions_a import make_world, INVENTORY

CAMPAIGN = {
    "meta": {"seed": 7},
    "options": {},
    "iocs": [
        {"type": "ipv4", "value": "185.220.101.5", "role": "c2"},
        {"type": "domain", "value": "update.badcdn.example", "role": "c2"},
        {"type": "ipv4", "value": "45.9.148.10", "role": "exfil"},
        {"type": "url", "value": "http://pay.load.example/a.bin", "role": "payload"},
        {"type": "ipv4", "value": "91.92.240.1", "role": "scanner"},
        {"type": "sha256", "value": "ab" * 32, "role": "payload"},
    ],
}


def _ctx(with_ot=False):
    """with_ot keeps the OT hosts in the inventory (a truthy ot_nets dict is the gather switch)."""
    return M.DiagramContext(M.gather(INVENTORY, ot_nets={"cell": None} if with_ot else None), [], [])


class Internal(unittest.TestCase):
    def test_fixed_roles_match_real(self):
        real, plan = make_world(), _ctx()
        for ref in ("ws", "dc", "file", "sql", "web", "server", "host:SENSOR1", "host:DC2", "host:MGMT1",
                    "host:WEB3", "FILE1"):
            h = HS.resolve_internal(real, ref, CAMPAIGN["options"])
            r = R.resolve_ref(plan, ref, CAMPAIGN)
            self.assertTrue(r["exists"], ref)
            self.assertEqual((r["label"], r["ip"]), (h.name, h.ip), ref)
            self.assertEqual(r["zone"], "server" if h.ip.startswith("10.10.20.") else "user", ref)

    def test_server_lateral_target(self):
        opts = {"lateral_target": "sql"}
        real = HS.resolve_internal(make_world(), "server", opts)
        self.assertEqual(R.resolve_ref(_ctx(), "server", {"options": opts})["label"], real.name)

    def test_workstation_choices(self):
        real, plan = make_world(), _ctx()
        ws = HS.resolve_internal(real, "ws")
        for ref in ("ws2", "any_ws"):
            h = HS.resolve_internal(real, ref)
            r = R.resolve_ref(plan, ref, CAMPAIGN)
            self.assertTrue(r["exists"] and r["approx"])
            self.assertEqual(r["zone"], "user")
            self.assertTrue(r["label"].startswith("EXL-WS-"))
            self.assertNotEqual(r["label"], ws.name)       # ws2 must differ from ws, as in the real build
            self.assertTrue(h.name.startswith("EXL-WS-"))  # random in a real build, only the family is shared
        self.assertEqual(R.resolve_ref(plan, "ws", CAMPAIGN)["label"], ws.name)

    def test_ws_falls_back_when_047_missing(self):
        plan = _ctx()
        plan.data = dict(plan.data, hosts=[h for h in plan.data["hosts"] if h["hostname"] != "EXL-WS-047"])
        self.assertEqual(R.resolve_ref(plan, "ws", CAMPAIGN)["label"], "EXL-WS-001")

    def test_fw_resolves_to_the_inside_leg(self):
        real = HS.resolve_internal(make_world(), "fw")
        r = R.resolve_ref(_ctx(), "fw", CAMPAIGN)
        self.assertEqual(r["zone"], "perimeter")
        self.assertEqual(r["ip"], real.ip)

    def test_missing_and_ot(self):
        real = make_world()
        for ref in ("host:NOPE", "host:OTJUMP1", "host:IDMZ-HIST"):
            with self.assertRaises(HS.EndpointError):
                HS.resolve_internal(real, ref)
            self.assertFalse(R.resolve_ref(_ctx(), ref, CAMPAIGN)["exists"], ref)

    def test_ot_present(self):
        plan = _ctx(with_ot=True)
        r = R.resolve_ref(plan, "host:OTJUMP1", CAMPAIGN)
        self.assertTrue(r["exists"])
        self.assertEqual(r["zone"], "ot")

    def test_default_ctx_and_determinism(self):
        a = R.resolve_ref(None, "dc", CAMPAIGN)
        self.assertEqual(a["label"], "EXL-DC1")
        c = copy.deepcopy(CAMPAIGN)
        self.assertEqual(R.resolve_ref(_ctx(), "ws2", c), R.resolve_ref(_ctx(), "ws2", c))


class External(unittest.TestCase):
    def test_match_real_addresses(self):
        real = make_world()
        camp = copy.deepcopy(CAMPAIGN)
        for ref in ("attacker", "c2:0", "c2:1", "c2:5", "exfil:0", "payload:0", "payload:1", "scanner:0",
                    "phish:0", "tor:0", "brute:0", "ioc:1", "ioc:3"):
            h, idx, ext = HS.resolve_endpoint(real, ref, camp)
            r = R.resolve_ref(_ctx(), ref, camp)
            self.assertTrue(ext)
            self.assertTrue(r["exists"], ref)
            self.assertEqual((r["ip"], r["label"]), (h.ip, h.name), ref)
            self.assertEqual(r["zone"], "internet")

    def test_real_address_mode(self):
        camp = copy.deepcopy(CAMPAIGN)
        camp["options"] = {"address_mode": "real"}
        real = make_world()
        h, _, _ = HS.resolve_endpoint(real, "ioc:0", camp)
        self.assertEqual(R.resolve_ref(_ctx(), "ioc:0", camp)["ip"], h.ip)
        self.assertEqual(h.ip, "185.220.101.5")

    def test_no_indicators_attacker(self):
        camp = {"meta": {"seed": 3}, "options": {}, "iocs": []}
        h, idx, _ = HS.resolve_endpoint(make_world(), "attacker", camp)
        r = R.resolve_ref(_ctx(), "attacker", camp)
        self.assertEqual((r["ip"], r["label"]), (h.ip, h.name))

    def test_unresolvable(self):
        camp = {"meta": {"seed": 3}, "options": {}, "iocs": []}
        self.assertFalse(R.resolve_ref(_ctx(), "c2:0", camp)["exists"])
        self.assertFalse(R.resolve_ref(_ctx(), "ioc:9", CAMPAIGN)["exists"])
        self.assertFalse(R.resolve_ref(_ctx(), "ioc:5", CAMPAIGN)["exists"])   # sha256 is not addressable


if __name__ == "__main__":
    unittest.main()
