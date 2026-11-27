"""S4: IPv6 scenario variants. Campaign option ``ip_family`` (v4 | v6 | dual) and the two IPv6 link-local scenarios.

Proves: the option off (the default) changes nothing; each v6 variant is clean under tshark (no malformed frames,
expert errors or bad checksums) and under the independent IPv6 checker; builds are deterministic; the shared random
streams end exactly where they started; and no campaign action builds a TCP session behind the helper's back.
"""
import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from collections import Counter

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "checks"))
import check_ipv6                              # noqa: E402 - sys.path is set up first
import opengenerator_build as OGB              # noqa: E402 - sys.path is set up first
from netgen import dualstack                   # noqa: E402 - sys.path is set up first
from netgen import incidents as INC            # noqa: E402 - sys.path is set up first
from netgen.campaign import actions as ACT, schema   # noqa: E402 - sys.path is set up first
from selftest import PIN                       # noqa: E402 - sys.path is set up first
from tests.test_ipv6_dualstack import _key, _key6, _records   # noqa: E402 - sys.path is set up first
from tshark_locate import find_tshark          # noqa: E402 - sys.path is set up first

TSHARK = find_tshark()
ACTIONS_DIR = os.path.join(DEV, "netgen", "campaign", "actions")
NEW = ("ndr-ipv6-rogue-ra", "ndr-ipv6-nd-flood")
BAD = ('_ws.malformed || _ws.expert.severity == "Error" || tcp.checksum.status == "Bad" || '
       'udp.checksum.status == "Bad" || icmpv6.checksum.status == "Bad"')

# (action, from, to, params): the highest-value twins, by tactic. Small parameters keep the build short.
GROUPS = {
    "recon": [("icmp_sweep", "ws", "server", {"max_hosts": 6}), ("syn_scan", "ws", "server", {"max_hosts": 3}),
              ("port_probe", "ws", "file", {}), ("ldap_recon", "ws", "dc", {"max_entries": 10})],
    "lateral": [("smb_admin_exec", "ws", "file", {}), ("rdp_session", "ws", "dc", {"duration_s": 15.0}),
                ("winrm_exec", "ws", "dc", {}), ("wmi_exec", "ws", "file", {})],
    "c2": [("https_beacon", "ws", "c2:0", {"count": 2, "interval_s": 5.0}),
           ("dns_beacon", "ws", "c2:0", {"count": 3, "interval_s": 5.0})],
    "exfil": [("https_upload", "ws", "exfil:0", {"total_bytes": 300000}),
              ("dns_exfil", "ws", "c2:0", {"queries": 12}), ("dns_tunnel", "ws", "c2:0", {"bursts": 1, "per_burst": 8}),
              ("icmp_tunnel", "ws", "c2:0", {"count": 12})],
}
EXPECT = {"recon": {"ipv6", "icmpv6", "ldap"}, "lateral": {"ipv6", "smb2", "rdp", "dcerpc"},
          "c2": {"ipv6", "tls", "dns"}, "exfil": {"ipv6", "tls", "dns", "icmpv6"}}


def campaign(ip_family=None, only=None, start="10:00"):
    """One stage per group, so the whole set builds once. ``ip_family`` None leaves the option out (the default)."""
    stages = []
    for i, (g, acts) in enumerate(GROUPS.items()):
        if only and g != only:
            continue
        stages.append({"id": "s%d" % i, "name": g, "tactic": "discovery", "techniques": ["T1046"], "duration_s": 120, "fast_s": 40,
                       "actions": [{"action": a, "from": f, "to": t, "params": p} for a, f, t, p in acts]})
    opts = {"address_mode": "mapped", "start": start}
    if ip_family:
        opts["ip_family"] = ip_family
    return {"schema": "opengenerator.campaign/1", "meta": {"name": "S4", "id": "s4", "seed": 5}, "options": opts,
            "iocs": [{"type": "ipv4", "value": "203.0.113.77", "role": "c2", "source": "test"},
                     {"type": "ipv4", "value": "203.0.113.90", "role": "exfil", "source": "test"}], "stages": stages}


def _build(d, stem, **kw):
    kw.setdefault("modules", [])
    return OGB.build(scale=0.004, out=os.path.join(d, stem + ".pcap"), keylog=os.path.join(d, stem + ".keys"),
                     inventory=os.path.join(DEV, "inventory.json"), certs_dir=None, iocs_prefix=None, progress=False, **kw)


class _NoDay(OGB.Day):
    def build(self):
        """The normal day switched off, so a scenario's own packets are the whole capture."""


def _scenario_only(d, stem, **kw):
    real, OGB.Day = OGB.Day, _NoDay
    try:
        return _build(d, stem, **kw)
    finally:
        OGB.Day = real


def _tshark(path, *extra):
    base = [TSHARK, "--disable-protocol", "ssh", "-r", path, "-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE"]
    return subprocess.run(base + list(extra), capture_output=True, text=True, timeout=600, check=True).stdout


def _protocols(path):
    out = set()
    for line in _tshark(path, "-T", "fields", "-e", "frame.protocols").splitlines():
        out.update(line.split(":"))
    return out


def _identity(path):
    """Deterministic identity of every frame: the 5-tuple (payload bytes carry random filler, so they are not compared)."""
    return Counter(_key6(f) if f[12:14] == b"\x86\xdd" else _key(f) for _, f in _records(path))


def _entries(r):
    return r["campaign"]["entries"]


class Structure(unittest.TestCase):
    def test_no_direct_tcp_session_in_campaign_actions(self):
        """Every action opens its sessions through ``ctx.tcp``, which is what the IPv6 context switches."""
        bad = []
        for name in sorted(os.listdir(ACTIONS_DIR)):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(ACTIONS_DIR, name), encoding="utf-8") as f:
                tree = ast.parse(f.read())
            for n in ast.walk(tree):
                if isinstance(n, ast.Call) and (getattr(n.func, "id", None) or getattr(n.func, "attr", None)) == "TcpSession":
                    bad.append("%s:%d" % (name, n.lineno))
        self.assertEqual(bad, [], "use ctx.tcp(...) so ip_family can route the session")

    def test_option_in_schema(self):
        self.assertIn("ip_family", schema.OPTIONS)
        out, errs = schema.normalise_options({"ip_family": "v6"})
        self.assertEqual((out["ip_family"], errs), ("v6", []))
        self.assertEqual(schema.normalise_options(None)[0]["ip_family"], "v4")
        self.assertTrue(schema.normalise_options({"ip_family": "v5"})[1])
        with open(schema.SCHEMA_FILE, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["properties"]["options"]["properties"]["ip_family"]["enum"], ["v4", "v6", "dual"])

    def test_v4_context_is_inert(self):
        from tests.test_actions_a import make_world
        ctx = make_world()
        self.assertIsNone(ctx.v6)
        h = list(ctx.h.values())
        self.assertEqual(type(ctx.tcp(h[0], h[1], 80, 1.0)).__name__, "TcpSession")


class Isolation(unittest.TestCase):
    def test_v6_action_leaves_streams_and_ports(self):
        """An action run on the IPv6 context leaves every shared random stream and every host port where it was."""
        from tests.test_actions_a import make_world
        from netgen.identity import H
        ctx = make_world()
        L = dualstack.campaign_layer(ctx)
        src, dst = ctx.h[H("WS-009")], ctx.h[H("FILE1")]
        before = [g.getstate() for g in L.gens]
        ports = [(h, h._port) for h in L.pool]
        pk = L.isolated("t", lambda: ACT.get("smb_admin_exec").fn(L.ctx, src, dst, ts=1773489600.0))
        self.assertTrue(pk)
        self.assertEqual([g.getstate() for g in L.gens], before)
        self.assertEqual([(h, h._port) for h in L.pool], ports)

    def test_new_scenarios_leave_streams_alone(self):
        """Scheduling and running either scenario's flows draws nothing from the shared streams."""
        from tests.test_actions_a import make_world

        class Sched:
            def __init__(self):
                self.items = []

            def schedule(self, ts, factory, tag="misc"):
                self.items.append(factory)
        for n in NEW:
            ctx = make_world()
            gens = dualstack.campaign_layer(ctx).gens
            before = [g.getstate() for g in gens]
            eng = Sched()
            INC.REGISTRY[n].builder(ctx, eng, "t", (1773489600.0, 1773489600.0 + 1800))
            self.assertEqual([g.getstate() for g in gens], before, n + " (scheduling)")
            self.assertTrue(eng.items, n)
            for fn in eng.items:
                self.assertTrue(fn(), n)
                self.assertEqual([g.getstate() for g in gens], before, n + " (running)")


@unittest.skipUnless(TSHARK, "tshark is not installed")
class CampaignFamily(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ACT.load_all()
        cls.d = tempfile.mkdtemp(prefix="og-s4-")
        cls.v4 = _build(cls.d, "v4", campaigns=[campaign()])
        cls.explicit = _build(cls.d, "explicit", campaigns=[campaign("v4")])
        cls.v6 = _build(cls.d, "v6", campaigns=[campaign("v6")])
        cls.again = _build(cls.d, "again", campaigns=[campaign("v6")])
        cls.dual = _build(cls.d, "dual", campaigns=[campaign("dual")])
        cls.v6_recon = _build(cls.d, "v6r", campaigns=[campaign("v6")], modules=["ndr-recon"])
        cls.recon = _build(cls.d, "recon", modules=["ndr-recon"], campaigns=[campaign(start="23:30")])   # same endpoints, nothing runs
        cls.only = _scenario_only(cls.d, "only", campaigns=[campaign("v6")])

    def test_default_equals_explicit_v4(self):
        self.assertEqual(self.v4["packets"], self.explicit["packets"])
        self.assertEqual(self.v4["protocols"], self.explicit["protocols"])
        self.assertEqual(_identity(self.v4["pcap"]), _identity(self.explicit["pcap"]))
        self.assertTrue(all(e["ip_family"] == "v4" for e in _entries(self.v4)))

    def test_the_day_and_other_scenarios_do_not_move(self):
        """A v6 campaign draws nothing from the shared streams: the day and ndr-recon are what they are when the campaign
        resolves its endpoints but runs nothing (resolving hosts is the runner's own, family-independent draw)."""
        for k in ("normal-day", "ndr-recon"):
            self.assertEqual(self.v6_recon["by_scenario"][k]["packets"], self.recon["by_scenario"][k]["packets"], k)

    def test_every_action_ran_over_v6(self):
        es = _entries(self.v6)
        self.assertEqual(len(es), sum(len(a) for a in GROUPS.values()))
        for e in es:
            self.assertEqual((e["status"], e["ip_family"]), ("ok", "v6"), (e["action"], e["error"]))
            self.assertIn(":", e["to_host"]["ip6"])
            self.assertGreater(e["packets"], 0, e["action"])

    def test_dual_alternates(self):
        es = _entries(self.dual)
        self.assertEqual({e["ip_family"] for e in es}, {"v4", "v6"})
        self.assertTrue(all(e["status"] == "ok" for e in es))

    def test_v6_only_capture_is_pure_ipv6(self):
        counts, fails, _, first = check_ipv6.check(self.only["pcap"], 20, ())
        self.assertFalse(sum(fails.values()), first)
        self.assertEqual(counts["frames"], counts["ipv6"])               # nothing but IPv6 (no ARP, no IPv4)

    def test_checker_on_the_full_capture(self):
        for r in (self.v6, self.dual):
            counts, fails, _, first = check_ipv6.check(r["pcap"], 20, ())
            self.assertFalse(sum(fails.values()), first)
            self.assertGreater(counts["ipv6"], 0)

    def test_tshark_clean(self):
        for r in (self.only, self.v6, self.dual):
            self.assertEqual(_tshark(r["pcap"], "-Y", BAD), "", r["pcap"])

    def test_expected_dissectors_per_group(self):
        for g in GROUPS:
            r = _scenario_only(self.d, g, campaigns=[campaign("v6", only=g)])
            self.assertEqual(_tshark(r["pcap"], "-Y", BAD), "", g)
            self.assertEqual(EXPECT[g] - _protocols(r["pcap"]), set(), g)

    def test_deterministic(self):
        self.assertEqual(self.v6["packets"], self.again["packets"])
        self.assertEqual(self.v6["protocols"], self.again["protocols"])
        self.assertEqual(_identity(self.v6["pcap"]), _identity(self.again["pcap"]))


@unittest.skipUnless(TSHARK, "tshark is not installed")
class NewScenarios(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="og-s4n-")
        cls.alone = {n: _scenario_only(cls.d, n, modules=[n]) for n in NEW}
        cls.again = {n: _scenario_only(cls.d, n + "-2", modules=[n]) for n in NEW}
        cls.day = _build(cls.d, "day", modules=list(NEW))

    def test_additive(self):
        self.assertEqual(self.day["by_scenario"]["normal-day"]["packets"], PIN)
        self.assertEqual(self.day["packets"], PIN + sum(self.day["by_scenario"][n]["packets"] for n in NEW))
        for n in NEW:
            self.assertEqual(self.day["by_scenario"][n]["packets"], self.alone[n]["packets"], n)

    def test_clean(self):
        for n, r in self.alone.items():
            counts, fails, _, first = check_ipv6.check(r["pcap"], 20, ())
            self.assertFalse(sum(fails.values()), first)
            self.assertGreater(counts["ipv6"], 0, n)
            self.assertEqual(_tshark(r["pcap"], "-Y", BAD), "", n)

    def test_rogue_ra_story(self):
        p = self.alone["ndr-ipv6-rogue-ra"]["pcap"]
        ras = _tshark(p, "-Y", "icmpv6.type == 134", "-T", "fields", "-e", "eth.src", "-e", "icmpv6.nd.ra.router_lifetime").splitlines()
        self.assertGreater(len(ras), 1)
        self.assertEqual(len({r.split("\t")[0] for r in ras}), 1, "one rogue source")
        self.assertEqual({r.split("\t")[1] for r in ras}, {"0"}, "no default-router lifetime")
        for want in ("dhcpv6.msgtype == 2", "dhcpv6.msgtype == 7", "dns.qry.name contains wpad", "ntlmssp.messagetype == 0x00000003",
                     'http.request.uri == "/wpad.dat"', "smb2 && ip"):
            self.assertTrue(_tshark(p, "-Y", want, "-T", "fields", "-e", "frame.number").split(), want)

    def test_nd_flood_story(self):
        p = self.alone["ndr-ipv6-nd-flood"]["pcap"]
        srcs = _tshark(p, "-Y", "icmpv6.type == 134", "-T", "fields", "-e", "eth.src").split()
        self.assertGreater(len(srcs), 200)
        self.assertGreater(len(set(srcs)), len(srcs) * 0.9, "a new source for nearly every advertisement")
        pfx = _tshark(p, "-Y", "icmpv6.type == 134", "-T", "fields", "-e", "icmpv6.opt.prefix").split()
        self.assertGreater(len(set(pfx)), len(pfx) * 0.9, "a new prefix for nearly every advertisement")
        self.assertTrue(_tshark(p, "-Y", "icmpv6.type == 135", "-T", "fields", "-e", "frame.number").split())

    def test_deterministic(self):
        for n in NEW:
            self.assertEqual(self.alone[n]["packets"], self.again[n]["packets"])
            self.assertEqual(self.alone[n]["protocols"], self.again[n]["protocols"])
            self.assertEqual(_identity(self.alone[n]["pcap"]), _identity(self.again[n]["pcap"]))


if __name__ == "__main__":
    unittest.main()
