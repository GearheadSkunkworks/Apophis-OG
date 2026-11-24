"""Tests for the campaign runner, console, exports, engine hooks and the RFC 791 validator.

Run from dev/:  python -m unittest tests.test_campaign_runner

The campaigns here use two STUB actions registered inside this file (never in the package), so the
runner is tested on its own. Each build is a real engine build at a small scale on a pinned day.
"""
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
if DEV not in sys.path:
    sys.path.insert(0, DEV)

import opengenerator_build as OGB                      # noqa: E402
from netgen import flows as F                          # noqa: E402
from netgen.campaign import actions as ACT, console, runner, hosts   # noqa: E402
from checks import check_rfc791 as RFC                 # noqa: E402

INVENTORY = os.path.join(DEV, "inventory.json")
DAY = "2026-03-14"
SCALE = 0.002
IP_C2 = "203.0.113.77"


def stub_udp(ctx, src, dst, *, ts, count=2):
    out = []
    for i in range(count):
        out.append(ctx.udp(src, dst, src.eph(), 9999, b"stub%d" % i, ts + 0.1 * i))
    s = ctx.tcp(src, dst, 8443, ts + 1.0).handshake()
    s.c2s(b"hello " * 20)
    s.s2c(b"world " * 30)
    return F.merged(out, s.close())


def _j(path):
    with open(path) as f:
        return json.load(f)


def count_ip(pcap, ip):
    """Frames with `ip` as IPv4 source or destination (independent of the engine)."""
    import socket
    want = socket.inet_aton(ip)
    n = 0
    with open(pcap, "rb") as f:
        f.read(24)
        while True:
            h = f.read(16)
            if len(h) < 16:
                return n
            cap = struct.unpack("<I", h[8:12])[0]
            d = f.read(cap)
            if d[12:14] == b"\x08\x00" and (d[26:30] == want or d[30:34] == want):
                n += 1


def stub_boom(ctx, src, dst, *, ts):
    raise RuntimeError("stub failure")


def _specs():
    return [
        ACT.ActionSpec(token="zz_stub_udp", fn=stub_udp, title="Stub UDP+TCP", tactic="command-and-control",
                       techniques=["T1071.001"], protocols=["UDP", "TCP"], summary="test stub",
                       params={"count": {"type": "int", "default": 2, "help": "datagrams"}},
                       src="internal", dst="external"),
        ACT.ActionSpec(token="zz_stub_boom", fn=stub_boom, title="Stub failure", tactic="discovery",
                       techniques=["T1046"], protocols=["TCP"], summary="always raises",
                       src="internal", dst="external"),
    ]


def campaign(actions=None, **options):
    acts = actions or [
        {"action": "zz_stub_udp", "from": "ws", "to": "c2:0", "params": {"count": 3}, "ioc": [0]},
        {"action": "zz_stub_udp", "from": "ws", "to": "c2:0", "params": {}, "at": 30},
    ]
    return {"schema": "opengenerator.campaign/1",
            "meta": {"name": "Runner Test", "id": "runner-test", "seed": 7},
            "options": dict({"address_mode": "mapped", "start": "10:00"}, **options),
            "iocs": [{"type": "ipv4", "value": IP_C2, "role": "c2", "source": "test"},
                     {"type": "sha256", "value": "a" * 64, "role": "payload", "source": "test"}],
            "stages": [
                {"id": "s1", "name": "Beacon", "tactic": "command-and-control", "techniques": ["T1071.001"],
                 "narrative": "the host beacons", "duration_s": 60, "fast_s": 20, "actions": acts},
                {"id": "s2", "name": "Again", "tactic": "command-and-control", "techniques": ["T1071.001"],
                 "duration_s": 30, "fast_s": 10,
                 "actions": [{"action": "zz_stub_udp", "from": "ws", "to": "c2:0"}]}]}


class RunnerBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.specs = []
        for sp in _specs():
            ACT.register(sp)
            cls.specs.append(sp.token)
        cls.tmp = tempfile.mkdtemp(prefix="og-camp-")
        cls.baseline = cls.build("base")["packets"]

    @classmethod
    def tearDownClass(cls):
        for t in cls.specs:
            ACT._REGISTRY.pop(t, None)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def build(cls, name, **kw):
        kw.setdefault("modules", [])
        return OGB.build(scale=SCALE, out=os.path.join(cls.tmp, name + ".pcap"),
                         keylog=os.path.join(cls.tmp, name + ".keys"), inventory=INVENTORY,
                         certs_dir=None, iocs_prefix=None, progress=False, date=DAY, **kw)


class TestRunner(RunnerBase):
    def test_campaign_builds_reports_and_exports(self):
        r = self.build("c1", campaigns=[campaign()])
        c = r["campaign"]
        self.assertEqual(c["built"], ["runner-test"])
        self.assertEqual(c["actions"], 3)
        self.assertEqual(c["emitted"], 3)
        # the report records every action with what it emitted
        crep = _j(c["exports"]["runner-test"]["campaign"])
        self.assertEqual(crep["meta"]["id"], "runner-test")
        # RFC 791 validity of the whole capture
        counts, fails, _ex, first = RFC.check(r["pcap"])
        self.assertEqual(fails, {}, first)
        self.assertGreater(counts["tcp"], 0)
        # exports
        paths = c["exports"]["runner-test"]
        for p in paths.values():
            self.assertTrue(os.path.getsize(p) > 0, p)
        stix = _j(paths["stix"])
        patterns = [o["pattern"] for o in stix["objects"]]
        self.assertEqual(len(patterns), 1, "only the C2 IP was emitted; the payload hash was not")
        self.assertNotIn(IP_C2, patterns[0], "mapped mode must export the mapped address")
        self.assertIn("198.", patterns[0])
        nav = _j(paths["navigator"])
        self.assertEqual([t["techniqueID"] for t in nav["techniques"]], ["T1071.001"])
        with open(paths["report"]) as _f:
            md = _f.read()
        self.assertIn("zz_stub_udp", md)
        self.assertIn(IP_C2, md)
        # console narration comes from the report
        text = "\n".join(r["campaign_console"])
        self.assertIn("Stage 1/2", text)
        self.assertIn("zz_stub_udp", text)
        self.assertIn("3 of 3 actions emitted", text)

    def test_report_matches_capture(self):
        """What the console says was emitted is exactly what is in the pcap for that endpoint."""
        r = self.build("c2", campaigns=[campaign()])
        paths = r["campaign"]["exports"]["runner-test"]
        mapped = _j(paths["stix"])["objects"][0]["pattern"].split("'")[1]
        total = int([ln for ln in r["campaign_console"] if "actions emitted" in ln][0].split("emitted ")[1].split()[0])
        self.assertGreater(total, 0)
        self.assertEqual(count_ip(r["pcap"], mapped), total)

    def test_inert_without_campaign(self):
        self.assertEqual(self.build("i1", modules=["campaign"])["packets"], self.baseline)
        self.assertEqual(self.build("i2", campaigns=[])["packets"], self.baseline)

    def test_deterministic(self):
        a = self.build("d1", campaigns=[campaign()])["packets"]
        b = self.build("d2", campaigns=[campaign()])["packets"]
        self.assertEqual(a, b)

    def test_invalid_campaign_is_skipped_with_error(self):
        bad = campaign()
        bad["stages"][0]["actions"][0]["action"] = "no_such_action"
        r = self.build("bad", campaigns=[bad])
        self.assertEqual(r["packets"], self.baseline)
        self.assertEqual(r["campaign"]["built"], [])
        errs = r["campaign"]["errors"]
        self.assertTrue(errs and "invalid campaign" in errs[0]["error"])
        self.assertTrue(any("no_such_action" in d for d in errs[0]["details"]))

    def test_one_valid_one_invalid(self):
        bad = {"schema": "opengenerator.campaign/1"}
        r = self.build("mix", campaigns=[bad, campaign()])
        self.assertEqual(r["campaign"]["built"], ["runner-test"])
        self.assertEqual(len(r["campaign"]["errors"]), 1)

    def test_failing_action_is_recorded_not_raised(self):
        camp = campaign([{"action": "zz_stub_boom", "from": "ws", "to": "c2:0"},
                         {"action": "zz_stub_udp", "from": "ws", "to": "c2:0"}])
        r = self.build("boom", campaigns=[camp])
        self.assertEqual(r["campaign"]["actions"], 3)
        self.assertEqual(r["campaign"]["emitted"], 2)
        self.assertIn("stub failure", "\n".join(r["campaign_console"]))
        self.assertIn("failed", "\n".join(r["campaign_console"]))

    def test_missing_host_skips_action(self):
        camp = campaign([{"action": "zz_stub_udp", "from": "host:NOSUCHHOST", "to": "c2:0"},
                         {"action": "zz_stub_udp", "from": "ws", "to": "c2:0"}])
        r = self.build("nohost", campaigns=[camp])
        errs = r["campaign"]["errors"]
        self.assertTrue(any("NOSUCHHOST" in e.get("error", "") for e in errs), errs)
        self.assertEqual(r["campaign"]["emitted"], 2)       # s1 second action + s2

    def test_fast_speed_is_shorter(self):
        slow = self.build("slow", campaigns=[campaign(speed="realistic")])
        fast = self.build("fast", campaigns=[campaign(speed="fast")])
        self.assertEqual(slow["campaign"]["emitted"], fast["campaign"]["emitted"])
        e_real = runner.estimate(campaign(speed="realistic"))
        self.assertLess(e_real["minutes_fast"], e_real["minutes_realistic"])
        self.assertEqual(e_real["stages"], 2)
        self.assertEqual(e_real["actions"], 3)

    def test_real_mode_needs_confirmation(self):
        camp = campaign(address_mode="real")
        camp["iocs"][0]["value"] = "8.8.4.4"
        with self.assertRaises(ValueError):
            self.build("real0", campaigns=[camp])
        r = self.build("real1", campaigns=[camp], confirm_real_addresses=True)
        patterns = [o["pattern"] for o in _j(r["campaign"]["exports"]["runner-test"]["stix"])["objects"]]
        self.assertIn("8.8.4.4", patterns[0])
        with self.assertRaises(ValueError):
            self.build("real2", campaigns=[campaign()], address_mode="bogus")

    def test_real_mode_rejects_reserved_address(self):
        r = self.build("real3", campaigns=[campaign(address_mode="real")], confirm_real_addresses=True)
        self.assertEqual(r["campaign"]["built"], [])          # 203.0.113.77 is documentation space
        self.assertIn("real", json.dumps(r["campaign"]["errors"]).lower())

    def test_address_mode_argument_overrides_campaign(self):
        r = self.build("amode", campaigns=[campaign(address_mode="real")], address_mode="mapped")
        self.assertEqual(r["campaign"]["emitted"], 3)

    def test_company_identity(self):
        r = self.build("acme", campaigns=[campaign()], company="Acme", industry="Manufacturing")
        self.assertEqual(r["campaign"]["emitted"], 3)
        self.assertNotIn("EXL-", "\n".join(r["campaign_console"]))


class TestHosts(unittest.TestCase):
    def test_external_host_cached_and_mapped(self):
        from netgen.campaign import addressing
        class C: pass
        ctx = C()
        camp = campaign()
        h1 = hosts.external_host(ctx, "c2:0", camp["iocs"][0], camp)
        h2 = hosts.external_host(ctx, "c2:0", camp["iocs"][0], camp)
        self.assertIs(h1, h2)
        self.assertTrue(addressing.is_mapped(h1.ip))
        self.assertNotEqual(h1.ip, IP_C2)

    def test_domain_becomes_fqdn(self):
        class C: pass
        camp = campaign()
        camp["iocs"].append({"type": "domain", "value": "update.bad.example", "role": "exfil"})
        h = hosts.external_host(C(), "exfil:0", camp["iocs"][2], camp)
        self.assertEqual(h.fqdn, "update.bad.example")

    def test_find_ioc_wraps_and_falls_back(self):
        camp = campaign()
        self.assertEqual(hosts.find_ioc(camp, "c2:5")[0], 0)           # wraps
        self.assertEqual(hosts.find_ioc(camp, "exfil:0")[0], 0)        # no exfil IOC: any addressable
        with self.assertRaises(hosts.EndpointError):
            hosts.find_ioc(camp, "ioc:99")


class TestConsole(unittest.TestCase):
    def test_only_from_report(self):
        rep = {"campaigns": [{"id": "x", "name": "X", "options": {"address_mode": "mapped"},
                              "stages": [{"id": "s1", "name": "One", "techniques": ["T1046"], "start": None}],
                              "entries": [{"stage": "s1", "action": "syn_scan", "from": "ws", "to": "server",
                                           "params": {"ports": 3}, "ts": None, "packets": 12, "bytes": 2048,
                                           "protocols": ["TCP"], "status": "ok"},
                                          {"stage": "s1", "action": "x", "from": "ws", "to": "dc", "ts": None,
                                           "status": "skipped", "error": "nope"}]}], "errors": []}
        text = "\n".join(console.narrate(rep))
        self.assertIn("$ syn_scan ports=3 ws -> server", text)
        self.assertIn("12 packets, 2.0 KB", text)
        self.assertIn("skipped: nope", text)
        self.assertIn("1 of 2 actions emitted 12 packets", text)


class TestRfc791Checker(unittest.TestCase):
    """The validator must fail corrupted packets, or a green result means nothing."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="og-rfc-")
        r = OGB.build(scale=0.001, out=os.path.join(cls.tmp, "g.pcap"), keylog=os.path.join(cls.tmp, "g.k"),
                      inventory=INVENTORY, certs_dir=None, iocs_prefix=None, modules=[], progress=False, date=DAY)
        cls.pcap = r["pcap"]
        with open(cls.pcap, "rb") as f:
            cls.raw = f.read()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _mutate(self, fn, name):
        """Apply fn(bytearray, offset_of_frame, caplen) to the first IPv4 TCP frame, return findings."""
        raw = bytearray(self.raw)
        off = 24
        while True:
            _s, _u, cap, _o = struct.unpack("<IIII", raw[off:off + 16])
            f = off + 16
            if raw[f + 12:f + 14] == b"\x08\x00" and raw[f + 23] == 6 and cap > 54:
                fn(raw, f, cap)
                break
            off = f + cap
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as f:
            f.write(raw)
        return RFC.check(p, 5)

    def test_clean_capture_passes(self):
        counts, fails, _e, first = RFC.check(self.pcap)
        self.assertEqual(fails, {}, first)
        self.assertGreater(counts["ipv4"], 1000)

    def test_detects_header_checksum(self):
        _c, fails, _e, _f = self._mutate(lambda r, f, c: r.__setitem__(f + 24, r[f + 24] ^ 0xFF), "ck.pcap")
        self.assertIn("ip.checksum", fails)

    def test_detects_tcp_checksum(self):
        _c, fails, _e, _f = self._mutate(lambda r, f, c: r.__setitem__(f + 14 + 20 + 16, r[f + 14 + 20 + 16] ^ 0xFF), "tck.pcap")
        self.assertIn("tcp.checksum", fails)

    def test_detects_ttl_zero_and_version(self):
        def ttl0(r, f, c):
            r[f + 22] = 0
        self.assertIn("ip.ttl", self._mutate(ttl0, "ttl.pcap")[1])

        def ver5(r, f, c):
            r[f + 14] = 0x55
        self.assertIn("ip.version", self._mutate(ver5, "ver.pcap")[1])

    def test_detects_total_length(self):
        def tl(r, f, c):
            r[f + 16:f + 18] = struct.pack("!H", c)           # larger than the bytes present
        self.assertIn("ip.totlen", self._mutate(tl, "tl.pcap")[1])

    def test_exempt_prefix(self):
        raw = bytearray(self.raw)
        # reuse the TTL mutation, then exempt it
        off = 24
        _s, _u, cap, _o = struct.unpack("<IIII", raw[off:off + 16])
        f = off + 16
        while not (raw[f + 12:f + 14] == b"\x08\x00"):
            off = f + cap
            _s, _u, cap, _o = struct.unpack("<IIII", raw[off:off + 16])
            f = off + 16
        raw[f + 22] = 0
        p = os.path.join(self.tmp, "ex.pcap")
        with open(p, "wb") as f:
            f.write(raw)
        _c, fails, ex, _f = RFC.check(p, 5, exempt=["ip.ttl"])
        self.assertNotIn("ip.ttl", fails)
        self.assertIn("ip.ttl", ex)


if __name__ == "__main__":
    unittest.main(verbosity=2)
