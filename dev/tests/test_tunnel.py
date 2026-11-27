"""Opt-in tunnel carriers (network_options tunnels): inner-frame equivalence, selectivity, byte counts, checker decap, tshark."""
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "checks"))
import build_manifest as BM        # noqa: E402 - sys.path is set up first
import check_ipv6                  # noqa: E402 - sys.path is set up first
import check_rfc791                # noqa: E402 - sys.path is set up first
import opengenerator_build as OGB  # noqa: E402 - sys.path is set up first
from decap import Decap            # noqa: E402 - sys.path is set up first
from netgen import tunnel          # noqa: E402 - sys.path is set up first
from netgen.core import PcapWriter, classify  # noqa: E402 - sys.path is set up first
from selftest import PIN           # noqa: E402 - sys.path is set up first
from tshark_locate import find_tshark  # noqa: E402 - sys.path is set up first

TSHARK = find_tshark()
PH = b"\x02\x00\x00\x00\x00\x00" * 2                 # the placeholder Ethernet header Decap gives an inner unicast IP packet


def _build(d, stem, scale=0.004, **kw):
    kw.setdefault("modules", [])
    return OGB.build(scale=scale, out=os.path.join(d, stem + ".pcap"), keylog=os.path.join(d, stem + ".keys"),
                     inventory=os.path.join(DEV, "inventory.json"), certs_dir=None, iocs_prefix=None,
                     progress=False, **kw)


def _frames(path):
    with open(path, "rb") as f:
        data = f.read()
    off = 24
    while off < len(data):
        incl = struct.unpack_from("<I", data, off + 8)[0]
        yield data[off + 16:off + 16 + incl]
        off += 16 + incl


def _placeholder(f):
    """What Decap makes of the IP packet inside frame f (an IPv6 multicast destination gets its derived MAC)."""
    dst = b"\x33\x33" + f[50:54] if f[12:14] == b"\x86\xdd" and f[38] == 0xFF else PH[:6]
    return dst + PH[6:] + f[12:]


def _write(path, frames):
    w = PcapWriter(path)
    for i, f in enumerate(frames):
        w.write(1e9 + i, f)
    w.close()


def _inner(frames, kinds):
    """-> (Decap, the packets the given outer frames carry, in order)."""
    dec = Decap.parse(kinds)
    return dec, [r[2] for r in dec.records(((len(f), len(f), f) for f in frames), outer=False)]


def _wrap(carrier, frames, mtu=1500, scenario="x"):
    t = tunnel.Tunneler(tunnel.normalize([{"carrier": carrier, "scenarios": ["*"], "mtu": mtu}]), BM.scenario_of)
    return t, [o for f in frames for o in t(scenario, f)]


def _meta(d, r):
    with open(os.path.join(d, r["manifest"])) as f:
        return json.load(f)


class Build(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="og-tunnel-")
        cls.off = _build(cls.d, "off")
        cls.vx = _build(cls.d, "vx", network_options={"tunnels": ["vxlan:normal-day"]})
        cls.gre = _build(cls.d, "gre", scale=0.0005, network_options={"tunnels": ["gre:*"], "vlan": "subnet"})
        cls.v6 = _build(cls.d, "v6", scale=0.0005, network_options={"ipv6": True})
        cls.v64 = _build(cls.d, "v64", scale=0.0005, network_options={"ipv6": True, "tunnels": ["6in4:ipv6"]})
        cls.name = "ndr-recon"
        cls.base = _build(cls.d, "base", scale=0.0005, modules=[cls.name])
        cls.sel = _build(cls.d, "sel", scale=0.0005, modules=[cls.name],
                         network_options={"tunnels": [{"carrier": "gre", "scenarios": [cls.name], "mtu": 9000}]})

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_option_off_pin(self):
        self.assertEqual(self.off["packets"], PIN)
        m = _meta(self.d, self.off)
        self.assertNotIn("network", m)
        self.assertNotIn("network_options", m["parameters"])

    def test_inner_frames_equal_untunneled_frame_stream(self):
        """One recorded frame list (IPv4, ARP, IPv6) through the wrapper, PcapWriter and the decapsulator: the carried
        frames equal the original ones, record by record; frames a carrier cannot take pass through unchanged."""
        frames = list(_frames(self.v6["pcap"]))
        self.assertTrue(any(f[12:14] == b"\x86\xdd" for f in frames))
        for carrier, mtu in (("gre", 1500), ("vxlan", 1500), ("6in4", 1500), ("gre", 9000), ("vxlan", 576)):
            t, outer = _wrap(carrier, frames, mtu)
            path = os.path.join(self.d, "eq.pcap")
            _write(path, outer)
            on_wire = list(_frames(path))
            dec, got = _inner(on_wire, carrier)
            taken = [f for f in frames if carrier == "vxlan" or f[12:14] == b"\x86\xdd" or (carrier == "gre" and f[12:14] == b"\x08\x00")]
            want = taken if carrier == "vxlan" else [_placeholder(f) for f in taken]
            self.assertEqual(got, want, (carrier, mtu))
            self.assertEqual(dec.problems, [])
            r = t.report()[0]
            self.assertEqual((r["inner_frames"], r["passed_through"]), (len(taken), len(frames) - len(taken)))
            self.assertEqual(r["outer_frames"] + r["passed_through"], len(outer))
            if mtu == 9000:
                self.assertEqual(r["fragmented"], 0)
            for o in outer:
                if o[12:14] == b"\x08\x00" and o[23] in (47, 41, 17) and mtu < 9000:
                    self.assertLessEqual(len(o) - 14, mtu)                  # never an outer packet above the carrier MTU

    def test_pin_and_inner_count(self):
        """VXLAN around the whole baseline: every default frame rides inside, none lost or added; fragments only add outer frames."""
        t = _meta(self.d, self.vx)["network"]["tunnels"]
        self.assertEqual(len(t), 1)
        self.assertEqual((t[0]["inner_frames"], t[0]["passed_through"]), (PIN, 0))
        self.assertEqual(self.vx["packets"], t[0]["outer_frames"])
        self.assertGreater(t[0]["fragmented"], 0)                          # full-size inner frames exceed 1500 once wrapped
        dec, inner = _inner(_frames(self.vx["pcap"]), "vxlan")
        self.assertEqual(len(inner), PIN)
        self.assertEqual(dec.problems, [])
        self.assertEqual(sum(c for _, c in self.vx["protocols"]), self.vx["packets"])

    def test_bytes_as_written(self):
        for r in (self.off, self.vx, self.gre, self.v64, self.sel):
            self.assertEqual(r["bytes"], os.path.getsize(r["pcap"]) - 24)          # file size less the global header
            m = _meta(self.d, r)
            self.assertEqual(m["totals"]["bytes"], r["bytes"])
            self.assertEqual(m["totals"]["packets"], r["packets"])
            self.assertTrue(m.get("counters_consistent"), m)                       # the per-scenario buckets still sum to the file
        self.assertGreater(self.vx["bytes"], self.off["bytes"])
        t = _meta(self.d, self.vx)["network"]["tunnels"][0]
        self.assertGreater(t["added_bytes"], 50 * PIN)                              # 50 bytes of outer headers per frame, plus fragment headers

    def test_selective_scenario(self):
        """Only the named scenario is wrapped; with mtu 9000 nothing is split, so the capture keeps its packet count."""
        t = _meta(self.d, self.sel)["network"]["tunnels"][0]
        mb, ms = _meta(self.d, self.base), _meta(self.d, self.sel)
        base, sel = ({s["id"]: s["observed"] for s in m["scenarios"]} for m in (mb, ms))
        self.assertEqual(t["inner_frames"] + t["passed_through"], base[self.name]["packets"])
        self.assertGreater(t["inner_frames"], 0)
        self.assertEqual(self.sel["packets"], self.base["packets"])
        self.assertEqual(ms["normal_day"]["packets"], mb["normal_day"]["packets"])
        self.assertGreater(sel[self.name]["bytes"], base[self.name]["bytes"])
        self.assertEqual(t["fragmented"], 0)

    def test_params_differ(self):
        mo, mn = _meta(self.d, self.off)["parameters"], _meta(self.d, self.vx)["parameters"]
        self.assertNotEqual(mo, mn)
        self.assertEqual(mn["network_options"], {"tunnels": [{"carrier": "vxlan", "scenarios": ["normal-day"], "mtu": 1500}]})

    def test_checkers_with_decap(self):
        for r, kinds in ((self.vx, "vxlan"), (self.gre, "gre"), (self.v64, "6in4")):
            _, fails, _, first = check_rfc791.check(r["pcap"], 20, (), decap=kinds)
            self.assertFalse(sum(fails.values()), (kinds, first))
            _, fails6, _, first6 = check_ipv6.check(r["pcap"], 20, (), decap=kinds)
            self.assertFalse(sum(fails6.values()), (kinds, first6))
        plain = check_rfc791.check(self.vx["pcap"], 20, ())[0]
        deep = check_rfc791.check(self.vx["pcap"], 20, (), decap="vxlan")[0]
        self.assertEqual(plain["tcp"], 0)                                           # outer frames only: no TCP is visible without decap
        self.assertGreater(deep["tcp"], 0)
        self.assertEqual(deep["frames"] - plain["frames"], PIN)
        v6 = (check_ipv6.check(self.v64["pcap"], 20, ())[0], check_ipv6.check(self.v64["pcap"], 20, (), decap="6in4")[0])
        self.assertGreater(v6[1]["ipv6"], v6[0]["ipv6"])                           # the 6in4 payloads are IPv6 only once decapsulated

    def test_vlan_and_tunnel_compose(self):
        self.assertTrue(all(f[12:14] == b"\x81\x00" for f in _frames(self.gre["pcap"])))
        self.assertEqual(_meta(self.d, self.gre)["network"]["vlan"]["tagged_frames"], self.gre["packets"])

    def test_decap_catches_inner_and_envelope_faults(self):
        tcp = next(f for f in _frames(self.v6["pcap"]) if f[12:14] == b"\x08\x00" and f[23] == 6 and 100 < len(f) < 1400)
        _, (g,) = _wrap("gre", [tcp])
        bad = g[:-1] + bytes([g[-1] ^ 0xFF])                                        # a payload byte flipped inside the tunnel
        path = os.path.join(self.d, "bad.pcap")
        _write(path, [bad])
        self.assertEqual(sum(check_rfc791.check(path, 20, ())[1].values()), 0)      # the outer header is fine: invisible without decap
        self.assertEqual(check_rfc791.check(path, 20, (), decap="gre")[1], {"tcp.checksum": 1})
        self.assertEqual([p[1] for p in _inner([g[:34] + b"\x00\x01" + g[36:]], "gre")[0].problems], ["gre.version"])
        _, (v,) = _wrap("vxlan", [tcp])
        self.assertEqual([p[1] for p in _inner([v[:42] + b"\x00" + v[43:]], "vxlan")[0].problems], ["vxlan.flags"])
        big = tcp[:12] + b"\x08\x00" + bytes([0x45, 0, 0x05, 0xDC]) + b"\x00" * 1496
        _, parts = _wrap("vxlan", [big], mtu=1000)
        self.assertGreater(len(parts), 1)
        self.assertEqual([p[1] for p in _inner(parts[:1], "vxlan")[0].problems], ["tunnel.fragment"])   # a first fragment alone never completes
        self.assertEqual(_inner(parts, "vxlan")[0].problems, [])

    @unittest.skipUnless(TSHARK, "tshark is not installed")
    def test_tshark(self):
        for r, proto in ((self.vx, "vxlan"), (self.gre, "gre"), (self.v64, "ipv6")):
            # ssh and prp are not dissected: random payload bytes can read as a malformed SSH message, and the PRP
            # trailer heuristic misfires on the zero padding of a short last fragment behind a VLAN tag (reproduced on
            # a captured frame pair: gone without the tag, and this generator never emits PRP)
            out = subprocess.run([TSHARK, "--disable-protocol", "ssh", "--disable-protocol", "prp", "-r", r["pcap"], "-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE",
                                  "-T", "fields", "-E", "separator=;", "-e", "frame.protocols", "-e", "_ws.malformed", "-e", "_ws.expert.severity"],
                                 capture_output=True, text=True, timeout=900, check=True).stdout.splitlines()
            self.assertEqual(len(out), r["packets"])
            self.assertTrue(any(proto in line.split(";")[0] for line in out), proto)
            for line in out:
                _, bad, expert = (line.split(";") + ["", ""])[:3]
                self.assertEqual(bad, "", line)
                self.assertNotIn("error", expert, line)


class Units(unittest.TestCase):
    def test_normalize(self):
        n = tunnel.normalize
        self.assertEqual(n("gre:a,b"), [{"carrier": "gre", "scenarios": ["a", "b"], "mtu": 1500}])
        self.assertEqual(n(["vxlan:z", {"carrier": "6in4", "scenarios": "y", "mtu": 1480}])[0]["carrier"], "6in4")      # sorted by carrier
        for bad in ("ipip:a", "gre:", "gre", [], 5, {"carrier": "gre", "scenarios": ["a"], "mtu": 100}, {"carrier": "gre", "scenarios": ["a"], "x": 1},
                    ["gre:a", "vxlan:a"], ["gre:*", "vxlan:a"], ["gre:a", "vxlan:*"], {"carrier": "gre", "scenarios": ["a"], "mtu": True}):
            with self.assertRaises(ValueError, msg=str(bad)):
                n(bad)
        with self.assertRaises(ValueError):
            tunnel.check_scenarios(n("gre:nope"), ["normal-day"])
        tunnel.check_scenarios(n("gre:*"), [])

    def test_build_options(self):
        n = OGB.normalize_network_options
        self.assertEqual(n({"tunnels": "gre:*"}), {"tunnels": [{"carrier": "gre", "scenarios": ["*"], "mtu": 1500}]})
        self.assertIsNone(n({"tunnels": None}))
        self.assertEqual(set(n({"vlan": True, "tunnels": "gre:*"})), {"vlan", "tunnels"})
        with self.assertRaises(ValueError):
            n({"tunnel": "gre:*"})                                                   # a typo must not build the default capture

    def test_unknown_scenario_fails_before_building(self):
        with self.assertRaises(ValueError):
            OGB.build(scale=0.0001, out=os.path.join(tempfile.gettempdir(), "og-tunnel-never.pcap"), certs_dir=None, iocs_prefix=None,
                      network_options={"tunnels": "gre:no-such-scenario"}, modules=[], progress=False)

    def test_wrap_shapes(self):
        """The outer headers of one frame per carrier, and the pass-through rules."""
        mac_a, mac_b = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02"
        arp = mac_a + mac_b + b"\x08\x06" + b"\x00" * 28
        ip4 = mac_a + mac_b + b"\x08\x00" + bytes([0x45, 0, 0, 40]) + b"\x00" * 36
        ip6 = mac_a + mac_b + b"\x86\xdd" + b"\x60" + b"\x00" * 39
        for carrier, proto, passes in (("gre", 47, [arp]), ("6in4", 41, [arp, ip4]), ("vxlan", 17, [])):
            t = tunnel.Tunneler(tunnel.normalize("%s:*" % carrier), BM.scenario_of)
            for f in passes:
                self.assertEqual(t("x", f), [f])
            wrapped = t("x", ip6)
            self.assertEqual(len(wrapped), 1)
            o = wrapped[0]
            self.assertEqual((o[:12], o[12:14], o[23]), (mac_a + mac_b, b"\x08\x00", proto))
            self.assertEqual(o[20:22], b"\x00\x00")                                  # DF clear, no fragment offset
            self.assertTrue(check_rfc791.csum_ok(o[14:34]))
        self.assertEqual(classify(tunnel.Tunneler(tunnel.normalize("vxlan:*"), BM.scenario_of)("x", ip4)[0]), "VXLAN")

    def test_other_scenarios_pass_through(self):
        t = tunnel.Tunneler(tunnel.normalize("gre:wanted"), BM.scenario_of)
        f = b"\x02" * 12 + b"\x08\x00" + bytes([0x45, 0, 0, 20]) + b"\x00" * 16
        self.assertEqual(t("incident:other", f), [f])
        self.assertEqual(len(t("incident:wanted", f)), 1)
        self.assertNotEqual(t("incident:wanted", f), [f])

    def test_directions_share_a_pair(self):
        t = tunnel.Tunneler(tunnel.normalize("gre:*"), BM.scenario_of)
        a, b = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\x02"
        body = b"\x08\x00" + bytes([0x45, 0, 0, 20]) + b"\x00" * 16
        fwd, rev = t("x", b + a + body)[0], t("x", a + b + body)[0]
        self.assertEqual((fwd[26:30], fwd[30:34]), (rev[30:34], rev[26:30]))        # swapped, same two endpoints


if __name__ == "__main__":
    unittest.main()
