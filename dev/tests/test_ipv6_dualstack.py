"""Opt-in dual-stack IPv6 slice (network option ipv6): pin, additive equivalence, checkers, tshark, determinism, VLAN."""
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from collections import Counter

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "checks"))
sys.path.insert(0, os.path.join(DEV, "tools"))
import build_manifest as BM        # noqa: E402 - sys.path is set up first
import check_ipv6                  # noqa: E402 - sys.path is set up first
import opengenerator_build as OGB  # noqa: E402 - sys.path is set up first
import verify_manifest as VM       # noqa: E402 - sys.path is set up first
from netgen import dualstack, flows as F, frames6 as F6  # noqa: E402 - sys.path is set up first
from netgen.core import classify   # noqa: E402 - sys.path is set up first
from selftest import PIN           # noqa: E402 - sys.path is set up first
from tshark_locate import find_tshark  # noqa: E402 - sys.path is set up first

TSHARK = find_tshark()


def _build(d, stem, scale=0.004, **kw):
    return OGB.build(scale=scale, out=os.path.join(d, stem + ".pcap"), keylog=os.path.join(d, stem + ".keys"),
                     inventory=os.path.join(DEV, "inventory.json"), certs_dir=None, iocs_prefix=None,
                     modules=[], progress=False, **kw)


def _records(path):
    with open(path, "rb") as f:
        data = f.read()
    off = 24
    while off < len(data):
        sec, usec, incl, _ = struct.unpack_from("<IIII", data, off)
        yield sec + usec / 1e6, data[off + 16:off + 16 + incl]
        off += 16 + incl


def _strip(frame):
    vids = []
    while frame[12:14] in (b"\x81\x00", b"\x88\xa8"):
        vids.append(struct.unpack_from("!H", frame, 14)[0] & 0x0FFF)
        frame = frame[:12] + frame[16:]
    return frame, vids


def _key(frame):
    """Deterministic identity of an IPv4 frame: addresses, protocol and ports (payload bytes carry os.urandom noise)."""
    if frame[12:14] == b"\x08\x06":
        return ("arp", frame[22:32])
    ihl = (frame[14] & 15) * 4
    return (frame[26:34], frame[23], frame[14 + ihl:14 + ihl + 4] if frame[23] in (6, 17) else b"")


def _key6(frame):
    """Deterministic identity of an IPv6 frame: addresses, next header, ports of TCP/UDP."""
    return (frame[22:54], frame[20], frame[54:58] if frame[20] in (6, 17) else b"")


def _meta(d, r):
    with open(os.path.join(d, r["manifest"])) as f:
        return json.load(f)


class Build(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="og-v6-")
        cls.off = _build(cls.d, "off")
        cls.on = _build(cls.d, "on", tag_sidecar=True, network_options={"ipv6": 0.25})
        cls.again = _build(cls.d, "again", network_options={"ipv6": 0.25})
        cls.both = _build(cls.d, "both", tag_sidecar=True, network_options={"ipv6": 0.25, "vlan": True})
        cls.v6_only = _build(cls.d, "v6only", scale=0.0005, network_options={"ipv6": {"share": 1, "chatter": False}})

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def _tags(self, stem):
        return BM.read_tags(os.path.join(self.d, stem + ".tags"))

    # (a) option off ------------------------------------------------------------------------------
    def test_option_off_pin(self):
        self.assertEqual(self.off["packets"], PIN)
        m = _meta(self.d, self.off)
        self.assertNotIn("network", m)
        self.assertNotIn("network_options", m["parameters"])
        self.assertNotIn("ipv6", self.off["by_scenario"])

    def test_ctx_switch_cannot_fire_when_off(self):
        self.assertIsNone(F.Ctx({}, None, None, None, None).v6)

    # (b) additive: remove the new frames and the option-off build is left ------------------------
    def test_removing_v6_frames_leaves_the_option_off_build(self):
        table, body = self._tags("on")
        v6_ids = {i for i, t in enumerate(table) if t.startswith("v6:")}
        recs = list(_records(self.on["pcap"]))
        self.assertEqual(len(recs), len(body))
        kept, v6 = [], 0
        for (ts, f), tag in zip(recs, body, strict=True):
            is_v6 = f[12:14] == b"\x86\xdd"
            self.assertEqual(is_v6, tag in v6_ids)                     # the tags and the EtherType name the same frames
            v6 += is_v6
            if not is_v6:
                kept.append((ts, f))
        self.assertGreater(v6, 0)
        base = list(_records(self.off["pcap"]))
        self.assertEqual(len(kept), PIN)
        self.assertEqual(len(kept), len(base))
        mix = {}
        for _, f in kept:
            mix[classify(f)] = mix.get(classify(f), 0) + 1
        self.assertEqual(mix, dict(self.off["protocols"]))
        # same endpoints and ports, frame for frame (timestamps differ by a microsecond between any two builds:
        # random TLS record sizes change the serialisation delay, so neither time nor order is compared)
        self.assertEqual(Counter(_key(f) for _, f in kept), Counter(_key(f) for _, f in base))

    def test_tag_budget(self):
        table, _ = self._tags("on")
        self.assertEqual({t for t in table if t.startswith("v6:")}, set(dualstack.TAGS))
        self.assertEqual(len(dualstack.TAGS), 5)

    def test_manifest_buckets(self):
        mp = os.path.join(self.d, self.on["manifest"])
        m = _meta(self.d, self.on)
        self.assertEqual(VM.verify(mp), [])
        self.assertTrue(m["counters_consistent"])
        self.assertEqual(m["parameters"]["network_options"], {"ipv6": {"share": 0.25, "chatter": True}})
        v6 = m["network"]["ipv6"]
        self.assertEqual(v6["packets"], self.on["packets"] - PIN)
        self.assertEqual(sum(t["packets"] for t in v6["tags"].values()), v6["packets"])
        self.assertEqual(self.on["by_scenario"]["ipv6"]["packets"], v6["packets"])
        self.assertEqual(m["normal_day"]["packets"], PIN)                # the v6 packets are not "normal day"
        self.assertGreater(v6["dual_stack_clients"], 0)
        self.assertNotEqual(m["parameters"], _meta(self.d, self.off)["parameters"])

    # (c) independent checker ---------------------------------------------------------------------
    def test_check_ipv6(self):
        for r in (self.on, self.both, self.v6_only):
            counts, fails, _, first = check_ipv6.check(r["pcap"], 20, ())
            self.assertFalse(sum(fails.values()), first)
            self.assertGreater(counts["ipv6"], 0)

    def test_frames_are_what_they_claim(self):
        kinds, biggest = set(), 0
        for _, f in _records(self.v6_only["pcap"]):
            if f[12:14] != b"\x86\xdd":
                continue
            kinds.add(classify(f))
            if f[20] == 6:                                              # no segment beyond a 1500-byte path MTU
                biggest = max(biggest, len(f) - 14)
        self.assertLessEqual(biggest, 1500)
        self.assertTrue({"ICMPv6", "DNS", "HTTPS", "SMB2", "Kerberos"} <= kinds, kinds)

    # (d) tshark ----------------------------------------------------------------------------------
    @unittest.skipUnless(TSHARK, "tshark is not installed")
    def test_tshark(self):
        # ssh is not dissected: a few generated SSH payloads are random bytes that read as a malformed SSH message
        base = [TSHARK, "--disable-protocol", "ssh", "-r", self.on["pcap"], "-o", "tcp.check_checksum:TRUE",
                "-o", "udp.check_checksum:TRUE"]
        for flt in ("ipv6 && (_ws.malformed || _ws.expert.severity==error)",
                    "ipv6 && (tcp.checksum.status==\"Bad\" || udp.checksum.status==\"Bad\" || icmpv6.checksum.status==\"Bad\")"):
            out = subprocess.run(base + ["-Y", flt], capture_output=True, text=True, timeout=600, check=True).stdout
            self.assertEqual(out, "", flt)
        protos = set()
        for line in subprocess.run(base + ["-Y", "ipv6", "-T", "fields", "-e", "frame.protocols"],
                                   capture_output=True, text=True, timeout=600, check=True).stdout.splitlines():
            protos.update(line.split(":"))
        for p in ("ipv6", "icmpv6", "dhcpv6", "dns", "tls", "smb2", "kerberos"):
            self.assertIn(p, protos)

    # (e) determinism -----------------------------------------------------------------------------
    def test_deterministic(self):
        a = Counter(_key6(f) if f[12:14] == b"\x86\xdd" else _key(f) for _, f in _records(self.on["pcap"]))
        b = Counter(_key6(f) if f[12:14] == b"\x86\xdd" else _key(f) for _, f in _records(self.again["pcap"]))
        self.assertEqual(self.on["packets"], self.again["packets"])
        self.assertEqual(self.on["protocols"], self.again["protocols"])
        self.assertEqual(a, b)

    # (f) with VLAN tagging -----------------------------------------------------------------------
    def test_with_vlan(self):
        recs = list(_records(self.both["pcap"]))
        plain = [f for _, f in _records(self.on["pcap"])]
        self.assertEqual(len(recs), self.on["packets"])
        self.assertEqual(self.both["protocols"], self.on["protocols"])
        seen, vids = {}, set()
        for (_, f), g in zip(recs, plain, strict=True):
            s, v = _strip(f)
            self.assertEqual(len(v), 1)
            self.assertEqual(s[12:14], g[12:14])
            vids.add(v[0])
            if s[12:14] == b"\x86\xdd" and s[20] == 6:                   # both directions of a v6 TCP flow share one VID
                key = frozenset(((s[22:38], s[54:56]), (s[38:54], s[56:58])))
                self.assertEqual(seen.setdefault(key, v[0]), v[0])
        self.assertEqual(vids, {10, 20})
        table, _ = self._tags("both")
        self.assertEqual({t for t in table if t.startswith("v6:")}, set(dualstack.TAGS))
        self.assertEqual(_meta(self.d, self.both)["network"]["vlan"]["tagged_frames"], self.both["packets"])


class Units(unittest.TestCase):
    def test_normalize(self):
        n = OGB.normalize_network_options
        self.assertEqual(n({"ipv6": True}), {"ipv6": {"share": OGB.DEFAULT_IPV6_SHARE, "chatter": True}})
        self.assertEqual(n({"ipv6": "0.5"}), {"ipv6": {"share": 0.5, "chatter": True}})
        self.assertEqual(n({"ipv6": {"share": 1, "chatter": False}}), {"ipv6": {"share": 1.0, "chatter": False}})
        self.assertIsNone(n({"ipv6": False}))
        self.assertEqual(set(n({"ipv6": True, "vlan": True})), {"ipv6", "vlan"})
        for bad in ({"ipv6": 0}, {"ipv6": 1.5}, {"ipv6": "x"}, {"ipv6": {"share": 0.5, "chatter": 1}}, {"ipv6": {"hosts": 3}},
                    {"ipv6": [1]}, {"ip6": 1}):
            with self.assertRaises(ValueError, msg=str(bad)):
                n(bad)

    def test_ndp_frames_have_hop_limit_255(self):
        smac = bytes.fromhex("0200000000aa")
        f = F6.ns(smac, F6.link_local(smac), F6.link_local(bytes.fromhex("0200000000bb")))
        self.assertEqual(f[21], 255)

    def test_dhcp6_message_shape(self):
        m = dualstack.dhcp6_msg(1, 0x123456, [dualstack._opt(1, b"\x00\x03\x00\x01" + bytes(6))])
        self.assertEqual(m[:4], b"\x01\x12\x34\x56")
        self.assertEqual(struct.unpack_from("!HH", m, 4), (1, 10))


if __name__ == "__main__":
    unittest.main()
