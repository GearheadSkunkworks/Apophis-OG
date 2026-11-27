"""Opt-in native 802.1Q tagging (network_options vlan): strip-equivalence, pin, manifest, parameters, tshark."""
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import types
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "checks"))
import opengenerator_build as OGB  # noqa: E402 - sys.path is set up first
import check_ipv6                  # noqa: E402 - sys.path is set up first
import check_rfc791                # noqa: E402 - sys.path is set up first
from netgen.core import MIN_FRAME, PcapWriter, VlanTagger, classify  # noqa: E402 - sys.path is set up first
from netgen.frames6 import eth_tag  # noqa: E402 - sys.path is set up first
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
        yield sec, usec, data[off + 16:off + 16 + incl]
        off += 16 + incl


def _strip(frame):
    """Remove every 802.1Q/802.1ad tag; returns (frame, [vids])."""
    vids = []
    while frame[12:14] in (b"\x81\x00", b"\x88\xa8"):
        vids.append(struct.unpack_from("!H", frame, 14)[0] & 0x0FFF)
        frame = frame[:12] + frame[16:]
    return frame, vids


def _meta(d, r):
    with open(os.path.join(d, r["manifest"])) as f:
        return json.load(f)


class Build(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="og-vlan-")
        cls.off = _build(cls.d, "off")
        cls.on = _build(cls.d, "on", network_options={"vlan": "subnet"})
        cls.sm = _build(cls.d, "sm", scale=0.0005, network_options={"vlan": True})
        cls.qq = _build(cls.d, "qq", scale=0.0005, network_options={"vlan": {"scheme": "fixed", "vid": 300, "qinq": 7}})

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_option_off_pin(self):
        self.assertEqual(self.off["packets"], PIN)
        m = _meta(self.d, self.off)
        self.assertNotIn("network", m)
        self.assertNotIn("network_options", m["parameters"])

    def test_tagged_build_is_structurally_sound(self):
        """Noise-free properties of the integration build (two independent builds differ in payload bytes, so no cross-build length or timestamp comparison)."""
        recs = list(_records(self.on["pcap"]))
        self.assertEqual(len(recs), PIN)
        self.assertEqual(self.on["packets"], PIN)
        self.assertEqual(self.on["protocols"], self.off["protocols"])      # tagged frames are classified through the tag
        for _, _, fb in recs:
            stripped, vids = _strip(fb)
            self.assertEqual(len(vids), 1)
            self.assertEqual(fb[12:14], b"\x81\x00")
            self.assertIn(vids[0], (10, 20))
            self.assertIn(stripped[12:14], (b"\x08\x00", b"\x08\x06"))
            if stripped[12:14] == b"\x08\x00":
                self.assertEqual(stripped[14] >> 4, 4)                     # the IPv4 header parses again once the tag is gone
        self.assertGreater(self.on["bytes"], self.off["bytes"])

    def test_strip_equivalence_same_frame_stream(self):
        """One recorded frame list through PcapWriter with and without a tagger: exact, record by record."""
        base = [(sec + usec / 1e6, f) for sec, usec, f in _records(self.off["pcap"])][:30000]
        base += [(base[-1][0], base[0][1][:n]) for n in range(40, 70)]     # short frames: tag before padding
        link = types.SimpleNamespace(fw={}, fw_a=types.SimpleNamespace(ipb=b"\n\n\n\x01"))
        plain, tagged = os.path.join(self.d, "p.pcap"), os.path.join(self.d, "t.pcap")
        pw, tw = PcapWriter(plain), PcapWriter(tagged, VlanTagger(link, "fixed", 123))
        for ts, f in base:
            self.assertEqual(tw.write(ts, f), len(f) + 4)                  # returned length: tag included, padding not
            pw.write(ts, f)
        pw.close()
        tw.close()
        a, b = list(_records(plain)), list(_records(tagged))
        self.assertEqual(len(a), len(b))
        for (sa, ua, fa), (sb, ub, fb), (_, raw) in zip(a, b, base, strict=True):
            self.assertEqual((sa, ua), (sb, ub))
            stripped, vids = _strip(fb)
            self.assertEqual(vids, [123])
            self.assertEqual(stripped + b"\x00" * max(0, MIN_FRAME - len(stripped)), fa)
            self.assertEqual(len(fb), max(len(raw) + 4, MIN_FRAME))        # +4 on the unpadded frame, then padded
        self.assertEqual(pw.protocols, tw.protocols)

    def test_vid_per_flow_from_vantage_segment(self):
        seen, vids = {}, set()
        for _, _, f in _records(self.on["pcap"]):
            vid = struct.unpack_from("!H", f, 14)[0] & 0x0FFF
            vids.add(vid)
            if f[16:18] == b"\x08\x00" and f[27] == 6:                    # TCP: both directions of a flow share one VID
                ip, ports = f[30:38], f[38:42]
                key = (frozenset((ip[:4] + ports[:2], ip[4:] + ports[2:])))
                self.assertEqual(seen.setdefault(key, vid), vid)
        self.assertEqual(vids, {10, 20})

    def test_bytes_as_written(self):
        for r in (self.off, self.on, self.qq):
            self.assertEqual(r["bytes"], os.path.getsize(r["pcap"]) - 24)      # file size less the global header
            self.assertEqual(_meta(self.d, r)["totals"]["bytes"], r["bytes"])
        self.assertGreater(self.on["bytes"], self.off["bytes"])
        v = _meta(self.d, self.on)["network"]["vlan"]
        self.assertEqual((v["scheme"], v["tagged_frames"], v["tag_bytes"]), ("subnet", PIN, 4 * PIN))
        self.assertEqual(_meta(self.d, self.qq)["network"]["vlan"]["tag_bytes"], 8 * self.qq["packets"])

    def test_params_differ(self):
        mo, mn = _meta(self.d, self.off)["parameters"], _meta(self.d, self.on)["parameters"]
        self.assertNotEqual(mo, mn)
        self.assertEqual(mn["network_options"], {"vlan": {"scheme": "subnet", "vid": None, "qinq": None}})

    def test_qinq_fixed(self):
        n = 0
        for _, _, f in _records(self.qq["pcap"]):
            self.assertEqual((f[12:14], f[16:18]), (b"\x88\xa8", b"\x81\x00"))
            self.assertEqual(struct.unpack_from("!H", f, 14)[0] & 0x0FFF, 7)
            self.assertEqual(struct.unpack_from("!H", f, 18)[0] & 0x0FFF, 300)
            n += 1
        self.assertEqual(n, self.qq["packets"])

    def test_checkers_walk_tags(self):
        for r in (self.on, self.qq):
            counts, fails, _, first = check_rfc791.check(r["pcap"], 20, ())
            self.assertFalse(sum(fails.values()), first)
            self.assertGreater(counts["ipv4"], 0)
            _, fails6, _, first6 = check_ipv6.check(r["pcap"], 20, ())
            self.assertFalse(sum(fails6.values()), first6)

    @unittest.skipUnless(TSHARK, "tshark is not installed")
    def test_tshark(self):
        for r, depth in ((self.sm, 1), (self.qq, 2)):
            # ssh is not dissected: a few generated SSH payloads are random bytes that read as a malformed SSH
            # message in some builds, tagged or not (payload, not tagging; seen in 1 of 8 builds)
            out = subprocess.run([TSHARK, "--disable-protocol", "ssh", "-r", r["pcap"], "-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE",
                                  "-T", "fields", "-E", "separator=;", "-e", "vlan.id", "-e", "ieee8021ad.id", "-e", "_ws.malformed",
                                  "-e", "_ws.expert.severity"],
                                 capture_output=True, text=True, timeout=600, check=True).stdout.splitlines()
            self.assertEqual(len(out), r["packets"])
            for line in out:
                vid, svid, bad, expert = (line.split(";") + ["", "", ""])[:4]
                self.assertTrue(vid, line)                                 # vlan.id on every frame; the 802.1ad outer tag has its own field
                self.assertEqual(bool(svid), depth == 2, line)
                self.assertEqual(bad, "", line)
                self.assertNotIn("error", expert, line)


class Units(unittest.TestCase):
    def test_tag_costs_four_bytes_before_padding(self):
        arp = b"\xaa" * 6 + b"\xbb" * 6 + b"\x08\x06" + b"\x00" * 28
        self.assertEqual(len(eth_tag(arp, 5)), len(arp) + 4)

    def test_classify_through_tag(self):
        f = b"\x00" * 12 + b"\x08\x06" + b"\x00" * 46
        self.assertEqual(classify(eth_tag(f, 10)), classify(f))

    def test_normalize(self):
        n = OGB.normalize_network_options
        self.assertIsNone(n(None))
        self.assertIsNone(n({"vlan": False}))
        self.assertEqual(n({"vlan": True}), n({"vlan": "subnet"}))
        self.assertEqual(n({"vlan": "42"})["vlan"], {"scheme": "fixed", "vid": 42, "qinq": None})
        self.assertEqual(n({"vlan": {"qinq": True, "scheme": "subnet"}})["vlan"]["qinq"], OGB.QINQ_DEFAULT_SVID)
        for bad in ({"vlan": 0}, {"vlan": 4095}, {"vlan": "nope"}, {"vlans": 1}, {"vlan": {"vid": 5, "scheme": "subnet"}}):
            with self.assertRaises(ValueError, msg=str(bad)):
                n(bad)

    def test_tagger_validates(self):
        with self.assertRaises(ValueError):
            VlanTagger.check("fixed", None, None)


if __name__ == "__main__":
    unittest.main()
