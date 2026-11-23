"""npm-wireless-degradation built alone (no normal day) must carry its own CAPWAP / DTLS traffic.

Run from dev/:  python -m unittest tests.test_wireless_degradation
The scenario is built in a child process (engine state is process-global) with the day switched off, then the
pcap is parsed with struct only.
"""
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from collections import defaultdict

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHILD = """
import sys
sys.path.insert(0, %r)
import opengenerator_build as OGB
class NoDay(OGB.Day):
    def build(self): pass
OGB.Day = NoDay
OGB.build(scale=0.004, out=sys.argv[1], keylog=sys.argv[1] + '.keys', inventory=%r, certs_dir=None,
          iocs_prefix=None, modules=['npm-wireless-degradation'], progress=False, ot_nets=None)
""" % (DEV, os.path.join(DEV, "inventory.json"))


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def read_pcap(path):
    with open(path, "rb") as f:
        g = f.read(24)
        end = "<" if g[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = g[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            sec, frac, n, _ = struct.unpack(end + "IIII", h)
            yield sec + frac / (1e9 if nano else 1e6), f.read(n)


FULL_CHILD = """
import sys
sys.path.insert(0, %r)
import opengenerator_build as OGB
from netgen import capwap
if sys.argv[2] == 'off':          # the scenario's own stream switched off: only the normal day's tunnels remain
    capwap.Plane.stream_all = lambda self, aps, t0, t1: iter(())
OGB.build(scale=0.004, out=sys.argv[1], keylog=sys.argv[1] + '.keys', inventory=%r, certs_dir=None,
          iocs_prefix=None, modules=['npm-wireless-degradation'], progress=False, ot_nets=None)
""" % (DEV, os.path.join(DEV, "inventory.json"))


class NoDoubleEmission(unittest.TestCase):
    def test_full_build_does_not_stream_the_tunnels_twice(self):
        """With the normal day on, the scenario must add no tunnel traffic of its own (plane.live is already set)."""
        d = tempfile.mkdtemp(prefix="og-wlan2-")
        try:
            sizes = {}
            for mode in ("on", "off"):
                pcap = os.path.join(d, mode + ".pcap")
                subprocess.run([sys.executable, "-c", FULL_CHILD, pcap, mode], check=True, timeout=400, capture_output=True)
                sizes[mode] = sum(1 for _ in read_pcap(pcap))
            self.assertEqual(sizes["on"], sizes["off"])
        finally:
            import shutil
            shutil.rmtree(d, ignore_errors=True)


class WirelessDegradation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="og-wlan-")
        pcap = os.path.join(cls.d, "w.pcap")
        subprocess.run([sys.executable, "-c", CHILD, pcap], check=True, timeout=300, capture_output=True)
        cls.pk = []      # (ts, ip header dict, ip payload) for IPv4
        for ts, fr in read_pcap(pcap):
            if len(fr) < 34 or fr[12:14] != b"\x08\x00":
                continue
            ip = fr[14:]
            ihl = (ip[0] & 15) * 4
            cls.pk.append((ts, {"ver": ip[0] >> 4, "ihl": ihl, "len": struct.unpack("!H", ip[2:4])[0],
                               "id": struct.unpack("!H", ip[4:6])[0], "ff": struct.unpack("!H", ip[6:8])[0],
                               "proto": ip[9], "src": ip[12:16], "dst": ip[16:20], "ok": csum(ip[:ihl]) == 0,
                               "hdr": ip[:ihl], "wire": len(ip)}, ip[ihl:struct.unpack("!H", ip[2:4])[0]]))
        # (ts, sport, dport, payload) of first fragments / unfragmented UDP
        cls.udp = [(ts, *struct.unpack("!HH", p[:4]), p[8:]) for ts, h, p in cls.pk
                   if h["proto"] == 17 and not (h["ff"] & 0x1FFF) and len(p) >= 8]

    def ports(self, side):
        return [u for u in self.udp if side in (u[1], u[2])]

    def test_capwap_both_channels(self):
        self.assertTrue(self.ports(5246) and self.ports(5247))

    def test_dtls_record_types_on_control(self):
        types = {u[3][4] for u in self.ports(5246) if u[3][:1] == b"\x01" and len(u[3]) > 5}
        self.assertTrue({21, 22, 23} <= types, types)

    def test_every_header_checksum_and_fields(self):
        for ts, h, p in self.pk:
            self.assertTrue(h["ok"])
            self.assertEqual(h["ver"], 4)
            self.assertEqual(h["len"], h["wire"])           # total length equals what is on the wire
            self.assertEqual(h["ihl"], 20)

    def test_ip_fragments_reassemble(self):
        sets = defaultdict(list)
        for ts, h, p in self.pk:
            if h["ff"] & 0x3FFF:        # MF or offset set
                sets[(h["src"], h["dst"], h["id"], h["proto"])].append((h["ff"], p, h["len"] - h["ihl"]))
        self.assertTrue(sets, "no IPv4 fragments")
        for k, frs in sets.items():
            frs.sort(key=lambda x: x[0] & 0x1FFF)
            pos = 0
            for i, (ff, p, ln) in enumerate(frs):
                self.assertEqual((ff & 0x1FFF) * 8, pos)
                self.assertEqual(bool(ff & 0x2000), i < len(frs) - 1)
                if i < len(frs) - 1:
                    self.assertEqual(ln % 8, 0)
                pos += ln
            first = frs[0][1]
            ulen = struct.unpack("!H", first[4:6])[0]      # UDP length from the first fragment's header
            self.assertEqual(pos, ulen)                    # reassembled length == original datagram

    def test_echo_gap_and_discovery_before_join(self):
        ctrl = [u for u in self.udp if u[2] == 5246 and u[3][:1] == b"\x01"]    # AP -> AC, DTLS-wrapped
        clear = [u for u in self.udp if u[2] == 5246 and u[3][:1] == b"\x00"]   # Discovery (clear)
        self.assertTrue(clear, "no Discovery Requests")
        # AP -> AC application data at the 30 s cadence: some AP shows a gap of >= 60 s in its control records
        by = defaultdict(list)
        for ts, h, p in self.pk:
            if h["proto"] == 17 and not (h["ff"] & 0x1FFF) and struct.unpack("!H", p[2:4])[0] == 5246 and p[8:9] == b"\x01" and p[12] == 23:
                by[(h["src"])].append(ts)
        self.assertTrue(by)
        gaps = [b - a for v in by.values() for a, b in zip(sorted(v), sorted(v)[1:])]
        self.assertTrue(any(g >= 60 for g in gaps), "no echo gap during the stall")
        self.assertTrue(sum(1 for g in gaps if 29 < g < 31) > 20, "steady 30 s echo cadence missing")
        # every handshake ClientHello after a Discovery from the same AP
        disc = defaultdict(list)
        for ts, h, p in self.pk:
            if h["proto"] == 17 and not (h["ff"] & 0x1FFF) and struct.unpack("!H", p[2:4])[0] == 5246:
                if p[8:9] == b"\x00":
                    disc[h["src"]].append(ts)
                elif p[8:9] == b"\x01" and len(p) > 21 and p[12] == 22 and p[25:26] == b"\x01":
                    self.assertTrue(any(d < ts for d in disc[h["src"]]), "ClientHello without a Discovery")
        self.assertTrue(len(disc) >= 2, "rejoin waves involve several APs")
