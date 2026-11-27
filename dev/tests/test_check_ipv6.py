"""Tests for the independent IPv6 checker (checks/check_ipv6.py) against hand-built golden frames.

Run from dev/:  python -m unittest tests.test_check_ipv6
"""
import os
import shutil
import struct
import subprocess
import tempfile
import unittest

from checks import check_ipv6 as C
from checks.tshark_locate import find_tshark
from tests import ipv6_vectors as V

TSHARK = find_tshark()


class CheckerTests(unittest.TestCase):
    def run_frames(self, frames, exempt=()):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "t.pcap")
        V.write_pcap(p, frames)
        return C.check(p, exempt=exempt)

    def codes(self, frames):
        return self.run_frames(frames)[1]

    def test_golden_pass_and_committed_fixture_is_current(self):
        counts, fails, _, first = self.run_frames(V.golden())
        self.assertEqual(fails, {}, first)
        self.assertEqual((counts["ipv6"], counts["tcp"], counts["udp"], counts["icmp6"], counts["ndp"]),
                         (7, 1, 1, 5, 4))
        with open(V.FIXTURE, "rb") as fh:
            self.assertEqual(fh.read(), V.pcap_bytes(V.golden()), "re-run: python3 -m tests.ipv6_vectors")
        self.assertEqual(C.check(V.FIXTURE)[1], {})

    def test_corruptions_are_caught(self):
        def flip(f, i):
            return f[:i] + bytes([f[i] ^ 0xFF]) + f[i + 1:]
        udp0 = V.udp()
        udp0 = udp0[:60] + b"\0\0" + udp0[62:]                  # UDP checksum field zeroed
        bad_opt = V.ns(opt=b"\x01\x00" + V.MAC_A)               # option length 0, checksum recomputed
        cases = {
            "tcp.checksum": flip(V.tcp(), 70),
            "ip6.plen": V.udp(plen=200),
            "ip6.hoplimit": V.tcp(hop=0),
            "ndp.option": bad_opt,
            "ip6.mcastmac": V.ns()[:5] + b"\x07" + V.ns()[6:],
            "udp.checksum": udp0,
            "icmp6.checksum": flip(V.echo(), 56),
            "ndp.hoplimit": V.ns()[:21] + b"\x40" + V.ns()[22:],
        }
        for code, f in cases.items():
            self.assertIn(code, self.codes([f]), code)

    def test_exempt_and_exit_status(self):
        self.assertEqual(self.run_frames([V.tcp(hop=0)], exempt=["ip6."])[1], {})
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "bad.pcap")
        V.write_pcap(p, [V.tcp(hop=0)])
        self.assertEqual(C.main([p, "--quiet"]), 1)
        self.assertEqual(C.main([V.FIXTURE, "--quiet"]), 0)
        self.assertEqual(C.main([V.FIXTURE, "--quiet", "--decap", "gre,vxlan,6in4"]), 0)      # decap is implemented: no tunnels, still clean
        with self.assertRaises(SystemExit):
            C.main([V.FIXTURE, "--decap", "ipip"])                                            # an unknown kind is a usage error

    def test_ipv4_only_pcap_is_silent(self):
        ip4 = bytes(6) + bytes(6) + b"\x08\x00" + struct.pack("!BBHHHBBH", 0x45, 0, 20, 0, 0, 64, 6, 0) + bytes(8)
        tagged = bytes(12) + b"\x81\x00\x00\x05\x08\x00" + ip4[14:]
        counts, fails, _, _ = self.run_frames([ip4, tagged])
        self.assertEqual((counts["ipv6"], counts["non_ip6"], fails), (0, 2, {}))

    def test_vlan_tag_walk(self):
        f = V.udp()
        tagged = f[:12] + b"\x81\x00\x00\x0a" + f[12:]
        counts, fails, _, _ = self.run_frames([tagged])
        self.assertEqual((counts["ipv6"], fails), (1, {}))

    def test_extension_chain(self):
        # hop-by-hop (PadN) in front of a UDP datagram: build checksum over the real next header
        seg = struct.pack("!HHHH", 1, 2, 9, 0) + b"x"
        seg = V.with_csum(V.A, V.B, 17, seg, 6)
        ext = b"\x11\x00\x01\x04\x00\x00\x00\x00"
        self.assertEqual(self.codes([V.frame(V.A, V.B, 0, ext + seg)]), {})
        self.assertIn("ip6.exthdr", self.codes([V.frame(V.A, V.B, 0, b"\x11\x09" + ext[2:] + seg)]))

    @unittest.skipUnless(TSHARK, "tshark not installed")
    def test_tshark_agrees_checksums_are_valid(self):
        out = subprocess.run([TSHARK, "-r", V.FIXTURE, "-o", "tcp.check_checksum:TRUE",
                              "-o", "udp.check_checksum:TRUE",
                              "-T", "fields", "-e", "tcp.checksum.status", "-e", "udp.checksum.status",
                              "-e", "icmpv6.checksum.status"],
                             capture_output=True, text=True, check=True).stdout
        vals = [v for line in out.splitlines() for v in line.split("\t") if v]
        self.assertEqual(len(vals), 7, out)
        self.assertEqual(set(vals), {"1"}, out)          # 1 = good


if __name__ == "__main__":
    unittest.main()
