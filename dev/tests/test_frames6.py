"""netgen/frames6.py: pure IPv6 / VLAN / tunnel frame builders, zero-draw addressing, additive classify() arms.

Run from dev/:  python -m unittest tests.test_frames6
The builders are compared byte for byte with the independent golden helpers (tests/ipv6_vectors.py), validated by
checks/check_ipv6.py, and cross-checked with tshark when it is installed (that one test is skipped without it).
"""
import ipaddress
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import netgen  # noqa: E402 - sys.path is set up first
from netgen import core, frames6 as F  # noqa: E402 - sys.path is set up first
from netgen.identity import Identity  # noqa: E402 - sys.path is set up first
from checks import check_ipv6 as C  # noqa: E402 - sys.path is set up first
from tests import ipv6_vectors as V  # noqa: E402 - sys.path is set up first

TSHARK = shutil.which("tshark") or ("/Applications/Wireshark.app/Contents/MacOS/tshark"
                                    if os.path.exists("/Applications/Wireshark.app/Contents/MacOS/tshark") else None)
MAC_A, MAC_B = V.MAC_A, V.MAC_B
RA_SRC = bytes.fromhex("fe80000000000000000000000000000f")
SYN = 0x02


def _v6(payload_nh, seg, **kw):
    return F.eth(V.MAC_B, V.MAC_A, F.ETH_IPV6, F.ipv6(V.A, V.B, payload_nh, seg, **kw))


def _outer(proto, payload):
    return F.eth(V.MAC_B, V.MAC_A, 0x0800, F.ipv4_raw(b"\xc0\x00\x02\x01", b"\xc0\x00\x02\x02", proto, payload))


def _icmp4_echo():
    """A minimal IPv4 ICMP echo for a GRE carrier test, checksummed with the independent helper."""
    msg = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"abcd"
    msg = msg[:2] + struct.pack("!H", V.csum(msg)) + msg[4:]
    return F.ipv4_raw(b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02", 1, msg, ident=7)


def all_frames():
    """One of everything, including the tagged, extension-header and tunnel shapes."""
    inner6 = _v6(6, F.tcp6(V.A, V.B, 40000, 443, 1, 0, SYN, 65535))
    prefix = bytes.fromhex("fd000000000000010000000000000000")
    udp = _v6(17, F.udp6(V.A, V.B, 40000, 50000, b"hello"))    # ports no dissector claims, so tshark has no payload to reject
    return {
        "tcp": V.tcp(), "udp": udp, "echo": V.echo(),
        "ns": F.ns(MAC_A, V.LL_A, V.B), "na": F.na(MAC_B, MAC_A, V.B, V.LL_A), "rs": F.rs(MAC_A, V.LL_A),
        "ra": F.ra(MAC_B, RA_SRC, mtu=1500, prefixes=[(prefix, 64, 86400, 14400)]),
        "dad": F.ns(MAC_A, F.UNSPECIFIED, V.B, slla=False),
        "mld": F.mld_report(MAC_A, V.LL_A, [bytes.fromhex("ff0200000000000000000001ff000001")]),
        "hbh": _v6(17, F.udp6(V.A, V.B, 40000, 50000, b"x"), ext=[("hbh", b"\x05\x02\x00\x00")], flow=0xABCDE, tc=0x28),
        "frag": _v6(17, b"\xaa" * 24, ext=[("frag", 5, False, 0x11223344)]),
        "vlan": F.eth_tag(udp, 100, pcp=5), "qinq": F.eth_qinq(V.echo(), 200, 100),
        "gre4": _outer(47, F.gre(_icmp4_echo(), 0x0800, key=7, seq=1)),
        "gre6": _outer(47, F.gre(inner6[14:], F.ETH_IPV6)),
        "vxlan": _outer(17, F.udp_nocsum(F.vxlan_sport(inner6), 4789, F.vxlan(inner6, 5001))),
    }


class Vectors(unittest.TestCase):
    """Builder output equals the independent helper's bytes."""

    def test_matches_independent_vectors(self):
        self.assertEqual(_v6(6, F.tcp6(V.A, V.B, 40000, 443, 1, 0, SYN, 65535)), V.tcp())
        self.assertEqual(_v6(17, F.udp6(V.A, V.B, 5353, 53, b"hello")), V.udp())
        self.assertEqual(_v6(58, F.echo6(V.A, V.B, 1, 1, b"abcd")), V.echo())
        self.assertEqual(F.ns(MAC_A, V.LL_A, V.B), V.ns())
        self.assertEqual(F.na(MAC_B, MAC_A, V.B, V.LL_A), V.na())
        self.assertEqual(F.rs(MAC_A, V.LL_A), V.rs())
        self.assertEqual(F.ra(MAC_B, RA_SRC, mtu=1500), V.ra())

    def test_solicited_node_and_multicast_mac(self):
        self.assertEqual(F.solicited_node(V.B), V.solicited(V.B))
        self.assertEqual(F.mcast_mac6(V.ALL_NODES), V.mcast_mac(V.ALL_NODES))
        self.assertEqual(F.mcast_mac6(F.solicited_node(V.B)), bytes.fromhex("3333ff000002"))
        with self.assertRaises(ValueError):
            F.mcast_mac6(V.A)

    def test_ndp_hop_limit(self):
        for f in (F.ns(MAC_A, V.LL_A, V.B), F.na(MAC_B, MAC_A, V.B, V.LL_A), F.rs(MAC_A, V.LL_A), F.ra(MAC_B, RA_SRC)):
            self.assertEqual(f[21], 255)
        self.assertEqual(F.mld_report(MAC_A, V.LL_A, [V.ALL_NODES])[21], 1)

    def test_ra_prefix_option_layout(self):
        prefix = bytes.fromhex("fd000000000000010000000000000000")
        f = F.ra(MAC_B, RA_SRC, mtu=1500, prefixes=[(prefix, 64, 86400, 14400)])
        opt = f[14 + 40 + 16 + 8 + 8:]                     # after SLLA (8) and MTU (8)
        self.assertEqual(opt[:4], bytes([3, 4, 64, 0xC0]))
        self.assertEqual(struct.unpack("!III", opt[4:16]), (86400, 14400, 0))
        self.assertEqual(opt[16:32], prefix)

    def test_udp_zero_checksum_becomes_ffff(self):
        for n in range(65536):                              # find a payload whose computed checksum is 0
            seg = F.udp6(V.A, V.B, 1, 2, struct.pack("!H", n))
            if seg[6:8] == b"\xff\xff":
                self.assertTrue(C.csum_ok(V.A + V.B + struct.pack("!IBBBB", len(seg), 0, 0, 0, 17) + seg))
                return
        self.fail("no payload produced a zero checksum in 65536 tries")

    def test_extension_chain_and_header_fields(self):
        pkt = F.ipv6(V.A, V.B, 17, b"payload!", ext=[("hbh", b""), ("frag", 3, True, 9)], flow=0x12345, tc=0xAB, hop=7)
        self.assertEqual(struct.unpack("!I", pkt[:4])[0], 0x60000000 | 0xAB << 20 | 0x12345)
        self.assertEqual((pkt[6], pkt[7]), (0, 7))          # next header = hop-by-hop, hop limit
        self.assertEqual((pkt[40], pkt[41]), (44, 0))       # hbh -> fragment, 8 bytes in total
        self.assertEqual(pkt[48], 17)                       # fragment -> UDP
        self.assertEqual(struct.unpack("!H", pkt[50:52])[0], 3 << 3 | 1)
        self.assertEqual(struct.unpack("!H", pkt[4:6])[0], len(pkt) - 40)
        for bad in (dict(flow=1 << 20), dict(tc=256), dict(hop=256), dict(ext=[("frag", 1 << 13, 0, 0)]),
                    dict(ext=[("frag", 0, 0, 0), ("hbh", b"")]), dict(ext=[("bogus",)])):
            with self.assertRaises(ValueError):
                F.ipv6(V.A, V.B, 59, b"", **bad)


class Vlan(unittest.TestCase):
    def test_tag_is_a_pure_four_byte_insert(self):
        f = V.udp()
        t = F.eth_tag(f, 100, pcp=5, dei=1)
        self.assertEqual(len(t), len(f) + 4)
        self.assertEqual(t[:12], f[:12])
        self.assertEqual(t[12:16], bytes.fromhex("8100") + struct.pack("!H", 5 << 13 | 1 << 12 | 100))
        self.assertEqual(t[:12] + t[16:], f)                # stripping the tag restores the frame

    def test_qinq_order_and_validation(self):
        f = V.echo()
        q = F.eth_qinq(f, 200, 100)
        self.assertEqual(q[12:18], bytes.fromhex("88a8") + struct.pack("!H", 200) + bytes.fromhex("8100"))
        self.assertEqual(q[18:20], struct.pack("!H", 100))
        self.assertEqual(q[20:], f[12:])
        for kw in (dict(vid=4096), dict(vid=1, pcp=8), dict(vid=1, dei=2)):
            with self.assertRaises(ValueError):
                F.eth_tag(f, **kw)

    def test_tagging_before_writer_padding_costs_no_extra_bytes(self):
        short = _v6(59, b"")                                # 54 bytes as built, 60 once the writer pads
        self.assertEqual(len(short), 54)
        self.assertEqual(len(F.eth_tag(short, 5)), 58)
        self.assertEqual(core.record_bytes(len(F.eth_tag(short, 5))), core.record_bytes(len(short)))


class Tunnels(unittest.TestCase):
    def test_gre_header(self):
        self.assertEqual(F.gre(b"X"), b"\x00\x00\x08\x00X")
        self.assertEqual(F.gre(b"X", F.ETH_IPV6, key=0x01020304), b"\x20\x00\x86\xdd\x01\x02\x03\x04X")
        self.assertEqual(F.gre(b"X", key=1, seq=2), b"\x30\x00\x08\x00" + struct.pack("!II", 1, 2) + b"X")

    def test_vxlan_header_and_port(self):
        self.assertEqual(F.vxlan(b"INNER", 0xABCDEF), b"\x08\x00\x00\x00\xab\xcd\xef\x00INNER")
        with self.assertRaises(ValueError):
            F.vxlan(b"", 1 << 24)
        self.assertTrue(49152 <= F.vxlan_sport(b"z" * 60) <= 65535)

    def test_mss_arithmetic(self):
        self.assertEqual(F.MSS_V6, 1500 - 40 - 20)
        self.assertEqual(F.MSS_GRE, 1500 - 20 - 4 - 20 - 20)
        self.assertEqual(F.MSS_VXLAN, 1500 - 20 - 8 - 8 - 14 - 20 - 20)
        self.assertEqual((F.MSS_V6, F.MSS_GRE, F.MSS_VXLAN), (1440, 1436, 1410))


class Addressing(unittest.TestCase):
    def test_eui64_known_vector(self):
        # RFC 4291 Appendix A style: 34:56:78:9A:BC:DE -> 3656:78FF:FE9A:BCDE
        self.assertEqual(F.eui64(bytes.fromhex("3456789abcde")), bytes.fromhex("365678fffe9abcde"))

    def test_derivation(self):
        ident = Identity("Acme", "Manufacturing")
        mac = bytes.fromhex("020000a1b2c3")
        a = F.ula(ident, 20, mac)
        self.assertEqual(a, F.ula(Identity("Acme", "Manufacturing"), 20, mac))              # deterministic
        self.assertNotEqual(a[:6], F.ula(Identity("Other", "Retail"), 20, mac)[:6])         # per identity
        self.assertEqual(a[0], 0xFD)
        self.assertEqual(a[6:8], struct.pack("!H", 20))
        self.assertEqual(a[8:], F.eui64(mac))
        self.assertEqual(F.link_local(mac), bytes.fromhex("fe80000000000000") + F.eui64(mac))
        ext = F.external("evil.example")
        self.assertEqual(ext, F.external("evil.example"))
        self.assertNotEqual(ext, F.external("other.example"))
        self.assertIn(ipaddress.IPv6Address(ext), ipaddress.IPv6Network("2001:db8::/32"))
        self.assertIn(ipaddress.IPv6Address(a), ipaddress.IPv6Network("fc00::/7"))
        with self.assertRaises(ValueError):
            F.ula(ident, 1 << 16, mac)

    def test_no_rng_use(self):
        mods = [m for m in netgen._engine_modules() if hasattr(m, "rng")]
        before = [m.rng.getstate() for m in mods] + [random.getstate()]
        F.ula(Identity(), 10, MAC_A), F.link_local(MAC_A), F.external("k")
        all_frames()
        after = [m.rng.getstate() for m in mods] + [random.getstate()]
        self.assertEqual(before, after)


class Registries(unittest.TestCase):
    def test_module_is_invisible_to_rng_discovery(self):
        self.assertFalse(hasattr(F, "rng") and hasattr(F, "SEED"))
        self.assertFalse([k for k, v in vars(F).items() if isinstance(v, random.Random)])
        listed = sorted(m.__name__ for m in netgen._engine_modules() if hasattr(m, "rng") and hasattr(m, "SEED"))
        self.assertNotIn("netgen.frames6", listed)
        self.assertEqual(netgen.reseed_all(), len(listed))


class Classify(unittest.TestCase):
    def test_new_arms(self):
        f = all_frames()
        expect = {"tcp": "HTTPS", "udp": "UDP-other", "echo": "ICMPv6", "ns": "ICMPv6", "ra": "ICMPv6", "mld": "ICMPv6",
                  "hbh": "UDP-other", "frag": "IPv6-fragment", "vlan": "UDP-other", "qinq": "ICMPv6",
                  "gre4": "GRE", "gre6": "GRE", "vxlan": "VXLAN"}
        for k, v in expect.items():
            self.assertEqual(core.classify(f[k]), v, k)
        self.assertEqual(core.classify(_v6(17, F.udp6(V.A, V.B, 40000, 53, b"x"))), "DNS")

    def test_ipv6_edge_cases(self):
        self.assertEqual(core.classify(V.tcp()[:50]), "IPv6-other")
        self.assertEqual(core.classify(_v6(99, b"abcd")), "IPv6-proto-99")
        self.assertEqual(core.classify(_v6(59, b"", ext=[("hbh", b"")])), "IPv6-proto-59")
        self.assertEqual(core.classify(_v6(17, b"abcd", ext=[("hbh", b"")])[:57]), "IPv6-other")

    def test_legacy_frames_unchanged(self):
        """Names recorded from classify() as it was before the new arms (the same inputs were run against that code)."""
        mac = b"\x02\x00\x00\x00\x00\x01" * 2

        def v4(proto, l4, flags=0):
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 1, flags, 64, proto, 0, b"\x0a\0\0\1", b"\x0a\0\0\2")
            return mac + b"\x08\x00" + ip + l4

        def udp(sp, dp, body):
            return struct.pack("!HHHH", sp, dp, 8 + len(body), 0) + body

        cases = [
            (mac + b"\x08\x06" + bytes(28), "ARP"),
            (mac + b"\x88\xcc" + bytes(40), "Ethernet-other"),
            (v4(6, struct.pack("!HH", 50000, 443) + bytes(16)), "HTTPS"),
            (v4(6, struct.pack("!HH", 50000, 50001) + bytes(16)), "TCP-other"),
            (v4(17, udp(50000, 53, bytes(12))), "DNS"),
            (v4(17, udp(50000, 50002, b"\x80\x08" + bytes(12))), "RTP"),
            (v4(17, udp(50000, 50002, b"\x80\xc8" + bytes(12))), "RTCP"),
            (v4(17, udp(50000, 50002, bytes(12))), "UDP-other"),
            (v4(1, bytes(8)), "ICMP"),
            (v4(2, bytes(8)), "IGMP"),
            (v4(99, bytes(8)), "IP-proto-99"),
            # pinned quirk: a non-first fragment is classified from payload bytes read as ports, so even
            # bytes that look like a VXLAN datagram stay "UDP-other" (the VXLAN arm refuses fragments)
            (v4(17, struct.pack("!HH", 0x12B5, 4789) + b"\x00\x20\x00\x00\x08" + bytes(20), flags=0x00B9), "UDP-other"),
        ]
        for frame, name in cases:
            self.assertEqual(core.classify(frame), name)
        self.assertEqual(core.classify(v4(17, udp(50000, 4789, b"\x08" + bytes(20)))), "VXLAN")


@unittest.skipUnless(TSHARK, "tshark is not installed")
class Tshark(unittest.TestCase):
    FLAGGED = ('_ws.malformed || ip.checksum.status == "Bad" || tcp.checksum.status == "Bad" || '
               'udp.checksum.status == "Bad" || icmpv6.checksum.status == "Bad" || _ws.expert.severity == "Error"')

    def test_dissectors_and_zero_problems(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "t.pcap")
        frames = all_frames()
        V.write_pcap(p, list(frames.values()))
        base = [TSHARK, "-r", p, "-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE",
                "-o", "ip.check_checksum:TRUE"]
        r = subprocess.run(base + ["-T", "fields", "-e", "frame.protocols"], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(r.stdout.splitlines()), len(frames))
        seen = {x for line in r.stdout.splitlines() for x in line.strip().split(":") if x}
        for want in ("ipv6", "icmpv6", "vlan", "gre", "vxlan"):
            self.assertIn(want, seen)
        f = subprocess.run(base + ["-Y", self.FLAGGED, "-T", "fields", "-e", "frame.number", "-e", "_ws.col.Info"],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(f.returncode, 0, f.stderr)
        self.assertEqual(f.stdout.strip(), "", "tshark flagged frames: " + f.stdout)


class Checker(unittest.TestCase):
    def test_every_builder_passes_the_independent_checker(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        p = os.path.join(d, "t.pcap")
        V.write_pcap(p, list(all_frames().values()))
        counts, fails, _, first = C.check(p)
        self.assertEqual(fails, {}, first)
        self.assertEqual(counts["ipv6"], 13)                # the three tunnel frames are IPv4 on the outside


if __name__ == "__main__":
    unittest.main()
