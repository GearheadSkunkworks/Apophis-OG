"""Regression tests for the pcap importer (pcapprofile): container formats, link layers, malformed
frames, size and table caps, recipe validation, and the report/compare content.

Run from dev/:  python -m unittest tests.test_pcap_import
Crafted captures only; nothing here needs a real capture or an external dissector.
"""
import json
import os
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
if DEV not in sys.path:
    sys.path.insert(0, DEV)

import pcapprofile as P                                # noqa: E402

ETH = b"\x00\x01\x02\x03\x04\x05" + b"\x06\x07\x08\x09\x0a\x0b"


def ip4(src, dst, proto, payload):
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0) + bytes(src) + bytes(dst)
    return hdr + payload


def tcp(sport, dport, flags, payload=b""):
    return struct.pack(">HHIIBBHHH", sport, dport, 1, 1, 0x50, flags, 8192, 0, 0) + payload


def frame(sport=40000, dport=80, flags=0x02, payload=b"", src=(10, 0, 0, 1), dst=(10, 0, 0, 2)):
    return ETH + b"\x08\x00" + ip4(src, dst, 6, tcp(sport, dport, flags, payload))


def write_pcap(path, frames, link=1, endian="<", ns=False):
    with open(path, "wb") as f:
        magic = 0xA1B23C4D if ns else 0xA1B2C3D4
        f.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, link))
        for i, d in enumerate(frames):
            f.write(struct.pack(endian + "IIII", 1_700_000_000 + i, 0, len(d), len(d)) + d)


def write_pcapng(path, frames, link=1, big=False):
    e = ">" if big else "<"

    def blk(t, body):
        body += b"\0" * ((-len(body)) % 4)
        return struct.pack(e + "II", t, len(body) + 12) + body + struct.pack(e + "I", len(body) + 12)
    out = blk(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    out += blk(1, struct.pack(e + "HHI", link, 0, 65535))
    for i, d in enumerate(frames):
        t = (1_700_000_000 + i) * 10 ** 6
        out += blk(6, struct.pack(e + "IIIII", 0, t >> 32, t & 0xFFFFFFFF, len(d), len(d)) + d)
    with open(path, "wb") as f:
        f.write(out)


class Base(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.dir = self._td.name

    def p(self, name):
        return os.path.join(self.dir, name)

    GOOD = [frame(40000 + i, 80, 0x02) for i in range(20)] + [frame(40000, 80, 0x18, b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n")]


class ContainerFormats(Base):
    def test_pcapng_reads_every_packet(self):
        """pcapng used to return zero packets (block type read from the length field)."""
        write_pcapng(self.p("a.pcapng"), self.GOOD)
        pr = P.profile(self.p("a.pcapng"))
        self.assertEqual(pr["format"], "pcapng")
        self.assertEqual(pr["pkts"], len(self.GOOD))
        self.assertEqual(len(pr["hosts"]), 2)
        self.assertEqual(pr["protocols"].get("HTTP"), 21)

    def test_pcapng_big_endian_matches_little(self):
        write_pcapng(self.p("le.pcapng"), self.GOOD)
        write_pcapng(self.p("be.pcapng"), self.GOOD, big=True)
        a, b = P.profile(self.p("le.pcapng")), P.profile(self.p("be.pcapng"))
        self.assertEqual((a["pkts"], a["protocols"]), (b["pkts"], b["protocols"]))

    def test_pcapng_matches_pcap(self):
        write_pcap(self.p("a.pcap"), self.GOOD)
        write_pcapng(self.p("a.pcapng"), self.GOOD)
        a, b = P.profile(self.p("a.pcap")), P.profile(self.p("a.pcapng"))
        self.assertEqual((a["pkts"], a["bytes"], a["protocols"]), (b["pkts"], b["bytes"], b["protocols"]))

    def test_endianness_and_nanosecond(self):
        for name, kw in (("be", dict(endian=">")), ("ns", dict(ns=True))):
            write_pcap(self.p(name), self.GOOD, **kw)
            self.assertEqual(P.profile(self.p(name))["pkts"], len(self.GOOD), name)

    def test_truncated_tail_is_tolerated(self):
        write_pcap(self.p("t.pcap"), self.GOOD)
        with open(self.p("t.pcap"), "rb") as fh:
            raw = fh.read()
        with open(self.p("t.pcap"), "wb") as fh:
            fh.write(raw[:-9])
        self.assertEqual(P.profile(self.p("t.pcap"))["pkts"], len(self.GOOD) - 1)


class LinkLayers(Base):
    def test_qinq_double_tag_stripped(self):
        fr = [d[:12] + b"\x88\xa8\x00\x64\x81\x00\x00\x65" + d[12:] for d in self.GOOD]
        write_pcap(self.p("q.pcap"), fr)
        pr = P.profile(self.p("q.pcap"))
        self.assertEqual(len(pr["hosts"]), 2)
        self.assertEqual(pr["nonip"], 0)

    def test_bsd_loopback(self):
        fr = [b"\x02\x00\x00\x00" + d[14:] for d in self.GOOD]
        write_pcap(self.p("lo.pcap"), fr, link=0)
        pr = P.profile(self.p("lo.pcap"))
        self.assertEqual(pr["unsupported"], 0)
        self.assertEqual(len(pr["hosts"]), 2)

    def test_unsupported_link_is_named_and_refused(self):
        write_pcap(self.p("w.pcap"), self.GOOD, link=105)
        pr = P.profile(self.p("w.pcap"))
        self.assertEqual(pr["unsupported_links"], {105: len(self.GOOD)})
        self.assertIn("802.11", P.unusable_reason(pr))

    def test_header_only_and_empty_are_refused_with_a_reason(self):
        write_pcap(self.p("e.pcap"), [])
        self.assertIn("no packets", P.unusable_reason(P.profile(self.p("e.pcap"))))
        with open(self.p("z.pcap"), "wb"):
            pass
        self.assertIsNone(P.kind(self.p("z.pcap")))


class MalformedFrames(Base):
    def test_runt_ipv4_frames_do_not_crash(self):
        runts = [ETH + b"\x08\x00" + b"\x45" * (n % 2) + b"\x00" * n for n in range(0, 19)]
        write_pcap(self.p("r.pcap"), runts + self.GOOD)
        pr = P.profile(self.p("r.pcap"))                 # used to raise IndexError
        self.assertEqual(pr["pkts"], len(runts) + len(self.GOOD))
        self.assertEqual(len(pr["hosts"]), 2)

    def test_non_first_fragment_is_counted_not_parsed(self):
        hdr = bytearray(ip4((10, 0, 0, 1), (10, 0, 0, 2), 6, b"GET /x HTTP/1.1\r\n\r\n" + b"\0" * 20))
        hdr[6:8] = b"\x00\xb9"                           # fragment offset 185
        write_pcap(self.p("f.pcap"), [ETH + b"\x08\x00" + bytes(hdr)] * 3)
        pr = P.profile(self.p("f.pcap"))
        self.assertEqual(pr["convos"], {})               # no bogus ports from payload bytes
        self.assertEqual(sum(pr["skips"].values()), 3)

    def test_ipv6_extension_header_reaches_tcp(self):
        t = tcp(40000, 443, 0x02)
        ext = bytes([6, 0, 1, 4, 0, 0, 0, 0])            # hop-by-hop, next header TCP
        ip6 = b"\x60\0\0\0" + struct.pack(">HBB", len(ext) + len(t), 0, 64) + bytes(range(16)) + bytes(range(16, 32))
        write_pcap(self.p("v6.pcap"), [ETH + b"\x86\xdd" + ip6 + ext + t] * 4)
        pr = P.profile(self.p("v6.pcap"))
        self.assertEqual(len(pr["convos"]), 1)
        self.assertEqual(list(pr["server_ports"].values()), [4])

    def test_hostile_strings_are_escaped_in_the_report(self):
        pl = b"GET /<script>alert(1)</script> HTTP/1.1\r\nHost: <img src=x onerror=1>\r\nUser-Agent: \"><svg/onload=1>\r\n\r\n"
        write_pcap(self.p("x.pcap"), [frame(40000, 80, 0x02), frame(40000, 80, 0x18, pl)])
        out = P.content(P.profile(self.p("x.pcap")))
        for bad in ("<script>", "<img src=x", "<svg/onload"):
            self.assertNotIn(bad, out)


class Limits(Base):
    def test_size_limit(self):
        write_pcap(self.p("a.pcap"), self.GOOD)
        old = P.MAX_CAPTURE_BYTES
        try:
            P.MAX_CAPTURE_BYTES = 100
            with self.assertRaises(ValueError) as cm:
                P.profile(self.p("a.pcap"))
            self.assertIn("importer accepts", str(cm.exception))
        finally:
            P.MAX_CAPTURE_BYTES = old

    def test_flow_table_is_capped_and_overflow_counted(self):
        write_pcap(self.p("m.pcap"), [frame(1000 + i, 80, 0x02, src=(10, 0, 1, i % 250 + 1)) for i in range(300)])
        old = (P.MAX_CONVOS, P.MAX_HOSTS)
        try:
            P.MAX_CONVOS, P.MAX_HOSTS = 50, 20
            pr = P.profile(self.p("m.pcap"))
        finally:
            P.MAX_CONVOS, P.MAX_HOSTS = old
        self.assertLessEqual(len(pr["convos"]), 50)
        self.assertLessEqual(len(pr["hosts"]), 20)
        self.assertGreater(pr["overflow"]["convos"], 0)
        self.assertGreater(pr["overflow"]["hosts"], 0)


class ReadGuard(Base):
    def test_blocked_open_times_out_instead_of_hanging(self):
        """A FIFO with no writer blocks open() the way a pending macOS folder-permission prompt does."""
        fifo = self.p("blocked")
        os.mkfifo(fifo)
        with self.assertRaises(ValueError) as cm:
            P.probe_readable(fifo, timeout=0.3)
        self.assertIn("did not answer", str(cm.exception))

    def test_missing_file_message_names_the_file(self):
        with self.assertRaises(ValueError) as cm:
            P.probe_readable(self.p("nope.pcap"), timeout=2)
        self.assertIn("nope.pcap", str(cm.exception))

    def test_load_recipe_rejects_unopenable_file(self):
        with self.assertRaises(ValueError):
            P.load_recipe(self.p("absent.json"))


class RecipeContract(Base):
    def spec(self):
        write_pcap(self.p("a.pcap"), self.GOOD)
        pr = P.profile(self.p("a.pcap"))
        return P.build_spec(pr, os.path.join(DEV, "inventory.json"))

    def test_exported_recipe_round_trips_through_validation(self):
        spec = self.spec()
        self.assertEqual(spec["schema"], P.RECIPE_SCHEMA)
        self.assertIn("profile_summary", spec)
        clean, warn = P.validate_recipe(json.loads(json.dumps(spec)))
        self.assertEqual(warn, [])
        self.assertEqual(len(clean["flows"]), len(spec["flows"]))

    def test_rejects_bad_shapes_with_a_reason(self):
        for bad in ([], {}, {"flows": None}, {"flows": []}, {"flows": [{"protocol": "HTTP"}], "host_map": "x"},
                    {"schema": 99, "flows": [{"protocol": "HTTP"}]},
                    {"flows": [{"protocol": "HTTP", "sessions": "lots"}]}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                P.validate_recipe(bad)

    def test_drops_only_the_bad_flows(self):
        clean, warn = P.validate_recipe({"flows": [{"protocol": "HTTP", "sessions": 5, "paths": "oops"},
                                                   {"protocol": 7}, "junk", {"protocol": "DNS", "sessions": 1e99}]})
        self.assertEqual([f["protocol"] for f in clean["flows"]], ["HTTP", "DNS"])
        self.assertEqual(clean["flows"][0]["paths"], [])
        self.assertLessEqual(clean["flows"][1]["sessions"], 10_000_000)
        self.assertEqual(len(warn), 2)

    def test_load_recipe_names_the_file(self):
        with open(self.p("bad.json"), "w") as fh:
            fh.write("{nope")
        with self.assertRaises(ValueError) as cm:
            P.load_recipe(self.p("bad.json"))
        self.assertIn("bad.json", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
