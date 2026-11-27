"""Flow table (dev/flowtable.py) and the opt-in truth export (dev/exports_truth.py, build option exports)."""
import json
import os
import shutil
import socket
import struct
import sys
import tempfile
import unittest
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "tools"))
import build_manifest as BM        # noqa: E402 - sys.path is set up before the import
import exports_truth as XT         # noqa: E402 - sys.path is set up before the import
import flowtable as FT             # noqa: E402 - sys.path is set up before the import
import opengenerator_build as OGB  # noqa: E402 - sys.path is set up before the import
import verify_manifest as VM       # noqa: E402 - sys.path is set up before the import

A, B = "10.0.0.1", "10.0.0.2"
SYN, ACK, FIN, RST = 0x02, 0x10, 0x01, 0x04


def _ip(proto, src, dst, l4):
    n = socket.inet_aton
    return b"\x45\x00" + struct.pack(">H", 20 + len(l4)) + b"\0\0\0\0\x40" + bytes([proto]) + b"\0\0" + n(src) + n(dst) + l4


def _eth(ip):
    return b"\1\1\1\1\1\1\2\2\2\2\2\2\x08\x00" + ip


def tcp(src, sp, dst, dp, flags, pay=b""):
    return _eth(_ip(6, src, dst, struct.pack(">HHIIBBHHH", sp, dp, 0, 0, 5 << 4, flags, 0, 0, 0) + pay))


def udp(src, sp, dst, dp, pay=b""):
    return _eth(_ip(17, src, dst, struct.pack(">HHHH", sp, dp, 8 + len(pay), 0) + pay))


ARP = b"\xff" * 6 + b"\2" * 6 + b"\x08\x06" + b"\0" * 28


def pcap(path, pkts):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in pkts:
            f.write(struct.pack("<IIII", int(ts), round((ts - int(ts)) * 1e6), len(fr), len(fr)) + fr)


class Synthetic(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="og-flow-")
        self.p = os.path.join(self.d, "t.pcap")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def flows(self, pkts, tags=None, **kw):
        pcap(self.p, pkts)
        tp = None
        if tags:
            tp = os.path.join(self.d, "t.tags")
            names = sorted(set(tags))
            BM.write_tags(tp, {t: [i] for i, t in enumerate(names)}, bytearray(names.index(t) for t in tags))
        st = {}
        return list(FT.flows(self.p, tp, stats=st, **kw)), st

    def test_idle_timeout_splits_udp(self):
        fl, _ = self.flows([(100.0, udp(A, 1000, B, 53)), (110.0, udp(B, 53, A, 1000)), (200.0, udp(A, 1000, B, 53))])
        self.assertEqual([(f["orig_pkts"], f["resp_pkts"]) for f in fl], [(1, 1), (1, 0)])
        self.assertEqual(fl[0]["start"], 100.0)
        self.assertEqual(fl[0]["end"], 110.0)

    def test_gap_under_idle_is_one_flow(self):
        fl, _ = self.flows([(100.0, udp(A, 1000, B, 53)), (150.0, udp(A, 1000, B, 53))])
        self.assertEqual(len(fl), 1)

    def test_tcp_port_reuse_after_fin(self):
        k = (A, 4000, B, 80)
        fl, st = self.flows([(1.0, tcp(*k, SYN)), (1.1, tcp(B, 80, A, 4000, SYN | ACK)), (1.2, tcp(*k, ACK, b"abc")),
                             (2.0, tcp(*k, FIN | ACK)), (3.0, tcp(*k, SYN)), (3.1, tcp(B, 80, A, 4000, SYN | ACK))])
        self.assertEqual(len(fl), 2)
        self.assertEqual((fl[0]["orig_pkts"], fl[0]["resp_pkts"], fl[0]["orig_bytes"]), (3, 1, 3))
        self.assertEqual(fl[0]["flags_orig"], SYN | ACK | FIN)
        self.assertEqual((fl[1]["first_pkt"], fl[1]["last_pkt"]), (5, 6))

    def test_syn_retransmit_without_close_is_same_flow(self):
        k = (A, 4000, B, 80)
        fl, _ = self.flows([(1.0, tcp(*k, SYN)), (2.0, tcp(*k, SYN))])
        self.assertEqual(len(fl), 1)

    def test_one_way_flow_and_bytes(self):
        fl, _ = self.flows([(1.0, udp(A, 5, B, 6, b"xxxx")), (1.5, udp(A, 5, B, 6, b"yy"))])
        f = fl[0]
        self.assertEqual((f["orig_pkts"], f["resp_pkts"], f["resp_ip_bytes"], f["flags_resp"]), (2, 0, 0, 0))
        self.assertEqual((f["orig_bytes"], f["orig_ip_bytes"]), (6, 20 + 8 + 4 + 20 + 8 + 2))
        self.assertEqual((f["src"], f["dport"], f["proto"], f["tag"], f["tags"]), (A, 6, "udp", None, []))

    def test_tag_majority_and_packet_identity(self):
        pk = [(1.0, udp(A, 5, B, 6)), (1.1, ARP), (1.2, udp(B, 6, A, 5)), (1.3, udp(A, 5, B, 6)), (1.4, ARP)]
        fl, st = self.flows(pk, tags=["baseline:x", "baseline:x", "incident:y", "incident:y", "baseline:x"])
        self.assertEqual((fl[0]["tag"], fl[0]["tags"]), ("incident:y", ["baseline:x", "incident:y"]))
        self.assertEqual(st, {"packets": 5, "unflowed": 2})
        self.assertEqual(sum(f["orig_pkts"] + f["resp_pkts"] for f in fl) + st["unflowed"], st["packets"])

    def test_sidecar_length_mismatch_raises(self):
        pcap(self.p, [(1.0, udp(A, 5, B, 6)), (2.0, udp(A, 5, B, 6))])
        tp = os.path.join(self.d, "t.tags")
        BM.write_tags(tp, {"a": [0]}, bytearray(1))
        with self.assertRaises(ValueError):
            list(FT.flows(self.p, tp))


NAMES = ["ndr-rdp-brute", "npm-sql1-service-failure"]


def _build(d, stem, modules=NAMES, **kw):
    return OGB.build(scale=0.004, out=os.path.join(d, stem + ".pcap"), keylog=os.path.join(d, stem + ".keys"),
                     inventory=os.path.join(DEV, "inventory.json"), certs_dir=None, iocs_prefix=None,
                     modules=modules, progress=False, **kw)


class Build(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="og-truth-")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def manifest(self, s):
        with open(os.path.join(self.d, s["manifest"])) as f:
            return json.load(f)

    def test_option_off_writes_nothing_extra(self):
        s = _build(self.d, "off")
        m = self.manifest(s)
        self.assertNotIn("exports", m)
        self.assertNotIn("exports", m["parameters"])
        self.assertNotIn("exports", s)
        self.assertFalse([f for f in os.listdir(self.d) if "truth" in f])

    def test_exports_on_writes_truth_and_manifest_block(self):
        s = _build(self.d, "on", exports={"truth"})
        m = self.manifest(s)
        b = m["exports"]["truth"]
        self.assertEqual((b["kind"], b["file"], b["exports_consistent"]), ("flow-truth", "on-truth.jsonl", True))
        self.assertEqual(b["packets"], s["packets"])
        self.assertEqual(b["tags_sha256"], BM.sha256_file(os.path.join(self.d, "on.tags")))
        self.assertEqual(m["parameters"]["exports"], ["truth"])
        self.assertTrue(m["parameters"]["tag_sidecar"])
        self.assertIn("on-truth.jsonl", [o["name"] for o in m["outputs"]])
        self.assertEqual(VM.verify(os.path.join(self.d, s["manifest"])), [])
        with open(os.path.join(self.d, "on-truth.jsonl")) as f:
            rows = [json.loads(x) for x in f]
        self.assertEqual(len(rows), b["records"])
        self.assertEqual(sum(r["orig_pkts"] + r["resp_pkts"] for r in rows) + b["unflowed_frames"], s["packets"])
        self.assertTrue(any(not r["benign"] and not r["scenario"].startswith("baseline:") for r in rows))
        self.assertTrue(all(r["scenario"].startswith("baseline:") for r in rows if r["benign"]))
        self.assertEqual(rows[0]["rules"]["tcp_idle"], 300.0)

    def test_hold_previous_keeps_build_when_only_exports_differ(self):
        _build(self.d, "x")
        s = _build(self.d, "x", exports={"truth"})
        earlier = os.path.join(self.d, "earlier-builds")
        self.assertTrue(os.path.isdir(earlier))
        self.assertTrue(any(f.endswith(".pcap") for _r, _d, fs in os.walk(earlier) for f in fs))
        self.assertTrue(os.path.isfile(os.path.join(self.d, s["manifest"])))

    def test_unknown_export_rejected(self):
        with self.assertRaises(ValueError):
            _build(self.d, "bad", exports={"nope"})
        self.assertFalse(os.path.exists(os.path.join(self.d, "bad.pcap")))

    def test_exporter_failure_keeps_capture(self):
        with mock.patch.object(XT.flowtable, "flows", side_effect=RuntimeError("boom")):
            s = _build(self.d, "f", exports={"truth"})
        self.assertTrue(os.path.isfile(s["pcap"]))
        b = self.manifest(s)["exports"]["truth"]
        self.assertIn("boom", b["error"])
        self.assertNotIn("file", b)
        self.assertFalse(os.path.exists(os.path.join(self.d, "f-truth.jsonl")))
        self.assertFalse(os.path.exists(os.path.join(self.d, "f-truth.jsonl.tmp")))

    def test_pin_unchanged_with_exports_on(self):
        s = _build(self.d, "pin", modules=[], exports={"truth"})
        self.assertEqual(s["packets"], 466343)
        self.assertTrue(self.manifest(s)["exports"]["truth"]["exports_consistent"])


if __name__ == "__main__":
    unittest.main()
