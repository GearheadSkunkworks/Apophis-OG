"""E4: IPFIX / NetFlow v9 encoder (ipfixenc), the exporter pcap + CSV writer and exporter wiring (exports_ipfix).

An independent decoder in this file checks the byte layout against RFC 7011 / RFC 3954; tshark's cflow
dissector checks a scale-0.004 build when tshark is installed (OG_TSHARK overrides its path).

Run from dev/:  python -m unittest tests.test_ipfix
"""
import csv
import datetime
import hashlib
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import types
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import build_manifest as BM        # noqa: E402 - sys.path is set up first
import exports_ipfix as XI         # noqa: E402 - sys.path is set up first
import flowtable as FT             # noqa: E402 - sys.path is set up first
import ipfixenc as E               # noqa: E402 - sys.path is set up first
import opengenerator_build as OGB  # noqa: E402 - sys.path is set up first
import pcapprofile                 # noqa: E402 - sys.path is set up first
from tests.test_flowtable import SYN, tcp, udp, pcap  # noqa: E402 - sys.path is set up first

TSHARK = os.environ.get("OG_TSHARK") or "/Applications/Wireshark.app/Contents/MacOS/tshark"
IPFIX, NF9 = E.IPFIX, E.NF9


# ---------------------------------------------------------------- an independent decoder (RFC 7011 / 3954 layout)
class Decoder:
    """Decodes messages in order, keeping templates; asserts the structure as it goes."""

    def __init__(self, version):
        self.v, self.tmpl = version, {}

    def message(self, m):
        v = struct.unpack("!H", m[:2])[0]
        assert v == self.v, v
        if v == IPFIX:
            _, ln, et, seq, dom = struct.unpack("!HHIII", m[:16])
            off = 16
            assert ln == len(m), (ln, len(m))
            up = count = None
        else:
            _, count, up, et, seq, dom = struct.unpack("!HHIIII", m[:20])
            off, ln = 20, len(m)
        sets, recs, ntmpl = [], [], 0
        while off < ln:
            sid, sl = struct.unpack("!HH", m[off:off + 4])
            assert sl >= 4 and off + sl <= ln, (sid, sl)
            body = m[off + 4:off + sl]
            if sid == (2 if v == IPFIX else 0):
                ntmpl += self._templates(body)
            else:
                assert sid >= 256 and sid in self.tmpl, "data set before its template: %d" % sid
                recs += [(sid, r) for r in self._records(sid, body, sl)]
            sets.append((sid, sl))
            off += sl
        if v == NF9:
            assert count == ntmpl + len(recs), (count, ntmpl, len(recs))
        return {"export_time": et, "seq": seq, "domain": dom, "uptime": up, "sets": sets, "ntmpl": ntmpl, "nrec": len(recs),
                "len": len(m)}, recs

    def _templates(self, body):
        p = n = 0
        while p + 4 <= len(body):
            tid, nf = struct.unpack("!HH", body[p:p + 4])
            p += 4
            fs = []
            for _ in range(nf):
                eid, fl = struct.unpack("!HH", body[p:p + 4])
                p += 4
                pen = None
                if eid & 0x8000:
                    assert self.v == IPFIX
                    eid &= 0x7FFF
                    pen = struct.unpack("!I", body[p:p + 4])[0]
                    p += 4
                fs.append((eid, fl, pen))
            self.tmpl[tid] = fs
            n += 1
        assert p == len(body), "template set has trailing bytes"
        return n

    def _records(self, sid, body, sl):
        fs = self.tmpl[sid]
        minlen = sum(1 if fl == 0xFFFF else fl for _, fl, _ in fs)
        p, out = 0, []
        while p + minlen <= len(body):
            r = {}
            for eid, fl, pen in fs:
                if fl == 0xFFFF:
                    fl = body[p]
                    p += 1
                    if fl == 255:
                        fl = struct.unpack("!H", body[p:p + 2])[0]
                        p += 2
                r[(eid, pen)] = body[p:p + fl]
                p += fl
            out.append(r)
        rest = body[p:]
        assert not any(rest), ("padding must be zero", rest)
        if self.v == NF9:
            assert len(rest) < 4 and sl % 4 == 0, "flowset not padded to 4 bytes"
        else:
            assert not rest, "IPFIX sets are not padded here"
        return out


def _addr(b):
    return socket.inet_ntop(socket.AF_INET6 if len(b) == 16 else socket.AF_INET, b)


def back(sid, r, version, boot=0):
    """A decoded data record -> the record dict form (for equality with the input)."""
    def g(eid):
        return r[(eid, None)]
    v6 = (27, None) in r
    out = {"src": _addr(g(27 if v6 else 8)), "dst": _addr(g(28 if v6 else 12)), "sport": int.from_bytes(g(7), "big"),
           "dport": int.from_bytes(g(11), "big"), "proto": g(4)[0], "flags": int.from_bytes(g(6), "big"),
           "pkts": int.from_bytes(g(2), "big"), "octets": int.from_bytes(g(1), "big"),
           "in_if": int.from_bytes(g(10), "big"), "out_if": int.from_bytes(g(14), "big"),
           "vlan": int.from_bytes(g(58), "big") if (58, None) in r else None}
    if version == IPFIX:
        out.update(start_ms=int.from_bytes(g(152), "big"), end_ms=int.from_bytes(g(153), "big"),
                   tag=r[(1, E.TAG_PEN)].decode("utf-8"))
    else:
        out.update(start_ms=int.from_bytes(g(22), "big") + boot, end_ms=int.from_bytes(g(21), "big") + boot)
    return out


def rec(i=0, **kw):
    r = {"src": "10.0.0.%d" % (i % 250 + 1), "dst": "10.1.0.9", "sport": 1024 + i % 60000, "dport": 443, "proto": 6, "pkts": 5 + i,
         "octets": 700 + i, "start_ms": 1_700_000_000_000 + i * 7, "end_ms": 1_700_000_000_500 + i * 7, "flags": 0x1B,
         "in_if": 1, "out_if": 2, "vlan": None, "tag": "t%d" % (i % 9)}
    r.update(kw)
    return r


def run(recs, version=IPFIX, **kw):
    """Encode and decode everything; returns (messages, per-message info, decoded (set id, record) list)."""
    msgs = list(E.messages(recs, version, **kw))
    d = Decoder(version)
    infos, out = [], []
    for _t, m in msgs:
        info, rs = d.message(m)
        infos.append(info)
        out += rs
    return msgs, infos, out


# ---------------------------------------------------------------- encoder unit tests
class EncoderTests(unittest.TestCase):
    def test_ipfix_layout_and_round_trip(self):
        recs = [rec(i) for i in range(40)]
        msgs, infos, out = run(recs)
        self.assertEqual([back(s, r, IPFIX) for s, r in out], recs)
        self.assertEqual({i["domain"] for i in infos}, {1})
        self.assertEqual(infos[-1]["export_time"], recs[-1]["end_ms"] // 1000)
        for i in infos:
            self.assertEqual(i["len"], 16 + sum(sl for _, sl in i["sets"]))        # header + sets, no padding

    def test_ipfix_sequence_counts_data_records_not_templates(self):
        _, infos, _ = run([rec(i) for i in range(500)], mtu=600)
        self.assertGreater(len(infos), 10)
        sent = 0
        for i in infos:
            self.assertEqual(i["seq"], sent)
            sent += i["nrec"]
        self.assertEqual(sent, 500)

    def test_nf9_sequence_counts_packets_and_header_count_is_templates_plus_records(self):
        _, infos, _ = run([rec(i) for i in range(500)], NF9, mtu=600)
        self.assertEqual([i["seq"] for i in infos], list(range(len(infos))))      # Decoder also checks the count field

    def test_nf9_layout_padding_and_uptime_times(self):
        recs = [rec(i, tag=None) for i in range(33)]
        boot = recs[0]["start_ms"] - 60000
        msgs, infos, out = run(recs, NF9, boot_ms=boot)
        self.assertEqual([back(s, r, NF9, boot) for s, r in out], [{k: v for k, v in r.items() if k != "tag"} for r in recs])
        for (t, m), i in zip(msgs, infos):
            self.assertEqual(i["uptime"], int(t * 1000) - boot)
            self.assertEqual(i["export_time"], int(t))
            self.assertEqual(len(m) % 4, 0)

    def test_nf9_has_no_tag_and_one_byte_flags(self):
        d = Decoder(NF9)
        d.message(next(iter(E.messages([rec()], NF9)))[1])
        fs = d.tmpl[256]
        self.assertNotIn(E.TAG_PEN, [p for _, _, p in fs])
        self.assertEqual({e: ln for e, ln, _ in fs}[6], 1)

    def test_template_refresh_by_count(self):
        _, infos, _ = run([rec(i) for i in range(400)], mtu=300, refresh_msgs=5)
        self.assertEqual([k for k, i in enumerate(infos) if i["ntmpl"]], list(range(0, len(infos), 5)))

    def test_template_refresh_by_export_time(self):
        recs = [rec(i, start_ms=1_700_000_000_000 + i * 4000, end_ms=1_700_000_000_000 + i * 4000 + 100) for i in range(40)]
        _, infos, _ = run(recs, mtu=28 + 150, refresh_msgs=10 ** 6, refresh_s=30.0)   # two records per message
        starts = [k for k, i in enumerate(infos) if i["ntmpl"]]
        self.assertGreater(len(starts), 2)
        gaps = [infos[b]["export_time"] - infos[a]["export_time"] for a, b in zip(starts, starts[1:])]
        self.assertTrue(all(g >= 20 for g in gaps), gaps)                              # 30 s minus the span of one message
        self.assertTrue(all(infos[k]["ntmpl"] == 1 for k in starts))

    def test_every_message_fits_the_mtu(self):
        recs = [rec(i, tag="x" * (i % 300)) for i in range(2000)]
        for mtu in (1500, 800, 576):
            msgs, _, out = run(recs, mtu=mtu)
            self.assertTrue(all(len(m) <= mtu - 28 for _, m in msgs), mtu)
            self.assertEqual([back(s, r, IPFIX)["tag"] for s, r in out], [r["tag"] for r in recs])

    def test_bad_input_is_an_error(self):
        with self.assertRaises(ValueError):
            list(E.messages([rec(tag="y" * 400)], mtu=300))                            # one record cannot fit
        with self.assertRaises(ValueError):
            list(E.messages([rec()], version=7))

    def test_nothing_in_nothing_out(self):
        self.assertEqual(list(E.messages([])), [])
        self.assertEqual(list(E.messages([], NF9)), [])

    def test_extreme_values_and_empty_tag(self):
        big = rec(pkts=2 ** 64 - 1, octets=2 ** 64 - 1, sport=65535, dport=65535, flags=0xFFFF, in_if=2 ** 32 - 1,
                  out_if=2 ** 32 - 1, start_ms=0, end_ms=2 ** 63, tag="")                # also wraps the 32-bit export time
        zero = rec(pkts=0, octets=0, sport=0, dport=0, proto=0, flags=0, tag=None)
        _, _, out = run([zero, big])
        got = [back(s, r, IPFIX) for s, r in out]
        self.assertEqual(got[1], big)
        self.assertEqual(got[0], {**zero, "tag": ""})

    def test_tag_length_encoding_and_truncation(self):
        for n in (0, 254):
            b = E._tag_bytes("a" * n)
            self.assertEqual((b[0], len(b)), (n, n + 1))
        for n in (255, 300):
            b = E._tag_bytes("a" * n)
            self.assertEqual((b[:1], struct.unpack("!H", b[1:3])[0], len(b)), (b"\xff", n, n + 3))
        self.assertEqual(len(E._tag_bytes("é" * 400)) - 3, E.TAG_MAX)                  # cut at TAG_MAX bytes, on a character boundary
        self.assertEqual(len(E._tag_bytes("€" * 200)) - 3, 510)                        # 3-byte characters: 170 of them, never split
        E._tag_bytes("€" * 200)[3:].decode("utf-8")

    def test_ipv6_records(self):
        recs = [rec(i, src="2001:db8::%x" % (i + 1), dst="fe80::1") for i in range(30)]
        _, _, out = run(recs)
        self.assertEqual([back(s, r, IPFIX) for s, r in out], recs)
        self.assertEqual({s for s, _ in out}, {E.template_id(True, False)})
        d = Decoder(IPFIX)
        d.message(next(iter(E.messages(recs[:1])))[1])
        self.assertEqual([(e, ln) for e, ln, _ in d.tmpl[258][:2]], [(27, 16), (28, 16)])

    def test_vlan_field_only_when_set_and_mixed_families_share_a_message(self):
        recs = [rec(0, vlan=100), rec(1), rec(2, src="2001:db8::2", dst="2001:db8::3", vlan=4094), rec(3, src="2001:db8::4", dst="::1")]
        _, infos, out = run(recs)
        self.assertEqual({s: back(s, r, IPFIX)["vlan"] for s, r in out}, {257: 100, 256: None, 259: 4094, 258: None})
        self.assertEqual((len(infos), infos[0]["ntmpl"]), (1, 4))                      # each template announced when first needed

    def test_template_precedes_first_use_when_a_new_family_appears_later(self):
        recs = [rec(i) for i in range(60)] + [rec(99, src="2001:db8::9", dst="2001:db8::a")]
        _, infos, out = run(recs, mtu=300)
        self.assertEqual(len(out), 61)                                                 # the Decoder asserts the template came first
        self.assertEqual(infos[-1]["ntmpl"], 1)

    def test_oversize_flag_and_time_values_wrap_instead_of_failing(self):
        _, _, out = run([rec(flags=0x1FF, start_ms=5, end_ms=2 ** 32 + 9)], NF9, boot_ms=0)
        self.assertEqual((back(*out[0], NF9)["flags"], back(*out[0], NF9)["end_ms"]), (0xFF, 9))


class FrameTests(unittest.TestCase):
    def test_checksums_lengths_and_addresses(self):
        for n in (0, 1, 1001, 1444):
            fr = XI.frame(b"\xab" * n, 4739, 7)
            ip, dgram = fr[14:34], fr[34:]
            self.assertEqual(XI._csum(ip), 0)                                          # a valid IPv4 header sums to zero
            self.assertEqual(XI._csum(ip[12:20] + struct.pack("!BBH", 0, 17, len(dgram)) + dgram), 0)
            self.assertEqual((struct.unpack("!H", ip[2:4])[0], struct.unpack("!H", dgram[4:6])[0]), (28 + n, 8 + n))
            self.assertEqual((socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])), (XI.EXPORTER, XI.COLLECTOR))
            self.assertEqual(struct.unpack("!H", dgram[2:4])[0], 4739)


# ---------------------------------------------------------------- records from the flow table
def flow(**kw):
    f = {"proto": "tcp", "src": "10.0.0.1", "sport": 1000, "dst": "10.0.0.2", "dport": 80, "start": 10.0004, "end": 11.5,
         "orig_pkts": 3, "resp_pkts": 2, "orig_ip_bytes": 120, "resp_ip_bytes": 80, "flags_orig": 2, "flags_resp": 18,
         "tag": "incident:x", "tags": ["incident:x"], "first_pkt": 1, "last_pkt": 5}
    f.update(kw)
    return f


class RecordTests(unittest.TestCase):
    def test_one_record_per_direction_with_packets_and_swapped_endpoints(self):
        a, b = XI.records([flow()])
        self.assertEqual((a["direction"], a["src"], a["sport"], a["pkts"], a["octets"], a["flags"], a["in_if"], a["out_if"]),
                         ("orig", "10.0.0.1", 1000, 3, 120, 2, 1, 2))
        self.assertEqual((b["direction"], b["src"], b["dst"], b["sport"], b["dport"], b["pkts"], b["octets"], b["flags"], b["in_if"]),
                         ("resp", "10.0.0.2", "10.0.0.1", 80, 1000, 2, 80, 18, 2))
        self.assertEqual((a["start_ms"], a["end_ms"]), (10000, 11500))
        self.assertEqual(len(XI.records([flow(resp_pkts=0, resp_ip_bytes=0)])), 1)

    def test_icmp_type_code_goes_into_the_destination_port(self):
        a, b = XI.records([flow(proto="icmp", sport=8, dport=0, flags_orig=0, flags_resp=0)])
        self.assertEqual((a["proto"], a["sport"], a["dport"], b["sport"], b["dport"]), (1, 0, 2048, 0, 0))

    def test_sorted_by_end_then_start_and_vlan_passes_through(self):
        r = XI.records([flow(end=20.0, first_pkt=1), flow(end=12.0, first_pkt=2, vlan=30), flow(end=12.0, start=9.0, first_pkt=3)])
        self.assertEqual([x["end_ms"] for x in r], [12000] * 4 + [20000] * 2)
        self.assertEqual([x["start_ms"] for x in r][:2], [9000, 9000])
        self.assertEqual({x["vlan"] for x in r}, {None, 30})


# ---------------------------------------------------------------- exporter over a small synthetic pcap
class ExporterTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="og-ipfix-")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.out = os.path.join(self.d, "e.pcap")
        t = 1_700_000_000.0
        pcap(self.out, [(t, tcp("10.0.0.1", 40000, "10.0.0.2", 80, SYN)), (t + .1, tcp("10.0.0.2", 80, "10.0.0.1", 40000, 0x12)),
                        (t + .2, udp("10.0.0.3", 5000, "10.0.0.4", 53, b"q")), (t + .3, udp("10.0.0.3", 5000, "10.0.0.4", 53, b"q")),
                        (t + 1, b"\xff" * 6 + b"\2" * 6 + b"\x08\x06" + b"\0" * 28)])
        self.tags = os.path.join(self.d, "e.tags")
        BM.write_tags(self.tags, {"baseline:web": [0], "incident:scan": [1]}, bytearray([0, 0, 1, 1, 0]))

    def ctx(self, exports, tags=True, n=5):
        return OGB._ExportCtx(out=self.out, writer=types.SimpleNamespace(n=n), exports=set(exports),
                              tags_path=self.tags if tags else None)

    def test_not_requested_means_nothing(self):
        self.assertEqual(XI.export(self.ctx({"truth", "ssl"})), {})
        self.assertEqual(sorted(os.listdir(self.d)), ["e.pcap", "e.tags"])

    def test_blocks_files_and_consistency(self):
        res = XI.export(self.ctx({"ipfix", "netflow9"}))
        self.assertEqual(sorted(res), ["ipfix", "netflow9"])
        b = res["ipfix"]
        self.assertEqual(b["files"], ["e-ipfix.pcap", "e-ipfix.csv"])
        self.assertEqual(res["netflow9"]["files"], ["e-netflow9.pcap", "e-netflow9.csv"])
        self.assertEqual((b["records"], b["flow_packets"], b["unflowed_frames"], b["exports_consistent"]), (3, 4, 1, True))
        self.assertIn("scenario-tag element (PEN 32473)", b["synthetic"])
        self.assertNotIn("scenario-tag element (PEN 32473)", res["netflow9"]["synthetic"])
        self.assertNotIn("10.0.0", json.dumps(res), "no scenario addresses in the manifest blocks")
        self.assertNotIn(XI.EXPORTER, json.dumps(res))
        self.assertFalse(XI.export(self.ctx({"ipfix"}, n=6))["ipfix"]["exports_consistent"])

    def test_pcap_decodes_and_matches_csv_and_flow_table(self):
        XI.export(self.ctx({"ipfix"}))
        d = Decoder(IPFIX)
        got, prev = [], 0
        for ts, fr in pcapprofile.iter_frames(os.path.join(self.d, "e-ipfix.pcap")):
            self.assertGreaterEqual(ts, prev)
            prev = ts
            self.assertEqual(XI._csum(fr[14:34]), 0)
            _, rs = d.message(fr[42:])
            got += [back(s, r, IPFIX) for s, r in rs]
        want = XI.records(FT.flows(self.out, self.tags))
        self.assertEqual(got, [{k: v for k, v in r.items() if k != "direction"} for r in want])
        with open(os.path.join(self.d, "e-ipfix.csv"), newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual([(r["direction"], r["src"], int(r["packets"]), int(r["octets"]), r["scenario_tag"]) for r in rows],
                         [(w["direction"], w["src"], w["pkts"], w["octets"], w["tag"]) for w in want])
        self.assertEqual(list(rows[0]), XI.CSV_COLUMNS)

    def test_message_time_is_flow_end_time(self):
        XI.export(self.ctx({"ipfix"}))
        ts = [t for t, _ in pcapprofile.iter_frames(os.path.join(self.d, "e-ipfix.pcap"))]
        self.assertEqual(len(ts), 1)
        self.assertAlmostEqual(ts[0], 1_700_000_000.3, places=3)                       # the latest flow end in the message

    def test_deterministic_same_pcap_same_files(self):
        def digest():
            res = XI.export(self.ctx({"ipfix", "netflow9"}))
            out = {}
            for b in res.values():
                for f in b["files"]:
                    with open(os.path.join(self.d, f), "rb") as fh:
                        out[f] = hashlib.sha256(fh.read()).hexdigest()
            return out
        self.assertEqual(digest(), digest())

    def test_sidecar_overflow_reports_error_and_leaves_no_files(self):
        res = XI.export(self.ctx({"ipfix", "netflow9"}, tags=False))
        for k in ("ipfix", "netflow9"):
            self.assertIn("tag sidecar is missing", res[k]["error"])
            self.assertNotIn("files", res[k])
        self.assertEqual(sorted(os.listdir(self.d)), ["e.pcap", "e.tags"])

    def test_a_missing_pcap_is_recorded_not_raised(self):
        e = self.ctx({"ipfix"})
        e.out = os.path.join(self.d, "gone.pcap")
        self.assertIn("Error", XI.export(e)["ipfix"]["error"])
        self.assertEqual(sorted(os.listdir(self.d)), ["e.pcap", "e.tags"])

    def test_empty_capture_gives_a_valid_empty_export(self):
        pcap(self.out, [])
        BM.write_tags(self.tags, {}, bytearray())
        res = XI.export(self.ctx({"ipfix"}, n=0))
        self.assertEqual((res["ipfix"]["records"], res["ipfix"]["messages"]), (0, 0))
        self.assertEqual(os.path.getsize(os.path.join(self.d, "e-ipfix.pcap")), 24)


# ---------------------------------------------------------------- scale-0.004 builds
def _build(d, stem, **kw):
    return OGB.build(scale=0.004, out=os.path.join(d, stem + ".pcap"), keylog=os.path.join(d, stem + ".keys"),
                     inventory=os.path.join(DEV, "inventory.json"), certs_dir=None, iocs_prefix=None,
                     modules=[], progress=False, **kw)


def tshark_records(path, port, fields):
    """One tuple per exported record (tshark lists each field's values per packet, comma separated)."""
    args = [TSHARK, "-r", path, "-d", "udp.port==%d,cflow" % port, "-T", "fields", "-E", "separator=;"]
    for f in fields:
        args += ["-e", f]
    p = subprocess.run(args, capture_output=True, text=True, check=True, env={**os.environ, "TZ": "UTC"})
    out = []
    for line in p.stdout.splitlines():
        out += list(zip(*[c.split(",") for c in line.split(";")]))
    return out


def tshark_malformed(path, port):
    p = subprocess.run([TSHARK, "-r", path, "-d", "udp.port==%d,cflow" % port, "-Y", "_ws.malformed || _ws.expert.severity>=0x600000"],
                       capture_output=True, text=True, check=True)
    return p.stdout.strip()


class BuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="og-e4-")
        cls.on = _build(cls.d, "on", exports=["ipfix", "netflow9"])
        cls.off = _build(cls.d, "off")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def manifest(self, stem):
        with open(os.path.join(self.d, stem + ".manifest.json")) as f:
            return json.load(f)

    def csv_rows(self, name):
        with open(os.path.join(self.d, name), newline="") as f:
            return list(csv.DictReader(f))

    def flows(self):
        return list(FT.flows(os.path.join(self.d, "on.pcap"), os.path.join(self.d, "on.tags")))

    def test_pin_unchanged_and_option_on_is_equivalent(self):
        self.assertEqual(self.off["packets"], 466343)                                   # the baseline pin (selftest.PIN)
        self.assertEqual((self.on["packets"], self.on["protocols"]), (self.off["packets"], self.off["protocols"]))
        self.assertNotIn("exports", self.off)
        self.assertEqual(sorted(f for f in os.listdir(self.d) if f.startswith("off")),
                         ["off-generation-report.csv", "off.keys", "off.manifest.json", "off.pcap"])

    def test_manifest_lists_every_new_file_with_bytes_and_sha(self):
        m = self.manifest("on")
        outs = {o["name"]: o for o in m["outputs"]}
        for name in ("on-ipfix.pcap", "on-ipfix.csv", "on-netflow9.pcap", "on-netflow9.csv", "on.tags"):
            p = os.path.join(self.d, name)
            self.assertEqual((outs[name]["bytes"], outs[name]["sha256"]), (os.path.getsize(p), BM.sha256_file(p)), name)
        self.assertEqual(sorted(m["exports"]), ["ipfix", "netflow9"])
        self.assertEqual(m["parameters"]["exports"], ["ipfix", "netflow9"])
        self.assertTrue(all(b["exports_consistent"] and b["packets"] == 466343 for b in m["exports"].values()))
        self.assertNotEqual(m["parameters"], self.manifest("off")["parameters"])        # else a rebuild would delete the earlier copy

    def test_csv_equals_the_flow_table(self):
        flows = self.flows()
        want = XI.records(flows)
        for name in ("on-ipfix.csv", "on-netflow9.csv"):
            rows = self.csv_rows(name)
            self.assertEqual(len(rows), len(want))
            for r, w in zip(rows, want):
                self.assertEqual((r["direction"], r["src"], r["dst"], int(r["sport"]), int(r["dport"]), int(r["proto"]), int(r["packets"]),
                                  int(r["octets"]), int(r["start_ms"]), int(r["end_ms"]), int(r["tcp_flags"]), r["scenario_tag"]),
                                 (w["direction"], w["src"], w["dst"], w["sport"], w["dport"], w["proto"], w["pkts"], w["octets"],
                                  w["start_ms"], w["end_ms"], w["flags"], w["tag"]))
        self.assertEqual(sum(1 for r in want if r["direction"] == "orig"), len(flows))
        self.assertEqual(sum(f["orig_pkts"] + f["resp_pkts"] for f in flows), sum(w["pkts"] for w in want))
        self.assertEqual(sum(f["orig_ip_bytes"] + f["resp_ip_bytes"] for f in flows), sum(w["octets"] for w in want))

    def test_own_decoder_reads_both_pcaps_and_matches_csv(self):
        for name, ver, port in (("ipfix", IPFIX, 4739), ("netflow9", NF9, 2055)):
            d = Decoder(ver)
            n = 0
            for _ts, fr in pcapprofile.iter_frames(os.path.join(self.d, "on-%s.pcap" % name)):
                self.assertLessEqual(len(fr), 1500 + 14)
                self.assertEqual(struct.unpack("!H", fr[36:38])[0], port)
                self.assertEqual(XI._csum(fr[14:34]), 0)
                n += len(d.message(fr[42:])[1])
            self.assertEqual(n, len(self.csv_rows("on-%s.csv" % name)), name)

    @unittest.skipUnless(os.path.exists(TSHARK), "tshark not installed")
    def test_tshark_cflow_ipfix_no_malformed_counts_and_values_match(self):
        pcap_ = os.path.join(self.d, "on-ipfix.pcap")
        self.assertEqual(tshark_malformed(pcap_, 4739), "")
        got = tshark_records(pcap_, 4739, ["cflow.srcaddr", "cflow.dstaddr", "cflow.srcport", "cflow.dstport", "cflow.protocol",
                                            "cflow.packets", "cflow.octets", "cflow.inputint", "cflow.outputint"])
        rows = self.csv_rows("on-ipfix.csv")
        self.assertEqual(len(got), len(rows))                                           # every record decodes
        self.assertEqual(len(got), self.manifest("on")["exports"]["ipfix"]["records"])
        for g, r in zip(got, rows):
            self.assertEqual(g, (r["src"], r["dst"], r["sport"], r["dport"], r["proto"], r["packets"], r["octets"],
                                 r["ingress_if_synthetic"], r["egress_if_synthetic"]))
        self.assertEqual(sum(1 for r in rows if r["direction"] == "orig"), len(self.flows()))   # one originator record per flow

    @unittest.skipUnless(os.path.exists(TSHARK), "tshark not installed")
    def test_tshark_ipfix_times_and_flags_and_netflow9(self):
        rows = self.csv_rows("on-ipfix.csv")
        got = tshark_records(os.path.join(self.d, "on-ipfix.pcap"), 4739, ["cflow.abstimestart", "cflow.abstimeend", "cflow.tcpflags"])
        self.assertEqual(len(got), len(rows))
        for g, r in list(zip(got, rows))[::97]:                                         # a sample across the whole file
            for col, key in ((0, "start_ms"), (1, "end_ms")):
                t = datetime.datetime.fromisoformat(g[col][:26] + "+00:00")
                self.assertEqual(int(round(t.timestamp() * 1000)), int(r[key]))
            self.assertEqual(int(g[2], 16), int(r["tcp_flags"]))
        v9pcap = os.path.join(self.d, "on-netflow9.pcap")
        self.assertEqual(tshark_malformed(v9pcap, 2055), "")
        v9 = tshark_records(v9pcap, 2055, ["cflow.srcaddr", "cflow.dstaddr", "cflow.srcport", "cflow.dstport", "cflow.packets", "cflow.octets"])
        self.assertEqual(v9, [(r["src"], r["dst"], r["sport"], r["dport"], r["packets"], r["octets"]) for r in self.csv_rows("on-netflow9.csv")])

    def test_hold_previous_moves_the_export_files_with_their_pcap(self):
        d = tempfile.mkdtemp(prefix="og-e4-hold-")
        self.addCleanup(shutil.rmtree, d, True)
        _build(d, "h", exports=["ipfix"])
        self.assertTrue(os.path.isfile(os.path.join(d, "h-ipfix.pcap")))
        _build(d, "h")                                                                  # different settings: the first build is kept
        for f in ("h-ipfix.pcap", "h-ipfix.csv"):
            self.assertFalse(os.path.exists(os.path.join(d, f)))
        kept = [os.path.join(r, f) for r, _, fs in os.walk(os.path.join(d, "earlier-builds")) for f in fs]
        for want in ("h-ipfix.pcap", "h-ipfix.csv"):
            self.assertTrue(any(k.endswith(want) for k in kept), (want, kept))

    def test_unknown_export_is_refused(self):
        with self.assertRaises(ValueError):
            _build(self.d, "bad", exports=["netflow5"])


if __name__ == "__main__":
    unittest.main()
