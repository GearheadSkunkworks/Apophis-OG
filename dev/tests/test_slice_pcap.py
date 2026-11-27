"""tools/slice_pcap.py: kinds A/B/C over a synthetic build and over one real scale-0.004 build."""
import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "tools"))
import build_manifest as BM        # noqa: E402 - sys.path is extended above; tools/ is not a package
import slice_pcap as SP            # noqa: E402 - sys.path is extended above; tools/ is not a package

BASE, T1, T2 = "normal-day", "incident:t1", "incident:other"
# baseline every 100 s from 1000..2000; t1 in two spans (1300-1310, 1800-1805); another scenario inside both
PKTS = ([(1000 + 100 * i + 0.5, BASE) for i in range(11)]
        + [(1300 + i, T1) for i in range(11)] + [(1800 + i, T1) for i in range(6)]
        + [(1305.25, T2), (1802.75, T2)])
PKTS.sort(key=lambda p: p[0])


def write_pcap(path, pkts):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for i, (ts, _t) in enumerate(pkts):
            fr = bytes([i % 251]) * (60 + i % 7)
            f.write(struct.pack("<IIII", int(ts), round((ts - int(ts)) * 1e6), len(fr), len(fr)) + fr)


def records(path):
    with open(path, "rb") as f:
        f.read(24)
        out = []
        while True:
            h = f.read(16)
            if not h:
                return out
            out.append(h + f.read(struct.unpack("<IIII", h)[2]))


def seal_to(d, m):
    with open(os.path.join(d, "b.manifest.json"), "w") as f:
        json.dump(BM.seal(m), f)


def make_build(d, spans=True, tags=True, total=None):
    pcap = os.path.join(d, "b.pcap")
    write_pcap(pcap, PKTS)
    t1 = [p[0] for p in PKTS if p[1] == T1]
    sc = {"id": "t1", "observed": {"packets": len(t1), "first_ts": t1[0], "last_ts": t1[-1]}}
    if spans:
        sc["active_spans"] = [[1300, 1310, 11], [1800, 1805, 6]]
    with open(pcap, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    m = {"schema_version": 1, "outputs": [{"name": "b.pcap", "bytes": os.path.getsize(pcap), "sha256": sha}],
         "totals": {"packets": len(PKTS) if total is None else total}, "scenarios": [sc]}
    seal_to(d, m)
    if tags:
        table = [BASE, T1, T2]
        BM.write_tags(os.path.join(d, "b.tags"), {t: (i, 0, 0, []) for i, t in enumerate(table)},
                      bytes(table.index(p[1]) for p in PKTS))
    return pcap, BM.seal(m)


class Synthetic(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="og-slice-")
        self.pcap, self.m = make_build(self.d)
        self.src = records(self.pcap)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def cut(self, kind, **kw):
        r = SP.slice_pcap(self.pcap, kind, "t1", **kw)
        out = records(r["pcap_out"])
        return r, [self.src.index(x) for x in out], out        # (sidecar, original indexes, record bytes)

    def test_a_window_all_tags_verbatim(self):
        r, idx, out = self.cut("A", ctx=0)                     # 1300..1805 (+1 s pad), other scenario included
        self.assertEqual(idx, [i for i, (ts, _t) in enumerate(PKTS) if 1299 <= ts <= 1806])
        self.assertTrue(all(a == self.src[i] for a, i in zip(out, idx)))
        self.assertEqual(r["kept_packets"], len(idx))
        self.assertEqual(r["manifest_sha256"], self.m["manifest_sha256"])
        self.assertEqual(r["source_pcap_sha256"], self.m["outputs"][0]["sha256"])
        self.assertTrue(r["json_out"].endswith("b.slice.t1.A.json") and os.path.isfile(r["json_out"]))

    def test_ctx_padding(self):
        _r, idx, _o = self.cut("A", ctx=0)
        self.assertNotIn(PKTS.index((1000.5, BASE)), idx)
        _r, idx, _o = self.cut("A", ctx=300)                   # 999..2106 swallows the 1000.5 baseline packet
        self.assertIn(PKTS.index((1000.5, BASE)), idx)

    def test_b_target_plus_window_baseline(self):
        r, idx, _ = self.cut("B", ctx=50)
        self.assertEqual({PKTS[i][1] for i in idx}, {BASE, T1})          # other scenario never leaks
        self.assertEqual(sum(PKTS[i][1] == T1 for i in idx), 17)
        for i in idx:
            if PKTS[i][1] == BASE:
                self.assertTrue(1249 <= PKTS[i][0] <= 1361 or 1749 <= PKTS[i][0] <= 1856, PKTS[i][0])
        self.assertEqual(len(r["kept_spans"]), 2)
        self.assertEqual(r["kept_outside_spans"], 0)

    def test_b_full_and_none(self):
        full, idx, _ = self.cut("B", baseline="full", ctx=0)
        self.assertEqual(sum(PKTS[i][1] == BASE for i in idx), 11)
        self.assertGreater(full["kept_outside_spans"], 0)
        self.assertEqual({PKTS[i][1] for i in self.cut("B", baseline="none")[1]}, {T1})

    def test_c_scenario_only_and_packet_numbers(self):
        r, idx, _ = self.cut("C", ctx=0)
        self.assertEqual([PKTS[i][1] for i in idx], [T1] * 17)
        self.assertEqual(r["baseline"], "none")
        a, b = r["kept_spans"]
        self.assertEqual((a["kept_packets"], b["kept_packets"]), (11, 6))
        self.assertEqual((a["first_packet_no"], b["last_packet_no"]), (idx[0] + 1, idx[-1] + 1))   # 1-based

    def test_multispan_merges_under_large_ctx(self):
        r, _i, _o = self.cut("C", ctx=600)
        self.assertEqual(len(r["kept_spans"]), 1)
        self.assertEqual(r["kept_packets"], 17)

    def test_sources_untouched(self):
        names = ("b.pcap", "b.manifest.json", "b.tags")

        def snap():
            out = []
            for n in names:
                with open(os.path.join(self.d, n), "rb") as f:
                    out.append(f.read())
            return out
        before = snap()
        self.cut("B")
        self.assertEqual(before, snap())

    def test_big_endian_nanosecond_pcap(self):
        be = os.path.join(self.d, "be.pcap")
        with open(be, "wb") as f:
            f.write(struct.pack(">IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
            f.write(struct.pack(">IIII", 1305, 250_000_000, 4, 4) + b"abcd")
        with open(os.path.join(self.d, "b.manifest.json")) as f:
            m = json.load(f)
        m["outputs"] = [{"name": "be.pcap", "bytes": os.path.getsize(be), "sha256": "0" * 64}]
        m["totals"]["packets"] = 1
        with open(os.path.join(self.d, "be.manifest.json"), "w") as f:
            json.dump(BM.seal(m), f)
        r = SP.slice_pcap(be, "A", "t1", ctx=0)
        self.assertEqual((r["kept_packets"], r["first_ts"]), (1, 1305.25))


class Errors(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="og-slice-")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def fails(self, msg, pcap, kind, scn="t1"):
        with self.assertRaises(SP.SliceError) as c:
            SP.slice_pcap(pcap, kind, scn)
        self.assertIn(msg, str(c.exception))
        self.assertEqual([n for n in os.listdir(self.d) if ".slice." in n], [])      # nothing left behind

    def test_missing_scenario(self):
        self.fails("not in the manifest", make_build(self.d)[0], "A", "nope")

    def test_no_active_spans_asks_for_rebuild(self):
        pcap, _ = make_build(self.d, spans=False)
        self.fails("rebuild with the tag sidecar", pcap, "B")
        SP.slice_pcap(pcap, "A", "t1")                                             # A needs neither

    def test_manifest_count_mismatch(self):
        self.fails("manifest says", make_build(self.d, total=len(PKTS) + 1)[0], "A")

    def test_sidecar_count_mismatch(self):
        pcap, _ = make_build(self.d)
        BM.write_tags(os.path.join(self.d, "b.tags"), {BASE: (0, 0, 0, []), T1: (1, 0, 0, []), T2: (2, 0, 0, [])},
                      bytes(len(PKTS) - 1))
        self.fails("tag sidecar has", pcap, "B")

    def test_missing_sidecar(self):
        self.fails("tag sidecar not found", make_build(self.d, tags=False)[0], "C")

    def test_edited_manifest_rejected(self):
        pcap, m = make_build(self.d)
        m["generator"] = "tampered"
        with open(os.path.join(self.d, "b.manifest.json"), "w") as f:
            json.dump(m, f)
        self.fails("manifest_sha256", pcap, "A")

    def test_wrong_pcap_size(self):
        pcap, _ = make_build(self.d)
        with open(pcap, "ab") as f:
            f.write(b"x")
        self.fails("differs from the manifest", pcap, "A")

    def test_hostile_scenario_id_names_nothing(self):
        pcap, m = make_build(self.d)
        for bad in ("../evil", "a/b", ".hidden", "", "x" * 65, "t1\n"):
            m["scenarios"][0]["id"] = bad
            seal_to(self.d, m)
            out = os.path.join(self.d, "out")
            os.makedirs(out, exist_ok=True)
            with self.assertRaises(SP.SliceError) as c:
                SP.slice_pcap(pcap, "A", bad, out_dir=out)
            self.assertIn("not a plain name", str(c.exception))
            self.assertEqual(os.listdir(out), [])
        self.assertEqual([n for n in os.listdir(self.d) if "evil" in n or ".slice." in n], [])

    def test_planted_tmp_symlink_is_not_followed(self):
        pcap, _ = make_build(self.d)
        victim = os.path.join(self.d, "victim.txt")
        with open(victim, "w") as f:
            f.write("keep")
        for guess in ("b.slice.t1.A.pcap.tmp", "b.slice.t1.A.json.tmp"):
            os.symlink(victim, os.path.join(self.d, guess))
        SP.slice_pcap(pcap, "A", "t1")
        with open(victim) as f:
            self.assertEqual(f.read(), "keep")
        self.assertTrue(os.path.isfile(os.path.join(self.d, "b.slice.t1.A.pcap")))

    def test_pcapng_rejected(self):
        pcap, m = make_build(self.d)
        with open(pcap, "wb") as f:
            f.write(b"\x0a\x0d\x0d\x0a" + b"\0" * 40)
        m = {k: v for k, v in m.items() if k != "manifest_sha256"}
        m["outputs"][0]["bytes"] = 44
        seal_to(self.d, m)
        self.fails("not a classic pcap", pcap, "A")

    def test_cli_returns_1_on_error(self):
        pcap, _ = make_build(self.d)
        self.assertEqual(SP.main([pcap, "--scenario", "nope", "--kind", "A"]), 1)
        self.assertEqual(SP.main([pcap, "--scenario", "t1", "--kind", "c", "--out-dir", self.d]), 0)


class RealBuild(unittest.TestCase):
    def test_scale_0004_with_sidecar(self):
        import opengenerator_build as OGB
        d = tempfile.mkdtemp(prefix="og-slice-real-")
        try:
            out = os.path.join(d, "r.pcap")
            OGB.build(scale=0.004, out=out, keylog=os.path.join(d, "r.keys"), inventory=os.path.join(DEV, "inventory.json"),
                      certs_dir=None, iocs_prefix=None, modules=["ndr-rdp-brute", "npm-sql1-service-failure"],
                      progress=False, tag_sidecar=True)
            table, body = BM.read_tags(os.path.join(d, "r.tags"))
            src = records(out)
            self.assertEqual(len(src), len(body))
            n = "ndr-rdp-brute"
            tgt = "incident:" + n
            tags = [table[b] for b in body]
            target = {s for s, t in zip(src, tags) if t == tgt}
            self.assertTrue(target)
            for kind in ("B", "C"):
                r = SP.slice_pcap(out, kind, n, ctx=60)
                kept = records(r["pcap_out"])
                self.assertEqual(len(kept), r["kept_packets"])
                ok = {s for s, t in zip(src, tags) if t == tgt or (kind == "B" and not t.startswith("incident:"))}
                self.assertTrue(set(kept) <= ok, kind)                        # only target (+ baseline for B) tags
                self.assertTrue(target <= set(kept), kind)                    # every target packet kept
            a = records(SP.slice_pcap(out, "A", n, ctx=60)["pcap_out"])
            self.assertTrue(target <= set(a))                                 # A keeps a superset of B's target packets
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
