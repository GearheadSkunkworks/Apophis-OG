"""Opt-in per-packet scenario-tag sidecar (Engine.record_tags) and the manifest spans/ranges it feeds."""
import json
import os
import shutil
import sys
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "tools"))
import opengenerator_build as OGB  # noqa: E402 - sys.path is set up before the import
import build_manifest as BM        # noqa: E402 - sys.path is set up before the import
import verify_manifest as VM       # noqa: E402 - sys.path is set up before the import
from netgen.core import Engine, PcapWriter  # noqa: E402 - sys.path is set up before the import

NAMES = ["ndr-rdp-brute", "npm-sql1-service-failure"]


def _build(d, stem, **kw):
    return OGB.build(scale=0.004, out=os.path.join(d, stem + ".pcap"), keylog=os.path.join(d, stem + ".keys"),
                     inventory=os.path.join(DEV, "inventory.json"), certs_dir=None, iocs_prefix=None,
                     modules=NAMES, progress=False, **kw)


class Build(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="og-tags-")
        cls.on = _build(cls.d, "on", tag_sidecar=True)
        cls.off = _build(cls.d, "off")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_length_and_table(self):
        table, body = BM.read_tags(os.path.join(self.d, self.on["tags"]))
        self.assertEqual(len(body), self.on["packets"])
        self.assertTrue(set(body) <= set(range(len(table))))
        self.assertEqual(sum(1 for _ in body), self.on["packets"])

    def test_option_off(self):
        self.assertFalse(os.path.exists(os.path.join(self.d, "off.tags")))
        self.assertNotIn("tags", self.off)
        m = json.load(open(os.path.join(self.d, self.off["manifest"])))
        self.assertNotIn("tag_sidecar", m["parameters"])
        for s in m["scenarios"]:
            self.assertNotIn("active_spans", s)
            self.assertNotIn("packet_range", s)
        self.assertEqual(self.on["packets"], self.off["packets"])

    def test_manifest_spans_consistent(self):
        mp = os.path.join(self.d, self.on["manifest"])
        m = json.load(open(mp))
        self.assertEqual(VM.verify(mp), [])
        self.assertIn("on.tags", [o["name"] for o in m["outputs"]])
        nd = m["normal_day"]
        self.assertEqual(sum(x[2] for x in nd["active_spans"]), nd["packets"])
        for s in m["scenarios"]:
            ob = s["observed"]
            self.assertEqual(sum(x[2] for x in s["active_spans"]), ob["packets"], s["id"])
            self.assertEqual(s["active_spans"][0][0], ob["first_ts"])
            self.assertEqual(s["active_spans"][-1][1], ob["last_ts"])
            lo, hi = s["packet_range"]
            self.assertTrue(1 <= lo <= hi <= self.on["packets"])
        table, body = BM.read_tags(os.path.join(self.d, self.on["tags"]))
        for s in m["scenarios"]:           # first/last frame carrying the scenario's tag match the range
            ids = {i for i, t in enumerate(table) if t == "incident:" + s["id"]}
            at = [k + 1 for k, b in enumerate(body) if b in ids]
            self.assertEqual([at[0], at[-1]], s["packet_range"])

    def test_overflow_in_a_build_is_reported_and_capture_kept(self):
        def stop(self, tag, ts):                      # what the engine does on the 257th tag
            self.tag_log, self.tag_overflow = None, True
        d = tempfile.mkdtemp(prefix="og-tags-ovf-")
        orig = Engine._tag
        Engine._tag = stop
        try:
            s = _build(d, "o", exports=["truth"])
        finally:
            Engine._tag = orig
        try:
            self.assertTrue(os.path.getsize(os.path.join(d, "o.pcap")) > 24)
            self.assertIn("256", s["tags_error"])
            self.assertFalse(os.path.exists(os.path.join(d, "o.tags")))
            m = json.load(open(os.path.join(d, s["manifest"])))
            self.assertIn("256", m["exports"]["truth"]["error"])
            self.assertNotIn("active_spans", m["scenarios"][0])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_hold_previous_keeps_when_only_option_differs(self):
        d = tempfile.mkdtemp(prefix="og-tags-hold-")
        try:
            _build(d, "h")
            _build(d, "h", tag_sidecar=True)
            kept = [r for r, _, fs in os.walk(os.path.join(d, "earlier-builds")) for f in fs if f.endswith(".pcap")]
            self.assertEqual(len(kept), 1)
            _build(d, "h", tag_sidecar=True)                    # identical again: sidecar moves with its pcap
            tags = [f for _, _, fs in os.walk(d) for f in fs if f.endswith(".tags")]
            self.assertEqual(len(tags), 1)
            _build(d, "h")                                      # back to off: the on-build and its tags are kept
            self.assertTrue(any(f.endswith(".tags") for _, _, fs in os.walk(os.path.join(d, "earlier-builds")) for f in fs))
        finally:
            shutil.rmtree(d, ignore_errors=True)


class Engine_(unittest.TestCase):
    def _run(self, side_copy):
        d = tempfile.mkdtemp(prefix="og-tags-eng-")
        try:
            w, side = PcapWriter(os.path.join(d, "m.pcap")), PcapWriter(os.path.join(d, "s.pcap"))
            e = Engine(w, side_writer=side, side_tag_prefix="incident:", side_copy=side_copy)
            e.record_tags(gap=10)
            flow = lambda t0, k: (lambda: iter([(t0 + i, b"\x00" * 60) for i in range(k)]))  # noqa: E731 - short single-use test helper
            e.schedule(0, flow(0, 3), "misc")
            e.schedule(1, flow(1, 3), "incident:x")
            e.schedule(100, flow(100, 2), "misc")                # a gap above 10 s: second span
            e.run()
            w.close()
            side.close()
            return e, w
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_side_copy_true_tags_every_main_frame(self):
        e, w = self._run(True)
        self.assertEqual(len(e.tag_log), w.n)
        self.assertEqual(e.tag_rec["misc"][3], [[0, 2, 3], [100, 101, 2]])

    def test_side_only_frames_not_tagged(self):
        e, w = self._run(False)
        self.assertEqual(len(e.tag_log), w.n)
        self.assertNotIn("incident:x", e.tag_rec)
        self.assertEqual(w.n, 5)

    def test_overflow_stops_recording_not_the_run(self):
        w = PcapWriter(os.devnull)
        e = Engine(w)
        e.record_tags()
        for i in range(300):
            e.schedule(i, (lambda i=i: iter([(i, b"\x00" * 60)])), "t%d" % i)
        e.run()
        self.assertIsNone(e.tag_log)
        self.assertTrue(e.tag_overflow)
        self.assertEqual(w.n, 300)

    def test_default_off(self):
        e = Engine(PcapWriter(os.devnull))
        self.assertIsNone(e.tag_log)


if __name__ == "__main__":
    unittest.main()
