"""A build never overwrites a different earlier build: it is moved to earlier-builds/ first; same settings replace."""
import json
import os
import shutil
import sys
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import captures_store as cs  # noqa: E402
import opengenerator_build as OGB  # noqa: E402
from netgen.core import Cancelled  # noqa: E402

INV = os.path.join(DEV, "inventory.json")
REG = list(OGB.INC.REGISTRY)


def rd(p):
    with open(p, "rb") as fh:
        return fh.read()


def touch(d, rel, body=b"x"):
    p = os.path.join(d, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as fh:
        fh.write(body)
    return p


class Real(unittest.TestCase):
    """Real small builds (scale 0.004, one scenario)."""

    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp(prefix="og-keep-"))
        self.out = os.path.join(self.d, "x-all-in-one.pcap")
        self.certs = os.path.join(self.d, "certs")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def build(self, mods, **kw):
        return OGB.build(scale=0.004, out=self.out, inventory=INV, certs_dir=self.certs, iocs_prefix=None,
                         modules=mods, progress=False, **kw)

    def kept(self):
        return cs.kept_dirs(self.d)

    def test_same_settings_leaves_one_set(self):
        self.build(REG[:1])
        s = self.build(REG[:1])
        self.assertTrue(s.get("replaced_previous"))
        self.assertNotIn("kept_previous", s)
        self.assertFalse(os.path.exists(os.path.join(self.d, cs.KEPT)))      # staging gone, nothing piled up
        self.assertEqual(sorted(f for f in os.listdir(self.d) if f != "certs"),
                         ["x-all-in-one-generation-report.csv", "x-all-in-one-tls-keys.log",
                          "x-all-in-one.manifest.json", "x-all-in-one.pcap"])

    def test_different_settings_keep_first(self):
        a = self.build(REG[:1])
        first = rd(self.out)
        certs_a = sorted(os.listdir(self.certs))
        b = self.build(REG[1:2])
        k = b["kept_previous"]
        self.assertEqual(self.kept(), [k["dir"]])
        self.assertTrue(os.path.realpath(k["dir"]).startswith(self.d + os.sep + cs.KEPT + os.sep))
        self.assertEqual(rd(os.path.join(k["dir"], "x-all-in-one.pcap")), first)                               # the earlier capture is byte-intact
        for n in ("x-all-in-one-tls-keys.log", "x-all-in-one.manifest.json", "x-all-in-one-generation-report.csv"):
            self.assertTrue(os.path.isfile(os.path.join(k["dir"], n)), n)
        self.assertEqual(sorted(os.listdir(os.path.join(k["dir"], "certs"))), certs_a)
        self.assertNotEqual(rd(self.out), first)              # the new build is its own capture
        m = json.loads(rd(os.path.join(k["dir"], "x-all-in-one.manifest.json")))
        self.assertEqual(m["packets"] if "packets" in m else m["totals"]["packets"], a["packets"])
        info = cs.info(os.path.join(k["dir"], "x-all-in-one.pcap"))
        self.assertEqual(info["scenarios"], 1)
        self.assertEqual(info["capture_date"], a["date"])

    def test_third_build_keeps_both(self):
        self.build(REG[:1])
        self.build(REG[1:2])
        self.build(REG[2:3])
        self.assertEqual(len(self.kept()), 2)

    def test_cancel_restores_previous(self):
        self.build(REG[:1])
        before = {f: rd(os.path.join(self.d, f)) for f in os.listdir(self.d) if f != "certs"}
        certs = {f: rd(os.path.join(self.certs, f)) for f in os.listdir(self.certs)}
        with self.assertRaises(Cancelled):
            self.build(REG[1:2], should_cancel=lambda: True)
        after = {f: rd(os.path.join(self.d, f)) for f in os.listdir(self.d) if f != "certs"}
        self.assertEqual(after, before)
        self.assertEqual({f: rd(os.path.join(self.certs, f)) for f in os.listdir(self.certs)}, certs)
        self.assertFalse(os.path.exists(os.path.join(self.d, cs.KEPT)))

    def test_cancel_during_run_restores_same_settings_too(self):
        self.build(REG[:1])
        size = os.path.getsize(self.out)
        calls = []

        def stop():
            calls.append(1)
            return len(calls) > 3               # past the scheduling loop, inside the engine run
        with self.assertRaises(Cancelled):
            self.build(REG[:1], should_cancel=stop)
        self.assertEqual(os.path.getsize(self.out), size)
        self.assertFalse(os.path.exists(os.path.join(self.d, cs.KEPT)))

    def test_kept_set_is_trashable_and_restorable(self):
        self.build(REG[:1])
        k = self.build(REG[1:2])["kept_previous"]["dir"]
        r = cs.trash(k, "x-all-in-one.pcap")
        self.assertIn("x-all-in-one.manifest.json", r["moved"])
        self.assertIn("x-all-in-one-generation-report.csv", r["moved"])
        ls = cs.listing(self.d)["items"]
        self.assertEqual([(i["name"], i["out_dir"]) for i in ls], [("x-all-in-one.pcap", k)])
        cs.restore(ls[0]["out_dir"], ls[0]["trash_id"])
        self.assertTrue(os.path.isfile(os.path.join(k, "x-all-in-one.pcap")))
        self.assertEqual(cs.listing(self.d)["items"], [])


class Unit(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp(prefix="og-keep-u-"))
        self.sig = {"generator": "1", "parameters": {"a": 1}}

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def hold(self, **kw):
        return cs.hold_previous(os.path.join(self.d, "c.pcap"), os.path.join(self.d, "c-tls-keys.log"),
                                kw.get("certs", os.path.join(self.d, "certs")), self.sig)

    def test_nothing_there_nothing_held(self):
        self.assertIsNone(self.hold())

    def test_no_manifest_is_kept_not_replaced(self):
        touch(self.d, "c.pcap")
        h = self.hold()
        self.assertFalse(h.same)
        self.assertFalse(os.path.exists(os.path.join(self.d, "c.pcap")))
        h.rollback()
        self.assertTrue(os.path.isfile(os.path.join(self.d, "c.pcap")))
        self.assertFalse(os.path.exists(os.path.join(self.d, cs.KEPT)))

    def test_certs_only_are_kept(self):
        touch(self.d, "certs/a.crt")
        h = self.hold()
        self.assertTrue(os.path.isfile(os.path.join(h.dir, "certs", "a.crt")))
        self.assertEqual(os.listdir(os.path.join(self.d, "certs")) if os.path.isdir(os.path.join(self.d, "certs")) else [], [])

    def test_unrelated_files_untouched(self):
        touch(self.d, "c.pcap")
        touch(self.d, "other.pcap")
        touch(self.d, "inventory.json")
        touch(self.d, "c-all-recipe.json")
        self.hold()
        self.assertEqual(sorted(f for f in os.listdir(self.d) if f != cs.KEPT), ["c-all-recipe.json", "inventory.json", "other.pcap"])

    def test_manifest_outputs_cannot_escape(self):
        outside = tempfile.mkdtemp(prefix="og-outside-")
        try:
            touch(outside, "secret.txt")
            os.symlink(os.path.join(outside, "secret.txt"), os.path.join(self.d, "link.txt"))
            os.symlink(outside, os.path.join(self.d, "linkdir"))
            touch(self.d, "c.pcap")
            mf = {"generator": "0", "parameters": {}, "created_utc": "2026-01-02T03:04:05Z",
                  "outputs": [{"name": n} for n in ("../" + os.path.basename(outside) + "/secret.txt", outside + "/secret.txt",
                                                    "link.txt", "linkdir/secret.txt", "../../etc/passwd", "", None, 5)]}
            touch(self.d, "c.manifest.json", json.dumps(mf).encode())
            h = self.hold()
            self.assertEqual(sorted(h.files), ["c.manifest.json", "c.pcap"])
            self.assertTrue(os.path.islink(os.path.join(self.d, "link.txt")))
            self.assertTrue(os.path.isfile(os.path.join(outside, "secret.txt")))
            self.assertTrue(os.path.basename(h.dir).startswith("20260102T030405Z-c"))
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_symlinked_certs_or_kept_dir_refused(self):
        outside = tempfile.mkdtemp(prefix="og-outside-")
        try:
            touch(outside, "k.key")
            os.symlink(outside, os.path.join(self.d, "certs"))
            self.assertIsNone(self.hold())                                   # a linked certs dir is never walked
            self.assertTrue(os.path.isfile(os.path.join(outside, "k.key")))
            touch(self.d, "c.pcap")
            os.symlink(outside, os.path.join(self.d, cs.KEPT))
            with self.assertRaises(RuntimeError):
                self.hold()
            self.assertTrue(os.path.isfile(os.path.join(self.d, "c.pcap")))
            self.assertEqual(sorted(os.listdir(outside)), ["k.key"])
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_kept_dirs_ignores_links_and_hidden(self):
        os.makedirs(os.path.join(self.d, cs.KEPT, "20260101T000000Z-a"))
        os.makedirs(os.path.join(self.d, cs.KEPT, ".replacing-x"))
        os.symlink(self.d, os.path.join(self.d, cs.KEPT, "lnk"))
        self.assertEqual([os.path.basename(k) for k in cs.kept_dirs(self.d)], ["20260101T000000Z-a"])


if __name__ == "__main__":
    unittest.main()


class Server(unittest.TestCase):
    """/api/captures lists kept builds with size/date/scenario count; /api/manifest serves their manifest."""

    def test_listing_and_manifest(self):
        import threading
        import urllib.parse
        import urllib.request
        import server
        from http.server import ThreadingHTTPServer
        d = os.path.realpath(tempfile.mkdtemp(prefix="og-keep-s-"))
        try:
            touch(d, "new.pcap", b"n" * 10)
            k = os.path.join(d, cs.KEPT, "20260102T030405Z-old")
            touch(k, "old.pcap", b"o" * 7)
            touch(k, "old.manifest.json", json.dumps({"parameters": {"date": "2026-01-02"}, "scenarios": [{}, {}, {}]}).encode())
            server.STATE["out_dir"] = d
            srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            base = "http://127.0.0.1:%d" % srv.server_port
            with urllib.request.urlopen(base + "/api/captures?out_dir=" + urllib.parse.quote(d)) as r:
                items = {i["name"]: i for i in json.loads(r.read())["items"]}
            self.assertEqual(sorted(items), ["new.pcap", "old.pcap"])
            self.assertTrue(items["old.pcap"]["kept"])
            self.assertEqual((items["old.pcap"]["size"], items["old.pcap"]["scenarios"], items["old.pcap"]["capture_date"]),
                             (7, 3, "2026-01-02"))
            self.assertNotIn("kept", items["new.pcap"])
            with urllib.request.urlopen(base + "/api/manifest?path=" + urllib.parse.quote(os.path.join(k, "old.pcap"))) as r:
                self.assertEqual(r.status, 200)
            srv.shutdown()
            srv.server_close()
            self.assertEqual([i["name"] for i in server.list_outputs(d)], ["new.pcap"])     # kept files are not this build's results
        finally:
            server.STATE.pop("out_dir", None)
            shutil.rmtree(d, ignore_errors=True)
