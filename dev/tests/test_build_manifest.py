"""Per-scenario counters and the build manifest: sums, hashes, verifier, tamper detection, route."""
import json
import os
import subprocess
import sys
import shutil
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "tools"))
import opengenerator_build as OGB  # noqa: E402
import verify_manifest as VM       # noqa: E402
import build_manifest as BM        # noqa: E402

PAIR = ["npm-sql1-service-failure", "ndr-rdp-brute"]


class T(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="og-manifest-")
        cls.out = os.path.join(cls.d, "m.pcap")
        names = [n for n in PAIR if n in OGB.INC.REGISTRY] or list(OGB.INC.REGISTRY)[:2]
        cls.names = names
        cls.s = OGB.build(scale=0.004, out=cls.out, keylog=os.path.join(cls.d, "m.keys"),
                          inventory=os.path.join(DEV, "inventory.json"), certs_dir=None,
                          iocs_prefix=None, modules=names, progress=False)
        cls.mp = os.path.join(cls.d, cls.s["manifest"])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_counter_sums(self):
        s = self.s
        self.assertTrue(s["counters_consistent"])
        self.assertEqual(sum(b["packets"] for b in s["by_scenario"].values()), s["packets"])
        self.assertEqual(sum(b["bytes"] for b in s["by_scenario"].values()), s["bytes"])
        self.assertIn("normal-day", s["by_scenario"])
        for n in self.names:
            self.assertGreater(s["by_scenario"][n]["packets"], 0, n)

    def test_pcap_bytes_match_file(self):                      # bytes = file size minus the 24-byte header
        self.assertEqual(self.s["bytes"], os.path.getsize(self.out) - 24)

    def test_manifest_shape_and_neutral(self):
        m = json.load(open(self.mp))
        self.assertEqual(m["schema_version"], 1)
        self.assertEqual([x["id"] for x in m["scenarios"]], self.s["module_names"])
        self.assertIn("m.pcap", [o["name"] for o in m["outputs"]])
        self.assertEqual(m["totals"]["packets"], self.s["packets"])
        self.assertNotIn(self.d, open(self.mp).read())          # no absolute paths

    def test_verifier_and_tamper(self):
        self.assertEqual(VM.verify(self.mp), [])
        m = json.load(open(self.mp))
        bad = os.path.join(self.d, "t.manifest.json")
        m["totals"]["packets"] += 1
        json.dump(m, open(bad, "w"))
        self.assertTrue(any("manifest_sha256" in p for p in VM.verify(bad)))
        m = BM.seal(m)                                          # re-sealed: the counter sums still catch it
        json.dump(m, open(bad, "w"))
        self.assertTrue(any("buckets sum" in p for p in VM.verify(bad)))
        os.remove(bad)

    def test_file_tamper(self):
        p2 = os.path.join(self.d, "copy")
        os.mkdir(p2)
        for f in os.listdir(self.d):
            if os.path.isfile(os.path.join(self.d, f)):
                shutil.copy(os.path.join(self.d, f), p2)
        with open(os.path.join(p2, "m.pcap"), "r+b") as fh:
            fh.seek(100)
            fh.write(b"\xff")
        self.assertTrue(any("sha256 mismatch" in p for p in VM.verify(os.path.join(p2, "m.manifest.json"))))

    def test_counters_failure_recorded(self):
        _, c = BM.by_scenario({"x": [1, 1, 80, 1.0, 1.0]}, [], 2, 80)
        self.assertEqual(c, {"counters_consistent": False, "counters_delta": {"packets": -1, "bytes": 0}})


class Sibling(unittest.TestCase):
    def test_manifest_moves_with_capture(self):
        import captures_store as cs
        with tempfile.TemporaryDirectory() as d:
            for n in ("x.pcap", "x.manifest.json"):
                open(os.path.join(d, n), "w").write("1")
            self.assertIn("x.manifest.json", cs.trash(d, "x.pcap")["moved"])


class Route(unittest.TestCase):
    def test_route(self):
        import server
        from http.server import ThreadingHTTPServer
        d = tempfile.mkdtemp()
        try:
            open(os.path.join(d, "a.manifest.json"), "w").write('{"ok": 1}')
            open(os.path.join(d, "a.pcap"), "w").write("x")
            open(os.path.join(d, "secret.json"), "w").write("{}")
            os.symlink(os.path.join(d, "secret.json"), os.path.join(d, "l.manifest.json"))
            server.STATE["out_dir"] = d                        # the folder of the last build is a served root
            srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()

            def get(p):
                try:
                    r = urllib.request.urlopen("http://127.0.0.1:%d/api/manifest?path=%s" % (srv.server_port, urllib.parse.quote(p)))
                    return r.status, r.read()
                except urllib.error.HTTPError as e:
                    return e.code, b""
            self.assertEqual(get(os.path.join(d, "a.manifest.json"))[0], 200)
            self.assertEqual(get(os.path.join(d, "a.pcap"))[0], 200)          # capture path maps to its manifest
            for bad in (os.path.join(d, "secret.json"), os.path.join(d, "l.manifest.json"),
                        os.path.join(d, "..", "etc", "a.manifest.json"), "/etc/passwd", ""):
                self.assertEqual(get(bad)[0], 400, bad)
            outside = tempfile.mkdtemp()                           # a real manifest outside the served folders
            try:
                open(os.path.join(outside, "o.manifest.json"), "w").write("{}")
                self.assertEqual(get(os.path.join(outside, "o.manifest.json"))[0], 400)
                self.assertEqual(get("a.manifest.json")[0], 400)   # relative paths are refused
            finally:
                shutil.rmtree(outside, ignore_errors=True)
            srv.shutdown()
        finally:
            server.STATE.pop("out_dir", None)
            shutil.rmtree(d, ignore_errors=True)


class EngineCliStats(unittest.TestCase):
    def test_engine_cli_prints_its_table(self):
        """The engine's own command line prints per-tag totals from Engine.stats (now five fields per tag)."""
        d = tempfile.mkdtemp()
        try:
            r = subprocess.run([sys.executable, "-m", "netgen.model", "--scale", "0.002", "--out", os.path.join(d, "x.pcap"),
                                "--keylog", os.path.join(d, "k.log"), "--stats", os.path.join(d, "s.json")],
                               cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))), capture_output=True, text=True, timeout=300)
            self.assertEqual(r.returncode, 0, r.stderr[-400:])
            self.assertIn("pkts", r.stdout)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
