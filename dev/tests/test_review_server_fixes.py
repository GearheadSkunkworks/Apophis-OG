"""Regression tests for the server-side review fixes (S-01..S-07)."""
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)


class S01(unittest.TestCase):
    def test_preflight_with_missing_tool(self):
        import replay
        with mock.patch.object(replay, "find_tool", return_value=None):
            r = replay.preflight(None, None, fresh=True)
        self.assertTrue(any("was not found" in e for e in r["errors"]))


class S02(unittest.TestCase):
    def test_bad_sensor_leaves_not_running(self):
        from sensorops import push_cert
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch.object(push_cert, "get_provider", side_effect=ValueError("bad sensor")):
            with self.assertRaises(ValueError):
                push_cert.push_cert("http://evil/x", "k", d)
        self.assertFalse(push_cert.status()["running"])


class S03(unittest.TestCase):
    def test_last_name_not_last_json(self):
        import sessions_api as S
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.environ["OPENGENERATOR_SESSIONS"] = d
        self.addCleanup(os.environ.pop, "OPENGENERATOR_SESSIONS", None)
        st = {"controls": {"company": "A"}}
        r = S.route_post("/api/session/save", {"name": "Weekly Demo", "state": st})
        r2 = S.route_post("/api/session/save", {"name": "weekly demo!", "state": st})
        self.assertNotEqual(json.loads(r[1])["id"], json.loads(r2[1])["id"])
        r = S.route_post("/api/session/save", {"name": "Last", "state": st})
        self.assertEqual(r[0], 200)
        sid = json.loads(r[1])["id"]
        self.assertNotEqual(sid, "last")
        self.assertEqual(len(json.loads(S.route_get("/api/session/list", "")[1])["sessions"]), 3)


class S04(unittest.TestCase):
    def test_restore_name_with_spaces_and_parens(self):
        import captures_store as cs
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        with open(os.path.join(d, "my capture (1).pcap"), "wb") as fh:
            fh.write(b"x")
        r = cs.trash(d, "my capture (1).pcap")
        cs.restore(d, r["trash_id"])
        self.assertTrue(os.path.exists(os.path.join(d, "my capture (1).pcap")))


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        os.environ["OG_SETTINGS_DIR"] = cls.tmp
        import server
        cls.server = server
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_port

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        os.environ.pop("OG_SETTINGS_DIR", None)
        shutil.rmtree(cls.tmp, True)

    def post(self, path, body):
        rq = urllib.request.Request(self.base + path, data=body.encode(), method="POST",
                                    headers={"Content-Type": "application/json",
                                             "Cookie": "og_ui=" + self.server.UI_SECRET})
        try:
            r = urllib.request.urlopen(rq, timeout=10)
        except urllib.error.HTTPError as e:
            r = e
        return r.status, json.loads(r.read())

    def test_s06_bad_bodies_get_400(self):
        for path, body in (("/api/generate", "[]"), ("/api/generate", '{"scale":"x"}'),
                           ("/api/generate", '{"scale":null}'), ("/api/replay/start", "[]"),
                           ("/api/sensor/push", "[]"), ("/api/reveal", '{"out_dir":5}'),
                           ("/api/recipe/save", "[]")):
            st, js = self.post(path, body)
            self.assertEqual(st, 400, (path, body, st, js))
            self.assertIn("error", js)

    def test_s05_claim_is_atomic(self):
        srv = self.server
        started = []
        with mock.patch.object(srv, "run_generator", side_effect=lambda *a: started.append(a)):
            srv.STATE["running"] = False
            st1, _ = self.post("/api/generate", json.dumps({"scale": 0.001, "out_dir": self.tmp}))
            st2, _ = self.post("/api/generate", json.dumps({"scale": 0.001, "out_dir": self.tmp}))
        srv.STATE["running"] = False
        self.assertEqual((st1, st2), (200, 409))


class S07(unittest.TestCase):
    def test_activate_oserror_does_not_crash(self):
        import overlay
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        os.makedirs(os.path.join(base, "current"))
        open(os.path.join(base, ".booting"), "w").close()
        saved = overlay._ROOT
        overlay._ROOT = None
        self.addCleanup(setattr, overlay, "_ROOT", saved)
        with mock.patch("os.replace", side_effect=OSError("denied")):
            self.assertEqual(overlay.activate("/bundle", base=base, frozen=True), "/bundle")


if __name__ == "__main__":
    unittest.main()
