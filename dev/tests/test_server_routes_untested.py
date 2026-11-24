"""Literal-path tests for server routes that had none: /api/reveal, /api/recipe/save,
/api/capabilities/*, /diagram. Real handler on an ephemeral port; no network, no builds."""
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
import http.client
from http.server import ThreadingHTTPServer
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import server  # noqa: E402


class Routes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ogroutes-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def req(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        data = json.dumps(body).encode() if body is not None else None
        c.request(method, path, body=data, headers={"Content-Type": "application/json"} if data else {})
        r = c.getresponse()
        b = r.read()
        c.close()
        return r.status, b

    def post(self, path, body):
        s, b = self.req("POST", path, body)
        return s, json.loads(b)

    # ---- /api/reveal
    def test_reveal_refuses_missing_bundle_and_symlink(self):
        with mock.patch.object(server.subprocess, "run") as run:
            s, d = self.post("/api/reveal", {"out_dir": os.path.join(self.tmp, "nope")})
            self.assertEqual(s, 400)
            bundle = os.path.join(self.tmp, "Evil.app")
            os.mkdir(bundle)
            s, d = self.post("/api/reveal", {"out_dir": bundle})
            self.assertEqual(s, 400)
            self.assertIn("bundle", d["error"])
            link = os.path.join(self.tmp, "link")
            os.symlink(bundle, link)           # realpath resolves to the bundle
            s, d = self.post("/api/reveal", {"out_dir": link})
            self.assertEqual(s, 400)
            run.assert_not_called()

    def test_reveal_plain_folder_opens_resolved_path(self):
        with mock.patch.object(server.subprocess, "run") as run, \
                mock.patch.object(server.sys, "platform", "darwin"):
            s, d = self.post("/api/reveal", {"out_dir": self.tmp})
        self.assertEqual((s, d), (200, {"ok": True}))
        self.assertEqual(run.call_args[0][0], ["open", os.path.realpath(self.tmp)])

    # ---- /api/recipe/save
    def test_recipe_save_bad_paths(self):
        s, d = self.post("/api/recipe/save", {"path": os.path.join(self.tmp, "x.pcap")})
        self.assertEqual(s, 400)
        txt = os.path.join(self.tmp, "x.pcap")
        with open(txt, "w") as f:
            f.write("not a pcap")
        s, d = self.post("/api/recipe/save", {"path": txt, "out_dir": self.tmp})
        self.assertIn(s, (400, 422))
        self.assertIn("error", d)
        self.assertEqual([f for f in os.listdir(self.tmp) if f.endswith("-recipe.json")], [])

    def test_recipe_save_writes_named_recipe(self):
        src = os.path.join(self.tmp, "cap.pcap")
        open(src, "wb").close()
        pp = server.pcapprofile
        out = os.path.join(self.tmp, "out")
        with mock.patch.object(pp, "probe_readable"), mock.patch.object(pp, "kind", return_value="pcap"), \
                mock.patch.object(pp, "profile", return_value={}), \
                mock.patch.object(pp, "unusable_reason", return_value=None), \
                mock.patch.object(pp, "build_spec", return_value={"k": 1}):
            s, d = self.post("/api/recipe/save", {"path": src, "out_dir": out})
        self.assertEqual(s, 200, d)
        with open(os.path.join(out, "cap-recipe.json")) as f:
            self.assertEqual(json.load(f), {"k": 1})

    def test_recipe_save_unusable_is_422(self):
        src = os.path.join(self.tmp, "cap.pcap")
        open(src, "wb").close()
        pp = server.pcapprofile
        with mock.patch.object(pp, "probe_readable"), mock.patch.object(pp, "kind", return_value="pcap"), \
                mock.patch.object(pp, "profile", return_value={}), \
                mock.patch.object(pp, "unusable_reason", return_value="empty"):
            s, d = self.post("/api/recipe/save", {"path": src, "out_dir": self.tmp})
        self.assertEqual(s, 422)

    # ---- /api/capabilities/*
    def test_capabilities_catalog_and_validation(self):
        s, b = self.req("GET", "/api/capabilities")
        d = json.loads(b)
        self.assertEqual(s, 200)
        self.assertIn("capabilities", d)
        self.assertIn("builtins", d)
        for act in ("enable", "load", "unload", "reload", "test"):
            s, d = self.post("/api/capabilities/" + act, {})
            self.assertEqual(s, 400, act)
            self.assertIn("name", d["error"])

    def test_capabilities_unknown_module_400_and_busy_409(self):
        s, d = self.post("/api/capabilities/load", {"name": "no-such-module-xyz"})
        self.assertEqual(s, 400)
        with mock.patch.dict(server.STATE, {"running": True}):
            s, d = self.post("/api/capabilities/load", {"name": "x"})
            self.assertEqual(s, 409)
            s, d = self.post("/api/capabilities/test-all", {})
            self.assertEqual(s, 409)

    def test_capabilities_enable_toggles_flag(self):
        k = server.capkernel.kernel
        with mock.patch.object(k, "set_enabled") as se:
            s, d = self.post("/api/capabilities/enable", {"name": "m", "on": True})
        self.assertEqual(s, 200)
        se.assert_called_once_with("m", True)

    # ---- /diagram
    def test_diagram_ok_unknown_and_bad_net(self):
        s, b = self.req("GET", "/diagram?name=topology&company=A%26B%3Cx%3E&industry=Retail")
        self.assertEqual(s, 200)
        self.assertNotIn(b"<x>", b)
        s, b = self.req("GET", "/diagram?name=nope-nope")
        self.assertEqual(s, 400)
        s, b = self.req("GET", "/diagram?name=topology&user_net=not-a-net")
        self.assertEqual(s, 400)

    def test_diagram_render_crash_is_500_page(self):
        with mock.patch.object(server.make_diagram, "render", side_effect=RuntimeError("<boom>")):
            s, b = self.req("GET", "/diagram?name=topology")
        self.assertEqual(s, 500)
        self.assertNotIn(b"<boom>", b)


if __name__ == "__main__":
    unittest.main()
