"""Persistent UI settings: the store (validation, merge, atomic write, corrupt file) and /api/settings."""
import http.client
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import settings_store as ss  # noqa: E402
import server  # noqa: E402


class TmpDirCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch.dict(os.environ, {"OG_SETTINGS_DIR": self.tmp.name})
        p.start()
        self.addCleanup(p.stop)


class TestStore(TmpDirCase):
    def test_missing_file_gives_defaults(self):
        self.assertEqual(ss.load(), ss.DEFAULTS)

    def test_corrupt_file_gives_defaults(self):
        for junk in (b"{not json", b"[1,2]", b"\xff\xfe", b""):
            with open(ss.settings_path(), "wb") as f:
                f.write(junk)
            self.assertEqual(ss.load(), ss.DEFAULTS)

    def test_bad_stored_value_falls_back_per_key(self):
        with open(ss.settings_path(), "w") as f:
            json.dump({"palette": "neon", "theme": "light", "bogus": 1}, f)
        got = ss.load()
        self.assertEqual(got["palette"], ss.DEFAULTS["palette"])
        self.assertEqual(got["theme"], "light")
        self.assertNotIn("bogus", got)

    def test_update_merges_and_persists(self):
        ss.update({"palette": "teal"})
        out = ss.update({"lab_tools": True, "choose_mode": "map"})
        self.assertEqual(out["palette"], "teal")
        self.assertTrue(out["lab_tools"])
        self.assertEqual(out["choose_mode"], "map")
        self.assertEqual(ss.load(), out)

    def test_defaults_and_folder_settings(self):
        d = ss.load()
        self.assertTrue(d["restore_last_session"])
        self.assertEqual((d["default_size"], d["out_dir"]), ("standard", ""))
        out = ss.update({"default_size": "full", "out_dir": "  /tmp/caps  ", "restore_last_session": False})
        self.assertEqual((out["default_size"], out["out_dir"], out["restore_last_session"]), ("full", "/tmp/caps", False))

    def test_file_mode_and_no_temp_left(self):
        ss.update({"theme": "system"})
        self.assertEqual(stat.S_IMODE(os.stat(ss.settings_path()).st_mode), 0o600)
        self.assertEqual(os.listdir(self.tmp.name), [ss.FILE_NAME])

    def test_validation(self):
        bad = [{"nope": 1}, {"palette": "pink"}, {"theme": 1}, {"choose_mode": "grid"},
               {"lab_tools": "yes"}, {"lab_tools": 1}, {"default_scale": 0.5},
               {"default_size": "huge"}, {"out_dir": 5}, {"out_dir": "a" * 2000}, {"restore_last_session": "yes"}, [], "x"]
        for b in bad:
            with self.assertRaises(ss.SettingsError, msg=repr(b)):
                ss.validate(b)
        self.assertFalse(os.path.exists(ss.settings_path()))

    def test_invalid_update_is_atomic(self):
        ss.update({"palette": "sage"})
        with self.assertRaises(ss.SettingsError):
            ss.update({"theme": "light", "palette": "bad"})
        self.assertEqual(ss.load()["theme"], ss.DEFAULTS["theme"])
        self.assertEqual(ss.load()["palette"], "sage")

    def test_default_dir_by_platform(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OG_SETTINGS_DIR")
            with mock.patch.object(ss.sys, "platform", "darwin"):
                self.assertTrue(ss.settings_dir().endswith("Library/Application Support/OpenGenerator"))
            with mock.patch.object(ss.sys, "platform", "linux"), \
                    mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": ""}):
                self.assertTrue(ss.settings_dir().endswith(".config/opengenerator"))


class TestRoute(TmpDirCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def call(self, method, body=None, raw=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
        c.request(method, "/api/settings", body=data, headers={"Content-Type": "application/json"})
        r = c.getresponse()
        out = r.read()
        c.close()
        return r.status, json.loads(out)

    def test_get_defaults(self):
        st, j = self.call("GET")
        self.assertEqual(st, 200)
        self.assertEqual(j["settings"], ss.DEFAULTS)
        self.assertEqual(j["defaults"], ss.DEFAULTS)

    def test_post_roundtrip(self):
        st, j = self.call("POST", {"palette": "clay", "choose_mode": "list"})
        self.assertEqual(st, 200)
        self.assertEqual(j["settings"]["palette"], "clay")
        self.assertEqual(j["settings"]["theme"], "dark")
        st, j = self.call("GET")
        self.assertEqual(j["settings"]["choose_mode"], "list")

    def test_post_invalid(self):
        for body in ({"palette": "x"}, {"zzz": True}, [1]):
            st, j = self.call("POST", body)
            self.assertEqual(st, 400)
            self.assertIn("error", j)
        st, j = self.call("POST", raw=b"{oops")
        self.assertEqual(st, 400)
        self.assertEqual(self.call("GET")[1]["settings"], ss.DEFAULTS)

    def test_oversize_body_rejected(self):
        st, j = self.call("POST", raw=b'{"palette":"teal","pad":"' + b"a" * 5000 + b'"}')
        self.assertEqual(st, 413)
        self.assertIn("error", j)
        self.assertEqual(self.call("GET")[1]["settings"], ss.DEFAULTS)


if __name__ == "__main__":
    unittest.main()
