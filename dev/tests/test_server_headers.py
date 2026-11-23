"""Every server response is unframeable and not type-sniffed; replay interface names must have a sane shape."""
import os
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)

EXPECT = {"X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'",
          "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}


class Headers(unittest.TestCase):
    def test_all_response_kinds_carry_the_headers(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        os.environ["OG_SETTINGS_DIR"] = tmp
        self.addCleanup(os.environ.pop, "OG_SETTINGS_DIR", None)
        import server
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = "http://127.0.0.1:%d" % srv.server_port
        for path in ("/api/settings", "/", "/ui/app.css", "/no-such-page"):
            try:
                r = urllib.request.urlopen(base + path)
            except urllib.error.HTTPError as e:              # a 404 is a response too
                r = e
            for k, v in EXPECT.items():
                self.assertEqual(r.headers.get(k), v, "%s on %s" % (k, path))


class InterfaceNames(unittest.TestCase):
    def test_odd_names_are_refused_even_with_no_interface_list(self):
        import replay
        for bad in ("-w", "en0; reboot", "a b", "x" * 40, "--help", "../x"):
            r = replay.preflight(None, bad)
            self.assertTrue(any("valid interface" in e for e in r["errors"]), bad)
        r = replay.preflight(None, "en0")
        self.assertFalse(any("valid interface" in e for e in r["errors"]))


if __name__ == "__main__":
    unittest.main()
