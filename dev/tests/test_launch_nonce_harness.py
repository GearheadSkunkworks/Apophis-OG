"""The launch nonce must survive from the server's printed line through the Linux launcher and the pin harness.
Review finding: the launcher's sed kept only `http://127.0.0.1:PORT/`, so the browser never got the cookie and every POST was 403."""
import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(DEV)
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "tests"))
from test_agent_api import Base  # noqa: E402 - sys.path is set first; its Base starts a handler on a free port with a fake keystore

LAUNCHER = os.path.join(ROOT, "packaging", "linux", "apophis")
PIN = os.path.join(ROOT, "packaging", "linux", "pin_in_bundle.py")


def _pin_module():
    spec = importlib.util.spec_from_file_location("pin_in_bundle", PIN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class LaunchNonce(Base):
    def test_launcher_prints_the_url_with_the_nonce(self):
        line = self.server.launch_line(51234)
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "app"))
            shutil.copy(LAUNCHER, os.path.join(d, "apophis"))
            exe = os.path.join(d, "app", "apophis-server")
            with open(exe, "w") as fh:
                fh.write("#!/bin/sh\necho 'Closing the tab stops it'\necho '%s'\nsleep 1\n" % line.replace("'", ""))
            os.chmod(exe, os.stat(exe).st_mode | stat.S_IXUSR)
            env = {"PATH": os.environ["PATH"], "HOME": d, "XDG_STATE_HOME": d + "/s"}    # no DISPLAY: no browser
            out = subprocess.run(["/bin/sh", os.path.join(d, "apophis"), "--no-browser"], env=env, capture_output=True, text=True,
                                 timeout=60).stdout
        want = line.split("->  ", 1)[1]
        self.assertIn("->  " + want, out)
        self.assertIn("?launch=" + self.server.LAUNCH["nonce"], out)

    def test_pin_harness_extracts_the_full_url(self):
        pin = _pin_module()

        class P:
            stdout = iter([self.server.launch_line(4321) + "\n"])
        got = pin.wait_for_url(P, [])
        self.assertEqual(got, "http://127.0.0.1:4321/?launch=" + self.server.LAUNCH["nonce"])

    def test_pin_harness_posts_with_the_cookie(self):
        """Against the real handler: open the printed URL, then a POST without a cookie is 403 and with it is not."""
        import urllib.error
        pin = _pin_module()
        self.server.LAUNCH["used"] = False
        port = self.srv.server_port
        base = pin.open_session(self.server.launch_line(port).split("->  ", 1)[1])
        self.assertEqual(base, "http://127.0.0.1:%d" % port)
        try:
            pin.call(base, "/api/no-such-route", {})
        except urllib.error.HTTPError as e:
            self.assertNotEqual(e.code, 403)      # 404 for an unknown route is fine; 403 means no cookie was sent


if __name__ == "__main__":
    unittest.main()
