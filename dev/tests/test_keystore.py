"""Tests for dev/keystore.py and dev/keys_api.py. The `security` tool is mocked; a real Keychain round
trip runs only on macOS with OPENGENERATOR_TEST_KEYCHAIN=1 (it may prompt).

Run from dev/:  python -m unittest tests.test_keystore
"""
import binascii
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
if DEV not in sys.path:
    sys.path.insert(0, DEV)

import keystore                                        # noqa: E402
import keys_api                                        # noqa: E402

SECRET = 'sk-TEST "quoted" \\ key 0123456789'


class FakeSecurity:
    """Stands in for subprocess.run of /usr/bin/security -i; records argv and stdin."""
    def __init__(self, rc=0, out=""):
        self.calls, self.rc, self.out = [], rc, out

    def __call__(self, argv, input=None, **kw):
        self.calls.append((list(argv), input))
        return mock.Mock(returncode=self.rc, stdout=self.out, stderr="")


def on_mac(fake):
    return mock.patch.multiple(keystore, available=lambda: True), mock.patch.object(keystore.subprocess, "run", fake)


class Mocked(unittest.TestCase):
    def run_with(self, fake):
        for p in on_mac(fake):
            p.start(); self.addCleanup(p.stop)

    def test_save_keeps_secret_off_argv(self):
        f = FakeSecurity(); self.run_with(f)
        keystore.save("feed:otx", SECRET)
        argv, stdin = f.calls[0]
        self.assertEqual(argv, ["/usr/bin/security", "-i"])
        self.assertNotIn(SECRET, " ".join(argv))
        self.assertIn("-a feed:otx", stdin)
        self.assertIn("-s opengenerator", stdin)
        self.assertIn(binascii.hexlify(SECRET.encode()).decode(), stdin)
        self.assertNotIn(SECRET, stdin)

    def test_load_and_missing(self):
        f = FakeSecurity(out="abc123\n"); self.run_with(f)
        self.assertEqual(keystore.load("feed:otx"), "abc123")
        self.assertIn("find-generic-password", f.calls[0][1])
        self.assertNotIn("-d", f.calls[0][1].split())
        f.rc, f.out = 44, ""
        self.assertIsNone(keystore.load("feed:otx"))

    def test_forget_missing_is_fine(self):
        f = FakeSecurity(rc=44); self.run_with(f)
        keystore.forget("feed:otx")

    def test_failure_messages_have_no_secret(self):
        f = FakeSecurity(rc=1, out=SECRET); self.run_with(f)
        with self.assertRaises(keystore.KeystoreError) as cm:
            keystore.save("feed:otx", SECRET)
        self.assertNotIn(SECRET, str(cm.exception))
        self.assertNotIn("\n", str(cm.exception))
        s, body = keys_api.keys_save({"id": "feed:otx", "key": SECRET})
        self.assertEqual(s, 400); self.assertNotIn(SECRET, repr(body))

    def test_subprocess_error_is_scrubbed(self):
        for p in on_mac(mock.Mock(side_effect=OSError("boom " + SECRET))):
            p.start(); self.addCleanup(p.stop)
        with self.assertRaises(keystore.KeystoreError) as cm:
            keystore.save("feed:otx", SECRET)
        self.assertNotIn(SECRET, str(cm.exception))
        self.assertIsNone(cm.exception.__cause__)

    def test_stored_ids_reads_no_secret(self):
        dump = ('keychain: "/Users/x/login.keychain-db"\nattributes:\n    "acct"<blob>="feed:otx"\n'  # release-scan: allow
                '    "svce"<blob>="opengenerator"\n'
                'keychain: "/Users/x/login.keychain-db"\nattributes:\n    "acct"<blob>="other"\n'  # release-scan: allow
                '    "svce"<blob>="someapp"\n'
                'keychain: "/Users/x/login.keychain-db"\nattributes:\n    "svce"<blob>="opengenerator"\n'  # release-scan: allow
                '    "acct"<blob>="sensor:10.0.0.5"\n')
        f = FakeSecurity(out=dump); self.run_with(f)
        self.assertEqual(keystore.stored_ids(), ["feed:otx", "sensor:10.0.0.5"])
        self.assertEqual(f.calls[0][1].strip(), "dump-keychain")

    def test_id_and_secret_validation(self):
        f = FakeSecurity(); self.run_with(f)
        for bad in ["", "A", "feed otx", "feed;rm", "x" * 65, "a\nb", None, 5, "feed/otx", "$(x)"]:
            with self.assertRaises(keystore.KeystoreError):
                keystore.save(bad, "k")
        for bad in ["", "a\nb", "a\x00b", "x" * 301, None, 5, "café"]:
            with self.assertRaises(keystore.KeystoreError):
                keystore.save("feed:otx", bad)
        keystore.save("sensor:10.0.0.5", "x" * 300)
        self.assertEqual(len(f.calls), 1)                 # only the valid call ran

    def test_resolve_key(self):
        f = FakeSecurity(out="stored\n"); self.run_with(f)
        self.assertEqual(keys_api.resolve_key("feed:otx", "typed", True), "typed")
        self.assertEqual(f.calls, [])
        self.assertEqual(keys_api.resolve_key("feed:otx", "", True), "stored")
        self.assertEqual(keys_api.resolve_key("feed:otx", "", False), "")
        f.rc, f.out = 44, ""
        with self.assertRaises(keystore.KeystoreError):
            keys_api.resolve_key("feed:otx", "", True)

    def test_routes(self):
        f = FakeSecurity(); self.run_with(f)
        self.assertEqual(set(keys_api.ROUTES), {"/api/keys/status", "/api/keys/save", "/api/keys/forget"})
        self.assertEqual(keys_api.keys_status({})[1]["available"], True)
        self.assertEqual(keys_api.keys_save({"id": "feed:otx", "key": "k"}), (200, {"ok": True}))
        self.assertEqual(keys_api.keys_forget({"id": "feed:otx"}), (200, {"ok": True}))
        self.assertEqual(keys_api.keys_save("nope")[0], 400)
        self.assertEqual(keys_api.keys_forget({"id": "BAD ID"})[0], 400)


class NotMac(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(keystore.sys, "platform", "linux"); p.start(); self.addCleanup(p.stop)

    def test_unavailable(self):
        self.assertFalse(keystore.available())
        self.assertEqual(keys_api.keys_status({}), (200, {"available": False, "stored": []}))
        with mock.patch.object(keystore.subprocess, "run") as run:
            self.assertEqual(keys_api.keys_save({"id": "feed:otx", "key": "k"})[0], 400)
            self.assertEqual(keys_api.keys_forget({"id": "feed:otx"})[0], 400)
            with self.assertRaises(keystore.KeystoreError):
                keys_api.resolve_key("feed:otx", "", True)
            self.assertEqual(keys_api.resolve_key("feed:otx", "", False), "")
            run.assert_not_called()


@unittest.skipUnless(os.environ.get("OPENGENERATOR_TEST_KEYCHAIN") == "1" and keystore.available(),
                     "set OPENGENERATOR_TEST_KEYCHAIN=1 on macOS to use the real Keychain")
class RealKeychain(unittest.TestCase):
    def test_round_trip(self):
        item = "test:roundtrip"
        self.addCleanup(keystore.forget, item)
        keystore.save(item, SECRET)
        self.assertEqual(keystore.load(item), SECRET)
        self.assertIn(item, keystore.stored_ids())
        keystore.forget(item)
        self.assertIsNone(keystore.load(item))
        self.assertNotIn(item, keystore.stored_ids())


if __name__ == "__main__":
    unittest.main()
