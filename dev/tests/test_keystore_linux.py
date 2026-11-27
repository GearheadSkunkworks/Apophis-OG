"""Linux keystore backends (dev/keystore.py): selection matrix, secret-tool argv/stdin, the 0600 file backend,
fallback, status, and that no secret reaches argv, an error message or a log. Everything runs on any OS: the
Secret Service CLI is a fake runner and the platform and probe result are injected.

Run from dev/:  python -m unittest tests.test_keystore_linux
Not verified here: a real desktop distro with GNOME Keyring or KWallet; only the CLI contract is faked.
"""
import json
import logging
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
if DEV not in sys.path:
    sys.path.insert(0, DEV)

import keystore                                        # noqa: E402 - sys.path is set up first

SECRET = 'sk-LINUX "q" \\ 0123456789'


class FakeRunner:
    """Stands in for subprocess.run of secret-tool; records (argv, stdin, timeout) and replies from a script."""
    def __init__(self, rc=0, out="", err=""):
        self.calls, self.rc, self.out, self.err, self.exc = [], rc, out, err, None

    def __call__(self, argv, input=None, timeout=None, **kw):
        self.calls.append((list(argv), input, timeout))
        if self.exc:
            raise self.exc
        return mock.Mock(returncode=self.rc, stdout=self.out, stderr=self.err)


class Selection(unittest.TestCase):
    def test_matrix(self):
        for platform, probe, want in [("darwin", None, "keychain"), ("darwin", "ok", "keychain"),
                                      ("linux", "ok", "secret-service"), ("linux", "no-tool", "file"),
                                      ("linux", "unreachable", "file"), ("freebsd", "unreachable", "file")]:
            name, why = keystore.select_backend(platform, probe)
            self.assertEqual(name, want, (platform, probe))
            self.assertTrue(why)

    def test_probe(self):
        found = lambda _: "/usr/bin/secret-tool"          # noqa: E731 - one-line stand-in for shutil.which
        self.assertEqual(keystore.probe_secret_service(FakeRunner(), which=lambda _: None), "no-tool")
        self.assertEqual(keystore.probe_secret_service(FakeRunner(rc=1), which=found), "ok")            # quiet miss
        self.assertEqual(keystore.probe_secret_service(FakeRunner(rc=0, out="x"), which=found), "ok")
        self.assertEqual(keystore.probe_secret_service(FakeRunner(rc=1, err="Cannot autolaunch D-Bus"), which=found),
                         "unreachable")
        hung = FakeRunner(); hung.exc = keystore.subprocess.TimeoutExpired("secret-tool", 5)
        self.assertEqual(keystore.probe_secret_service(hung, which=found), "unreachable")
        gone = FakeRunner(); gone.exc = FileNotFoundError()
        self.assertEqual(keystore.probe_secret_service(gone, which=found), "unreachable")

    def test_probe_is_bounded_list_argv(self):
        r = FakeRunner(rc=1)
        keystore.probe_secret_service(r, which=lambda _: "/x")
        argv, stdin, timeout = r.calls[0]
        self.assertIsInstance(argv, list)
        self.assertIsNone(stdin)
        self.assertEqual(timeout, keystore.PROBE_TIMEOUT)

    def test_runtime_selection_and_status(self):
        self.addCleanup(keystore.reset)
        for platform, probe, name, secure in [("linux", "ok", "secret-service", True), ("linux", "unreachable", "file", False)]:
            keystore.reset()
            with mock.patch.object(keystore.sys, "platform", platform), \
                    mock.patch.object(keystore, "probe_secret_service", lambda p=probe: p):
                st = keystore.status()
                self.assertEqual((st["backend"], st["secure"], st["available"]), (name, secure, True))
                self.assertTrue(st["why"])
        keystore.reset()
        with mock.patch.object(keystore.sys, "platform", "darwin"):
            self.assertEqual(keystore.status()["backend"], "keychain")

    def test_probe_runs_once(self):
        self.addCleanup(keystore.reset)
        keystore.reset()
        probe = mock.Mock(return_value="no-tool")
        with mock.patch.object(keystore.sys, "platform", "linux"), mock.patch.object(keystore, "probe_secret_service", probe):
            keystore.available(); keystore.status(); keystore.stored_ids()
        probe.assert_called_once()


class SecretService(unittest.TestCase):
    def backend(self, **kw):
        self.r = FakeRunner(**kw)
        return keystore._SecretService(self.r)

    def test_save_secret_on_stdin_only(self):
        b = self.backend(); b.save("feed:otx", SECRET)
        argv, stdin, timeout = self.r.calls[0]
        self.assertEqual(argv, ["secret-tool", "store", "--label=OpenGenerator key",
                                "service", "opengenerator", "account", "feed:otx"])
        self.assertEqual(stdin, SECRET)
        self.assertNotIn(SECRET, " ".join(argv))
        self.assertEqual(timeout, keystore.TIMEOUT)

    def test_load(self):
        self.assertEqual(self.backend(out=SECRET).load("feed:otx"), SECRET)
        self.assertEqual(self.r.calls[0][0], ["secret-tool", "lookup", "service", "opengenerator", "account", "feed:otx"])
        self.assertIsNone(self.backend(rc=1).load("feed:otx"))
        with self.assertRaises(keystore.KeystoreError):
            self.backend(rc=1, err="boom").load("feed:otx")

    def test_forget(self):
        b = self.backend(); b.forget("feed:otx")
        self.assertEqual(self.r.calls[0][0][:2], ["secret-tool", "clear"])
        self.backend(rc=1).forget("feed:otx")                   # nothing stored: fine
        with self.assertRaises(keystore.KeystoreError):
            self.backend(rc=2, err="locked").forget("feed:otx")

    def test_stored_ids_drop_secrets(self):
        out = ("[/org/x/1]\nlabel = OpenGenerator key\nsecret = %s\nattribute.account = feed:otx\n"
               "attribute.service = opengenerator\n\n[/org/x/2]\nsecret = other\nattribute.account = BAD ID\n"
               "attribute.account = sensor:10.0.0.5\n" % SECRET)
        self.assertEqual(self.backend(out=out).stored_ids(), ["feed:otx", "sensor:10.0.0.5"])
        self.assertEqual(self.backend(rc=1).stored_ids(), [])

    def test_failures_are_sanitised(self):
        b = self.backend(rc=1, err="secret is %s" % SECRET)
        with self.assertRaises(keystore.KeystoreError) as cm:
            b.save("feed:otx", SECRET)
        self.assertNotIn(SECRET, str(cm.exception))
        b.runner.exc = keystore.subprocess.TimeoutExpired(["secret-tool", "store", SECRET], 15)
        with self.assertRaises(keystore.KeystoreError) as cm:
            b.save("feed:otx", SECRET)
        self.assertNotIn(SECRET, str(cm.exception))
        self.assertIsNone(cm.exception.__cause__)               # the chained TimeoutExpired holds argv


class FileBackend(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.dir = os.path.join(self.tmp.name, "settings")      # does not exist yet
        p = mock.patch.dict(os.environ, {"OG_SETTINGS_DIR": self.dir}); p.start(); self.addCleanup(p.stop)
        self.b = keystore._File()
        self.path = os.path.join(self.dir, keystore.FILE_NAME)

    def mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    def test_round_trip_and_permissions(self):
        self.assertIsNone(self.b.load("feed:otx"))
        self.assertEqual(self.b.stored_ids(), [])
        self.b.save("feed:otx", SECRET)
        self.b.save("sensor:10.0.0.5", "k2")
        self.assertEqual(self.b.load("feed:otx"), SECRET)
        self.assertEqual(self.b.stored_ids(), ["feed:otx", "sensor:10.0.0.5"])
        self.assertEqual(self.mode(self.path), 0o600)
        self.assertEqual(self.mode(self.dir), 0o700)

    def test_forget(self):
        self.b.save("feed:otx", SECRET); self.b.save("a:b", "k")
        self.b.forget("feed:otx")
        self.assertIsNone(self.b.load("feed:otx"))
        self.assertEqual(self.b.load("a:b"), "k")
        self.b.forget("feed:otx")                               # already gone: fine
        self.b.forget("never:there")

    def test_atomic_write_leaves_old_file_on_failure(self):
        self.b.save("feed:otx", "old")
        with mock.patch.object(keystore.os, "replace", side_effect=OSError("disk")):
            with self.assertRaises(keystore.KeystoreError):
                self.b.save("feed:otx", SECRET)
        self.assertEqual(self.b.load("feed:otx"), "old")
        self.assertEqual(os.listdir(self.dir), [keystore.FILE_NAME])          # no temp file left behind

    def test_write_goes_through_a_temp_file_then_replace(self):
        real = os.replace
        seen = []
        def spy(src, dst):
            seen.append((os.path.basename(src), self.mode(src), dst)); real(src, dst)
        with mock.patch.object(keystore.os, "replace", spy):
            self.b.save("feed:otx", SECRET)
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0][0].startswith(".keystore-"))
        self.assertEqual(seen[0][1], 0o600)
        self.assertEqual(seen[0][2], self.path)

    def test_refuses_wide_mode(self):
        self.b.save("feed:otx", SECRET)
        for mode in (0o644, 0o640, 0o604, 0o660, 0o700):
            os.chmod(self.path, mode)
            with self.assertRaises(keystore.KeystoreError) as cm:
                self.b.load("feed:otx")
            self.assertIn("chmod 600", str(cm.exception))
            self.assertNotIn(SECRET, str(cm.exception))
        os.chmod(self.path, 0o400)                              # narrower than 0600 is fine
        self.assertEqual(self.b.load("feed:otx"), SECRET)

    def test_refuses_other_owner(self):
        self.b.save("feed:otx", SECRET)
        with mock.patch.object(keystore.os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(keystore.KeystoreError) as cm:
                self.b.load("feed:otx")
        self.assertIn("another user", str(cm.exception))

    def test_refuses_symlink(self):
        os.makedirs(self.dir)
        real = os.path.join(self.tmp.name, "elsewhere.json")
        with open(real, "w") as fh:
            fh.write("{}")
        os.chmod(real, 0o600)
        os.symlink(real, self.path)
        with self.assertRaises(keystore.KeystoreError):
            self.b.load("feed:otx")

    def test_damaged_file(self):
        os.makedirs(self.dir)
        for text in ("{not json", "[1]", '{"a": 1}'):
            with open(self.path, "w") as fh:
                fh.write(text)
            os.chmod(self.path, 0o600)
            with self.assertRaises(keystore.KeystoreError) as cm:
                self.b.load("a")
            self.assertIn("damaged", str(cm.exception))

    def test_write_refusal_does_not_overwrite_wide_file(self):
        self.b.save("feed:otx", "old")
        os.chmod(self.path, 0o644)
        with self.assertRaises(keystore.KeystoreError):
            self.b.save("feed:otx", SECRET)                     # read-modify-write reads first, so it refuses
        with open(self.path) as fh:
            self.assertEqual(json.load(fh), {"feed:otx": "old"})


class PublicApi(unittest.TestCase):
    """The unchanged public names route to the chosen backend and validate input first."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        for p in (mock.patch.dict(os.environ, {"OG_SETTINGS_DIR": self.tmp.name}),
                  mock.patch.object(keystore.sys, "platform", "linux"),
                  mock.patch.object(keystore, "probe_secret_service", lambda: "unreachable")):
            p.start(); self.addCleanup(p.stop)
        keystore.reset(); self.addCleanup(keystore.reset)

    def test_fallback_to_file_when_service_unreachable(self):
        self.assertEqual(keystore.status()["backend"], "file")
        keystore.save("feed:otx", SECRET)
        self.assertEqual(keystore.load("feed:otx"), SECRET)
        self.assertEqual(keystore.stored_ids(), ["feed:otx"])
        keystore.forget("feed:otx")
        self.assertIsNone(keystore.load("feed:otx"))

    def test_validation_runs_before_any_backend(self):
        with self.assertRaises(keystore.KeystoreError):
            keystore.save("BAD ID", "k")
        with self.assertRaises(keystore.KeystoreError):
            keystore.save("feed:otx", "bad\nsecret")
        self.assertEqual(os.listdir(self.tmp.name), [])

    def test_secret_service_selected_routes_through_cli(self):
        keystore.reset()
        r = FakeRunner(out=SECRET)
        with mock.patch.object(keystore, "probe_secret_service", lambda: "ok"), \
                mock.patch.object(keystore.subprocess, "run", r):
            keystore.save("feed:otx", SECRET)
            self.assertEqual(keystore.load("feed:otx"), SECRET)
        self.assertEqual([c[0][1] for c in r.calls], ["store", "lookup"])
        self.assertEqual(os.listdir(self.tmp.name), [])         # nothing leaked to the file backend
        for argv, _, _ in r.calls:
            self.assertNotIn(SECRET, " ".join(argv))

    def test_no_secret_in_logs(self):
        keystore.reset()
        with self.assertNoLogs(level=logging.DEBUG), mock.patch("sys.stdout") as out, mock.patch("sys.stderr") as err:
            keystore.save("feed:otx", SECRET)
            keystore.load("feed:otx")
            keystore.status()
            with self.assertRaises(keystore.KeystoreError):
                keystore.save("feed:otx", SECRET + "\n")
        for stream in (out, err):
            self.assertNotIn(SECRET, "".join(str(c) for c in stream.method_calls + stream.write.call_args_list))


class MacUnchanged(unittest.TestCase):
    def test_darwin_uses_keychain_and_never_probes(self):
        keystore.reset(); self.addCleanup(keystore.reset)
        with mock.patch.object(keystore.sys, "platform", "darwin"), \
                mock.patch.object(keystore, "probe_secret_service") as probe, \
                mock.patch.object(keystore, "_kc_available", lambda: True):
            self.assertEqual(keystore.status()["backend"], "keychain")
            probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
