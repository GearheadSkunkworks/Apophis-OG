"""make_patch signing round trip with a throwaway Ed25519 key generated here (never a real key)."""
import os
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "tools"))
import make_patch  # noqa: E402
import overlay     # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


class Signing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        p = mock.patch.object(overlay, "PUBLIC_KEY", pub.hex())
        p.start()
        self.addCleanup(p.stop)
        self.src = os.path.join(self.tmp.name, "src")
        os.makedirs(self.src)
        for n, t in (("VERSION", "9.9.3\n"), ("a.py", "x=1\n")):
            with open(os.path.join(self.src, n), "w") as f:
                f.write(t)
        self.out = os.path.join(self.tmp.name, "out")

    def keyfile(self, pw=None):
        enc = serialization.BestAvailableEncryption(pw.encode()) if pw else serialization.NoEncryption()
        path = os.path.join(self.tmp.name, "k.pem" if not pw else "ke.pem")
        with open(path, "wb") as f:
            f.write(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc))
        return path

    def check_round_trip(self, kp):
        v, z = make_patch.build(self.src, self.out, "n", kp)
        self.assertEqual(v, "9.9.3")
        base = os.path.join(self.out, "og-patch-9.9.3")
        man, sig = open(base + ".json", "rb").read(), open(base + ".sig", "rb").read()
        m = overlay.verify_signed(man, sig)
        self.assertEqual(m["version"], "9.9.3")
        self.assertEqual(set(m["files"]), {"VERSION", "a.py"})
        with zipfile.ZipFile(z) as zf:
            self.assertEqual(set(zf.namelist()), {"VERSION", "a.py"})
        with self.assertRaises(ValueError):
            overlay.verify_signed(man + b" ", sig)         # tampered manifest

    def test_unencrypted_key(self):
        self.check_round_trip(self.keyfile())

    def test_encrypted_key_via_env(self):
        with mock.patch.dict(os.environ, {"OG_SIGNING_PASSPHRASE": "throwaway-pass-123"}):
            self.check_round_trip(self.keyfile("throwaway-pass-123"))

    def test_unencrypted_key_with_env_passphrase_set(self):
        with mock.patch.dict(os.environ, {"OG_SIGNING_PASSPHRASE": "unused"}), \
                mock.patch.object(make_patch.getpass, "getpass", side_effect=AssertionError("prompted")):
            self.check_round_trip(self.keyfile())

    def test_wrong_key_signature_rejected(self):
        make_patch.build(self.src, self.out, "n", self.keyfile())
        other = Ed25519PrivateKey.generate().sign(b"x").hex().encode()
        base = os.path.join(self.out, "og-patch-9.9.3")
        with self.assertRaises(ValueError):
            overlay.verify_signed(open(base + ".json", "rb").read(), other)

    def test_refuses_symlink_and_bad_version(self):
        os.symlink("a.py", os.path.join(self.src, "l.py"))
        with self.assertRaises(SystemExit):
            make_patch.build(self.src, self.out, "n", self.keyfile())
        os.unlink(os.path.join(self.src, "l.py"))
        with open(os.path.join(self.src, "VERSION"), "w") as f:
            f.write("9.9.0\n")
        with self.assertRaises(SystemExit):
            make_patch.build(self.src, self.out, "n", self.keyfile())

    def test_build_app_requires_name_and_signs(self):
        bad = os.path.join(self.tmp.name, "x.zip")
        open(bad, "wb").close()
        with self.assertRaises(SystemExit):
            make_patch.build_app(bad, self.out, "n", self.keyfile())
        z = os.path.join(self.tmp.name, "OpenGenerator-9.9.1-app.zip")
        with open(z, "wb") as f:
            f.write(b"zip")
        self.assertEqual(make_patch.build_app(z, self.out, "n", self.keyfile()), "9.9.1")
        base = os.path.join(self.out, "og-app-9.9.1")
        m = overlay.verify_signed(open(base + ".json", "rb").read(), open(base + ".sig", "rb").read())
        self.assertEqual(m["kind"], "app")


if __name__ == "__main__":
    unittest.main()
