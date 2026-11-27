"""The pure parts of the Linux release path (tools/linux_release.py): the asset-name set, the one SHA256SUMS, and tamper detection.
The container builds are packaging/linux/release-linux.sh and are not part of this gate."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(os.path.dirname(DEV), "packaging", "linux")
sys.path.insert(0, os.path.join(DEV, "tools"))
import linux_release as lr  # noqa: E402 - sys.path is set up first

V = "6.0.0"
EXPECTED = [
    "apophis-6.0.0-aarch64.AppImage", "apophis-6.0.0-1.aarch64.rpm", "apophis-6.0.0-linux-aarch64.tar.gz", "apophis_6.0.0_arm64.deb",
    "apophis-6.0.0-x86_64.AppImage", "apophis-6.0.0-1.x86_64.rpm", "apophis-6.0.0-linux-x86_64.tar.gz", "apophis_6.0.0_amd64.deb",
]


def fake_build(tmp):
    for a, deb in (("x86_64", "amd64"), ("aarch64", "arm64")):
        d = os.path.join(tmp, "build", a, "artifacts")
        os.makedirs(d)
        for n in lr.asset_names(V):
            if a in n or deb in n:
                with open(os.path.join(d, n), "wb") as fh:
                    fh.write(("data " + n).encode())
    return os.path.join(tmp, "build")


def sign_all(case, out, version=V, digest=None):
    """Write all four signed manifests with a throwaway key whose public half replaces the app's for this process."""
    sys.path.insert(0, DEV)
    import overlay
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    case.addCleanup(setattr, overlay, "PUBLIC_KEY", overlay.PUBLIC_KEY)     # later tests in this process need the real key
    overlay.PUBLIC_KEY = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    with open(os.path.join(out, "SHA256SUMS"), encoding="utf-8") as fh:
        listed = dict(ln[66:].strip() and (ln[66:], ln[:64]) for ln in fh.read().splitlines())
    for a in ("x86_64", "aarch64"):
        tb = "apophis-%s-linux-%s.tar.gz" % (V, a)
        body = json.dumps({"product": "opengenerator", "kind": "app", "platform": "linux", "arch": a, "version": version,
                           "tarball": {"name": tb, "sha256": digest or listed[tb]}}).encode()
        stem = os.path.join(out, "og-app-%s-linux-%s" % (V, a))
        with open(stem + ".json", "wb") as fh:
            fh.write(body)
        with open(stem + ".sig", "w") as fh:
            fh.write(key.sign(body).hex())


class Names(unittest.TestCase):
    def test_asset_set(self):
        self.assertEqual(lr.asset_names(V), sorted(EXPECTED))

    def test_prerelease_names_follow_the_package_rules(self):
        names = lr.asset_names("6.0.0rc1")
        self.assertIn("apophis_6.0.0~rc1_amd64.deb", names)
        self.assertIn("apophis-6.0.0-0.rc1.x86_64.rpm", names)

    def test_signed_names_match_the_updater(self):
        sys.path.insert(0, DEV)
        import updater_linux
        want = sorted(n for a in ("x86_64", "aarch64") for n in updater_linux.names(V, a))
        self.assertEqual(lr.signed_names(V), want)


class Sums(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = os.path.join(self.tmp.name, "out")
        lr.collect(fake_build(self.tmp.name), V, self.out)

    def test_one_sums_file_in_sha256sum_format_over_all_assets(self):
        with open(os.path.join(self.out, "SHA256SUMS"), encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        self.assertEqual([ln[66:] for ln in lines], sorted(EXPECTED))
        self.assertTrue(all(ln[64:66] == "  " for ln in lines))
        self.assertEqual(lr.verify(self.out, V), [])

    def test_flipped_byte_is_caught(self):
        p = os.path.join(self.out, "apophis-6.0.0-linux-x86_64.tar.gz")
        with open(p, "rb") as fh:
            data = bytearray(fh.read())
        data[0] ^= 1
        with open(p, "wb") as fh:
            fh.write(bytes(data))
        self.assertEqual(lr.verify(self.out, V), ["apophis-6.0.0-linux-x86_64.tar.gz: checksum mismatch"])

    def test_missing_and_extra_files_are_caught(self):
        os.remove(os.path.join(self.out, "apophis_6.0.0_arm64.deb"))
        open(os.path.join(self.out, "stray.txt"), "w").close()
        bad = lr.verify(self.out, V)
        self.assertIn("apophis_6.0.0_arm64.deb: missing", bad)
        self.assertIn("stray.txt: unexpected file", bad)

    def test_signed_manifests_are_optional_until_asked_for(self):
        self.assertEqual(lr.verify(self.out, V), [])
        self.assertEqual(len(lr.verify(self.out, V, signed=True)), 4)
        sign_all(self, self.out)
        self.assertEqual(lr.verify(self.out, V, signed=True), [])
        self.assertEqual(len(lr.upload_files(self.out, V)), 8 + 1 + 4)

    def test_signed_means_the_signature_verifies_not_that_the_file_exists(self):       # S-J
        sign_all(self, self.out)
        j, s = ("og-app-%s-linux-x86_64.%s" % (V, e) for e in ("json", "sig"))
        with open(os.path.join(self.out, j), "ab") as fh:
            fh.write(b" ")                                      # the manifest changed after signing: a stale .sig beside a new .json
        bad = lr.verify(self.out, V, signed=True)
        self.assertEqual(len(bad), 1)
        self.assertIn("does not verify", bad[0])
        sign_all(self, self.out)
        with open(os.path.join(self.out, s), "w") as fh:
            fh.write("00" * 64)                                 # garbage signature of the right shape
        self.assertEqual(len(lr.verify(self.out, V, signed=True)), 1)
        sign_all(self, self.out, version="6.0.1")      # validly signed, but for another version
        self.assertTrue(any("not 6.0.0" in b for b in lr.verify(self.out, V, signed=True)))
        sign_all(self, self.out, digest="0" * 64)      # validly signed, but its digest is not the file we hold
        self.assertTrue(any("signed digest" in b for b in lr.verify(self.out, V, signed=True)))

    def test_collect_refuses_missing_asset_and_nonempty_out(self):
        os.remove(os.path.join(self.tmp.name, "build", "aarch64", "artifacts", "apophis_6.0.0_arm64.deb"))
        with self.assertRaises(ValueError):
            lr.collect(os.path.join(self.tmp.name, "build"), V, os.path.join(self.tmp.name, "out2"))
        with self.assertRaises(ValueError):
            lr.collect(os.path.join(self.tmp.name, "build"), V, self.out)


class Script(unittest.TestCase):
    def test_dry_run_lists_exactly_the_expected_names(self):
        r = subprocess.run(["sh", os.path.join(PKG, "release-linux.sh"), "plan"], capture_output=True, text=True, check=True)
        listed = [ln.strip() for ln in r.stdout.split("assets under SHA256SUMS:")[1].split("owner-signed")[0].splitlines() if ln.strip()]
        with open(os.path.join(DEV, "VERSION"), encoding="utf-8") as fh:
            self.assertEqual(listed, lr.asset_names(fh.read().strip()))

    def test_shell_syntax_and_neutrality(self):
        path = os.path.join(PKG, "release-linux.sh")
        subprocess.run(["sh", "-n", path], check=True)
        with open(path, encoding="utf-8") as fh:
            self.assertNotIn("/" + "Users" + "/", fh.read())


if __name__ == "__main__":
    unittest.main()
