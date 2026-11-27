"""Linux full-app update: install-kind decisions, signed manifest, tarball and AppImage swap, tamper and package refusals."""
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "tools"))
import make_patch  # noqa: E402 - path set up first
import overlay  # noqa: E402 - path set up first
import updater  # noqa: E402 - path set up first
import updater_linux as ul  # noqa: E402 - path set up first
from cryptography.hazmat.primitives import serialization  # noqa: E402 - path set up first
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402 - path set up first

ARCH = "x86_64"


def rd(path, mode="rb"):
    with open(path, mode) as f:
        return f.read()


def make_tarball(path, version, extra=None):
    top = "apophis-%s-linux-%s" % (version, ARCH)
    files = {"VERSION": version + "\n", "apophis": "#!/bin/sh\n", "app/apophis-server": "bin " + version, "app/_internal/lib.so": "lib"}
    files.update(extra or {})
    with tarfile.open(path, "w:gz") as t:
        for rel, body in files.items():
            ti = tarfile.TarInfo(top + "/" + rel)
            ti.size, ti.mode = len(body), 0o755 if rel in ("apophis", "app/apophis-server") else 0o644
            t.addfile(ti, io.BytesIO(body.encode()))
        ln = tarfile.TarInfo(top + "/app/_internal/lib.so.1")
        ln.type, ln.linkname = tarfile.SYMTYPE, "lib.so"
        t.addfile(ln)


class Decisions(unittest.TestCase):
    def test_install_kind(self):
        yes, no, isf = (lambda p: True), (lambda p: False), (lambda p: True)
        self.assertEqual(ul.install_kind("/home/u/apophis-5.9.0-linux-x86_64/app/apophis-server", "", yes, "", isf), "tarball")
        self.assertEqual(ul.install_kind("/home/u/apophis-5.9.0-linux-x86_64/app/apophis-server", "", no, "", isf), "readonly")
        self.assertEqual(ul.install_kind("/usr/lib/apophis/apophis-server", "", yes), "package")   # even if somehow writable: never touched
        self.assertEqual(ul.install_kind("/tmp/.mount_x/usr/bin/apophis-server", "/home/u/A.AppImage", yes, "/tmp/.mount_x"), "appimage")
        self.assertEqual(ul.install_kind("/tmp/.mount_x/usr/bin/apophis-server", "/opt/A.AppImage", no, "/tmp/.mount_x"), "readonly")
        self.assertIn("package manager", ul.refuse_text("package"))

    def test_leaked_appimage_env_does_not_make_an_appimage(self):       # S-D
        yes = lambda p: True  # noqa: E731 - a one-line stub
        isf = lambda p: True  # noqa: E731 - a one-line stub
        leak = dict(appimage="/home/u/Other.AppImage", appdir="/tmp/.mount_other")
        self.assertEqual(ul.install_kind("/usr/lib/apophis/apophis-server", writable=yes, **leak), "package")
        self.assertEqual(ul.install_kind("/home/u/apophis-6.0.0-linux-x86_64/app/apophis-server", writable=yes, isfile=isf, **leak), "tarball")
        self.assertEqual(ul.install_kind("/tmp/.mount_x/usr/bin/s", "/home/u/A.AppImage", yes, ""), "readonly")   # no APPDIR: not proven
        self.assertEqual(ul.own_appimage("/tmp/.mount_xy/s", "/h/A.AppImage", "/tmp/.mount_x"), "")             # prefix is not containment
        self.assertEqual(ul.restart_argv(["/h/bin"], ul.own_appimage("/h/bin", "/h/A.AppImage", "/tmp/.mount_x")), ["/h/bin"])

    def test_tarball_root_needs_the_app_layout(self):                  # S-K
        yes = lambda p: True  # noqa: E731 - a one-line stub
        dev_layout = "/home/u/dist/apophis-server/apophis-server"
        self.assertIsNone(ul.tarball_root(dev_layout, isfile=lambda p: False))
        self.assertEqual(ul.install_kind(dev_layout, "", yes, "", lambda p: False), "readonly")
        self.assertIsNone(ul.tarball_root("/home/u/top/app/apophis-server", isfile=lambda p: False))      # no launcher beside app/
        self.assertEqual(ul.tarball_root("/home/u/top/app/apophis-server", isfile=lambda p: True), "/home/u/top")

    def test_names_arch_restart(self):
        self.assertEqual(ul.names("6.0.0", "aarch64"), ("og-app-6.0.0-linux-aarch64.json", "og-app-6.0.0-linux-aarch64.sig"))
        self.assertEqual(ul.arch_of("arm64"), "aarch64")
        with self.assertRaises(ul.LinuxUpdateError):
            ul.arch_of("riscv64")
        self.assertEqual(ul.restart_argv(["/mnt/x/bin", "--a"], "/h/A.AppImage"), ["/h/A.AppImage", "--a"])
        self.assertEqual(ul.restart_argv(["/h/bin", "--a"], ""), ["/h/bin", "--a"])

    def test_pick_refuses_other_builds(self):
        m = {"kind": "app", "platform": "linux", "arch": ARCH, "version": "6.0.0", "tarball": {"name": "t", "sha256": "0" * 64}}
        self.assertEqual(ul.pick(m, "tarball", "6.0.0", ARCH)["name"], "t")
        for bad in (dict(m, arch="aarch64"), dict(m, platform="mac"), dict(m, kind="patch"), dict(m, version="6.0.1")):
            with self.assertRaises(ul.LinuxUpdateError):
                ul.pick(bad, "tarball", "6.0.0", ARCH)
        with self.assertRaises(ul.LinuxUpdateError):
            ul.pick(m, "appimage", "6.0.0", ARCH)                    # no AppImage in the manifest


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        key = Ed25519PrivateKey.generate()
        self.keyfile = os.path.join(self.tmp, "k.pem")
        with open(self.keyfile, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        old = overlay.PUBLIC_KEY
        overlay.PUBLIC_KEY = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.addCleanup(setattr, overlay, "PUBLIC_KEY", old)
        home = os.path.join(self.tmp, "home")                         # the installed (old) tarball tree, 5.9.0
        self.old_tb = os.path.join(self.tmp, "old.tar.gz")
        make_tarball(self.old_tb, "5.9.0")
        self.root = ul.extract_tarball(self.old_tb, home)
        self.exe = os.path.join(self.root, "app", "apophis-server")
        self.new_tb = os.path.join(self.tmp, "apophis-6.0.0-linux-%s.tar.gz" % ARCH)
        make_tarball(self.new_tb, "6.0.0")
        self.appimg = os.path.join(self.tmp, "apophis-6.0.0-%s.AppImage" % ARCH)
        with open(self.appimg, "wb") as f:
            f.write(b"new appimage")
        self.out = os.path.join(self.tmp, "out")
        make_patch.build_linux(self.new_tb, self.out, "notes", self.keyfile, self.appimg)
        self.files = {n: rd(os.path.join(self.out, n)) for n in os.listdir(self.out)}
        for p in (self.new_tb, self.appimg):
            self.files[os.path.basename(p)] = rd(p)
        self.app_dir = os.path.join(self.tmp, "cur")                  # what current_version() reads
        os.makedirs(self.app_dir)
        with open(os.path.join(self.app_dir, "VERSION"), "w") as f:
            f.write("5.9.0")
        self.keep = os.path.join(self.tmp, "app-previous")

    def get(self, tamper=None, listing=None):
        assets = [{"name": n, "browser_download_url": "https://x/" + n} for n in self.files]

        def g(url, cap):
            if "releases" in url:
                return listing or json.dumps([{"tag_name": "v6.0.0", "assets": assets}]).encode()
            name = url.rsplit("/", 1)[1]
            return tamper(name, self.files[name]) if tamper else self.files[name]
        return g

    def info(self, **kw):
        return updater.check("5.9.0", self.get(**kw), arch=ARCH)

    def go(self, exe=None, appimage="", tamper=None):
        return updater.install_app_linux(self.info(), self.app_dir, get=self.get(tamper=tamper), exe=exe or self.exe, appimage=appimage,
                                         appdir=self.tmp if appimage else "", arch=ARCH, keep=self.keep)

    def version_of_root(self):
        return rd(os.path.join(self.root, "VERSION"), "r").strip()


class Flow(Env):
    def test_check_offers_signed_linux_update(self):
        i = self.info()
        self.assertEqual((i["state"], i["latest"]), ("app", "6.0.0"))
        self.assertEqual(updater.check("5.9.0", self.get(), arch="aarch64")["state"], "newer")   # no aarch64 assets: pointed to the page only

    def test_tarball_swap_keeps_previous(self):
        self.assertEqual(self.go(), "6.0.0")
        self.assertEqual(self.version_of_root(), "6.0.0")
        self.assertTrue(os.access(self.exe, os.X_OK))
        self.assertTrue(os.path.islink(os.path.join(self.root, "app", "_internal", "lib.so.1")))
        kept = os.path.join(self.keep, os.path.basename(self.root) + ".old", "VERSION")
        self.assertEqual(rd(kept, "r").strip(), "5.9.0")
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.root))), [os.path.basename(self.root)])   # no work folder left

    def test_appimage_swap(self):
        img = os.path.join(self.tmp, "Apophis.AppImage")
        with open(img, "wb") as f:
            f.write(b"old appimage")
        self.go(appimage=img)
        self.assertEqual(rd(img), b"new appimage")
        self.assertTrue(os.access(img, os.X_OK))
        self.assertEqual(rd(os.path.join(self.keep, "Apophis.AppImage.old")), b"old appimage")

    def test_unsupported_machine_is_an_error_state_not_an_exception(self):    # S-K
        with mock.patch("platform.machine", return_value="riscv64"), mock.patch.object(updater.sys, "platform", "linux"):
            r = updater.check("5.9.0", self.get())
        self.assertEqual(r["state"], "error")
        self.assertIn("architecture", r["message"])

    def test_tamper_changes_nothing(self):
        before = self.version_of_root()
        def flip(n, d):
            return d + b"x" if n.endswith(".tar.gz") else d

        def sigbad(n, d):
            return ("00" * 64 + "\n").encode() if n.endswith(".sig") else d

        def manbad(n, d):
            return d.replace(b"notes", b"evil") if n.endswith(".json") else d
        for t in (flip, sigbad, manbad):
            with self.assertRaises(updater.UpdateError):
                self.go(tamper=t)
            self.assertEqual(self.version_of_root(), before)
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.root))), [os.path.basename(self.root)])
        self.assertFalse(os.path.exists(self.keep))

    def test_per_file_hash_mismatch_refused(self):
        """A tarball whose bytes match the signed sha256 but whose files do not match the signed file list (a mis-signed release)."""
        m = json.loads(self.files["og-app-6.0.0-linux-%s.json" % ARCH])
        m["tarball"]["files"]["app/apophis-server"] = "0" * 64
        raw = json.dumps(m).encode()
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        sig = load_pem_private_key(rd(self.keyfile), None).sign(raw).hex().encode()
        self.files["og-app-6.0.0-linux-%s.json" % ARCH], self.files["og-app-6.0.0-linux-%s.sig" % ARCH] = raw, sig
        with self.assertRaises(updater.UpdateError):
            self.go()
        self.assertEqual(self.version_of_root(), "5.9.0")

    def test_package_install_refused_without_touching(self):
        with self.assertRaises(updater.UpdateError) as c:
            updater.install_app_linux(self.info(), self.app_dir, get=self.get(), exe="/usr/lib/apophis/apophis-server", appimage="", arch=ARCH, keep=self.keep)
        self.assertIn("package manager", str(c.exception))
        self.assertEqual(self.version_of_root(), "5.9.0")

    def test_same_line_is_not_an_app_update(self):
        info = self.info()
        m = json.loads(self.files["og-app-6.0.0-linux-%s.json" % ARCH])
        self.assertEqual(m["platform"], "linux")
        with open(os.path.join(self.app_dir, "VERSION"), "w") as f:
            f.write("6.0.1")
        with self.assertRaises(updater.UpdateError):
            updater.install_app_linux(info, self.app_dir, get=self.get(), exe=self.exe, appimage="", arch=ARCH, keep=self.keep)


class Unsafe(unittest.TestCase):
    def test_extract_refuses_escapes(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for name, link in (("top/../evil", None), ("/abs", None), ("top/l", "/etc/passwd"), ("top/l", "../../out"), ("other/x", None)):
            p = os.path.join(d, "t.tar")
            with tarfile.open(p, "w") as t:
                ok = tarfile.TarInfo("top/ok")
                ok.size = 0
                t.addfile(ok)
                ti = tarfile.TarInfo(name)
                if link:
                    ti.type, ti.linkname = tarfile.SYMTYPE, link
                t.addfile(ti)
            with self.assertRaises(ul.LinuxUpdateError, msg=name):
                ul.extract_tarball(p, os.path.join(d, "dest"))
            shutil.rmtree(os.path.join(d, "dest"), ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
