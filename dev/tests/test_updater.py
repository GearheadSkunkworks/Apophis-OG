"""Patch updates: check, signature and checksum, safe unpack, install swap, overlay loading and the crash fallback."""
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "tools"))
import make_patch  # noqa: E402
import overlay  # noqa: E402,F401
import updater  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def release_list(*tags, assets=True):
    out = []
    for t in tags:
        v = t[1:]
        names = ["og-patch-%s.%s" % (v, x) for x in ("json", "sig", "zip")] if assets else []
        out.append({"tag_name": t, "body": "notes " + t, "assets": [{"name": n, "browser_download_url": "https://x/" + n} for n in names]})
    return json.dumps(out).encode()


class Env(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.key = Ed25519PrivateKey.generate()
        self.keyfile = os.path.join(self.tmp, "k.pem")
        with open(self.keyfile, "wb") as f:
            f.write(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        old = overlay.PUBLIC_KEY
        overlay.PUBLIC_KEY = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.addCleanup(setattr, overlay, "PUBLIC_KEY", old)
        self.src = os.path.join(self.tmp, "src")                    # a pretend release/ tree at 5.2.3
        os.makedirs(os.path.join(self.src, "ui"))
        os.makedirs(os.path.join(self.src, "tests"))
        for rel, body in {"VERSION": "5.2.3", "server.py": "print('patched')\n", "ui/index.html": "<html>", "probe.py": "WHERE='overlay'\n", "tests/t.py": "x", "README.md": "r"}.items():
            with open(os.path.join(self.src, rel), "w") as f:
                f.write(body)
        self.out = os.path.join(self.tmp, "out")
        make_patch.build(self.src, self.out, "fixes", self.keyfile)
        self.files = {}
        for n in os.listdir(self.out):
            with open(os.path.join(self.out, n), "rb") as f:
                self.files[n] = f.read()
        self.app = os.path.join(self.tmp, "app")                    # the installed bundle at 5.2.2
        os.makedirs(self.app)
        with open(os.path.join(self.app, "VERSION"), "w") as f:
            f.write("5.2.2")
        self.base = os.path.join(self.tmp, "overlay")

    def get(self, listing=None, tamper=None):
        def g(url, cap):
            if "releases" in url:
                return listing or release_list("v5.2.3")
            name = url.rsplit("/", 1)[1]
            data = self.files[name]
            return tamper(name, data) if tamper else data
        return g

    def info(self, **kw):
        return updater.check("5.2.2", self.get(**kw))


class Check(Env):
    def test_states(self):
        self.assertEqual(self.info()["state"], "patch")
        self.assertEqual(self.info()["latest"], "5.2.3")
        src2 = os.path.join(self.tmp, "src2")                          # a signed 5.2.4 as well: the highest patch on the line wins
        shutil.copytree(self.src, src2)
        with open(os.path.join(src2, "VERSION"), "w") as f:
            f.write("5.2.4")
        make_patch.build(src2, os.path.join(self.tmp, "out2"), "newer", self.keyfile)
        for n in os.listdir(os.path.join(self.tmp, "out2")):
            with open(os.path.join(self.tmp, "out2", n), "rb") as f:
                self.files[n] = f.read()
        self.assertEqual(self.info(listing=release_list("v5.2.3", "v5.2.4"))["latest"], "5.2.4")
        self.assertEqual(updater.check("5.2.3", self.get())["state"], "current")
        self.assertEqual(updater.check("5.2.2", self.get(listing=release_list("v5.3.0")))["state"], "newer")
        self.assertEqual(updater.check("5.2.2", self.get(listing=release_list("v5.2.3", assets=False)))["state"], "current")   # no assets, no offer
        self.assertEqual(updater.check("5.2.2", self.get(listing=b"not json"))["state"], "error")

    def test_patch_on_other_line_not_offered(self):
        self.assertEqual(updater.check("5.1.0", self.get())["state"], "newer")


class Install(Env):
    def test_installs(self):
        v = updater.install(self.info(), self.app, base=self.base, get=self.get())
        self.assertEqual(v, "5.2.3")
        self.assertTrue(os.path.isfile(os.path.join(self.base, "current", "server.py")))
        self.assertFalse(os.path.exists(os.path.join(self.base, "current", "tests")))

    def test_second_patch_keeps_previous(self):
        updater.install(self.info(), self.app, base=self.base, get=self.get())
        os.makedirs(os.path.join(self.base, "new"), exist_ok=True)
        updater.install(self.info(), self.app, base=self.base, get=self.get())
        self.assertTrue(os.path.isdir(os.path.join(self.base, "previous")))

    def test_bad_signature_and_tamper_change_nothing(self):
        for tamper in (lambda n, d: d.replace(b"fixes", b"evil") if n.endswith(".json") else d,
                       lambda n, d: d + b"x" if n.endswith(".zip") else d,
                       lambda n, d: ("00" * 64 + "\n").encode() if n.endswith(".sig") else d):
            with self.assertRaises(updater.UpdateError):
                updater.install(self.info(), self.app, base=self.base, get=self.get(tamper=tamper))
            self.assertFalse(os.path.exists(os.path.join(self.base, "current")))

    def test_wrong_line_refused(self):
        with open(os.path.join(self.app, "VERSION"), "w") as f:
            f.write("5.3.0")
        with self.assertRaises(updater.UpdateError):
            updater.install(self.info(), self.app, base=self.base, get=self.get())

    def test_unsafe_zip_refused(self):
        for name in ("../evil.py", "/abs.py"):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as z:
                z.writestr(name, "x")
            with self.assertRaises(updater.UpdateError):
                updater.unpack(buf.getvalue(), self.tmp + "/dest")

    def test_symlink_entry_refused(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            info = zipfile.ZipInfo("link")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, "/etc/hosts")
        with self.assertRaises(updater.UpdateError):
            updater.unpack(buf.getvalue(), self.tmp + "/dest")

    def test_source_run_refused(self):
        with self.assertRaises(updater.UpdateError):
            updater.install(self.info(), self.app, get=self.get())

    def test_route_needs_a_check_and_respects_busy(self):
        updater._LAST.clear()
        self.assertEqual(updater.route_post("/api/update/install", self.app, lambda: "")[0], 409)
        updater._LAST.update(self.info())
        self.assertEqual(updater.route_post("/api/update/install", self.app, lambda: "a capture is being generated")[0], 409)
        updater._LAST.clear()


class OverlayLoad(Env):
    def run_py(self, code):
        code = "import overlay; overlay.PUBLIC_KEY = %r\n%s" % (overlay.PUBLIC_KEY, code)     # the test key stands in for the built-in one
        return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=DEV))

    def install_patch(self):
        updater.install(self.info(), self.app, base=self.base, get=self.get())

    def test_overlay_wins_then_crash_marker_disables_it(self):
        self.install_patch()
        with open(os.path.join(self.app, "probe.py"), "w") as f:
            f.write("WHERE='bundle'\n")
        code = ("import sys, overlay; sys.path.append(%r); r = overlay.activate(%r, base=%r, frozen=True); import probe; print(r, probe.WHERE)"
                % (self.app, self.app, self.base))
        r = self.run_py(code)
        self.assertEqual(r.stdout.split()[1], "overlay", r.stderr)
        self.assertTrue(os.path.exists(os.path.join(self.base, ".booting")))     # start never confirmed
        r = self.run_py(code)                                                      # so the next start sets it aside
        self.assertEqual(r.stdout.split()[1], "bundle", r.stderr)
        self.assertTrue(os.path.isdir(os.path.join(self.base, "bad")))
        self.assertFalse(os.path.isdir(os.path.join(self.base, "current")))

    def test_confirmed_start_keeps_overlay(self):
        self.install_patch()
        self.run_py("import overlay; overlay.activate(%r, base=%r, frozen=True); overlay.confirm_boot()" % (self.app, self.base))
        self.assertTrue(os.path.isdir(os.path.join(self.base, "current")))
        self.assertFalse(os.path.exists(os.path.join(self.base, ".booting")))

    def test_overlay_for_another_line_ignored(self):
        self.install_patch()
        with open(os.path.join(self.app, "VERSION"), "w") as f:
            f.write("5.3.0")
        r = self.run_py("import overlay; print(overlay.activate(%r, base=%r, frozen=True))" % (self.app, self.base))
        self.assertEqual(r.stdout.strip(), self.app)

    def test_inactive_when_not_frozen(self):
        self.install_patch()
        r = self.run_py("import overlay; print(overlay.activate(%r, base=%r, frozen=False))" % (self.app, self.base))
        self.assertEqual(r.stdout.strip(), self.app)


class Hardening(Env):
    def test_url_rule_uses_the_parsed_host(self):
        for ok in ("https://api.github.com/repos/x/y/releases", "https://github.com/x/y/releases/download/v1/a.zip",
                   "https://objects.githubusercontent.com/abc", "http://127.0.0.1:8799/a.json"):
            self.assertTrue(updater.allowed_url(ok), ok)
        for bad in ("http://127.0.0.1.evil.example/a", "https://evil.example/a", "https://github.com.evil.example/a",
                    "http://api.github.com/a", "ftp://github.com/a", "https://127.0.0.1@evil.example/a", "file:///etc/passwd"):
            self.assertFalse(updater.allowed_url(bad), bad)

    def test_notes_come_from_the_signed_manifest_not_the_release_body(self):
        self.assertEqual(self.info()["notes"], "fixes")              # the release body said "notes v5.2.3"

    def test_unsigned_or_mismatched_details_are_not_offered(self):
        r = self.info(tamper=lambda n, d: d.replace(b"fixes", b"evil") if n.endswith(".json") else d)
        self.assertEqual(r["state"], "error")

    def test_manifest_lists_every_file_and_the_tree_is_checked_at_install(self):
        m = json.loads(self.files["og-patch-5.2.3.json"])
        self.assertEqual(sorted(m["files"]), ["VERSION", "probe.py", "server.py", "ui/index.html"])
        buf = io.BytesIO()                                                  # a zip whose server.py differs from the signed list...
        with zipfile.ZipFile(io.BytesIO(self.files["og-patch-5.2.3.zip"])) as z, zipfile.ZipFile(buf, "w") as o:
            for i in z.namelist():
                o.writestr(i, z.read(i) + (b"#x" if i == "server.py" else b""))
        manifest = json.dumps(dict(m, sha256=hashlib.sha256(buf.getvalue()).hexdigest())).encode()   # ...with a manifest that is validly signed for it
        self.files.update({"og-patch-5.2.3.zip": buf.getvalue(), "og-patch-5.2.3.json": manifest,
                           "og-patch-5.2.3.sig": (self.key.sign(manifest).hex() + "\n").encode()})
        with self.assertRaises(updater.UpdateError) as cm:
            updater.install(self.info(), self.app, base=self.base, get=self.get())
        self.assertIn("signed list", str(cm.exception))
        self.assertFalse(os.path.exists(os.path.join(self.base, "current")))


class OverlayVerify(OverlayLoad):
    def activate(self):
        return self.run_py("import overlay; r = overlay.activate(%r, base=%r, frozen=True); overlay.confirm_boot(); print(r)" % (self.app, self.base))

    def test_untouched_install_loads(self):
        self.install_patch()
        self.assertEqual(self.activate().stdout.strip(), os.path.join(self.base, "current"))

    def test_changed_file_extra_file_or_missing_signature_are_set_aside(self):
        for damage in ("change", "extra", "nosig"):
            shutil.rmtree(self.base, ignore_errors=True)
            self.install_patch()
            cur = os.path.join(self.base, "current")
            if damage == "change":
                with open(os.path.join(cur, "server.py"), "a") as f:
                    f.write("# planted\n")
            elif damage == "extra":
                with open(os.path.join(cur, "evil.py"), "w") as f:
                    f.write("x=1\n")
            else:
                os.remove(os.path.join(cur, ".patch.sig"))
            self.assertEqual(self.activate().stdout.strip(), self.app, damage)
            self.assertTrue(os.path.isdir(os.path.join(self.base, "bad")), damage)

    def test_a_higher_version_planted_without_a_signature_is_refused(self):
        os.makedirs(os.path.join(self.base, "current"))
        for rel, body in {"VERSION": "5.2.9", "server.py": "x"}.items():
            with open(os.path.join(self.base, "current", rel), "w") as f:
                f.write(body)
        self.assertEqual(self.activate().stdout.strip(), self.app)


class Network(unittest.TestCase):
    def test_accept_header_suits_the_endpoint(self):
        self.assertEqual(updater._accept("https://api.github.com/repos/x/y/releases?per_page=30"), "application/vnd.github+json")
        self.assertEqual(updater._accept("https://github.com/x/y/releases/download/v1/a.zip"), "*/*")
        self.assertEqual(updater._accept("http://127.0.0.1:8799/a.json"), "*/*")

    def test_the_opener_verifies_https_with_the_feed_fetchers_certificate_bundle(self):
        import urllib.request
        handlers = [h for h in updater._opener().handlers if isinstance(h, urllib.request.HTTPSHandler)]
        self.assertTrue(handlers)
        self.assertGreater(handlers[0]._context.cert_store_stats().get("x509_ca", 0), 0)      # certificates are really loaded


class PatchSource(Env):
    def test_symlink_refused(self):
        os.symlink("/etc/hosts", os.path.join(self.src, "link.txt"))
        with self.assertRaises(SystemExit):
            make_patch.build(self.src, self.out, "n", self.keyfile)

    def test_release_build_needs_the_promote_manifest_and_matching_files(self):
        with self.assertRaises(SystemExit):
            make_patch.build(self.src, self.out, "n", self.keyfile, require_manifest=True)
        lines = []
        for rel in make_patch.tree_files(self.src):
            with open(os.path.join(self.src, rel), "rb") as f:
                lines.append("%s  %s" % (hashlib.sha256(f.read()).hexdigest(), rel))
        with open(os.path.join(self.src, "MANIFEST.sha256"), "w") as f:
            f.write("\n".join(lines) + "\n")
        make_patch.build(self.src, self.out, "n", self.keyfile, require_manifest=True)       # matches: fine
        with open(os.path.join(self.src, "server.py"), "a") as f:
            f.write("# changed after promote\n")
        with self.assertRaises(SystemExit):
            make_patch.build(self.src, self.out, "n", self.keyfile, require_manifest=True)

    def test_protected_key_needs_its_passphrase(self):
        enc = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"correct horse"))
        p = os.path.join(self.tmp, "enc.pem")
        with open(p, "wb") as f:
            f.write(enc)
        os.environ["OG_SIGNING_PASSPHRASE"] = "correct horse"
        self.addCleanup(os.environ.pop, "OG_SIGNING_PASSPHRASE", None)
        v, _ = make_patch.build(self.src, self.out, "n", p)
        self.assertEqual(v, "5.2.3")


class PatchBuilder(Env):
    def test_zip_contents_and_manifest(self):
        names = zipfile.ZipFile(os.path.join(self.out, "og-patch-5.2.3.zip")).namelist()
        self.assertEqual(sorted(names), ["VERSION", "probe.py", "server.py", "ui/index.html"])
        m = json.loads(self.files["og-patch-5.2.3.json"])
        self.assertEqual((m["product"], m["base"], m["version"]), ("opengenerator", "5.2", "5.2.3"))

    def test_x_y_0_is_not_a_patch(self):
        with open(os.path.join(self.src, "VERSION"), "w") as f:
            f.write("5.3.0")
        with self.assertRaises(SystemExit):
            make_patch.build(self.src, self.out, "n", self.keyfile)


if __name__ == "__main__":
    unittest.main()
