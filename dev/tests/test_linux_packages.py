"""The pure parts of the Linux L4 packages (.deb, .rpm, AppImage) in tools/linux_pkg.py, and a syntax check of the scripts.
The container builds and installs are not part of this gate; they are packaging/linux/package.sh and verify-packages.sh."""
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(os.path.dirname(DEV), "packaging", "linux")
sys.path.insert(0, os.path.join(DEV, "tools"))
import linux_pkg  # noqa: E402 - sys.path is set up first

V, ARCH = "6.0.0", "aarch64"
TOP = "apophis-%s-linux-%s" % (V, ARCH)
FILES = {   # path below the top directory -> (content, mode as PyInstaller/umask might leave it)
    "apophis": (b"#!/bin/sh\n", 0o775),
    "app/apophis-server": (b"elf", 0o777),
    "app/_internal/VERSION": (V.encode() + b"\n", 0o664),
    "app/_internal/libx.so": (b"lib", 0o666),
    "share/apophis.desktop": (b"[Desktop Entry]\nExec=apophis\n", 0o664),
    "share/apophis.png": (b"png", 0o644),
    "LICENSE": (b"licence", 0o644),
    "NOTICE": (b"notice", 0o644),
    "VERSION": (V.encode() + b"\n", 0o644),
}


def make_tarball(directory, files=FILES, extra=()):
    path = os.path.join(directory, TOP + ".tar.gz")
    with tarfile.open(path, "w:gz") as t:
        d = tarfile.TarInfo(TOP)
        d.type, d.mode = tarfile.DIRTYPE, 0o777
        t.addfile(d)
        made = set()
        for rel, (data, mode) in files.items():
            parent = os.path.dirname(rel)
            while parent and parent not in made:
                di = tarfile.TarInfo(TOP + "/" + parent)
                di.type, di.mode = tarfile.DIRTYPE, 0o775
                t.addfile(di)
                made.add(parent)
                parent = os.path.dirname(parent)
            ti = tarfile.TarInfo(TOP + "/" + rel)
            ti.size, ti.mode = len(data), mode
            t.addfile(ti, io.BytesIO(data))
        for ti in extra:
            t.addfile(ti)
    return path


class Naming(unittest.TestCase):
    def test_names(self):
        self.assertEqual(linux_pkg.deb_name("6.0.0", "aarch64"), "apophis_6.0.0_arm64.deb")
        self.assertEqual(linux_pkg.deb_name("6.0.0", "x86_64"), "apophis_6.0.0_amd64.deb")
        self.assertEqual(linux_pkg.rpm_name("6.0.0", "x86_64"), "apophis-6.0.0-1.x86_64.rpm")
        self.assertEqual(linux_pkg.appimage_name("6.0.0", "arm64"), "apophis-6.0.0-aarch64.AppImage")
        self.assertEqual(linux_pkg.parse_tarball_name("/x/" + TOP + ".tar.gz"), (V, ARCH))
        with self.assertRaises(ValueError):
            linux_pkg.parse_tarball_name("apophis-6.0.0-linux-mips.tar.gz")

    def test_prerelease_sorts_before_release(self):
        self.assertEqual(linux_pkg.deb_version("6.0.0rc1"), "6.0.0~rc1")
        self.assertEqual(linux_pkg.rpm_version_release("6.0.0rc1"), ("6.0.0", "0.rc1"))
        self.assertEqual(linux_pkg.rpm_version_release("6.0.0"), ("6.0.0", "1"))

    def test_modes(self):
        self.assertEqual([linux_pkg.norm_mode(m) for m in (0o777, 0o775, 0o666, 0o664, 0o644, 0o4755)], [0o755, 0o755, 0o644, 0o644, 0o644, 0o755])
        self.assertEqual(linux_pkg.norm_mode(0o700, is_dir=True), 0o755)


class Layout(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.tb = make_tarball(self.tmp)

    def _tb(self, **kw):
        return make_tarball(tempfile.mkdtemp(dir=self.tmp), **kw)

    def test_install_tree_paths_and_modes(self):
        root = os.path.join(self.tmp, "root")
        self.assertEqual(linux_pkg.build_root(self.tb, root), (V, ARCH))
        tree = {rel: mode & 0o7777 for rel, mode in linux_pkg.walk_tree(root)}
        self.assertEqual(tree["usr/bin/apophis"], 0o755)
        self.assertEqual(tree["usr/lib/apophis/apophis-server"], 0o755)
        self.assertEqual(tree["usr/lib/apophis/_internal/libx.so"], 0o644)     # 666 in the tarball: write bits stripped
        self.assertEqual(tree["usr/share/doc/apophis/NOTICE"], 0o644)
        self.assertEqual(tree["usr/lib/apophis"], 0o755)
        self.assertEqual(linux_pkg.tree_problems(root), [])
        self.assertFalse(os.path.exists(os.path.join(root, "VERSION")))

    def test_world_writable_is_a_problem(self):
        root = os.path.join(self.tmp, "r")
        linux_pkg.build_root(self.tb, root)
        os.chmod(os.path.join(root, "usr/bin/apophis"), 0o4777)
        self.assertEqual(len(linux_pkg.tree_problems(root)), 1)

    def test_bundle_version_must_match(self):
        tb = self._tb(files={**FILES, "app/_internal/VERSION": (b"1.2.3\n", 0o644)})
        with self.assertRaisesRegex(ValueError, "VERSION"):
            linux_pkg.build_root(tb, os.path.join(self.tmp, "x"))

    def test_hostile_tarballs_are_refused(self):
        def link(target, hard=False):
            ti = tarfile.TarInfo(TOP + "/app/evil")
            ti.type, ti.linkname = (tarfile.LNKTYPE if hard else tarfile.SYMTYPE), target
            return ti
        for bad in (link("/etc/passwd"), link("../../../../etc"), link("x", hard=True)):
            with self.assertRaises(ValueError, msg=bad.linkname):
                linux_pkg.build_root(self._tb(extra=[bad]), os.path.join(self.tmp, "h"))
        with self.assertRaises(ValueError):    # unknown top-level entry
            linux_pkg.build_root(self._tb(files={**FILES, "surprise": (b"x", 0o644)}), os.path.join(self.tmp, "u"))

    def test_internal_relative_symlink_is_kept(self):
        ti = tarfile.TarInfo(TOP + "/app/_internal/liby.so")
        ti.type, ti.linkname = tarfile.SYMTYPE, "libx.so"
        root = os.path.join(self.tmp, "s")
        linux_pkg.build_root(self._tb(extra=[ti]), root)
        self.assertEqual(os.readlink(os.path.join(root, "usr/lib/apophis/_internal/liby.so")), "libx.so")

    def test_appdir(self):
        d = os.path.join(self.tmp, "AppDir")
        linux_pkg.build_appdir(self.tb, d)
        self.assertEqual(os.readlink(os.path.join(d, "AppRun")), "apophis")      # the launcher resolves symlinks itself
        self.assertEqual(os.readlink(os.path.join(d, ".DirIcon")), "apophis.png")
        for f in ("apophis.desktop", "apophis.png", "app/apophis-server", "share/apophis.png"):
            self.assertTrue(os.path.isfile(os.path.join(d, f)), f)
        self.assertEqual(linux_pkg.tree_problems(d), [])


class Deb(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.tb = make_tarball(self.tmp)

    def _build(self, name):
        out = os.path.join(self.tmp, name)
        os.makedirs(out)
        return linux_pkg.make_deb(self.tb, out)

    def test_structure_ownership_and_control(self):
        path = self._build("o")
        self.assertEqual(os.path.basename(path), "apophis_6.0.0_arm64.deb")
        members, control, entries = linux_pkg.read_deb(path)
        self.assertEqual(list(members), ["debian-binary", "control.tar.gz", "data.tar.gz"])
        self.assertEqual(members["debian-binary"], b"2.0\n")
        for line in ("Package: apophis", "Version: 6.0.0", "Architecture: arm64", "Recommends: tcpreplay", "Depends: libc6 (>= 2.34)"):
            self.assertIn(line, control.splitlines())
        self.assertEqual({(uid, gid) for _, _, uid, gid, *_ in entries}, {(0, 0)})
        modes = {e[0]: e[1] for e in entries}
        self.assertEqual(modes["./usr/bin/apophis"], 0o755)
        self.assertEqual(modes["./usr/lib/apophis/_internal/libx.so"], 0o644)
        self.assertFalse([n for n, m in modes.items() if m & 0o022], "group/world-writable member in the deb")

    def test_reproducible(self):
        a, b = self._build("a"), self._build("b")
        self.assertEqual(linux_pkg.sha256_file(a), linux_pkg.sha256_file(b))

    def test_md5sums_cover_every_file(self):
        members, _, entries = linux_pkg.read_deb(self._build("m"))
        text = tarfile.open(fileobj=io.BytesIO(members["control.tar.gz"])).extractfile("./md5sums").read().decode()
        listed = {ln.split("  ", 1)[1] for ln in text.splitlines()}
        self.assertEqual(listed, {n[2:] for n, _, _, _, _, t in entries if t == tarfile.REGTYPE})


class Spec(unittest.TestCase):
    def test_spec(self):
        spec = linux_pkg.rpm_spec("/x/" + TOP + ".tar.gz", "/stage")
        for line in ("Name: apophis", "Version: 6.0.0", "Release: 1", "BuildArch: aarch64", "Recommends: tcpreplay",
                     "AutoReqProv: no", "Requires: glibc >= 2.34", "%defattr(-,root,root,-)", "cp -a /stage/. %{buildroot}/"):
            self.assertIn(line, spec.splitlines())

    def test_files_section_names_only_installed_paths(self):
        spec = linux_pkg.rpm_spec("/x/" + TOP + ".tar.gz", "/stage")
        files = spec.split("%files\n", 1)[1].splitlines()[1:]
        with tempfile.TemporaryDirectory() as tmp:
            linux_pkg.build_root(make_tarball(tmp), os.path.join(tmp, "root"))
            for f in files:
                self.assertTrue(os.path.lexists(os.path.join(tmp, "root", f.lstrip("/"))), f)


class Scripts(unittest.TestCase):
    def test_shell_syntax_and_neutrality(self):
        for name in ("package.sh", "pkg.sh", "verify-packages.sh", "verify-appimage.sh"):
            path = os.path.join(PKG, name)
            subprocess.run(["sh", "-n", path], check=True)
            with open(path, encoding="utf-8") as fh:
                self.assertNotIn("/" + "Users" + "/", fh.read(), name)

    def test_docker_recipe_documents_unsupported_replay(self):
        with open(os.path.join(PKG, "Dockerfile.app"), encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("UNSUPPORTED", text)
        self.assertIn("--no-install-recommends", text)     # tcpreplay is not pulled in
        self.assertRegex(text, r"(?m)^FROM ubuntu@sha256:[0-9a-f]{64}$")


class ProofRestamp(unittest.TestCase):
    def test_long_names_follow_the_new_top_folder(self):
        # a path over 100 bytes is stored in a pax header, which wins over the member name when written: restamp must move it too
        import importlib.machinery
        import importlib.util
        loader = importlib.machinery.SourceFileLoader("og_proof_linux", os.path.join(PKG, "og-proof-linux"))
        proof = importlib.util.module_from_spec(importlib.util.spec_from_loader("og_proof_linux", loader))
        loader.exec_module(proof)
        old = "apophis-5.9.9-linux-aarch64"
        long_rel = "app/_internal/" + "d" * 60 + "/" + "f" * 60 + ".json"
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, old + ".tar.gz")
            with tarfile.open(src, "w:gz", format=tarfile.PAX_FORMAT) as t:
                d = tarfile.TarInfo(old)
                d.type = tarfile.DIRTYPE
                t.addfile(d)
                ti = tarfile.TarInfo(old + "/" + long_rel)
                ti.size = 1
                t.addfile(ti, io.BytesIO(b"x"))
            out = proof.restamp(src, tmp, "aarch64", "5.9.9")
            with tarfile.open(out) as t:
                names = [m.name for m in t.getmembers()]
        self.assertEqual(names, ["apophis-6.0.0-linux-aarch64", "apophis-6.0.0-linux-aarch64/" + long_rel])


if __name__ == "__main__":
    unittest.main()
