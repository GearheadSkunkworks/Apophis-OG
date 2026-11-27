"""The pure helpers behind the Linux download artifacts (tools/linux_pkg.py) and the per-platform frozen-module lists.
The container build itself is not part of this gate; it is documented in packaging/linux/build.sh."""
import hashlib
import io
import os
import sys
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(DEV, "tools"))
import frozen_modules  # noqa: E402 - sys.path is set up first
import linux_pkg  # noqa: E402 - sys.path is set up first


def _write(d, name, data=b"x"):
    p = os.path.join(d, name)
    with open(p, "wb") as fh:
        fh.write(data)
    return p


class Naming(unittest.TestCase):
    def test_arch_spellings(self):
        for raw, want in (("x86_64", "x86_64"), ("amd64", "x86_64"), ("aarch64", "aarch64"), ("arm64", "aarch64"), (" ARM64\n", "aarch64")):
            self.assertEqual(linux_pkg.norm_arch(raw), want)
        for bad in ("i686", "armv7l", "", "riscv64"):
            with self.assertRaises(ValueError):
                linux_pkg.norm_arch(bad)

    def test_tarball_name(self):
        self.assertEqual(linux_pkg.tarball_name("6.0.0", "amd64"), "apophis-6.0.0-linux-x86_64.tar.gz")
        self.assertEqual(linux_pkg.tarball_name("6.0.1\n", "aarch64"), "apophis-6.0.1-linux-aarch64.tar.gz")
        self.assertEqual(linux_pkg.top_dir("6.0.0", "arm64"), "apophis-6.0.0-linux-aarch64")
        self.assertEqual(linux_pkg.tarball_name("6.0.0rc1", "x86_64"), "apophis-6.0.0rc1-linux-x86_64.tar.gz")

    def test_version_is_checked(self):
        for bad in ("", "latest", "6", "../6.0.0", "6.0.0 x", "v6.0.0"):
            with self.assertRaises(ValueError, msg=bad):
                linux_pkg.tarball_name(bad, "x86_64")


class Checksums(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        _write(self.d, "a.tar.gz", b"alpha")
        _write(self.d, "b.deb", b"beta")

    def tearDown(self):
        self.tmp.cleanup()

    def test_covers_every_artifact_in_sha256sum_format(self):
        text = linux_pkg.sums_text(self.d)
        self.assertEqual(text, "%s  a.tar.gz\n%s  b.deb\n" % (hashlib.sha256(b"alpha").hexdigest(), hashlib.sha256(b"beta").hexdigest()))
        self.assertEqual(linux_pkg.parse_sums(text), {"a.tar.gz": hashlib.sha256(b"alpha").hexdigest(),
                                                       "b.deb": hashlib.sha256(b"beta").hexdigest()})

    def test_written_file_excludes_itself_and_verifies(self):
        linux_pkg.write_sums(self.d)
        linux_pkg.write_sums(self.d)                     # idempotent: the checksum file never lists itself
        with open(os.path.join(self.d, linux_pkg.SUMS), encoding="utf-8") as fh:
            self.assertNotIn(linux_pkg.SUMS, linux_pkg.parse_sums(fh.read()))
        self.assertEqual(linux_pkg.verify_sums(self.d), [])

    def test_tamper_missing_and_extra_are_all_reported(self):
        linux_pkg.write_sums(self.d)
        _write(self.d, "a.tar.gz", b"tampered")
        os.remove(os.path.join(self.d, "b.deb"))
        _write(self.d, "c.rpm", b"unlisted")
        self.assertEqual(linux_pkg.verify_sums(self.d),
                         ["a.tar.gz: checksum mismatch", "b.deb: listed but missing", "c.rpm: present but not listed"])

    def test_malformed_lines_are_rejected(self):
        for bad in ("nothex  a\n", "%s a\n" % ("0" * 64), "%s  ../a\n" % ("0" * 64), "%s\n" % ("0" * 64)):
            with self.assertRaises(ValueError, msg=bad):
                linux_pkg.parse_sums(bad)
        self.assertEqual(linux_pkg.parse_sums("%s *bin\n\n" % ("a" * 64)), {"bin": "a" * 64})   # `sha256sum -b` form

    def test_empty_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as empty, self.assertRaises(ValueError):
            linux_pkg.write_sums(empty)

    def test_cli_exit_codes(self):
        linux_pkg.write_sums(self.d)
        self.assertEqual(linux_pkg.main(["x", "check", self.d]), 0)
        _write(self.d, "a.tar.gz", b"tampered")
        with redirect_stderr(io.StringIO()):
            self.assertEqual(linux_pkg.main(["x", "check", self.d]), 1)
            self.assertEqual(linux_pkg.main(["x", "bogus"]), 2)
            self.assertEqual(linux_pkg.main(["x", "name", "6.0.0", "mips"]), 2)


class Tarball(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bundle = os.path.join(self.tmp.name, "stage")
        os.makedirs(os.path.join(self.bundle, "app", "_internal"))
        _write(self.bundle, "apophis", b"#!/bin/sh\n")
        os.chmod(os.path.join(self.bundle, "apophis"), 0o755)
        _write(os.path.join(self.bundle, "app"), "apophis-server", b"elf")
        _write(os.path.join(self.bundle, "app", "_internal"), "base_library.zip", b"zip")

    def tearDown(self):
        self.tmp.cleanup()

    def _make(self, name):
        out = os.path.join(self.tmp.name, name)
        os.makedirs(out)
        return linux_pkg.make_tarball(self.bundle, "6.0.0", "amd64", out)

    def test_layout_and_modes(self):
        with tarfile.open(self._make("one")) as t:
            members = {m.name: m for m in t.getmembers()}
        top = "apophis-6.0.0-linux-x86_64"
        self.assertEqual(sorted(members), sorted([top, top + "/app", top + "/app/_internal", top + "/app/_internal/base_library.zip",
                                                  top + "/app/apophis-server", top + "/apophis"]))
        self.assertTrue(members[top + "/apophis"].mode & 0o111, "launcher lost its executable bit")
        self.assertEqual({(m.uid, m.gid, m.mtime) for m in members.values()}, {(0, 0, 0)})

    def test_reproducible(self):
        a, b = self._make("one"), self._make("two")
        self.assertEqual(os.path.basename(a), "apophis-6.0.0-linux-x86_64.tar.gz")
        self.assertEqual(linux_pkg.sha256_file(a), linux_pkg.sha256_file(b))


class FrozenLists(unittest.TestCase):
    def test_diff(self):
        self.assertEqual(frozen_modules.diff({"a", "b"}, {"b", "c"}), (["a"], ["c"]))
        self.assertEqual(frozen_modules.diff({"a"}, {"a"}), ([], []))

    def test_linux_lists_cover_every_import_in_the_patch_tree(self):
        """A patch zip serves every platform, so each Linux bundle must offer every module the tree imports."""
        lists = {n: m for n, m in frozen_modules.platform_lists().items() if n.startswith("frozen-modules-linux-")}
        self.assertEqual(sorted(lists), ["frozen-modules-linux-aarch64.txt", "frozen-modules-linux-x86_64.txt"])
        for name, mods in lists.items():
            self.assertEqual(frozen_modules.violations(frozen=mods), [], name)
            self.assertTrue({"os", "hmac", "base64", "struct", "cryptography", "zoneinfo"} <= mods, name + " looks truncated")
            self.assertNotIn("_scproxy", mods, name + " has a macOS-only module: it was not built on Linux")

    def test_the_architectures_agree(self):
        """Same Python, same flags: the lists differ only by the architecture-named _sysconfigdata module."""
        lists = {n: {m for m in mods if not m.startswith("_sysconfigdata__")} for n, mods in frozen_modules.platform_lists().items()}
        gone, new = frozen_modules.diff(lists["frozen-modules-linux-x86_64.txt"], lists["frozen-modules-linux-aarch64.txt"])
        self.assertEqual((gone, new), ([], []), "x86_64 and aarch64 bundles must freeze the same modules")


if __name__ == "__main__":
    unittest.main()
