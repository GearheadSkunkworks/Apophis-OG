import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import safeio  # noqa: E402 - sys.path is set up before the import


class CreateNew(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, self.d, True)

    def test_writes_text_and_bytes(self):
        p = os.path.join(self.d, "a.tmp")
        with safeio.create_new(p, "w", encoding="utf-8") as f:
            f.write("hi")
        with safeio.create_new(p, "wb") as f:      # a stale file of the same name is replaced
            f.write(b"\x00\x01")
        self.assertEqual(open(p, "rb").read(), b"\x00\x01")

    def test_planted_symlink_is_replaced_not_followed(self):
        victim = os.path.join(self.d, "victim")
        open(victim, "w").write("keep")
        p = os.path.join(self.d, "out.tmp")
        os.symlink(victim, p)
        with safeio.create_new(p, "w") as f:
            f.write("new")
        self.assertEqual(open(victim).read(), "keep")
        self.assertFalse(os.path.islink(p))
        self.assertEqual(open(p).read(), "new")

    def test_rejects_append_and_read_modes(self):
        for m in ("a", "r", "r+b"):
            with self.assertRaises(ValueError):
                safeio.create_new(os.path.join(self.d, "x"), m)


if __name__ == "__main__":
    unittest.main()
