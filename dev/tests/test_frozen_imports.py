"""A patch must import only what the frozen full release it patches bundles (5.5.1 and 5.5.2 died at start on `secrets`).
The list is tools/frozen-modules.txt, built from the X.Y.0 .app; refresh it per tools/frozen_modules.py on a minor release."""
import os
import sys
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(DEV, "tools"))
import frozen_modules  # noqa: E402 - sys.path is set up before the import


class FrozenImports(unittest.TestCase):
    def test_patch_tree_imports_only_frozen_modules(self):
        bad = frozen_modules.violations()
        self.assertEqual(bad, [], "not in the frozen app (see tools/frozen_modules.py): %s" % bad)

    def test_the_check_catches_the_5_5_1_mistake(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "server.py"), "w") as fh:
                fh.write("import os\ndef f():\n    import secrets\ntry:\n    import nothere\nexcept ImportError:\n    pass\n")
            self.assertEqual(frozen_modules.violations(d, {"os"}), [("server.py", 3, "secrets")])

    def test_list_has_the_basics(self):
        m = frozen_modules.load()
        self.assertTrue({"os", "hmac", "base64", "struct", "cryptography"} <= m, "list looks truncated")
        self.assertNotIn("secrets", m)


if __name__ == "__main__":
    unittest.main()
