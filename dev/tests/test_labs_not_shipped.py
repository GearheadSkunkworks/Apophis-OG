"""The validation-VM lab (labs/ at the repository root, outside dev/) is development tooling and must never ship.

Skipped when labs/ is absent (a release export has no labs/). Checks: the release allow-list selects nothing from it,
no publish step reads it, and its tracked files pass the release scan (no home paths, internal names, keys)."""
import os
import subprocess
import sys
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(DEV)
LABS = os.path.join(ROOT, "labs")
sys.path.insert(0, os.path.join(DEV, "tools"))
import promote  # noqa: E402 - sys.path is set up before the import


@unittest.skipUnless(os.path.isdir(LABS), "no labs/ folder in this tree")
class LabsNotShipped(unittest.TestCase):
    def test_release_selection_never_includes_labs(self):
        selected, _ = promote.select(DEV, os.path.join(DEV, "tools", promote.MANIFEST_NAME))
        self.assertEqual([p for p in selected if "labs" in p.split("/") or "validate-vms" in p], [])

    def test_publish_tooling_does_not_reference_labs(self):
        for name in ("publish.sh", "compose_public.py", "promote.py"):
            with open(os.path.join(DEV, "tools", name), encoding="utf-8") as f:
                self.assertNotIn("labs/", f.read(), name)

    def test_lab_files_pass_the_release_scan(self):
        out = subprocess.run(["git", "ls-files", "-z", "--", "labs"], cwd=ROOT, capture_output=True).stdout
        files = [p.decode() for p in out.split(b"\0") if p]
        self.assertTrue(files, "labs/ has no tracked files")
        self.assertEqual(promote.scan(ROOT, files), [])


if __name__ == "__main__":
    unittest.main()
