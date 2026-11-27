"""Checks that need an optional program (git) say so and carry on when it is missing, as they do on a bare Linux image."""
import os
import subprocess
import sys
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CheckIpOptionsWithoutGit(unittest.TestCase):
    def test_old_engine_comparison_is_skipped_when_git_is_not_installed(self):
        with tempfile.TemporaryDirectory() as empty:           # a PATH with no git in it
            r = subprocess.run([sys.executable, os.path.join(DEV, "checks", "check_ip_options.py")], capture_output=True,
                               text=True, timeout=300, env={"PATH": empty, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("old-engine comparison skipped", r.stdout)


if __name__ == "__main__":
    unittest.main()
