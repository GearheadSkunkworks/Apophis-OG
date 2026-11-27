"""tshark discovery works the same on macOS and Linux: explicit TSHARK wins, then the Wireshark.app bundle, then PATH."""
import os
import sys
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(DEV, "tools"))
import render_diagram  # noqa: E402 - sys.path is set up first
from checks.tshark_locate import MACOS_APP, find_tshark


class FindTshark(unittest.TestCase):
    def test_explicit_env_path_wins_when_it_exists(self):
        self.assertEqual(find_tshark(env={"TSHARK": "/x/tshark"}, which=lambda n: "/usr/bin/tshark",
                                     exists=lambda p: p == "/x/tshark"), "/x/tshark")

    def test_explicit_env_path_that_is_missing_is_not_silently_replaced(self):
        self.assertIsNone(find_tshark(env={"TSHARK": "/nope"}, which=lambda n: "/usr/bin/tshark",
                                      exists=lambda p: p != "/nope"))

    def test_macos_bundle_used_when_present(self):
        self.assertEqual(find_tshark(env={}, which=lambda n: "/usr/bin/tshark", exists=lambda p: p == MACOS_APP),
                         MACOS_APP)

    def test_linux_path_lookup_when_no_bundle(self):
        self.assertEqual(find_tshark(env={}, which=lambda n: "/usr/bin/tshark" if n == "tshark" else None,
                                     exists=lambda p: False), "/usr/bin/tshark")

    def test_none_when_not_installed(self):
        self.assertIsNone(find_tshark(env={}, which=lambda n: None, exists=lambda p: False))


class FindBrowser(unittest.TestCase):
    """render_diagram finds a Chromium-family browser on macOS (app bundle) and on Linux (PATH)."""

    def test_chrome_env_wins(self):
        self.assertEqual(render_diagram.browser(env={"CHROME": "/c"}, exists=lambda p: p == "/c", which=lambda n: "/x"), "/c")

    def test_macos_bundle(self):
        mac = render_diagram.CANDIDATES[0]
        self.assertEqual(render_diagram.browser(env={}, exists=lambda p: p == mac, which=lambda n: None), mac)

    def test_linux_path_names(self):
        self.assertEqual(render_diagram.browser(env={}, exists=lambda p: False,
                                                which=lambda n: "/usr/bin/chromium" if n == "chromium" else None),
                         "/usr/bin/chromium")

    def test_nothing_found_says_how_to_fix_it(self):
        with self.assertRaises(SystemExit) as cm:
            render_diagram.browser(env={}, exists=lambda p: False, which=lambda n: None)
        self.assertIn("CHROME", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
