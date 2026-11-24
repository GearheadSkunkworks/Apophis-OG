"""dev/VERSION is the single source of truth for the app version."""
import os
import sys
import tempfile
import unittest

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import make_diagram  # noqa: E402


def _dev_version():
    with open(os.path.join(DEV, "VERSION"), encoding="utf-8") as fh:
        return fh.read().strip()


class VersionTest(unittest.TestCase):
    def test_version_comes_from_file(self):
        self.assertEqual(make_diagram.VERSION, _dev_version())

    def test_read_version_from_given_dir(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "VERSION"), "w", encoding="utf-8") as fh:
                fh.write("9.8.7-rc3\n")
            self.assertEqual(make_diagram._read_version(d), "9.8.7-rc3")

    def test_fallback_when_missing_or_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(make_diagram._read_version(d), make_diagram._FALLBACK_VERSION)
            with open(os.path.join(d, "VERSION"), "w", encoding="utf-8") as fh:
                fh.write("  \n")
            self.assertEqual(make_diagram._read_version(d), make_diagram._FALLBACK_VERSION)

    def test_fallback_equals_dev_version(self):
        self.assertEqual(make_diagram._FALLBACK_VERSION, _dev_version(),
                         "update make_diagram._FALLBACK_VERSION to match dev/VERSION")

    def test_version_shape(self):
        self.assertRegex(make_diagram.VERSION, r"^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$")

    def test_about_page_shows_version(self):
        self.assertIn(make_diagram.VERSION, make_diagram.VERSION_DISPLAY)
        self.assertTrue(make_diagram.VERSION_DISPLAY.startswith("v5 (Apophis) "))
        data = make_diagram.gather(os.path.join(DEV, "inventory.json"), None, None)
        mods, selected = make_diagram.load_modules(None)
        spec = make_diagram.about_page(make_diagram.DiagramContext(data, mods, selected))
        flat = " ".join(str(k) for kpi in spec["kpis"] for k in kpi)
        self.assertIn(make_diagram.VERSION_DISPLAY, flat)


if __name__ == "__main__":
    unittest.main()
