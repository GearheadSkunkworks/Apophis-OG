"""deps.check() in the packaged app: no install advice, built-in rows, bundled tz data."""
import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import deps  # noqa: E402 - sys.path is set up before the import

ADVICE = re.compile(r"pip3?\b|brew\b|python\.org|python3\b|inventory\.py|requirements\.txt", re.I)
KEYS = {"name", "required", "found", "why", "version", "hint", "detail"}


def _frozen():
    return mock.patch.object(sys, "frozen", True, create=True)


def _rows(rep):
    return {t["name"]: t for t in rep["tools"]}


class FrozenDepsTest(unittest.TestCase):
    def test_passing_rows_built_in(self):
        with _frozen():
            rows = _rows(deps.check())
        for n in ("python", "cryptography"):
            self.assertEqual(rows[n]["version"], "built in")
            self.assertEqual(rows[n]["detail"], "")
            self.assertTrue(rows[n]["found"] and rows[n]["required"])
            self.assertEqual(set(rows[n]), KEYS)

    def test_found_required_unchanged(self):
        plain = {t["name"]: (t["required"], t["found"]) for t in deps.check()["tools"]}
        with _frozen():
            frozen = {t["name"]: (t["required"], t["found"]) for t in deps.check()["tools"]}
        self.assertEqual(plain, frozen)

    def test_failure_hints_say_reinstall(self):
        with _frozen(), \
                mock.patch.object(deps, "MIN_PYTHON", (99, 0)), \
                mock.patch.dict(sys.modules, {"cryptography": None}), \
                mock.patch.dict(sys.modules, {"zoneinfo": None}), \
                mock.patch.object(deps, "APP_DIR", "/nonexistent"):
            rep = deps.check()
        for t in rep["tools"]:
            self.assertFalse(ADVICE.search(t["hint"]), t)
        for m in rep["errors"] + rep["warnings"]:
            self.assertFalse(ADVICE.search(m), m)
        rows = _rows(rep)
        for n in ("python", "cryptography", "time zone data", "inventory.json"):
            self.assertFalse(rows[n]["found"])
            self.assertIn("reinstall", rows[n]["hint"])

    def test_source_hints_unchanged(self):
        with mock.patch.object(deps, "MIN_PYTHON", (99, 0)), \
                mock.patch.dict(sys.modules, {"cryptography": None}), \
                mock.patch.dict(sys.modules, {"zoneinfo": None}):
            rows = _rows(deps.check())
        self.assertIn("python.org", rows["python"]["hint"])
        self.assertEqual(rows["cryptography"]["hint"], "pip3 install -r requirements.txt")
        self.assertEqual(rows["time zone data"]["hint"], "pip3 install tzdata")
        self.assertNotEqual(rows["python"]["version"], "built in")


class TzFallbackTest(unittest.TestCase):
    def test_bundled_tzdata_used_when_system_db_missing(self):
        try:
            import tzdata  # noqa: F401 - imported only to prove the package is bundled
        except ImportError:
            self.skipTest("tzdata package not installed")
        import zoneinfo
        old = zoneinfo.TZPATH
        zoneinfo.reset_tzpath(to=())
        zoneinfo.ZoneInfo.clear_cache()
        try:
            self.assertEqual(zoneinfo.TZPATH, ())
            self.assertIsNotNone(zoneinfo.ZoneInfo(deps.TZ_NAME))
            self.assertTrue(deps._check_tzdata()["found"])
        finally:
            zoneinfo.reset_tzpath(to=old)
            zoneinfo.ZoneInfo.clear_cache()


if __name__ == "__main__":
    unittest.main()
