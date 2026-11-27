"""The replay preflight and the update check reuse a recent result; an explicit recheck always bypasses it."""
import os
import sys
import unittest
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import replay  # noqa: E402 - sys.path is set first
import updater  # noqa: E402 - sys.path is set first


class PreflightCache(unittest.TestCase):
    def setUp(self):
        replay._PREFLIGHT.clear()
        replay._VERSIONS.clear()
        self.addCleanup(replay._PREFLIGHT.clear)
        self.addCleanup(replay._VERSIONS.clear)

    def test_repeat_is_served_from_cache_and_fresh_bypasses(self):
        with mock.patch.object(replay, "_preflight", side_effect=lambda p, i: {"ok": True, "n": object()}) as m:
            a = replay.preflight(None, "en0")
            b = replay.preflight(None, "en0")
            self.assertEqual(1, m.call_count)
            self.assertIsNot(a, b)                               # callers get their own copy
            replay.preflight(None, "en0", fresh=True)
            self.assertEqual(2, m.call_count)
            replay.preflight(None, "en1")                        # another interface is another key
            self.assertEqual(3, m.call_count)

    def test_ttl_expiry_rechecks(self):
        with mock.patch.object(replay, "_preflight", return_value={"ok": True}) as m:
            replay.preflight()
            with mock.patch.object(replay.time, "monotonic", return_value=replay.time.monotonic() + replay.PREFLIGHT_TTL + 1):
                replay.preflight()
            self.assertEqual(2, m.call_count)

    def test_tool_version_runs_once_per_path(self):
        with mock.patch.object(replay, "_tool_version", return_value="v1") as m:
            self.assertEqual("v1", replay.tool_version("/x/tool"))
            self.assertEqual("v1", replay.tool_version("/x/tool"))
            replay.tool_version("/y/tool")
        self.assertEqual(2, m.call_count)


class UpdateCheckCache(unittest.TestCase):
    def setUp(self):
        updater._LAST.clear()
        updater._LAST_AT = 0.0
        self.addCleanup(updater._LAST.clear)

    def get(self, calls, query="", state="current"):
        def fake_check(cur, get=None):
            calls.append(1)
            return {"state": state, "current": "1"}
        with mock.patch.object(updater, "check", fake_check), mock.patch.object(updater, "current_version", lambda d: "1"):
            return updater.route_get("/api/update/check", ".", query=query)

    def test_reuse_then_force(self):
        calls = []
        first, second = self.get(calls), self.get(calls)
        self.assertEqual(1, len(calls))
        self.assertEqual(first[1], second[1])
        self.get(calls, "force=1")
        self.assertEqual(2, len(calls))

    def test_errors_are_not_reused(self):
        calls = []
        self.get(calls, state="error")
        self.get(calls, state="error")
        self.assertEqual(2, len(calls))

    def test_expiry(self):
        calls = []
        self.get(calls)
        updater._LAST_AT -= updater.CHECK_TTL + 1
        self.get(calls)
        self.assertEqual(2, len(calls))


if __name__ == "__main__":
    unittest.main()
