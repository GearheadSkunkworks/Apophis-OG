"""The campaign size estimate is remembered per (campaign, scale, nets, day, identity, inventory file)."""
import os
import sys
import unittest
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import server  # noqa: E402 - sys.path is set first


class PreviewCache(unittest.TestCase):
    def setUp(self):
        server._PREVIEWS.clear()
        self.addCleanup(server._PREVIEWS.clear)
        self.calls = []

        def fake(campaign, **kw):
            self.calls.append(campaign)
            return {"entries": [1, 2]}, {"packets": 3, "bytes": 4}
        p = mock.patch.object(server.opengenerator_build, "preview_campaign", fake)
        p.start()
        self.addCleanup(p.stop)

    def test_repeat_hits_cache_and_changes_recompute(self):
        c = {"id": "a", "steps": [1]}
        server._preview_campaign(c, 0.5, {})
        server._preview_campaign(dict(c), 0.5, {})
        self.assertEqual(1, len(self.calls))
        server._preview_campaign(c, 0.6, {})                       # scale
        server._preview_campaign(c, 0.5, {"user": "10.9.9.0/24"})  # nets
        server._preview_campaign({"id": "a", "steps": [2]}, 0.5, {})  # campaign
        self.assertEqual(4, len(self.calls))

    def test_inventory_mtime_and_identity_are_part_of_the_key(self):
        inv = os.path.join(server.APP_DIR, "inventory.json")
        k1 = server._preview_key({"id": "a"}, 1.0, {}, inv)
        with mock.patch.object(server.os, "stat", return_value=mock.Mock(st_mtime_ns=1)):
            self.assertNotEqual(k1, server._preview_key({"id": "a"}, 1.0, {}, inv))
        ident = server.opengenerator_build.identity
        with mock.patch.object(ident, "get_current", return_value=mock.Mock(name="x", industry="y")):
            self.assertNotEqual(k1, server._preview_key({"id": "a"}, 1.0, {}, inv))

    def test_callers_cannot_poison_the_cache(self):
        c = {"id": "a"}
        r1, _ = server._preview_campaign(c, 1.0, {})
        r1["entries"].append("junk")
        r2, _ = server._preview_campaign(c, 1.0, {})
        self.assertEqual([1, 2], r2["entries"])


if __name__ == "__main__":
    unittest.main()
