"""Behavior changed while draining the lint baseline."""
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import campaign_api  # noqa: E402 - sys.path is set up before the import
import server  # noqa: E402 - sys.path is set up before the import


class Hooks(unittest.TestCase):
    def test_run_campaign_hook_is_installed_by_setter(self):
        old = campaign_api.RUN_CAMPAIGN
        self.addCleanup(campaign_api.set_run_campaign, old)
        fn = lambda *a: ({}, {})  # noqa: E731 - throwaway stub
        campaign_api.set_run_campaign(fn)
        self.assertIs(campaign_api.RUN_CAMPAIGN, fn)

    def test_watchdog_returns_promptly_once_shutdown_is_set(self):
        server.SHUTDOWN.set()
        self.addCleanup(server.SHUTDOWN.clear)
        t = threading.Thread(target=server._watchdog, daemon=True)
        t0 = time.time()
        t.start()
        t.join(0.5)
        self.assertFalse(t.is_alive())
        self.assertLess(time.time() - t0, 0.5)


if __name__ == "__main__":
    unittest.main()
