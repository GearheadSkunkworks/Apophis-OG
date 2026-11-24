"""Regression tests for review findings S-08..S-12, B-01, B-02, B-03 residual and P-05."""
import json
import os
import pathlib
import sys
import tempfile
import threading
import unittest
import urllib.error
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)


class BuildCleanup(unittest.TestCase):
    def test_non_cancel_failure_removes_partial_output_and_reraises(self):
        import opengenerator_build as B
        d = tempfile.mkdtemp()
        out, kl = os.path.join(d, "o.pcap"), os.path.join(d, "o.log")
        with mock.patch.object(B.Engine, "run", side_effect=RuntimeError("engine bug")):
            with self.assertRaises(RuntimeError):
                B.build(scale=0.0005, out=out, keylog=kl, progress=False, modules=[],
                        certs_dir=os.path.join(d, "certs"))
        self.assertFalse(os.path.exists(out))
        self.assertFalse(os.path.exists(kl))

    def test_preview_campaign_leaves_no_temp_files_on_failure(self):
        import opengenerator_build as B
        before = set(os.listdir(tempfile.gettempdir()))
        with mock.patch.object(B.INC, "build", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                B.preview_campaign({"id": "x"}, scale=0.001)
        left = [f for f in set(os.listdir(tempfile.gettempdir())) - before if f.endswith((".log", ".pcap"))]
        self.assertEqual(left, [])


class UpdaterGuards(unittest.TestCase):
    def test_check_skips_non_dict_release(self):
        import updater
        r = updater.check("5.0.0", get=lambda *a, **k: json.dumps(["junk", 3, None]))
        self.assertNotEqual(r.get("state"), "error")

    def test_install_gets_a_copy_and_second_caller_gets_409(self):
        import updater
        updater._LAST.clear()
        updater._LAST.update({"state": "patch"})
        seen = {}
        gate, entered = threading.Event(), threading.Event()

        def slow_install(info, app_dir, get=None):
            seen["same"] = info is updater._LAST
            entered.set()
            gate.wait(5)
            return "9.9.9"
        res = {}
        with mock.patch.object(updater, "install", slow_install):
            t = threading.Thread(target=lambda: res.update(a=updater.route_post(
                "/api/update/install", "/x", lambda: None)))
            t.start()
            self.assertTrue(entered.wait(5))
            second = updater.route_post("/api/update/install", "/x", lambda: None)
            gate.set()
            t.join(5)
        self.assertEqual(second[0], 409)
        self.assertEqual(res["a"][0], 200)
        self.assertFalse(seen["same"])


class ReplayStart(unittest.TestCase):
    def setUp(self):
        import replay
        self.r = replay
        self.addCleanup(replay.RSTATE.update, running=False)
        replay.RSTATE["running"] = False

    def test_failed_preflight_rolls_back_running(self):
        with mock.patch.object(self.r, "preflight", return_value={"ok": False, "errors": ["nope"]}):
            with self.assertRaises(RuntimeError):
                self.r.start("rel.pcap", "en0")
        self.assertFalse(self.r.RSTATE["running"])

    def test_second_start_refused_while_first_in_preflight(self):
        def pre(*a, **k):
            with self.assertRaises(RuntimeError):
                self.r.start("b.pcap", "en0")
            return {"ok": False, "errors": ["x"]}
        with mock.patch.object(self.r, "preflight", side_effect=pre):
            with self.assertRaises(RuntimeError):
                self.r.start("a.pcap", "en0")

    def test_pcap_is_absolute(self):
        seen = {}
        with mock.patch.object(self.r, "preflight", side_effect=lambda p, i: seen.update(p=p) or
                               {"ok": False, "errors": ["x"]}):
            with self.assertRaises(RuntimeError):
                self.r.start("-weird.pcap", "en0")
        self.assertTrue(os.path.isabs(seen["p"]))


class RootSafe(unittest.TestCase):
    def _tool(self, mode_dir=0o755, mode_file=0o755):
        d = tempfile.mkdtemp()
        os.chmod(d, mode_dir)
        f = os.path.join(d, "tcpreplay")
        open(f, "w").close()
        os.chmod(f, mode_file)
        return d, f

    def test_user_owned_dir_is_not_root_safe(self):
        import replay
        d, f = self._tool()
        if os.getuid() == 0:
            self.skipTest("running as root")
        self.assertFalse(replay.root_safe(f, prefixes=[]))

    def test_owner_of_package_prefix_is_trusted_inside_it_only(self):
        import replay
        d, f = self._tool()
        self.assertTrue(replay.root_safe(f, prefixes=[d]))
        other, g = self._tool()
        self.assertFalse(replay.root_safe(g, prefixes=[d]) and os.getuid() != 0)

    def test_group_or_world_writable_rejected(self):
        import replay
        d, f = self._tool(mode_dir=0o775)
        self.assertFalse(replay.root_safe(f, prefixes=[d]))
        d2, f2 = self._tool(mode_file=0o757)
        self.assertFalse(replay.root_safe(f2, prefixes=[d2]))

    def test_privileged_tool_falls_back_then_none(self):
        import replay
        bad, fb = self._tool()
        good, gf = self._tool()
        self.assertEqual(replay.privileged_tool("tcpreplay", fb, fallback_dirs=(good,), prefixes=[good]), gf)
        self.assertIsNone(replay.privileged_tool("tcpreplay", fb, fallback_dirs=(), prefixes=[good]))


class CampaignRunErrors(unittest.TestCase):
    def test_invalid_campaign_is_400_and_engine_not_called(self):
        import campaign_api as C
        called = []
        with mock.patch.object(C, "RUN_CAMPAIGN", lambda *a: called.append(1)), \
                mock.patch.object(C, "_norm_and_validate", return_value=({}, ["bad stage"])):
            with self.assertRaises(C.ApiError) as c:
                C.campaign_run({"campaign": {}})
        self.assertEqual(c.exception.status, 400)
        self.assertEqual(c.exception.extra["errors"], ["bad stage"])
        self.assertEqual(called, [])


class SensorHardening(unittest.TestCase):
    def test_ids_validated_before_url_use(self):
        from sensorops.providers import network_sensor as NS
        p = NS.NetworkSensorProvider("10.0.0.5", "K")
        with mock.patch.object(p, "_req") as rq:
            with self.assertRaises(urllib.error.URLError):
                p.delete_decrypt_key("../../x")
            with self.assertRaises(urllib.error.URLError):
                p.delete_collection("a/b")
            p.delete_decrypt_key("ab12_-Z")
            rq.assert_called_once()

    def test_opener_ignores_env_proxies(self):
        from sensorops.providers import network_sensor as NS
        import urllib.request
        seen = {}

        class O:
            def open(s, req, timeout=None):
                raise urllib.error.URLError("stop")
        _real = urllib.request.build_opener

        def spy(*handlers):
            seen["h"] = handlers
            return O()
        with mock.patch.object(urllib.request, "build_opener", spy):
            with self.assertRaises(urllib.error.URLError):
                NS._urlopen(urllib.request.Request("https://10.0.0.5/"), timeout=1, context=None)
        ph = [h for h in seen["h"] if isinstance(h, urllib.request.ProxyHandler)]
        self.assertEqual(ph[0].proxies, {})


class IntelCache(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        p = mock.patch.dict(os.environ, {"OPENGENERATOR_CACHE": self.d})
        p.start()
        self.addCleanup(p.stop)

    def test_typed_url_not_persisted_but_hits_work(self):
        from intel import cache
        url = "https://feeds.example.net/list.csv?apikey=SEKRET&x=1"
        cache.put("url", {"url": url}, "payload")
        self.assertEqual(cache.get("url", {"url": url}), "payload")
        blob = "".join(pathlib.Path(self.d, f).read_text() for f in os.listdir(self.d))
        self.assertNotIn("SEKRET", blob)
        self.assertNotIn("list.csv", blob)

    def test_concurrent_puts_keep_all_manifest_entries(self):
        from intel import cache
        ts = [threading.Thread(target=cache.put, args=("f%d" % i, {}, "p")) for i in range(12)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(len(cache.manifest()), 12)


if __name__ == "__main__":
    unittest.main()
