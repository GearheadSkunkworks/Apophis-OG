"""Agent API: scope tests. The refusals come first: an agent can never replay or push to a sensor."""
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import mock

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)

import agent_api  # noqa: E402
import keystore  # noqa: E402

DENIED = sorted(agent_api.HUMAN_ONLY)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        os.environ["OG_SETTINGS_DIR"] = cls.tmp
        cls.kp = mock.patch.object(keystore, "available", return_value=False)    # never touch the real Keychain
        cls.kp.start()
        import server
        cls.server = server
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_port
        cls.token = agent_api.create_token()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.kp.stop()
        os.environ.pop("OG_SETTINGS_DIR", None)
        shutil.rmtree(cls.tmp, True)

    def call(self, method, path, body=None, bearer=None, cookie=None):
        h = {"Content-Type": "application/json"}
        if bearer:
            h["Authorization"] = "Bearer " + bearer
        if cookie:
            h["Cookie"] = cookie
        data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        rq = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            r = urllib.request.urlopen(rq, timeout=10)
        except urllib.error.HTTPError as e:
            r = e
        raw = r.read()
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, raw


class Deny(Base):
    """Replay and sensor push stay human-only."""

    def test_a1_token_is_refused_on_every_human_route(self):
        for p in DENIED:
            st, js = self.call("POST", p, {}, bearer=self.token, cookie="og_ui=" + self.server.UI_SECRET)
            self.assertEqual(st, 403, (p, st, js))

    def test_a2_no_cookie_no_token_is_refused(self):
        for p in DENIED:
            st, js = self.call("POST", p, {})
            self.assertEqual(st, 403, (p, st, js))

    def test_a3_wrong_cookie_is_refused(self):
        for p in DENIED:
            st, _ = self.call("POST", p, {}, cookie="og_ui=nope")
            self.assertEqual(st, 403, p)

    def test_a4_the_app_page_still_reaches_them(self):
        for p in DENIED:
            if p.startswith("/api/agent/"):
                continue                           # the Settings controls change state; covered in test_e1
            st, _ = self.call("POST", p, b"[]", cookie="og_ui=" + self.server.UI_SECRET)
            self.assertNotEqual(st, 403, p)        # reached the handler (it answers 400 for a bad body)

    def test_a5_token_is_refused_outside_the_agent_namespace(self):
        for m, p in (("GET", "/api/status"), ("POST", "/api/generate"), ("GET", "/"), ("POST", "/api/reveal"),
                     ("POST", "/api/sensor/preflight"), ("POST", "/api/update/install"), ("GET", "/api/replay/status")):
            st, _ = self.call(m, p, {} if m == "POST" else None, bearer=self.token)
            self.assertEqual(st, 403, (m, p))

    def test_a6_no_verb_replays_or_pushes(self):
        for verb in ("replay/start", "replay/stop", "sensor/push", "sensor/stop", "sensor/collection/push",
                     "sensor/collection/stop", "build/replay"):
            st, _ = self.call("POST", "/agent/v1/" + verb, {}, bearer=self.token)
            self.assertEqual(st, 404, verb)
        names = {v for (_, v) in agent_api.VERBS}
        self.assertFalse([n for n in names if "replay" in n or n.endswith("push") or n.endswith("/stop")], names)
        for target in agent_api.VERBS.values():
            if isinstance(target, str):
                self.assertNotIn(target, agent_api.HUMAN_ONLY)

    def test_a7_stage_runs_nothing(self):
        from sensorops import push_cert
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch.object(push_cert, "push_cert") as pc, mock.patch("replay.start") as rs:
            st, js = self.call("POST", "/agent/v1/sensor/stage", {"sensor": "s1.example.net", "certs_dir": d},
                               bearer=self.token)
            self.assertEqual(st, 200, js)
            pc.assert_not_called()
            rs.assert_not_called()
        self.assertEqual(len(agent_api.pending()), 1)
        agent_api.dismiss(js["pending"]["id"])

    def test_a8_page_only_routes_need_the_page_cookie(self):
        """Sensor check and detection scoring can use the stored sensor key: no cookie, no entry (5.5.5)."""
        self.assertEqual(sorted(agent_api.PAGE_ONLY), ["/api/campaign/feedback", "/api/sensor/check"])
        for p in sorted(agent_api.PAGE_ONLY):
            self.assertEqual(self.call("POST", p, {"use_stored": True})[0], 403, p)                    # bare local client
            self.assertEqual(self.call("POST", p, {}, cookie="og_ui=nope")[0], 403, p)                 # wrong cookie
            self.assertEqual(self.call("POST", p, {}, bearer=self.token)[0], 403, p)                   # a token alone
            st, _ = self.call("POST", p, b"[]", cookie="og_ui=" + self.server.UI_SECRET)
            self.assertNotEqual(st, 403, p)                                                            # the app page reaches the handler

    def test_a9_the_agent_sensor_check_verb_still_works(self):
        self.assertEqual(agent_api.VERBS[("POST", "sensor/check")], "/api/sensor/check")
        st, js = self.call("POST", "/agent/v1/sensor/check", {}, bearer=self.token)
        self.assertNotIn(st, (401, 403, 404), (st, js))       # reaches the handler, which answers 400 for an empty body
        for target in agent_api.VERBS.values():
            if isinstance(target, str):
                self.assertNotIn(target, agent_api.HUMAN_ONLY)


class Scope(Base):
    def test_b1_requires_a_valid_token(self):
        self.assertEqual(self.call("GET", "/agent/v1/build/status")[0], 401)
        self.assertEqual(self.call("GET", "/agent/v1/build/status", bearer="ogagent_wrong")[0], 401)

    def test_b2_valid_token_reaches_status_and_is_audited(self):
        st, js = self.call("GET", "/agent/v1/build/status", bearer=self.token)
        self.assertEqual(st, 200, js)
        self.assertIn("running", js)
        path = os.path.join(self.tmp, agent_api.AUDIT_FILE)
        # The server replies first and writes the line just after. The log file exists (empty) before the line is written,
        # so wait for the line itself, not the file, and read only whole lines; allow plenty of time on a loaded machine.
        last = None
        for _ in range(200):
            try:
                with open(path) as fh:
                    lines = [ln for ln in fh.read().splitlines() if ln.strip()]
                last = json.loads(lines[-1]) if lines else None
            except (OSError, ValueError):
                last = None
            if last and (last.get("verb"), last.get("status")) == ("build/status", 200):
                break
            time.sleep(0.05)
        self.assertIsNotNone(last, "no audit line was written")
        self.assertEqual((last["verb"], last["status"]), ("build/status", 200))

    def test_b3_unknown_verb_and_method(self):
        self.assertEqual(self.call("GET", "/agent/v1/nothing", bearer=self.token)[0], 404)
        self.assertEqual(self.call("POST", "/agent/v1/build/status", {}, bearer=self.token)[0], 404)

    def test_b4_off_until_a_token_exists(self):
        agent_api.revoke_token()
        self.addCleanup(lambda: setattr(type(self), "token", agent_api.create_token()))
        self.assertEqual(self.call("GET", "/agent/v1/build/status", bearer=self.token)[0], 401)

    def test_b5_sensor_key_may_not_travel_through_the_agent(self):
        for verb in ("sensor/check", "sensor/preflight", "sensor/stage"):
            st, _ = self.call("POST", "/agent/v1/" + verb, {"sensor": "s1.example.net", "key": "x" * 8,
                                                            "certs_dir": self.tmp}, bearer=self.token)
            self.assertEqual(st, 400, verb)

    def test_b6_sensor_without_a_saved_key_is_refused(self):
        with mock.patch.object(keystore, "load", return_value=None):
            st, js = self.call("POST", "/agent/v1/sensor/check", {"sensor": "s1.example.net"}, bearer=self.token)
        self.assertEqual(st, 409, js)

    def test_b7_stage_validates_and_lists(self):
        self.assertEqual(self.call("POST", "/agent/v1/sensor/stage", {"sensor": "s1.example.net",
                                                                      "certs_dir": "/no/such/dir"},
                                   bearer=self.token)[0], 400)
        st, js = self.call("GET", "/agent/v1/sensor/pending", bearer=self.token)
        self.assertEqual((st, js), (200, {"pending": []}))

    def test_b8_page_gets_a_httponly_strict_cookie(self):
        rq = urllib.request.Request(self.base + "/")
        with urllib.request.urlopen(rq, timeout=10) as r:
            ck = r.headers.get("Set-Cookie", "")
        self.assertIn("og_ui=" + self.server.UI_SECRET, ck)
        self.assertIn("HttpOnly", ck)
        self.assertIn("SameSite=Strict", ck)

    def test_b9_audit_hides_secrets(self):
        agent_api.audit("x/y", 200, {"sensor": "s1", "apikey": "SECRET", "campaign": {"a": 1}})
        with open(os.path.join(self.tmp, agent_api.AUDIT_FILE)) as fh:
            txt = fh.read()
        self.assertNotIn("SECRET", txt)
        self.assertIn("<hidden>", txt)


class Token(unittest.TestCase):
    def test_c1_token_file_is_private_and_rotates(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch.dict(os.environ, {"OG_SETTINGS_DIR": d}), mock.patch.object(keystore, "available",
                                                                                       return_value=False):
            t1 = agent_api.create_token()
            self.assertEqual(os.stat(os.path.join(d, agent_api.TOKEN_FILE)).st_mode & 0o777, 0o600)
            self.assertTrue(agent_api.check_bearer("Bearer " + t1))
            t2 = agent_api.create_token()
            self.assertFalse(agent_api.check_bearer("Bearer " + t1))
            self.assertTrue(agent_api.check_bearer("Bearer " + t2))
            self.assertFalse(agent_api.check_bearer("Basic " + t2))
            agent_api.revoke_token()
            self.assertFalse(agent_api.enabled())


if __name__ == "__main__":
    unittest.main()


class Adapter(Base):
    """The MCP adapter lists the server's verbs and cannot offer replay or push."""

    def test_d1_tools_come_from_the_app_and_exclude_replay_and_push(self):
        import og_mcp
        with mock.patch.object(og_mcp, "BASE", self.base), mock.patch.object(og_mcp, "TOKEN", self.token):
            table = {}
            r = og_mcp.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, table)
            names = {t["name"] for t in r["result"]["tools"]}
            self.assertIn("og_build_status", names)
            self.assertIn("og_sensor_stage", names)
            self.assertFalse([n for n in names if "replay" in n or n.endswith("push") or n.endswith("_stop")], names)
            r = og_mcp.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                               "params": {"name": "og_build_status", "arguments": {}}}, table)
            self.assertFalse(r["result"]["isError"])
            self.assertEqual(og_mcp.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}, table), None)


class Settings(Base):
    def test_e1_settings_controls_need_the_page_cookie(self):
        ck = "og_ui=" + self.server.UI_SECRET
        self.assertEqual(self.call("POST", "/api/agent/status", {})[0], 403)
        self.assertEqual(self.call("POST", "/api/agent/token", {}, bearer=self.token, cookie=ck)[0], 403)
        st, js = self.call("POST", "/api/agent/status", {}, cookie=ck)
        self.assertEqual((st, js["enabled"], js["pending"]), (200, True, []))
        st, js = self.call("POST", "/api/agent/token", {}, cookie=ck)           # replacing the token
        self.assertTrue(js["token"].startswith("ogagent_"))
        self.assertEqual(self.call("GET", "/agent/v1/build/status", bearer=self.token)[0], 401)
        type(self).token = js["token"]
        self.assertEqual(self.call("GET", "/agent/v1/build/status", bearer=self.token)[0], 200)
        self.assertEqual(self.call("POST", "/api/agent/off", {}, cookie=ck)[1], {"enabled": False})
        self.assertEqual(self.call("GET", "/agent/v1/build/status", bearer=self.token)[0], 401)
