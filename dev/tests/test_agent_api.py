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

import agent_api  # noqa: E402 - sys.path is set up before the import
import keystore  # noqa: E402 - sys.path is set up before the import

DENIED = sorted(agent_api.HUMAN_ONLY)


class FakeKeys:
    """An in-memory keystore, so tests never touch the real Keychain or start a helper process."""
    def __init__(self):
        self.items, self.loads = {}, 0

    def patches(self):
        return [mock.patch.object(keystore, "available", return_value=True),
                mock.patch.object(keystore, "save", side_effect=lambda i, v: self.items.__setitem__(i, v)),
                mock.patch.object(keystore, "load", side_effect=self.load),
                mock.patch.object(keystore, "forget", side_effect=lambda i: self.items.pop(i, None))]

    def load(self, item_id):
        self.loads += 1
        return self.items.get(item_id)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        os.environ["OG_SETTINGS_DIR"] = cls.tmp
        cls.keys = FakeKeys()                                                    # never touch the real Keychain
        cls.kps = cls.keys.patches()
        for p in cls.kps:
            p.start()
        import server
        cls.server = server
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = "http://127.0.0.1:%d" % cls.srv.server_port
        cls.token = agent_api.create_token()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        for p in cls.kps:
            p.stop()
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
        for verb in ("replay/start", "replay/stop", "replay/records", "replay/resume", "replay/options",
                     "sensor/push", "sensor/stop", "sensor/collection/push", "sensor/collection/stop", "build/replay"):
            st, _ = self.call("POST", "/agent/v1/" + verb, {}, bearer=self.token)
            self.assertEqual(st, 404, verb)
        names = {v for (_, v) in agent_api.VERBS}
        self.assertFalse([n for n in names if "replay" in n or n.endswith("push") or n.endswith("/stop")], names)
        for target in agent_api.VERBS.values():
            if isinstance(target, str):
                self.assertNotIn(target, agent_api.HUMAN_ONLY)
                self.assertFalse(target.startswith("/api/replay/"), target)
        self.assertIn("/api/replay/records", agent_api.HUMAN_ONLY)

    def test_a6b_replay_options_need_the_cookie_and_never_a_token(self):
        body = {"pcap": "x.pcap", "iface": "en0", "maxsleep_ms": 100, "include": {"start": 2}, "resume_from": "0" * 12,
                "sensor_label": "lab", "note": "n"}
        for p in ("/api/replay/start", "/api/replay/records"):
            for kw in ({"bearer": self.token}, {}, {"cookie": "og_ui=nope"},
                       {"bearer": self.token, "cookie": "og_ui=" + self.server.UI_SECRET}):
                st, _ = self.call("POST", p, body, **kw)
                self.assertEqual(st, 403, (p, kw))
        with mock.patch("replay.start") as rs:
            self.call("POST", "/api/replay/start", body, bearer=self.token)
            self.call("POST", "/api/replay/start", body)
        rs.assert_not_called()

    def test_a6c_bad_options_are_a_400_for_the_person(self):
        ck = "og_ui=" + self.server.UI_SECRET
        for bad in ({"speed_mode": "topspeed"}, {"speed_value": 11}, {"loop": 1.5}, {"maxsleep_ms": -1},
                    {"include": {"start": 0}}, {"resume_from": "x"}, {"sensor_label": "10.0.0.1"}, {"note": "n" * 2000}):
            with mock.patch("replay.preflight", return_value={"ok": False, "errors": ["unreachable"]}):
                st, js = self.call("POST", "/api/replay/start", dict(pcap="x.pcap", iface="en0", **bad), cookie=ck)
            self.assertEqual(st, 400, bad)
            self.assertIn("bad replay parameters", js["error"], bad)

    def test_a6d_records_route_for_the_person(self):
        ck = "og_ui=" + self.server.UI_SECRET
        st, _ = self.call("POST", "/api/replay/records", {"pcap": os.path.join(self.tmp, "missing.pcap")}, cookie=ck)
        self.assertEqual(st, 404)
        pc = os.path.join(self.tmp, "r.pcap")
        open(pc, "wb").close()
        st, js = self.call("POST", "/api/replay/records", {"pcap": pc}, cookie=ck)
        self.assertEqual((st, js), (200, {"records": []}))
        st, _ = self.call("POST", "/api/replay/records", {"pcap": pc, "id": "../x"}, cookie=ck)
        self.assertEqual(st, 400)

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
                self.assertFalse(target.startswith("/api/replay/"), target)
        self.assertIn("/api/replay/records", agent_api.HUMAN_ONLY)

    def test_a6b_replay_options_need_the_cookie_and_never_a_token(self):
        body = {"pcap": "x.pcap", "iface": "en0", "maxsleep_ms": 100, "include": {"start": 2}, "resume_from": "0" * 12,
                "sensor_label": "lab", "note": "n"}
        for p in ("/api/replay/start", "/api/replay/records"):
            for kw in ({"bearer": self.token}, {}, {"cookie": "og_ui=nope"},
                       {"bearer": self.token, "cookie": "og_ui=" + self.server.UI_SECRET}):
                st, _ = self.call("POST", p, body, **kw)
                self.assertEqual(st, 403, (p, kw))
        with mock.patch("replay.start") as rs:
            self.call("POST", "/api/replay/start", body, bearer=self.token)
            self.call("POST", "/api/replay/start", body)
        rs.assert_not_called()

    def test_a6c_bad_options_are_a_400_for_the_person(self):
        ck = "og_ui=" + self.server.UI_SECRET
        for bad in ({"speed_mode": "topspeed"}, {"speed_value": 11}, {"loop": 1.5}, {"maxsleep_ms": -1},
                    {"include": {"start": 0}}, {"resume_from": "x"}, {"sensor_label": "10.0.0.1"}, {"note": "n" * 2000}):
            with mock.patch("replay.preflight", return_value={"ok": False, "errors": ["unreachable"]}):
                st, js = self.call("POST", "/api/replay/start", dict(pcap="x.pcap", iface="en0", **bad), cookie=ck)
            self.assertEqual(st, 400, bad)
            self.assertIn("bad replay parameters", js["error"], bad)

    def test_a6d_records_route_for_the_person(self):
        ck = "og_ui=" + self.server.UI_SECRET
        st, _ = self.call("POST", "/api/replay/records", {"pcap": os.path.join(self.tmp, "missing.pcap")}, cookie=ck)
        self.assertEqual(st, 404)
        pc = os.path.join(self.tmp, "r.pcap")
        open(pc, "wb").close()
        st, js = self.call("POST", "/api/replay/records", {"pcap": pc}, cookie=ck)
        self.assertEqual((st, js), (200, {"records": []}))
        st, _ = self.call("POST", "/api/replay/records", {"pcap": pc, "id": "../x"}, cookie=ck)
        self.assertEqual(st, 400)


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
        with mock.patch.object(keystore, "load", side_effect=lambda i: None if i.startswith("sensor:") else self.keys.items.get(i)):
            st, js = self.call("POST", "/agent/v1/sensor/check", {"sensor": "s1.example.net"}, bearer=self.token)
        self.assertEqual(st, 409, js)

    def test_b7_stage_validates_and_lists(self):
        self.assertEqual(self.call("POST", "/agent/v1/sensor/stage", {"sensor": "s1.example.net",
                                                                      "certs_dir": "/no/such/dir"},
                                   bearer=self.token)[0], 400)
        st, js = self.call("GET", "/agent/v1/sensor/pending", bearer=self.token)
        self.assertEqual((st, js), (200, {"pending": []}))

    def test_b8_page_gets_a_httponly_strict_cookie(self):
        with urllib.request.urlopen(self.base + "/", timeout=10) as r:        # no nonce: the page, but no cookie
            self.assertEqual(r.headers.get("Set-Cookie"), None)
        rq = urllib.request.Request(self.base + "/?launch=" + self.server.LAUNCH["nonce"])
        with urllib.request.urlopen(rq, timeout=10) as r:
            ck = r.headers.get("Set-Cookie", "")
        with urllib.request.urlopen(rq, timeout=10) as r:                      # the nonce works once
            self.assertEqual(r.headers.get("Set-Cookie"), None)
        self.assertIn("og_ui=" + self.server.UI_SECRET, ck)
        self.assertIn("HttpOnly", ck)
        self.assertIn("SameSite=Strict", ck)

    def test_b12_mcp_adapter_refuses_to_send_the_token_over_plain_http_off_machine(self):
        import og_mcp
        for ok in ("http://127.0.0.1:8765", "http://localhost:1", "http://[::1]:5", "https://og.example.net"):
            self.assertTrue(og_mcp.base_ok(ok), ok)
        for bad in ("http://og.example.net", "http://127.0.0.1.evil.example", "ftp://127.0.0.1", "127.0.0.1:8765", ""):
            self.assertFalse(og_mcp.base_ok(bad), bad)
        with mock.patch.object(og_mcp, "BASE", "http://og.example.net"), \
                mock.patch("urllib.request.urlopen", side_effect=AssertionError("must not connect")):
            self.assertEqual(og_mcp.call("GET", "verbs")[0], 0)

    def test_b10_agent_bodies_cannot_name_paths_or_confirm_real_addresses(self):
        for body in ({"out_dir": "/tmp/x"}, {"recipes": ["/a"]}, {"recipe": "/a"}, {"confirm_real_addresses": True},
                     {"confirm_real_addresses": False}, {"address_mode": "real"}):
            for verb in ("build/submit", "campaign/run", "library/save"):
                st, js = self.call("POST", "/agent/v1/" + verb, body, bearer=self.token)
                self.assertEqual(st, 400, (verb, body, js))
        st, _ = self.call("POST", "/agent/v1/build/submit", {"scale": "x"}, bearer=self.token)
        self.assertNotEqual(st, 403)                                      # other fields still reach the handler

    def test_b11_replies_to_an_agent_hide_the_home_folder(self):
        with mock.patch.dict(os.environ, {"HOME": "/home/someone"}):
            self.assertEqual(agent_api.scrub('{"dir": "/home/someone/Documents/x"}'), '{"dir": "~/Documents/x"}')
        with mock.patch.dict(os.environ, {"HOME": self.tmp, "OPENGENERATOR_CAMPAIGNS": os.path.join(self.tmp, "ogt")}):
            st, js = self.call("GET", "/agent/v1/library/list", bearer=self.token)
        self.assertEqual(st, 200)
        self.assertTrue(js["dir"].startswith("~"), js["dir"])

    def test_b9_audit_logs_names_never_values(self):
        agent_api.audit("x/y", 200, {"sensor": "s1.internal.example", "url": "https://f.example/x?apikey=SECRET",
                                     "apikey": "SECRET2", "campaign": {"a": 1}, "n": 5, "weird name!": 1})
        with open(os.path.join(self.tmp, agent_api.AUDIT_FILE)) as fh:
            last = json.loads(fh.read().splitlines()[-1])
        self.assertEqual(last["args"], ["apikey", "campaign", "n", "sensor", "url", "weird?name?"])
        raw = json.dumps(last)
        for leaked in ("SECRET", "internal.example", "f.example"):
            self.assertNotIn(leaked, raw)

    def test_b10_audit_log_and_folder_are_private(self):
        agent_api.audit("x/y", 200, {})
        self.assertEqual(os.stat(os.path.join(self.tmp, agent_api.AUDIT_FILE)).st_mode & 0o777, 0o600)

    def test_b11_audit_log_made_world_readable_is_tightened_and_symlink_refused(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch.dict(os.environ, {"OG_SETTINGS_DIR": os.path.join(d, "new")}):
            agent_api.audit("a", 200, {})                                  # folder did not exist: made 0700
            self.assertEqual(os.stat(os.path.join(d, "new")).st_mode & 0o777, 0o700)
            log = os.path.join(d, "new", agent_api.AUDIT_FILE)
            os.chmod(log, 0o644)
            agent_api.audit("b", 200, {})
            self.assertEqual(os.stat(log).st_mode & 0o777, 0o600)
            os.remove(log)
            victim = os.path.join(d, "victim")
            open(victim, "w").write("keep")
            os.symlink(victim, log)
            agent_api.audit("c", 200, {})                                   # must not write through the link
            self.assertEqual(open(victim).read(), "keep")


class Token(unittest.TestCase):
    def setUp(self):
        self.keys = FakeKeys()
        for p in self.keys.patches():
            p.start()
            self.addCleanup(p.stop)
        agent_api._forget_cached_token()

    def test_c1_token_rotates_and_revokes(self):
        t1 = agent_api.create_token()
        self.assertTrue(agent_api.check_bearer("Bearer " + t1))
        t2 = agent_api.create_token()
        self.assertFalse(agent_api.check_bearer("Bearer " + t1))      # create invalidates the cache at once
        self.assertTrue(agent_api.check_bearer("Bearer " + t2))
        self.assertFalse(agent_api.check_bearer("Basic " + t2))
        agent_api.revoke_token()
        self.assertFalse(agent_api.enabled())
        self.assertFalse(agent_api.check_bearer("Bearer " + t2))

    def test_c2_bearer_check_does_not_hit_the_keystore_per_request(self):
        t = agent_api.create_token()
        self.keys.loads = 0
        for _ in range(50):
            agent_api.check_bearer("Bearer wrong")
            agent_api.check_bearer("Bearer " + t)
        self.assertLessEqual(self.keys.loads, 1)

    def test_c3_cache_expires_so_outside_changes_apply(self):
        t = agent_api.create_token()
        self.assertTrue(agent_api.check_bearer("Bearer " + t))
        self.keys.items.pop(agent_api.TOKEN_ID)                        # removed through another route
        self.assertTrue(agent_api.check_bearer("Bearer " + t))         # still cached inside the TTL
        with mock.patch.object(agent_api.time, "monotonic", return_value=time.monotonic() + agent_api.TOKEN_TTL + 1):
            self.assertFalse(agent_api.check_bearer("Bearer " + t))

    def test_c4_no_token_file_is_ever_written(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with mock.patch.dict(os.environ, {"OG_SETTINGS_DIR": d}):
            agent_api.create_token()
        self.assertEqual(os.listdir(d), [])


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
