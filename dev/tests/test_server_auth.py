"""Server gate: every POST needs the page cookie (default deny), the cookie is handed out once against a launch nonce,
and Host / Origin / Sec-Fetch-Site must match this page. Review findings H1, H2, M1, M2, L3."""
import ast
import http.client
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_agent_api import Base  # noqa: E402 - sys.path is set first

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTE_FILES = ("server.py", "campaign_api.py", "keys_api.py", "sessions_api.py", "settings_store.py",
               "captures_store.py", "updater.py", "agent_api.py")


def api_routes():
    """Every '/api/...' string constant in the modules that route requests, so a new route is covered unseen."""
    found = set()
    for name in ROUTE_FILES:
        with open(os.path.join(DEV, name)) as fh:
            for n in ast.walk(ast.parse(fh.read())):
                if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith("/api/") \
                        and n.value.count("/") >= 2 and " " not in n.value and not n.value.endswith("/"):
                    found.add(n.value)
    return sorted(found)


class Gate(Base):
    def raw(self, method, path, headers=None, body=b"{}"):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=10)
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        c.request(method, path, body=body if method == "POST" else None, headers=h)
        r = c.getresponse()
        r.read()
        c.close()
        return r.status

    def test_route_table_is_not_empty(self):
        routes = api_routes()
        self.assertGreater(len(routes), 40)
        self.assertIn("/api/update/install", routes)
        self.assertIn("/api/keys/save", routes)

    def test_every_post_route_refuses_a_caller_without_the_cookie(self):
        for p in api_routes():
            self.assertEqual(self.raw("POST", p), 403, p)
            self.assertEqual(self.raw("POST", p, {"Cookie": "og_ui=nope"}), 403, p)

    def test_agent_token_save_needs_the_cookie(self):
        st, _ = self.call("POST", "/api/keys/save", {"id": "agent:token", "key": "ogagent_x"})
        self.assertEqual(st, 403)
        st, _ = self.call("POST", "/api/keys/forget", {"id": "agent:token"})
        self.assertEqual(st, 403)

    def test_update_install_and_check_need_the_cookie(self):
        self.assertEqual(self.call("POST", "/api/update/install", {})[0], 403)
        self.assertEqual(self.call("GET", "/api/update/check")[0], 403)
        self.assertNotEqual(self.call("GET", "/api/update/check", cookie="og_ui=" + self.server.UI_SECRET)[0], 403)

    def test_read_routes_that_answer_for_any_path_need_the_cookie(self):
        for p in ("/profile?path=/etc/hosts", "/recipe?path=/x", "/profile/export?path=/x", "/profile/summary?path=/x",
                  "/api/replay/preflight?pcap=/x"):
            self.assertEqual(self.call("GET", p)[0], 403, p)

    def test_a_handler_fault_reply_names_nothing(self):
        import server
        with mock.patch.object(server.Handler, "_blocked", side_effect=ValueError("/srv/hiddendir/secret")):
            st, js = self.call("GET", "/api/status")
        self.assertEqual(st, 400)
        self.assertNotIn("hiddendir", json.dumps(js))

    def test_a_bearer_token_never_buys_a_non_agent_route(self):
        self.assertEqual(self.call("POST", "/api/keys/save", {}, bearer=self.token)[0], 403)

    def test_cookie_with_a_cross_site_header_or_other_port_is_refused(self):
        ck = {"Cookie": "og_ui=" + self.server.UI_SECRET}
        p = "/api/settings"
        self.assertNotEqual(self.raw("POST", p, ck), 403)
        for site in ("same-site", "cross-site", "none"):
            self.assertEqual(self.raw("POST", p, dict(ck, **{"Sec-Fetch-Site": site})), 403, site)
        self.assertNotEqual(self.raw("POST", p, dict(ck, **{"Sec-Fetch-Site": "same-origin"})), 403)
        port = self.srv.server_port
        self.assertNotEqual(self.raw("POST", p, dict(ck, Origin="http://localhost:%d" % port)), 403)
        for origin in ("http://localhost:%d" % (port + 1), "http://127.0.0.1", "https://localhost:%d" % port,
                       "http://localhost:80", "null", "http://evil.example"):
            self.assertEqual(self.raw("POST", p, dict(ck, Origin=origin)), 403, origin)
        self.assertEqual(self.raw("POST", p, dict(ck, Host="localhost:%d" % (port + 1))), 403)
        self.assertEqual(self.raw("GET", "/api/status", {"Host": "127.0.0.1:%d" % (port + 1)}), 403)
        self.assertEqual(self.raw("GET", "/api/status", {"Host": "127.0.0.1:%d" % port}), 200)


if __name__ == "__main__":
    unittest.main()
