"""Tests for the Campaign Builder HTTP API (dev/campaign_api.py + its hooks in server.py).

Run from dev/:  python -m unittest tests.test_campaign_api

The real server handler runs on an ephemeral port in a thread. No network (intel.sources.fetch is
stubbed) and no real build (server.run_generator is stubbed).
"""
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
if DEV not in sys.path:
    sys.path.insert(0, DEV)

import server                                          # noqa: E402
import campaign_api                                    # noqa: E402

SECRET = "sk-TESTKEY-0123456789abcdef"  # release-scan: allow
IOCS = [
    {"type": "ipv4", "value": "203.0.113.77", "role": "c2", "confidence": 80, "source": "t",
     "tags": [], "techniques": [], "first_seen": None, "note": "", "why": "test"},
    {"type": "domain", "value": "update.example.net", "role": "c2", "confidence": 70, "source": "t",
     "tags": [], "techniques": [], "first_seen": None, "note": "", "why": "test"},
    {"type": "ipv4", "value": "198.51.100.20", "role": "exfil", "confidence": 60, "source": "t",
     "tags": [], "techniques": [], "first_seen": None, "note": "", "why": "test"},
]


class ApiCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.tmp = tempfile.mkdtemp(prefix="ogcamp-")
        cls.libdir = os.path.join(cls.tmp, "lib")
        cls._env = mock.patch.dict(os.environ, {"OPENGENERATOR_CAMPAIGNS": cls.libdir})
        cls._env.start()

    @classmethod
    def tearDownClass(cls):
        cls._env.stop()
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # ---- helpers
    def req(self, method, path, body=None, headers=None, raw=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        h = dict(headers or {})
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        payload = r.read()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        c.close()
        return r.status, payload, hdrs

    def get(self, path):
        s, b, h = self.req("GET", path)
        return s, (json.loads(b) if b[:1] in (b"{", b"[") else b), h

    def post(self, path, body=None, **kw):
        s, b, h = self.req("POST", path, body, **kw)
        return s, (json.loads(b) if b[:1] in (b"{", b"[") else b)

    def compiled(self):
        s, d = self.post("/api/campaign/compile", {"iocs": IOCS, "name": "Test Campaign"})
        self.assertEqual(s, 200, d)
        return d["campaign"]


class TestCatalog(ApiCase):
    def test_feeds(self):
        s, d, _ = self.get("/api/intel/feeds")
        self.assertEqual(s, 200)
        ids = {f["id"] for f in d["feeds"]}
        self.assertTrue({"feodo", "otx", "url"} <= ids)
        for f in d["feeds"]:
            for k in ("id", "title", "group", "url", "needs_key", "key_env", "roles", "note"):
                self.assertIn(k, f)
        self.assertTrue(next(f for f in d["feeds"] if f["id"] == "otx")["needs_key"])

    def test_actions(self):
        s, d, _ = self.get("/api/campaign/actions")
        self.assertEqual(s, 200)
        self.assertGreater(len(d["actions"]), 5)
        keys = [(a["tactic"], a["token"]) for a in d["actions"]]
        self.assertEqual(keys, sorted(keys))
        a = d["actions"][0]
        for k in ("token", "title", "tactic", "techniques", "protocols", "summary", "params",
                  "src", "dst", "needs", "ot"):
            self.assertIn(k, a)
        self.assertTrue(all({"slug", "name", "id"} <= set(t) for t in d["tactics"]))

    def test_attack_search(self):
        s, d, _ = self.get("/api/campaign/attack?q=T1071")
        self.assertEqual(s, 200)
        self.assertTrue(0 < len(d["techniques"]) <= 40)
        self.assertTrue(all("T1071" in t["id"] for t in d["techniques"]))
        s, d, _ = self.get("/api/campaign/attack?q=phishing")
        self.assertTrue(any("hishing" in t["name"] for t in d["techniques"]))
        s, d, _ = self.get("/api/campaign/attack?q=%00%00zz")
        self.assertEqual((s, d["techniques"]), (200, []))
        s, d, _ = self.get("/api/campaign/attack")
        self.assertLessEqual(len(d["techniques"]), 40)


class TestIntel(ApiCase):
    def test_parse_text(self):
        s, d = self.post("/api/intel/parse", {"text": "c2: 203.0.113.9 and evil.example.org\n10.0.0.1\n",
                                              "filename": "../../etc/list.txt"})
        self.assertEqual(s, 200)
        self.assertEqual(d["count"], len(d["iocs"]))
        vals = {i["value"] for i in d["iocs"]}
        self.assertIn("evil.example.org", vals)
        self.assertNotIn("10.0.0.1", vals)
        self.assertTrue(any(r["value"] == "10.0.0.1" for r in d["dropped"]))
        self.assertIn(d["formats"], ("text", "csv", "stix", "misp", "otx", "threatfox"))

    def test_parse_hostile(self):
        for body in ({}, {"text": 5}, {"text": None}, [1], "x"):
            s, d = self.post("/api/intel/parse", body)
            self.assertEqual(s, 400, body)
            self.assertIn("error", d)
        s, d = self.post("/api/intel/parse", {"text": "a" * (1024 * 1024 + 10)})
        self.assertEqual(s, 413)
        s, d = self.post("/api/intel/parse", {"text": "x\x00y 203.0.113.9"})
        self.assertEqual(s, 200)

    def test_parse_stix_format(self):
        bundle = {"type": "bundle", "id": "bundle--1", "objects": [
            {"type": "indicator", "id": "indicator--1", "pattern": "[ipv4-addr:value = '203.0.113.50']",
             "pattern_type": "stix", "valid_from": "2026-01-01T00:00:00Z", "spec_version": "2.1",
             "created": "2026-01-01T00:00:00Z", "modified": "2026-01-01T00:00:00Z"}]}
        s, d = self.post("/api/intel/parse", {"text": json.dumps(bundle)})
        self.assertEqual((s, d["formats"]), (200, "stix"))

    def test_fetch_key_never_echoed(self):
        from intel import sources
        seen = {}

        def fake(feed_id, **kw):
            seen.update(kw, feed=feed_id)
            raise sources.FeedError("auth failed for key " + kw["key"])
        with mock.patch.object(sources, "fetch", fake):
            s, b, h = self.req("POST", "/api/intel/fetch", {"feed": "otx", "key": SECRET, "q": "c2"})
        self.assertEqual(s, 200)
        self.assertNotIn(SECRET.encode(), b)
        self.assertNotIn(SECRET, json.dumps(h))
        d = json.loads(b)
        self.assertEqual((d["iocs"], d["count"]), ([], 0))
        self.assertTrue(d["error"])
        self.assertEqual(seen["key"], SECRET)             # it did reach fetch()
        self.assertNotIn(SECRET, json.dumps(server.STATE, default=str))
        self.assertEqual(seen["q"], "c2")

    def test_fetch_ok_and_unexpected_error(self):
        from intel import sources, model
        ok = [model.new_ioc("ipv4", "203.0.113.5", role="c2"), model.new_ioc("ipv4", "192.168.1.1", role="c2")]
        with mock.patch.object(sources, "fetch", lambda feed_id, **kw: ok):
            s, d = self.post("/api/intel/fetch", {"feed": "feodo", "limit": 10, "key": SECRET})
        self.assertEqual(s, 200)
        self.assertEqual(d["count"], 1)
        self.assertEqual(d["iocs"][0]["value"], "203.0.113.5")
        self.assertEqual(len(d["dropped"]), 1)
        self.assertNotIn(SECRET, json.dumps(d))

        def boom(feed_id, **kw):
            raise RuntimeError("/Users/x/secret/path " + kw["key"])  # release-scan: allow
        with mock.patch.object(sources, "fetch", boom):
            s, b, _ = self.req("POST", "/api/intel/fetch", {"feed": "feodo", "key": SECRET})
        self.assertEqual(s, 200)
        self.assertNotIn(SECRET.encode(), b)
        self.assertNotIn(b"/Users/", b)  # release-scan: allow

    def test_fetch_bad_input(self):
        for body in ({}, {"feed": 3}, {"feed": "nope"}, {"feed": "otx", "key": 5},
                     {"feed": "otx", "limit": "many"}, {"feed": "otx", "q": ["a"]}, {"feed": "a" * 100}):
            s, d = self.post("/api/intel/fetch", body)
            self.assertEqual(s, 400, body)
            self.assertNotIn("Traceback", json.dumps(d))

    def test_offline_no_cache_is_inline_error(self):
        with mock.patch.dict(os.environ, {"OPENGENERATOR_CACHE": os.path.join(self.tmp, "nocache")}):
            s, d = self.post("/api/intel/fetch", {"feed": "feodo", "offline": True})
        self.assertEqual(s, 200)
        self.assertTrue(d["error"])


class TestCampaign(ApiCase):
    def test_compile_validate_estimate(self):
        camp = self.compiled()
        s, d = self.post("/api/campaign/compile", {"iocs": IOCS, "name": "T"})
        self.assertEqual(d["errors"], [])
        self.assertGreater(d["summary"]["stages"], 0)
        self.assertEqual(set(d["summary"]), {"stages", "actions", "iocs", "skipped"})
        self.assertTrue(d["explain"])
        s, d = self.post("/api/campaign/validate", {"campaign": camp})
        self.assertEqual((s, d["errors"]), (200, []))
        self.assertEqual(d["campaign"]["schema"], camp["schema"])
        s, d = self.post("/api/campaign/estimate", {"campaign": camp, "scale": 1.0})
        self.assertEqual(s, 200)
        for k in ("stages", "flows", "minutes_realistic", "minutes_fast", "errors"):
            self.assertIn(k, d)
        self.assertEqual(d["errors"], [])

    def test_preview_one_indicator(self):
        s, d = self.post("/api/campaign/preview", {"ioc": {"type": "ipv4", "value": "203.0.113.5", "role": "c2"}})
        self.assertEqual(s, 200)
        self.assertTrue(d["observable"])
        self.assertTrue(all(r["protocols"] and r["summary"] for r in d["actions"]))
        s, d = self.post("/api/campaign/observability", {"iocs": IOCS})
        self.assertTrue(d["plan"] and all({"name", "narrative", "actions"} <= set(p) for p in d["plan"]))
        s, d = self.post("/api/campaign/preview", {"ioc": "x"})
        self.assertEqual(s, 400)

    def test_compile_with_options(self):
        s, d = self.post("/api/campaign/compile", {"iocs": IOCS, "options": {"beacons_per_c2": 2}})
        self.assertEqual(s, 200)
        s, d = self.post("/api/campaign/compile", {"iocs": IOCS, "options": {"address_mode": "bogus"}})
        self.assertEqual(s, 400)
        self.assertIn("error", d)
        self.assertNotIn("Traceback", json.dumps(d))

    def test_compile_hostile(self):
        for body in ({}, {"iocs": "x"}, {"iocs": [1]}, {"iocs": [], "options": 3},
                     {"iocs": [], "name": 5}, {"iocs": [{"type": "ipv4", "value": "\x00"}]}):
            s, d = self.post("/api/campaign/compile", body)
            self.assertIn(s, (200, 400), body)
            self.assertNotIn("Traceback", json.dumps(d))

    def test_validate_errors(self):
        s, d = self.post("/api/campaign/validate", {"campaign": {"schema": "x"}})
        self.assertEqual(s, 200)
        self.assertTrue(d["errors"])
        self.assertIsNone(d["campaign"])
        s, d = self.post("/api/campaign/validate", {"campaign": [1, 2]})
        self.assertEqual(s, 200)
        self.assertTrue(d["errors"])
        s, d = self.post("/api/campaign/validate", {})
        self.assertEqual(s, 400)
        s, d = self.post("/api/campaign/estimate", {"campaign": {}, "scale": "x"})
        self.assertEqual(s, 400)
        s, d = self.post("/api/campaign/estimate", {"campaign": "junk"})
        self.assertEqual(s, 200)
        self.assertTrue(d["errors"])

    def test_bad_json_and_types(self):
        s, b, _ = self.req("POST", "/api/campaign/compile", raw=b"{not json")
        self.assertEqual(s, 400)
        self.assertIn("error", json.loads(b))
        s, d = self.post("/api/campaign/compile", [1, 2, 3])
        self.assertEqual(s, 400)


class TestLimits(ApiCase):
    def test_oversize_body_413(self):
        s, b, _ = self.req("POST", "/api/intel/parse", raw=b"{" + b"a" * (2 * 1024 * 1024 + 100))
        self.assertEqual(s, 413)
        self.assertIn("error", json.loads(b))
        # server still healthy afterwards
        self.assertEqual(self.get("/api/intel/feeds")[0], 200)

    def test_oversize_generate_413(self):
        s, b, _ = self.req("POST", "/api/generate", raw=b" " * (2 * 1024 * 1024 + 5))
        self.assertEqual(s, 413)

    def test_foreign_origin_rejected(self):
        for path, body in (("/api/campaign/compile", {"iocs": []}), ("/api/intel/parse", {"text": "x"}),
                           ("/api/campaign/library/save", {"campaign": {}}), ("/api/generate", {})):
            s, b, _ = self.req("POST", path, body, headers={"Origin": "http://evil.example"})
            self.assertEqual(s, 403, path)
        s, b, _ = self.req("POST", "/api/campaign/validate", {"campaign": {}},
                           headers={"Origin": "http://127.0.0.1:%d" % self.port})
        self.assertEqual(s, 200)

    def test_foreign_host_rejected(self):
        s, b, _ = self.req("GET", "/api/campaign/library", headers={"Host": "evil.example"})
        self.assertEqual(s, 403)


class TestLibrary(ApiCase):
    def setUp(self):
        shutil.rmtree(self.libdir, ignore_errors=True)

    def test_round_trip(self):
        camp = self.compiled()
        s, d = self.post("/api/campaign/library/save", {"campaign": camp})
        self.assertEqual(s, 200, d)
        cid = d["id"]
        self.assertRegex(cid, r"^[a-z0-9_-]{1,64}$")
        path = d["path"]
        self.assertTrue(path.startswith(self.libdir))
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
        self.assertEqual(oct(os.stat(self.libdir).st_mode & 0o777), "0o700")
        self.assertEqual([f for f in os.listdir(self.libdir) if f.startswith(".tmp")], [])
        # exists -> 409, overwrite -> 200
        s, d2 = self.post("/api/campaign/library/save", {"campaign": camp})
        self.assertEqual(s, 409)
        s, d2 = self.post("/api/campaign/library/save", {"campaign": camp, "overwrite": True})
        self.assertEqual((s, d2["id"]), (200, cid))
        # list
        s, lst, _ = self.get("/api/campaign/library")
        self.assertEqual(lst["dir"], self.libdir)
        row = lst["campaigns"][0]
        self.assertEqual(row["id"], cid)
        for k in ("id", "name", "description", "stages", "iocs", "modified", "size"):
            self.assertIn(k, row)
        self.assertEqual(row["name"], "Test Campaign")
        # load
        s, d = self.post("/api/campaign/library/load", {"id": cid})
        self.assertEqual(s, 200)
        self.assertEqual(d["campaign"]["meta"]["name"], "Test Campaign")
        # export
        s, b, h = self.req("GET", "/campaign/export?id=" + cid)
        self.assertEqual(s, 200)
        self.assertIn("attachment", h["content-disposition"])
        self.assertIn(cid + ".campaign.json", h["content-disposition"])
        exported = b.decode()
        # import (does not save)
        s, d = self.post("/api/campaign/library/import", {"text": exported})
        self.assertEqual((s, d["errors"], d["id"]), (200, [], None))
        self.assertEqual(d["campaign"]["meta"]["name"], "Test Campaign")
        n_before = len(os.listdir(self.libdir))
        self.post("/api/campaign/library/import", {"text": exported})
        self.assertEqual(len(os.listdir(self.libdir)), n_before)
        # delete
        s, d = self.post("/api/campaign/library/delete", {"id": cid})
        self.assertEqual((s, d), (200, {"ok": True}))
        self.assertEqual(self.post("/api/campaign/library/delete", {"id": cid})[0], 404)
        self.assertEqual(self.post("/api/campaign/library/load", {"id": cid})[0], 404)
        self.assertEqual(self.req("GET", "/campaign/export?id=" + cid)[0], 404)
        self.assertEqual(self.get("/api/campaign/library")[1]["campaigns"], [])

    def test_save_invalid(self):
        s, d = self.post("/api/campaign/library/save", {"campaign": {"schema": "nope"}})
        self.assertEqual(s, 400)
        self.assertTrue(d["errors"])
        self.assertEqual(self.post("/api/campaign/library/save", {})[0], 400)
        self.assertEqual(self.post("/api/campaign/library/save", {"campaign": 5})[0], 400)

    def test_import_invalid(self):
        for text in ("", "not json", "[1,2]", '{"schema": "x"}', "{" * 50):
            s, d = self.post("/api/campaign/library/import", {"text": text})
            self.assertEqual(s, 200, text)
            self.assertTrue(d["errors"], text)
            self.assertIsNone(d["campaign"])
        self.assertEqual(self.post("/api/campaign/library/import", {"text": 4})[0], 400)

    def test_bad_ids(self):
        bad = ["../x", "..", "a/b", "A", "x" * 65, "", "a b", "x\x00y", "x\n", "/etc/passwd",
               "..%2f..%2fetc", "a.campaign.json", 5, None, ["a"]]
        for i in bad:
            for ep in ("load", "delete"):
                s, d = self.post("/api/campaign/library/" + ep, {"id": i})
                self.assertEqual(s, 400, (ep, i))
                self.assertNotIn("Traceback", json.dumps(d))
        for q in ("../x", "..%2Fserver", "%00", "a%00b", "", "A", "x%0A"):
            s, b, _ = self.req("GET", "/campaign/export?id=" + q)
            self.assertIn(s, (400, 404), q)
        # a file outside the library is never reachable
        outside = os.path.join(self.tmp, "secret.campaign.json")
        with open(outside, "w") as f:
            f.write("{}")
        self.assertEqual(self.req("GET", "/campaign/export?id=..%2Fsecret")[0], 400)
        self.assertTrue(os.path.exists(outside))

    def test_listing_ignores_junk_and_symlinks(self):
        camp = self.compiled()
        self.post("/api/campaign/library/save", {"campaign": camp})
        with open(os.path.join(self.libdir, "junk.campaign.json"), "w") as f:
            f.write("not json")
        with open(os.path.join(self.libdir, "Bad Name.campaign.json"), "w") as f:
            f.write("{}")
        os.symlink(os.path.join(self.tmp, "x"), os.path.join(self.libdir, "link.campaign.json"))
        s, lst, _ = self.get("/api/campaign/library")
        self.assertEqual([r["id"] for r in lst["campaigns"]], ["test-campaign"])


class TestStatic(ApiCase):
    def test_allow_list(self):
        for name, ctype in (("campaigns.js", "text/javascript"), ("campaigns-editor.js", "text/javascript"),
                            ("campaigns-library.js", "text/javascript"), ("campaigns.css", "text/css")):
            s, b, h = self.req("GET", "/ui/" + name)
            if os.path.exists(os.path.join(server.UI_DIR, name)):
                self.assertEqual(s, 200, name)
                self.assertTrue(h["content-type"].startswith(ctype), name)
                self.assertEqual(h["cache-control"], "no-cache")
            else:
                self.assertEqual(s, 404, name)

    def test_served_with_temp_ui_dir(self):
        d = tempfile.mkdtemp(dir=self.tmp)
        with open(os.path.join(d, "campaigns.js"), "w") as f:
            f.write("window.x=1;")
        with open(os.path.join(d, "campaigns.css"), "w") as f:
            f.write("a{}")
        with open(os.path.join(d, "secret.txt"), "w") as f:
            f.write("no")
        with mock.patch.object(server, "UI_DIR", d):
            s, b, h = self.req("GET", "/ui/campaigns.js")
            self.assertEqual((s, b), (200, b"window.x=1;"))
            self.assertTrue(h["content-type"].startswith("text/javascript"))
            self.assertEqual(h["cache-control"], "no-cache")
            s, b, h = self.req("GET", "/ui/campaigns.css")
            self.assertTrue(h["content-type"].startswith("text/css"))
            self.assertEqual(self.req("GET", "/ui/campaigns-editor.js")[0], 404)   # allowed name, file missing
            self.assertEqual(self.req("GET", "/ui/secret.txt")[0], 404)

    def test_traversal_404(self):
        for p in ("/ui/../server.py", "/ui/..%2Fserver.py", "/ui/%2e%2e/server.py", "/ui/", "/ui/index.html",
                  "/ui/campaigns.js/", "/ui/campaigns.js%00.png", "/ui/CAMPAIGNS.JS", "/ui/campaigns.js/../../server.py",
                  "/ui/header-logo.png", "/ui/x%00"):
            self.assertEqual(self.req("GET", p)[0], 404, p)

    def test_existing_routes_unchanged(self):
        self.assertEqual(self.req("GET", "/")[0], 200)
        self.assertEqual(self.req("GET", "/api/modules")[0], 200)
        self.assertEqual(self.req("GET", "/nope")[0], 404)


class FakeRun:
    def __init__(self):
        self.calls = []
        self.ev = threading.Event()

    def __call__(self, *a, **kw):
        self.calls.append((a, kw))
        self.ev.set()


class TestGenerate(ApiCase):
    def run_gen(self, body):
        fake = FakeRun()
        with mock.patch.object(server, "run_generator", fake):
            s, d = self.post("/api/generate", body)
            if s == 200:
                self.assertTrue(fake.ev.wait(5))
        return s, d, fake

    def test_no_campaign_fields_unchanged(self):
        s, d, fake = self.run_gen({"scale": 0.01, "out_dir": self.tmp, "modules": []})
        self.assertEqual(s, 200)
        self.assertEqual(len(fake.calls), 1)
        a, kw = fake.calls[0]
        self.assertEqual(len(a), 13)                     # exactly the historical positional arguments
        self.assertEqual(kw, {})
        self.assertEqual(d["modules"], [])
        self.assertEqual(set(d), {"ok", "out_dir", "modules", "user_net", "server_net"})

    def test_invalid_campaign_400(self):
        for camps in ([{"schema": "x"}], ["str"], "nope", {"a": 1}, [None]):
            s, d, fake = self.run_gen({"campaigns": camps, "out_dir": self.tmp})
            self.assertEqual(s, 400, camps)
            self.assertIn("error", d)
            self.assertEqual(fake.calls, [])
        s, d, fake = self.run_gen({"campaigns": [{"schema": "x"}], "out_dir": self.tmp})
        self.assertTrue(d["errors"])

    def test_too_many_campaigns(self):
        c = self.compiled()
        s, d, fake = self.run_gen({"campaigns": [c] * 5, "out_dir": self.tmp})
        self.assertEqual(s, 400)
        self.assertEqual(fake.calls, [])

    def test_real_requires_confirm(self):
        c = self.compiled()
        s, d, fake = self.run_gen({"campaigns": [c], "address_mode": "real", "out_dir": self.tmp})
        self.assertEqual(s, 400)
        self.assertIn("confirm", d["error"])
        self.assertEqual(fake.calls, [])
        real = json.loads(json.dumps(c))
        real["options"]["address_mode"] = "real"
        s, d, fake = self.run_gen({"campaigns": [real], "out_dir": self.tmp})
        self.assertEqual(s, 400)
        s, d, fake = self.run_gen({"campaigns": [c], "address_mode": "real", "confirm_real_addresses": "yes",
                                   "out_dir": self.tmp})
        self.assertEqual(s, 400)
        s, d, fake = self.run_gen({"campaigns": [c], "address_mode": "sideways", "out_dir": self.tmp})
        self.assertEqual(s, 400)

    def test_valid_campaign_passed_through(self):
        c = self.compiled()
        s, d, fake = self.run_gen({"campaigns": [c], "address_mode": "mapped", "modules": None,
                                   "scale": 0.01, "out_dir": self.tmp})
        self.assertEqual(s, 200, d)
        a, kw = fake.calls[0]
        self.assertEqual(len(a), 16)
        camps, mode, confirm = a[13:]
        self.assertEqual(mode, "mapped")
        self.assertIs(confirm, False)
        self.assertEqual(len(camps), 1)
        self.assertEqual(camps[0]["meta"]["name"], "Test Campaign")
        self.assertIsNone(a[4])                           # modules=null keeps "all modules" semantics
        s, d, fake = self.run_gen({"campaigns": [c], "address_mode": "real", "confirm_real_addresses": True,
                                   "modules": ["ransomware"] if False else [], "out_dir": self.tmp})
        self.assertEqual(s, 200)
        a, _ = fake.calls[0]
        self.assertEqual((a[14], a[15]), ("real", True))
        self.assertEqual(a[4], [])

    def test_run_generator_forwards_to_build(self):
        """run_generator hands the campaign fields to build() and surfaces the campaign summary."""
        captured = {}

        def fake_build(**kw):
            captured.update(kw)
            return {"nets": {}, "modules": [], "module_names": [], "by_category": {}, "all_modules": [],
                    "packets": 1, "bytes": 100, "protocols": [], "iocs": None,
                    "pcap": os.path.join(self.tmp, "x.pcap"),
                    "campaign": {"built": ["a"], "exports": {}, "errors": [], "actions": 2, "emitted": 2},
                    "campaign_console": ["line one", "line two"]}
        c = self.compiled()
        out = tempfile.mkdtemp(dir=self.tmp)
        with mock.patch.object(server.opengenerator_build, "build", fake_build):
            server.run_generator(0.001, out, False, False, [], None, None, None, None, None, None, None,
                                 None, [c], "mapped", False)
        self.assertEqual(captured["campaigns"], [c])
        self.assertEqual((captured["address_mode"], captured["confirm_real_addresses"]), ("mapped", False))
        s, st, _ = self.get("/api/status")
        self.assertEqual(st["campaign"]["built"], ["a"])
        self.assertEqual(st["campaign"]["console"], ["line one", "line two"])
        self.assertEqual(st["summary"]["campaign_console"], ["line one", "line two"])
        for k in ("running", "done", "error", "packets", "log", "outputs", "pcap", "report_ready"):
            self.assertIn(k, st)
        # a following run without campaigns drops the campaign result and passes no campaign kwargs
        captured.clear()

        def plain_build(**kw):
            captured.update(kw)
            return {"nets": {}, "modules": [], "module_names": [], "by_category": {}, "all_modules": [],
                    "packets": 1, "bytes": 100, "protocols": [], "iocs": None,
                    "pcap": os.path.join(self.tmp, "x.pcap")}
        with mock.patch.object(server.opengenerator_build, "build", plain_build):
            server.run_generator(0.001, out, False, False, [], None, None, None, None, None, None, None, None)
        self.assertNotIn("campaigns", captured)
        st = self.get("/api/status")[1]
        self.assertNotIn("campaign", st)
        self.assertNotIn("campaign", st["summary"])


if __name__ == "__main__":
    unittest.main()
