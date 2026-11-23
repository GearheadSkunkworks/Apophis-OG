"""Network hardening: SSRF, size caps, sensor addresses, server request guards.

No real network: sockets, getaddrinfo and urlopen are mocked; the server checks use an in-process
server on 127.0.0.1 with an ephemeral port.
"""
import gzip
import http.client
import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from http.server import ThreadingHTTPServer
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import campaign_api  # noqa: E402
import server  # noqa: E402
from intel import cache, sources  # noqa: E402
from sensorops import _util  # noqa: E402
try:
    from sensorops.providers.network_sensor import NetworkSensorProvider  # noqa: E402
except ImportError:                                  # public builds do not ship the vendor connector
    NetworkSensorProvider = None


def setUpModule():
    if NetworkSensorProvider is None:
        raise unittest.SkipTest("the sensor connector is not installed")


def gai(*addrs):
    return lambda host, port=None, *a, **k: [(2, 1, 6, "", (x, port or 443)) for x in addrs]


class FakeResp:
    def __init__(self, body=b"", headers=None, chunks=None):
        self.headers = http.client.HTTPMessage()
        for k, v in (headers or {}).items():
            self.headers[k] = v
        self._chunks = list(chunks) if chunks is not None else [body]

    def read(self, n=-1):
        return self._chunks.pop(0) if self._chunks else b""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_opener(resp):
    op = mock.Mock()
    op.open.return_value = resp
    return mock.patch.object(urllib.request, "build_opener", return_value=op)


# ---------------------------------------------------------------- gap 2: user URL feed
class TestUserUrl(unittest.TestCase):
    def test_rejected_urls(self):
        bad = ["http://example.com/", "https://u:p@example.com/", "https://:p@example.com/",
               "https://example.com@127.0.0.1/", "https://example.com:8443/", "https://example.com:22/",
               "https://169.254.169.254/latest/meta-data", "https://[::ffff:169.254.169.254]/",
               "https://[::ffff:7f00:1]/", "https://[64:ff9b::7f00:1]/", "https://[2002:7f00:1::]/",
               "https://[fd00:ec2::254]/", "https://100.100.100.200/",
               "https://2130706433/", "https://0x7f.1/", "https://0177.0.0.1/", "https://127.1/",
               "https://017700000001/", "https://0x7f000001/", "https://[fe80::1%25eth0]/",
               "https://localhost./", "ftp://example.com/", "file:///etc/passwd"]
        with mock.patch("socket.getaddrinfo", side_effect=AssertionError("no DNS for literals")) as g:
            for u in bad:
                g.side_effect = lambda host, port=None, *a, **k: [(2, 1, 6, "", ("127.0.0.1", port))]
                with self.assertRaises(sources.FeedError, msg=u):
                    sources.check_user_url(u)

    def test_names_resolving_private_are_refused(self):
        for ip in ("127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "::ffff:10.0.0.1", "0.0.0.0", "224.0.0.1"):
            with mock.patch("socket.getaddrinfo", gai(ip)):
                with self.assertRaises(sources.FeedError, msg=ip):
                    sources.check_user_url("https://feed.example/x")

    def test_port_443_only_unless_allowed(self):
        with mock.patch("socket.getaddrinfo", gai("93.184.216.34")):
            self.assertTrue(sources.check_user_url("https://ok.example:443/x"))
            with self.assertRaises(sources.FeedError):
                sources.check_user_url("https://ok.example:8443/x")
            self.assertTrue(sources.check_user_url("https://ok.example:8443/x", allow_ports=(8443,)))

    def test_connect_pins_the_validated_address(self):
        """The socket is opened to the address that passed the check, and a later different answer is not used."""
        answers = iter([["93.184.216.34"], ["127.0.0.1"]])
        seen = []

        def g(host, port=None, *a, **k):
            return [(2, 1, 6, "", (x, port)) for x in next(answers)]

        conn = sources._make_conn_class(True)("rebind.example", 443, timeout=1)
        conn._context = mock.Mock()
        with mock.patch("socket.getaddrinfo", g), \
                mock.patch("socket.create_connection", side_effect=lambda addr, t: seen.append(addr) or mock.Mock()):
            conn.connect()
        self.assertEqual(seen, [("93.184.216.34", 443)])
        conn2 = sources._make_conn_class(True)("rebind.example", 443, timeout=1)
        with mock.patch("socket.getaddrinfo", gai("127.0.0.1")), \
                mock.patch("socket.create_connection", side_effect=AssertionError("must not connect")):
            with self.assertRaises(sources.FeedError):
                conn2.connect()

    def test_every_redirect_hop_is_revalidated(self):
        import urllib.request as ur
        h = sources._Redirect([], ssrf=True)
        req = ur.Request("https://a.example/x")
        for new in ("http://b.example/", "https://127.0.0.1/", "https://169.254.169.254/",
                    "https://u:p@b.example/", "https://b.example:8443/", "https://2130706433/"):
            with mock.patch("socket.getaddrinfo", gai("93.184.216.34")):
                with self.assertRaises(urllib.error.URLError, msg=new):
                    h.redirect_request(req, None, 302, "Found", {}, new)
        with mock.patch("socket.getaddrinfo", gai("10.0.0.9")):
            with self.assertRaises(urllib.error.URLError):
                h.redirect_request(req, None, 302, "Found", {}, "https://internal.example/")
        with mock.patch("socket.getaddrinfo", gai("93.184.216.34")):
            self.assertIsNotNone(h.redirect_request(req, None, 302, "Found", {}, "https://c.example/y"))

    def test_redirect_limit_and_no_proxy(self):
        self.assertLessEqual(sources._Redirect.max_redirections, 3)
        seen = {}
        real = urllib.request.build_opener

        def spy(*handlers):
            seen["h"] = handlers
            return real(*handlers)
        with mock.patch.object(urllib.request, "build_opener", spy), \
                mock.patch.object(urllib.request.OpenerDirector, "open", side_effect=urllib.error.URLError("x")):
            with self.assertRaises(sources.FeedError):
                sources.http_get("https://ok.example/", ssrf=True)
        self.assertTrue(any(isinstance(x, urllib.request.ProxyHandler) and not x.proxies for x in seen["h"]))

    def test_redirect_body_never_read(self):
        h = sources._Redirect([], ssrf=False)
        fp = mock.Mock()
        fp.read = lambda *a: b"x" * 10
        req = urllib.request.Request("https://a.example/x")
        h.redirect_request(req, fp, 302, "Found", {}, "https://a.example/y")
        self.assertEqual(fp.read(), b"")

    def test_tls_verification_on(self):
        ctx = sources._ssl_context()
        import ssl
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)

    def test_fetch_url_feed_never_reaches_network_for_bad_url(self):
        with mock.patch.object(sources, "http_get", side_effect=AssertionError("no fetch")):
            with self.assertRaises(sources.FeedError):
                sources.fetch("url", cache=False, url="https://127.0.0.1/x")


# ---------------------------------------------------------------- gaps 3 and 4: size
class TestSizeCaps(unittest.TestCase):
    def test_gzip_bomb(self):
        bomb = gzip.compress(b"A" * (3 * 1024 * 1024), 9)
        self.assertLess(len(bomb), 20000)
        with self.assertRaises(sources.FeedError):
            sources.unpack(bomb, cap=1024 * 1024)
        with fake_opener(FakeResp(bomb, {"Content-Encoding": "gzip"})):
            with self.assertRaises(sources.FeedError):
                sources.http_get("https://ok.example/", max_bytes=1024 * 1024)
        self.assertEqual(sources.unpack(gzip.compress(b"hello"), cap=100), b"hello")
        self.assertEqual(sources.unpack(gzip.compress(b"hi"), 100, "gzip"), b"hi")

    def test_deflate_bomb(self):
        import zlib
        with self.assertRaises(sources.FeedError):
            sources.unpack(zlib.compress(b"A" * 3000000), 1000, "deflate")

    def test_zip_bomb(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("a.txt", b"A" * (3 * 1024 * 1024))
        with self.assertRaises(sources.FeedError):
            sources.unpack(buf.getvalue(), cap=1024 * 1024)
        ok = io.BytesIO()
        with zipfile.ZipFile(ok, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("a.txt", b"198.51.100.7\n")
        self.assertEqual(sources.unpack(ok.getvalue(), cap=1024), b"198.51.100.7\n")

    def test_zip_with_lying_header(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("a.txt", b"A" * 5000)
        raw = bytearray(buf.getvalue())
        # patch the uncompressed size in local and central headers to a small lie
        size = (5000).to_bytes(4, "little")
        lie = (10).to_bytes(4, "little")
        i = 0
        while True:
            i = raw.find(size, i)
            if i < 0:
                break
            raw[i:i + 4] = lie
            i += 4
        with self.assertRaises(sources.FeedError):
            sources.unpack(bytes(raw), cap=100)

    def test_content_length_over_cap_refused_without_reading(self):
        r = FakeResp(chunks=[b"x"], headers={"Content-Length": str(10 ** 9)})
        r.read = mock.Mock(side_effect=AssertionError("must not read"))
        with fake_opener(r):
            with self.assertRaises(sources.FeedError):
                sources.http_get("https://ok.example/", max_bytes=1000)

    def test_content_length_lie_and_chunked_stop_at_cap(self):
        chunks = [b"x" * 65536] * 40                         # declared small, delivers 2.5 MB
        r = FakeResp(chunks=chunks, headers={"Content-Length": "10"})
        with fake_opener(r):
            with self.assertRaises(sources.FeedError):
                sources.http_get("https://ok.example/", max_bytes=300000)
        self.assertGreater(len(r._chunks), 30)               # stopped reading early
        r2 = FakeResp(chunks=chunks, headers={"Transfer-Encoding": "chunked"})
        with fake_opener(r2):
            with self.assertRaises(sources.FeedError):
                sources.http_get("https://ok.example/", max_bytes=300000)

    def test_slow_body_deadline(self):
        r = FakeResp(chunks=[b"x"] * 50)
        clock = iter(range(0, 1000, 20))
        with fake_opener(r), mock.patch.object(sources.time, "monotonic", lambda: next(clock)):
            with self.assertRaises(sources.FeedError):
                sources.http_get("https://ok.example/", deadline=60)

    def test_normal_body_and_http_refused(self):
        with fake_opener(FakeResp(b"abc", {"Content-Length": "3"})):
            self.assertEqual(sources.http_get("https://ok.example/"), b"abc")
        with self.assertRaises(sources.FeedError):
            sources.http_get("http://ok.example/")


# ---------------------------------------------------------------- gap 5: fresh
class TestFresh(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        p = mock.patch.dict(os.environ, {"OPENGENERATOR_CACHE": self.tmp.name})
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(self.tmp.cleanup)

    def test_fresh_bypasses_cache_read_via_api(self):
        calls = []

        def fake(url, **k):
            calls.append(url)
            return b'{"blocklist": [{"ip_address": "198.51.100.5", "port": 443, "status": "online", "malware": "x"}]}'
        with mock.patch.object(sources, "http_get", fake):
            s, d = campaign_api.intel_fetch({"feed": "feodo"})
            self.assertEqual((s, len(calls)), (200, 1))
            campaign_api.intel_fetch({"feed": "feodo"})
            self.assertEqual(len(calls), 1)                         # served from cache
            campaign_api.intel_fetch({"feed": "feodo", "cache": False})
            self.assertEqual(len(calls), 1)                         # not a supported option: cache still used
            campaign_api.intel_fetch({"feed": "feodo", "fresh": True})
            self.assertEqual(len(calls), 2)
        for bad in ({"fresh": "yes"}, {"fresh": 1}, {"fresh": True, "offline": True}, {"offline": "x"}):
            with self.assertRaises(campaign_api.ApiError):
                campaign_api.intel_fetch(dict(bad, feed="feodo"))


# ---------------------------------------------------------------- gap 1: sensor addresses
class TestSensorAddress(unittest.TestCase):
    def test_names_resolving_to_loopback_or_link_local_refused(self):
        for ip in ("127.0.0.1", "127.9.9.9", "::1", "169.254.169.254", "fe80::1", "0.0.0.0", "224.0.0.1",
                   "::ffff:127.0.0.1"):
            with mock.patch("socket.getaddrinfo", gai(ip)):
                with self.assertRaises(campaign_api.ApiError, msg=ip) as c:
                    campaign_api._sensor_target({"sensor": "lab-sensor.example.net", "key": "K"})
                self.assertEqual(c.exception.status, 400)
        # one bad answer among good ones is enough
        with mock.patch("socket.getaddrinfo", gai("10.0.0.5", "127.0.0.1")):
            with self.assertRaises(campaign_api.ApiError):
                campaign_api._sensor_target({"sensor": "multi.example.net:8443", "key": "K"})

    def test_private_targets_allowed(self):
        for ip in ("10.0.0.5", "172.16.4.4", "192.168.1.9", "100.64.0.1", "fd00::5"):
            with mock.patch("socket.getaddrinfo", gai(ip)):
                self.assertEqual(campaign_api._sensor_target({"sensor": "lab.example.net", "key": "K"})[0],
                                 "lab.example.net")
        self.assertEqual(campaign_api._sensor_target({"sensor": "10.0.0.5:8443", "key": "K"})[0], "10.0.0.5:8443")

    def test_unresolvable_name_is_not_a_400(self):
        with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror("nope")):
            self.assertEqual(campaign_api._sensor_target({"sensor": "gone.example.net", "key": "K"})[0],
                             "gone.example.net")
        with self.assertRaises(LookupError):
            _util.resolve_sensor("gone.example.net", getaddrinfo=mock.Mock(side_effect=socket.gaierror("x")))

    def test_request_is_pinned_to_the_resolved_address(self):
        prov = NetworkSensorProvider("rebind.example.net:8443", "SECRETKEY")
        captured = {}

        class R:
            status = 200
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def geturl(s): return captured["req"].full_url
            def read(s, n=-1): return b'{"hostname": "h"}'

        def fake_open(req, timeout=None, context=None):
            captured["req"] = req
            return R()
        answers = iter([["10.1.1.1"], ["127.0.0.1"]])
        with mock.patch("socket.getaddrinfo", lambda h, p=None, *a, **k: [(2, 1, 6, "", (next(answers)[0], p))]), \
                mock.patch.object(urllib.request, "urlopen", fake_open):
            prov._req("/extra" + "hop")
        req = captured["req"]
        self.assertEqual(req.full_url, "https://10.1.1.1:8443/api/v1/extra" + "hop")
        self.assertEqual(req.get_header("Host"), "rebind.example.net:8443")
        self.assertIn("Authorization", req.unredirected_hdrs.keys() | {k.capitalize() for k in req.unredirected_hdrs})
        self.assertNotIn("Authorization", req.headers)           # not carried across a redirect

    def test_provider_refuses_rebound_loopback_without_connecting(self):
        prov = NetworkSensorProvider("rebind.example.net", "SECRETKEY")
        with mock.patch("socket.getaddrinfo", gai("127.0.0.1")), \
                mock.patch.object(urllib.request, "urlopen", side_effect=AssertionError("must not connect")):
            with self.assertRaises(urllib.error.URLError) as c:
                prov._req("/extra" + "hop")
        self.assertNotIn("SECRETKEY", str(c.exception))

    def test_redirect_from_sensor_is_an_error(self):
        prov = NetworkSensorProvider("10.0.0.5", "K")

        class R:
            status = 200
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def geturl(s): return "https://elsewhere.example/"
            def read(s, n=-1): return b"{}"
        with mock.patch.object(urllib.request, "urlopen", lambda *a, **k: R()):
            with self.assertRaises(urllib.error.URLError):
                prov._req("/extra" + "hop")

    def test_odd_spellings(self):
        for a in ("127.1", "2130706433", "0x7f.1", "localhost", "a.localhost", "LOCALHOST:443", "[::1]",
                  "[::ffff:127.0.0.1]", "169.254.169.254", "0.0.0.0", "[fe80::1]"):
            with self.assertRaises(ValueError, msg=a):
                _util.resolve_sensor(a, getaddrinfo=mock.Mock(side_effect=AssertionError("no DNS")))
        for a in ("user@host", "https://host", "host/path", "host?x", "ho st", "host:99999", ""):
            with self.assertRaises(ValueError, msg=a):
                _util.valid_sensor(a)


# ---------------------------------------------------------------- API input caps
class TestApiCaps(unittest.TestCase):
    def test_nesting_and_size(self):
        deep = cur = []
        for _ in range(60):
            nxt = []
            cur.append(nxt)
            cur = nxt
        r = campaign_api.route_post("/api/campaign/validate", {"campaign": deep})
        self.assertEqual(r[0], 400)
        wide = {"campaign": [0] * (campaign_api.MAX_NODES + 1)}
        self.assertEqual(campaign_api.route_post("/api/campaign/validate", wide)[0], 413)
        big = {"campaign": "x" * (campaign_api.MAX_STR + 1)}
        self.assertEqual(campaign_api.route_post("/api/campaign/validate", big)[0], 413)
        r = campaign_api.route_post("/api/campaign/compile", {"iocs": [{}] * (campaign_api.MAX_IOCS + 1)})
        self.assertEqual(r[0], 400)

    def test_long_query_refused(self):
        r = campaign_api.route_get("/api/campaign/attack", "q=" + "a" * 5000, "/nonexistent")
        self.assertEqual(r[0], 414)

    def test_static_allow_list(self):
        for name in ("../server.py", "..%2fserver.py", "campaigns.js/../../x", "/etc/passwd", "", "a\x00b",
                     "CAMPAIGNS.JS", "campaigns.js/", ".."):
            self.assertEqual(campaign_api.static_file(name, "/nonexistent")[0], 404, name)


# ---------------------------------------------------------------- server request guards (127.0.0.1 only)
class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def raw(self, data, read=True):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        try:
            s.sendall(data)
            out = b""
            while read:
                try:
                    c = s.recv(65536)
                except OSError:
                    break
                if not c:
                    break
                out += c
            return out
        finally:
            s.close()

    def status(self, method, path, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        h = dict(headers or {})
        h.setdefault("Host", "127.0.0.1:%d" % self.port)
        for k, v in h.items():
            if v is not None:
                c.putheader(k, v)
        if body is not None:
            c.putheader("Content-Length", str(len(body)))
        c.endheaders(body)
        r = c.getresponse()
        r.read()
        c.close()
        return r.status

    def test_host_header(self):
        for h in ("evil.example", "evil.example:%d" % self.port, "127.0.0.1.evil.example", "localhost.evil.example",
                  "127.0.0.1@evil.example", "evil.example@127.0.0.1", "127.0.0.1/", "0.0.0.0", "[::2]", "10.0.0.1",
                  "127.0.0.1:99999x", "127.0.0.1 evil", "a" * 200):
            self.assertEqual(self.status("GET", "/api/alive", {"Host": h}), 403, h)
            self.assertEqual(self.status("POST", "/api/campaign/validate", {"Host": h}, b"{}"), 403, h)
        for h in ("127.0.0.1", "127.0.0.1:%d" % self.port, "localhost:%d" % self.port, "LOCALHOST", "[::1]:%d" % self.port):
            self.assertEqual(self.status("GET", "/api/campaign/actions", {"Host": h}), 200, h)

    def test_origin_header(self):
        body = json.dumps({"campaign": {}}).encode()
        for o in ("http://evil.example", "null", "http://127.0.0.1.evil.example", "https://localhost.evil.example",
                  "file://", "http://127.0.0.1@evil.example", "ftp://127.0.0.1"):
            self.assertEqual(self.status("POST", "/api/campaign/validate", {"Origin": o}, body), 403, o)
        self.assertEqual(self.status("POST", "/api/campaign/validate",
                                     {"Origin": "http://127.0.0.1:%d" % self.port}, body), 200)

    def test_post_body_cap(self):
        n = campaign_api.BODY_CAP + 1
        self.assertEqual(self.status("POST", "/api/campaign/validate", None, b"x" * n), 413)
        out = self.raw(b"POST /api/campaign/validate HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 99999999999\r\n\r\n")
        self.assertIn(b" 413 ", out.split(b"\r\n")[0] + b" ")
        for bad in ("-5", "abc", "1e3"):
            out = self.raw(("POST /api/campaign/validate HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: %s\r\n\r\n" % bad).encode())
            self.assertTrue(out.startswith(b"HTTP/1.0 400") or out.startswith(b"HTTP/1.1 400"), (bad, out[:40]))

    def test_chunked_refused(self):
        out = self.raw(b"POST /api/campaign/validate HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n"
                       b"5\r\nhello\r\n0\r\n\r\n")
        self.assertIn(b" 411 ", out.split(b"\r\n")[0] + b" ")

    def test_invalid_and_deep_json(self):
        self.assertEqual(self.status("POST", "/api/campaign/validate", None, b"{not json"), 400)
        self.assertEqual(self.status("POST", "/api/campaign/validate", None, b"[" * 100000), 400)
        self.assertEqual(self.status("POST", "/api/campaign/validate", None,
                                     b'{"campaign":' + b"[" * 200 + b"]" * 200 + b"}"), 400)

    def test_header_size(self):
        out = self.raw(b"GET /api/alive HTTP/1.1\r\nHost: 127.0.0.1\r\nX-A: " + b"a" * 70000 + b"\r\n\r\n")
        self.assertRegex(out.split(b"\r\n")[0], rb" 4\d\d ")
        many = b"".join(b"X-%d: 1\r\n" % i for i in range(200))
        out = self.raw(b"GET /api/alive HTTP/1.1\r\nHost: 127.0.0.1\r\n" + many + b"\r\n")
        self.assertRegex(out.split(b"\r\n")[0], rb" 4\d\d ")

    def test_path_traversal(self):
        for p in ("/ui/../server.py", "/ui/%2e%2e/server.py", "/ui/..%2fserver.py", "/ui/%2e%2e%2fserver.py",
                  "/ui//etc/passwd", "/ui/campaigns.js/../../server.py", "/ui/.", "/ui/", "/ui/campaigns.js%00.png",
                  "/ui/..\\server.py", "/campaign/export?id=../../etc/passwd", "/campaign/export?id=..%2f..%2fx"):
            out = self.raw(("GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" % p).encode())
            self.assertRegex(out.split(b"\r\n")[0], rb" (400|404) ", p)
            self.assertNotIn(b"import ", out, p)

    def test_stalled_client_is_dropped(self):
        self.assertLessEqual(server.Handler.timeout, 60)
        self.assertGreater(server.Handler.timeout, 0)


if __name__ == "__main__":
    unittest.main()
