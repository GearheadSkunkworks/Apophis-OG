"""The server-rendered static pages (/about, /report, /profile/compare): they follow ?theme= and
?palette=, use the shared chrome (the inline pulse mark, no letter-spaced capitals) and carry no script."""
import http.client
import os
import re
import struct
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, DEV)
import server  # noqa: E402


def _pcap(path):
    """A valid pcap with one Ethernet/IPv4/UDP frame."""
    eth = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"
    udp = struct.pack(">HHHH", 1234, 53, 8 + 4, 0) + b"abcd"
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    frame = eth + ip + udp
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        fh.write(struct.pack("<IIII", 1700000000, 0, len(frame), len(frame)) + frame)


class TestStaticPages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.a = os.path.join(cls.tmp.name, "a.pcap")
        cls.b = os.path.join(cls.tmp.name, "b.pcap")
        _pcap(cls.a)
        _pcap(cls.b)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()

    def get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        c.request("GET", path)
        r = c.getresponse()
        body = r.read().decode("utf-8", "replace")
        c.close()
        return r.status, body

    def assert_chrome(self, body):
        self.assertIn('class="mark gh"', body)                       # the inline pulse mark, not the old logo
        self.assertNotIn("<script", body.lower())
        css = body.split("<style>", 1)[1].split("</style>", 1)[0]
        css = re.sub(r"\.mh-title[^}]*\}", "", css)               # SVG attribute selectors are not text styles
        self.assertNotIn("text-transform", css)
        self.assertNotIn("letter-spacing:.1", css)

    def test_about_follows_theme_and_palette(self):
        st, body = self.get("/about?theme=light&palette=teal")
        self.assertEqual(st, 200)
        self.assertIn('<html lang="en" data-theme="light" data-palette="teal">', body)
        self.assert_chrome(body)

    def test_report_empty_state_uses_shared_page_and_theme(self):
        with server.LOCK:
            had = server.STATE.get("protocols")
            server.STATE["protocols"] = []
        try:
            st, body = self.get("/report?theme=light&palette=clay")
            self.assertEqual(st, 404)
            self.assertIn('data-theme="light" data-palette="clay"', body)
            self.assertIn("Nothing to report yet", body)
            self.assertIn('href="/ui/theme.css"', body)
            self.assert_chrome(body)
            st, body = self.get("/report?theme=dark")
            self.assertIn('data-theme="dark"', body)
            self.assertIn('<html lang="en" data-theme="dark">', body)
        finally:
            with server.LOCK:
                server.STATE["protocols"] = had

    def test_compare_honours_theme_and_palette(self):
        from urllib.parse import quote
        q = "/profile/compare?a=%s&b=%s" % (quote(self.a), quote(self.b))
        st, body = self.get(q + "&theme=light&palette=sage")
        self.assertEqual(st, 200, body[:300])
        self.assertIn('data-theme="light" data-palette="sage"', body)
        self.assert_chrome(body)
        st, body = self.get(q)
        self.assertEqual(st, 200)
        self.assertIn('<html lang="en">', body)

    def test_index_passes_theme_to_compare(self):
        with open(os.path.join(DEV, "ui", "index.html"), encoding="utf-8") as fh:
            html = fh.read()
        m = re.search(r"'/profile/compare\?a='[^;]*;", html)
        self.assertIn("ogThemeParams()", m.group(0))


    # ---- shared page template -------------------------------------------------------------------
    def _page_types(self):
        """(label, path) for every static page type, including the message pages."""
        from urllib.parse import quote
        return [("about", "/about?"), ("report empty", "/report?"),
                ("compare", "/profile/compare?a=%s&b=%s&" % (quote(self.a), quote(self.b))),
                ("profile", "/profile?path=%s&" % quote(self.a)),
                ("profile error", "/profile?path=/nonexistent/x.pcap&"),
                ("compare error", "/profile/compare?a=/nonexistent&b=/nonexistent&")]

    def test_every_page_type_has_shared_header_and_theme(self):
        with server.LOCK:
            had = server.STATE.get("protocols")
            server.STATE["protocols"] = []
        try:
            for label, path in self._page_types():
                st, body = self.get(path + "theme=light&palette=teal")
                with self.subTest(label):
                    self.assertIn('<html lang="en" data-theme="light" data-palette="teal">', body)
                    self.assertIn('class="mark gh"', body)
                    self.assertIn('href="/ui/theme.css"', body)
                    st2, body2 = self.get(path + "theme=bogus&palette=<x>")
                    self.assertIn('<html lang="en">', body2)
        finally:
            with server.LOCK:
                server.STATE["protocols"] = had

    def test_no_inline_hex_colours_in_server_message_pages(self):
        import page_template
        for label, path in self._page_types()[4:]:
            st, body = self.get(path + "theme=light")
            with self.subTest(label):
                self.assertFalse(re.search(r"#[0-9a-fA-F]{3,8}\b", body), body[:400])
        self.assertNotRegex(page_template._CSS, r"#[0-9a-fA-F]{3,8}\b")
        # the ad hoc page strings in server.py are gone: no inline colour or its own doctype
        with open(os.path.join(DEV, "server.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("color:#b23f0f", src)
        self.assertNotIn("<!doctype html><meta charset=utf-8>", src)


class TestDiagramTitles(unittest.TestCase):
    ACRONYMS = {"DNS", "SMB", "OT", "C2", "TLS", "VPN", "NDR", "NPM", "IP", "TCP", "UDP", "HTTP", "RDP", "MCP",
                "SYN", "SPN", "LDAP", "ATT&CK"}

    def test_sentence_case_helper(self):
        import make_diagram as M
        self.assertEqual(M.sentence_case("BEACON CADENCE"), "Beacon cadence")
        self.assertEqual(M.sentence_case("WHY IT LOOKS LIKE C2"), "Why it looks like C2")
        self.assertEqual(M.sentence_case("READ/WRITE RATIO"), "Read/write ratio")
        self.assertEqual(M.sentence_case("What this tool does"), "What this tool does")

    def test_no_all_caps_panel_title_in_any_diagram(self):
        import html as _h
        import make_diagram as M
        pat = re.compile(r'<text[^>]*font-weight="900"[^>]*fill="%s"[^>]*>([^<]*)</text>' % re.escape(M.SAPPHIRE))
        seen = 0
        for d in M.catalog(include_scenarios=True):
            page = M.render(d["name"])
            for m in pat.finditer(page):
                t = _h.unescape(m.group(1)).strip()
                words = [w for w in re.split(r"[^A-Za-z0-9&]+", t) if len(w) > 1 and w.isalpha()]
                seen += 1
                with self.subTest(diagram=d["name"], title=t):
                    caps = [w for w in words if w == w.upper() and w not in self.ACRONYMS]
                    self.assertFalse(len(words) > 1 and len(caps) == len(words), t)
        self.assertGreater(seen, 20)


if __name__ == "__main__":
    unittest.main()
