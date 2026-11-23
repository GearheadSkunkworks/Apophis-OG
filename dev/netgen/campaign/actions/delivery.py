"""Delivery actions: an inert file download and a login-lookalike page visit.

Wire behaviour only. A "payload" is file-type magic bytes followed by random filler: it is not a
program, an archive or a document anyone can open. The credentials posted by the phishing visit are
fixed dummy values. See ``c2.py`` for the determinism note.
"""
from ... import flows as F
from ... import protocols as P
from . import ActionSpec, register
from .c2 import (_p, _rb, _b64, _b32, _req, _resp, _tls_open, _tls_close, _tcp_open, _host_of, _client_ua, _sz)

# file type -> (magic/header bytes, content type, default name)
FILETYPES = {
    "exe": (b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00", "application/x-msdownload", "update.exe"),
    "dll": (b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00", "application/x-msdownload", "module.dll"),
    "elf": (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8, "application/x-executable", "agent.bin"),
    "zip": (b"PK\x03\x04\x14\x00\x00\x00\x08\x00", "application/zip", "archive.zip"),
    "pdf": (b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", "application/pdf", "invoice.pdf"),
    "doc": (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/msword", "document.doc"),
}


def inert_file(ftype, size):
    """``size`` bytes: the file type's magic bytes then random filler. Not openable, not executable."""
    magic = FILETYPES.get(str(ftype).lower(), FILETYPES["exe"])[0]
    size = max(len(magic) + 16, int(size))
    return magic + _rb(size - len(magic))


def _name_from(path):
    return path.rstrip("/").rsplit("/", 1)[-1] if path and path != "/" else ""


def payload_download(ctx, src, dst, *, ts, scheme="http", path="", filetype="exe", size=150000, filename=""):
    """Download of an inert file: DNS lookup of the host, GET (HTTP on 80 or decryptable HTTPS on 443),
    a 200 whose body is the file-type magic bytes plus filler with the right Content-Length and
    Content-Type. The file name comes from ``path`` (an IOC url path) when given, else ``filename``."""
    ft = str(filetype).lower()
    if ft not in FILETYPES:
        ft = "exe"
    magic, ctype, default_name = FILETYPES[ft]
    size = min(max(int(size), 4096), 50_000_000)
    name = filename or _name_from(path) or default_name
    if not path or path == "/":
        path = "/files/" + name
    host = _host_of(dst)
    ua = _client_ua(ctx, src)
    body = inert_file(ft, size)
    req = _req("GET", path, host, ua, [])
    resp = _resp("200 OK", body, ctype, ts, headers=['Content-Disposition: attachment; filename="%s"' % name])
    if str(scheme).lower() == "https":
        pre, s, tls = _tls_open(ctx, src, dst, ts, profile=getattr(src, "tls_profile", "winhttp"), rate=80e6)
        s.c2s(tls.app_data(True, req), think=F.rng.uniform(0.0008, 0.004))
        s.s2c(tls.app_data(False, resp), think=F.rng.uniform(0.02, 0.12))
        return _tls_close(s, tls, pre, 0.3)
    pre, s = _tcp_open(ctx, src, dst, ts, 80, rate=80e6)
    s.c2s(req, think=F.rng.uniform(0.0008, 0.004))
    s.s2c(resp, think=F.rng.uniform(0.02, 0.12))
    return F.merged(pre, s.close(think=F.rng.uniform(0.05, 0.4)))


DUMMY_USER = "user@example.test"
DUMMY_PASSWORD = "not-a-real-password"


def _login_page(host):
    """A plain generic sign-in page: no brand, no script, a form that posts to /login."""
    return ("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Account sign in</title></head>"
            "<body><main><h1>Sign in</h1><p>Enter your account details to continue.</p>"
            "<form method=\"post\" action=\"/login\"><label>Email <input type=\"email\" name=\"email\"></label>"
            "<label>Password <input type=\"password\" name=\"password\"></label>"
            "<input type=\"hidden\" name=\"csrf\" value=\"%s\"><button type=\"submit\">Sign in</button></form>"
            "<p><a href=\"/help\">Need help?</a></p></main><footer>%s</footer></body></html>" % (_b32(24), host)).encode()


def phishing_visit(ctx, src, dst, *, ts, scheme="https", path="/login", think_s=12.0):
    """A browser visits a login-lookalike page then submits a form: DNS lookup, GET of a plain generic sign-in
    page, a pause (``think_s``), then POST /login carrying the DUMMY credentials user@example.test /
    not-a-real-password, a 302 and the follow-up page. Decryptable HTTPS by default."""
    host = _host_of(dst)
    ua = _client_ua(ctx, src)
    page = _login_page(host)
    csrf = _b32(24)
    form = ("email=user%%40example.test&password=%s&csrf=%s" % (DUMMY_PASSWORD, csrf)).encode()
    sess = "sid=%s; Path=/; HttpOnly" % _b64(32)
    steps = [
        (_req("GET", path, host, ua, ["Accept: text/html"]), _resp("200 OK", page, "text/html; charset=utf-8", ts), 0.0),
        (_req("POST", "/login", host, ua, ["Content-Type: application/x-www-form-urlencoded", "Origin: %s://%s" % (scheme, host),
                                          "Referer: %s://%s%s" % (scheme, host, path)], form),
         _resp("302 Found", b"", "text/html", ts, headers=["Location: /account", "Set-Cookie: " + sess]), max(1.0, float(think_s))),
        (_req("GET", "/account", host, ua, ["Cookie: " + sess.split(";")[0]]),
         _resp("200 OK", b"<!DOCTYPE html><html><head><title>Account</title></head><body><h1>Account</h1></body></html>",
               "text/html; charset=utf-8", ts), 0.05),
    ]
    https = str(scheme).lower() == "https"
    if https:
        pre, s, tls = _tls_open(ctx, src, dst, ts, profile=getattr(src, "tls_profile", "chrome"), rate=60e6)
    else:
        pre, s = _tcp_open(ctx, src, dst, ts, 80, rate=60e6)
        tls = None
    for req, resp, gap in steps:
        g = F.rng.uniform(0.0008, 0.004) if gap == 0.0 else gap * F.rng.uniform(0.7, 1.4)
        if https:
            s.c2s(tls.app_data(True, req), think=g)
            s.s2c(tls.app_data(False, resp), think=F.rng.uniform(0.02, 0.12))
        else:
            s.c2s(req, think=g)
            s.s2c(resp, think=F.rng.uniform(0.02, 0.12))
    if https:
        return _tls_close(s, tls, pre, F.rng.uniform(0.3, 2.0))
    return F.merged(pre, s.close(think=F.rng.uniform(0.3, 2.0)))


register(ActionSpec(
    token="payload_download", fn=payload_download, title="Payload download", tactic="command-and-control",
    techniques=["T1105"], protocols=["DNS", "HTTP", "HTTPS"],
    summary="An HTTP or HTTPS GET answered with an inert file (file-type magic bytes plus filler) of the stated size.",
    params={"scheme": _p("str", "http", "http or https."), "path": _p("str", "", "URL path (from an IOC url); default /files/<name>."),
            "filetype": _p("str", "exe", "exe, dll, elf, zip, pdf or doc (sets the magic bytes and Content-Type)."),
            "size": _p("int", 150000, "Body size in bytes (4096 to 50,000,000)."),
            "filename": _p("str", "", "File name; default from the path or the file type.")},
    src="internal", dst="external", needs=("DC1",), min_duration_s=5.0))

register(ActionSpec(
    token="phishing_visit", fn=phishing_visit, title="Phishing page visit", tactic="initial-access",
    techniques=["T1566.002", "T1056.003"], protocols=["DNS", "HTTP", "HTTPS"],
    summary="A browser loads a generic sign-in page then POSTs dummy credentials (user@example.test) and follows the redirect.",
    params={"scheme": _p("str", "https", "https or http."), "path": _p("str", "/login", "Page path."),
            "think_s": _p("float", 12.0, "Seconds between page load and form submit.")},
    src="internal", dst="external", needs=("DC1",), min_duration_s=20.0))
