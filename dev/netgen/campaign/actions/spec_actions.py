"""Actions defined as data: an HTTP(S) exchange described in a JSON file, no Python needed.

A spec file (``actions/specs/*.json``, plus any ``*.json`` in the directory named by the environment variable
OPENGENERATOR_ACTION_SPECS) describes a client that sends a fixed list of requests and the server's fixed replies::

    {"token": "admin_panel_probe", "title": "...", "tactic": "reconnaissance", "techniques": ["T1595.003"],
     "summary": "one sentence of what appears on the wire", "direction": "inbound|outbound", "tls": false, "port": 80,
     "user_agent": "...", "repeat": 1, "gap_s": 0.4,
     "for_role": "scanner",   (optional: the compiler adds this action for every indicator of that role)
     "requests": [{"method": "GET", "path": "/admin", "headers": ["Accept: text/html"], "body": "",
                   "status": "401 Unauthorized", "reply": "<html>...</html>", "content_type": "text/html"}]}

A spec with ``"kind": "tcp"`` describes a plain-text protocol instead (SMTP, FTP, IRC, a custom banner): no
``requests``; an optional ``"banner"`` the server sends first, and ``"exchanges": [{"send": "HELO x\\r\\n", "reply": "250 ok\\r\\n"}]``
(only ``\\r`` and ``\\n`` escapes; no TLS).

``inbound`` is an internet client reaching an internal server; ``outbound`` an internal client reaching the outside.
Specs are untrusted input: every field is validated (``validate``), bodies and replies are short printable text, and a
spec that fails validation is skipped with its errors in ``LOAD_ERRORS`` and is never registered. Nothing here can
carry bytes that are not printable ASCII, so a spec cannot encode a payload.
"""
import glob
import json
import os
import re

from . import ActionSpec, register
from .c2 import _p, _req, _resp, _tls_open, _tls_close, _tcp_open
from .outside import _in_open, _exchange, _web_name
from ... import flows as F

LOAD_ERRORS = []                       # [(file, [error, ...])] from the last load
_SPEC_META = {}                        # token -> metadata record, read by actions.meta
_PLACE = {}                            # token -> indicator role the compiler places it for (spec key "for_role")
PLACE_ROLES = ("c2", "payload", "exfil", "scanner", "brute", "phishing", "tor")
_PRINT = re.compile(r"^[\x20-\x7e]*$")
_TOKEN = re.compile(r"^[a-z][a-z0-9_]{2,39}$")
_METHODS = ("GET", "POST", "PUT", "HEAD", "OPTIONS", "DELETE")
_STATUS = re.compile(r"^[1-5]\d\d [A-Za-z ]{2,30}$")
_CTYPES = ("text/html", "text/plain", "application/json", "application/xml", "application/octet-stream", "image/png")
MAX_REQUESTS, MAX_REPEAT, MAX_TEXT = 20, 50, 2048
_KEYS = {"token", "title", "tactic", "techniques", "summary", "direction", "tls", "port", "user_agent", "repeat",
         "gap_s", "requests", "for_role", "kind", "banner", "exchanges"}
_EXCH_KEYS = {"send", "reply"}
_REQ_KEYS = {"method", "path", "headers", "body", "status", "reply", "content_type"}


def validate(spec, taken=()):
    """Error strings for a spec dict; an empty list means it can be registered."""
    from .. import attack
    errs = []
    if not isinstance(spec, dict):
        return ["the spec must be a JSON object"]
    errs += ["unknown key %r" % k for k in spec if k not in _KEYS]
    tok = spec.get("token")
    if not isinstance(tok, str) or not _TOKEN.match(tok):
        errs.append("token must be lower_snake, 3 to 40 characters")
    elif tok in taken:
        errs.append("token %r is already an action" % tok)
    for k in ("title", "summary", "user_agent"):
        v = spec.get(k, "x")
        if not isinstance(v, str) or not v.strip() or len(v) > 300 or not _PRINT.match(v):
            errs.append("%s must be short printable text" % k)
    if spec.get("tactic") not in [t["slug"] for t in attack.tactics()]:
        errs.append("tactic must be an ATT&CK tactic slug")
    t = spec.get("techniques", [])
    if not isinstance(t, list) or not t or attack.validate_ids(t):
        errs.append("techniques must be a non-empty list of known ATT&CK ids")
    if spec.get("direction") not in ("inbound", "outbound"):
        errs.append("direction must be inbound or outbound")
    if spec.get("for_role") is not None and spec["for_role"] not in PLACE_ROLES:
        errs.append("for_role must be one of " + ", ".join(PLACE_ROLES))
    if not isinstance(spec.get("tls", False), bool):
        errs.append("tls must be true or false")
    port = spec.get("port", 443 if spec.get("tls") else 80)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        errs.append("port must be 1 to 65535")
    rep = spec.get("repeat", 1)
    if isinstance(rep, bool) or not isinstance(rep, int) or not 1 <= rep <= MAX_REPEAT:
        errs.append("repeat must be 1 to %d" % MAX_REPEAT)
    gap = spec.get("gap_s", 0.4)
    if isinstance(gap, bool) or not isinstance(gap, (int, float)) or not 0.05 <= gap <= 30:
        errs.append("gap_s must be 0.05 to 30")
    if spec.get("kind", "http") not in ("http", "tcp"):
        errs.append("kind must be http or tcp")
    elif spec.get("kind") == "tcp":
        return errs + _validate_tcp(spec)
    reqs = spec.get("requests")
    if not isinstance(reqs, list) or not 1 <= len(reqs) <= MAX_REQUESTS:
        errs.append("requests must be a list of 1 to %d" % MAX_REQUESTS)
        return errs
    for n, r in enumerate(reqs, 1):
        p = "request %d: " % n
        if not isinstance(r, dict):
            errs.append(p + "must be an object")
            continue
        errs += [p + "unknown key %r" % k for k in r if k not in _REQ_KEYS]
        if r.get("method", "GET") not in _METHODS:
            errs.append(p + "method must be one of " + ", ".join(_METHODS))
        path = r.get("path")
        if not isinstance(path, str) or not path.startswith("/") or len(path) > 200 or not re.match(r"^/[\x21-\x7e]*$", path):
            errs.append(p + "path must start with / and hold no spaces or control characters")
        hs = r.get("headers", [])
        if not isinstance(hs, list) or len(hs) > 6 or not all(isinstance(h, str) and re.match(r"^[A-Za-z0-9-]{1,40}: [\x20-\x7e]{0,200}$", h) for h in hs):
            errs.append(p + "headers must be up to 6 'Name: value' strings")
        elif any(h.split(":")[0].lower() in ("host", "content-length", "transfer-encoding", "connection") for h in hs):
            errs.append(p + "Host, Content-Length, Transfer-Encoding and Connection are set by the engine")
        for k in ("body", "reply"):
            v = r.get(k, "")
            if not isinstance(v, str) or len(v) > MAX_TEXT or not _PRINT.match(v):
                errs.append(p + "%s must be printable ASCII up to %d characters" % (k, MAX_TEXT))
        if not _STATUS.match(str(r.get("status", "200 OK"))):
            errs.append(p + "status must look like '200 OK'")
        if r.get("content_type", "text/html") not in _CTYPES:
            errs.append(p + "content_type must be one of " + ", ".join(_CTYPES))
    return errs


def _text(v):
    """Spec text with the \\r and \\n escapes decoded."""
    return v.replace("\\r", "\r").replace("\\n", "\n").encode("ascii")


def _validate_tcp(spec):
    errs = []
    if spec.get("tls"):
        errs.append("a tcp spec cannot use tls")
    if "requests" in spec:
        errs.append("a tcp spec uses exchanges, not requests")
    b = spec.get("banner", "")
    if not isinstance(b, str) or len(b) > 300 or not _PRINT.match(b):
        errs.append("banner must be printable ASCII up to 300 characters")
    ex = spec.get("exchanges")
    if not isinstance(ex, list) or not 1 <= len(ex) <= MAX_REQUESTS:
        return errs + ["exchanges must be a list of 1 to %d" % MAX_REQUESTS]
    for n, e in enumerate(ex, 1):
        p = "exchange %d: " % n
        if not isinstance(e, dict):
            errs.append(p + "must be an object")
            continue
        errs += [p + "unknown key %r" % k for k in e if k not in _EXCH_KEYS]
        for k in ("send", "reply"):
            v = e.get(k, "")
            if not isinstance(v, str) or len(v) > 600 or not _PRINT.match(v):
                errs.append(p + "%s must be printable ASCII up to 600 characters" % k)
        if not e.get("send") and not e.get("reply"):
            errs.append(p + "needs a send or a reply")
    return errs


def _make_tcp_fn(spec):
    port, inbound, gap = int(spec.get("port") or 80), spec["direction"] == "inbound", float(spec.get("gap_s", 0.4))
    banner, ex, default_repeat = spec.get("banner", ""), spec["exchanges"], int(spec.get("repeat", 1))

    def fn(ctx, src, dst, *, ts, host="", repeat=default_repeat):
        if inbound:
            s, _tl = _in_open(ctx, src, dst, ts, port)
            pre = []
        else:
            pre, s = _tcp_open(ctx, src, dst, ts, port)
        if banner:
            s.s2c(_text(banner), think=F.rng.uniform(0.002, 0.02))
        for _ in range(max(1, min(int(repeat), MAX_REPEAT))):
            for e in ex:
                if e.get("send"):
                    s.c2s(_text(e["send"]), think=gap * F.rng.uniform(0.6, 1.4))
                if e.get("reply"):
                    s.s2c(_text(e["reply"]), think=F.rng.uniform(0.0004, 0.004))
        return F.merged(pre, s.close(think=F.rng.uniform(0.002, 0.03)))
    fn.__name__ = spec["token"]
    return fn


def _make_fn(spec):
    if spec.get("kind") == "tcp":
        return _make_tcp_fn(spec)
    tls_on, port, ua = bool(spec.get("tls")), int(spec.get("port") or (443 if spec.get("tls") else 80)), spec.get("user_agent") or "Mozilla/5.0"
    inbound, gap, reqs = spec["direction"] == "inbound", float(spec.get("gap_s", 0.4)), spec["requests"]
    default_repeat = int(spec.get("repeat", 1))

    def fn(ctx, src, dst, *, ts, host="", repeat=default_repeat):
        name = _web_name(host) if inbound else (dst.fqdn or dst.ip)
        pre, tl = [], None
        if inbound:
            s, tl = _in_open(ctx, src, dst, ts, port, name if tls_on else None)
        elif tls_on:
            pre, s, tl = _tls_open(ctx, src, dst, ts, host=name, port=port)
        else:
            pre, s = _tcp_open(ctx, src, dst, ts, port)
        for _ in range(max(1, min(int(repeat), MAX_REPEAT))):
            for r in reqs:
                reply = _resp(r.get("status", "200 OK"), r.get("reply", "").encode(), r.get("content_type", "text/html"), s.t)
                _exchange(s, tl, _req(r.get("method", "GET"), r["path"], name, ua, list(r.get("headers", [])), r.get("body", "").encode()),
                          reply, gap * F.rng.uniform(0.6, 1.4))
        if tl is not None and not inbound:
            return _tls_close(s, tl, pre, F.rng.uniform(0.2, 1.0))
        if tl is not None:
            s.c2s(tl.close_notify(True), think=F.rng.uniform(0.01, 0.1))
        return F.merged(pre, s.close(think=F.rng.uniform(0.002, 0.03)))
    fn.__name__ = spec["token"]
    return fn


def _meta_tcp(spec):
    port, n = int(spec.get("port") or 80), len(spec["exchanges"]) * int(spec.get("repeat", 1))
    first = next((e["send"] for e in spec["exchanges"] if e.get("send")), "")[:40].replace("\\r", " ").replace("\\n", " ").strip()
    return {
        "plain": spec["summary"],
        "tells": ["%d exchanges over one plain-text connection to tcp/%d" % (n, port),
                  ("First client line: " + first) if first else "The server speaks first",
                  "Defined by a data spec, not code (%s)" % spec["token"]],
        "filters": [("Connection", "tcp.port == %d" % port, "one TCP connection to port %d" % port),
                    ("Payload", "tcp.port == %d && tcp.len > 0" % port, "%d exchanges of text" % n)],
        "wire": ("tcp/%d plain text, %s, %d exchanges" % (port, spec["direction"], n))[:100]}


def _meta(spec):
    if spec.get("kind") == "tcp":
        return _meta_tcp(spec)
    paths = ", ".join(dict.fromkeys(r["path"] for r in spec["requests"]))[:80]
    codes = ", ".join(dict.fromkeys(str(r.get("status", "200 OK"))[:3] for r in spec["requests"]))
    n = len(spec["requests"]) * int(spec.get("repeat", 1))
    proto = "HTTPS tcp/%d" % int(spec.get("port") or 443) if spec.get("tls") else "HTTP tcp/%d" % int(spec.get("port") or 80)
    return {
        "plain": spec["summary"],
        "tells": ["%d requests over one connection: %s" % (n, paths), "Reply status codes: " + codes,
                  "Defined by a data spec, not code (%s)" % spec["token"]],
        "filters": [("Requests", "ip.src == {src_ip} && http.request", "one per request, %d in all" % n),
                    ("Replies", "ip.src == {dst_ip} && http.response", "status codes " + codes)],
        "wire": ("%s, %s, %d requests" % (proto, spec["direction"], n))[:100]}


def load(dirs=None):
    """Register every valid spec in the bundled folder and OPENGENERATOR_ACTION_SPECS. Returns the tokens added."""
    from . import _REGISTRY
    LOAD_ERRORS.clear()
    base = [os.path.join(os.path.dirname(__file__), "specs")]
    extra = os.environ.get("OPENGENERATOR_ACTION_SPECS")
    added = []
    for d in (dirs if dirs is not None else base + ([extra] if extra else [])):
        for path in sorted(glob.glob(os.path.join(d, "*.json")))[:200]:
            try:
                if os.path.getsize(path) > 64 * 1024:
                    raise ValueError("file is larger than 64 KB")
                with open(path, encoding="utf-8") as fh:
                    spec = json.load(fh)
            except (OSError, ValueError) as e:
                LOAD_ERRORS.append((os.path.basename(path), [str(e)[:200]]))
                continue
            errs = validate(spec, taken=_REGISTRY)
            if errs:
                LOAD_ERRORS.append((os.path.basename(path), errs))
                continue
            inbound = spec["direction"] == "inbound"
            register(ActionSpec(
                token=spec["token"], fn=_make_fn(spec), title=spec["title"], tactic=spec["tactic"],
                techniques=list(spec["techniques"]), protocols=["TCP"] if spec.get("kind") == "tcp" else ["TCP", "HTTP"] + (["TLS"] if spec.get("tls") else []),
                summary=spec["summary"],
                params={"host": _p("str", "", "Host header (and SNI with TLS); default is the destination's name."),
                        "repeat": _p("int", int(spec.get("repeat", 1)), "Times the request list is sent (1 to %d)." % MAX_REPEAT)},
                src="external" if inbound else "internal", dst="internal" if inbound else "external",
                min_duration_s=max(1.0, len(spec.get("requests") or spec["exchanges"]) * float(spec.get("gap_s", 0.4)))))
            _SPEC_META[spec["token"]] = _meta(spec)
            if spec.get("for_role"):
                _PLACE[spec["token"]] = spec["for_role"]
            added.append(spec["token"])
    return added


def placements():
    """{token: role}: data specs the compiler places automatically for indicators of that role."""
    return dict(_PLACE)


def meta_records():
    return dict(_SPEC_META)


load()
