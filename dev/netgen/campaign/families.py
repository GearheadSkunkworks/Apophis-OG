"""Malware-family beacon look-alike profiles for the campaign builder.

Each family is a *behavioural look-alike* of the network traffic that public reporting documents for that
family: the request path, user agent, header, cookie, method, body kind, TLS client profile, check-in cadence and
reply sizes. Nothing here is tooling or payload. Every body is inert random filler, every host is the caller's
indicator, and the bytes decode to nothing. A sensor's behavioural analytics see a family-shaped beacon, which is
the point; a person reading the capture finds no malware in it.

``FAMILIES`` maps a family id to::

    {"name", "aliases": [...], "kind": "http|https|dns", "profile": {...same keys as c2.PROFILES entries...},
     "interval_s", "jitter", "size_min", "size_max", "tls": "<tls client profile>", "notes"}

``notes`` says what is imitated and how a sensor tells the traffic apart from ordinary web use. The cadence and size
numbers are representative defaults taken from public analyses, not a claim about every build or configuration of a
family (most are operator-configurable).

``lookup(name_or_tag)`` resolves an id, name, alias or IOC tag; ``for_iocs(iocs)`` returns the id of the first family
found in the indicators' tags, note or source. Both are pure functions of their input (deterministic).
"""
import re

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _norm(text):
    return _NON_ALNUM.sub("", str(text or "").lower())


def _checksum8_paths(n=5, want=92):
    """Short URI paths whose characters sum to ``want`` modulo 256 (the documented 'checksum8' stage-URI look).
    Built from a fixed alphabet in a fixed order, so the list never changes."""
    alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    base = len(alpha)
    out, i = [], 12345
    while len(out) < n:
        i = (i * 48271 + 11) % 14776336            # 62**4, fixed multiplier: a repeatable scatter over 4-char names
        s = "".join(alpha[(i // base ** k) % base] for k in range(4))
        if sum(map(ord, s)) % 256 == want and "/" + s not in out:
            out.append("/" + s)
    return out


_MS_PATHS = _checksum8_paths()
_MSIE9 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
_MSIE7 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727)"
_CHROME_WIN = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
               "Chrome/120.0.0.0 Safari/537.36")
_FF50 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0"


def _fam(name, aliases, kind, profile, interval_s, jitter, size_min, size_max, notes):
    return {"name": name, "aliases": list(aliases), "kind": kind, "profile": profile, "interval_s": interval_s,
            "jitter": jitter, "size_min": size_min, "size_max": size_max, "tls": profile["tls"], "notes": notes}


def _prof(ua, method, paths, headers, ctype, tls, cookie, post_body):
    return dict(ua=ua, method=method, paths=list(paths), headers=list(headers), ctype=ctype, tls=tls,
                cookie=cookie, post_body=post_body)


FAMILIES = {
    "cobalt-strike": _fam(
        "Cobalt Strike", ["cobaltstrike", "cs beacon", "cobalt strike beacon", "cobaltstrike beacon"], "https",
        _prof(_MSIE9, "GET", ["/jquery-3.3.1.min.js", "/ca", "/pixel.gif", "/__utm.gif", "/updates.rss"],
              ["Accept: */*"], "application/octet-stream", "winhttp", "__cfduid", False),
        60.0, 0.0, 80, 1400,
        "Imitates the stock malleable-profile HTTP(S) check-in publicly documented for the default profile: GET of a "
        "static-looking file name, an old browser user agent, a long base64-looking cookie, an opaque octet-stream reply, a "
        "system-HTTP-client TLS hello. A sensor tells it from web use by the single fixed URI repeated on a steady sleep "
        "with an old user agent and no browser Accept-* set, to a host that serves nothing else."),
    "sliver": _fam(
        "Sliver", ["sliver c2", "sliver implant"], "https",
        _prof(_CHROME_WIN, "GET", ["/login.php", "/static/app.js", "/assets/main.woff", "/oauth2/auth.php"],
              ["Accept: */*"], "application/octet-stream", "go", None, False),
        60.0, 0.3, 120, 2000,
        "Imitates the HTTP(S) C2 channel of an open-source Go framework: requests to ordinary-looking script, "
        "font and login paths with a current desktop-browser user agent, an opaque body in reply, and a Go TLS client hello. "
        "A sensor tells it apart by the Go TLS fingerprint paired with a browser user agent and a jittered fixed sleep."),
    "brute-ratel": _fam(
        "Brute Ratel C4", ["bruteratel", "brc4", "badger", "brute ratel c4"], "https",
        _prof(_CHROME_WIN, "POST", ["/api/v2/content", "/static/css/main.css", "/cdn/analytics"],
              ["Content-Type: application/json"], "application/json", "winhttp", None, False),
        45.0, 0.25, 100, 1600,
        "Imitates a commercial red-team framework's profile-defined HTTPS check-in. Its URIs and headers are operator "
        "configured, so this uses a representative API/CDN-style profile: small JSON-looking POSTs on a jittered "
        "sleep from a system-HTTP-client. A sensor tells it apart by the periodicity and the near-constant request size."),
    "havoc": _fam(
        "Havoc", ["havoc c2", "havoc demon"], "https",
        _prof(_FF50, "POST", ["/"], ["Content-Type: application/octet-stream"],
              "text/html; charset=UTF-8", "winhttp", None, True),
        2.0, 0.0, 40, 300,
        "Imitates the default listener of an open-source framework: a POST to the site root with a fixed old "
        "desktop-browser user agent and an opaque body, every couple of seconds. A sensor tells it apart by the rapid, "
        "regular POSTs to / with a fixed user agent that no current browser sends."),
    "meterpreter-http": _fam(
        "Meterpreter HTTP", ["meterpreter", "metasploit", "reverse_http", "metasploit meterpreter"], "http",
        _prof("Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", "GET", _MS_PATHS or ["/AbCd"],
              ["Accept: */*"], "application/octet-stream", "winhttp", None, False),
        5.0, 0.0, 100, 600,
        "Imitates the reverse_http check-in publicly documented for the Metasploit payload: a short URI whose "
        "characters sum to 92 modulo 256 (the stage-URI convention), an old browser user agent, plain HTTP, and an "
        "opaque reply. A sensor tells it apart by the checksum-shaped four-character URI and the legacy user agent."),
    "qakbot": _fam(
        "Qakbot", ["qbot", "pinkslipbot", "qakbot c2", "quakbot"], "https",
        _prof("Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0", "POST",
              ["/t4", "/t5", "/ys/prof.php"], ["Content-Type: application/x-www-form-urlencoded"],
              "text/html", "winhttp", None, False),
        30.0, 0.3, 150, 1200,
        "Imitates the HTTPS check-in publicly documented for the loader: POSTs of a form-encoded base64-looking body "
        "to short fixed paths with a desktop-browser user agent. A sensor tells it apart by the same short path hit "
        "repeatedly from a workstation and a non-browser TLS hello behind a browser user agent."),
    "emotet": _fam(
        "Emotet", ["heodo", "geodo", "emotet c2"], "http",
        _prof(_MSIE7, "POST", ["/wp-content/", "/cgi-bin/", "/images/", "/news/", "/admin/", "/tmp/"],
              ["Content-Type: multipart/form-data"], "application/octet-stream", "winhttp", "session", True),
        45.0, 0.4, 200, 4000,
        "Imitates the loader's HTTP check-in publicly documented: POSTs of opaque form-data bodies to bare "
        "directory-style paths (a content-management-looking path on a compromised site), an old browser user agent and a "
        "session-like cookie. A sensor tells it apart by POSTs to a directory path with no page, to bare IPs or odd sites."),
    "icedid": _fam(
        "IcedID", ["bokbot", "icedid c2", "icedid bokbot"], "https",
        _prof("Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko", "GET",
              ["/news/", "/photo.png", "/main/", "/update"], ["Accept: */*"], "application/octet-stream",
              "winhttp", "__gads", False),
        60.0, 0.3, 200, 3000,
        "Imitates the HTTPS check-in publicly documented: GETs of short news/image-looking paths with a tracking-cookie "
        "look (__gads and similar) and a legacy-browser user agent, opaque replies. A sensor tells it apart by the "
        "tracking cookie sent to a host that sets none, together with the system-HTTP-client TLS hello."),
    "asyncrat": _fam(
        "AsyncRAT", ["async rat", "asyncrat c2"], "https",
        _prof("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AsyncClient/1.0", "POST", ["/api/ping"],
              ["Content-Type: application/octet-stream"], "application/octet-stream", "winhttp", None, True),
        10.0, 0.1, 40, 400,
        "APPROXIMATION. The real family frames its own protocol directly inside TLS (a self-signed server "
        "certificate, small length-prefixed packets, a keep-alive ping about every ten seconds), not HTTP. This "
        "look-alike carries only the cadence, packet sizes and a managed-runtime-style client TLS hello inside ordinary HTTPS. "
        "A sensor tells the real thing apart by the self-signed certificate and the fixed-size ping on a high port; "
        "those are not reproduced here."),
    "remcos": _fam(
        "Remcos", ["remcos rat", "remcosrat", "remcos c2"], "https",
        _prof("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AsyncClient/1.0", "POST", ["/api/heartbeat"],
              ["Content-Type: application/octet-stream"], "application/octet-stream", "winhttp", None, True),
        1.0, 0.0, 40, 200,
        "APPROXIMATION. The real tool uses a custom TLS-wrapped TCP protocol with a one-second keep-alive, not "
        "HTTP. This look-alike keeps the one-second cadence and small packets inside ordinary HTTPS. A sensor "
        "tells the real thing apart by the self-signed certificate and the constant sub-second keep-alive; only the "
        "cadence is reproduced here."),
    "lumma-stealer": _fam(
        "Lumma Stealer", ["lumma", "lummac2", "lumma c2", "lumma stealer c2"], "https",
        _prof(_CHROME_WIN, "POST", ["/c2sock", "/api"],
              ["Content-Type: multipart/form-data; boundary=----BoundaryAbCdEf"], "application/json",
              "winhttp", None, False),
        15.0, 0.2, 120, 1500,
        "Imitates the stealer's HTTPS check-in publicly documented: multipart/form-data POSTs to a fixed short "
        "path with a desktop-browser user agent and a JSON-looking reply, a few quick exchanges then silence. A sensor tells "
        "it apart by the POSTs to /c2sock or /api on a host with no site content and a non-browser TLS hello."),
    "generic-rmm": _fam(
        "Generic remote-management agent", ["rmm", "rmm agent", "remote management agent", "generic rmm agent"], "https",
        _prof("RMMAgent/1.0", "POST", ["/agent/heartbeat", "/agent/tasks"], ["Content-Type: application/json"],
              "application/json", "go", None, False),
        30.0, 0.1, 60, 800,
        "Imitates the heartbeat of a legitimate remote-monitoring-and-management agent that attackers also "
        "abuse: small JSON POSTs on a thirty-second cadence with a fixed agent user agent and a Go TLS hello. "
        "The traffic is the same for the legitimate and the abused case; a sensor tells them apart only by whether "
        "the destination and the endpoint are sanctioned."),
}

# Indicator text is matched in a looser way than a tag: a family name found inside a note or source counts when
# it is long enough not to hit ordinary words, and 'generic-rmm' is never inferred from free text.
_TEXT_MIN = 6
_NO_TEXT = ("generic-rmm",)


def _keys(fid):
    f = FAMILIES[fid]
    return {_norm(fid), _norm(f["name"])} | {_norm(a) for a in f["aliases"]}


_INDEX = {}
for _fid in FAMILIES:
    for _k in _keys(_fid):
        _INDEX.setdefault(_k, _fid)


def ids():
    """Family ids in definition order."""
    return list(FAMILIES)


def lookup(name_or_tag):
    """Family dict for an id, name, alias or IOC tag (case, space, dash and punctuation insensitive), else None.
    The returned dict has an extra ``"id"`` key."""
    fid = _INDEX.get(_norm(name_or_tag))
    if fid is None:
        return None
    return dict(FAMILIES[fid], id=fid)


def _from_text(text):
    n = _norm(text)
    if not n:
        return None
    best = None
    for fid in FAMILIES:
        if fid in _NO_TEXT:
            continue
        for k in _keys(fid):
            if len(k) >= _TEXT_MIN and k in n:
                pos = n.index(k)
                if best is None or pos < best[0]:
                    best = (pos, fid)
    return best[1] if best else None


def for_ioc(ioc):
    """Family id carried by one indicator dict (tags first, then note, then source) or None."""
    if not isinstance(ioc, dict):
        return None
    for t in ioc.get("tags") or []:
        f = _INDEX.get(_norm(t))
        if f:
            return f
    for t in ioc.get("tags") or []:
        f = _from_text(t)
        if f:
            return f
    return _from_text(ioc.get("note")) or _from_text(ioc.get("source"))


def for_iocs(iocs):
    """Family id of the first indicator that carries one, or None."""
    for ioc in iocs or []:
        f = for_ioc(ioc)
        if f:
            return f
    return None
