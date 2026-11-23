"""Command-and-control actions: beacons, DNS channels, algorithmic lookups, Tor.

Everything here is network BEHAVIOUR with inert, benign bytes. A beacon is a cadence of small
check-ins; a DNS channel is queries carrying random-looking label text; nothing decodes to a
command, a tool or malware. The "profiles" are only URI / user-agent / header / cadence presets of
benign look-alike requests, so a sensor's behavioural analytics have something to see.

All randomness in this file comes from ``netgen.flows.rng`` (never the stdlib random module, OS entropy or the
clock). The one exception is outside it: the engine's TLS layer draws handshake randoms and keys from system entropy,
so the *bytes* of a TLS handshake differ between runs while packet counts, sizes, timing and ordering
repeat exactly (see the engine note in ``netgen/__init__.py``).

Helpers prefixed ``_`` are shared with ``delivery.py`` and ``exfil.py``.
"""
import base64

from ... import flows as F
from ... import protocols as P
from ...core import Host
from . import ActionSpec, register
from .. import families as _families

_B32 = "abcdefghijklmnopqrstuvwxyz234567"


# ---------------------------------------------------------------------------- shared helpers
def _rb(n):
    """n inert filler bytes from the engine's seeded generator."""
    return F.rng.randbytes(max(0, int(n)))


def _b32(n):
    """n characters of random lower-case base32 text (DNS-safe), from the engine's generator."""
    n = max(1, int(n))
    return base64.b32encode(_rb((n * 5) // 8 + 2)).decode().lower().replace("=", "")[:n]


def _b64(n):
    """About n characters of random base64 text."""
    return base64.b64encode(_rb((n * 3) // 4 + 1)).decode().rstrip("=")[:n]


def _gap(interval, jitter):
    j = min(max(float(jitter), 0.0), 0.95)
    return max(0.05, float(interval) * F.rng.uniform(1.0 - j, 1.0 + j))


def _client_ua(ctx, src):
    return P.UAS[0] if ctx.is_windows(src) else P.UAS[2]


def _host_of(dst):
    return dst.fqdn or dst.ip


def _has_name(dst):
    return bool(dst.fqdn)


def _lookup(ctx, src, dst, ts, force=True):
    """DNS lookup of the destination's name through the corporate resolver (cached 300 s per client)."""
    if not _has_name(dst) or not F._wants_dns(ctx, src, dst.fqdn, ts, True if force else None):
        return []
    return F.dns_lookup(ctx, src, dst.fqdn, ts, external=True, answers=[(P.DNS_A, dst.ipb)])


def _req(method, path, host, ua, headers=None, body=b""):
    """A minimal client request (non-browser clients do not send a browser's Accept-* set)."""
    h = ["%s %s HTTP/1.1" % (method, path), "Host: %s" % host, "User-Agent: %s" % ua, "Accept: */*"]
    h += list(headers or [])
    if body or method in ("POST", "PUT"):
        if not any(x.lower().startswith(("content-length", "transfer-encoding")) for x in h):
            h.append("Content-Length: %d" % len(body))
    h.append("Connection: keep-alive")
    return ("\r\n".join(h) + "\r\n\r\n").encode() + body


def _resp(status, body, ctype, ts, server="nginx/1.26.2", headers=None):
    return P.http_response(status, body, ctype, ts, server=server, headers=headers)


def _tls_open(ctx, src, dst, ts, *, host=None, port=443, profile=None, rate=None, dns=True, selfsigned=False, alpn=b"http/1.1"):
    """DNS (if the destination has a name) + ARP + TCP handshake + TLS handshake.
    Returns (pre_packets, session, tls)."""
    from ...tls import TlsSession
    host = host or _host_of(dst)
    pre = _lookup(ctx, src, dst, ts) if dns else []
    t = ts + F.rng.uniform(0.005, 0.05) + (0.02 if pre else 0.0)
    out = list(pre) + ctx.arp_for(src, dst, t)
    s = ctx.tcp(src, dst, port, t + 0.001, rate=rate).handshake()
    tls = TlsSession(ctx.pki, host, ctx.keylog, profile=profile or getattr(src, "tls_profile", "winhttp"),
                     selfsigned=selfsigned, alpn=alpn)
    for from_c, data in tls.handshake():
        if from_c:
            s.c2s(data, think=F.rng.uniform(0.0005, 0.003))
        else:
            s.s2c(data, think=F.rng.uniform(0.002, 0.01))
    return out, s, tls


def _tls_close(s, tls, pre, keep_open=0.3):
    s.c2s(tls.close_notify(True), think=keep_open)
    return F.merged(pre, s.close(think=0.002))


def _tcp_open(ctx, src, dst, ts, port=80, rate=None):
    pre = _lookup(ctx, src, dst, ts)
    t = ts + F.rng.uniform(0.005, 0.05) + (0.02 if pre else 0.0)
    out = list(pre) + ctx.arp_for(src, dst, t)
    s = ctx.tcp(src, dst, port, t + 0.001, rate=rate).handshake()
    return out, s


def _sz(lo, hi):
    lo, hi = int(lo), int(hi)
    return F.rng.randint(min(lo, hi), max(lo, hi))


# ---------------------------------------------------------------------------- beacon profiles
# Cadence / look presets. These are benign look-alike requests, not tooling: a path, a user agent,
# one header and an opaque body. ``body_in`` is the request body kind, ``resp`` the response type.
PROFILES = {
    "generic": dict(ua=None, method="GET", paths=["/api/v1/status", "/api/v1/sync", "/health/check"],
                    headers=["Accept: application/json"], ctype="application/json", tls="winhttp", cookie=None, post_body=False),
    "cobaltstrike-like": dict(ua="Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)", method="GET",
                              paths=["/jquery-3.3.1.min.js"], headers=["Accept: */*"], ctype="application/javascript",
                              tls="winhttp", cookie="__cfduid", post_body=False),
    "empire-like": dict(ua="Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko", method="GET",
                        paths=["/news.php", "/admin/get.php", "/login/process.php"], headers=[],
                        ctype="text/html; charset=UTF-8", tls="winhttp", cookie="session", post_body=False),
    "updater-like": dict(ua="UpdateAgent/2.1", method="POST", paths=["/v2/telemetry", "/v2/checkin"],
                         headers=["Content-Type: application/octet-stream"], ctype="application/octet-stream",
                         tls="go", cookie=None, post_body=True),
}


def _profile(name):
    p = PROFILES.get(str(name or "generic").lower())
    if p is None:
        from .. import families                      # malware-family look-alikes, consulted after the presets above
        fam = families.lookup(name)
        p = fam["profile"] if fam else None
    return p if p is not None else PROFILES["generic"]


def _beacon_exchange(ctx, src, host, prof, size_lo, size_hi, ts, method=None):
    """One request/response of a beacon profile. Returns (request_bytes, response_builder)."""
    method = method or prof["method"]
    path = F.rng.choice(prof["paths"])
    hdrs = list(prof["headers"])
    ua = prof["ua"] or _client_ua(ctx, src)
    body = b""
    if prof["cookie"]:
        hdrs.append("Cookie: %s=%s" % (prof["cookie"], _b64(_sz(40, 90))))
    if method == "POST":
        body = _rb(_sz(60, 240)) if prof["post_body"] else _b64(_sz(60, 240)).encode()
        if not any(h.lower().startswith("content-type") for h in hdrs):
            hdrs.append("Content-Type: application/x-www-form-urlencoded")
    req = _req(method, path, host, ua, hdrs, body)
    size = _sz(size_lo, size_hi)
    rb = _rb(size) if "json" not in prof["ctype"] else (b'{"s":0,"d":"' + _b64(max(4, size - 14)).encode() + b'"}')
    return req, rb


# ---------------------------------------------------------------------------- https_beacon / http_beacon
def https_beacon(ctx, src, dst, *, ts, count=4, interval_s=60.0, jitter=0.2, size_min=180, size_max=900,
                 profile="generic", keepalive=False):
    """Low-and-slow HTTPS check-ins to a C2 host. DNS lookup of the C2 name first (when the host has one),
    then ``count`` decryptable TLS 1.2 sessions on a jittered cadence (or one kept-open session when
    ``keepalive``). Each is a small GET/POST with a fixed look (profile) and a small opaque reply.
    Written to the key log, so the sensor can decrypt them."""
    prof = _profile(profile)
    host = _host_of(dst)
    count = max(1, int(count))
    t = ts
    out = []
    if keepalive:
        pre, s, tls = _tls_open(ctx, src, dst, t, profile=prof["tls"], rate=50e6)
        for i in range(count):
            req, rb = _beacon_exchange(ctx, src, host, prof, size_min, size_max, s.t)
            s.c2s(tls.app_data(True, req), think=F.rng.uniform(0.0008, 0.004) if i == 0 else _gap(interval_s, jitter))
            s.s2c(tls.app_data(False, _resp("200 OK", rb, prof["ctype"], s.t)), think=F.rng.uniform(0.02, 0.12))
        return _tls_close(s, tls, pre, 0.4)
    for i in range(count):
        pre, s, tls = _tls_open(ctx, src, dst, t, profile=prof["tls"], rate=50e6)
        req, rb = _beacon_exchange(ctx, src, host, prof, size_min, size_max, s.t)
        s.c2s(tls.app_data(True, req), think=F.rng.uniform(0.0008, 0.004))
        s.s2c(tls.app_data(False, _resp("200 OK", rb, prof["ctype"], s.t)), think=F.rng.uniform(0.02, 0.12))
        out += _tls_close(s, tls, pre, 0.4)
        t += _gap(interval_s, jitter)
    return F.merged(out)


def http_beacon(ctx, src, dst, *, ts, count=4, interval_s=60.0, jitter=0.2, size_min=120, size_max=700,
                profile="generic", method="GET"):
    """Plain-HTTP check-ins (port 80) to a C2 host: DNS lookup first, then ``count`` short TCP sessions on a
    jittered cadence, each one small request (GET, POST, or alternating with ``mixed``) and a small opaque reply."""
    prof = _profile(profile)
    host = _host_of(dst)
    out, t = [], ts
    for i in range(max(1, int(count))):
        m = method.upper()
        if m == "MIXED":
            m = "GET" if i % 2 == 0 else "POST"
        req, rb = _beacon_exchange(ctx, src, host, prof, size_min, size_max, t, method=m)
        pre, s = _tcp_open(ctx, src, dst, t, 80, rate=50e6)
        s.c2s(req, think=F.rng.uniform(0.0008, 0.004))
        s.s2c(_resp("200 OK", rb, prof["ctype"], s.t), think=F.rng.uniform(0.02, 0.12))
        out += F.merged(pre, s.close(think=F.rng.uniform(0.1, 0.6)))
        t += _gap(interval_s, jitter)
    return F.merged(out)


# ---------------------------------------------------------------------------- DNS channel plumbing
def _ext_host(ctx, key, name, ip, hops):
    cache = ctx.__dict__.setdefault("_campa_ext", {})
    if key not in cache:
        h = Host(name.split(".")[0].upper(), ip, "02:00:5e:%02x:%02x:%02x" % tuple(F.rng.randrange(256) for _ in range(3)),
                 "linux", "external", "198.51.100.0/24", name)
        h.hops = hops
        cache[key] = h
    return cache[key]


def _domain_of(dst, domain):
    d = (domain or dst.fqdn or "c2.example.test").strip(".").lower()
    return d


def _delegation_walk(ctx, dc, domain, ns, t):
    """The resolver's first walk for a zone it has not seen: root, then TLD, then the zone's own server."""
    done = ctx.__dict__.setdefault("_campa_deleg", set())
    zone = ".".join(domain.split(".")[-2:])
    if zone in done:
        return [], t
    done.add(zone)
    tldn = zone.rsplit(".", 1)[-1]
    root = _ext_host(ctx, "root-a", "a.root-servers.net", "198.41.0.4", 7)
    tld = _ext_host(ctx, "tld-" + tldn, "a0.nic." + tldn, "194.0.1.1", 8)
    out = []
    for host, qn, ref_zone, ref_ns in ((root, tldn, tldn, ["a0.nic." + tldn]), (tld, zone, zone, [ns.fqdn or "ns1." + zone])):
        x = ctx.next_txid()
        dsp = dc.eph()
        out += ctx.arp_for(dc, host, t)
        out.append(ctx.udp(dc, host, dsp, 53, P.dns_query(x, qn, 2, rd=False, edns=True), t))
        out.append(ctx.udp(host, dc, 53, dsp, P.dns_referral(x, qn, 2, ref_zone, ref_ns), t + F.rng.uniform(0.012, 0.04), vantage=dc))
        t += 0.06
    return out, t


def _ns_exchange(ctx, src, dc, ns, domain, qname, qtype, t, answers, rcode=0):
    """One lookup: client -> resolver, resolver -> the zone's server and back, resolver -> client.
    ``answers`` is the (rtype, rdata) list the zone's server returns."""
    out = []
    txid = ctx.next_txid()
    sport = src.eph()
    out.append(ctx.udp(src, dc, sport, 53, P.dns_query(txid, qname, qtype), t))
    dtx = ctx.next_txid()
    dsp = dc.eph()
    out += ctx.arp_for(dc, ns, t + 0.0005)
    out.append(ctx.udp(dc, ns, dsp, 53, P.dns_query(dtx, qname, qtype, rd=False, edns=True), t + 0.0007))
    auth = (domain, P.soa_rdata(ns.fqdn or "ns1." + domain, "hostmaster." + domain)) if (rcode or not answers) else None
    up = P.dns_response(dtx, qname, qtype, answers, rcode=rcode, aa=True, ttl=0, authority=auth, auth_ttl=60)
    out.append(ctx.udp(ns, dc, 53, dsp, up, t + F.rng.uniform(0.02, 0.08), vantage=dc))
    down = P.dns_response(txid, qname, qtype, answers, rcode=rcode, aa=False, ttl=0, authority=auth, auth_ttl=60)
    out.append(ctx.udp(dc, src, 53, sport, down, t + F.rng.uniform(0.09, 0.12), vantage=src))
    return out


def _txt(data):
    chunk = base64.b64encode(data)[:255]
    return (P.DNS_TXT, bytes([len(chunk)]) + chunk)


QTYPES = {"A": P.DNS_A, "TXT": P.DNS_TXT, "CNAME": 5, "AAAA": P.DNS_AAAA}


def _answer_for(qtype, ns, size):
    """A small benign answer record of the type asked for."""
    if qtype == P.DNS_TXT:
        return [_txt(_rb(size))]
    if qtype == 5:
        return [(5, P._dns_name(_b32(min(40, max(8, size // 2))) + "." + (ns.fqdn or "example.test").split(".", 1)[-1]))]
    if qtype == P.DNS_AAAA:
        return [(P.DNS_AAAA, b"\x00" * 15 + b"\x01")]
    return [(P.DNS_A, bytes([127, 0, 0, 1]))]


def _dns_stream(ctx, src, ns, domain, ts, names, qtype, gaps, ans_size=(24, 90)):
    """Emit one lookup per name in ``names`` using the per-step gaps. Returns packets."""
    dc = F._dc_for(ctx, src, None, 0.85)
    out = ctx.arp_for(src, dc, ts)
    pre, t = _delegation_walk(ctx, dc, domain, ns, ts)
    out += pre
    for nm, g in zip(names, gaps):
        out += _ns_exchange(ctx, src, dc, ns, domain, nm, qtype, t, _answer_for(qtype, ns, _sz(*ans_size)))
        t += g
    return F.merged(out)


# ---------------------------------------------------------------------------- dns_beacon / dns_tunnel
def dns_beacon(ctx, src, dst, *, ts, count=6, interval_s=60.0, jitter=0.1, qtype="TXT", label_len=32, domain=""):
    """Periodic DNS check-ins to a C2 domain: one query every ~interval_s whose name is a fixed-size random
    base32 label under the domain (A or TXT), answered by the C2 name server with a tiny benign record.
    The constant label length and the steady period are what a DNS-beacon analytic keys on."""
    dom = _domain_of(dst, domain)
    qt = QTYPES.get(str(qtype).upper(), P.DNS_TXT)
    n = max(1, int(count))
    names = ["%s.%s" % (_b32(min(63, max(4, int(label_len)))), dom) for _ in range(n)]
    return _dns_stream(ctx, src, dst, dom, ts, names, qt, [_gap(interval_s, jitter) for _ in range(n)], (16, 48))


def dns_tunnel(ctx, src, dst, *, ts, bursts=2, per_burst=25, burst_gap_s=30.0, qtype="TXT", label_len=60, labels=2, domain=""):
    """Bursts of encoded-looking DNS queries: ``per_burst`` queries back to back (50-250 ms apart), each with
    ``labels`` long random base32 labels under the C2 domain, TXT (or CNAME) answers carrying base64 filler.
    No real data and nothing decodes; it has the length, entropy and rate of a DNS tunnel."""
    dom = _domain_of(dst, domain)
    qt = QTYPES.get(str(qtype).upper(), P.DNS_TXT)
    if qt not in (P.DNS_TXT, 5):
        qt = P.DNS_TXT
    ll = min(63, max(8, int(label_len)))
    nl = max(1, min(int(labels), (253 - len(dom) - 1) // (ll + 1)))
    names, gaps = [], []
    for b in range(max(1, int(bursts))):
        for i in range(max(1, int(per_burst))):
            names.append(".".join(_b32(ll) for _ in range(nl)) + "." + dom)
            last = i == int(per_burst) - 1
            gaps.append(_gap(burst_gap_s, 0.3) if last else F.rng.uniform(0.05, 0.25))
    return _dns_stream(ctx, src, dst, dom, ts, names, qt, gaps, (40, 160))


# ---------------------------------------------------------------------------- dga_lookup
DGA_TLDS = ["top", "xyz", "info", "net", "com", "online"]


def _dga_name():
    r = F.rng
    alphabet = "bcdfghjklmnpqrstvwxyz0123456789"
    return "".join(r.choice(alphabet) for _ in range(r.randint(10, 16))) + "." + r.choice(DGA_TLDS)


def dga_lookup(ctx, src, dst, *, ts, count=8, gap_s=0.25, resolve=True):
    """Domain-generation lookups: ``count`` algorithmic-looking names that all come back NXDOMAIN (recursion
    to the ISP resolver and a negative answer with SOA), then, if ``resolve``, the one name that answers
    with the destination's address. Uses the destination's name for the final lookup when it has one."""
    out = []
    t = ts
    for _ in range(max(0, int(count))):
        out += F.dns_lookup(ctx, src, _dga_name(), t, external=True, rcode=3)
        t += F.rng.uniform(0.05, max(0.06, float(gap_s) * 2))
    if resolve:
        name = dst.fqdn or _dga_name()
        out += F.dns_lookup(ctx, src, name, t + F.rng.uniform(0.2, 1.0), external=True,
                            answers=[(P.DNS_A, dst.ipb)], ttl=F.rng.randint(60, 300))
    return F.merged(out)


# ---------------------------------------------------------------------------- tor_connect
CELL = 514          # a Tor cell on the wire for link protocol v4+ (2-byte circuit id): records carry multiples of it


def _tor_name(tld):
    return "www.%s.%s" % (_b32(F.rng.randint(8, 20)), tld)


def tor_connect(ctx, src, dst, *, ts, duration_s=120.0, port=443, records=24):
    """A Tor-like link connection to a relay address: no DNS (the relay is reached by IP), a TLS handshake
    with a random ``www.<random>.com`` SNI and a self-signed certificate under a different random ``.net``
    name (the pattern of a relay link certificate), then application-data records that are whole multiples
    of the 514-byte cell, in both directions, with gaps. Bytes are benign filler."""
    from ...tls import TlsSession
    sni = _tor_name("com")
    t = ts + F.rng.uniform(0.005, 0.05)
    out = ctx.arp_for(src, dst, t)
    s = ctx.tcp(src, dst, int(port), t + 0.001, rate=30e6).handshake()
    tls = TlsSession(ctx.pki, sni, ctx.keylog, profile="openssl", selfsigned=True, alpn=b"")
    for from_c, data in tls.handshake():
        (s.c2s if from_c else s.s2c)(data, think=F.rng.uniform(0.001, 0.01))
    n = max(2, int(records))
    step = float(duration_s) / n
    for i in range(n):
        s.c2s(tls.app_data(True, _rb(CELL * F.rng.choice([1, 1, 1, 2, 3, 4, 8]))), think=step * F.rng.uniform(0.2, 1.4) if i else 0.05)
        s.s2c(tls.app_data(False, _rb(CELL * F.rng.choice([1, 1, 2, 3, 6, 10, 19]))), think=F.rng.uniform(0.03, 0.4))
    s.c2s(tls.close_notify(True), think=F.rng.uniform(0.2, 1.0))
    return F.merged(out, s.close(think=0.01))


# ---------------------------------------------------------------------------- registration
def _p(typ, default, help_):
    return {"type": typ, "default": default, "help": help_}


_BEACON_COMMON = {
    "count": _p("int", 4, "Number of check-ins."),
    "interval_s": _p("float", 60.0, "Mean seconds between check-ins."),
    "jitter": _p("float", 0.2, "Fractional jitter on the interval (0.2 = plus or minus 20 percent)."),
    "profile": _p("str", "generic", "Look-alike request preset: " + ", ".join(sorted(PROFILES)) +
                  "; or a malware-family look-alike: " + ", ".join(_families.ids()) + "."),
}

register(ActionSpec(
    token="https_beacon", fn=https_beacon, title="HTTPS beacon", tactic="command-and-control",
    techniques=["T1071.001", "T1573.002"], protocols=["DNS", "TLS", "HTTPS"],
    summary="A DNS lookup of the C2 name, then small decryptable HTTPS check-ins on a jittered low-and-slow cadence.",
    params=dict(_BEACON_COMMON, size_min=_p("int", 180, "Smallest reply body in bytes."),
                size_max=_p("int", 900, "Largest reply body in bytes."),
                keepalive=_p("bool", False, "One kept-open TLS session instead of a new one per check-in.")),
    src="internal", dst="external", needs=("DC1",), min_duration_s=60.0))

register(ActionSpec(
    token="http_beacon", fn=http_beacon, title="HTTP beacon", tactic="command-and-control",
    techniques=["T1071.001"], protocols=["DNS", "HTTP"],
    summary="A DNS lookup of the C2 name, then plain-HTTP GET or POST check-ins on port 80 on a jittered cadence.",
    params=dict(_BEACON_COMMON, size_min=_p("int", 120, "Smallest reply body in bytes."),
                size_max=_p("int", 700, "Largest reply body in bytes."),
                method=_p("str", "GET", "GET, POST or mixed.")),
    src="internal", dst="external", needs=("DC1",), min_duration_s=60.0))

register(ActionSpec(
    token="dns_beacon", fn=dns_beacon, title="DNS beacon", tactic="command-and-control",
    techniques=["T1071.004"], protocols=["DNS"],
    summary="Periodic TXT or A lookups of a fixed-length random label under the C2 domain, answered by its name server.",
    params={"count": _p("int", 6, "Number of lookups."), "interval_s": _p("float", 60.0, "Mean seconds between lookups."),
            "jitter": _p("float", 0.1, "Fractional jitter on the interval."), "qtype": _p("str", "TXT", "TXT, A, CNAME or AAAA."),
            "label_len": _p("int", 32, "Length of the random label (fixed pattern)."),
            "domain": _p("str", "", "C2 domain; default the destination's name.")},
    src="internal", dst="external", needs=("DC1",), min_duration_s=60.0))

register(ActionSpec(
    token="dns_tunnel", fn=dns_tunnel, title="DNS tunnel", tactic="command-and-control",
    techniques=["T1572", "T1071.004"], protocols=["DNS"],
    summary="Bursts of long base32-label TXT queries to a C2 domain with base64 TXT answers, at tunnel rates.",
    params={"bursts": _p("int", 2, "Number of bursts."), "per_burst": _p("int", 25, "Queries per burst."),
            "burst_gap_s": _p("float", 30.0, "Mean seconds between bursts."), "qtype": _p("str", "TXT", "TXT or CNAME."),
            "label_len": _p("int", 60, "Length of each random label (max 63)."), "labels": _p("int", 2, "Labels per query name."),
            "domain": _p("str", "", "C2 domain; default the destination's name.")},
    src="internal", dst="external", needs=("DC1",), min_duration_s=30.0))

register(ActionSpec(
    token="dga_lookup", fn=dga_lookup, title="DGA lookups", tactic="command-and-control",
    techniques=["T1568.002"], protocols=["DNS"],
    summary="A burst of algorithmic-looking names that all return NXDOMAIN, then one name that answers.",
    params={"count": _p("int", 8, "Number of NXDOMAIN names."), "gap_s": _p("float", 0.25, "Mean seconds between names."),
            "resolve": _p("bool", True, "End with one answering name.")},
    src="internal", dst="external", needs=("DC1",), min_duration_s=5.0))

register(ActionSpec(
    token="tor_connect", fn=tor_connect, title="Tor relay connection", tactic="command-and-control",
    techniques=["T1090.003"], protocols=["TCP", "TLS"],
    summary="A TLS connection to a relay IP with a random www.<random>.com SNI and cell-size-multiple records.",
    params={"duration_s": _p("float", 120.0, "Seconds the connection stays active."), "port": _p("int", 443, "Relay port (443 or 9001)."),
            "records": _p("int", 24, "Record exchanges in the connection.")},
    src="internal", dst="external", needs=(), min_duration_s=120.0))
