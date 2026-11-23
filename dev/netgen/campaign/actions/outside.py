"""Outside-in actions: what an internet-side party does to, and from, the environment
(ATT&CK tactics "reconnaissance", "resource-development" and "initial-access").

Every action here reproduces network *behaviour* only, so a sensor has something to see: a burst of
web requests that mostly miss, DNS guesses that mostly come back NXDOMAIN, a TLS contact with a
certificate that is minutes old or self-signed, a login URL hit with many dummy credential pairs, an
exposed remote-access service that is tried until a few attempts get through. There is no exploit,
no web shell, no tool output and no working credential on the wire: bodies are inert filler or plain
look-alike pages, every account and password is a dummy, and every name is under ``.example``.

Direction. ``web_dir_scan``, ``subdomain_enum``, ``web_login_spray`` and ``exposed_service_login`` are
inbound: ``src`` is an internet host, ``dst`` an internal server (frames are captured on the
internal side, so the engine addresses them from ``dst``'s segment). ``new_domain_contact`` and
``selfsigned_tls_contact`` are the opposite: an internal host reaches out.

Randomness comes from ``netgen.flows.rng`` only (the registry also makes the OS entropy source repeatable).
The one non-repeatable input is the RSA key material the TLS layer mints, so TLS flows repeat in shape,
sizes and timing but not in handshake bytes.
"""
import datetime

from . import ActionSpec, register
from .c2 import _b64, _gap, _req, _resp, _rb, _sz, _tls_open, _tls_close
from .recon import account_names
from ... import flows as F
from ... import protocols as P
from ...identity import get_current

# --------------------------------------------------------------------------- shared helpers
SCAN_UA = "Mozilla/5.0 (compatible; webprobe/1.0)"
DUMMY_USERS = ["admin", "administrator", "test", "user", "support", "guest", "info", "sales", "backup", "service",
               "helpdesk", "operator", "manager", "demo", "webmaster"]
DUMMY_PASSWORDS = ["Welcome1!", "Spring2026!", "Password1", "Changeme123", "Summer2026#", "Qwerty123!"]


def _public_domain():
    """The company's public-facing zone, always under .example (never the internal AD name)."""
    return "%s.example" % get_current().slug


def _web_name(host):
    return (host or "www." + _public_domain()).strip(".").lower()


def _in_open(ctx, src, dst, t, port, tls_host=None, profile="openssl", rate=50e6):
    """Inbound TCP (and TLS when ``tls_host``) connection setup. Frames are captured on dst's side.
    Returns (session, tls or None)."""
    from ...tls import TlsSession
    s = ctx.tcp(src, dst, port, t + F.rng.uniform(0.001, 0.01), vantage=dst, rate=rate).handshake()
    if not tls_host:
        return s, None
    tls = TlsSession(ctx.pki, tls_host, ctx.keylog, profile=profile, alpn=b"http/1.1")
    for from_c, data in tls.handshake():
        if from_c:
            s.c2s(data, think=F.rng.uniform(0.0005, 0.003))
        else:
            s.s2c(data, think=F.rng.uniform(0.002, 0.01))
    return s, tls


def _exchange(s, tls, req, resp, c_think, s_think=None):
    """One request and its reply on an open (optionally TLS) session."""
    if tls is None:
        s.c2s(req, think=c_think)
        s.s2c(resp, think=s_think if s_think is not None else F.rng.uniform(0.0004, 0.004))
    else:
        s.c2s(tls.app_data(True, req), think=c_think)
        s.s2c(tls.app_data(False, resp), think=s_think if s_think is not None else F.rng.uniform(0.0006, 0.006))


# --------------------------------------------------------------------------- web_dir_scan
_WORDS = ["admin", "login", "wp-login.php", "wp-admin", "administrator", "phpmyadmin", "backup", "backups", "old", "test",
          "dev", "staging", "api", "api/v1", "console", "dashboard", "manager", "config", "config.php", "uploads",
          "upload", "files", "images", "img", "js", "css", "static", "assets", "includes", "inc", "tmp", "temp",
          "logs", "log", "cgi-bin", "server-status", "robots.txt", "sitemap.xml", "index.php", "index.html", "home",
          "user", "users", "account", "portal", "intranet", "private", "secret", "download", "downloads", "docs",
          "doc", "help", "support", "register", "signup", "search", "status", "health", "metrics", "swagger",
          ".env", ".git/config", ".htaccess", "web.config", "readme.txt", "changelog.txt", "db", "sql", "data"]
_HITS = {   # path -> (status, location or None, body kind)
    "/login": ("200 OK", None, "page"), "/admin": ("302 Found", "/admin/login", "redirect"),
    "/robots.txt": ("200 OK", None, "robots"), "/images": ("301 Moved Permanently", "/images/", "redirect"),
    "/js": ("301 Moved Permanently", "/js/", "redirect"), "/css": ("301 Moved Permanently", "/css/", "redirect"),
    "/uploads": ("403 Forbidden", None, "forbidden"), "/server-status": ("403 Forbidden", None, "forbidden"),
    "/index.html": ("200 OK", None, "page"), "/api": ("401 Unauthorized", None, "json401"),
}
_NOT_FOUND = (b"<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
              b"<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")
_FORBIDDEN = _NOT_FOUND.replace(b"404 Not Found", b"403 Forbidden")


def _scan_paths(count, extensions):
    out = []
    exts = [e for e in (extensions or [""]) if isinstance(e, str)] or [""]
    for e in exts:
        for w in _WORDS:
            out.append("/" + w + (e if "." not in w else ""))
    seen, uniq = set(), []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq[:max(1, int(count))]


def _scan_reply(path, ts, host):
    hit = _HITS.get(path)
    if hit is None:
        return _resp("404 Not Found", _NOT_FOUND, "text/html", ts, server="nginx")
    status, loc, kind = hit
    hdrs = ["Location: http://%s%s" % (host, loc)] if loc else None
    if kind == "page":
        body = b"<!DOCTYPE html><html><head><title>Sign in</title></head><body><form method=\"post\"></form></body></html>"
        return _resp(status, body, "text/html; charset=utf-8", ts, server="nginx")
    if kind == "robots":
        return _resp(status, b"User-agent: *\nDisallow: /admin\n", "text/plain", ts, server="nginx")
    if kind == "forbidden":
        return _resp(status, _FORBIDDEN, "text/html", ts, server="nginx")
    if kind == "json401":
        return _resp(status, b'{"error":"unauthorized"}', "application/json", ts, server="nginx", headers=["WWW-Authenticate: Bearer"])
    return _resp(status, b"<html><head><title>%s</title></head></html>" % status[4:].encode(), "text/html", ts, server="nginx", headers=hdrs)


def web_dir_scan(ctx, src, dst, *, ts, count=60, connections=4, rate_rps=25.0, host="", port=80, tls=False,
                 extensions=None, user_agent=SCAN_UA):
    """Content discovery against a web server. The internet-side client sends ``count`` GET requests for a
    word list of common paths over ``connections`` keep-alive TCP connections at about ``rate_rps`` requests per
    second in total. Nearly every reply is a fixed-size 404; a handful are 200, 301/302, 401 or 403. With
    ``tls`` the same exchange runs inside a decryptable TLS session on ``port`` (443 is used when ``port`` is 80).
    Not simulated: any request that exploits a flaw; there are only plain, valid GETs."""
    host = _web_name(host)
    paths = _scan_paths(count, extensions)
    n = max(1, min(int(connections), len(paths)))
    port = int(port)
    if tls and port == 80:
        port = 443
    per = 1.0 / max(0.5, float(rate_rps)) * n
    sessions = []
    t = ts
    for i in range(n):
        sessions.append(_in_open(ctx, src, dst, t + i * F.rng.uniform(0.01, 0.12), port, host if tls else None))
    for i, p in enumerate(paths):
        s, tl = sessions[i % n]
        req = _req("GET", p, host, user_agent)
        _exchange(s, tl, req, _scan_reply(p, s.t, host), per * F.rng.uniform(0.5, 1.5))
    out = []
    for s, tl in sessions:
        if tl is not None:
            s.c2s(tl.close_notify(True), think=F.rng.uniform(0.01, 0.1))
        out += s.close(think=F.rng.uniform(0.002, 0.03))
    return F.merged(out)


# --------------------------------------------------------------------------- subdomain_enum
_SUBS = ["www", "mail", "smtp", "pop", "imap", "vpn", "remote", "dev", "test", "staging", "stage", "api", "portal",
         "intranet", "admin", "ftp", "ns1", "ns2", "webmail", "owa", "autodiscover", "git", "ci", "jenkins", "jira",
         "wiki", "help", "support", "cdn", "static", "assets", "app", "beta", "demo", "db", "sql", "backup", "old",
         "secure", "sso", "login", "m", "shop", "blog", "crm", "erp", "proxy", "gateway", "mx", "uat", "qa",
         "monitor", "files", "sftp", "dns", "citrix", "rdp", "ldap", "docs", "status", "grafana"]


def _txt_rdata(text):
    b = text.encode()
    return bytes([len(b)]) + b


def _dns_q(ctx, src, dst, name, qtype, t, answers, rcode, domain, soa):
    """One external query to the zone's server and its reply (UDP/53, captured on dst's side)."""
    tx = ctx.next_txid()
    sp = src.eph()
    q = ctx.udp(src, dst, sp, 53, P.dns_query(tx, name, qtype, rd=False, edns=True), t, vantage=dst)
    auth = (domain, soa) if (rcode or not answers) else None
    r = P.dns_response(tx, name, qtype, answers, rcode=rcode, aa=True, ttl=300, authority=auth, auth_ttl=300)
    return [q, ctx.udp(dst, src, 53, sp, r, t + F.rng.uniform(0.0004, 0.003), vantage=dst)]


def subdomain_enum(ctx, src, dst, *, ts, count=60, found=6, rate_qps=15.0, domain="", axfr=True):
    """Name guessing against the company's public zone. The internet-side host asks the zone's DNS server (``dst``)
    for the apex records (SOA, NS, MX, TXT), optionally attempts a zone transfer over TCP/53 (answered REFUSED),
    then sends ``count`` A queries for common sub-names at ``rate_qps``. Most come back NXDOMAIN with the zone's
    SOA; ``found`` of them answer with a documentation-range address. Not simulated: any record that exists
    in a real zone, and every answer is a placeholder."""
    dom = (domain or _public_domain()).strip(".").lower()
    ns1, ns2 = "ns1." + dom, "ns2." + dom
    soa = P.soa_rdata(ns1, "hostmaster." + dom)
    out, t = [], ts
    apex = [(P.DNS_SOA, [(P.DNS_SOA, soa)]), (2, [(2, P._dns_name(ns1)), (2, P._dns_name(ns2))]),
            (15, [(15, b"\x00\x0a" + P._dns_name("mail." + dom))]), (P.DNS_TXT, [(P.DNS_TXT, _txt_rdata("v=spf1 -all"))])]
    for qt, ans in apex:
        out += _dns_q(ctx, src, dst, dom, qt, t, ans, 0, dom, soa)
        t += F.rng.uniform(0.02, 0.12)
    if axfr:
        tx = ctx.next_txid()
        s = ctx.tcp(src, dst, 53, t, vantage=dst).handshake()
        q = P.dns_query(tx, dom, 252, rd=False)
        s.c2s(len(q).to_bytes(2, "big") + q, think=F.rng.uniform(0.001, 0.005))
        r = P.dns_response(tx, dom, 252, [], rcode=5, aa=True)
        s.s2c(len(r).to_bytes(2, "big") + r, think=F.rng.uniform(0.001, 0.004))
        out += s.close(think=F.rng.uniform(0.01, 0.1))
        t = s.t + F.rng.uniform(0.2, 1.0)
    names = list(_SUBS)
    F.rng.shuffle(names)
    k = 2
    while len(names) < int(count):          # more than the list holds: numbered variants of the same names
        names += ["%s%d" % (w, k) for w in _SUBS]
        k += 1
    names = names[:max(1, int(count))]
    hit_idx = set(F.rng.sample(range(len(names)), min(len(names), max(0, int(found)))))
    gap = 1.0 / max(0.5, float(rate_qps))
    for i, w in enumerate(names):
        fq = "%s.%s" % (w, dom)
        if i in hit_idx:
            ip = bytes([203, 0, 113, F.rng.randint(2, 250)])
            out += _dns_q(ctx, src, dst, fq, P.DNS_A, t, [(P.DNS_A, ip)], 0, dom, soa)
        else:
            out += _dns_q(ctx, src, dst, fq, P.DNS_A, t, [], 3, dom, soa)
        t += gap * F.rng.uniform(0.5, 1.5)
    return F.merged(out)


# --------------------------------------------------------------------------- new_domain_contact
def _fresh_leaf(ctx, name, ts, issued_minutes_ago, valid_days):
    """Register a leaf certificate for ``name`` that was issued ``issued_minutes_ago`` before ``ts`` and is valid
    ``valid_days`` days, chained to the engine's public look-alike CA, so the shared certificate cache serves it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(65537, 2048)
    ca_key, ca_cert = ctx.pki._public_ca()
    t0 = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc) - datetime.timedelta(minutes=float(issued_minutes_ago))
    t0 = t0.replace(microsecond=0)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(t0).not_valid_after(t0 + datetime.timedelta(days=int(valid_days)))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ctx.pki.leaf[name] = (key, cert.public_bytes(serialization.Encoding.DER), ca_cert.public_bytes(serialization.Encoding.DER))


def new_domain_contact(ctx, src, dst, *, ts, domain="", visits=2, interval_s=20.0, issued_minutes_ago=12.0, valid_days=90):
    """First contact with a freshly stood-up domain. A DNS lookup of the name (short TTL), then HTTPS on 443 to a
    server presenting a certificate issued ``issued_minutes_ago`` minutes before the contact with a ``valid_days``-day
    life, answering a small look-alike placeholder page. ``visits`` sessions follow on a jittered cadence. The name is
    ``domain``, else the destination's name, else a random name under .example. Not simulated: the registry data a
    sensor might enrich with; only the DNS, certificate and web exchange are on the wire."""
    name = (domain or dst.fqdn or "").strip(".").lower() or ("%s-%s.example" % (_b64(6).lower().replace("+", "a").replace("/", "b"),
                                                                           F.rng.choice(["portal", "update", "secure", "docs"])))
    _fresh_leaf(ctx, name, ts, issued_minutes_ago, valid_days)
    out = F.dns_lookup(ctx, src, name, ts, external=True, answers=[(P.DNS_A, dst.ipb)], ttl=60)
    t = ts + F.rng.uniform(0.15, 0.6)
    ua = P.UAS[0] if ctx.is_windows(src) else P.UAS[2]
    page = b"<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>It works</h1></body></html>"
    for i in range(max(1, int(visits))):
        pre, s, tls = _tls_open(ctx, src, dst, t, host=name, profile=getattr(src, "tls_profile", "chrome"), dns=False, rate=50e6)
        s.c2s(tls.app_data(True, _req("GET", "/", name, ua)), think=F.rng.uniform(0.001, 0.004))
        s.s2c(tls.app_data(False, _resp("200 OK", page, "text/html; charset=utf-8", s.t, server="nginx")), think=F.rng.uniform(0.02, 0.1))
        out += _tls_close(s, tls, pre, 0.3)
        t += _gap(interval_s, 0.3)
    return F.merged(out)


# --------------------------------------------------------------------------- selfsigned_tls_contact
def selfsigned_tls_contact(ctx, src, dst, *, ts, port=8443, sessions=3, interval_s=45.0, jitter=0.3, size_min=200,
                           size_max=1200, host=""):
    """Check-ins to a server that presents a self-signed certificate (issuer equals subject, not trusted) on a
    non-standard TCP port (default 8443). DNS lookup first when the destination has a name. ``sessions`` TLS 1.2
    connections on a jittered cadence, each a small opaque request and reply, decryptable from the key log. The
    ClientHello name is ``host``, else the destination's name, else ``localhost``. Not simulated: any
    payload; the bytes are inert filler."""
    sni = (host or dst.fqdn or "localhost").strip(".").lower()
    out, t = [], ts
    for i in range(max(1, int(sessions))):
        pre, s, tls = _tls_open(ctx, src, dst, t, host=sni, port=int(port), profile="go", dns=bool(dst.fqdn), selfsigned=True, rate=50e6)
        s.c2s(tls.app_data(True, _rb(_sz(120, 420))), think=F.rng.uniform(0.001, 0.005))
        s.s2c(tls.app_data(False, _rb(_sz(size_min, size_max))), think=F.rng.uniform(0.02, 0.12))
        out += _tls_close(s, tls, pre, 0.4)
        t += _gap(interval_s, jitter)
    return F.merged(out)


# --------------------------------------------------------------------------- web_login_spray
def _login_users(ctx, n, users):
    base = [str(u) for u in (users or [])]
    if not base:
        base = list(account_names(ctx, int(n))) or []
    for u in DUMMY_USERS:
        if len(base) >= int(n):
            break
        if u not in base:
            base.append(u)
    return base[:max(1, int(n))]


def web_login_spray(ctx, src, dst, *, ts, attempts=24, passwords=None, users=None, path="/login", host="", port=443,
                    connections=2, gap_s=0.7, successes=1):
    """Credential guessing against a web login form. The internet-side client opens ``connections`` decryptable
    HTTPS sessions to ``dst`` (SNI and Host ``host``, else the public name of the site) and sends ``attempts`` POSTs
    of dummy username and password pairs (each password tried across the user list, a spray) to ``path``.
    Replies are 401 with a small JSON error, except ``successes`` attempt(s) late in the run that answer 302 with a
    dummy session cookie. Not simulated: real accounts, real passwords or any request that is not a plain form post."""
    host = _web_name(host)
    pw = [str(p) for p in (passwords or DUMMY_PASSWORDS)] or DUMMY_PASSWORDS
    us = _login_users(ctx, max(3, int(attempts) // max(1, len(pw))) + 2, users)
    pairs = []
    for p in pw:
        for u in us:
            pairs.append((u, p))
    pairs = pairs[:max(1, int(attempts))]
    n = len(pairs)
    ok = set()
    if n > 2 and int(successes) > 0:
        ok = set(F.rng.sample(range(n // 2, n), min(int(successes), n - n // 2)))
    nconn = max(1, min(int(connections), n))
    sessions = [_in_open(ctx, src, dst, ts + i * F.rng.uniform(0.05, 0.4), int(port), host, profile="go") for i in range(nconn)]
    for i, (u, p) in enumerate(pairs):
        s, tl = sessions[i % nconn]
        body = ("username=%s&password=%s" % (u, p)).encode()
        req = _req("POST", path, host, "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
                   ["Content-Type: application/x-www-form-urlencoded", "Origin: https://" + host], body)
        if i in ok:
            resp = _resp("302 Found", b"", "text/html", s.t, server="nginx",
                         headers=["Location: /home", "Set-Cookie: sid=%s; Path=/; Secure; HttpOnly" % _b64(32)])
        else:
            resp = _resp("401 Unauthorized", b'{"error":"invalid credentials"}', "application/json", s.t, server="nginx")
        _exchange(s, tl, req, resp, _gap(gap_s, 0.5) * nconn, F.rng.uniform(0.03, 0.12))
    out = []
    for s, tl in sessions:
        s.c2s(tl.close_notify(True), think=F.rng.uniform(0.05, 0.4))
        out += s.close(think=0.003)
    return F.merged(out)


# --------------------------------------------------------------------------- exposed_service_login
def _ssh_attempt(ctx, src, dst, t, user, success, session_s):
    s = ctx.tcp(src, dst, 22, t, vantage=dst, rate=50e6).handshake()
    s.c2s(b"SSH-2.0-libssh_0.10.5\r\n", think=0.002)
    s.s2c(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n", think=0.003)
    s.c2s(P.ssh_kexinit(True), think=0.002)
    s.s2c(P.ssh_kexinit(False), think=0.002)
    s.c2s(P.ssh_ecdh_init(), think=0.003)
    s.s2c(P.ssh_ecdh_reply() + P.ssh_newkeys(), think=0.004)
    s.c2s(P.ssh_newkeys(), think=0.002)
    s.c2s(P.ssh_encrypted(44), think=0.003)
    s.s2c(P.ssh_encrypted(60), think=0.002)
    s.c2s(P.ssh_encrypted(92 + 4 * len(user)), think=F.rng.uniform(0.05, 0.4))
    if success:
        s.s2c(P.ssh_encrypted(28), think=F.rng.uniform(0.05, 0.25))                  # userauth success
        t_end = s.t + float(session_s)
        while s.t < t_end:                                                           # an interactive session: small bursts both ways
            s.c2s(P.ssh_encrypted(F.rng.choice([36, 52, 68, 100])), think=F.rng.uniform(0.4, 3.0))
            s.s2c(P.ssh_encrypted(F.rng.choice([52, 84, 148, 420, 1100])), think=F.rng.uniform(0.01, 0.1))
        return s.close(think=F.rng.uniform(0.05, 0.3)), s.t
    s.s2c(P.ssh_encrypted(76), think=F.rng.uniform(0.9, 2.2))                        # userauth failure after the KDF delay
    return s.close(by_client=True, think=F.rng.uniform(0.01, 0.05)), s.t


def _rdp_attempt(ctx, src, dst, t, user, success, session_s):
    from ...tls import TlsSession
    s = ctx.tcp(src, dst, 3389, t, vantage=dst, rate=50e6).handshake()
    s.c2s(P.rdp_x224_connect(user), think=0.002)
    s.s2c(P.rdp_x224_confirm(), think=0.003)
    tls = TlsSession(ctx.pki, dst.fqdn or "rdp-host", F._NullLog(), alpn=b"", kex="ecdhe", selfsigned=True)
    for from_c, data in tls.handshake():
        (s.c2s if from_c else s.s2c)(data, think=F.rng.uniform(0.002, 0.01))
    for size, from_c in ((420, True), (310, False)):                                  # CredSSP request, then the server's answer
        data = tls.app_data(from_c, P.blob(int(size * F.rng.uniform(0.95, 1.05))))
        (s.c2s if from_c else s.s2c)(data, think=F.rng.uniform(0.01, 0.08))
    if success:
        t_end = s.t + float(session_s)
        s.c2s(tls.app_data(True, P.blob(F.rng.randint(300, 900))), think=F.rng.uniform(0.05, 0.2))
        s.s2c(tls.app_data(False, P.blob(F.rng.randint(1500, 6000))), think=F.rng.uniform(0.02, 0.1))
        while s.t < t_end:                                                            # graphics updates and input
            s.s2c(tls.app_data(False, P.blob(F.rng.choice([300, 900, 2400, 8000]))), think=F.rng.uniform(0.05, 0.6))
            s.c2s(tls.app_data(True, P.blob(F.rng.choice([60, 90, 140]))), think=F.rng.uniform(0.05, 0.8))
        s.c2s(tls.close_notify(True), think=F.rng.uniform(0.1, 0.5))
        return s.close(think=0.01), s.t
    if F.rng.random() < 0.6:
        return s.rst_from_server(think=F.rng.uniform(0.05, 0.2)), s.t
    s.s2c(tls.close_notify(False), think=F.rng.uniform(0.02, 0.1))
    return s.close(by_client=False, think=0.003), s.t


def exposed_service_login(ctx, src, dst, *, ts, service="rdp", attempts=14, successes=2, users=None, gap_s=2.5,
                          session_s=20.0):
    """Logon attempts from the internet against an exposed remote-access service. ``service`` is ``rdp`` (TCP/3389:
    X.224 negotiation, TLS, CredSSP) or ``ssh`` (TCP/22: banners, key exchange, encrypted authentication). Each of
    ``attempts`` is one connection; most end in the service's ordinary failure, but ``successes`` attempt(s) in the
    second half go through and stay up for about ``session_s`` seconds of interactive-looking traffic before closing.
    Account names are dummies. Not simulated: real credentials or the contents of the session (the bytes are
    encrypted filler)."""
    svc = str(service).lower()
    if svc not in ("rdp", "ssh"):
        svc = "rdp"
    fn = _rdp_attempt if svc == "rdp" else _ssh_attempt
    default = ["administrator", "admin", "backup", "svc_admin", "user1", "support"] if svc == "rdp" else ["root", "admin", "ubuntu", "oracle", "deploy", "test"]
    names = [str(u) for u in (users or default)] or default
    n = max(1, int(attempts))
    ok = set()
    if n > 2 and int(successes) > 0:
        ok = set(F.rng.sample(range(n // 2, n), min(int(successes), n - n // 2)))
    out, t = [], ts
    for i in range(n):
        pk, t_end = fn(ctx, src, dst, t, names[i % len(names)], i in ok, session_s)
        out += pk
        t = t_end + _gap(gap_s, 0.6)
    return F.merged(out)


# --------------------------------------------------------------------------- registration
def _p(typ, default, help_):
    return {"type": typ, "default": default, "help": help_}


register(ActionSpec(
    token="web_dir_scan", fn=web_dir_scan, title="Web content discovery scan", tactic="reconnaissance",
    techniques=["T1595.003"], protocols=["TCP", "HTTP", "TLS"],
    summary="An internet host sends a burst of GETs for common paths to a web server over a few keep-alive connections; nearly all replies are 404.",
    params={"count": _p("int", 60, "Paths requested."),
            "connections": _p("int", 4, "Parallel keep-alive connections."),
            "rate_rps": _p("float", 25.0, "Total requests per second."),
            "host": _p("str", "", "Host header (and SNI with tls); default is the company's public www name."),
            "port": _p("int", 80, "TCP port (443 is used when tls and the port is 80)."),
            "tls": _p("bool", False, "Run the exchange inside a decryptable TLS session."),
            "extensions": _p("list", None, "Suffixes tried after each plain word, for example ['', '.bak']."),
            "user_agent": _p("str", SCAN_UA, "User-Agent header of the scanner.")},
    src="external", dst="internal", min_duration_s=6.0))

register(ActionSpec(
    token="subdomain_enum", fn=subdomain_enum, title="Sub-domain name guessing", tactic="reconnaissance",
    techniques=["T1596.001", "T1590.002"], protocols=["DNS"],
    summary="An internet host asks the zone's DNS server for the apex records, tries a zone transfer (refused), then guesses common sub-names; most return NXDOMAIN.",
    params={"count": _p("int", 60, "Sub-name queries."),
            "found": _p("int", 6, "How many of the guessed names exist."),
            "rate_qps": _p("float", 15.0, "Queries per second."),
            "domain": _p("str", "", "Zone under test; default is the company's public domain under .example."),
            "axfr": _p("bool", True, "Include a TCP zone-transfer attempt (answered REFUSED).")},
    src="external", dst="internal", min_duration_s=5.0))

register(ActionSpec(
    token="new_domain_contact", fn=new_domain_contact, title="Contact with a freshly issued domain", tactic="resource-development",
    techniques=["T1583.001", "T1608.003"], protocols=["DNS", "TLS", "HTTPS"],
    summary="A DNS lookup of a freshly named domain, then HTTPS to a server whose certificate was issued minutes earlier with a short validity.",
    params={"domain": _p("str", "", "Name contacted; default the destination's name or a random name under .example."),
            "visits": _p("int", 2, "HTTPS sessions."),
            "interval_s": _p("float", 20.0, "Mean seconds between sessions."),
            "issued_minutes_ago": _p("float", 12.0, "Age of the certificate at first contact, in minutes."),
            "valid_days": _p("int", 90, "Certificate validity in days.")},
    src="internal", dst="external", min_duration_s=3.0))

register(ActionSpec(
    token="selfsigned_tls_contact", fn=selfsigned_tls_contact, title="TLS to a self-signed server on a non-standard port",
    tactic="resource-development", techniques=["T1587.003"], protocols=["DNS", "TLS"],
    summary="Repeated TLS sessions to a server presenting a self-signed certificate on a non-standard port such as 8443.",
    params={"port": _p("int", 8443, "Server TCP port."),
            "sessions": _p("int", 3, "TLS sessions."),
            "interval_s": _p("float", 45.0, "Mean seconds between sessions."),
            "jitter": _p("float", 0.3, "Fractional jitter on the interval."),
            "size_min": _p("int", 200, "Smallest reply in bytes."),
            "size_max": _p("int", 1200, "Largest reply in bytes."),
            "host": _p("str", "", "ClientHello name; default the destination's name or localhost.")},
    src="internal", dst="external", min_duration_s=5.0))

register(ActionSpec(
    token="web_login_spray", fn=web_login_spray, title="Web login credential spray", tactic="initial-access",
    techniques=["T1110.004", "T1078"], protocols=["TCP", "TLS", "HTTPS"],
    summary="An internet host posts many dummy username and password pairs to a login URL over HTTPS; replies are 401 except one 302.",
    params={"attempts": _p("int", 24, "Login attempts."),
            "passwords": _p("list", None, "Dummy passwords sprayed across the user list."),
            "users": _p("list", None, "Dummy account names; default the build's directory names plus generic ones."),
            "path": _p("str", "/login", "Login URL path."),
            "host": _p("str", "", "Host header and SNI; default the company's public www name."),
            "port": _p("int", 443, "TCP port."),
            "connections": _p("int", 2, "Parallel HTTPS sessions."),
            "gap_s": _p("float", 0.7, "Mean seconds between attempts per session."),
            "successes": _p("int", 1, "Attempts (in the second half) answered with a 302.")},
    src="external", dst="internal", min_duration_s=10.0))

register(ActionSpec(
    token="exposed_service_login", fn=exposed_service_login, title="Logon attempts on an exposed remote-access service",
    tactic="initial-access", techniques=["T1133"], protocols=["TCP", "RDP", "SSH", "TLS"],
    summary="An internet host tries an exposed RDP or SSH service connection after connection; most fail, a few succeed and stay up.",
    params={"service": _p("str", "rdp", "rdp (TCP/3389) or ssh (TCP/22)."),
            "attempts": _p("int", 14, "Connections attempted."),
            "successes": _p("int", 2, "Attempts (in the second half) that succeed."),
            "users": _p("list", None, "Dummy account names."),
            "gap_s": _p("float", 2.5, "Mean seconds between attempts."),
            "session_s": _p("float", 20.0, "Seconds a successful session stays up.")},
    src="external", dst="internal", min_duration_s=30.0))
