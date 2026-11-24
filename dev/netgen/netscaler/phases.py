"""The NetScaler-compromise attack phases plus benign interleave.

Every builder has the engine's scheduled-flow signature ``fn(ctx, <hosts...>, ts=None)`` and returns
a merged packet list. The orchestrator in ``__init__.py`` resolves the (remapped) hosts once and
schedules these at the exact relative offsets of the source incident. Nothing here runs unless the scenario is
selected, and no host is created until the builder runs -- so the baseline pin is untouched.

Addressing is REMAPPED into the OpenGenerator framework (internal 10.10.x.x + corp.example.local,
external documentation IPs); the attack *content* (UAs, URIs, C2 domains, the SPN-scan filter, the
enumerated account names, OpenSSH/curl versions) is kept verbatim so the records read true.
"""
import base64
import os
import struct

from netgen import flows as F
from netgen import protocols as P
from netgen import asn1 as A

from . import wire
from . import content

rng = F.rng


# ============================================================ small HTTP helper (JA4H-aware)
def _http_req(method, path, host, ua, cookie=None, referer=None, accept_lang=None, extra=None, body=b""):
    """Raw HTTP/1.1 request with explicit control over the headers JA4H keys on (cookie, referer,
    Accept-Language), so each phase lands on the spec's JA4H_a prefix. Literal JA4H cookie hashes
    are not reproducible from the spec; the *same-cookie-two-clients* signal is (phases pass one
    identical literal cookie to owner and attacker)."""
    h = ["%s %s HTTP/1.1" % (method, path), "Host: %s" % host, "User-Agent: %s" % ua]
    if referer:
        h.append("Referer: %s" % referer)
    if accept_lang:
        h.append("Accept-Language: %s" % accept_lang)
    if extra:
        h += extra
    if cookie:
        h.append("Cookie: %s" % cookie)
    if body:
        h.append("Content-Length: %d" % len(body))
    h.append("Connection: keep-alive")
    return ("\r\n".join(h) + "\r\n\r\n").encode() + body


def _https_open(ctx, client, server, ts, profile, sni=None, vantage=None, selfsigned=False):
    """TCP + crafted TLS 1.3 handshake (ClientHello for JA4, ServerHello+Cert for JA4S/JA4X509).
    Returns the live TcpSession positioned after the handshake."""
    out = ctx.arp_for(client, server, ts, vantage=vantage)
    s = ctx.tcp(client, server, 443, ts + 0.001, vantage=vantage).handshake()
    s.c2s(wire.client_hello_for(profile, sni), think=0.002)
    if selfsigned:
        _key, der = ctx.pki.bad_cert_for(server.fqdn, "selfsigned")
        ca_der = None
    else:
        _key, der, ca_der = ctx.pki.cert_for(server.fqdn)
    s.s2c(wire.server_hello_flight(der, ca_der), think=0.004)
    s._ns_pre = out
    return s


def _https_msg(s, req, resp):
    s.c2s(wire.tls_cleartext(req), think=rng.uniform(0.002, 0.02))
    s.s2c(wire.tls_cleartext(resp), think=rng.uniform(0.01, 0.12))


# ============================================================ Phase 1 -- webshell / implant C2
_WSHOT_UA = "Wshot/3.1 (X11; Linux x86_64) "
# decoded command -> plausible output body sizes (spec 4)
_WS_CMDS = {
    "ls /var/vpn/scripts/": (73, 146),
    "whoami": (17, 90),
    "id": (134,),
    "uname -a": (117, 190),
    "netstat -tlnp": (413, 486),
    "cat /netscaler/ns.conf": (862,),
}
_WS_ASSETS = {
    "logo": ("/vpn/images/logo_header.png", "image/png"),
    "theme": ("/Citrix/StoreWeb/resources/css/theme.css", "text/css"),
    "whip": ("/vpn/media/css/whipshot.css?ver=3.1.2", "text/css"),
    "boot": ("/vpn/media/css/bootstrap-grid.min.css?v=7.0", "text/css"),
}


def _conf_cache(ctx, vip):
    """The appliance's ns.conf text (what `cat /netscaler/ns.conf` shows), built once per run."""
    from . import nsconf, _SNIP_IP
    c = ctx.__dict__.setdefault("_ns_conf_text", {})
    if vip.ip not in c:
        c[vip.ip] = nsconf.ns_conf(vip=vip.ip, snip=ctx.link.place(_SNIP_IP), domain=P.DOMAIN,
                                   server_pfx=".".join(str(b) for b in ctx.link.fw_b.ipb[:3]))
    return c[vip.ip]


def webshell_beacon(ctx, implant, vip, cmd, asset, ts=None):
    """One Wshot HTTPS GET: base64 command in the UA, a static-asset path, body size encodes the
    command output. Decryptable content (cleartext in TLS record)."""
    host = "%s:443" % vip.ip
    path, ctype = _WS_ASSETS[asset]
    body_n = rng.choice(_WS_CMDS[cmd])
    from . import _SNIP_IP
    ns_conf = _conf_cache(ctx, vip) if cmd.startswith("cat") else b""
    ua = _WSHOT_UA + base64.b64encode(cmd.encode()).decode()
    s = _https_open(ctx, implant, vip, ts, "implant", sni=None, vantage=vip)
    req = _http_req("GET", path, host, ua, referer="https://%s/vpn/index.html" % vip.ip)  # no cookie -> JA4H ge11nr
    # the shell answers with the command's own output, whatever the camouflage asset's name says
    out = content.netscaler_cmd_output(cmd, body_n, ns_conf, vip.ip, ctx.link.place(_SNIP_IP), ctx.link.user_net.rsplit(".", 1)[0])
    resp = P.http_response("200 OK", out, "text/plain", s.t, server="Apache")
    _https_msg(s, req, resp)
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


# ============================================================ Phase 2 -- outbound C2 beacon (TCP 8443)
def c2_beacon(ctx, snip, sink, counter, ts=None):
    """Raw TCP 8443 heartbeat: 'BD <b64 ping counter epoch>' out, 'ACK <epoch>' back. ~5 pkts."""
    out = ctx.arp_for(snip, sink, ts, vantage=snip)
    s = ctx.tcp(snip, sink, 8443, ts + 0.001, vantage=snip).handshake()
    epoch = int(ts) if ts else 1791560678
    ping = ("ping %d %d" % (counter, epoch)).encode()
    s.c2s(b"BD " + base64.b64encode(ping), think=rng.uniform(0.01, 0.08))
    s.s2c(("ACK %d" % epoch).encode(), think=rng.uniform(0.02, 0.2))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.05, 0.3)))


# ============================================================ Phase 3 -- DTLS probe + burst (UDP 443)
def _udp_port(host):
    """An ephemeral port outside 33434-33689, which Wireshark reads as a traceroute probe."""
    p = host.eph()
    while 33434 <= p <= 33689:
        p = host.eph()
    return p


def dtls_probe(ctx, attacker, vip, ts=None):
    """1 datagram 53B out, 1 datagram 44B back (exact), each a DTLS 1.2 application-data record
    (13-byte record header + payload). No handshake."""
    sport = _udp_port(attacker)
    return F.merged([
        ctx.udp(attacker, vip, sport, 443, wire.dtls_record(0, 53 - 13), ts, vantage=vip),
        ctx.udp(vip, attacker, 443, sport, wire.dtls_record(0, 44 - 13), ts + rng.uniform(0.01, 0.05), vantage=vip),
    ])


def _split_total(total, n):
    """n positive sizes summing exactly to total, varied."""
    base = max(1, total // n)
    sizes = [base] * n
    rem = total - base * n
    i = 0
    while rem > 0:
        add = min(rem, rng.randint(1, max(1, base)))
        sizes[i % n] += add
        rem -= add
        i += 1
    rng.shuffle(sizes)
    return sizes


def dtls_burst(ctx, attacker, vip, ts=None):
    """27 client datagrams summing 16,992 B; 27 server datagrams summing 1,188 B; ~1.84 s span.
    Each datagram is one DTLS 1.2 record (epoch 1, increasing sequence number): the sizes are the
    datagram sizes, so the record length is the size less the 13-byte header."""
    sport = _udp_port(attacker)
    out = []
    cs = _split_total(16992, 27)
    ss = _split_total(1188, 27)
    span = 1.84
    for i in range(27):
        t = ts + span * i / 27.0
        out.append(ctx.udp(attacker, vip, sport, 443, wire.dtls_record(i + 1, cs[i] - 13), t, vantage=vip))
        out.append(ctx.udp(vip, attacker, 443, sport, wire.dtls_record(i + 1, ss[i] - 13), t + rng.uniform(0.002, 0.03), vantage=vip))
    return F.merged(out)


# ============================================================ Phase 4 -- portal session replay
# The owner logs in (POST /cgi/login -> 302 with Set-Cookie NSC_AAAC), so the cookie the attacker
# later replays was issued by the gateway. One identical cookie then rides on BOTH the owner's and
# the attacker's requests -> a sensor computes the SAME JA4H cookie hashes for two clients.
STOLEN_SESSION = "kP3vN8xQ2mTz7Lw9RbYc5Hs1"
STOLEN_COOKIE = "NSC_AAAC=%s; NSC_TASS=on" % STOLEN_SESSION
_CHROME_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/125.0.0.0 Safari/537.36")
_FIREFOX_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0"
_REPLAY_PAGES = [("/vpn/index.html", 1520, "Citrix Gateway"), ("/Citrix/StoreWeb/", 639, "Example StoreFront"),
                 ("/Citrix/StoreWeb/", 639, "Example StoreFront"), ("/", 5083, "Dashboard"),
                 ("/reports.php", 14751, "Reports"), ("/accounts.php?id=29", 4058, "Accounts")]
_SET_COOKIE = ["Set-Cookie: NSC_AAAC=%s; path=/; secure; HttpOnly" % STOLEN_SESSION,
               "Set-Cookie: NSC_TASS=on; path=/; secure"]


def portal_replay(ctx, attacker, vip, ts=None):
    """Attacker replays the stolen session (Chrome/125 + stolen cookie), 6 GETs of the portal pages."""
    host = "%s:443" % vip.ip
    s = _https_open(ctx, attacker, vip, ts, "chrome", sni=None, vantage=vip)
    for path, size, title in _REPLAY_PAGES:
        req = _http_req("GET", path, host, _CHROME_UA, cookie=STOLEN_COOKIE, accept_lang="en-US,en;q=0.9")
        _https_msg(s, req, P.http_response("200 OK", content.html_page(title, size, path), "text/html; charset=utf-8",
                                           s.t, server="Apache"))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.1, 0.5)))


def portal_legit(ctx, owner, vip, ts=None):
    """The owner signs in (the gateway issues the cookie), then browses with it (two-network overlap)."""
    host = "%s:443" % vip.ip
    s = _https_open(ctx, owner, vip, ts, "workforce", sni=None, vantage=vip)
    form = ("login=%s&passwd=%s" % (P.username_for("EXL-WS-017"), "".join(chr(97 + rng.randrange(26)) for _ in range(12)))).encode()
    req = _http_req("POST", "/cgi/login", host, _FIREFOX_UA, accept_lang="en-US,en;q=0.9",
                    referer="https://%s/vpn/index.html" % vip.ip,
                    extra=["Content-Type: application/x-www-form-urlencoded"], body=form)
    _https_msg(s, req, P.http_response("302 Found", b"", "text/html", s.t, server="Apache",
                                       headers=_SET_COOKIE + ["Location: /Citrix/StoreWeb/"]))
    for path in ("/", "/index.php"):
        req = _http_req("GET", path, host, _FIREFOX_UA, cookie=STOLEN_COOKIE, accept_lang="en-US,en;q=0.9")
        _https_msg(s, req, P.http_response("200 OK", content.html_page("Dashboard", rng.randint(1200, 5000), path),
                                           "text/html", s.t, server="Apache"))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.1, 0.5)))


# ============================================================ Phase 5 -- first-seen C2 DNS (NXDOMAIN)
def c2_dns(ctx, snip, dns, qname, ts=None):
    """Two A lookups of a first-seen C2 domain (two client ports), both NXDOMAIN (rcode 3)."""
    out = []
    for _ in range(2):
        sport = snip.eph()
        txid = rng.randint(1, 0xFFFF)
        out.append(ctx.udp(snip, dns, sport, 53, P.dns_query(txid, qname, P.DNS_A), ts, vantage=snip))
        zone, soa, atl = P.tld_negative(qname)
        out.append(ctx.udp(dns, snip, 53, sport, P.dns_response(txid, qname, P.DNS_A, [], rcode=3, aa=False,
                                                                authority=(zone, soa), auth_ttl=atl),
                           ts + rng.uniform(0.002, 0.02), vantage=snip))
        ts += rng.uniform(0.01, 0.05)
    return F.merged(out)


# ============================================================ Phase 6 -- config exfil (cleartext HTTP 443)
def config_exfil(ctx, snip, sink, body, ts=None, path="/staging/ns1_ns.conf"):
    """Cleartext HTTP PUT of the stolen artefact on 443 (NOT TLS), named by `path`
    (default: the NetScaler's own ns1_ns.conf). ~200KB body -> ~199 req packets
    (MSS clamped). curl/7.81.0 -> JA4H pu11nn prefix. The Host header and the PUT's
    destination are always `sink`'s own fqdn/address -- never another scenario's."""
    out = ctx.arp_for(snip, sink, ts, vantage=snip)
    s = ctx.tcp(snip, sink, 443, ts + 0.001, mss=1008, vantage=snip, rate=12e6).handshake()
    req = _http_req("PUT", path, "%s:443" % sink.fqdn, "curl/7.81.0", body=body)
    s.c2s(req, think=0.01)
    s.s2c(P.http_response("200 OK", ("ok: stored %s\n" % path).encode(), "text/plain", s.t, server="nginx"),
          think=rng.uniform(0.05, 0.2))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.05, 0.3)))


# ============================================================ bulk data exfil (HIGH-volume stage)
def data_exfil(ctx, src, sink, total_bytes, ts=None, label="archive.bin"):
    """Staged bulk data exfil: a large multi-MB cleartext HTTP PUT to the exfil sink. This is the
    HIGH-volume stage (tens of MB), deliberately distinct from the ~KB config/key exfil
    (config_exfil) and the hundreds-of-bytes C2 heartbeats (c2_beacon), so a bytes-to-attacker view
    separates the stages of an incident. The body is high-entropy filler the size of the staged
    archive -- nothing is real data; only the volume and the destination are the signal."""
    total = max(200_000, int(total_bytes))
    out = ctx.arp_for(src, sink, ts, vantage=src)
    s = ctx.tcp(src, sink, 443, ts + 0.001, mss=1460, vantage=src, rate=25e6).handshake()
    req = _http_req("PUT", "/stage/%s" % label, (sink.fqdn or sink.ip) + ":443", "curl/8.4.0",
                    extra=["Content-Type: application/octet-stream"], body=P.blob(total))
    s.c2s(req, think=0.01)
    s.s2c(P.http_response("200 OK", b"ok\n", "text/plain", s.t, server="nginx"),
          think=rng.uniform(0.05, 0.3))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.05, 0.4)))


# ============================================================ Phase 7 -- LDAP enum + SPN scan (389)
# The accounts the enumeration looks for exist in the estate's directory (netgen/accounts.py):
# built-ins, four workstation users, the service accounts. The bind account is a service account
# whose name the stolen ns.conf carries.
BIND_ACCOUNT = "svc_scan"
_USERS = [P.username_for("EXL-WS-%03d" % n) for n in (3, 17, 29, 40)]
_ENUM = [("samAccountName", "administrator"), ("samAccountName", "krbtgt"), ("samAccountName", BIND_ACCOUNT),
         ("samAccountName", _USERS[0]), ("samAccountName", _USERS[1]),
         ("samAccountName", _USERS[2]), ("samAccountName", _USERS[3]),
         ("samAccountName", "svc_sql"), ("samAccountName", "svc_backup"), ("samAccountName", "svc_legacy"),
         ("objectClass", "group"), ("memberOf", "CN=Domain Admins,OU=Groups," + P.BASE_DN),
         ("adminCount", "1"), ("__SPN__", "*")]
_SPN_ACCOUNTS = [("svc_sql", "MSSQLSvc/exl-sql1.corp.example.local"), ("svc_scan", "HTTP/exl-log1.corp.example.local")]   # template tokens; see _retoken
_BIND_PW = "".join(content._rnd("ldap-bind").choice("abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#%") for _ in range(16))


def _retoken(s):
    """Module-level LDAP names (_ENUM, _SPN_ACCOUNTS) are written in the TEMPLATE identity's tokens
    (corp.example.local, DC=corp,DC=example,DC=local, exl-) and frozen at import; re-express them for
    the identity of the build being generated, at the moment they are used."""
    from netgen import identity as ID
    cur, tpl = ID.get_current(), ID.DEFAULT
    tpl_dn = ",".join("DC=" + lbl for lbl in tpl.domain.split("."))
    return (s.replace(tpl_dn, P.BASE_DN).replace(tpl.domain, P.DOMAIN)
             .replace(tpl.prefix.lower(), cur.prefix.lower()))


def _user_dn(name):
    if name in ("administrator", "krbtgt"):
        return "CN=%s,CN=Users,%s" % (name.capitalize() if name == "administrator" else name, P.BASE_DN)
    if name.startswith("svc_"):
        return "CN=%s,OU=Service Accounts,%s" % (name, P.BASE_DN)
    return "CN=%s,OU=Staff,OU=Users,%s" % (name, P.BASE_DN)


def _simple_bind_success(mid):
    return A.seq(A.integer(mid), A.tlv(0x61, A.enum(0) + A.octets(b"") + A.octets(b"")))


def ldap_enum_run(ctx, snip, dc, queries, offsets, ts=None, bind=None):
    """One cleartext LDAP 389 connection for the whole enumeration (one tool run): a single simple
    bind, then each search at its offset (seconds after `ts`), then an unbind. The SPN scan
    (servicePrincipalName=*) is the one query that fires a detection."""
    out = ctx.arp_for(snip, dc, ts, vantage=snip)
    s = ctx.tcp(snip, dc, 389, ts + 0.001, vantage=snip).handshake()
    mid = 1
    s.c2s(P.ldap_bind_request_simple(mid, "%s\\%s" % (P.NETBIOS, bind or BIND_ACCOUNT), _BIND_PW.encode()), think=0.002)
    s.s2c(_simple_bind_success(mid), think=rng.uniform(0.001, 0.006))
    for (attr, value), off in zip(queries, offsets, strict=False):
        mid += 1
        if attr == "__SPN__":
            filt = P._filter_present("servicePrincipalName")
            attrs = ["servicePrincipalName", "sAMAccountName"]
            entries = [(_user_dn(a), {"servicePrincipalName": [_retoken(spn)], "sAMAccountName": [a]}) for a, spn in _SPN_ACCOUNTS]
        else:
            filt = P._filter_eq(attr, _retoken(value) if isinstance(value, str) else value)
            attrs = ["distinguishedName", "sAMAccountName", "memberOf", "servicePrincipalName"]
            if attr == "samAccountName":
                entries = [(_user_dn(value), {"sAMAccountName": [value]})]
            elif attr == "objectClass":
                entries = [("CN=%s,OU=Groups,%s" % (g, P.BASE_DN), {"sAMAccountName": [g]})
                           for g in ("Domain Admins", "IT-Operations")]
            else:
                entries = [(_user_dn(a), {"sAMAccountName": [a]}) for a in ("administrator", "adm_claypool-mud")]
        s.c2s(P.ldap_search_request(mid, P.BASE_DN, 2, filt, attrs), think=max(0.003, ts + off - s.t))
        resp = b"".join(P.ldap_search_entry(mid, dn, at) for dn, at in entries) + P.ldap_search_done(mid)
        s.s2c(resp, think=rng.uniform(0.002, 0.01))
    mid += 1
    s.c2s(P.ldap_unbind(mid), think=rng.uniform(0.005, 0.05))
    return F.merged(out, s.close(think=0.002))


def ldaps_routine(ctx, snip, dc, ts=None):
    """Routine baseline contrast: an LDAPS 636 bind + search (samaccountname=robert.paulson), the
    gateway's normal auth lookup. Opaque TLS records (not the attack path)."""
    out = ctx.arp_for(snip, dc, ts, vantage=snip)
    s = ctx.tcp(snip, dc, 636, ts + 0.001, vantage=snip).handshake()
    s.c2s(wire.client_hello_for("workforce", sni=dc.fqdn), think=0.002)
    _key, der, ca = ctx.pki.cert_for(dc.fqdn)
    s.s2c(wire.server_hello_flight(der, ca), think=0.004)
    s.c2s(os.urandom(220), think=0.01)       # opaque encrypted bind + search
    s.s2c(os.urandom(640), think=0.02)
    return F.merged(out, s.close(think=rng.uniform(0.05, 0.2)))


# ============================================================ Phase 8 -- SMB session-setup fails (445)
def smb_fail(ctx, snip, dc, ts=None):
    """SMB2 NEGOTIATE then SESSION_SETUP as [Pre-Auth] -> STATUS_INVALID_PARAMETER (0xC000000D)."""
    out = ctx.arp_for(snip, dc, ts, vantage=snip)
    s = ctx.tcp(snip, dc, 445, ts + 0.001, vantage=snip).handshake()
    smb = P.Smb2(require_signing=F._dc_host(dc))
    s.c2s(smb.negotiate_req(os.urandom(16)), think=0.001)
    s.s2c(smb.negotiate_resp(os.urandom(16), s.t), think=0.002)
    nego = bytearray(P.ntlm_negotiate(domain="", workstation="PRE-AUTH"))
    nego[12:16] = struct.pack("<I", struct.unpack("<I", bytes(nego[12:16]))[0] | 0x2000)   # OEM workstation supplied
    s.c2s(smb.session_setup_req(P.spnego_ntlm_init(bytes(nego))), think=0.002)
    s.s2c(smb.session_setup_fail(0xC000000D), think=0.002)   # STATUS_INVALID_PARAMETER
    return F.merged(out, s.close(think=rng.uniform(0.02, 0.1)))


# ============================================================ Phase 9 -- SSH (test + reverse)
# The appliance is FreeBSD-based, the intranet server is Windows: each presents its own OpenSSH banner.
# The algorithm lists (and so HASSH) stay the spec's OpenSSH 9.6 lists. The FreeBSD patch suffix
# is a representative value, not one measured on a real appliance.
_BANNER_NS = b"SSH-2.0-OpenSSH_9.6 FreeBSD-20240701\r\n"
_BANNER_WIN = b"SSH-2.0-OpenSSH_for_Windows_9.5\r\n"


def _ssh_flow(ctx, client, server, ts, duration, vantage=None, cbanner=_BANNER_NS, sbanner=_BANNER_WIN):
    out = ctx.arp_for(client, server, ts, vantage=vantage)
    s = ctx.tcp(client, server, 22, ts + 0.001, vantage=vantage).handshake()
    s.c2s(cbanner, think=0.003)
    s.s2c(sbanner, think=0.003)
    s.c2s(wire.ssh_kexinit(True), think=0.002)      # exact 9.6 client lists -> HASSH aae6b9604f...
    s.s2c(wire.ssh_kexinit(False), think=0.002)     # exact 9.6 server lists -> HASSH e42184b06d...
    s.c2s(wire.ssh_kex_init_sntrup(), think=0.003)           # sntrup761x25519 is the negotiated kex
    s.s2c(wire.ssh_kex_reply_sntrup() + P.ssh_newkeys(), think=0.004)
    s.c2s(P.ssh_newkeys(), think=0.002)
    for c, r in ((44, 60), (120, 76), (508, 36), (92, 52)):
        s.c2s(P.ssh_encrypted(c), think=rng.uniform(0.005, 0.04))
        s.s2c(P.ssh_encrypted(r), think=rng.uniform(0.002, 0.02))
    t_end = s.t + duration
    while s.t < t_end:
        s.c2s(P.ssh_encrypted(rng.choice([36, 52])), think=rng.uniform(0.1, 0.8))
        s.s2c(P.ssh_encrypted(rng.choice([36, 52, 164, 1200])), think=rng.uniform(0.002, 0.02))
    return F.merged(out, s.close(by_client=False, think=rng.uniform(0.05, 0.3)))


def ssh_test(ctx, snip, app, ts=None, cbanner=_BANNER_NS):
    """Outbound SSH test SNIP -> app server (two brief opens); `cbanner` is the client's banner."""
    a = _ssh_flow(ctx, snip, app, ts, rng.uniform(0.3, 0.6), vantage=snip, cbanner=cbanner)
    b = _ssh_flow(ctx, snip, app, ts + rng.uniform(1.0, 3.0), rng.uniform(0.3, 0.6), vantage=snip, cbanner=cbanner)
    return F.merged(a, b)


def ssh_reverse(ctx, app, snip, ts=None):
    """Reverse SSH persistence: app server -> gateway SNIP:22, ~47 s (the inbound foothold)."""
    return _ssh_flow(ctx, app, snip, ts, 46.8, vantage=snip, cbanner=_BANNER_WIN, sbanner=_BANNER_NS)


def rdp_pivot(ctx, client, server, user, duration, ts=None):
    """An RDP logon with a full Kerberos story: the AS exchange for `user` first, then the TGS and
    the RDP session whose X.224 cookie names the same account."""
    as_pk = F.kerberos_as_outcome(ctx, client, ts, user)
    return F.merged(as_pk, F.rdp_session(ctx, client, server, ts + 0.05, duration, user=user))


# ============================================================ pre-window: NDR-API probe (context)
def ndr_api_probe(ctx, vip, probe, ts=None):
    """VIP -> external NDR-API host: curl GET then POST, HTTP 404 (reconnaissance context)."""
    out = ctx.arp_for(vip, probe, ts, vantage=vip)
    s = ctx.tcp(vip, probe, 443, ts + 0.001, vantage=vip).handshake()
    s.c2s(wire.client_hello_for("chrome", sni=probe.fqdn), think=0.002)
    _k, der, ca = ctx.pki.cert_for(probe.fqdn)
    s.s2c(wire.server_hello_flight(der, ca), think=0.004)
    for method in ("GET", "POST"):
        req = _http_req(method, "/api/v1/detections", "%s" % probe.fqdn, "curl/8.5.0",
                        body=(b"{}" if method == "POST" else b""))
        _https_msg(s, req, P.http_response("404 Not Found", b'{"error":"not found"}', "application/json", s.t, server="nginx"))
    return F.merged(out, s.close(think=rng.uniform(0.05, 0.2)))


# ============================================================ benign interleave (spec 13)
_BENIGN_UAS = {
    "A": ("workforce", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0"),
    "B": ("chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"),
    "C": ("chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"),
    "D": ("chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Edg/126.0.0.0"),
}
# Per-product benign-portal profile (shared defect #28's second half): paths, cookie name/shape
# and Server banner, one per product this toolkit is reused by -- it used to send the
# NetScaler's own Citrix paths, NSC_AAAC cookie and an Apache banner to every sibling's host
# regardless of which product's portal the visitor was actually browsing.
_PORTAL_PROFILES = {
    "netscaler": {
        "paths": ["/vpn/index.html", "/vpn/login.html", "/Citrix/StoreWeb/", "/", "/index.php",
                  "/reports.php", "/accounts.php", "/orders.php", "/search.php", "/style.css"],
        "cookie": lambda: "NSC_AAAC=%s; NSC_TASS=on" % base64.b64encode(os.urandom(9)).decode().rstrip("="),
        "server": "Apache", "title": "Citrix Gateway",
    },
    "beyondtrust": {
        "paths": ["/login", "/session/list", "/api/clients", "/css/style.css", "/"],
        "cookie": lambda: "BOMGAR_SESSION=%s" % os.urandom(16).hex(),
        "server": "BeyondTrust Remote Support", "title": "BeyondTrust Remote Support",
    },
    "metabase": {
        "paths": ["/", "/api/user/current", "/dashboard/1", "/assets/app.css"],
        "cookie": lambda: "metabase.SESSION=%s" % os.urandom(16).hex(),
        "server": "Jetty(9.4.51.v20230217)", "title": "Metabase",
    },
    "sharepoint": {
        "paths": ["/_layouts/15/start.aspx", "/sites/Intranet/default.aspx",
                  "/_layouts/15/images/favicon.ico", "/style.css"],
        "cookie": lambda: "ASP.NET_SessionId=%s" % os.urandom(12).hex(),
        "server": "Microsoft-IIS/10.0", "title": "SharePoint",
    },
    "panos": {
        "paths": ["/global-protect/login.esp", "/global-protect/portal/css/portal.css", "/php/login.php"],
        "cookie": lambda: "PHPSESSID=%s" % os.urandom(13).hex(),
        "server": "PanWeb Server/1.0", "title": "GlobalProtect Portal",
    },
    "vcenter": {
        "paths": ["/ui/", "/vsphere-client/", "/websso/SAML2/SSO/vsphere.local", "/sdk"],
        "cookie": lambda: "JSESSIONID=%s" % os.urandom(16).hex().upper(),
        "server": "VMware", "title": "vSphere Client",
    },
}


def _benign_page_body(path, title):
    """A real, readable body for its declared content type (shared defect #31's portal_browse
    part): P.blob random bytes typed text/html/text/css is not what either dissects as."""
    if path.endswith(".css"):
        return (("/* %s */\n" % title) + "body { font-family: sans-serif; margin: 0; }\n"
                ".header { background: #1a1a2e; color: #fff; padding: 12px; }\n").encode()
    return ("<!DOCTYPE html><html><head><title>%s</title></head>"
            "<body><div class=\"header\">%s</div><p>Loading...</p></body></html>"
            % (title, title)).encode()


def portal_browse(ctx, client, vip, label, ts=None, product="netscaler"):
    """A benign workforce portal visit to the scenario's own product's portal (paths, cookie,
    Server banner and page bodies all per `product`): a few GETs with the client's own cookie
    (distinct per session), so the estate shows normal portal traffic around the attack."""
    profile, ua = _BENIGN_UAS[label]
    prof = _PORTAL_PROFILES[product]
    host = "%s:443" % vip.ip
    cookie = prof["cookie"]()
    s = _https_open(ctx, client, vip, ts, profile, sni=None, vantage=vip)
    paths = prof["paths"]
    set_cookie = ["Set-Cookie: %s; path=/; secure" % part for part in cookie.split("; ")]
    first = True
    for path in rng.sample(paths, min(rng.randint(2, 5), len(paths))):
        # the server issues the session on the first response; every later request carries it
        req = _http_req("GET", path, host, ua, cookie=None if first else cookie, accept_lang="en-US,en;q=0.9")
        ctype = "text/css" if path.endswith(".css") else "text/html"
        _https_msg(s, req, P.http_response("200 OK", _benign_page_body(path, prof["title"]),
                                           ctype, s.t, server=prof["server"],
                                           headers=set_cookie if first else None))
        first = False
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.2, 1.5)))
