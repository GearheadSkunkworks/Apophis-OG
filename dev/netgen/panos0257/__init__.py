"""netgen.panos0257 -- the "PAN-OS GlobalProtect CVE-2026-0257" incident-replay scenario.

A replay of the PAN-OS GlobalProtect authentication-bypass zero-day (CVE-2026-0257, CVSS 7.8;
exploited in the wild, CISA KEV; used by ransomware operators Qilin / Inc). The attacker reads the
gateway's certificate chain over TLS and forges an auth-override cookie -- no credentials -- to
stand up an UNAUTHORIZED GlobalProtect VPN session, is assigned an internal VPN IP, and from there
does internal reconnaissance and RDP/SMB lateral movement (the ransomware precursor).

Modelled as a selectable scenario (``ir-panos-globalprotect-cve0257``, category IR). Unlike the other
IR replays, the pivot does NOT originate from the compromised edge box: two hosts are injected at
runtime -- the published GlobalProtect gateway (EXL-GPGW1) and the attacker's VPN-ASSIGNED internal
foothold (EXL-VPN-7731, an address inside the user subnet) -- and the lateral movement is framed as
that internal VPN IP reaching the jump host, the DC and the file server.

RFC 791 / network-observable: real IPv4 datagrams (RFC 1918 estate + RFC 5737 external offender). The
portal legs carry a real key-logged TLS 1.3 handshake with the HTTP as cleartext in the record
(decrypts with the exported keys); the RDP/SMB/LDAP lateral movement from the VPN IP is observable.
(GlobalProtect's ESP data tunnel has no emitter; the observable control channel and the resulting
internal flows are what a sensor sees, which is what this models.)

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

rng = NSP.rng

_GW_SUFFIX, _GW_IP = "GPGW1", "10.10.20.58"          # PAN-OS GlobalProtect gateway (published edge)
_GW_MAC = "00:50:56:bb:07:3d"
_VPN_SUFFIX, _VPN_IP = "VPN-7731", "10.10.10.200"    # the attacker's VPN-assigned internal foothold
_VPN_MAC = "02:00:5e:71:31:aa"
_EXTERNAL = {
    "attacker": ("node57.probe-pool.example", "203.0.113.57", 11),  # offender
    # own benign-workforce identities (shared defect #28): see metabase72898's comment.
    "wfA": ("host-a.gp-telemetry.example", "198.51.100.91", 7),
    "wfB": ("host-b.gp-telemetry.example", "198.51.100.92", 7),
    "wfC": ("host-c.gp-telemetry.example", "198.51.100.93", 7),
    "wfD": ("host-d.gp-telemetry.example", "198.51.100.94", 7),
}
_UA = "PAN GlobalProtect/6.2.0 (Windows 10)"
# the forged auth-override cookie -- the CVE-2026-0257 bypass (observable in the cleartext record)
# An opaque, encrypted-looking override cookie value (not the literal placeholder) -- realistic
# base64-ish length for a signed/encrypted session blob.
import base64 as _b64
_OVERRIDE_VALUE = _b64.b64encode(bytes((i * 37 + 11) % 256 for i in range(96))).decode().rstrip("=")
_OVERRIDE_COOKIE = "portal-userauthcookie=%s; PORTAL-AUTH-OVERRIDE=1" % _OVERRIDE_VALUE
# The account the foothold's RDP/Kerberos identity uses -- a workstation user whose credentials a
# phished/compromised foothold could plausibly hold (not a Domain Admin, not the host-derived
# default), kept the same between the RDP cookie and the Kerberos principal (brief fix 1).
_FOOTHOLD_USER = P.username_for(H("WS-014"))


def _inject_hosts(ctx):
    """Add the GlobalProtect gateway, the attacker's VPN foothold, and the external offender."""
    domain = P.DOMAIN
    gw_name, vpn_name = _host(ctx, _GW_SUFFIX), _host(ctx, _VPN_SUFFIX)
    if gw_name not in ctx.h:
        ctx.h[gw_name] = Host(gw_name, ctx.link.place(_GW_IP), _GW_MAC, "https",
                              "PAN-OS GlobalProtect gateway (published VPN edge)", ctx.link.server_net,
                              "vpn-gp." + domain)
    if vpn_name not in ctx.h:
        # Windows-shaped (TTL 128, Windows SYN options) so the foothold's wire identity matches
        # the Win10 client string the bypass sends (brief fix 2).
        ctx.h[vpn_name] = Host(vpn_name, ctx.link.place(_VPN_IP), _VPN_MAC, "windows workstation",
                               "unauthorized GlobalProtect VPN client", ctx.link.user_net,
                               "gp-client-7731." + domain)
    cache = ctx.__dict__.setdefault("_gp_ext", {})
    for key, (fqdn, ip, hops) in _EXTERNAL.items():
        if key not in cache:
            h = Host(fqdn.split(".")[0].upper(), ip,
                     "02:00:5e:%02x:%02x:%02x" % (rng.randrange(256), rng.randrange(256), rng.randrange(256)),
                     "linux", "external", ip.rsplit(".", 1)[0] + ".0/24", fqdn)
            h.hops = hops
            cache[key] = h
    return cache


def gp_portal_bypass(ctx, atk, gw, ts=None):
    """Stage 1 -- CVE-2026-0257: read the portal config, then log in with the FORGED auth-override
    cookie (no credentials). The cookie is cleartext in the TLS record; the gateway accepts it."""
    host = "%s:443" % gw.ip
    s = _https_open(ctx, atk, gw, ts, "chrome", sni=None, vantage=gw)
    _https_msg(s, _http_req("POST", "/global-protect/portal/config.esp", host, _UA,
                            extra=["Content-Type: application/x-www-form-urlencoded"],
                            body=b"prot=https:&server=" + gw.ip.encode()),
               P.http_response("200 OK", content.xml_doc("policy", 1240, "portal"), "application/xml", s.t, server="PanWeb"))
    _https_msg(s, _http_req("POST", "/ssl-vpn/login.esp", host, _UA, cookie=_OVERRIDE_COOKIE,
                            extra=["Content-Type: application/x-www-form-urlencoded"],
                            body=b"user=&passwd=&ok=Login&clientos=Windows&os-version=Microsoft Windows 10"),
               P.http_response("200 OK", content.xml_doc("response", 380, "login"), "application/xml", s.t, server="PanWeb"))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


def gp_gateway_connect(ctx, atk, gw, ts=None):
    """Stage 2 -- the unauthorized gateway-connected event: getconfig returns the assigned internal
    VPN IP. The IoC shape -- the hard-coded Win10 OS string and an empty domain -- is carried here."""
    host = "%s:443" % gw.ip
    s = _https_open(ctx, atk, gw, ts, "chrome", sni=None, vantage=gw)
    _https_msg(s, _http_req("POST", "/ssl-vpn/getconfig.esp", host, _UA, cookie=_OVERRIDE_COOKIE,
                            extra=["Content-Type: application/x-www-form-urlencoded"],
                            body=b"client-type=1&os-version=Microsoft Windows 10&domain=&computer=DESKTOP-0257"),
               P.http_response("200 OK", ("<?xml version=\"1.0\"?><response><ip-address>%s</ip-address>"
                                          "<netmask>255.255.255.0</netmask></response>" % ctx.link.place(_VPN_IP)).encode(),
                               "application/xml", s.t, server="PanWeb"))
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


# LDAP recon the VPN foothold runs against the DC, ending in the SPN scan
_ENUM = [("samAccountName", "administrator"), ("samAccountName", "svc_backup"),
         ("objectClass", "computer"), ("memberOf", "CN=Domain Admins,OU=Groups," + P.BASE_DN),
         ("__SPN__", "*")]


def build(ctx, eng, tag, win):
    """Schedule the CVE-2026-0257 incident: portal auth-bypass (forged override cookie) -> gateway
    connect (assigned VPN IP) -> internal recon + RDP/SMB/LDAP lateral movement FROM the VPN IP.
    Signature-critical records always emitted; benign VPN volume scales with ctx.scale. Registered
    as ``ir-panos-globalprotect-cve0257`` (imported lazily)."""
    ext = _inject_hosts(ctx)
    from netgen import incidents as INC
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))

    def at(offset):
        return lo + offset

    gw = ctx.h[_host(ctx, _GW_SUFFIX)]
    vpn = ctx.h[_host(ctx, _VPN_SUFFIX)]
    dc1 = ctx.h.get(_host(ctx, "DC1"))
    dc2 = ctx.h.get(_host(ctx, "DC2"))
    file1 = ctx.h.get(_host(ctx, "FILE1"))
    mgmt = ctx.h.get(_host(ctx, "MGMT1"))
    atk = ext["attacker"]

    # ---- Stage 1: portal auth-bypass + unauthorized gateway connect ------------------------
    s(at(20), gp_portal_bypass, atk, gw)
    s(at(48), gp_gateway_connect, atk, gw)
    # the Windows client identity a real join sends: name resolution noise + a DC lookup, so the
    # foothold's early traffic looks like a joining Windows host, not an ARP-only ghost (fix 2)
    s(at(55), F.name_noise, vpn)
    s(at(58), F.dns_lookup, vpn, P.DOMAIN, qtype=P.DNS_A)

    # ---- Stage 2: internal recon + lateral movement FROM the VPN-assigned IP ----------------
    # LDAP enumeration of the DC (ends in the SPN scan)
    if dc1 is not None:
        s(at(180), NSP.ldap_enum_run, vpn, dc1, _ENUM, [i * 5 for i in range(len(_ENUM))])
        s(at(260), NSP.smb_fail, vpn, dc1)
    if dc2 is not None:
        s(at(262), NSP.smb_fail, vpn, dc2)
    # SMB probes of the file server (ransomware looking for shares)
    if file1 is not None:
        s(at(300), NSP.smb_fail, vpn, file1)
        s(at(430), NSP.smb_fail, vpn, file1)
    # RDP into the jump host (the lateral foothold): a real Kerberos AS exchange for the same
    # account the X.224 cookie names, before the TGS (brief fix 1)
    if mgmt is not None:
        s(at(520), NSP.rdp_pivot, vpn, mgmt, _FOOTHOLD_USER, rng.uniform(90, 240))
        s(at(900), NSP.rdp_pivot, vpn, mgmt, _FOOTHOLD_USER, rng.uniform(60, 180))

    # ---- benign interleave: legitimate GlobalProtect portal traffic to the gateway ----------
    for label in ("A", "B", "C", "D"):
        visits = max(2, int(round(8 * scale)))
        for _ in range(visits):
            client = ext[{"A": "wfA", "B": "wfB", "C": "wfC", "D": "wfD"}[label]]
            s(lo + rng.uniform(0, max(1.0, hi - lo - 60)), NSP.portal_browse, client, gw, label, product="panos")
