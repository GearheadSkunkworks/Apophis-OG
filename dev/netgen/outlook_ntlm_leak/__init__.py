"""netgen.outlook_ntlm_leak -- the "Outlook NTLM hash leak (CVE-2026-124194)" incident-replay scenario.

A replay of the exploited Outlook spoofing zero-day (patched in the November 2026 update, CISA KEV):
opening a crafted message file makes Outlook reach an attacker-controlled UNC path WITHOUT the usual
external-content warning, so the user's NTLMv2 challenge-response goes to the attacker.

What a sensor sees (all real wire protocols, no exploit content):
  * the workstation resolves a never-before-seen external name, then opens outbound SMB (TCP 445):
    SMB2 negotiate + a full NTLM NEGOTIATE/CHALLENGE/AUTHENTICATE exchange whose target is NOT a
    domain host, ending in STATUS_LOGON_FAILURE (the capture server records the hash and refuses);
  * the Windows WebClient fallback: HTTP/1.1 OPTIONS + PROPFIND on port 80 from the
    ``Microsoft-WebDAV-MiniRedir`` agent, with the same NTLM handshake carried in
    Authorization / WWW-Authenticate headers;
  * minutes later the harvested identity appears at the internet-facing mail portal: a short password
    spray then a successful sign-in, from the same external address.

Registered as ``ir-outlook-ntlm-leak-cve124194`` (category IR), a SIBLING of the other IR replays.

PIN-SAFE: hosts are injected inside ``build()``; a build that does not select this scenario is
byte-for-byte the baseline.
"""
import base64
import os

from netgen import flows as F
from netgen import protocols as P
from netgen.identity import H
from netgen import packkit as K

from netgen.netscaler import phases as NSP
from netgen.netscaler.phases import _https_open, _http_req, _https_msg

rng = NSP.rng

_EXTERNAL = {
    "rogue": ("share-sync.docfetch-cdn.example", "203.0.113.124", 11),   # SMB + WebDAV capture server
    "actor": ("node124.probe-pool.example", "203.0.113.125", 13),        # later portal sign-ins
    "wfA": ("host-a.docfetch-cdn.example", "198.51.100.124", 7),
    "wfB": ("host-b.docfetch-cdn.example", "198.51.100.125", 7),
}
_OWA_SUFFIX, _OWA_IP, _OWA_MAC = "OWA1", "10.10.20.124", "00:50:56:bb:12:4c"
_UA_OL = "Microsoft-WebDAV-MiniRedir/10.0.19045"
_UA_BR = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/131.0.0.0 Safari/537.36")


def _inject_hosts(ctx):
    owa = K.add_internal(ctx, _OWA_SUFFIX, _OWA_IP, _OWA_MAC, "Windows Server 2022 / Exchange", "https",
                         "mail")
    return K.add_externals(ctx, "_olk_ext", _EXTERNAL, rng), owa


def _victim(ctx, n=0):
    """A user workstation (not the shared compromised foothold)."""
    ws = sorted(h.name for h in ctx.h.values() if h.name.startswith(H("WS")) and h.name != H("WS-047"))
    return ctx.h[ws[n % len(ws)]]


def smb_unc_capture(ctx, victim, rogue, ts=None):
    """Outlook follows the crafted \\\\rogue\\share path: DNS for the new name, then SMB2 on 445 with
    a full NTLM handshake that the capture server answers with STATUS_LOGON_FAILURE."""
    pre = F.dns_lookup(ctx, victim, rogue.fqdn, ts, external=True, answers=[(P.DNS_A, rogue.ipb)])
    t = ts + 0.08
    out = ctx.arp_for(victim, rogue, t)
    s = ctx.tcp(victim, rogue, 445, t + 0.001).handshake()
    smb = P.Smb2(require_signing=False)
    s.c2s(smb.negotiate_req(os.urandom(16)), think=0.0004)
    s.s2c(smb.negotiate_resp(os.urandom(16), s.t), think=rng.uniform(0.012, 0.04))
    s.c2s(smb.session_setup_req(P.spnego_ntlm_init(P.ntlm_negotiate("", victim.name))), think=rng.uniform(0.001, 0.004))
    # a stand-alone capture server answers with a workgroup-style target, not the domain
    s.s2c(smb.session_setup_challenge(P.spnego_ntlm_challenge(P.ntlm_challenge("WORKGROUP"))),
          think=rng.uniform(0.012, 0.04))
    s.c2s(smb.session_setup_req(P.spnego_ntlm_auth(P.ntlm_authenticate(P.username_for(victim.name), P.NETBIOS,
                                                                      victim.name, nt_len=rng.choice((176, 192, 208))))),
          think=rng.uniform(0.003, 0.02))
    s.s2c(smb.session_setup_fail(0xC000006D), think=rng.uniform(0.012, 0.04))      # STATUS_LOGON_FAILURE
    return F.merged(pre, out, s.close(think=rng.uniform(0.001, 0.02)))


def _b64(b):
    return base64.b64encode(b).decode()


def webdav_fallback(ctx, victim, rogue, ts=None):
    """WebClient fallback on :80 when 445 is slow or filtered: OPTIONS then PROPFIND with NTLM in the
    HTTP headers (type 1 -> 401 + type 2 -> type 3), the same identity leak over a second protocol."""
    out = ctx.arp_for(victim, rogue, ts)
    s = ctx.tcp(victim, rogue, 80, ts + 0.001).handshake()
    host = rogue.fqdn
    s.c2s(("OPTIONS /share HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nTranslate: f\r\nConnection: Keep-Alive\r\n\r\n"
           % (host, _UA_OL)).encode(), think=0.001)
    s.s2c(P.http_response("200 OK", b"", "text/plain", s.t, server="Microsoft-IIS/10.0",
                          headers=["Allow: OPTIONS, GET, HEAD, PROPFIND", "DAV: 1, 2", "MS-Author-Via: DAV"]),
          think=rng.uniform(0.01, 0.05))
    pf = ("PROPFIND /share HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nDepth: 0\r\nTranslate: f\r\n"
          "Content-Length: 0\r\n" % (host, _UA_OL))
    s.c2s((pf + "Authorization: NTLM %s\r\n\r\n" % _b64(P.ntlm_negotiate("", victim.name))).encode(),
          think=rng.uniform(0.001, 0.01))
    s.s2c(P.http_response("401 Unauthorized", b"", "text/html", s.t, server="Microsoft-IIS/10.0",
                          headers=["WWW-Authenticate: NTLM " + _b64(P.ntlm_challenge("WORKGROUP"))]),
          think=rng.uniform(0.01, 0.04))
    auth = P.ntlm_authenticate(P.username_for(victim.name), P.NETBIOS, victim.name, nt_len=192)
    s.c2s((pf + "Authorization: NTLM %s\r\n\r\n" % _b64(auth)).encode(), think=rng.uniform(0.001, 0.01))
    s.s2c(P.http_response("401 Unauthorized", b"", "text/html", s.t, server="Microsoft-IIS/10.0",
                          headers=["WWW-Authenticate: NTLM"]), think=rng.uniform(0.01, 0.04))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.05, 0.3)))


def portal_signin(ctx, actor, owa, ok, ts=None, user="user"):
    """One sign-in attempt at the mail portal's forms logon (cleartext POST in the TLS record)."""
    host = "%s:443" % owa.ip
    s = _https_open(ctx, actor, owa, ts, "chrome", sni=owa.fqdn, vantage=owa)
    body = ("destination=https%%3A%%2F%%2F%s%%2Fowa%%2F&flags=4&forcedownlevel=0&username=%s%%5C%s&password=%s&isUtf8=1"
            % (owa.fqdn, P.NETBIOS.lower(), user, "Spring2026!" if ok else "Winter2026!")).encode()
    req = _http_req("POST", "/owa/auth.owa", host, _UA_BR,
                    extra=["Content-Type: application/x-www-form-urlencoded", "Origin: https://" + owa.fqdn], body=body)
    if ok:
        resp = P.http_response("302 Found", b"", "text/html", s.t, server="Microsoft-IIS/10.0",
                               headers=["Location: /owa/", "Set-Cookie: cadata=" + os.urandom(24).hex() + "; path=/owa; secure; HttpOnly"])
    else:
        resp = P.http_response("302 Found", b"", "text/html", s.t, server="Microsoft-IIS/10.0",
                               headers=["Location: /owa/auth/logon.aspx?reason=2&url=https%3a%2f%2f" + owa.fqdn + "%2fowa%2f"])
    _https_msg(s, req, resp)
    return F.merged(s._ns_pre, s.close(think=rng.uniform(0.05, 0.3)))


def file_logon(ctx, ws, file1, ts=None):
    """Ordinary in-estate NTLM share logon (look-alike): same protocol, internal target, success."""
    return F.ntlm_smb_logon(ctx, ws, file1, ts, P.username_for(ws.name))


def build(ctx, eng, tag, win):
    """Schedule the CVE-2026-124194 incident: the crafted message is opened on a few workstations over
    the window (each one leaks over SMB, then WebDAV), then the harvested account is sprayed and used at
    the mail portal. Benign NTLM file-share logons from other workstations run alongside."""
    ext, owa = _inject_hosts(ctx)
    from netgen import incidents as INC
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    rogue, actor = ext["rogue"], ext["actor"]
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))

    # ---- the leak: three recipients open the message, each over SMB then the WebDAV fallback ----
    for i, off in enumerate((95, 640, 1480)):
        v = _victim(ctx, i)
        s(lo + off, smb_unc_capture, v, rogue)
        s(lo + off + 4.2, webdav_fallback, v, rogue)
    # an unpatched-client retry loop: the same UNC target again a few minutes later
    s(lo + 1500, smb_unc_capture, _victim(ctx, 2), rogue)

    # ---- use of the harvested account at the portal: a short spray, then a success ------------
    t = lo + 2100
    for _ in range(max(3, int(round(7 * scale)) + 3)):
        s(t, portal_signin, actor, owa, False, user="tnguyen")
        t += rng.uniform(3, 9)
    s(t + 20, portal_signin, actor, owa, True, user="tnguyen")

    # ---- benign interleave: ordinary NTLM file-share logons and portal visits -----------------
    file1 = ctx.h.get(H("FILE1"))
    if file1 is not None:
        for i in range(max(3, int(round(10 * scale)) + 3)):
            s(lo + rng.uniform(0, max(1.0, hi - lo - 30)), file_logon, _victim(ctx, i + 3), file1)
    for key in ("wfA", "wfB"):
        for _ in range(max(2, int(round(5 * scale)))):
            s(lo + rng.uniform(0, max(1.0, hi - lo - 60)), NSP.portal_browse, ext[key], owa, key[-1],
              product="owa")
