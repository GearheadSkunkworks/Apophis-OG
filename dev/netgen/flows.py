"""
Conversation builders. Each returns a time-sorted list of (ts, frame) that
the Engine streams into the pcap. Application payloads come from
protocols.py; TCP/UDP/ARP mechanics from core.py.
"""
import base64
import os
import random
import struct
import time
import zlib

from . import protocols as P
from .identity import get_current, H
from .core import TcpSession, udp_frame, udp_bcast, mcast_mac, same_subnet, ipv4, eth, ETH_IP

SEED = 9001                 # reseeded per build by netgen.reseed_all()
rng = random.Random(SEED)


def merged(*lists):
    out = []
    for l in lists:
        out.extend(l)
    out.sort(key=lambda p: p[0])
    return out


class Ctx:
    """Shared state: hosts, link model, ARP cache, PKI, key log, counters."""

    def __init__(self, hosts, link, arp, pki, keylog, scale=1.0):
        self.h = hosts
        self.link = link
        self.arp = arp
        self.pki = pki
        self.keylog = keylog
        self.scale = scale
        self.txid = rng.randint(1, 60000)
        self.tgs_cache = set()
        self.dns_cache = {}
        self.sql_pool = []
        self.sql_pool2 = []
        self.isp_resolvers = []
        self.sites = {}
        # Per-device SNMP state (Host has __slots__, so this can't live on the device itself):
        # boot instant and running counter values, so repeated polls/walks of the same OID are
        # monotonic instead of independently random, and devices don't all share one uptime.
        self.snmp_state = {}
        # The directory. Built lazily by the caller (model.build_hosts wires it) so that Ctx
        # stays constructible in isolation for tests.
        self.dir = None

    def next_txid(self):
        self.txid = (self.txid + 1) & 0xFFFF
        return self.txid

    def udp(self, a, b, sport, dport, payload, ts, vantage=None, tos=0, df=False, nocsum=False):
        return (ts, udp_frame(self.link, a, b, sport, dport, payload, vantage or a, tos=tos, df=df, nocsum=nocsum))

    def tcp(self, client, server, dport, t, **kw):
        return TcpSession(self.link, client, server, dport, t, **kw)

    def arp_for(self, a, b, ts, vantage=None):
        return self.arp.before_flow(a, b, ts, vantage)

    def is_windows(self, h):
        return h.ttl == 128


# ============================================================================ DNS
def dns_lookup(ctx: Ctx, client, name, ts, qtype=P.DNS_A, answers=None, external=False, dc=None, rcode=0, ttl=300):
    """Client -> DC1 (or DC2) query. External names trigger DC recursion to the ISP resolver.
    rcode: 0 normal, 3 = NXDOMAIN (no such name), 2 = SERVFAIL.
    ttl: TTL on a positive external answer (both the ISP->DC leg and the DC->client leg);
    callers that return a short-lived answer (e.g. fast-flux) pass their own."""
    dc = _dc_for(ctx, client, dc, 0.85)
    out = ctx.arp_for(client, dc, ts)
    txid = ctx.next_txid()
    sport = client.eph()
    q = P.dns_query(txid, name, qtype)
    out.append(ctx.udp(client, dc, sport, 53, q, ts))
    delay = rng.uniform(0.0004, 0.0025)
    if external:
        cached = ctx.dns_cache.get(name, 0) > ts
        if not cached:
            ctx.dns_cache[name] = ts + rng.uniform(300, 1800)
            isp = rng.choice(ctx.isp_resolvers)
            out += ctx.arp_for(dc, isp, ts + 0.0005)
            txid2 = ctx.next_txid()
            dsport = dc.eph()
            out.append(ctx.udp(dc, isp, dsport, 53, P.dns_query(txid2, name, qtype), ts + 0.0007))
            delay = rng.uniform(0.012, 0.045)
            if answers is None:
                zone, soa, atl = P.tld_negative(name, nxdomain=(rcode == 3))
                isp_resp = P.dns_response(txid2, name, qtype, [], rcode=rcode, aa=False, authority=(zone, soa), auth_ttl=atl)
            else:
                isp_resp = P.dns_response(txid2, name, qtype, answers or [], aa=False, ttl=ttl)
            out.append(ctx.udp(isp, dc, 53, dsport, isp_resp, ts + delay - 0.0003, vantage=dc))
    if answers is None:
        if external:
            zone, soa, atl = P.tld_negative(name, nxdomain=(rcode == 3))
            resp = P.dns_response(txid, name, qtype, [], rcode=rcode, aa=False, authority=(zone, soa), auth_ttl=atl)
        else:
            resp = P.dns_response(txid, name, qtype, [], rcode=rcode, authority=(P.DOMAIN, P.soa_rdata()))
    else:
        resp = P.dns_response(txid, name, qtype, answers, aa=not external, ttl=1200 if not external else ttl)
    out.append(ctx.udp(dc, client, 53, sport, resp, ts + delay, vantage=client))
    if qtype == P.DNS_A and rng.random() < 0.35 and ctx.is_windows(client):
        # Windows resolvers frequently pair an AAAA query with the A query
        txid3 = ctx.next_txid()
        out.append(ctx.udp(client, dc, sport, 53, P.dns_query(txid3, name, P.DNS_AAAA), ts + 0.0002))
        if external:
            nx = answers is None and rcode == 3     # a name that does not exist has no AAAA either
            zone, soa, atl = P.tld_negative(name, nxdomain=nx)
            aaaa = P.dns_response(txid3, name, P.DNS_AAAA, [], rcode=3 if nx else 0, aa=False, authority=(zone, soa), auth_ttl=atl)
        else:
            aaaa = P.dns_response(txid3, name, P.DNS_AAAA, [], authority=(P.DOMAIN, P.soa_rdata()))
        out.append(ctx.udp(dc, client, 53, sport, aaaa, ts + delay + 0.0003, vantage=client))
    return merged(out)


def resolve_internal(ctx, client, hostobj, ts):
    return dns_lookup(ctx, client, hostobj.fqdn, ts, answers=[(P.DNS_A, hostobj.ipb)])


# =========================================================================== DHCP
def dhcp_acquire(ctx: Ctx, client, ts):
    fw = ctx.link.gateway_for(client)
    dc1 = ctx.h[H("DC1")]
    windows = ctx.is_windows(client)
    xid = rng.getrandbits(32)
    out = []
    disc = P.dhcp(1, xid, client.mac, 1, options=P.dhcp_client_opts(client.name, client.mac, windows))
    out.append((ts, udp_bcast(client, 68, 67, disc, src_ip=b"\x00\x00\x00\x00")))
    t = ts + rng.uniform(0.004, 0.02)
    sopts = P.dhcp_server_opts(dc1.ipb, fw.ipb, [dc1.ipb, ctx.h[H("DC2")].ipb])
    offer = P.dhcp(2, xid, client.mac, 2, yiaddr=client.ipb, siaddr=dc1.ipb, giaddr=fw.ipb, options=sopts, flags=0)

    class _R:  # relay agent as sender, client as receiver (unicast to MAC, IP = yiaddr)
        pass
    out.append((t, udp_frame(ctx.link, fw, client, 67, 68, offer, client)))
    t += rng.uniform(0.001, 0.01)
    req = P.dhcp(1, xid, client.mac, 3, options=P.dhcp_client_opts(client.name, client.mac, windows, req_ip=client.ipb, server_id=dc1.ipb))
    out.append((t, udp_bcast(client, 68, 67, req, src_ip=b"\x00\x00\x00\x00")))
    t += rng.uniform(0.004, 0.02)
    ack = P.dhcp(2, xid, client.mac, 5, yiaddr=client.ipb, siaddr=dc1.ipb, giaddr=fw.ipb, options=sopts, flags=0)
    out.append((t, udp_frame(ctx.link, fw, client, 67, 68, ack, client)))
    out += ctx.arp.probe(client, t + 0.05)
    return merged(out)


def dhcp_renew(ctx: Ctx, client, ts):
    """T1 renewal: unicast REQUEST straight to the DHCP server, ACK back."""
    dc1 = ctx.h[H("DC1")]
    windows = ctx.is_windows(client)
    xid = rng.getrandbits(32)
    out = ctx.arp_for(client, dc1, ts)
    req = P.dhcp(1, xid, client.mac, 3, ciaddr=client.ipb, options=P.dhcp_client_opts(client.name, client.mac, windows), flags=0)
    out.append(ctx.udp(client, dc1, 68, 67, req, ts))
    sopts = P.dhcp_server_opts(dc1.ipb, ctx.link.gateway_for(client).ipb, [dc1.ipb, ctx.h[H("DC2")].ipb])
    ack = P.dhcp(2, xid, client.mac, 5, ciaddr=client.ipb, yiaddr=client.ipb, siaddr=dc1.ipb, options=sopts, flags=0)
    out.append(ctx.udp(dc1, client, 67, 68, ack, ts + rng.uniform(0.001, 0.004), vantage=client))
    return merged(out)


# ============================================================================ NTP
def ntp_exchange(ctx: Ctx, client, ts):
    srv = ctx.h[H("NTP1")]
    out = ctx.arp_for(client, srv, ts)
    sport = 123 if not ctx.is_windows(client) else client.eph()
    req = P.ntp_request(ts, ctx.is_windows(client))
    out.append(ctx.udp(client, srv, sport, 123, req, ts))
    rt = ts + rng.uniform(0.0005, 0.002)
    out.append(ctx.udp(srv, client, 123, sport, P.ntp_response(req[-8:], rt, rt + 0.00002, vn=(req[0] >> 3) & 7), ts + rng.uniform(0.001, 0.003), vantage=client))
    return merged(out)


# ======================================================================== KERBEROS
def _tcp_len(b: bytes) -> bytes:
    return struct.pack("!I", len(b)) + b


def _dc_for(ctx: Ctx, client, prefer=None, p=0.8):
    """The domain controller a host actually authenticates against: one in its own zone.

    Purdue level 3 runs its own directory (EXL-OTDC1), which is how real plants are built --
    an OT domain that survives the enterprise being unreachable. Without this every OT SMB and
    Kerberos flow went across the IT/OT boundary to the enterprise DCs on port 88, which is both
    unrealistic and noise on the one boundary the whole design is trying to keep legible.
    Resolution is by the client's own /24 rather than a parameter threaded through six call
    sites, because "a host uses a DC in its own site" is the actual rule being modelled.
    """
    if prefer is not None:
        return prefer
    ot_dc = ctx.h.get(H("OTDC1"))
    if ot_dc is not None and client is not None and client.ipb[:3] != ctx.link.user_prefix \
            and client.ipb[:3] != ctx.link.server_prefix:
        return ot_dc
    # p is per call site on purpose: the three enterprise flows that pick a DC used
    # 0.85, 0.8 and 0.7, and collapsing them to one value moves 4,248 packets in the
    # validated baseline. Same draw, same order, same capture.
    return ctx.h[H("DC1")] if rng.random() < p else ctx.h[H("DC2")]


def kerberos_as(ctx: Ctx, client, ts, user=None):
    """Windows-style AS exchange: AS-REQ -> KRB-ERROR(preauth required) -> AS-REQ(preauth) -> AS-REP, over TCP."""
    dc = _dc_for(ctx, client)
    user = user or P.username_for(client.name)
    out = ctx.arp_for(client, dc, ts)
    s = ctx.tcp(client, dc, 88, ts + 0.001).handshake()
    s.c2s(_tcp_len(P.krb_as_req(user, ts, rng.getrandbits(31), False)), think=0.0004)
    s.s2c(_tcp_len(P.krb_error_preauth(user, ts)), think=rng.uniform(0.0008, 0.003))
    pk = s.close(think=0.0006)
    s2 = ctx.tcp(client, dc, 88, s.t + rng.uniform(0.002, 0.008)).handshake()
    s2.c2s(_tcp_len(P.krb_as_req(user, ts, rng.getrandbits(31), True)), think=0.0004)
    s2.s2c(_tcp_len(P.krb_as_rep(user)), think=rng.uniform(0.002, 0.006))
    pk += s2.close(think=0.0006)
    return merged(out, pk)


FTP_LISTING = [
    "drwxrwxrwx 1 ftp ftp            0 Jan 14 09:12 incoming",
    "drwxrwxrwx 1 ftp ftp            0 Jan 14 09:12 pub",
    "-rw-rw-rw- 1 ftp ftp       184320 Mar 02 11:40 room-schedule.csv",
    "-rw-rw-rw- 1 ftp ftp      2458624 Mar 02 11:41 whiteboard-export.pdf",
    "-rw-rw-rw- 1 ftp ftp        50176 Mar 02 11:41 display-config.xml",
    "-rw-rw-rw- 1 ftp ftp      7340032 Mar 02 11:42 firmware-backup.bin",
]

# The file catalogue. Each entry is (name, builder) and the builder returns the file's REAL
# bytes — see netgen/ftpfiles.py. Content is never truncated by the capture scale: a fragment
# of a PNG is not a PNG, and the whole point of these transfers is that what comes off the
# wire is the file. Entries are consumed in order rather than sampled, so every one of them
# appears on the wire on every build.
from . import ftpfiles as FF                                     # noqa: E402

_FTP_CONTENT = {}
_DEFAULT_LINK = None     # set while a diagram is drawn for custom networks, so it quotes the capture's sizes


def ftp_content(name, link=None):
    """The bytes of a catalogue file, built once per set of networks and cached so every build is
    identical. `link` re-homes the addresses the files mention (the device inventory, the board's
    syslog and the support bundle that holds them) onto the configured user/server /24s."""
    link = link if link is not None else _DEFAULT_LINK
    where = (link.place("10.10.10.0"), link.place("10.10.20.0")) if link is not None else None
    key = (name, where)
    if key not in _FTP_CONTENT:
        FF.place = link.place if link is not None else (lambda ip: ip)
        try:
            _FTP_CONTENT[key] = _FTP_BUILDERS[name]()
        finally:
            FF.place = lambda ip: ip
    return _FTP_CONTENT[key]


_FTP_BUILDERS = {
    # --- on the board, pulled off it -----------------------------------------------------
    "room-schedule.csv": FF.room_schedule_csv,
    "attendee-list.csv": FF.attendee_list_csv,
    "display-config.xml": FF.display_config_xml,
    "calibration-profile.json": FF.calibration_profile_json,
    "meeting-notes-2026-03-02.txt": FF.meeting_notes_txt,
    "device-inventory.csv": FF.device_inventory_csv,
    "syslog-latest.log": FF.syslog_latest_log,
    # the planted credential list — Caesar-shifted, which is no protection at all
    "exp0101.txt": FF.exp0101_txt,
    "whiteboard-export.pdf": lambda: FF.pdf(
        "Boardroom whiteboard - 2 March 2026",
        ["Peak season readiness", "", "Lane 3 scanner: drops reads above 180/hour",
         "Carrier fallback rates due 6 March", "Automation pilot: decision at Q2 review",
         "", "ACTION: disable the file share on the boardroom panel"]),
    "screenshot-0142.png": lambda: FF.png(800, 450, [(28, 31, 99), (127, 40, 84), (0, 170, 239)]),
    # CRP-04 brief fix 4: the bundle's logs/config alone (a few KB) never reads as "a support
    # bundle" -- the crash dump (genuinely high-entropy, so gzip can't shrink it away) is what
    # brings the compressed size on the wire into a realistic few-hundred-KB range.
    "support-bundle.tar.gz": lambda: FF.targz([
        ("support/sysinfo.txt", FF.device_inventory_csv()),
        ("support/display-config.xml", FF.display_config_xml()),
        ("support/syslog-latest.log", FF.syslog_latest_log()),
        ("support/calibration-profile.json", FF.calibration_profile_json()),
        ("support/display-agent.coredump", FF.crash_dump(400 * 1024)),
    ]),
    "firmware-backup.bin": FF.firmware_bin,
    # --- pushed onto the board -----------------------------------------------------------
    "agenda-2026.txt": FF.agenda_txt,
    "notes.txt": FF.notes_txt,
    "playlist.m3u": FF.playlist_m3u,
    "welcome-slide.png": lambda: FF.png(640, 360, [(28, 31, 99), (127, 40, 84)]),
    "logo-hires.png": lambda: FF.png(320, 180, [(0, 170, 239), (28, 31, 99)]),
    "room-banner.png": lambda: FF.png(640, 360, [(240, 89, 24), (127, 40, 84)]),
    "update-notice.pdf": lambda: FF.pdf("LuminaBoard firmware 4.3.0", FF.update_notice_lines()),
}

FTP_DOWNLOADS = ["room-schedule.csv", "attendee-list.csv", "display-config.xml",
                 "calibration-profile.json", "meeting-notes-2026-03-02.txt",
                 "device-inventory.csv", "syslog-latest.log", "exp0101.txt",
                 "whiteboard-export.pdf", "screenshot-0142.png",
                 "support-bundle.tar.gz", "firmware-backup.bin"]
FTP_UPLOADS = ["agenda-2026.txt", "notes.txt", "playlist.m3u", "welcome-slide.png",
               "logo-hires.png", "room-banner.png", "update-notice.pdf"]


def ftp_listing(link=None, uploaded=None):
    """A LIST response that matches what is actually on the server, with real sizes.

    `uploaded`: {name: (size, mtime_str)} for files a STOR has put there since the server
    started -- a later LIST must show them (CRP-04 brief fix 1: a file table across sessions,
    so a late listing differs from an early one and reflects overwrites).

    The static catalogue's own mtimes are spread across the months before the capture day
    instead of one shared timestamp (CRP-04 brief fix 5) -- deterministic per filename, not
    per call, so the same file reports the same mtime on every LIST within one build. A file
    `ls -l` considers old (more than ~6 months) gets the year instead of a time of day, the
    same real-world quirk a Wireshark/`ls` reader would expect."""
    from datetime import datetime, timedelta
    from .model import capture_day, TZ
    y, mo, d = capture_day()
    today = datetime(y, mo, d, tzinfo=TZ)
    six_months_ago = today - timedelta(days=182)
    rows = ["drwxrwxrwx 1 ftp ftp            0 Mar 02 07:12 incoming"]
    for n in FTP_DOWNLOADS:
        h = zlib.crc32(n.encode())
        days_ago = 45 + (h % 260)                         # spread 1.5 to ~10 months back
        hh, mm = 6 + (h >> 8) % 16, (h >> 16) % 60
        mtime = (today - timedelta(days=days_ago)).replace(hour=hh, minute=mm, second=0, microsecond=0)
        stamp = mtime.strftime("%b %e %Y") if mtime < six_months_ago else mtime.strftime("%b %e %H:%M")
        rows.append(f"-rw-rw-rw- 1 ftp ftp {len(ftp_content(n, link)):12d} {stamp} {n}")
    for n, (size, mtime) in (uploaded or {}).items():
        rows.append(f"-rw-rw-rw- 1 ftp ftp {size:12d} {mtime} {n}")
    return rows


def anon_ftp_session(ctx: Ctx, client, server, ts, ops=("LIST",), scale=1.0,
                     passwd="IEUser@", data_port=None):
    """A complete anonymous FTP session in clear text: control channel plus a PASV data channel.

    Everything a hardening view wants to read is on the wire unencrypted — `USER anonymous`,
    the password, the directory listing, the file names, and the transfers themselves. The
    existing crp-plaintext-creds FTP is control-channel only and stops after SYST; this one
    moves files, because "a device is running an FTP server nobody asked for" is only
    convincing if you can see what is being taken off it and put onto it.

    Passive mode throughout: it is what every modern client defaults to, and it means the data
    connection is also client->server, which is what gets through a firewall doing one
    inbound pinhole on port 21.

    Two things about the DATA channel are load-bearing for a consumer that wants to carve the
    file out, and both were wrong until 2026-09-17:

    * **The sender closes the data connection, not the receiver.** FTP puts no length on the
      data channel -- the sender's FIN *is* the end-of-file marker (RFC 959 s3.4). So a RETR
      and a LIST close with `by_client=False` and only a STOR closes from the client. Closing
      from the receiving end instead reads as the receiver aborting a transfer part-way, and a
      file-analysis engine drops a truncated transfer rather than cataloguing it. Measured
      before the fix: 24 of 34 data connections closed from the wrong end.
    * **The `150` must precede the first data byte.** The control session and the data session
      keep independent clocks, so the data handshake could finish and start sending before the
      control channel's `150` was timestamped -- by 4-10 ms, on 21 of 34 transfers. `d.t` is
      therefore pulled forward to the control clock after the `150` is emitted. A carver armed
      on the `150` would otherwise have already missed the start of the stream.

    Note that carving the files back out of the capture offline does NOT catch either of these:
    following a TCP stream reassembles the bytes happily whichever end closed it. The Phase 3r
    byte-for-byte test proved the *content* was right, never the protocol semantics.
    """
    # An inbound session from the internet has no ARP for the client on this segment — the
    # firewall does, and the board answers it. Only ARP when the client is actually local.
    # An inbound session from the internet has no ARP for the client on this segment — the
    # firewall does, and the board answers it. The sensor also sits on the *server's* segment
    # in that direction, so the vantage has to move: with vantage=client the link model looks
    # for a gateway on 203.0.113.0/24 and finds none.
    inbound = getattr(client, "role", "") == "external"
    van = server if inbound else client
    # A host nine hops across the internet does not see a LAN-like RTT -- CRP-04 brief fix 2.
    ext_rtt = rng.uniform(0.030, 0.120) if inbound else None
    out = [] if inbound else ctx.arp_for(client, server, ts)
    c = ctx.tcp(client, server, 21, ts + 0.001, vantage=van, rtt=ext_rtt).handshake()
    c.s2c(P.ftp_line(f"220 {server.name} FTP service ready."), think=rng.uniform(0.02, 0.12))
    c.c2s(P.ftp_line("USER anonymous"), think=rng.uniform(0.08, 0.4))
    c.s2c(P.ftp_line("331 Anonymous access allowed, send identity (e-mail name) as password."),
          think=rng.uniform(0.01, 0.05))
    c.c2s(P.ftp_line(f"PASS {passwd}"), think=rng.uniform(0.05, 0.3))
    c.s2c(P.ftp_line("230 Anonymous user logged in."), think=rng.uniform(0.02, 0.09))
    c.c2s(P.ftp_line("SYST"), think=rng.uniform(0.05, 0.2))
    c.s2c(P.ftp_line("215 UNIX Type: L8"), think=0.02)
    # Everything lives under /pub, not the share root (CRP-04 brief fix 5).
    c.c2s(P.ftp_line("CWD pub"), think=rng.uniform(0.05, 0.2))
    c.s2c(P.ftp_line("250 CWD command successful."), think=0.02)
    c.c2s(P.ftp_line("PWD"), think=rng.uniform(0.05, 0.2))
    c.s2c(P.ftp_line('257 "/pub" is current directory.'), think=0.02)
    c.c2s(P.ftp_line("TYPE I"), think=rng.uniform(0.05, 0.2))
    c.s2c(P.ftp_line("200 Type set to I."), think=0.02)

    pk = []
    for op in ops:
        # PASV: the server names the port for the data connection, encoded as six bytes
        dp = data_port or rng.randrange(49152, 65500)
        data_port = None
        h = server.ipb
        c.c2s(P.ftp_line("PASV"), think=rng.uniform(0.05, 0.3))
        c.s2c(P.ftp_line("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)."
                         % (h[0], h[1], h[2], h[3], dp >> 8, dp & 0xFF)),
              think=rng.uniform(0.01, 0.05))
        if op == "LIST":
            c.c2s(P.ftp_line("LIST"), think=rng.uniform(0.02, 0.15))
            d = ctx.tcp(client, server, dp, c.t + rng.uniform(0.004, 0.02), vantage=van, rtt=ext_rtt).handshake()
            c.s2c(P.ftp_line("150 Opening BINARY mode data connection for file list."), think=0.02)
            d.t = max(d.t, c.t + 0.0005)             # 150 must precede the bytes — see below
            uploaded = ctx.__dict__.setdefault("_ftp_uploaded", {})
            d.s2c(("\r\n".join(ftp_listing(ctx.link, uploaded)) + "\r\n").encode(), think=rng.uniform(0.01, 0.06))
            pk += d.close(by_client=False, think=rng.uniform(0.01, 0.05))
            c.s2c(P.ftp_line("226 Transfer complete."), think=rng.uniform(0.01, 0.05))
        elif op[0] == "RETR":
            name = op[1]
            body = ftp_content(name, ctx.link)                 # the real file, never truncated
            size = len(body)
            c.c2s(P.ftp_line(f"RETR {name}"), think=rng.uniform(0.05, 0.4))
            d = ctx.tcp(client, server, dp, c.t + rng.uniform(0.004, 0.02), vantage=van, rtt=ext_rtt).handshake()
            c.s2c(P.ftp_line(f"150 Opening BINARY mode data connection for {name} ({size} bytes)."),
                  think=0.02)
            d.t = max(d.t, c.t + 0.0005)             # 150 must precede the bytes — see below
            for off in range(0, size, 8192):
                d.s2c(body[off:off + 8192], think=rng.uniform(0.0008, 0.006))
            pk += d.close(by_client=False, think=rng.uniform(0.01, 0.06))
            c.s2c(P.ftp_line("226 Transfer complete."), think=rng.uniform(0.01, 0.05))
        elif op[0] == "STOR":
            name = op[1]
            body = ftp_content(name, ctx.link)
            size = len(body)
            c.c2s(P.ftp_line(f"STOR {name}"), think=rng.uniform(0.05, 0.4))
            d = ctx.tcp(client, server, dp, c.t + rng.uniform(0.004, 0.02), vantage=van, rtt=ext_rtt).handshake()
            c.s2c(P.ftp_line("150 Opening BINARY mode data connection."), think=0.02)
            d.t = max(d.t, c.t + 0.0005)             # 150 must precede the bytes — see below
            for off in range(0, size, 8192):
                d.c2s(body[off:off + 8192], think=rng.uniform(0.0008, 0.006))
            pk += d.close(by_client=True, think=rng.uniform(0.01, 0.06))
            c.s2c(P.ftp_line(f"226 Transfer complete ({size} bytes)."), think=rng.uniform(0.01, 0.05))
            uploaded = ctx.__dict__.setdefault("_ftp_uploaded", {})
            from datetime import datetime
            from .model import TZ
            uploaded[name] = (size, datetime.fromtimestamp(d.t, TZ).strftime("%b %d %H:%M"))

    c.c2s(P.ftp_line("QUIT"), think=rng.uniform(0.1, 0.6))
    c.s2c(P.ftp_line("221 Goodbye."), think=0.02)
    return merged(out, pk, c.close(think=rng.uniform(0.01, 0.05)))


# ===================================================================== page loads
# Subresource hosts a single page pulls in alongside its primary origin. Measured before this
# existed: the median client-minute touched exactly ONE server name, and the maximum was two.
# A real page opens connections to the origin plus a CDN, a font host, an analytics endpoint
# and an API, all within a second or two — which is why browsing looked so thin.
PAGE_SUBRESOURCE_HOSTS = [
    "cdn.jsdelivr.net", "fonts.gstatic.com", "www.cloudflare.com",
    "aax.amazon-adsystem.com", "objects.githubusercontent.com", "i.ytimg.com",
    "static.xx.fbcdn.net", "scontent.cdninstagram.com", "cdn.oaistatic.com",
]


def page_load(ctx: Ctx, client, site, ts, subresources=None):
    """One page: the origin plus the hosts it pulls in, fanning out in parallel.

    Each host gets its own TLS connection, started within a second or so of the origin's, which
    is what a browser actually does and what makes a page recognisable as a page rather than as
    an isolated request.
    """
    host, _srv = site
    out = https_session(ctx, client, site, ts, requests=rng.randint(2, 6))
    n = subresources if subresources is not None else rng.randint(3, 7)
    picks = rng.sample(PAGE_SUBRESOURCE_HOSTS, min(n, len(PAGE_SUBRESOURCE_HOSTS)))
    for i, name in enumerate(picks):
        sub = ctx.sites.get(name)
        if not sub:
            continue
        # browsers open these near-simultaneously, staggered by a few hundred ms
        t = ts + rng.uniform(0.05, 1.6) + i * rng.uniform(0.02, 0.18)
        out += https_session(ctx, client, sub, t, requests=rng.randint(1, 4),
                             sizes=[int(rng.lognormvariate(9.6, 0.9)) for _ in range(4)])
    return merged(out)


# ===================================================================== cloud egress
GENAI_PROMPT_PATHS = {
    "api.anthropic.com": "/v1/messages", "claude.ai": "/api/organizations/chat_conversations",
    "api.openai.com": "/v1/chat/completions", "chatgpt.com": "/backend-api/conversation",
    "gemini.google.com": "/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate",
    "generativelanguage.googleapis.com": "/v1beta/models/gemini-pro:streamGenerateContent",
    "grok.x.ai": "/v1/chat/completions", "api.x.ai": "/v1/chat/completions",
    "copilot.microsoft.com": "/c/api/conversations", "api.githubcopilot.com": "/chat/completions",
    "www.perplexity.ai": "/rest/sse/perplexity_ask", "api.mistral.ai": "/v1/chat/completions",
    "huggingface.co": "/api/models",
}


def genai_session(ctx: Ctx, client, site, ts, turns=None):
    """A conversation with a cloud AI assistant.

    Shaped the way these actually look on the wire, which is what makes them worth modelling
    separately from ordinary browsing: a **POST carrying a large request body** — the prompt,
    plus whatever context or pasted document came with it — answered by a long **streamed**
    response delivered in many small chunks over one long-lived connection. The asymmetry is
    the point: this is one of the few categories where a workstation uploads substantially, and
    it is usually unsanctioned, so a baseline without it makes any AI egress look novel.
    """
    from .tls import TlsSession
    host, srv = site
    ua = P.UAS[0] if ctx.is_windows(client) else P.UAS[2]
    path = GENAI_PROMPT_PATHS.get(host, "/v1/chat/completions")
    pre = dns_lookup(ctx, client, host, ts, external=True, answers=[(P.DNS_A, srv.ipb)]) if rng.random() < 0.7 else []
    t = ts + rng.uniform(0.01, 0.08)
    out = ctx.arp_for(client, srv, t)
    s = ctx.tcp(client, srv, 443, t + 0.001).handshake()
    tls = TlsSession(ctx.pki, host, ctx.keylog, profile=getattr(client, "tls_profile", "chrome"))
    for from_c, data in tls.handshake():
        if from_c:
            s.c2s(data, think=rng.uniform(0.0005, 0.003))
        else:
            s.s2c(data, think=rng.uniform(0.002, 0.01))
    sc = max(0.05, min(1.0, ctx.scale))
    for turn in range(turns or rng.randint(2, 7)):
        # the prompt: a few hundred bytes of question, sometimes a pasted document
        prompt = int(rng.lognormvariate(7.2, 1.1))
        if rng.random() < 0.22:                      # someone pastes a spreadsheet or a log
            prompt += int(rng.uniform(40_000, 400_000) * sc)
        prompt = max(220, min(prompt, 900_000))
        body = P.text_blob(prompt)
        req = P.http_request("POST", path, host, ua,
                             ["Content-Type: application/json", "Accept: text/event-stream",
                              "Authorization: Bearer sk-" + os.urandom(12).hex()],
                             body=body)
        s.c2s(tls.app_data(True, req), think=rng.uniform(2.0, 45.0) if turn else rng.uniform(0.002, 0.02))
        # the answer streams back as many small server-sent-event chunks
        hdr = P.http_response("200 OK", b"", "text/event-stream", s.t,
                              server="cloudflare", headers=["Cache-Control: no-cache"])
        s.s2c(tls.app_data(False, hdr), think=rng.uniform(0.15, 1.2))
        for _ in range(rng.randint(12, 70)):
            chunk = b"data: " + P.text_blob(rng.randint(30, 220)) + b"\n\n"
            s.s2c(tls.app_data(False, chunk), think=rng.uniform(0.01, 0.09))
        s.s2c(tls.app_data(False, b"data: [DONE]\n\n"), think=rng.uniform(0.01, 0.05))
    return merged(pre, out, s.close(think=rng.uniform(0.5, 6.0)))


def media_stream(ctx: Ctx, client, site, ts, minutes=None):
    """Music or video streaming: a long-lived TLS connection pulling ranged segments.

    The shape that matters is steady, chunked, one-directional volume over minutes — quite
    unlike page browsing, and the reason a capture without it under-represents how much of a
    working day is actually media.
    """
    from .tls import TlsSession
    host, srv = site
    ua = P.UAS[0] if ctx.is_windows(client) else P.UAS[2]
    pre = dns_lookup(ctx, client, host, ts, external=True, answers=[(P.DNS_A, srv.ipb)]) if rng.random() < 0.5 else []
    t = ts + rng.uniform(0.01, 0.06)
    out = ctx.arp_for(client, srv, t)
    s = ctx.tcp(client, srv, 443, t + 0.001).handshake()
    tls = TlsSession(ctx.pki, host, ctx.keylog, profile=getattr(client, "tls_profile", "chrome"))
    for from_c, data in tls.handshake():
        if from_c:
            s.c2s(data, think=rng.uniform(0.0005, 0.003))
        else:
            s.s2c(data, think=rng.uniform(0.002, 0.01))
    sc = max(0.04, min(1.0, ctx.scale))
    segs = max(3, int((minutes or rng.uniform(6, 40)) * 6 * sc))
    for i in range(segs):
        rng_hdr = f"Range: bytes={i * 262144}-{(i + 1) * 262144 - 1}"
        req = P.http_request("GET", f"/videoplayback/seg-{i:05d}.m4s", host, ua, [rng_hdr])
        s.c2s(tls.app_data(True, req), think=rng.uniform(0.9, 4.0) if i else rng.uniform(0.002, 0.02))
        size = int(rng.uniform(55_000, 160_000) * sc)      # ~64-192 kbps, audio-weighted
        resp = P.http_response("206 Partial Content", P.blob(max(2000, size)), "video/mp4", s.t,
                               server="gvs 1.0")
        s.s2c(tls.app_data(False, resp), think=rng.uniform(0.02, 0.2))
    return merged(pre, out, s.close(think=rng.uniform(0.2, 3.0)))


# ------------------------------------------------------------- server OS patching
def win_server_update(ctx: Ctx, server, meta_site, cdn_site, ts, mb=None):
    """A Windows server patching itself from Microsoft, not from an internal WSUS.

    Two legs, and the split is real: the scan/metadata exchange is HTTPS to the update service,
    then the payload itself comes over **plain HTTP** in large ranged chunks from the delivery
    CDN, because the packages are individually signed. That cleartext leg is the part a sensor
    can actually see into, so it is worth having on the wire rather than hiding everything in
    TLS.
    """
    from .tls import TlsSession
    mhost, msrv = meta_site
    chost, csrv = cdn_site
    ua = "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.81"
    pre = dns_lookup(ctx, server, mhost, ts, external=True, answers=[(P.DNS_A, msrv.ipb)])
    t = ts + rng.uniform(0.01, 0.06)
    out = ctx.arp_for(server, msrv, t)
    s = ctx.tcp(server, msrv, 443, t + 0.001).handshake()
    tls = TlsSession(ctx.pki, mhost, ctx.keylog, profile="winhttp")
    for from_c, data in tls.handshake():
        if from_c:
            s.c2s(data, think=rng.uniform(0.0005, 0.003))
        else:
            s.s2c(data, think=rng.uniform(0.002, 0.01))
    for _ in range(rng.randint(2, 4)):               # SOAP scan for applicable updates
        req = P.http_request("POST", "/ClientWebService/client.asmx", mhost, ua,
                             ["Content-Type: text/xml; charset=utf-8",
                              'SOAPAction: "http://www.microsoft.com/SoftwareDistribution/Server/'
                              'ClientWebService/SyncUpdates"'],
                             body=P.text_blob(rng.randint(1800, 9000)))
        s.c2s(tls.app_data(True, req), think=rng.uniform(0.05, 0.8))
        s.s2c(tls.app_data(False, P.http_response("200 OK", P.text_blob(rng.randint(4000, 60000)),
                                                  "text/xml", s.t, server="Microsoft-IIS/10.0")),
              think=rng.uniform(0.2, 1.6))
    pk = s.close(think=rng.uniform(0.1, 1.0))

    # payload: cleartext HTTP, ranged, from the delivery CDN
    sc = max(0.03, min(1.0, ctx.scale))
    total = int((mb or rng.uniform(180, 900)) * 1e6 * sc)
    t2 = s.t + rng.uniform(0.5, 4.0)
    pre2 = dns_lookup(ctx, server, chost, t2, external=True, answers=[(P.DNS_A, csrv.ipb)])
    out2 = ctx.arp_for(server, csrv, t2 + 0.01)
    d = ctx.tcp(server, csrv, 80, t2 + 0.02).handshake()
    got, i = 0, 0
    while got < total:
        n = min(1_048_576, total - got)
        cab = f"/d/msdownload/update/software/updt/2026/03/windows11.0-kb50{rng.randint(10000, 99999)}-x64_{os.urandom(8).hex()}.cab"
        d.c2s(P.http_request("GET", cab, chost, ua, [f"Range: bytes={got}-{got + n - 1}"]),
              think=rng.uniform(0.005, 0.06))
        d.s2c(P.http_response("206 Partial Content", P.blob(n), "application/octet-stream", d.t,
                              server="Microsoft-IIS/10.0"), think=rng.uniform(0.02, 0.25))
        got += n
        i += 1
        if i > 40:
            break
    return merged(pre, out, pk, pre2, out2, d.close(think=rng.uniform(0.2, 2.0)))


def linux_server_update(ctx: Ctx, server, site, ts, mb=None):
    """apt/dnf against a distribution mirror — index metadata then packages, over plain HTTP.

    Distro tooling still fetches over HTTP because every package is signed; the readable
    `InRelease`/`Packages` requests and the `.deb` paths are exactly what identifies the
    platform and its patch level to anything watching.
    """
    host, srv = site
    ua = "Debian APT-HTTP/1.3 (2.6.1)"
    pre = dns_lookup(ctx, server, host, ts, external=True, answers=[(P.DNS_A, srv.ipb)])
    t = ts + rng.uniform(0.01, 0.06)
    out = ctx.arp_for(server, srv, t)
    s = ctx.tcp(server, srv, 80, t + 0.001).handshake()
    for idx in ("/ubuntu/dists/jammy/InRelease", "/ubuntu/dists/jammy-security/InRelease",
                "/ubuntu/dists/jammy/main/binary-amd64/Packages.gz",
                "/ubuntu/dists/jammy-security/main/binary-amd64/Packages.gz"):
        s.c2s(P.http_request("GET", idx, host, ua), think=rng.uniform(0.01, 0.2))
        size = rng.randint(2000, 120_000)
        s.s2c(P.http_response("200 OK", P.blob(size), "application/octet-stream", s.t,
                              server="Apache/2.4.52 (Ubuntu)"), think=rng.uniform(0.02, 0.4))
    sc = max(0.03, min(1.0, ctx.scale))
    total = int((mb or rng.uniform(40, 260)) * 1e6 * sc)
    got = 0
    pkgs = ["linux-image-generic", "openssl", "libssl3", "python3.10", "systemd", "curl",
            "openssh-server", "tzdata", "ca-certificates", "libc6"]
    while got < total:
        n = min(4_000_000, total - got)
        pkg = rng.choice(pkgs)
        path = f"/ubuntu/pool/main/{pkg[0]}/{pkg}/{pkg}_{rng.randint(1, 9)}.{rng.randint(0, 20)}_amd64.deb"
        s.c2s(P.http_request("GET", path, host, ua), think=rng.uniform(0.01, 0.15))
        s.s2c(P.http_response("200 OK", P.blob(n), "application/vnd.debian.binary-package", s.t,
                              server="Apache/2.4.52 (Ubuntu)"), think=rng.uniform(0.05, 0.5))
        got += n
    return merged(pre, out, s.close(think=rng.uniform(0.1, 1.5)))


# ======================================================== peer-to-peer and failed connections
# Two things the baseline had none of, both measured at exactly zero: not one
# workstation-to-workstation TCP conversation in a whole day, and not one TCP reset. Real
# segments are full of both. An estate where every endpoint talks only to servers, and where
# every connection succeeds, is the strongest remaining "this is synthetic" tell.

PEER_SHARES = ["Public", "Share", "Scans", "Projects"]
PEER_FILES = ["quarter-close.xlsx", "dock-photos.zip", "route-plan.pdf", "labels.csv",
              "handover.docx", "inventory-draft.xlsx"]
# Ports a workstation genuinely tries and finds nothing on: a peer that is asleep, a service
# that was decommissioned, an app probing for a helper that is not installed.
DEAD_PORTS = [445, 3389, 5357, 8080, 139, 62078, 7680]


def peer_smb(ctx: Ctx, client, peer, ts, files=2):
    """One workstation opening another's shared folder.

    People share folders with each other constantly and it never shows up in a server-centric
    model. It is also the exact shape lateral movement borrows, so a baseline with none of it
    makes SMB between workstations look inherently suspicious.
    """
    share = rng.choice(PEER_SHARES)
    acct = ctx.dir.for_host(client) if ctx.dir else None
    user = acct.name if acct else P.username_for(client.name)
    s, smb, pre = _smb_open(ctx, client, peer, share, ts, user=user)
    body = []
    for _ in range(files):
        name = rng.choice(PEER_FILES)
        size = int(rng.uniform(40_000, 900_000) * max(0.05, min(1.0, ctx.scale)))
        s.c2s(smb.create_req(name), think=rng.uniform(0.05, 0.6))
        r, fid = smb.create_resp(s.t, size)
        s.s2c(r, think=rng.uniform(0.002, 0.02))
        got = 0
        while got < size:
            n = min(65536, size - got)
            s.c2s(smb.read_req(fid, got, n), think=0.0008)
            s.s2c(smb.read_resp(P.blob(n)), think=rng.uniform(0.001, 0.006))
            got += n
        s.c2s(smb.close_req(fid), think=0.001)
        s.s2c(smb.close_resp(s.t, size), think=0.0008)
    return merged(pre, body, _smb_close(s, smb))


def peer_media(ctx: Ctx, client, peer, ts, seconds=45):
    """A direct call leg between two desks — the peer-to-peer path a collaboration client takes
    when both parties are on the same LAN and the relay is bypassed."""
    pa, pb = rng.randrange(50000, 60000, 2), rng.randrange(50000, 60000, 2)
    ssa, ssb = rng.getrandbits(32), rng.getrandbits(32)
    rta, rtb = rng.getrandbits(32), rng.getrandbits(32)
    out = ctx.arp_for(client, peer, ts)
    n = int(seconds / 0.02 * max(0.05, min(1.0, ctx.scale)))
    for i in range(n):
        tt = ts + i * 0.02
        out.append(ctx.udp(client, peer, pa, pb, P.rtp_packet(i, rta + i * 160, ssa, marker=(i == 0)),
                           tt + rng.uniform(-0.0006, 0.0006), tos=0xB8))
        out.append(ctx.udp(peer, client, pb, pa, P.rtp_packet(i, rtb + i * 160, ssb, marker=(i == 0)),
                           tt + 0.004 + rng.uniform(-0.0006, 0.0006), tos=0xB8, vantage=client))
    return merged(out)


def connection_refused(ctx: Ctx, client, target, ts, port=None, attempts=None):
    """A connection to something that is not listening: SYN answered with RST/ACK.

    Windows retries a refused connect, so the retry pattern is part of the signature.
    """
    port = port or rng.choice(DEAD_PORTS)
    out = ctx.arp_for(client, target, ts)
    s = ctx.tcp(client, target, port, ts + 0.001)
    return merged(out, s.refused(attempts=attempts or rng.randint(1, 3), gap=rng.uniform(0.3, 1.1)))


def connection_aborted(ctx: Ctx, client, server, ts, port=80):
    """A transfer the client abandons — the user navigated away, the app was closed. The client
    stops mid-stream and resets instead of closing politely."""
    out = ctx.arp_for(client, server, ts)
    s = ctx.tcp(client, server, port, ts + 0.001).handshake()
    s.c2s(P.http_request("GET", "/reports/large-export.csv", server.fqdn,
                         "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), think=rng.uniform(0.01, 0.2))
    s.s2c(P.http_response("200 OK", b"x" * 1400, "text/csv", s.t), think=rng.uniform(0.05, 0.4))
    # client gives up and resets rather than finishing the read
    s.t += rng.uniform(0.3, 2.5)
    return merged(out, s.rst_from_server() if rng.random() < 0.3 else s.client_data_then_rst(b""))


def kerberos_as_outcome(ctx: Ctx, client, ts, user, outcome="ok", dc=None, realm=None):
    """One AS exchange with a chosen ending — the failure twin of kerberos_as().

    `kerberos_as()` is left exactly as it was: it is the validated success path that every
    workstation logon uses. This function exists because the baseline needs authentication that
    does NOT succeed, and bolting outcomes onto the success path would have meant editing a
    flow that a dozen scenarios already depend on.

    outcome:
      ok            AS-REQ -> preauth-required -> AS-REQ(preauth) -> AS-REP   (a second logon)
      bad_password  ... -> KRB-ERROR 24  (KDC_ERR_PREAUTH_FAILED)
      revoked       ... -> KRB-ERROR 18  (disabled, or locked out — Windows uses 18 for both)
      expired       ... -> KRB-ERROR 23  (KDC_ERR_KEY_EXPIRED)
      unknown       ... -> KRB-ERROR 6   (KDC_ERR_C_PRINCIPAL_UNKNOWN), no preauth leg: the
                                          KDC rejects an unknown principal immediately

    realm: None = the enterprise realm; P.OT_REALM for an OT-forest logon against EXL-OTDC1.
    """
    dc = _dc_for(ctx, client, dc, 0.8)
    code = {"bad_password": 24, "revoked": 18, "expired": 23, "unknown": 6}.get(outcome)
    out = ctx.arp_for(client, dc, ts)

    if outcome == "unknown":
        s = ctx.tcp(client, dc, 88, ts + 0.001).handshake()
        s.c2s(_tcp_len(P.krb_as_req(user, ts, rng.getrandbits(31), False, realm=realm)), think=0.0004)
        s.s2c(_tcp_len(P.krb_error(6, user, ts)), think=rng.uniform(0.0008, 0.003))
        return merged(out, s.close(think=0.0006))

    # every other outcome starts with the ordinary preauth-required round trip
    s = ctx.tcp(client, dc, 88, ts + 0.001).handshake()
    s.c2s(_tcp_len(P.krb_as_req(user, ts, rng.getrandbits(31), False, realm=realm)), think=0.0004)
    s.s2c(_tcp_len(P.krb_error_preauth(user, ts, realm=realm)), think=rng.uniform(0.0008, 0.003))
    pk = s.close(think=0.0006)

    s2 = ctx.tcp(client, dc, 88, s.t + rng.uniform(0.002, 0.008)).handshake()
    s2.c2s(_tcp_len(P.krb_as_req(user, ts, rng.getrandbits(31), True, realm=realm)), think=0.0004)
    if code is None:
        s2.s2c(_tcp_len(P.krb_as_rep(user, realm=realm)), think=rng.uniform(0.002, 0.006))
    else:
        s2.s2c(_tcp_len(P.krb_error_preauth(user, ts, code=code, realm=realm)), think=rng.uniform(0.001, 0.005))
    return merged(out, pk + s2.close(think=0.0006))


def kerberos_pkinit(ctx: Ctx, client, ts, principal, dc=None, realm=None):
    """A certificate-backed AS exchange (PA-PK-AS-REQ / PA-PK-AS-REP) -- one round trip, no
    preauth-required leg, the way a client presenting a cert (not a password) actually logs on."""
    dc = _dc_for(ctx, client, dc, 0.8)
    out = ctx.arp_for(client, dc, ts)
    s = ctx.tcp(client, dc, 88, ts + 0.001).handshake()
    s.c2s(_tcp_len(P.krb_as_req_pkinit(principal, ts, rng.getrandbits(31), realm=realm)), think=0.0004)
    s.s2c(_tcp_len(P.krb_as_rep_pkinit(principal, realm=realm)), think=rng.uniform(0.002, 0.008))
    pk = s.close(think=0.0006)
    return merged(out, pk)


def kerberos_lockout(ctx: Ctx, client, ts, user, tries=None):
    """A real lockout: several bad passwords in a row, then the KDC starts answering 18.

    The shape is what distinguishes this from a password spray. One account, one source, a
    handful of attempts over a couple of minutes, ending in CLIENT_REVOKED — versus a spray's
    one attempt each against dozens of accounts. Both produce KDC_ERR_PREAUTH_FAILED, so the
    baseline must look unmistakably like the former.
    """
    tries = tries or rng.randint(4, 6)
    out = []
    t = ts
    for i in range(tries):
        out += kerberos_as_outcome(ctx, client, t, user, "bad_password")
        t += rng.uniform(8, 35)
    # threshold reached — the account is now locked and the KDC says so
    for _ in range(rng.randint(1, 3)):
        out += kerberos_as_outcome(ctx, client, t, user, "revoked")
        t += rng.uniform(20, 90)
    return merged(out)


def ntlm_smb_logon(ctx: Ctx, client, server, ts, user, outcome="ok", share="Dept", domain=None, share_host=None):
    """SMB2 session setup over NTLM instead of Kerberos, with a real NT status on the end.

    Why this exists at all: the baseline had zero NTLM, and a Windows estate without any is not
    a Windows estate. NTLM shows up wherever Kerberos cannot be used — a share reached by IP
    literal, an app with no SPN registered, a non-domain-joined device. It also carries the
    clearest failure signal on the wire, because the NT status names the exact reason.

    domain: the NetBIOS domain the account authenticates against (default `P.NETBIOS`, the
    enterprise domain -- every existing caller is unaffected). share_host: the host part of
    the tree path (default the server's own FQDN); pass the server's IP literal for a logon
    whose whole reason for falling back to NTLM is that the share was reached by address, not
    name -- Kerberos needs the FQDN to find the right SPN.
    """
    domain = domain or P.NETBIOS
    status = {
        "ok": 0x00000000, "bad_password": 0xC000006D, "disabled": 0xC0000072,
        "expired": 0xC0000071, "locked": 0xC0000234, "unknown": 0xC0000064,
    }[outcome]
    out = ctx.arp_for(client, server, ts)
    s = ctx.tcp(client, server, 445, ts + 0.001).handshake()
    smb = P.Smb2(require_signing=_dc_host(server))
    s.c2s(smb.negotiate_req(os.urandom(16)), think=0.0004)
    s.s2c(smb.negotiate_resp(os.urandom(16), s.t), think=rng.uniform(0.0006, 0.002))
    # type 1 -> type 2 challenge (STATUS_MORE_PROCESSING_REQUIRED) -> type 3 -> final status
    s.c2s(smb.session_setup_req(P.spnego_ntlm_init(P.ntlm_negotiate(domain, client.name))),
          think=rng.uniform(0.0008, 0.003))
    s.s2c(smb.session_setup_challenge(P.spnego_ntlm_challenge(P.ntlm_challenge(domain))),
          think=rng.uniform(0.001, 0.004))
    s.c2s(smb.session_setup_req(P.spnego_ntlm_auth(P.ntlm_authenticate(user, domain, client.name))),
          think=rng.uniform(0.002, 0.012))
    if status == 0:
        s.s2c(smb.session_setup_resp(), think=rng.uniform(0.001, 0.005))
        s.c2s(smb.tree_connect_req(f"\\\\{share_host or server.fqdn}\\{share}"), think=0.0006)
        s.s2c(smb.tree_connect_resp(), think=rng.uniform(0.0005, 0.002))
        s.c2s(smb.tree_disconnect_req(), think=rng.uniform(0.05, 0.6))
        s.s2c(smb.tree_disconnect_resp(), think=0.0005)
        s.c2s(smb.logoff_req(), think=0.0005)
        s.s2c(smb.logoff_resp(), think=0.0005)
    else:
        s.s2c(smb.session_setup_fail(status), think=rng.uniform(0.002, 0.02))
    return merged(out, s.close(think=rng.uniform(0.001, 0.02)))


def ldap_bind_failure(ctx: Ctx, client, ts, user, data="52e", dc=None):
    """A simple LDAP bind that is refused — an appliance or script with a stale credential.

    This is the other half of "no errors": every LDAP bind in the baseline returned success.
    Devices with saved passwords are the classic source of the long, quiet tail of failures
    that a real directory sees all day.
    """
    dc = _dc_for(ctx, client, dc, 0.7)
    out = ctx.arp_for(client, dc, ts)
    s = ctx.tcp(client, dc, 389, ts + 0.001).handshake()
    mid = rng.randint(1, 60000)
    s.c2s(P.ldap_bind_request_simple(mid, f"{P.NETBIOS}\\{user}", os.urandom(rng.randint(8, 16))),
          think=rng.uniform(0.0005, 0.002))
    s.s2c(P.ldap_bind_response_fail(mid, 49, data), think=rng.uniform(0.001, 0.006))
    s.c2s(P.ldap_unbind(mid + 1), think=rng.uniform(0.001, 0.01))
    return merged(out, s.close(think=0.0006))


def service_account_job(ctx: Ctx, client, target, ts, user, service="cifs", share="Dept",
                        files=2, size=240_000):
    """A service account authenticating on a schedule and then doing its job.

    Service accounts are the accounts that matter most and were entirely absent: they hold
    standing privilege, they never interact with a screen, and their traffic is periodic and
    machine-regular, which is exactly what makes a deviation visible. Each one gets a real
    Kerberos logon rather than appearing from nowhere mid-session.
    """
    pk = kerberos_as_outcome(ctx, client, ts, user, "ok")
    t = ts + rng.uniform(0.05, 0.4)
    tgs, t = kerberos_tgs(ctx, client, service, target, t, force=True)
    s, smb, pre = _smb_open(ctx, client, target, share, t + 0.01, user=user)
    body = []
    for _ in range(files):
        name = f"{user}\\{rng.randint(1000, 9999)}.bak"
        s.c2s(smb.create_req(name), think=rng.uniform(0.002, 0.02))
        r, fid = smb.create_resp(s.t, size)
        s.s2c(r, think=rng.uniform(0.001, 0.008))
        got = 0
        while got < size:
            n = min(65536, size - got)
            s.c2s(smb.read_req(fid, got, n), think=0.0006)
            s.s2c(smb.read_resp(P.blob(n)), think=rng.uniform(0.0008, 0.004))
            got += n
        s.c2s(smb.close_req(fid), think=0.0008)
        s.s2c(smb.close_resp(s.t, size), think=0.0006)
    return merged(pk, tgs, pre, body, _smb_close(s, smb))


def privileged_session(ctx: Ctx, admin, ts, acct, groups=None, dcs=None):
    """An administrator doing ordinary administration: log on, read a few privileged groups.

    The baseline needs legitimate privileged activity for the illegitimate kind to stand out
    against. Note where it comes from — the jump host — because an admin account authenticating
    from an ordinary desktop is the anomaly worth alerting on, and a capture with no normal
    admin traffic gives a detector nothing to contrast.
    """
    from .accounts import PRIV_GROUPS
    groups = groups or PRIV_GROUPS
    dc = (dcs or [ctx.h[H("DC1")], ctx.h[H("DC2")]])[0 if rng.random() < 0.7 else 1]
    pk = kerberos_as_outcome(ctx, admin, ts, acct, "ok", dc=dc)
    t = ts + rng.uniform(0.2, 1.5)
    tgs, t = kerberos_tgs(ctx, admin, "ldap", dc, t, force=True)
    out = ctx.arp_for(admin, dc, t)
    s = ctx.tcp(admin, dc, 389, t + 0.001).handshake()
    mid = rng.randint(1, 50000)
    s.c2s(P.ldap_bind_request(mid, P.krb_ap_req_token(acct, "ldap", dc.fqdn)), think=0.0006)
    s.s2c(P.ldap_bind_response(mid), think=rng.uniform(0.001, 0.004))
    for g in rng.sample(groups, rng.randint(2, min(4, len(groups)))):
        mid += 1
        filt = P._filter_and(P._filter_eq("objectClass", "group"), P._filter_eq("cn", g))
        s.c2s(P.ldap_search_request(mid, "DC=corp,DC=example,DC=local", 2, filt,
                                    ["member", "cn", "distinguishedName"]),
              think=rng.uniform(0.05, 0.6))
        s.s2c(P.ldap_search_entry(mid, f"CN={g},OU=Groups,DC=corp,DC=example,DC=local",
                                  {"cn": [g], "member": [f"CN={a},OU=Staff,DC=corp,DC=example,DC=local"
                                                         for a in rng.sample(
                                                             [x.name for x in ctx.dir.users], 3)]}),
              think=rng.uniform(0.002, 0.01))
        s.s2c(P.ldap_search_done(mid), think=0.0008)
    s.c2s(P.ldap_unbind(mid + 1), think=rng.uniform(0.01, 0.2))
    return merged(pk, tgs, out, s.close(think=0.001))


def kerberos_tgs_refresh(ctx: Ctx, client, service, target, ts):
    """A service ticket requested again, bypassing the day-long cache.

    `kerberos_tgs()` caches on (client, service, target) for the whole run, so each workstation
    asked for each ticket exactly once per day and service-ticket activity was correspondingly
    invisible. Real clients re-request constantly — after an unlock, when a ticket ages out,
    whenever a session is re-established.
    """
    return merged(kerberos_tgs(ctx, client, service, target, ts, force=True)[0])


def kerberos_tgs(ctx: Ctx, client, service, target, ts, force=False, user=None, realm=None, dc=None):
    """user/realm/dc default to the client's own enterprise account against its zone's DC; an OT
    account passes its user, P.OT_REALM and EXL-OTDC1 (cached per user, so two accounts on one
    host each get their own ticket)."""
    key = (client.name, service, target.name) if user is None else (client.name, service, target.name, user)
    if key in ctx.tgs_cache and not force:
        return [], ts
    ctx.tgs_cache.add(key)
    dc = _dc_for(ctx, client, dc, 0.8)
    # An OT host that asks the OT forest's DC for a ticket on its own behalf does so as its OT
    # identity (the station's signed-in account, or a server's computer account NAME$), in the OT
    # realm -- not as an enterprise person. ctx.ot_account is set by the Day only when OT is on.
    ot_account = getattr(ctx, "ot_account", None)
    if user is None and ot_account is not None and dc is ctx.h.get(H("OTDC1")):
        user, realm = ot_account(client.name, ts), realm or P.OT_REALM
    user = user or P.username_for(client.name)
    out = ctx.arp_for(client, dc, ts)
    s = ctx.tcp(client, dc, 88, ts + 0.001).handshake()
    s.c2s(_tcp_len(P.krb_tgs_req(user, service, target.fqdn, ts, rng.getrandbits(31), realm=realm)), think=0.0004)
    s.s2c(_tcp_len(P.krb_tgs_rep(user, service, target.fqdn, realm=realm)), think=rng.uniform(0.0015, 0.005))
    pk = s.close(think=0.0006)
    return merged(out, pk), s.t + 0.002


# =========================================================================== LDAP
def cldap_ping(ctx: Ctx, client, ts):
    dc = ctx.h[H("DC1")]
    out = ctx.arp_for(client, dc, ts)
    sport = client.eph()
    mid = rng.randint(1, 60000)
    out.append(ctx.udp(client, dc, sport, 389, P.cldap_netlogon_query(mid, client.name), ts))
    out.append(ctx.udp(dc, client, 389, sport, P.cldap_netlogon_response(mid, dc.fqdn), ts + rng.uniform(0.0008, 0.003), vantage=client))
    return merged(out)


def ldap_session(ctx: Ctx, client, ts, queries=3, dc=None):
    dc = _dc_for(ctx, client, dc, 0.7)
    user = P.username_for(client.name)
    pre, t = kerberos_tgs(ctx, client, "ldap", dc, ts)
    out = ctx.arp_for(client, dc, t)
    s = ctx.tcp(client, dc, 389, t + 0.001).handshake()
    mid = 1
    s.c2s(P.ldap_bind_request(mid, P.krb_ap_req_token(user, "ldap", dc.fqdn)), think=0.0005)
    s.s2c(P.ldap_bind_response(mid), think=rng.uniform(0.001, 0.004))
    for _ in range(queries):
        mid += 1
        kind = rng.random()
        if kind < 0.4:
            filt = P._filter_and(P._filter_eq("objectClass", "user"), P._filter_eq("sAMAccountName", rng.choice([user, P.username_for(H("WS-%03d" % rng.randint(1, 75)))])))
            attrs = ["displayName", "mail", "memberOf", "userPrincipalName", "department", "title"]
            base, scope = P.BASE_DN, 2
            entries = [(f"CN={user},OU=Staff,OU=Users,{P.BASE_DN}", {"displayName": [user.title()], "mail": [f"{user}@{get_current().slug}.example"],
                        "memberOf": [f"CN=Logistics-Staff,OU=Groups,{P.BASE_DN}", f"CN=Intranet-Users,OU=Groups,{P.BASE_DN}"],
                        "userPrincipalName": [f"{user}@{P.DOMAIN}"], "department": [rng.choice(["Operations", "Dispatch", "Finance", "IT"])], "title": [rng.choice(["Analyst", "Coordinator", "Manager"])]})]
        elif kind < 0.7:
            filt = P._filter_and(P._filter_eq("objectClass", "computer"), P._filter_eq("cn", client.name))
            attrs = ["distinguishedName", "operatingSystem", "dNSHostName", "servicePrincipalName"]
            base, scope = P.BASE_DN, 2
            entries = [(f"CN={client.name},OU=Workstations,{P.BASE_DN}", {"distinguishedName": [f"CN={client.name},OU=Workstations,{P.BASE_DN}"], "operatingSystem": [client.os],
                        "dNSHostName": [client.fqdn], "servicePrincipalName": [f"HOST/{client.fqdn}", f"HOST/{client.name}"]})]
        else:
            filt = P._filter_present("objectClass")
            attrs = ["defaultNamingContext", "dnsHostName", "supportedLDAPVersion", "domainFunctionality"]
            base, scope = "", 0
            entries = [("", {"defaultNamingContext": [P.BASE_DN], "dnsHostName": [dc.fqdn], "supportedLDAPVersion": ["3", "2"], "domainFunctionality": ["7"]})]
        s.c2s(P.ldap_search_request(mid, base, scope, filt, attrs), think=rng.uniform(0.002, 0.05))
        resp = b"".join(P.ldap_search_entry(mid, dn, at) for dn, at in entries) + P.ldap_search_done(mid)
        s.s2c(resp, think=rng.uniform(0.001, 0.006))
    mid += 1
    s.c2s(P.ldap_unbind(mid), think=rng.uniform(0.01, 0.2))
    pk = s.close(think=0.0005)
    return merged(pre, out, pk)


# =========================================================================== SMB2
def _dc_host(host) -> bool:
    """Windows domain controllers require SMB signing by default."""
    return host.name.upper().startswith(H("DC"))


def _smb_open(ctx, client, server, share, t, user=None):
    """Negotiate, session setup (Kerberos), tree connect. Returns (session, smb, pkts)."""
    own = P.username_for(client.name)
    user = user or own
    # the service ticket belongs to the account that authenticates (a stolen credential asks for its own)
    pre, t = kerberos_tgs(ctx, client, "cifs", server, t, user=None if user == own else user)
    out = ctx.arp_for(client, server, t)
    s = ctx.tcp(client, server, 445, t + 0.001).handshake()
    smb = P.Smb2(require_signing=_dc_host(server))
    s.c2s(smb.negotiate_req(os.urandom(16)), think=0.0004)
    s.s2c(smb.negotiate_resp(os.urandom(16), s.t), think=rng.uniform(0.0006, 0.002))
    s.c2s(smb.session_setup_req(P.krb_ap_req_token(user, "cifs", server.fqdn)), think=rng.uniform(0.0008, 0.004))
    s.s2c(smb.session_setup_resp(), think=rng.uniform(0.001, 0.004))
    s.c2s(smb.tree_connect_req(f"\\\\{server.fqdn}\\{share}"), think=0.0006)
    s.s2c(smb.tree_connect_resp(), think=rng.uniform(0.0005, 0.002))
    return s, smb, merged(pre, out)


def _smb_open_ntlm(ctx, client, server, share, t, account):
    """Negotiate, session setup over NTLM (NEGOTIATE/CHALLENGE/AUTHENTICATE) with a named,
    harvested account, tree connect. For a client with no domain computer account of its own to
    request a Kerberos ticket with (a compromised appliance, not a joined host) -- the NTLM
    three-leg is what a stolen credential presented from outside the domain actually looks like.
    Returns (session, smb, pkts)."""
    out = ctx.arp_for(client, server, t)
    s = ctx.tcp(client, server, 445, t + 0.001).handshake()
    smb = P.Smb2(require_signing=_dc_host(server))
    s.c2s(smb.negotiate_req(os.urandom(16)), think=0.0004)
    s.s2c(smb.negotiate_resp(os.urandom(16), s.t), think=rng.uniform(0.0006, 0.002))
    s.c2s(smb.session_setup_req(P.spnego_ntlm_init(P.ntlm_negotiate(P.NETBIOS, client.name))), think=rng.uniform(0.0008, 0.003))
    s.s2c(smb.session_setup_challenge(P.spnego_ntlm_challenge(P.ntlm_challenge(P.NETBIOS))), think=rng.uniform(0.001, 0.004))
    s.c2s(smb.session_setup_req(P.spnego_ntlm_auth(P.ntlm_authenticate(account, P.NETBIOS, client.name))), think=rng.uniform(0.002, 0.012))
    s.s2c(smb.session_setup_resp(), think=rng.uniform(0.001, 0.005))
    s.c2s(smb.tree_connect_req(f"\\\\{server.fqdn}\\{share}"), think=0.0006)
    s.s2c(smb.tree_connect_resp(), think=rng.uniform(0.0005, 0.002))
    return s, smb, merged(out)


def _smb_close(s, smb):
    s.c2s(smb.tree_disconnect_req(), think=rng.uniform(0.01, 0.3))
    s.s2c(smb.tree_disconnect_resp(), think=0.0005)
    s.c2s(smb.logoff_req(), think=0.0005)
    s.s2c(smb.logoff_resp(), think=0.0005)
    return s.close(think=rng.uniform(0.001, 0.02))


def _smb_retree(s, smb, server, share, think_pre=0.0006, think_post=None):
    """Tree-connect to a different share on the SAME already-authenticated SMB session
    (one TCP connection, one session, several tree connects -- what PsExec actually does
    between ADMIN$ and IPC$, instead of opening a second session)."""
    s.c2s(smb.tree_connect_req(f"\\\\{server.fqdn}\\{share}"), think=think_pre)
    s.s2c(smb.tree_connect_resp(), think=rng.uniform(0.0005, 0.002) if think_post is None else think_post)


def _smb_untree(s, smb, think=None):
    """Tree-disconnect without logoff/close, so another tree connect can follow on the
    same session."""
    s.c2s(smb.tree_disconnect_req(), think=rng.uniform(0.01, 0.3) if think is None else think)
    s.s2c(smb.tree_disconnect_resp(), think=0.0005)


FILE_NAMES = ["Q3-Forecast.xlsx", "Carrier-Rates-2026.xlsx", "Dock-Schedule.docx", "Manifest-{n}.pdf", "Hazmat-Policy.pdf",
              "Onboarding.pptx", "Route-Plan-{n}.xlsx", "Invoice-{n}.pdf", "Claims-Log.xlsx", "Fleet-Maintenance.docx",
              "Customs-Declaration-{n}.pdf", "Safety-Briefing.pptx", "Budget-FY26.xlsx", "Driver-Roster.xlsx"]


def smb_file_activity(ctx: Ctx, client, server, ts, n_files=None, write_ratio=0.3, share=None, size_range=(30_000, 1_200_000), ntlm_user=None):
    """A user browsing a share, reading some files and saving one or two.

    ntlm_user: a named account to authenticate with NTLM instead of Kerberos -- for a client
    with no domain computer account of its own (a compromised appliance) to request a ticket
    with."""
    share = share or rng.choice(["Dept", "Users", "Dept"])
    if ntlm_user:
        s, smb, pre = _smb_open_ntlm(ctx, client, server, share, ts, ntlm_user)
    else:
        s, smb, pre = _smb_open(ctx, client, server, share, ts)
    n_files = n_files or rng.randint(1, 3)
    # directory listing
    s.c2s(smb.create_req("", write=False), think=rng.uniform(0.002, 0.02))
    r, dfid = smb.create_resp(s.t, 0, directory=True)
    s.s2c(r, think=0.0008)
    s.c2s(smb.query_dir_req(dfid), think=0.0006)
    listing = [(rng.choice(FILE_NAMES).replace("{n}", str(rng.randint(10000, 99999))), rng.randint(20_000, 4_000_000), False) for _ in range(rng.randint(6, 25))]
    listing += [("Archive", 0, True), ("Templates", 0, True)]
    s.s2c(smb.query_dir_resp(listing, s.t), think=rng.uniform(0.001, 0.004))
    s.c2s(smb.close_req(dfid), think=0.0006)
    s.s2c(smb.close_resp(s.t, 0), think=0.0006)
    for _ in range(n_files):
        name = rng.choice(listing[:-2])[0]
        size = rng.randint(*size_range)
        writing = rng.random() < write_ratio
        s.c2s(smb.create_req(name, write=writing, overwrite=True), think=rng.uniform(0.5, 6.0))
        r, fid = smb.create_resp(s.t, 0 if writing else size)
        s.s2c(r, think=rng.uniform(0.0008, 0.004))
        chunk = 1048576 if ctx.is_windows(client) else 65536
        data = P.blob(size) if not name.endswith((".txt", ".csv")) else P.text_blob(size)
        off = 0
        while off < size:
            part = data[off:off + chunk]
            if writing:
                s.c2s(smb.write_req(fid, off, part), think=rng.uniform(0.0003, 0.002))
                s.s2c(smb.write_resp(len(part)), think=rng.uniform(0.0006, 0.003))
            else:
                s.c2s(smb.read_req(fid, off, len(part)), think=rng.uniform(0.0003, 0.002))
                s.s2c(smb.read_resp(part), think=rng.uniform(0.0006, 0.003))
            off += len(part)
        s.c2s(smb.close_req(fid), think=rng.uniform(0.001, 0.01))
        s.s2c(smb.close_resp(s.t, size), think=0.0008)
    pk = _smb_close(s, smb)
    return merged(pre, pk)


def smb_sysvol_gpo(ctx: Ctx, client, ts):
    """Group-policy refresh: read gpt.ini and a few policy files from SYSVOL on a DC."""
    dc = _dc_for(ctx, client, None, 0.7)
    s, smb, pre = _smb_open(ctx, client, dc, "SYSVOL", ts, user=client.name + "$")
    for path, size in [(f"{P.DOMAIN}\\Policies\\{{31B2F340-016D-11D2-945F-00C04FB984F9}}\\gpt.ini", 60),
                       (f"{P.DOMAIN}\\Policies\\{{6AC1786C-016F-11D2-945F-00C04FB984F9}}\\gpt.ini", 62),
                       (f"{P.DOMAIN}\\Policies\\{{31B2F340-016D-11D2-945F-00C04FB984F9}}\\Machine\\Registry.pol", rng.randint(2000, 9000)),
                       (f"{P.DOMAIN}\\Policies\\{{7F5A8E4C-2B3D-4E6F-9A1B-3C5D7E9F1A2B}}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf", rng.randint(1500, 6000))]:
        s.c2s(smb.create_req(path), think=rng.uniform(0.002, 0.03))
        r, fid = smb.create_resp(s.t, size)
        s.s2c(r, think=rng.uniform(0.0008, 0.003))
        s.c2s(smb.read_req(fid, 0, size), think=0.0006)
        body = b"[General]\r\nVersion=" + str(rng.randint(100, 900)).encode() + b"\r\ndisplayName=New Group Policy Object\r\n" if size < 100 else P.blob(size)
        s.s2c(smb.read_resp(body[:size].ljust(size, b"\x00")), think=rng.uniform(0.0008, 0.003))
        s.c2s(smb.close_req(fid), think=0.0006)
        s.s2c(smb.close_resp(s.t, size), think=0.0006)
    pk = _smb_close(s, smb)
    return merged(pre, pk)


def smb_bulk_transfer(ctx: Ctx, client, server, share, total_bytes, ts, direction="read", chunk=1048576, files=None,
                      pace=None, pace_end=1.0):
    """Backup-style sequential transfer of many files (read from server, or write to it). A read
    lists the directory first (QUERY_DIRECTORY) and only opens names that listing returned, within
    the tree it is connected to (no invented path prefix for the share).

    pace (bytes/s) throttles the stream so a job lasts minutes instead of seconds; the rate falls
    linearly to pace * pace_end as the job completes (a ramp-down). None = full speed, as before."""
    s, smb, pre = _smb_open(ctx, client, server, share, ts, user=("svc_backup" if "BACKUP" in client.name else client.name + "$"))
    s.per_byte = 8.0 / 900e6
    done = 0
    i = 0
    files = files or 40
    per_file = max(65536, total_bytes // files)
    out = [pre]
    names = None
    if direction == "read":
        s.c2s(smb.create_req("", write=False), think=rng.uniform(0.002, 0.02))
        r, dfid = smb.create_resp(s.t, 0, directory=True)
        s.s2c(r, think=0.0008)
        s.c2s(smb.query_dir_req(dfid), think=0.0006)
        names = [rng.choice(FILE_NAMES).replace("{n}", str(10000 + k)) for k in range(files)]
        names = list(dict.fromkeys(names))     # keep the list stable and unique
        listing = [(n, int(per_file * rng.uniform(0.3, 1.8)), False) for n in names]
        s.s2c(smb.query_dir_resp(listing[:80], s.t), think=rng.uniform(0.001, 0.006))
        s.c2s(smb.close_req(dfid), think=0.0006)
        s.s2c(smb.close_resp(s.t, 0), think=0.0006)
        listed_sizes = {n: sz for n, sz, _ in listing}
    while done < total_bytes:
        if direction == "read":
            name = names[i % len(names)]
            size = min(total_bytes - done, max(65536, listed_sizes[name]))
        else:
            name = f"sqlbackup\\Logistics_full_{i:03d}.bak"
            size = min(total_bytes - done, int(per_file * rng.uniform(0.3, 1.8)))
        s.c2s(smb.create_req(name, write=(direction == "write"), overwrite=True) if direction == "write"
              else smb.create_req(name), think=rng.uniform(0.001, 0.01))
        r, fid = smb.create_resp(s.t, size if direction == "read" else 0)
        s.s2c(r, think=0.0008)
        content = P.file_blob(name, size) if direction == "read" else None
        off = 0
        while off < size:
            n = min(chunk, size - off)
            part = content[off:off + n] if direction == "read" else P.blob(n)
            if direction == "read":
                s.c2s(smb.read_req(fid, off, n), think=0.0002)
                s.s2c(smb.read_resp(part), think=0.0004)
            else:
                s.c2s(smb.write_req(fid, off, part), think=0.0002)
                s.s2c(smb.write_resp(n), think=0.0004)
            off += n
            if pace:
                rate = pace * (1.0 - (1.0 - pace_end) * min(1.0, (done + off) / max(1, total_bytes)))
                s.t += n / rate * rng.uniform(0.7, 1.3)
        s.c2s(smb.close_req(fid), think=0.0006)
        s.s2c(smb.close_resp(s.t, size), think=0.0006)
        done += size
        i += 1
    pk = _smb_close(s, smb)
    out.append(pk)
    return merged(*out)


# ============================================================ INTRANET HTTP + TDS
def sql_pool_open(ctx: Ctx, ts, n=4, web=None, svc="svc_intranet", pool=None,
                  sql=None, db="Logistics"):
    """IIS app pool opens pooled TDS connections to SQL1 at start-up.

    `sql`/`db` are parameters so the MES tier at Purdue level 3 can use the same builder
    against its own database server; the defaults are the historical enterprise values, so
    no existing caller moves. web/sql default to None and resolve to the build identity's
    WEB1/SQL1 here -- a default bound at import would freeze to the template company."""
    web = web or H("WEB1")
    sql = sql or H("SQL1")
    pool = ctx.sql_pool if pool is None else pool
    web, sql = ctx.h[web], ctx.h[sql]
    out = ctx.arp_for(web, sql, ts)
    for i in range(n):
        s = ctx.tcp(web, sql, 1433, ts + 0.01 * i).handshake()
        s.c2s(P.tds_prelogin(True), think=0.0004)
        s.s2c(P.tds_prelogin(False), think=rng.uniform(0.0005, 0.002))
        s.c2s(P.tds_login7(svc), think=0.0006)
        s.s2c(P.tds_login_ack(), think=rng.uniform(0.001, 0.004))
        s.c2s(P.tds_sql_batch("SET NOCOUNT ON; SELECT @@SPID AS spid, DB_NAME() AS db"), think=0.001)
        s.s2c(P.tds_split(0x04, P.tds_result([("spid", "int"), ("db", "nvarchar")], [(rng.randint(51, 120), db)]), 60), think=0.001)
        pool.append(s)
        out += s.drain()
    return merged(out)


def sql_query(ctx: Ctx, ts, user, rows=None, pool=None):
    """One request/response on a pooled connection, emitted at ts."""
    pool = ctx.sql_pool if pool is None else pool
    s = rng.choice(pool)
    s.at(ts)
    q = rng.choice(P.SQL_QUERIES).replace("{n}", str(rng.randint(100000, 999999))).replace("{user}", user).replace("{prefix}", get_current().prefix)
    s.c2s(P.tds_sql_batch(q), think=0.0)
    rows = rows if rows is not None else rng.randint(1, 60)
    cols = [("ShipmentId", "int"), ("TrackingNo", "nvarchar"), ("HubCode", "nvarchar"), ("Status", "nvarchar"), ("Pallets", "int"), ("ETA", "datetime")]
    data = [(rng.randint(100000, 999999), f"{get_current().prefix}{rng.randint(100000, 999999)}", rng.choice(["ORD", "DFW", "EWR", "MEM", "DEN"]), rng.choice(["IN_TRANSIT", "DELIVERED", "AT_HUB"]), rng.randint(1, 26), None) for _ in range(rows)]
    s.s2c(P.tds_split(0x04, P.tds_result(cols, data), 60), think=rng.uniform(0.0008, 0.02))
    return s.drain()


def sql_pool_close(ctx: Ctx, ts, pool=None):
    pool = ctx.sql_pool if pool is None else pool
    out = []
    for s in pool:
        s.at(ts + rng.uniform(0, 2))
        out += s.close(think=0.001)
    pool[:] = []
    return merged(out)


def intranet_session(ctx: Ctx, client, ts, pages=None, web=None,
                     host=None, pool=None):
    web = web or H("WEB1")           # None default: an import-bound H() would freeze the company
    host = host or ("intranet." + get_current().domain)
    pool = ctx.sql_pool if pool is None else pool
    web = ctx.h[web]
    user = P.username_for(client.name)
    ua = P.UAS[0] if ctx.is_windows(client) else P.UAS[2]
    pre = resolve_internal(ctx, client, web, ts) if rng.random() < 0.5 else []
    t = ts + rng.uniform(0.003, 0.02)
    tgs, t = kerberos_tgs(ctx, client, "HTTP", web, t)
    out = ctx.arp_for(client, web, t)
    s = ctx.tcp(client, web, 80, t + 0.001).handshake()
    sql_pkts = []
    # first request challenged with Negotiate, then authenticated
    s.c2s(P.http_request("GET", "/", host, ua), think=rng.uniform(0.001, 0.01))
    s.s2c(P.http_response("401 Unauthorized", b"", "text/html", s.t, headers=["WWW-Authenticate: Negotiate", "WWW-Authenticate: NTLM"]), think=rng.uniform(0.001, 0.004))
    token = base64.b64encode(P.krb_ap_req_token(user, "HTTP", web.fqdn)).decode()
    pages = pages or rng.randint(2, 7)
    paths = ["/"] + [rng.choice(["/shipments", "/shipments?page=%d" % rng.randint(2, 9), "/carriers", "/reports", "/api/shipments?page=1&size=50", "/api/shipments?status=EXCEPTION", "/shipments/%d" % rng.randint(100000, 999999)]) for _ in range(pages - 1)]
    first = True
    for path in paths:
        think = rng.uniform(0.0005, 0.003) if first else rng.uniform(2.0, 45.0)
        hdrs = ["Authorization: Negotiate " + token] if first else ["Cookie: ASP.NET_SessionId=" + os.urandom(12).hex()]
        if path.startswith("/api/"):
            hdrs.append("Accept: application/json")
            hdrs.append("X-Requested-With: XMLHttpRequest")
        s.c2s(P.http_request("GET", path, host, ua, hdrs), think=think)
        # backend query on a pooled TDS connection
        if pool:
            sql_pkts += sql_query(ctx, s.t + rng.uniform(0.0005, 0.002), user, pool=pool)
        if path.startswith("/api/"):
            body = P.shipments_json(rng.randint(20, 50))
            ctype = "application/json; charset=utf-8"
        else:
            body = P.intranet_page(path.strip("/").split("?")[0].title() or "Dashboard", rng.randint(15, 60), s.t)
            ctype = "text/html; charset=utf-8"
        extra = ["Persistent-Auth: true", "X-Powered-By: ASP.NET", "Cache-Control: private"]
        if first:
            extra.append("Set-Cookie: ASP.NET_SessionId=" + os.urandom(12).hex() + "; path=/; HttpOnly")
        s.s2c(P.http_response("200 OK", body, ctype, s.t, headers=extra, gzip=True), think=rng.uniform(0.004, 0.03))
        if first:
            # static assets follow the first page
            for ap, ab, at in (("/static/site.css", P.SITE_CSS, "text/css"), ("/static/app.js", P.APP_JS, "application/javascript"), ("/static/logo.png", FF.png_sized(rng.randint(6000, 14000)), "image/png")):
                s.c2s(P.http_request("GET", ap, host, ua, [f"Referer: http://{host}/"]), think=rng.uniform(0.002, 0.015))
                s.s2c(P.http_response("200 OK", ab, at, s.t, headers=["Cache-Control: public, max-age=86400", "ETag: \"%s\"" % os.urandom(6).hex()], gzip=(at != "image/png")), think=rng.uniform(0.001, 0.006))
        first = False
    pk = s.close(by_client=rng.random() < 0.7, think=rng.uniform(5, 30))
    return merged(pre, tgs, out, pk, sql_pkts)


# ==================================================================== HTTPS EGRESS
def _wants_dns(ctx, client, host, ts, dns):
    """dns=True resolves on first contact and again once the answer's 300 s TTL has run out (a client
    caches it, so a beacon every 60 s does not query every time); False never; None the browsing default."""
    if dns is None:
        return rng.random() < 0.6
    if not dns:
        return False
    cache = ctx.__dict__.setdefault("_client_dns", {})
    key = (client.name, host)
    if cache.get(key, 0) > ts:
        return False
    cache[key] = ts + 300
    return True


def tls_channel(ctx: Ctx, client, site, ts, duration, period=30.0, jitter=(0.6, 1.4),
                tls_profile=None, dns=True, rate=None, chunk=(60, 1600)):
    """A persistent TLS connection carrying opaque application data, not HTTP: what AnyDesk's
    RMM call-home, a Cloudflare/ngrok tunnel and a Cobalt Strike/Ligolo channel actually look
    like on the wire after the handshake -- one long-lived session with small bidirectional
    records on a steady keep-alive cadence, closing only at the end. Fully decryptable with the
    key log (the records are opaque at the HTTP layer, not TLS-opaque)."""
    from .tls import TlsSession
    host, srv = site
    pre = dns_lookup(ctx, client, host, ts, external=True, answers=[(P.DNS_A, srv.ipb)]) if _wants_dns(ctx, client, host, ts, dns) else []
    t = ts + rng.uniform(0.005, 0.05)
    out = ctx.arp_for(client, srv, t)
    s = ctx.tcp(client, srv, 443, t + 0.001, rate=rate).handshake()
    tls = TlsSession(ctx.pki, host, ctx.keylog, profile=tls_profile or getattr(client, "tls_profile", "winhttp"))
    for from_c, data in tls.handshake():
        (s.c2s if from_c else s.s2c)(data, think=rng.uniform(0.0005, 0.01))
    end = ts + duration
    while s.t < end:
        s.c2s(tls.app_data(True, P.blob(rng.randint(*chunk))), think=period * rng.uniform(*jitter))
        if s.t >= end:
            break
        s.s2c(tls.app_data(False, P.blob(rng.randint(*chunk))), think=rng.uniform(0.01, 0.2))
    s.c2s(tls.close_notify(True), think=0.5)
    pk = s.close(think=0.01)
    return merged(pre, out, pk)


def https_session(ctx: Ctx, client, site, ts, requests=None, sizes=None, keep_open=None,
                  rate=None, ua=None, paths=None, req_headers=None, dns=None, ctype=None, tls_profile=None):
    """TLS 1.2 session to an internet site through the firewall. Fully decryptable with the key log.
    dns: True always resolves the name first (C2 / exfil, so first contact is visible in DNS), False never
    (the caller already did), None the browsing default (resolved 60% of the time; the rest hit the cache)."""
    from .tls import TlsSession
    fixed_ctype = ctype
    host, srv = site
    # ua/paths/req_headers let a non-browser client pin its own request shape. A client that
    # calls one fixed path with a hard-coded, atypical user agent is the decryptable tell;
    # left as None this is the ordinary browser default and nothing changes.
    ua = ua or (P.UAS[0] if ctx.is_windows(client) else P.UAS[2])
    pre = dns_lookup(ctx, client, host, ts, external=True, answers=[(P.DNS_A, srv.ipb)]) if _wants_dns(ctx, client, host, ts, dns) else []
    t = ts + rng.uniform(0.005, 0.05)
    out = ctx.arp_for(client, srv, t)
    s = ctx.tcp(client, srv, 443, t + 0.001, rate=rate).handshake()
    tls = TlsSession(ctx.pki, host, ctx.keylog, profile=tls_profile or getattr(client, "tls_profile", "chrome"))
    for from_c, data in tls.handshake():
        if from_c:
            s.c2s(data, think=rng.uniform(0.0005, 0.003))
        else:
            s.s2c(data, think=rng.uniform(0.002, 0.01))
    requests = requests or rng.randint(2, 10)
    for i in range(requests):
        path = rng.choice(paths) if paths else rng.choice(
            ["/", "/index.html", "/news/%d" % rng.randint(1000, 9999), "/api/v1/feed?limit=20", "/assets/app.%s.js" % os.urandom(4).hex(),
                           "/assets/style.css", "/images/hero-%d.jpg" % rng.randint(1, 40), "/search?q=freight+rates", "/account/session"])
        hdrs = list(req_headers) if req_headers else ([] if not i else ["Referer: https://%s/" % host])
        req = P.http_request("GET", path, host, ua, hdrs)
        s.c2s(tls.app_data(True, req), think=rng.uniform(0.0008, 0.004) if i == 0 else rng.uniform(1.0, 20.0))
        size = sizes[i] if sizes and i < len(sizes) else int(rng.lognormvariate(10.4, 1.0))
        size = min(size, 6_000_000) if (sizes and i < len(sizes)) else max(400, min(size, 6_000_000))
        if fixed_ctype:       # a pinned beacon profile: one content type, opaque body
            body, ctype = P.blob(size), fixed_ctype
        elif path.endswith((".js", ".css", ".html")) or path == "/":
            body = (P.text_blob(size) if size < 200_000 else P.blob(size))
            ctype = "text/html; charset=utf-8" if not path.endswith((".js", ".css")) else ("application/javascript" if path.endswith(".js") else "text/css")
        elif "api" in path:
            body, ctype = P.shipments_json(rng.randint(10, 40)), "application/json"
        else:
            body, ctype = P.blob(size), "image/jpeg"
        resp = P.http_response("200 OK", body, ctype, s.t, server=rng.choice(["nginx/1.26.2", "cloudflare", "Apache/2.4.62", "AmazonS3"]),
                               headers=["Cache-Control: max-age=600", "Strict-Transport-Security: max-age=63072000"])
        s.s2c(tls.app_data(False, resp), think=rng.uniform(0.02, 0.12))
    s.c2s(tls.close_notify(True), think=rng.uniform(0.5, 15.0) if keep_open is None else keep_open)
    pk = s.close(think=0.002)
    return merged(pre, out, pk)

def needymantis_beacon(ctx: Ctx, client, site, ts, first=False):
    """One decryptable HTTPS check-in from a NeedyMantis-style implant.

    Every network-observable the implant has, inside a TLS session the key log decrypts:
      * a DNS A lookup of the C2 domain (always emitted -- it is the first thing on the wire);
      * SNI = the C2 domain, to the Cloudflare-fronted edge address;
      * GET /library/zip/ with the hard-coded User-Agent "firefox/21.0";
      * on the FIRST contact, a Cookie carrying base64 system metadata (the implant's system-info
        check-in: computer name, user, a short process-id list), answered with a Set-Cookie and
        a Cloudflare-fronted response (Server/CF-RAY/CF-Cache-Status), then an HTTP->WebSocket
        UPGRADE handshake (Upgrade/Connection/Sec-WebSocket-Key -> 101 Switching Protocols with
        Sec-WebSocket-Accept). The upgrade HEADERS are the observable the platform classifies on; the
        RFC 6455 binary frames that would follow are encrypted and opaque, so they are
        deliberately not synthesised, and the connection is not kept open -- every later contact
        is its own fresh TLS session with a small check-in GET, not a kept-alive poll.
    """
    from .tls import TlsSession
    import base64 as _b64
    host, srv = site
    ua = "firefox/21.0"
    path = "/library/zip/"

    def _cfray():
        return "%016x-%s" % (rng.getrandbits(64), rng.choice(["SJC", "DFW", "ORD", "IAD", "LHR", "AMS"]))

    def _cf_headers(extra=()):
        return ["CF-RAY: " + _cfray(), "CF-Cache-Status: DYNAMIC"] + list(extra)

    # the lookup is always present for this flow, not the 60% of a browser session
    pre = dns_lookup(ctx, client, host, ts, external=True, answers=[(P.DNS_A, srv.ipb)])
    t = ts + rng.uniform(0.005, 0.03)
    out = ctx.arp_for(client, srv, t)
    s = ctx.tcp(client, srv, 443, t + 0.001, rate=50e6).handshake()
    tls = TlsSession(ctx.pki, host, ctx.keylog, profile=getattr(client, "tls_profile", "winhttp"))
    for from_c, data in tls.handshake():
        if from_c: s.c2s(data, think=rng.uniform(0.0005, 0.003))
        else:      s.s2c(data, think=rng.uniform(0.002, 0.01))

    if first:
        # system-info check-in: a Cookie carrying base64 of readable "host|user|pids" text,
        # not random noise -- a defender who decodes it learns exactly what the implant sent
        pids = ",".join(str(rng.randint(400, 9000)) for _ in range(rng.randint(3, 6)))
        meta = "%s|%s|%s" % (client.name, P.username_for(client.name), pids)
        meta_b64 = _b64.b64encode(meta.encode()).decode()
        req = P.http_request("GET", path, host, ua, ["Cookie: SESSIONID=" + meta_b64])
        s.c2s(tls.app_data(True, req), think=rng.uniform(0.001, 0.01))
        resp = P.http_response("200 OK", P.blob(rng.randint(120, 400)), "application/octet-stream", s.t,
                               server="cloudflare",
                               headers=_cf_headers(["Set-Cookie: SESSIONID=%s; Path=/; HttpOnly" % _b64.b64encode(os.urandom(18)).decode()]))
        s.s2c(tls.app_data(False, resp), think=rng.uniform(0.02, 0.1))
        # HTTP -> WebSocket upgrade (headers only; no frame builder, which stays out of scope).
        # This upgrade happens once, on first contact only -- it is not kept open.
        wskey = _b64.b64encode(os.urandom(16)).decode()
        up = P.http_request("GET", path, host, ua,
                            ["Upgrade: websocket", "Connection: Upgrade",
                             "Sec-WebSocket-Key: " + wskey, "Sec-WebSocket-Version: 13"])
        s.c2s(tls.app_data(True, up), think=rng.uniform(0.001, 0.008))
        acc = _b64.b64encode(os.urandom(20)).decode()
        up_r = P.http_response("101 Switching Protocols", b"", "application/octet-stream", s.t,
                               server="cloudflare",
                               headers=_cf_headers(["Upgrade: websocket", "Connection: Upgrade",
                                                    "Sec-WebSocket-Accept: " + acc]))
        s.s2c(tls.app_data(False, up_r), think=rng.uniform(0.01, 0.05))
    else:
        # later contacts: a fresh TLS session each time (no persistent channel), one small
        # check-in GET and a 200
        req = P.http_request("GET", path, host, ua, ["Cookie: SESSIONID=" + _b64.b64encode(os.urandom(12)).decode()])
        s.c2s(tls.app_data(True, req), think=rng.uniform(0.001, 0.01))
        resp = P.http_response("200 OK", P.blob(rng.randint(60, 200)), "application/octet-stream", s.t,
                               server="cloudflare", headers=_cf_headers())
        s.s2c(tls.app_data(False, resp), think=rng.uniform(0.02, 0.08))

    s.c2s(tls.close_notify(True), think=rng.uniform(0.3, 0.8))
    pk = s.close(think=0.002)
    return merged(pre, out, pk)



def patch_download(ctx: Ctx, client, ts, total=None):
    """OS update download: a few large HTTPS responses from the update CDN."""
    site = ctx.sites["updates.example.org"] if ctx.is_windows(client) else ctx.sites["swcdn.example.net"]
    total = total or int(rng.uniform(6e6, 40e6) * ctx.scale)
    parts = max(1, total // 5_000_000)
    sizes = [total // parts] * parts
    return https_session(ctx, client, site, ts, requests=parts, sizes=sizes, keep_open=0.3, rate=90e6)


# =========================================================================== PRINT
def print_job(ctx: Ctx, client, ts):
    ps = ctx.h[H("PRINT1")]
    printer = rng.choice([h for h in ctx.h.values() if h.name.startswith(H("PRN"))])
    user = P.username_for(client.name)
    doc = rng.choice(FILE_NAMES).replace("{n}", str(rng.randint(10000, 99999)))
    size = rng.randint(30_000, 900_000)
    # workstation -> print server: spoolss over SMB named pipe
    s, smb, pre = _smb_open(ctx, client, ps, "IPC$", ts)
    s.c2s(smb.create_req("spoolss", pipe=True), think=rng.uniform(0.002, 0.01))
    r, fid = smb.create_resp(s.t, 0)
    s.s2c(r, think=0.0008)
    callid = rng.randint(1, 500)
    auth = (user, "cifs", ps.fqdn)
    bind = P.dcerpc_bind(callid, P.SPOOLSS_UUID, 1, auth=auth)
    s.c2s(smb.write_req(fid, 0, bind), think=0.0008)
    s.s2c(smb.write_resp(len(bind)), think=0.0006)
    s.c2s(smb.read_req(fid, 0, 1024), think=0.0004)
    s.s2c(smb.read_resp(P.dcerpc_bind_ack(callid, "\\PIPE\\spoolss", auth=True)), think=0.0008)

    def rpc(opnum, req_len, resp_len, think=0.001):
        nonlocal callid
        callid += 1
        req = P.dcerpc_request(callid, opnum, P.blob(req_len), sealed=True)
        s.c2s(smb.write_req(fid, 0, req), think=think)
        s.s2c(smb.write_resp(len(req)), think=0.0006)
        s.c2s(smb.read_req(fid, 0, 1024), think=0.0004)
        s.s2c(smb.read_resp(P.dcerpc_response(callid, P.blob(resp_len), sealed=True)), think=rng.uniform(0.0008, 0.004))
    for opnum, rq, rs in ((69, 300, 40), (17, 420, 60), (19, 120, 24)):  # RpcOpenPrinterEx, RpcStartDocPrinter, RpcStartPagePrinter
        rpc(opnum, rq, rs, rng.uniform(0.001, 0.005))
    job = P.pjl_job(user, doc, size)
    for off in range(0, len(job), 32768):
        rpc(20, len(job[off:off + 32768]) + 16, 8, 0.0006)          # RpcWritePrinter
    for opnum in (21, 23, 29):                                        # EndPage, EndDoc, ClosePrinter
        rpc(opnum, 24, 8)
    s.c2s(smb.close_req(fid), think=0.001)
    s.s2c(smb.close_resp(s.t, 0), think=0.0006)
    pk = _smb_close(s, smb)
    t2 = s.t + rng.uniform(0.3, 2.0)
    # print server -> printer: SNMP status check, then raw 9100 job
    snmp = snmp_poll(ctx, ps, printer, t2, oids=["1.3.6.1.2.1.25.3.5.1.1.1", "1.3.6.1.2.1.43.16.5.1.2.1.1"], community=b"public")
    out = ctx.arp_for(ps, printer, t2 + 0.05)
    s2 = ctx.tcp(ps, printer, 9100, t2 + 0.06, rate=100e6).handshake()
    s2.c2s(job, think=0.002)
    pk2 = s2.close(think=rng.uniform(0.05, 0.4))
    return merged(pre, pk, snmp, out, pk2)


# ============================================================================ SNMP
SNMP_OIDS = ["1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.2.2.1.10.1", "1.3.6.1.2.1.2.2.1.16.1", "1.3.6.1.2.1.2.2.1.14.1", "1.3.6.1.2.1.2.2.1.8.1", "1.3.6.1.2.1.1.5.0"]
IF_TABLE_OID = "1.3.6.1.2.1.2.2.1"             # ifTable subtree walked by salt_recon


def _snmp_dev_state(ctx: Ctx, device):
    """Per-device SNMP state: a distinct boot instant and a counters dict, so successive
    polls/walks of the same device agree with each other and with its own past."""
    st = ctx.snmp_state.get(device.name)
    if st is None:
        st = {"boot": 1_720_000_000 - rng.randint(0, 45 * 86400), "counters": {}}
        ctx.snmp_state[device.name] = st
    return st


def _snmp_counter(st, oid, ts, lo, hi, rate_lo, rate_hi):
    """A Counter32 that only ever increases (mod 2**32) between successive calls for the
    same (device, oid), at a plausible rate -- not an independent random draw per poll."""
    c = st["counters"].get(oid)
    if c is None:
        val = rng.randint(lo, hi)
        st["counters"][oid] = {"ts": ts, "val": val, "rate": rng.uniform(rate_lo, rate_hi)}
        return val
    dt = max(0.0, ts - c["ts"])
    inc = int(c["rate"] * dt * rng.uniform(0.6, 1.4))
    c["val"] = (c["val"] + max(0, inc)) & 0xFFFFFFFF
    c["ts"] = ts
    return c["val"]


def _snmp_value(ctx: Ctx, device, st, o, ts):
    from . import asn1 as A
    if o.endswith(".1.3.0"):
        up = int((ts - st["boot"]) * 100) & 0x7FFFFFFF
        return A.snmp_timeticks(up)
    if o.endswith(".1.5.0"):
        return A.octets(device.name.encode())
    if ".2.2.1.8." in o:
        return A.integer(1)                                        # ifOperStatus: up
    if ".2.2.1.14." in o or ".2.2.1.20." in o:                       # ifInErrors/ifOutErrors: small, near-flat
        return A.snmp_counter32(_snmp_counter(st, o, ts, 0, 8, 0.0, 0.0006))
    if ".2.2.1.10." in o or ".2.2.1.16." in o:                       # ifInOctets/ifOutOctets: real traffic rate
        return A.snmp_counter32(_snmp_counter(st, o, ts, 2_000_000, 900_000_000, 400, 60_000))
    if ".25.3.5.1.1" in o:
        return A.integer(3)
    return A.snmp_counter32(rng.randint(1, 2**31))                   # unmodelled OID: unchanged behaviour


def snmp_poll(ctx: Ctx, poller, device, ts, oids=None, community=None):
    oids = oids or SNMP_OIDS
    community = community or (get_current().prefix.lower() + "ro").encode()
    st = _snmp_dev_state(ctx, device)
    out = ctx.arp_for(poller, device, ts)
    sport = poller.eph()
    rid = rng.randint(1, 2**30)
    out.append(ctx.udp(poller, device, sport, 161, P.snmp_get(rid, oids, community), ts))
    vals = [(o, _snmp_value(ctx, device, st, o, ts)) for o in oids]
    out.append(ctx.udp(device, poller, 161, sport, P.snmp_response(rid, vals, community), ts + rng.uniform(0.001, 0.006), vantage=poller))
    return merged(out)


def _iftable_leaves(device, n_if):
    """Synthetic ifTable rows in real SNMP walk order: column-major (all of column C across
    every row, then the next column), matching numeric OID order under IF_TABLE_OID."""
    descr_pfx = {H("SWB1"): "GigabitEthernet0/", H("WLC1"): "wifi", H("SENSOR1"): "eth",
                 H("NTP1"): "eth", H("LOG1"): "eth"}.get(device.name, "eth")
    cols = (1, 2, 3, 4, 5, 6, 7, 8, 10, 14, 16)                       # ifIndex..ifOutOctets, numeric order
    leaves = []
    for col in cols:
        for idx in range(1, n_if + 1):
            leaves.append((f"{IF_TABLE_OID}.{col}.{idx}", col, idx))
    return leaves, descr_pfx


def snmp_walk(ctx: Ctx, poller, device, ts, community=b"public"):
    """A real table walk of ifTable: one UDP socket for the whole walk, GetBulkRequest PDUs
    whose request id increments by 1 each step and whose OIDs advance through the subtree,
    ending in endOfMibView once the walk steps off the end -- not a run of identical GETs."""
    from . import asn1 as A
    st = _snmp_dev_state(ctx, device)
    n_if = {H("SWB1"): 4, H("WLC1"): 3}.get(device.name, 2)
    leaves, descr_pfx = _iftable_leaves(device, n_if)
    out = ctx.arp_for(poller, device, ts)
    sport = poller.eph()
    rid = rng.randint(1, 2**30)
    max_rep = rng.randint(10, 25)
    pos = 0
    t = ts
    last_oid = IF_TABLE_OID
    while True:
        req_oid = last_oid
        out.append(ctx.udp(poller, device, sport, 161, P.snmp_getbulk(rid, [req_oid], community, max_repetitions=max_rep), t))
        vals = []
        padded = False
        for _ in range(max_rep):
            if pos >= len(leaves):
                vals.append((last_oid, A.snmp_end_of_mib_view()))
                padded = True
                continue
            oid, col, idx = leaves[pos]
            if col == 1:
                val = A.integer(idx)
            elif col == 2:
                val = A.octets(f"{descr_pfx}{idx}".encode())
            elif col == 3:
                val = A.integer(6 if device.name != H("WLC1") else 71)        # ethernetCsmacd / ieee80211
            elif col == 4:
                val = A.integer(1500)
            elif col == 5:
                val = A.snmp_gauge32(1_000_000_000)
            elif col == 6:
                val = A.octets(bytes([0x02, 0x00, idx & 0xFF, 0x00, 0x00, (idx * 7) & 0xFF]))
            elif col == 7 or col == 8:
                val = A.integer(1)                                              # admin/oper status: up
            elif col in (10, 16):
                val = A.snmp_counter32(_snmp_counter(st, oid, t, 2_000_000, 900_000_000, 400, 60_000))
            else:  # 14: ifInErrors
                val = A.snmp_counter32(_snmp_counter(st, oid, t, 0, 8, 0.0, 0.0006))
            vals.append((oid, val))
            last_oid = oid
            pos += 1
        resp_t = t + rng.uniform(0.004, 0.03)
        out.append(ctx.udp(device, poller, 161, sport, P.snmp_response(rid, vals, community), resp_t, vantage=poller))
        rid += 1
        t = resp_t + rng.uniform(0.02, 0.25)
        if padded:
            break
    return merged(out)


# ========================================================================== SYSLOG
FW_APPS = ["web-browsing", "ssl", "dns", "ms-ds-smb", "kerberos", "ldap", "mssql-db", "sip", "ntp", "snmp", "capwap", "ms-rdp", "ssh"]


def syslog_msg(ctx: Ctx, sender, ts, text=None):
    log = ctx.h[H("LOG1")]
    if text is None:
        # these log bodies quote addresses on the emulated network, so derive them from the
        # actual hosts — otherwise a re-addressed capture has firewall logs citing the old net
        user_pfx = ctx.link.fw_a.ip.rsplit(".", 1)[0]
        mgmt = ctx.h[H("MGMT1")].ip
        if "FW" in sender.name:
            src = f"{user_pfx}.{rng.randint(100, 195)}"
            app = rng.choice(FW_APPS)
            # Both timestamps derive from ts. The first was the literal "2026/09/14", so
            # every one of these lines carried a receive time that disagreed with its own
            # generated time as soon as the capture day moved -- and was only ever right by
            # coincidence before that.
            text = (f"1,{P.time.strftime('%Y/%m/%d %H:%M:%S', P.time.localtime(ts))},012345678901,TRAFFIC,end,2561,{P.time.strftime('%Y/%m/%d %H:%M:%S', P.time.localtime(ts))},{src},"
                    f"{rng.choice([ctx.h[H('DC1')].ip, ctx.h[H('FILE1')].ip, ctx.h[H('WEB1')].ip])},0.0.0.0,0.0.0.0,Allow-Users-to-Servers,,,{app},vsys1,Users,Servers,ethernet1/1,ethernet1/2,Forward-LOG1,{rng.randint(1,9999999)},1,{rng.randint(49152,65535)},"
                    f"{rng.choice([53,80,445,88,389,1433])},0,0,0x400019,tcp,allow,{rng.randint(1000,900000)},{rng.randint(500,400000)},{rng.randint(300,500000)},{rng.randint(4,900)},aged-out,0,0,0,0,,{H('FW1')},from-policy")
            text = H("FW1") + " " + text
            pri = 14
        elif "SW" in sender.name:
            text = rng.choice([f"%SYS-5-CONFIG_I: Configured from console by admin on vty0 ({mgmt})", f"%LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/{rng.randint(1,48)}, changed state to up",
                               f"%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: {mgmt}] [localport: 22] at {P.time.strftime('%H:%M:%S', P.time.localtime(ts))} EDT",
                               f"%ILPOWER-5-IEEE_DISCONNECT: Interface Gi1/0/{rng.randint(1,48)}: PD removed", f"%DHCP_SNOOPING-6-BINDING: DHCP snooping binding added {user_pfx}.{rng.randint(100,195)}"])
            text = f"{rng.randint(1000, 99999)}: {sender.name}: {text}"
            pri = 189
        else:
            text = rng.choice([f"sshd[{rng.randint(1000,60000)}]: Accepted publickey for admin from {mgmt} port {rng.randint(40000,60000)} ssh2",
                               f"systemd[1]: Started Session {rng.randint(100,999)} of user admin.", f"CRON[{rng.randint(1000,60000)}]: (root) CMD (/usr/local/bin/rotate-logs.sh)",
                               f"chronyd[812]: Selected source {ctx.h[H('NTP1')].ip}", f"asterisk[1202]: NOTICE[1210]: chan_sip.c: Registration from '<sip:{rng.randint(2001,2010)}@{get_current().host('PBX1').lower()}>' accepted",
                               f"Microsoft-Windows-Security-Auditing: 4624 An account was successfully logged on. Account Name: {P.username_for(H('WS-%03d' % rng.randint(1,75)))}"])
            text = f"{sender.name.lower()} {text}"
            pri = 30
    else:
        pri = 30
    out = ctx.arp_for(sender, log, ts)
    out.append(ctx.udp(sender, log, 514 if sender.ttl == 64 else sender.eph(), 514, P.syslog(pri, ts, sender.name.lower(), text), ts))
    return merged(out)


# ========================================================================== CAPWAP
def capwap_ap(ctx: Ctx, ap, t_start, t_end):
    """Generator: the AP's CAPWAP control tunnel (DTLS, Echo every 30 s) and data channel keep-alive (RFC 5415).
    The tunnels are modelled in capwap.py; a scenario can stall the controller and the AP then rejoins."""
    from .capwap import get_plane
    yield from get_plane(ctx).stream(ap, t_start, t_end)


# ============================================================================ VOIP
def sip_register(ctx: Ctx, phone, ts, expires=3600):
    _pbx = get_current().fqdn("PBX1"); _rlm = get_current().sip_realm
    pbx = ctx.h[H("PBX1")]
    ext = 2000 + int(phone.name[-2:])
    out = ctx.arp_for(phone, pbx, ts)
    callid = os.urandom(8).hex() + "@" + phone.ip
    branch = "z9hG4bK" + os.urandom(6).hex()
    tag = os.urandom(4).hex()
    common = [f"Via: SIP/2.0/UDP {phone.ip}:5060;branch={branch}", f"From: <sip:{ext}@{_pbx}>;tag={tag}",
              f"To: <sip:{ext}@{_pbx}>", f"Call-ID: {callid}", "Max-Forwards: 70",
              f"Contact: <sip:{ext}@{phone.ip}:5060;transport=udp>", f"Expires: {expires}", "User-Agent: Cisco-CP8841/14.2.1", "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REFER, SUBSCRIBE, UPDATE"]
    out.append(ctx.udp(phone, pbx, 5060, 5060, P.sip_msg(f"REGISTER sip:{_pbx} SIP/2.0", common + ["CSeq: 1 REGISTER"]), ts))
    nonce = os.urandom(8).hex()
    out.append(ctx.udp(pbx, phone, 5060, 5060, P.sip_msg("SIP/2.0 401 Unauthorized", [common[0] + ";received=" + phone.ip, common[1], common[2] + ";tag=as" + os.urandom(4).hex(), common[3], "CSeq: 1 REGISTER", "Server: Asterisk PBX 20.9.2",
                       f"WWW-Authenticate: Digest algorithm=MD5, realm=\"{_rlm}\", nonce=\"{nonce}\""]), ts + rng.uniform(0.001, 0.004), vantage=phone))
    auth = f"Authorization: Digest username=\"{ext}\", realm=\"{_rlm}\", nonce=\"{nonce}\", uri=\"sip:{_pbx}\", response=\"{os.urandom(16).hex()}\", algorithm=MD5"
    common[0] = f"Via: SIP/2.0/UDP {phone.ip}:5060;branch=z9hG4bK{os.urandom(6).hex()}"
    out.append(ctx.udp(phone, pbx, 5060, 5060, P.sip_msg(f"REGISTER sip:{_pbx} SIP/2.0", common + ["CSeq: 2 REGISTER", auth]), ts + rng.uniform(0.01, 0.04)))
    out.append(ctx.udp(pbx, phone, 5060, 5060, P.sip_msg("SIP/2.0 200 OK", [common[0] + ";received=" + phone.ip, common[1], common[2] + ";tag=as" + os.urandom(4).hex(), common[3], "CSeq: 2 REGISTER", "Server: Asterisk PBX 20.9.2",
                       f"Contact: <sip:{ext}@{phone.ip}:5060;transport=udp>;expires={expires}", "Date: " + P.http_date(ts)]), ts + rng.uniform(0.015, 0.05), vantage=phone))
    return merged(out)


def sip_call(ctx: Ctx, a, b, ts, duration):
    """Phone a calls phone b through the PBX; RTP flows directly between the phones."""
    _pbx = get_current().fqdn("PBX1")
    pbx = ctx.h[H("PBX1")]
    ea, eb = 2000 + int(a.name[-2:]), 2000 + int(b.name[-2:])
    pa, pb = rng.randrange(16384, 32766, 2), rng.randrange(16384, 32766, 2)
    out = ctx.arp_for(a, pbx, ts) + ctx.arp_for(pbx, b, ts + 0.05, vantage=b)
    cid1, cid2 = os.urandom(8).hex() + "@" + a.ip, os.urandom(8).hex() + "@" + pbx.ip
    ta, tb, tp = os.urandom(4).hex(), os.urandom(4).hex(), "as" + os.urandom(4).hex()

    def leg(frm, to, via_ip, cid, cseq, extra=None):
        return [f"Via: SIP/2.0/UDP {via_ip}:5060;branch=z9hG4bK{os.urandom(6).hex()}", frm, to, f"Call-ID: {cid}", f"CSeq: {cseq}", "Max-Forwards: 70"] + (extra or [])
    fa = f"From: \"{P.username_for(a.name).title()}\" <sip:{ea}@{_pbx}>;tag={ta}"
    toB = f"To: <sip:{eb}@{_pbx}>"
    sdp_a = P.sdp(a.ip, pa, rng.randint(1000, 99999))
    sdp_b = P.sdp(b.ip, pb, rng.randint(1000, 99999))
    t = ts
    # leg 1: A -> PBX
    out.append(ctx.udp(a, pbx, 5060, 5060, P.sip_msg(f"INVITE sip:{eb}@{_pbx} SIP/2.0", leg(fa, toB, a.ip, cid1, "101 INVITE", [f"Contact: <sip:{ea}@{a.ip}:5060>", "User-Agent: Cisco-CP8841/14.2.1"]), sdp_a), t))
    out.append(ctx.udp(pbx, a, 5060, 5060, P.sip_msg("SIP/2.0 100 Trying", leg(fa, toB, a.ip, cid1, "101 INVITE", ["Server: Asterisk PBX 20.9.2"])), t + 0.004, vantage=a))
    # leg 2: PBX -> B
    fp = f"From: \"{P.username_for(a.name).title()}\" <sip:{ea}@{pbx.ip}>;tag={tp}"
    toB2 = f"To: <sip:{eb}@{b.ip}:5060>"
    out.append(ctx.udp(pbx, b, 5060, 5060, P.sip_msg(f"INVITE sip:{eb}@{b.ip}:5060 SIP/2.0", leg(fp, toB2, pbx.ip, cid2, "102 INVITE", [f"Contact: <sip:{ea}@{pbx.ip}:5060>", "User-Agent: Asterisk PBX 20.9.2"]), sdp_a), t + 0.02, vantage=b))
    out.append(ctx.udp(b, pbx, 5060, 5060, P.sip_msg("SIP/2.0 100 Trying", leg(fp, toB2, pbx.ip, cid2, "102 INVITE")), t + 0.03, vantage=b))
    out.append(ctx.udp(b, pbx, 5060, 5060, P.sip_msg("SIP/2.0 180 Ringing", leg(fp, toB2 + f";tag={tb}", pbx.ip, cid2, "102 INVITE", [f"Contact: <sip:{eb}@{b.ip}:5060>"])), t + 0.09, vantage=b))
    out.append(ctx.udp(pbx, a, 5060, 5060, P.sip_msg("SIP/2.0 180 Ringing", leg(fa, toB + f";tag={tp}", a.ip, cid1, "101 INVITE")), t + 0.1, vantage=a))
    ring = rng.uniform(2, 9)
    t += ring
    out.append(ctx.udp(b, pbx, 5060, 5060, P.sip_msg("SIP/2.0 200 OK", leg(fp, toB2 + f";tag={tb}", pbx.ip, cid2, "102 INVITE", [f"Contact: <sip:{eb}@{b.ip}:5060>"]), sdp_b), t, vantage=b))
    out.append(ctx.udp(pbx, b, 5060, 5060, P.sip_msg(f"ACK sip:{eb}@{b.ip}:5060 SIP/2.0", leg(fp, toB2 + f";tag={tb}", pbx.ip, cid2, "102 ACK")), t + 0.006, vantage=b))
    out.append(ctx.udp(pbx, a, 5060, 5060, P.sip_msg("SIP/2.0 200 OK", leg(fa, toB + f";tag={tp}", a.ip, cid1, "101 INVITE", [f"Contact: <sip:{eb}@{pbx.ip}:5060>"]), sdp_b), t + 0.008, vantage=a))
    out.append(ctx.udp(a, pbx, 5060, 5060, P.sip_msg(f"ACK sip:{eb}@{_pbx} SIP/2.0", leg(fa, toB + f";tag={tp}", a.ip, cid1, "101 ACK")), t + 0.03))
    # media: G.711 20 ms both directions, direct between the phones
    out += ctx.arp_for(a, b, t + 0.02)
    ssa, ssb = rng.getrandbits(32), rng.getrandbits(32)
    sa, sb = rng.randint(0, 40000), rng.randint(0, 40000)
    rta, rtb = rng.getrandbits(32), rng.getrandbits(32)
    n = int(duration / 0.02)
    t0 = t + 0.04
    for i in range(n):
        tt = t0 + i * 0.02
        out.append(ctx.udp(a, b, pa, pb, P.rtp_packet(sa + i, rta + i * 160, ssa, marker=(i == 0)), tt + rng.uniform(-0.0005, 0.0005), tos=0xB8))
        out.append(ctx.udp(b, a, pb, pa, P.rtp_packet(sb + i, rtb + i * 160, ssb, marker=(i == 0)), tt + 0.01 + rng.uniform(-0.0005, 0.0005), tos=0xB8))
        if i % 250 == 249:  # RTCP SR every 5 s
            out.append(ctx.udp(a, b, pa + 1, pb + 1, P.rtcp_sr(ssa, tt, rta + i * 160, i, i * 160), tt + 0.003))
            out.append(ctx.udp(b, a, pb + 1, pa + 1, P.rtcp_sr(ssb, tt, rtb + i * 160, i, i * 160), tt + 0.013))
    t = t0 + n * 0.02 + 0.05
    # hang-up by A
    out.append(ctx.udp(a, pbx, 5060, 5060, P.sip_msg(f"BYE sip:{eb}@{_pbx} SIP/2.0", leg(fa, toB + f";tag={tp}", a.ip, cid1, "102 BYE")), t))
    out.append(ctx.udp(pbx, a, 5060, 5060, P.sip_msg("SIP/2.0 200 OK", leg(fa, toB + f";tag={tp}", a.ip, cid1, "102 BYE")), t + 0.005, vantage=a))
    out.append(ctx.udp(pbx, b, 5060, 5060, P.sip_msg(f"BYE sip:{eb}@{b.ip}:5060 SIP/2.0", leg(fp, toB2 + f";tag={tb}", pbx.ip, cid2, "103 BYE")), t + 0.01, vantage=b))
    out.append(ctx.udp(b, pbx, 5060, 5060, P.sip_msg("SIP/2.0 200 OK", leg(fp, toB2 + f";tag={tb}", pbx.ip, cid2, "103 BYE")), t + 0.016, vantage=b))
    return merged(out)


# ================================================================= NAME NOISE
def name_noise(ctx: Ctx, client, ts):
    """LLMNR/NBNS/mDNS/SSDP chatter typical of workstations and smart boards."""
    out = []
    if ctx.is_windows(client):
        name = rng.choice(["wpad", H("FILE1"), "isatap", H("PRINT1"), "_ldap._tcp.dc._msdcs", "FILESERVER"])
        txid = ctx.next_txid()
        for i in range(2):
            out.append((ts + i * 0.4, udp_bcast(client, 5355, 5355, P.llmnr_query(txid, name), dst_ip=b"\xe0\x00\x00\xfc", dst_mac=mcast_mac(b"\xe0\x00\x00\xfc"), ttl=1)))
        if rng.random() < 0.5:
            for i in range(3):
                out.append((ts + 1.0 + i * 0.75, udp_bcast(client, 137, 137, P.nbns_query(ctx.next_txid(), name.split(".")[0]), dst_ip=client.ipb[:3] + b"\xff")))
        if rng.random() < 0.2:
            out.append((ts + 0.2, udp_bcast(client, client.eph(), 1900, P.ssdp_msearch(), dst_ip=b"\xef\xff\xff\xfa", dst_mac=mcast_mac(b"\xef\xff\xff\xfa"), ttl=1)))
    else:
        q = P.mdns_query(rng.sample(["_airplay._tcp.local", "_companion-link._tcp.local", "_raop._tcp.local", "_googlecast._tcp.local", "_ipp._tcp.local", "_smb._tcp.local"], 2))
        out.append((ts, udp_bcast(client, 5353, 5353, q, dst_ip=b"\xe0\x00\x00\xfb", dst_mac=mcast_mac(b"\xe0\x00\x00\xfb"), ttl=255)))
        boards = [h for h in ctx.h.values() if h.name.startswith(H("SB"))]
        for sb in rng.sample(boards, rng.randint(0, 2)):
            out.append((ts + rng.uniform(0.02, 0.4), udp_bcast(sb, 5353, 5353, P.mdns_response("_airplay._tcp.local", f"{get_current().name} Room {sb.name[-1]}", sb.fqdn, 7000, sb.ipb), dst_ip=b"\xe0\x00\x00\xfb", dst_mac=mcast_mac(b"\xe0\x00\x00\xfb"), ttl=255)))
    return merged(out)


def nbns_register(ctx: Ctx, client, ts):
    out = []
    for i, suffix in enumerate((0x00, 0x20)):
        for j in range(3):
            out.append((ts + i * 2 + j * 0.25, udp_bcast(client, 137, 137, P.nbns_registration(ctx.next_txid(), client.name, client.ipb, suffix), dst_ip=client.ipb[:3] + b"\xff")))
    return merged(out)




# ============================================================ AD REPLICATION
def ad_replication(ctx: Ctx, ts):
    dc1, dc2 = ctx.h[H("DC1")], ctx.h[H("DC2")]
    src, dst = (dc1, dc2) if rng.random() < 0.5 else (dc2, dc1)
    pre, t = kerberos_tgs(ctx, src, "E3514235-4B06-11D1-AB04-00C04FC2DCD2", dst, ts, force=rng.random() < 0.1)
    out = ctx.arp_for(src, dst, t)
    # endpoint mapper
    s = ctx.tcp(src, dst, 135, t + 0.001).handshake()
    cid = rng.randint(1, 100)
    dport = rng.randint(49152, 49200)
    s.c2s(P.dcerpc_bind(cid, P.EPM_UUID, 3), think=0.0004)
    s.s2c(P.dcerpc_bind_ack(cid, "135"), think=0.001)
    s.c2s(P.dcerpc_request(cid + 1, 3, P.epm_map_request(P.DRSUAPI_UUID, 4, dst.ipb)), think=0.0005)
    s.s2c(P.dcerpc_response(cid + 1, P.epm_map_response(P.DRSUAPI_UUID, 4, dport, dst.ipb)), think=0.0015)
    pk = s.close(think=0.002)
    # DRSUAPI on the dynamic port, Kerberos packet privacy
    s2 = ctx.tcp(src, dst, dport, s.t + 0.003).handshake()
    auth = (src.name + "$", "E3514235-4B06-11D1-AB04-00C04FC2DCD2", dst.fqdn)
    s2.c2s(P.dcerpc_bind(cid + 2, P.DRSUAPI_UUID, 4, auth=auth), think=0.0004)
    s2.s2c(P.dcerpc_bind_ack(cid + 2, str(dport), auth=True), think=0.001)
    calls = [(0, 80, 60), (3, 220, int(rng.uniform(2000, 40000)))]  # DsBind, DsGetNCChanges
    for i, (op, rq, rs) in enumerate(calls):
        s2.c2s(P.dcerpc_request(cid + 3 + i, op, P.blob(rq), sealed=True), think=rng.uniform(0.0005, 0.003))
        s2.s2c(P.dcerpc_response(cid + 3 + i, P.blob(rs), sealed=True), think=rng.uniform(0.001, 0.01))
    s2.c2s(P.dcerpc_request(cid + 9, 1, P.blob(40), sealed=True), think=0.002)  # DsUnbind
    s2.s2c(P.dcerpc_response(cid + 9, P.blob(24), sealed=True), think=0.001)
    pk2 = s2.close(think=rng.uniform(0.01, 0.5))
    return merged(pre, out, pk, pk2)


# ================================================================ ADMIN ACCESS
def rdp_session(ctx: Ctx, admin, server, ts, duration, user=None, realm=None, dc=None):
    """user: the account in the X.224 mstshash cookie and the TERMSRV ticket (default: the legacy
    "admin" cookie with the client's own enterprise ticket); realm/dc for an OT-forest account."""
    from .tls import TlsSession
    pre = resolve_internal(ctx, admin, server, ts)
    tgs, t = kerberos_tgs(ctx, admin, "TERMSRV", server, ts + 0.01, user=user, realm=realm, dc=dc)
    out = ctx.arp_for(admin, server, t)
    s = ctx.tcp(admin, server, 3389, t + 0.001).handshake()
    s.c2s(P.rdp_x224_connect(user or "admin"), think=0.001)
    s.s2c(P.rdp_x224_confirm(), think=0.002)
    tls = TlsSession(ctx.pki, server.fqdn, _NullLog(), alpn=b"", kex="ecdhe", selfsigned=True)  # RDP: self-signed, forward-secret; its TLS keys are not exported: CredSSP stays opaque
    for from_c, data in tls.handshake():
        (s.c2s if from_c else s.s2c)(data, think=rng.uniform(0.001, 0.006))
    # CredSSP + connection sequence, then screen updates / input
    for size_c, size_s in ((250, 600), (1400, 300), (400, 4000), (900, 2500)):
        s.c2s(tls.app_data(True, os.urandom(size_c)), think=rng.uniform(0.002, 0.02))
        s.s2c(tls.app_data(False, os.urandom(size_s)), think=rng.uniform(0.002, 0.02))
    t_end = s.t + duration
    while s.t < t_end:
        if rng.random() < 0.6:
            s.c2s(tls.app_data(True, os.urandom(rng.randint(40, 120))), think=rng.uniform(0.05, 0.6))   # keystrokes / mouse
            s.s2c(tls.app_data(False, os.urandom(rng.randint(200, 6000))), think=rng.uniform(0.01, 0.05))
        else:
            s.s2c(tls.app_data(False, os.urandom(rng.randint(4000, 60000))), think=rng.uniform(0.3, 2.0))  # bitmap updates
    s.c2s(tls.close_notify(True), think=0.5)
    pk = s.close(think=0.01)
    return merged(pre, tgs, out, pk)


class _NullLog:
    def write(self, *_):
        pass


def ssh_session(ctx: Ctx, admin, server, ts, duration, server_banner=None):
    pre = resolve_internal(ctx, admin, server, ts)
    out = ctx.arp_for(admin, server, ts + 0.01)
    s = ctx.tcp(admin, server, 22, ts + 0.011).handshake()
    s.c2s(b"SSH-2.0-PuTTY_Release_0.81\r\n", think=0.002)
    s.s2c((server_banner or "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5").encode() + b"\r\n", think=0.003)
    s.c2s(P.ssh_kexinit(True), think=0.002)
    s.s2c(P.ssh_kexinit(False), think=0.002)
    s.c2s(P.ssh_ecdh_init(), think=0.003)
    s.s2c(P.ssh_ecdh_reply() + P.ssh_newkeys(), think=0.004)
    s.c2s(P.ssh_newkeys(), think=0.002)
    # service request, auth, channel open (encrypted)
    for c, r in ((44, 60), (120, 76), (508, 36), (92, 52), (140, 300)):
        s.c2s(P.ssh_encrypted(c), think=rng.uniform(0.005, 0.05))
        s.s2c(P.ssh_encrypted(r), think=rng.uniform(0.002, 0.02))
    t_end = s.t + duration
    while s.t < t_end:
        s.c2s(P.ssh_encrypted(36), think=rng.uniform(0.08, 0.9))       # one keystroke
        s.s2c(P.ssh_encrypted(rng.choice([36, 36, 36, 52, 164, 1200, 4300])), think=rng.uniform(0.001, 0.01))
    s.c2s(P.ssh_encrypted(52), think=0.3)
    s.s2c(P.ssh_encrypted(84), think=0.01)
    pk = s.close(by_client=False, think=0.02)
    return merged(pre, out, pk)


def icmp_ping(ctx: Ctx, src, dst, ts, count=4):
    out = ctx.arp_for(src, dst, ts)
    ident = rng.randint(1, 65535)
    for i in range(count):
        t = ts + i * 1.0
        dmac, smac, ttl = ctx.link.addr(src, dst, src)
        out.append((t, eth(dmac, smac, ETH_IP, ipv4(src, dst, 1, P.icmp_echo(ident, i + 1, True), ttl=ttl))))
        dmac, smac, ttl = ctx.link.addr(dst, src, src)
        out.append((t + rng.uniform(0.0004, 0.002), eth(dmac, smac, ETH_IP, ipv4(dst, src, 1, P.icmp_echo(ident, i + 1, False), ttl=ttl))))
    return merged(out)


# ====================================================== normal-day background noise
def dns_query_ext(ctx: Ctx, client, name, ts, qtype=P.DNS_A, answers=None, rcode=0):
    """A single external DNS lookup with an explicit qtype / rcode (A/AAAA/PTR/TXT/CNAME,
    NXDOMAIN=3, SERVFAIL=2). Adds realistic query-type and failure variety to the baseline."""
    return dns_lookup(ctx, client, name, ts, qtype=qtype, answers=answers, external=True, rcode=rcode)


def connectivity_check(ctx: Ctx, client, ts, host=None):
    """OS connectivity probe (Windows NCSI / Chrome / Apple), a tiny HTTP 200/204 to a CDN."""
    host = host or ("www.msftconnecttest.com" if ctx.is_windows(client) else "connectivitycheck.gstatic.com")
    srv = ctx.sites.get(host)
    if not srv:
        return []
    srv = srv[1]
    ua = "Microsoft NCSI" if ctx.is_windows(client) else P.UAS[9 % len(P.UAS)]
    pre = dns_lookup(ctx, client, host, ts, external=True, answers=[(P.DNS_A, srv.ipb)]) if rng.random() < 0.7 else []
    t = ts + rng.uniform(0.003, 0.02)
    out = ctx.arp_for(client, srv, t)
    s = ctx.tcp(client, srv, 80, t + 0.001).handshake()
    if ctx.is_windows(client):
        s.c2s(P.http_request("GET", "/connecttest.txt", host, ua), think=rng.uniform(0.001, 0.006))
        s.s2c(P.http_response("200 OK", b"Microsoft Connect Test", "text/plain", s.t, server="Microsoft-IIS/10.0"), think=rng.uniform(0.002, 0.02))
    else:
        s.c2s(P.http_request("GET", "/generate_204", host, ua), think=rng.uniform(0.001, 0.006))
        s.s2c(P.http_response("204 No Content", b"", "text/html", s.t, server="gws"), think=rng.uniform(0.002, 0.02))
    pk = s.close(by_client=True, think=rng.uniform(0.2, 2.0))
    return merged(pre, out, pk)


def ocsp_check(ctx: Ctx, client, ts, responder=None):
    """Certificate revocation check: HTTP OCSP request to a CA responder (real CAs use port 80)."""
    responder = responder or rng.choice([h for h in ("ocsp.digicert.com", "ocsp.sectigo.com", "ocsp.pki.goog", "crl.microsoft.com") if h in ctx.sites])
    if not responder:
        return []
    srv = ctx.sites[responder][1]
    ua = "Microsoft-CryptoAPI/10.0" if ctx.is_windows(client) else "com.apple.trustd/2.0"
    pre = dns_lookup(ctx, client, responder, ts, external=True, answers=[(P.DNS_A, srv.ipb)]) if rng.random() < 0.5 else []
    t = ts + rng.uniform(0.003, 0.02)
    out = ctx.arp_for(client, srv, t)
    s = ctx.tcp(client, srv, 80, t + 0.001).handshake()
    if "crl" in responder:                       # CRL: plain GET of a .crl blob (served as octet-stream)
        s.c2s(P.http_request("GET", "/pki/crl/products/%s.crl" % os.urandom(4).hex(), responder, ua), think=rng.uniform(0.001, 0.006))
        s.s2c(P.http_response("200 OK", P.blob(rng.randint(600, 4000)), "application/octet-stream", s.t, server="ECAcc"), think=rng.uniform(0.004, 0.03))
    else:                                        # OCSP: POST a well-formed DER ocsp-request
        req = P.ocsp_request()
        s.c2s(P.http_request("POST", "/", responder, ua, ["Content-Type: application/ocsp-request"], body=req), think=rng.uniform(0.001, 0.006))
        s.s2c(P.http_response("200 OK", P.ocsp_response(0), "application/ocsp-response", s.t, server="nginx"), think=rng.uniform(0.004, 0.03))
    pk = s.close(by_client=True, think=rng.uniform(0.2, 2.0))
    return merged(pre, out, pk)


# ========================================================== SMART BOARDS / MCP
# Baseline behaviour (not an incident module): every smart board polls its vendor's update
# service over HTTPS through the day. One board takes an update mid-morning and afterwards
# runs an MCP server, which is then driven over plaintext HTTP by workstations and the admin
# jump host, and keeps a link open to the vendor cloud.
MCP_BOARD = "SB-02"                     # the board that successfully updates (suffix; resolve with H())
MCP_UPDATE_HM = (10, 15)                # when it updates and starts serving
SB_VENDOR_UPDATES = "updates.luminaboard-cloud.net"
SB_VENDOR_CLOUD = "sync.luminaboard-cloud.net"
SB_FW_CURRENT, SB_FW_NEW = "2.3.11", "2.4.0"


def _sb_room(sb):
    return f"{get_current().name} Room {sb.name[-1]}"


def smartboard_update_check(ctx: Ctx, sb, ts, offer=False):
    """Periodic vendor update poll: HTTPS GET of a firmware manifest.

    Boards that are already current get 204 No Content; the one board that is offered an
    update gets a 200 with the manifest JSON. Ordinary, benign egress.
    """
    from .tls import TlsSession
    host, srv = ctx.sites[SB_VENDOR_UPDATES]
    ua = f"LuminaBoard/{SB_FW_CURRENT} (Android; {H('SB')})"
    pre = dns_lookup(ctx, sb, host, ts, external=True, answers=[(P.DNS_A, srv.ipb)])
    t = ts + rng.uniform(0.01, 0.06)
    out = ctx.arp_for(sb, srv, t)
    s = ctx.tcp(sb, srv, 443, t + 0.001).handshake()
    tls = TlsSession(ctx.pki, host, ctx.keylog, profile=getattr(sb, "tls_profile", "embedded"))
    for from_c, data in tls.handshake():
        (s.c2s if from_c else s.s2c)(data, think=rng.uniform(0.0008, 0.01))
    path = f"/api/v2/firmware/check?model={H('SB')}&serial={sb.name}&version={SB_FW_CURRENT}"
    req = P.http_request("GET", path, host, ua, ["Accept: application/json"])
    s.c2s(tls.app_data(True, req), think=rng.uniform(0.001, 0.005))
    if offer:
        body = P._json({"status": "update-available", "version": SB_FW_NEW,
                        "size": 48234112, "channel": "stable",
                        "url": f"https://{host}/dist/luminaboard-{SB_FW_NEW}.img",
                        "sha256": os.urandom(32).hex(),
                        "notes": "Adds local agent endpoint (Model Context Protocol) for room automation."})
        resp = P.http_response("200 OK", body, "application/json", s.t, server="nginx/1.26.2")
    else:
        resp = P.http_response("204 No Content", b"", "application/json", s.t, server="nginx/1.26.2")
    s.s2c(tls.app_data(False, resp), think=rng.uniform(0.03, 0.2))
    s.c2s(tls.close_notify(True), think=rng.uniform(0.2, 1.5))
    pk = s.close(think=0.002)
    return merged(pre, out, pk)


def smartboard_update_download(ctx: Ctx, sb, ts):
    """The board that accepted the update pulls the firmware image over HTTPS."""
    site = ctx.sites[SB_VENDOR_UPDATES]
    total = int(48_234_112 * max(0.05, min(1.0, ctx.scale)))
    parts = max(1, total // 4_000_000)
    return https_session(ctx, sb, site, ts, requests=parts, sizes=[total // parts] * parts,
                         keep_open=0.4, rate=60e6)


def smartboard_beacon(ctx: Ctx, sb, ts, mcp=False):
    """mDNS advertisement. After the update the board also advertises its MCP endpoint,
    which is how a client on the user subnet would discover it in the first place."""
    out = [(ts, udp_bcast(sb, 5353, 5353, P.mdns_response("_airplay._tcp.local", _sb_room(sb), sb.fqdn, 7000, sb.ipb), dst_ip=b"\xe0\x00\x00\xfb", dst_mac=mcast_mac(b"\xe0\x00\x00\xfb"), ttl=255))]
    if mcp:
        txt = P.txt_rdata([f"mcp={P.MCP_PROTOCOL_VERSION}", "transport=streamable-http",
                           f"path={P.MCP_ENDPOINT}", f"ver={SB_FW_NEW}"])
        out.append((ts + rng.uniform(0.02, 0.15),
                    udp_bcast(sb, 5353, 5353,
                              P.mdns_response("_mcp._tcp.local", _sb_room(sb) + " Agent", sb.fqdn,
                                              P.MCP_PORT, sb.ipb, txt=txt),
                              dst_ip=b"\xe0\x00\x00\xfb", dst_mac=mcast_mac(b"\xe0\x00\x00\xfb"), ttl=255)))
    return out


def _mcp_host(sb):
    return f"{sb.fqdn}:{P.MCP_PORT}"


def mcp_session(ctx: Ctx, client, sb, ts, calls=None, ua=None, stream_result=None):
    """One full MCP client session over the Streamable HTTP transport, plaintext HTTP.

    Follows the spec lifecycle exactly:
      POST initialize                     -> 200 application/json + Mcp-Session-Id
      POST notifications/initialized      -> 202 Accepted, no body
      POST tools/list                     -> 200 application/json
      POST tools/call                     -> 200 application/json, or an SSE stream whose
                                             last event carries the JSON-RPC response
      DELETE                              -> 204, explicit session termination
    Every request after initialize carries Mcp-Session-Id and MCP-Protocol-Version.
    """
    host = _mcp_host(sb)
    ua = ua or rng.choice(["mcp-client/1.2.0", "mcp-inspector/0.9.1", f"{get_current().assistant}/1.4"])
    sid = os.urandom(16).hex()
    calls = calls if calls is not None else rng.randint(1, 3)
    stream_result = rng.random() < 0.45 if stream_result is None else stream_result

    out = ctx.arp_for(client, sb, ts)
    s = ctx.tcp(client, sb, P.MCP_PORT, ts + 0.001).handshake()
    rid = 1

    # --- initialization. No MCP-Protocol-Version yet: nothing has been negotiated.
    s.c2s(P.mcp_post(host, P.mcp_initialize(rid), ua=ua, proto=False), think=rng.uniform(0.001, 0.006))
    s.s2c(P.mcp_json_response(P.mcp_initialize_result(rid), s.t, session_id=sid),
          think=rng.uniform(0.004, 0.03))
    rid += 1
    # a notification gets 202 Accepted with no body
    s.c2s(P.mcp_post(host, P.jsonrpc_notification("notifications/initialized"), session_id=sid, ua=ua),
          think=rng.uniform(0.001, 0.008))
    s.s2c(P.mcp_accepted(s.t), think=rng.uniform(0.001, 0.01))

    # --- discovery
    s.c2s(P.mcp_post(host, P.jsonrpc_request(rid, "tools/list", {}), session_id=sid, ua=ua),
          think=rng.uniform(0.01, 0.2))
    s.s2c(P.mcp_json_response(P.mcp_tools_list_result(rid), s.t), think=rng.uniform(0.004, 0.04))
    rid += 1

    # --- tool invocation
    for i in range(calls):
        name, args, reply = rng.choice([
            ("get_room_status", {},
             "Room: %s\nOccupancy: %d\nDisplay: on\nInput: HDMI-1" % (_sb_room(sb), rng.randint(0, 12))),
            ("display_message", {"text": rng.choice(["Meeting starts in 5 minutes",
                                                     "Room booked 14:00-15:00",
                                                     "Please tidy the whiteboard"]),
                                 "seconds": rng.choice([15, 30, 60])},
             "Message displayed."),
            ("list_scheduled_meetings", {"date": P.time.strftime("%Y-%m-%d", P.time.localtime(ts))},
             "3 meetings: 09:00 Standup, 11:00 Freight review, 14:00 Carrier sync"),
            ("capture_whiteboard", {"format": "png"},
             "Captured whiteboard: 1920x1080 png, 412 KB"),
        ])
        s.c2s(P.mcp_post(host, P.mcp_tool_call(rid, name, args), session_id=sid, ua=ua),
              think=rng.uniform(0.3, 8.0))
        if stream_result and i == 0:
            # server upgrades to SSE: progress notifications, then the response, then closes
            s.s2c(P.mcp_sse_headers(s.t, session_id=sid), think=rng.uniform(0.003, 0.02))
            for k in range(rng.randint(1, 3)):
                s.s2c(P.mcp_sse_event(P.jsonrpc_notification(
                    "notifications/progress",
                    {"progressToken": rid, "progress": (k + 1) * 30, "total": 100}), event_id=k + 1),
                    think=rng.uniform(0.08, 0.5))
            s.s2c(P.mcp_sse_event(P.mcp_tool_result(rid, reply), event_id=9),
                  think=rng.uniform(0.05, 0.3))
        else:
            s.s2c(P.mcp_json_response(P.mcp_tool_result(rid, reply), s.t),
                  think=rng.uniform(0.02, 0.4))
        rid += 1

    # --- explicit session termination
    s.c2s(P.mcp_delete(host, sid, ua=ua), think=rng.uniform(0.2, 3.0))
    s.s2c(P.http_response("204 No Content", b"", "application/json", s.t,
                          server="luminaboard-mcp/2.4.0"), think=rng.uniform(0.002, 0.02))
    pk = s.close(think=rng.uniform(0.05, 0.6))
    return merged(out, pk)


def mcp_sse_listen(ctx: Ctx, client, sb, ts, minutes=None, ua=None):
    """A long-lived server-to-client SSE stream: GET /mcp held open, with periodic
    server-initiated notifications and SSE keepalive comments. This is the shape that makes
    an MCP server obvious on the wire — a persistent HTTP connection carrying text/event-stream."""
    host = _mcp_host(sb)
    ua = ua or "mcp-client/1.2.0"
    sid = os.urandom(16).hex()
    minutes = minutes or rng.uniform(8, 25)

    out = ctx.arp_for(client, sb, ts)
    s = ctx.tcp(client, sb, P.MCP_PORT, ts + 0.001).handshake()
    # a stream is opened against an established session, so initialize first
    s.c2s(P.mcp_post(host, P.mcp_initialize(1), ua=ua, proto=False), think=rng.uniform(0.001, 0.006))
    s.s2c(P.mcp_json_response(P.mcp_initialize_result(1), s.t, session_id=sid), think=rng.uniform(0.004, 0.03))
    s.c2s(P.mcp_post(host, P.jsonrpc_notification("notifications/initialized"), session_id=sid, ua=ua),
          think=rng.uniform(0.001, 0.008))
    s.s2c(P.mcp_accepted(s.t), think=rng.uniform(0.001, 0.01))

    s.c2s(P.mcp_get_stream(host, sid, ua=ua), think=rng.uniform(0.01, 0.1))
    s.s2c(P.mcp_sse_headers(s.t, session_id=sid), think=rng.uniform(0.003, 0.02))

    end = ts + minutes * 60
    eid = 0
    while s.t < end:
        gap = rng.uniform(12, 45)
        if s.t + gap >= end:
            break
        s.idle(gap)
        eid += 1
        if rng.random() < 0.35:
            s.s2c(P.mcp_sse_comment(), think=0.0)          # keepalive comment
        else:
            note = rng.choice([
                P.jsonrpc_notification("notifications/tools/list_changed"),
                P.jsonrpc_notification("notifications/resources/updated",
                                       {"uri": f"room://{sb.name.lower()}/whiteboard"}),
                P.jsonrpc_notification("notifications/message",
                                       {"level": "info", "logger": "room-agent",
                                        "data": rng.choice(["display woke", "input switched to HDMI-1",
                                                            "occupancy sensor updated"])}),
            ])
            s.s2c(P.mcp_sse_event(note, event_id=eid), think=0.0)
    s.c2s(P.mcp_delete(host, sid, ua=ua), think=rng.uniform(0.1, 1.0))
    s.s2c(P.http_response("204 No Content", b"", "application/json", s.t,
                          server="luminaboard-mcp/2.4.0"), think=rng.uniform(0.002, 0.02))
    pk = s.close(think=rng.uniform(0.05, 0.4))
    return merged(out, pk)


def smartboard_cloud_link(ctx: Ctx, sb, ts):
    """After updating, the board keeps a link to the vendor cloud: HTTPS telemetry plus a
    relay poll for remotely-issued agent work. Outbound only — the firewall NATs egress."""
    from .tls import TlsSession
    host, srv = ctx.sites[SB_VENDOR_CLOUD]
    ua = f"LuminaBoard/{SB_FW_NEW} (Android; agent)"
    pre = dns_lookup(ctx, sb, host, ts, external=True, answers=[(P.DNS_A, srv.ipb)]) if rng.random() < 0.5 else []
    t = ts + rng.uniform(0.01, 0.05)
    out = ctx.arp_for(sb, srv, t)
    s = ctx.tcp(sb, srv, 443, t + 0.001).handshake()
    tls = TlsSession(ctx.pki, host, ctx.keylog, profile=getattr(sb, "tls_profile", "embedded"))
    for from_c, data in tls.handshake():
        (s.c2s if from_c else s.s2c)(data, think=rng.uniform(0.0008, 0.01))
    body = P._json({"device": sb.name, "version": SB_FW_NEW, "agent": "mcp",
                    "protocolVersion": P.MCP_PROTOCOL_VERSION,
                    "uptime_s": rng.randint(600, 36000),
                    "sessions": rng.randint(0, 6), "tools": len(P.MCP_TOOLS)})
    req = P.http_request("POST", "/api/v1/agent/heartbeat", host, ua,
                         ["Content-Type: application/json"], body=body)
    s.c2s(tls.app_data(True, req), think=rng.uniform(0.001, 0.006))
    resp = P.http_response("200 OK", P._json({"ack": True, "pending": 0}), "application/json",
                           s.t, server="nginx/1.26.2")
    s.s2c(tls.app_data(False, resp), think=rng.uniform(0.03, 0.25))
    s.c2s(tls.close_notify(True), think=rng.uniform(0.3, 2.0))
    pk = s.close(think=0.002)
    return merged(pre, out, pk)


# ============================================================ OT / ICS (Purdue levels 0-3.5)
# The cell/area zone is packet-dense and byte-light: a Modbus poll is ~66 bytes of request and
# ~83 of response on a connection that stays open all day. That is the opposite of the
# enterprise, and it is the single most characteristic thing about process traffic.
#
# One session per HMI/PLC pair, opened once and reused. Do NOT open a connection per poll:
# real supervisory software holds the socket, and a handshake every two seconds would treble
# the packet count and invent a connection-churn signal that no real plant shows.

def modbus_poll_block(ctx: Ctx, client, plc, ts, n_polls=1, period=2.0, unit=1, start=0):
    """One long-lived Modbus/TCP connection carrying `n_polls` polls `period` apart.

    Above roughly 500 ms the client's 200 ms delayed-ACK timer fires before the next request,
    so each transaction is three frames (req, rsp, ack) rather than two. That is why the
    budgeting model uses three, and it is what the session below actually emits.

    start: the register map's base address. Left at 0 (every ordinary caller), this is the
    baseline poll's own fixed map; a caller probing registers the baseline never touches (a
    recon read, say) passes its own base so the request itself -- not just the source -- reads
    differently from a legitimate poll.
    """
    out = ctx.arp_for(client, plc, ts)
    s = ctx.tcp(client, plc, P.MODBUS_PORT, ts + 0.0008).handshake()
    pk = []
    tid = rng.randrange(1, 4096)
    for i in range(n_polls):
        s.at(ts + i * period)
        tid = (tid + 1) & 0xFFFF
        # The register map is fixed per PLC, which is what makes the traffic modellable as a
        # DFA in the literature -- the same request repeating on a fixed cadence.
        func = P.MB_READ_HOLDING if i % 4 else P.MB_READ_INPUT
        count = 10 if func == P.MB_READ_HOLDING else 8
        s.c2s(P.modbus_read_req(tid, unit, func, start, count), think=0.0002)
        # A small, steady fraction of polls hit a register the map does not cover. The platform
        # reports these under Response Errors by Error, so the baseline needs some.
        if rng.random() < 0.004:
            s.s2c(P.modbus_exception(tid, unit, func, P.MB_EX_ILLEGAL_ADDR),
                  think=rng.uniform(0.0006, 0.004))
        else:
            s.s2c(P.modbus_read_rsp(tid, unit, func, count), think=rng.uniform(0.0006, 0.004))
    pk += s.drain()
    return merged(out, pk)


def modbus_setpoint_write(ctx: Ctx, client, plc, ts, unit=1, mix=False, targets=None):
    """An operator changing a setpoint: a short connection, one write, echoed back.

    mix=False (default, every other caller): always FC6, a fresh random register each time --
    unchanged. mix=True: mostly FC6, with FC16 (multi-register) and FC5 (coil) writes in a
    minority of sessions and an occasional exception reply for an out-of-range value -- the real
    function-code variety a setpoint tamper shows, not a single repeated write shape.
    targets: a small, reused register pool (2-4 addresses) instead of a fresh uniform-random
    one each time, so the same register gets written repeatedly, as a real tamper would."""
    out = ctx.arp_for(client, plc, ts)
    s = ctx.tcp(client, plc, P.MODBUS_PORT, ts + 0.001).handshake()
    tid = rng.randrange(1, 4096)
    addr = rng.choice(targets) if targets else rng.randrange(40, 80)
    val = rng.randrange(100, 900)
    roll = rng.random() if mix else 0.0
    if not mix or roll < 0.7:
        s.c2s(P.modbus_write_reg_req(tid, unit, addr, val), think=0.0003)
        if mix and rng.random() < 0.03:
            s.s2c(P.modbus_exception(tid, unit, P.MB_WRITE_REG, P.MB_EX_ILLEGAL_VALUE), think=rng.uniform(0.001, 0.005))
        else:
            s.s2c(P.modbus_write_reg_rsp(tid, unit, addr, val), think=rng.uniform(0.001, 0.005))
    elif roll < 0.85:
        n = rng.randint(2, 4)
        values = [rng.randrange(100, 900) for _ in range(n)]
        s.c2s(P.modbus_write_regs_req(tid, unit, addr, values), think=0.0003)
        s.s2c(P.modbus_write_regs_rsp(tid, unit, addr, n), think=rng.uniform(0.001, 0.005))
    else:
        coil = rng.randrange(0, 20)
        on = rng.random() < 0.5
        s.c2s(P.modbus_write_coil_req(tid, unit, coil, on), think=0.0003)
        s.s2c(P.modbus_write_coil_rsp(tid, unit, coil, on), think=rng.uniform(0.001, 0.005))
    return merged(out, s.close(think=0.002))


def dnp3_poll_block(ctx: Ctx, master, rtu, ts, n_polls=1, period=10.0, dest=4, src=3):
    """DNP3 integrity polls from a SCADA master to an RTU, on one long-lived connection."""
    out = ctx.arp_for(master, rtu, ts)
    s = ctx.tcp(master, rtu, P.DNP3_PORT, ts + 0.0008).handshake()
    seq = rng.randrange(16)
    for i in range(n_polls):
        s.at(ts + i * period)
        seq = (seq + 1) & 0x0F
        s.c2s(P.dnp3_read_req(seq, dest, src), think=0.0003)
        s.s2c(P.dnp3_response(seq, src, dest, count=8), think=rng.uniform(0.002, 0.012))
        # Unsolicited responses are what DNP3 is for -- the RTU reporting a change of state
        # without being asked. They arrive between polls, not in answer to one.
        if rng.random() < 0.02:
            s.at(ts + i * period + rng.uniform(0.2, 0.8))
            s.s2c(P.dnp3_unsolicited((seq + 1) & 0x0F, src, dest), think=0.0005)
    return merged(out, s.drain())


def bacnet_cov_burst(ctx: Ctx, dev, controller, ts, dev_instance=1):
    """Unconfirmed change-of-value: one datagram, no reply, broadcast NPDU. The bulk of a
    quiet building-management system, and the reason BACnet is byte-light."""
    val = rng.uniform(15.0, 26.0)
    return [ctx.udp(dev, controller, P.BACNET_PORT, P.BACNET_PORT,
                    P.bacnet_cov_notification(rng.randrange(1, 40), dev_instance,
                                              P.BAC_OBJ_ANALOG_INPUT, dev_instance, val),
                    ts, vantage=dev)]


def bacnet_read_exchange(ctx: Ctx, controller, dev, ts, dev_instance=1):
    """Confirmed readProperty and its ComplexACK, with the occasional error and reject so the
    APDU breakdown the platform reports is not a single flat category."""
    out = ctx.arp_for(controller, dev, ts)
    inv = rng.randrange(1, 255)
    out.append(ctx.udp(controller, dev, P.BACNET_PORT, P.BACNET_PORT,
                       P.bacnet_read_property_req(inv, P.BAC_OBJ_ANALOG_INPUT, dev_instance),
                       ts, vantage=controller))
    rt = ts + rng.uniform(0.004, 0.030)
    r = rng.random()
    if r < 0.012:
        pdu = P.bacnet_error(inv)
    elif r < 0.018:
        pdu = P.bacnet_reject(inv)
    elif r < 0.020:
        pdu = P.bacnet_abort(inv)
    else:
        pdu = P.bacnet_complex_ack(inv, P.BAC_OBJ_ANALOG_INPUT, dev_instance,
                                   rng.uniform(15.0, 26.0))
    out.append(ctx.udp(dev, controller, P.BACNET_PORT, P.BACNET_PORT, pdu, rt, vantage=controller))
    return merged(out)


def bacnet_write_exchange(ctx: Ctx, controller, dev, ts, dev_instance=1):
    """A setpoint written down to a field device, answered with a SimpleACK."""
    out = ctx.arp_for(controller, dev, ts)
    inv = rng.randrange(1, 255)
    out.append(ctx.udp(controller, dev, P.BACNET_PORT, P.BACNET_PORT,
                       P.bacnet_write_property_req(inv, P.BAC_OBJ_ANALOG_VALUE, dev_instance,
                                                   rng.uniform(18.0, 23.0)),
                       ts, vantage=controller))
    out.append(ctx.udp(dev, controller, P.BACNET_PORT, P.BACNET_PORT, P.bacnet_simple_ack(inv),
                       ts + rng.uniform(0.005, 0.040), vantage=controller))
    return merged(out)


# ============================================================ OT process protocols (ported 2026-10)
# EtherNet/IP, S7comm, OPC UA, synchrophasor and ICCP/TASE.2. Emitted only by the Day.ot_* methods
# for protocols selected through Day(ot_protocols=...), so the default build never calls these.
# Same framing discipline as the Modbus/DNP3/BACnet builders above.
def enip_session(ctx: Ctx, scanner, plc, ts, n_reads=1, period=1.0, tags=None):
    """EtherNet/IP explicit messaging (TCP 44818): RegisterSession, then periodic CIP Read Tag on
    one connection. The session handle is echoed and the tag names ride on the wire."""
    tags = tags or ["Line_Flow", "Tank_Level", "Motor_RPM", "Valve_Pos", "Batch_Count"]
    out = ctx.arp_for(scanner, plc, ts)
    s = ctx.tcp(scanner, plc, P.ENIP_PORT, ts + 0.0008).handshake()
    session = rng.randrange(0x10000, 0x7FFFFFFF)
    s.c2s(P.enip_register_session(0), think=0.0003)
    s.s2c(P.enip_register_session_rsp(session), think=rng.uniform(0.0006, 0.004))
    for i in range(n_reads):
        s.at(ts + i * period)
        s.c2s(P.enip_send_rr_data(session, P.cip_read_tag(tags[i % len(tags)])), think=0.0003)
        s.s2c(P.enip_send_rr_data(session, P.cip_read_tag_rsp(4)), think=rng.uniform(0.0006, 0.005))
    return merged(out, s.drain())


def enip_io(ctx: Ctx, producer, consumer, ts, n=1, period=0.5):
    """EtherNet/IP implicit (Class 1) cyclic I/O over UDP 2222 -- producer -> consumer, no reply."""
    out = ctx.arp_for(producer, consumer, ts)
    seq = rng.randrange(0x10000)
    for i in range(n):
        seq = (seq + 1) & 0xFFFF
        out.append(ctx.udp(producer, consumer, P.ENIP_IO_PORT, P.ENIP_IO_PORT,
                           P.enip_io_data(seq, 16), ts + i * period, vantage=producer))
    return merged(out)


def s7comm_session(ctx: Ctx, client, plc, ts, n_reads=1, period=1.0, writes=0):
    """Siemens S7comm (TCP 102): COTP connection, S7 setup-communication, then periodic Read Var
    (and optional Write Var) on one long-lived connection."""
    out = ctx.arp_for(client, plc, ts)
    s = ctx.tcp(client, plc, P.ISO_TSAP_PORT, ts + 0.0008).handshake()
    s.c2s(P.cotp_cr(), think=0.0004)
    s.s2c(P.cotp_cc(), think=rng.uniform(0.0008, 0.004))
    ref = rng.randrange(1, 0xFFFF)
    s.c2s(P.s7_setup_comm(ref), think=0.0004)
    s.s2c(P.s7_setup_comm_rsp(ref), think=rng.uniform(0.0008, 0.004))
    for i in range(n_reads):
        s.at(ts + i * period)
        ref = (ref + 1) & 0xFFFF
        s.c2s(P.s7_read_req(ref, db=(i % 4) + 1, start=0, length=16), think=0.0003)
        s.s2c(P.s7_read_rsp(ref, length=16), think=rng.uniform(0.0006, 0.005))
    for _ in range(writes):
        ref = (ref + 1) & 0xFFFF
        s.c2s(P.s7_write_req(ref, db=1, start=rng.randrange(0, 40),
                             values=rng.randrange(65536).to_bytes(2, "big")), think=0.0004)
        s.s2c(P.s7_write_rsp(ref), think=rng.uniform(0.0008, 0.004))
    return merged(out, s.drain())


def opcua_session(ctx: Ctx, client, server, ts, n_reads=1, period=1.0):
    """OPC UA binary (TCP 4840): Hello/Ack, OpenSecureChannel, Create/ActivateSession, then
    periodic Read/Browse/Publish service calls, closed at the end of the block."""
    out = ctx.arp_for(client, server, ts)
    s = ctx.tcp(client, server, P.OPCUA_PORT, ts + 0.0008).handshake()
    s.c2s(P.opcua_hello("opc.tcp://%s:%d" % (server.fqdn or server.ip, P.OPCUA_PORT)), think=0.0004)
    s.s2c(P.opcua_ack(), think=rng.uniform(0.0008, 0.004))
    s.c2s(P.opcua_open_secure_channel(), think=0.0004)
    s.s2c(P.opcua_open_secure_channel_rsp(), think=rng.uniform(0.001, 0.005))
    chan, tok, seq = rng.randrange(1, 1 << 30), rng.randrange(1, 1 << 30), 1
    svcs = ["CreateSession", "ActivateSession"]
    for i in range(max(n_reads, 2)):
        s.at(ts + i * period)
        svc = svcs[i] if i < len(svcs) else rng.choice(["Read", "Browse", "Publish"])
        s.c2s(P.opcua_service(chan, tok, seq, seq, svc), think=0.0004)
        seq += 1
        s.s2c(P.opcua_service(chan, tok, seq, seq, svc), think=rng.uniform(0.001, 0.006))
        seq += 1
    return merged(out, s.close(think=0.003))


def c37118_stream(ctx: Ctx, pmu, pdc, ts, seconds=2.0, fps=30):
    """Synchrophasor IEEE C37.118.2: the PDC opens the TCP/4712 command channel (send CFG-2, then
    data ON), and the PMU streams CRC-checked data frames over UDP/4713 at `fps`."""
    out = ctx.arp_for(pdc, pmu, ts)
    idcode = 1 + (sum(pmu.ipb) % 60000)
    soc = int(ts)
    s = ctx.tcp(pdc, pmu, P.C37118_CMD_PORT, ts + 0.0008).handshake()
    s.c2s(P.c37118_command(idcode, soc, cmd=4), think=0.0004)              # send CFG-2
    s.s2c(P.c37118_config2(idcode, soc, station=pmu.name), think=rng.uniform(0.001, 0.006))
    s.c2s(P.c37118_command(idcode, soc, cmd=2), think=0.0004)              # data ON
    cmd_pk = s.drain()
    n = max(1, int(seconds * fps * min(1.0, max(0.05, getattr(ctx, "scale", 1.0)))))
    sport = pmu.eph()
    data = [ctx.udp(pmu, pdc, sport, P.C37118_DATA_PORT,
                    P.c37118_data(idcode, soc + i // fps, int((i % fps) / fps * 1_000_000)),
                    ts + 0.05 + i / float(fps), vantage=pdc) for i in range(n)]
    return merged(out, cmd_pk, data)


def iccp_session(ctx: Ctx, local, remote, ts, n=1, period=4.0):
    """ICCP/TASE.2 (MMS over TCP 102): COTP setup, MMS Initiate, then periodic Read plus
    unsolicited InformationReports between control centres (by-exception data transfer)."""
    out = ctx.arp_for(local, remote, ts)
    s = ctx.tcp(local, remote, P.ISO_TSAP_PORT, ts + 0.0008).handshake()
    s.c2s(P.cotp_cr(), think=0.0004)
    s.s2c(P.cotp_cc(), think=rng.uniform(0.001, 0.005))
    s.c2s(P.mms_initiate_req(), think=0.0006)
    s.s2c(P.mms_initiate_rsp(), think=rng.uniform(0.002, 0.01))
    inv = rng.randrange(1, 1000)
    for i in range(n):
        s.at(ts + i * period)
        inv = (inv + 1) & 0xFFFF
        s.c2s(P.mms_read_req(inv, var=rng.choice(["MeasuredValueF_1", "StatusValue_3", "Transfer_Set_1"])),
              think=0.0006)
        s.s2c(P.mms_read_rsp(inv, value=rng.randrange(100000)), think=rng.uniform(0.002, 0.01))
        if rng.random() < 0.5:
            s.s2c(P.mms_information_report(var=rng.choice(["Transfer_Set_1", "Alarm_Set_2"])),
                  think=rng.uniform(0.01, 0.1))
    return merged(out, s.drain())


# ============================================================ SMTP / RADIUS / NFS (Phase 3 CUSTOM)
# Added so custom-import can reconstruct the three the platform record types the engine previously had
# no builder for (~smtp, ~aaa_request/response, ~nfs). Scenario-only; not part of the baseline day.
def smtp_session(ctx: Ctx, client, server, ts, sender=None, rcpts=None, subject="Daily status"):
    """One cleartext SMTP submission: EHLO, MAIL FROM, RCPT TO, DATA, QUIT. Everything a hardening
    view reads -- envelope, headers, body -- is on the wire; the engine does not do STARTTLS here."""
    out = ctx.arp_for(client, server, ts)
    s = ctx.tcp(client, server, 25, ts + 0.001).handshake()
    srv = server.name.lower()
    hn = client.name.lower()
    sender = sender or ("%s@%s" % (P.username_for(client.name), P.DOMAIN))
    rcpts = rcpts or ["helpdesk@%s" % P.DOMAIN]
    s.s2c(b"220 %s ESMTP Postfix\r\n" % srv.encode(), think=rng.uniform(0.02, 0.08))
    s.c2s(b"EHLO %s\r\n" % hn.encode(), think=rng.uniform(0.03, 0.12))
    s.s2c(b"250-%s\r\n250-PIPELINING\r\n250-SIZE 20480000\r\n250-8BITMIME\r\n250 HELP\r\n" % srv.encode(),
          think=rng.uniform(0.01, 0.04))
    s.c2s(b"MAIL FROM:<%s>\r\n" % sender.encode(), think=rng.uniform(0.02, 0.1))
    s.s2c(b"250 2.1.0 Ok\r\n", think=rng.uniform(0.01, 0.03))
    for r in rcpts:
        s.c2s(b"RCPT TO:<%s>\r\n" % r.encode(), think=rng.uniform(0.02, 0.08))
        s.s2c(b"250 2.1.5 Ok\r\n", think=rng.uniform(0.01, 0.03))
    s.c2s(b"DATA\r\n", think=rng.uniform(0.02, 0.06))
    s.s2c(b"354 End data with <CR><LF>.<CR><LF>\r\n", think=rng.uniform(0.01, 0.03))
    body = (("From: <%s>\r\nTo: <%s>\r\nSubject: %s\r\n"
             "Date: Mon, 14 Sep 2026 09:00:00 -0400\r\nMIME-Version: 1.0\r\n"
             "Content-Type: text/plain; charset=utf-8\r\n\r\n"
             % (sender, rcpts[0], subject)).encode()
            + P.blob(rng.randint(400, 2400)).hex().encode()[:rng.randint(300, 1500)]
            + b"\r\n.\r\n")
    s.c2s(body, think=rng.uniform(0.03, 0.15))
    s.s2c(b"250 2.0.0 Ok: queued as %010X\r\n" % rng.getrandbits(40), think=rng.uniform(0.02, 0.06))
    s.c2s(b"QUIT\r\n", think=rng.uniform(0.03, 0.1))
    s.s2c(b"221 2.0.0 Bye\r\n", think=rng.uniform(0.01, 0.03))
    return merged(out, s.close(think=rng.uniform(0.01, 0.04)))


def radius_auth(ctx: Ctx, client, ts, server=None, user=None, port_type=19):
    """A supplicant authenticating through a NAS: Access-Request then Access-Accept over UDP 1812."""
    srv = server or ctx.h[H("DC1")]
    user = user or P.username_for(client.name)
    out = ctx.arp_for(client, srv, ts)
    sport = client.eph()
    ident = rng.randint(0, 255)
    mac = "-".join("%02X" % b for b in client.mac)
    req, auth = P.radius_access_request(ident, user, client.ipb, calling_id=mac, nas_port_type=port_type)
    out.append(ctx.udp(client, srv, sport, 1812, req, ts))
    accept_attrs = P.radius_attr(6, (2).to_bytes(4, "big")) + P.radius_attr(7, (1).to_bytes(4, "big"))
    resp = P.radius_response(2, ident, auth, attrs=accept_attrs)
    out.append(ctx.udp(srv, client, 1812, sport, resp, ts + rng.uniform(0.003, 0.02), vantage=client))
    return merged(out)


def nfs_session(ctx: Ctx, client, server, ts, filename="report.xlsx"):
    """An NFSv3 read over TCP 2049: NULL, FSINFO, GETATTR, LOOKUP, ACCESS, READ. One RPC call per
    segment, each paired with its reply by xid so the dissector resolves the procedure."""
    out = ctx.arp_for(client, server, ts)
    s = ctx.tcp(client, server, 2049, ts + 0.001).handshake()
    uid = 10000 + (int(client.name[-2:]) if client.name[-2:].isdigit() else 1)
    cred = P.rpc_auth_unix(client.name.lower(), uid=uid, gid=10000)
    fh_root = bytes(rng.getrandbits(8) for _ in range(32))
    fh_file = bytes(rng.getrandbits(8) for _ in range(32))
    xid = [rng.getrandbits(32)]

    def exch(proc, args, results, tc=0.01, tr=0.005):
        xid[0] = (xid[0] + 1) & 0xFFFFFFFF
        s.c2s(P.rpc_call(xid[0], 100003, 3, proc, cred=cred, args=args), think=rng.uniform(0.004, tc))
        s.s2c(P.rpc_reply(xid[0], results), think=rng.uniform(0.002, tr))

    FALSE = b"\x00\x00\x00\x00"                      # post_op_attr: attributes_follow = FALSE
    OK = b"\x00\x00\x00\x00"                         # nfsstat3 NFS3_OK
    exch(0, b"", b"")                                                        # NULL
    exch(19, P.xdr_opaque(fh_root), P.nfs3_fsinfo())                        # FSINFO
    exch(1, P.xdr_opaque(fh_root), OK + P.nfs3_fattr3(is_dir=True))         # GETATTR (dir)
    exch(3, P.xdr_opaque(fh_root) + P.xdr_str(filename),                    # LOOKUP
         OK + P.xdr_opaque(fh_file) + FALSE + FALSE)
    exch(4, P.xdr_opaque(fh_file) + (0x2000003).to_bytes(4, "big"),         # ACCESS (read|lookup)
         OK + FALSE + (0x1F).to_bytes(4, "big"))
    data = P.blob(rng.randint(2048, 8192))
    exch(6, P.xdr_opaque(fh_file) + (0).to_bytes(8, "big") + len(data).to_bytes(4, "big"),  # READ
         OK + FALSE + len(data).to_bytes(4, "big") + (1).to_bytes(4, "big") + P.xdr_opaque(data),
         tc=0.02, tr=0.02)
    return merged(out, s.close(think=rng.uniform(0.01, 0.04)))
