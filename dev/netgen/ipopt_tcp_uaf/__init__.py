"""netgen.ipopt_tcp_uaf -- the "Linux IPv4 TCP use-after-free race" incident-replay scenario
(CVE-2026-98432; Akamai Security Research analysis, Red Hat RHSB-2026-016).

A connection request (SYN) that carries IPv4 options (Record Route, Timestamp) is saved with the
request socket and reused to build the SYN-ACK; a retransmission of the same SYN races it. Two
internet sources spray one Linux host each for about 50 minutes: the plain TCP listener (EXL-LNX1,
tcp/8443) never gives up a completed handshake; the Go MPTCP listener (EXL-LNX2, tcp/9000) loses
one race, leaks bytes in the SYN-ACK, takes one payload and calls back out.

Wire facts SOURCED: options on the SYN plus a retransmit of the same SYN; IPv4 only; Linux; MPTCP
not required, but the exploit targeted an MPTCP listener. Everything else is ASSUMED and the page
says so: the SYN retransmit gap (200 to 500 ms, a custom tool, not a stock stack), the attacker's
kernel resetting each unsolicited SYN-ACK (raw-socket tooling), the attempt rate, the leak (three
8-byte kernel-address-shaped values inside the IP options area of the winning SYN-ACK), the
payload and the callback. Options are assumed to pass transit routers.

A failed attempt is five packets: SYN, SYN-ACK (stored options echoed, RFC 791 fields filled in),
the SAME SYN (same source port and ISN) 200-500 ms later, SYN-ACK, RST from the attacker. The first
SYN-ACK is NOT reset (ASSUMED: a reset would delete the request socket the race needs, so the tool's
host is taken to hold it back; only the SYN-ACK that ends the attempt is reset). No third ACK, so the
plain target has zero completed handshakes from its attacker.

PIN-SAFE: every host is injected into ``ctx.h`` INSIDE ``build()``; a build that does not select
this scenario is byte-for-byte the baseline. Hosts: EXL-LNX1 10.10.20.45, EXL-LNX2 10.10.20.46.
"""
import struct

from netgen import flows as F
from netgen.identity import H, get_current
from netgen import protocols as P
from netgen.core import Host, SYN, ACK, RST

from netgen.netscaler import _host

rng = F.rng

_LNX1_SUFFIX, _LNX1_IP, _LNX1_MAC, _LNX1_PORT = "LNX1", "10.10.20.45", "00:50:56:bb:0a:45", 8443
_LNX2_SUFFIX, _LNX2_IP, _LNX2_MAC, _LNX2_PORT = "LNX2", "10.10.20.46", "00:50:56:bb:0a:46", 9000
_CALLBACK_PORT = 38271                      # ASSUMED high port the attacker listens on

# RFC 5737 documentation ranges only; none of these is used by another scenario.
_EXTERNAL = {
    "att1": ("scan140.edge-sweep.example", "203.0.113.140", 10),     # sprays EXL-LNX1 (plain listener)
    "att2": ("scan141.edge-sweep.example", "203.0.113.141", 12),     # sprays EXL-LNX2 (MPTCP listener), wins
    "scanner": ("survey142.netcensus.example", "203.0.113.142", 9),  # one-off benign scanner (Timestamp option, no retry)
    "partner": ("gw.partner-co.example", "198.51.100.171", 8),       # partner client, negotiates MP_CAPABLE normally
}

# (Record Route slots, Timestamp slots): option bytes 15, 19, 19 -> padded 16, 20, 20 -> ip.hdr_len 36, 40, 40
_VARIANTS = ((1, 1), (2, 1), (1, 2))
_RETX_GAP = (0.20, 0.50)                    # ASSUMED, custom attack tool
_SPRAY_S = 3000.0                           # about 50 minutes of spray per target
_BURST_EVERY = (8.0, 14.0)
_BURST_N = (8, 16)                          # attempts per burst at scale 1.0 (about 3 per second inside a burst)
_BURST_SPAN = 3.0


def _inject_hosts(ctx):
    """Add EXL-LNX1, EXL-LNX2 and the external actors. Pin-safe: runs only in build()."""
    domain = P.DOMAIN
    n1, n2 = _host(ctx, _LNX1_SUFFIX), _host(ctx, _LNX2_SUFFIX)
    if n1 not in ctx.h:
        ctx.h[n1] = Host(n1, ctx.link.place(_LNX1_IP), _LNX1_MAC, "linux", "Published API service (plain TCP listener)",
                         ctx.link.server_net, "lnx1." + domain)
    if n2 not in ctx.h:
        ctx.h[n2] = Host(n2, ctx.link.place(_LNX2_IP), _LNX2_MAC, "linux", "Go service with an MPTCP listener",
                         ctx.link.server_net, "lnx2." + domain)
    cache = ctx.__dict__.setdefault("_ipu_ext", {})
    for key, (fqdn, ip, hops) in _EXTERNAL.items():
        if key not in cache:
            h = Host(fqdn.split(".")[0].upper(), ip, "02:00:5e:%02x:%02x:%02x" % tuple(rng.randrange(256) for _ in range(3)),
                     "linux", "external", ip.rsplit(".", 1)[0] + ".0/24", fqdn)
            h.hops = hops
            cache[key] = h
    return cache


# ================================================================================ option bytes
def _syn_ipopts(var):
    """Record Route (kind 7, empty slots, pointer 4) then Timestamp (kind 68, flag 0, pointer 5)."""
    a, b = var
    return bytes([7, 3 + 4 * a, 4]) + b"\0" * (4 * a) + bytes([68, 4 + 4 * b, 5, 0]) + b"\0" * (4 * b)


def _echo_ipopts(var, srv_ip, tsms):
    """What the kernel builds from the stored options for the SYN-ACK: the server's address in the first
    Record Route slot (pointer 8) and a millisecond-of-UTC-day stamp in the first Timestamp slot (pointer 9)."""
    a, b = var
    rr = bytes([7, 3 + 4 * a, 8]) + srv_ip + b"\0" * (4 * (a - 1))
    ts = bytes([68, 4 + 4 * b, 9, 0]) + struct.pack("!I", tsms & 0xFFFFFFFF) + b"\0" * (4 * (b - 1))
    return rr + ts


def _leak_ipopts(srv_ip, tsms):
    """ASSUMED leak: the winning SYN-ACK's Record Route option is longer than the stored one (len 31) and its
    slots after the server's address hold three 8-byte little-endian values with kernel-address-shaped high
    bytes (two direct-map heap pointers and one kernel-text pointer). 31 + 8 bytes of Timestamp = 39 -> 40."""
    heap1 = 0xFFFF888000000000 | (rng.getrandbits(32) << 4 & 0x0FFFFFFFF0)
    text = 0xFFFFFFFF81000000 | (rng.getrandbits(23) & 0x7FFFF0)
    heap2 = 0xFFFF888000000000 | (rng.getrandbits(32) << 4 & 0x0FFFFFFFF0)
    rr = bytes([7, 31, 8]) + srv_ip + struct.pack("<QQQ", heap1, text, heap2)
    ts = bytes([68, 8, 9, 0]) + struct.pack("!I", tsms & 0xFFFFFFFF)
    return rr + ts


def _tsms(t):
    return int((t % 86400.0) * 1000)


def _mp_syn(key):        # MP_CAPABLE (kind 30, len 12, subtype 0 / version 1, flags H) with the sender key
    return b"\x1e\x0c\x01\x01" + key


def _mp_ack(kc, ks):     # MP_CAPABLE on the third ACK (len 20): both keys
    return b"\x1e\x14\x01\x01" + kc + ks


def _key():
    return rng.getrandbits(64).to_bytes(8, "big")


def _syn_tcpopts(mss, tsval, mp=b""):       # Linux client SYN: MSS, SACK-permitted, timestamps, NOP, window scale 7
    return struct.pack("!BBH", 2, 4, mss) + b"\x04\x02\x08\x0a" + struct.pack("!II", tsval, 0) + b"\x01\x03\x03\x07" + mp


def _synack_tcpopts(mss, tsval, tsecr, mp=b""):
    return struct.pack("!BBH", 2, 4, mss) + b"\x04\x02\x08\x0a" + struct.pack("!II", tsval, tsecr) + b"\x01\x03\x03\x07" + mp


def _ack_tcpopts(tsval, tsecr, mp=b""):
    return b"\x01\x01\x08\x0a" + struct.pack("!II", tsval, tsecr) + mp


def _fresh_port(ctx, atk):
    used = ctx.__dict__.setdefault("_ipu_ports", {}).setdefault(atk.ip, set())
    while True:
        p = rng.randint(32768, 60999)
        if p not in used:
            used.add(p)
            return p


# ================================================================================ packet helpers
def _pkt(s, a, b, t, flags, seq, ack, win, opts=b"", ipo_c=b"", ipo_s=b""):
    s.t = t
    s.ip_opts_c2s, s.ip_opts_s2c = ipo_c, ipo_s
    sp, dp = (s.sport, s.dport) if a is s.c else (s.dport, s.sport)
    s._emit(a, b, sp, dp, seq, ack, flags, win, b"", opts)
    s.ip_opts_c2s, s.ip_opts_s2c = b"", b""


def _fail_attempt(ctx, atk, tgt, port, t, mp, rtt):
    """One failed attempt (five packets): SYN with IP options, SYN-ACK echoing them, the SAME SYN again 200-500 ms later
    (same source port and ISN), SYN-ACK, then the attacker's host resets the unsolicited SYN-ACK."""
    s = ctx.tcp(atk, tgt, port, t, vantage=tgt, rtt=rtt, sport=_fresh_port(ctx, atk))
    isn, sisn = s.cseq, s.sseq
    var = rng.choice(_VARIANTS)
    ipo = _syn_ipopts(var)
    kc, ks = (_key(), _key()) if mp else (b"", b"")
    ts_c, ts_s = rng.randint(1, 2 ** 31), rng.randint(1, 2 ** 31)
    syn_opts = _syn_tcpopts(1460, ts_c, _mp_syn(kc) if mp else b"")
    gap = rng.uniform(*_RETX_GAP)
    for k in (0, 1):
        tk = t + k * gap
        _pkt(s, atk, tgt, tk, SYN, isn, 0, 64240, syn_opts, ipo_c=ipo)
        ta = tk + rng.uniform(0.0002, 0.0009)
        sa_opts = _synack_tcpopts(1460, ts_s + int(k * gap * 1000), ts_c, _mp_syn(ks) if mp else b"")
        _pkt(s, tgt, atk, ta, SYN | ACK, sisn, isn + 1, 65160, sa_opts,
             ipo_s=_echo_ipopts(var, tgt.ipb, _tsms(ta)))
        if k == 1:      # ASSUMED: the attacker's host resets only the SYN-ACK that ends the attempt
            _pkt(s, atk, tgt, ta + rtt * rng.uniform(0.95, 1.1), RST, isn + 1, 0, 0)
    return s.pkts


def _spray_burst(ctx, atk, tgt, port, mp, n, ts):
    out = ctx.arp_for(atk, tgt, ts, vantage=tgt)
    rtt = rng.uniform(0.018, 0.070)
    pk = []
    for o in sorted(rng.uniform(0, _BURST_SPAN) for _ in range(n)):
        pk += _fail_attempt(ctx, atk, tgt, port, ts + o, mp, rtt * rng.uniform(0.95, 1.1))
    return F.merged(out, pk)


def ipu_spray_lnx1(ctx, atk, tgt, n, ts):
    """A burst of failed attempts against the plain TCP listener."""
    return _spray_burst(ctx, atk, tgt, _LNX1_PORT, False, n, ts)


def ipu_spray_lnx2(ctx, atk, tgt, n, ts):
    """A burst of failed attempts against the MPTCP listener (SYN and SYN-ACK also carry MP_CAPABLE)."""
    return _spray_burst(ctx, atk, tgt, _LNX2_PORT, True, n, ts)


def ipu_win_exchange(ctx, atk, tgt, ts):
    """The winning attempt (ASSUMED shape): SYN with options, SYN-ACK (stored options echoed), the SAME SYN again 200-500 ms
    later, a second SYN-ACK carrying the leak in its IP options, the third ACK (MP_CAPABLE with both keys), one small
    attacker payload on the established connection, then the attacker closes. No RST."""
    out = ctx.arp_for(atk, tgt, ts, vantage=tgt)
    s = ctx.tcp(atk, tgt, _LNX2_PORT, ts, vantage=tgt, rtt=rng.uniform(0.018, 0.070), sport=_fresh_port(ctx, atk))
    isn, sisn = s.cseq, s.sseq
    ipo = _syn_ipopts((1, 1))
    kc, ks = _key(), _key()
    ts_c, ts_s = rng.randint(1, 2 ** 31), rng.randint(1, 2 ** 31)
    gap = rng.uniform(*_RETX_GAP)
    for k in (0, 1):            # the race precondition: the SAME SYN twice; the leak rides the second SYN-ACK
        tk = ts + k * gap
        _pkt(s, atk, tgt, tk, SYN, isn, 0, 64240, _syn_tcpopts(1460, ts_c, _mp_syn(kc)), ipo_c=ipo)
        ta = tk + rng.uniform(0.0002, 0.0009)
        sa_opts = _synack_tcpopts(1460, ts_s + int(k * gap * 1000), ts_c, _mp_syn(ks))
        _pkt(s, tgt, atk, ta, SYN | ACK, sisn, isn + 1, 65160, sa_opts,
             ipo_s=_leak_ipopts(tgt.ipb, _tsms(ta)) if k else _echo_ipopts((1, 1), tgt.ipb, _tsms(ta)))
    t3 = ta + s.rtt * rng.uniform(0.95, 1.1)
    _pkt(s, atk, tgt, t3, ACK, isn + 1, sisn + 1, 64240, _ack_tcpopts(ts_c + 1, ts_s, _mp_ack(kc, ks)))
    s.cseq, s.sseq, s.open, s.t = isn + 1, sisn + 1, True, t3
    s.c2s(bytes(rng.getrandbits(8) for _ in range(rng.randint(120, 260))), think=rng.uniform(0.05, 0.25))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.4, 1.2)))


def _cb_out():
    """The callback's command output; resolved per build so the hostname follows the company identity."""
    return (b"uid=0(root) gid=0(root) groups=0(root)\n",
            ("Linux %slnx2 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux\n" % get_current().prefix.lower()).encode(),
            b"total 24\ndrwxr-xr-x 2 root root 4096 svc\n-rw-r--r-- 1 root root 1187 config.yaml\n-rwxr-xr-x 1 root root 9120 lnx2-svc\n")


def ipu_callback(ctx, tgt, atk, ts):
    """ASSUMED: after the payload runs, EXL-LNX2 opens an outbound TCP connection to the attacker on a high port and sends
    a short burst (under 2 KB in all)."""
    out = ctx.arp_for(tgt, atk, ts, vantage=tgt)
    s = ctx.tcp(tgt, atk, _CALLBACK_PORT, ts + 0.001, vantage=tgt).handshake(server_stack="linux")
    for chunk in _cb_out():
        s.c2s(chunk, think=rng.uniform(0.02, 0.2))
    s.s2c(b"\n", think=rng.uniform(0.1, 0.4))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.2, 0.8)))


# ================================================================================ benign look-alikes
_REQS = (b'{"op":"status"}\n', b'{"op":"list","limit":20}\n', b'{"op":"get","id":4711}\n')


def ipu_benign_session(ctx, client, tgt, port, ts):
    """An ordinary option-free client: plain SYN, 3-way handshake, a short request and reply, close."""
    out = ctx.arp_for(client, tgt, ts, vantage=tgt)
    s = ctx.tcp(client, tgt, port, ts + 0.001, vantage=tgt).handshake(server_stack="linux")
    s.c2s(rng.choice(_REQS), think=rng.uniform(0.005, 0.05))
    s.s2c(b'{"ok":true,"n":%d}\n' % rng.randint(1, 999), think=rng.uniform(0.01, 0.08))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.05, 0.5)))


def ipu_benign_syn_retransmit(ctx, client, tgt, port, ts):
    """A plain SYN retransmit (no IP options): the first SYN-ACK is lost, the client resends the same SYN a second
    later, the second SYN-ACK arrives, the handshake completes and a short exchange follows."""
    out = ctx.arp_for(client, tgt, ts, vantage=tgt)
    s = ctx.tcp(client, tgt, port, ts, vantage=tgt, sport=client.eph())
    isn, sisn = s.cseq, s.sseq
    ts_c, ts_s = rng.randint(1, 2 ** 31), rng.randint(1, 2 ** 31)
    for k in (0, 1):
        tk = ts + k * 1.0
        _pkt(s, client, tgt, tk, SYN, isn, 0, 64240, _syn_tcpopts(1460, ts_c))
        _pkt(s, tgt, client, tk + rng.uniform(0.0002, 0.0009), SYN | ACK, sisn, isn + 1, 65160,
             _synack_tcpopts(1460, ts_s + k * 1000, ts_c))
    t3 = ts + 1.0 + s.rtt * rng.uniform(0.95, 1.1)
    _pkt(s, client, tgt, t3, ACK, isn + 1, sisn + 1, 64240, _ack_tcpopts(ts_c + 1000, ts_s))
    s.cseq, s.sseq, s.open, s.t = isn + 1, sisn + 1, True, t3
    s.c2s(rng.choice(_REQS), think=rng.uniform(0.005, 0.05))
    s.s2c(b'{"ok":true}\n', think=rng.uniform(0.01, 0.08))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.05, 0.5)))


def ipu_benign_mptcp_client(ctx, client, tgt, ts):
    """A partner client negotiating MP_CAPABLE normally with the MPTCP listener: SYN (12-byte key), SYN-ACK (12-byte key),
    third ACK (20 bytes, both keys), a short exchange, close. No IP options."""
    out = ctx.arp_for(client, tgt, ts, vantage=tgt)
    s = ctx.tcp(client, tgt, _LNX2_PORT, ts, vantage=tgt, sport=client.eph())
    isn, sisn = s.cseq, s.sseq
    kc, ks = _key(), _key()
    ts_c, ts_s = rng.randint(1, 2 ** 31), rng.randint(1, 2 ** 31)
    _pkt(s, client, tgt, ts, SYN, isn, 0, 64240, _syn_tcpopts(1460, ts_c, _mp_syn(kc)))
    ta = ts + rng.uniform(0.0002, 0.0009)
    _pkt(s, tgt, client, ta, SYN | ACK, sisn, isn + 1, 65160, _synack_tcpopts(1460, ts_s, ts_c, _mp_syn(ks)))
    t3 = ta + s.rtt * rng.uniform(0.95, 1.1)
    _pkt(s, client, tgt, t3, ACK, isn + 1, sisn + 1, 64240, _ack_tcpopts(ts_c + 1, ts_s, _mp_ack(kc, ks)))
    s.cseq, s.sseq, s.open, s.t = isn + 1, sisn + 1, True, t3
    s.c2s(rng.choice(_REQS), think=rng.uniform(0.005, 0.05))
    s.s2c(b'{"ok":true}\n', think=rng.uniform(0.01, 0.08))
    return F.merged(out, s.close(by_client=True, think=rng.uniform(0.05, 0.5)))


def ipu_scanner_probe(ctx, scanner, tgt, port, ts):
    """The one-off benign scanner: ONE SYN with a Timestamp IP option, the server's SYN-ACK echoes it, the scanner's
    kernel RSTs it. No retransmit, no follow-on."""
    out = ctx.arp_for(scanner, tgt, ts, vantage=tgt)
    s = ctx.tcp(scanner, tgt, port, ts, vantage=tgt, sport=_fresh_port(ctx, scanner), rtt=rng.uniform(0.018, 0.070))
    isn, sisn = s.cseq, s.sseq
    ipo = bytes([68, 12, 5, 0]) + b"\0" * 8
    ts_c, ts_s = rng.randint(1, 2 ** 31), rng.randint(1, 2 ** 31)
    _pkt(s, scanner, tgt, ts, SYN, isn, 0, 64240, _syn_tcpopts(1460, ts_c), ipo_c=ipo)
    ta = ts + rng.uniform(0.0002, 0.0009)
    echo = bytes([68, 12, 9, 0]) + struct.pack("!I", _tsms(ta)) + b"\0" * 4
    _pkt(s, tgt, scanner, ta, SYN | ACK, sisn, isn + 1, 65160, _synack_tcpopts(1460, ts_s, ts_c), ipo_s=echo)
    _pkt(s, scanner, tgt, ta + s.rtt * rng.uniform(0.95, 1.1), RST, isn + 1, 0, 0)
    return F.merged(out, s.pkts)


# ================================================================================ build
def build(ctx, eng, tag, win):
    """Schedule CVE-2026-98432: two sprays of option-bearing, retransmitted SYNs (one burst per scheduled flow), the plain
    target never completing a handshake, the MPTCP target losing one race (leak, payload, callback), plus the benign
    look-alikes. Registered as ``ir-ipopt-tcp-uaf`` (imported lazily)."""
    ext = _inject_hosts(ctx)
    from netgen import incidents as INC
    sched = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))
    lnx1, lnx2 = ctx.h[_host(ctx, _LNX1_SUFFIX)], ctx.h[_host(ctx, _LNX2_SUFFIX)]
    att1, att2, scanner, partner = ext["att1"], ext["att2"], ext["scanner"], ext["partner"]

    t_win = lo + 3900.0                      # the winning SYN
    sprays = ((att1, lnx1, ipu_spray_lnx1, lo + 240.0, lo + 240.0 + _SPRAY_S),
              (att2, lnx2, ipu_spray_lnx2, t_win - _SPRAY_S - 4.5, t_win - 4.5))
    for atk, tgt, fn, t0, t1 in sprays:
        t = t0
        while t < t1 - _BURST_SPAN - 1.0:
            sched(t, fn, atk, tgt, max(1, int(round(rng.randint(*_BURST_N) * scale))))
            t += rng.uniform(*_BURST_EVERY)

    sched(t_win, ipu_win_exchange, att2, lnx2)
    sched(t_win + rng.uniform(3.0, 6.0), ipu_callback, lnx2, att2)

    # benign look-alikes, all day inside the window
    clients = [c for c in (ctx.h.get(_host(ctx, "WS-%03d" % n)) for n in (21, 22, 23, 24, 25)) if c is not None] + [partner]
    per_target = max(20, int(150 * scale))
    span = max(1.0, hi - lo - 30.0)
    for tgt, port in ((lnx1, _LNX1_PORT), (lnx2, _LNX2_PORT)):
        for _ in range(per_target):
            sched(lo + rng.uniform(0, span), ipu_benign_session, rng.choice(clients), tgt, port)
        for _ in range(max(4, int(12 * scale))):
            sched(lo + rng.uniform(0, span), ipu_benign_syn_retransmit, partner, tgt, port)
    for _ in range(max(6, int(30 * scale))):
        sched(lo + rng.uniform(0, span), ipu_benign_mptcp_client, partner, lnx2)
    sched(lo + 1500.0, ipu_scanner_probe, scanner, lnx1, _LNX1_PORT)
    sched(lo + 1500.0 + rng.uniform(20, 90), ipu_scanner_probe, scanner, lnx2, _LNX2_PORT)
