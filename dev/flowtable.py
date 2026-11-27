"""Flow table from a finished classic pcap plus the optional per-packet tag sidecar (stdlib only).

flows(pcap_path, tags_path=None, ...) streams the capture once and yields one dict per flow:
  {"proto": "tcp|udp|icmp", "src", "sport", "dst", "dport", "start", "end", "orig_pkts", "resp_pkts",
   "orig_ip_bytes", "resp_ip_bytes", "orig_bytes", "resp_bytes", "flags_orig", "flags_resp",
   "tag", "tags", "first_pkt", "last_pkt"}
Times are epoch floats at microsecond precision; *_ip_bytes sum the IP total length, *_bytes the L4
payload; flags_* are the OR of TCP flags (0 otherwise); first_pkt/last_pkt are 1-based packet numbers
in the capture (equal to the main writer's numbering); tag is the majority scenario tag (ties go to
the tag first seen in the capture), tags every tag seen; both are None/[] without a sidecar.

Flow key: IPv4 TCP/UDP/ICMP 5-tuple, direction = first packet seen. ICMP has no ports: its key uses
0/0 and the record carries the first packet's type/code as sport/dport (the Zeek convention). Frames
that are not a flow (non-IP, IPv6, other IP protocols, non-first fragments, runts) are counted in
`stats["unflowed"]`, so sum(orig_pkts + resp_pkts) + stats["unflowed"] == packets in the file.

Segmentation: a gap above the idle timeout ends a flow; so does a TCP SYN (no ACK) arriving on a flow
that has already seen FIN or RST (port reuse). Idle flows are flushed as the capture clock advances,
so memory stays bounded by the number of live flows. Records come out in the order flows end
(flows still open at the end of the file last, in start order); sort by "start" if you need that.

RULES are provisional. TCP 300 s is Zeek's published tcp_inactivity_timeout; UDP 60 s and ICMP 30 s
are UNVERIFIED placeholders, not measured against any sensor.
"""
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_manifest as _bm  # noqa: E402 - sys.path is set up before the import
import pcapprofile as _pp     # noqa: E402 - sys.path is set up before the import

RULES = {"tcp_idle": 300.0, "udp_idle": 60.0, "icmp_idle": 30.0,
         "tcp_port_reuse": "SYN without ACK after FIN or RST starts a new flow",
         "unverified": ["udp_idle", "icmp_idle"]}

_SWEEP_S = 30.0                                  # capture-clock interval between idle sweeps
_NAME = {6: "tcp", 17: "udp", 1: "icmp"}
# flow list slots; _KEY is the table key the flow is stored under (its first packet's direction)
(_PROTO, _SRC, _SPORT, _DST, _DPORT, _START, _LAST, _OP, _RP, _OI, _RI, _OB, _RB, _FO, _FR,
 _FP, _LP, _TAGS, _KEY) = range(19)


def _record(f, table):
    c = f[_TAGS]
    tag, tags = None, []
    if c:
        ids = sorted(c)
        tags = [table[i] for i in ids]
        tag = table[max(ids, key=lambda i: (c[i], -i))]
    return {"proto": _NAME[f[_PROTO]], "src": socket.inet_ntoa(f[_SRC]), "sport": f[_SPORT],
            "dst": socket.inet_ntoa(f[_DST]), "dport": f[_DPORT],
            "start": f[_START], "end": f[_LAST], "orig_pkts": f[_OP], "resp_pkts": f[_RP],
            "orig_ip_bytes": f[_OI], "resp_ip_bytes": f[_RI], "orig_bytes": f[_OB], "resp_bytes": f[_RB],
            "flags_orig": f[_FO], "flags_resp": f[_FR], "tag": tag, "tags": tags,
            "first_pkt": f[_FP], "last_pkt": f[_LP]}


def export_flows(e, stats):
    """The flow records an exporter reads for build context `e`, `stats` filled as flows() would.
    When truth and ipfix/netflow9 both run they share ONE pass over the pcap (held on the context
    until the last of them has taken it); a lone consumer still streams."""
    ex = getattr(e, "exports", None) or ()
    users = ("truth" in ex) + any(k in ex for k in ("ipfix", "netflow9"))
    if users < 2:
        return flows(e.out, e.tags_path, stats=stats)
    memo = e.__dict__.get("_flow_pass")
    if memo is None:
        s = {}
        memo = e._flow_pass = [list(flows(e.out, e.tags_path, stats=s)), s, users]
    stats.update(memo[1])
    memo[2] -= 1
    if memo[2] <= 0:
        del e._flow_pass
    return iter(memo[0])


def flows(pcap_path, tags_path=None, tcp_idle=300.0, udp_idle=60.0, icmp_idle=30.0, stats=None):
    """Yield flow records (see module docstring). `stats`, if a dict, gets "packets" and "unflowed"
    once the generator is exhausted. A sidecar whose length differs from the pcap's packet count
    raises ValueError at the end."""
    table, body = (_bm.read_tags(tags_path) if tags_path else ([], None))
    nb = len(body) if body is not None else 0
    idle = {6: tcp_idle, 17: udp_idle, 1: icmp_idle}
    tab = {}
    n = unflowed = 0
    nxt = None
    for n, (ts, fr) in enumerate(_pp.iter_frames(pcap_path), 1):
        ts = round(ts, 6)
        if nxt is None:
            nxt = ts + _SWEEP_S
        elif ts >= nxt:
            nxt = ts + _SWEEP_S
            for k in [k for k, f in tab.items() if ts - f[_LAST] > idle[f[_PROTO]]]:
                yield _record(tab.pop(k), table)
        if fr is None or len(fr) < 34 or fr[12] != 8 or fr[13] != 0 or fr[14] >> 4 != 4:
            unflowed += 1
            continue
        ihl = (fr[14] & 15) * 4
        p = fr[23]
        l4 = 14 + ihl
        if (fr[20] << 8 | fr[21]) & 0x1FFF or p not in idle or ihl < 20 or len(fr) < l4 + (20 if p == 6 else 8):
            unflowed += 1
            continue
        tl = fr[16] << 8 | fr[17]
        flags = 0
        if p == 6:
            sp, dp, flags = fr[l4] << 8 | fr[l4 + 1], fr[l4 + 2] << 8 | fr[l4 + 3], fr[l4 + 13]
            pay = tl - ihl - (fr[l4 + 12] >> 4) * 4
            kp, kd = sp, dp
        elif p == 17:
            sp, dp = fr[l4] << 8 | fr[l4 + 1], fr[l4 + 2] << 8 | fr[l4 + 3]
            pay = tl - ihl - 8
            kp, kd = sp, dp
        else:
            sp, dp, kp, kd = fr[l4], fr[l4 + 1], 0, 0
            pay = tl - ihl - 8
        pay = max(pay, 0)
        src, dst = fr[26:30], fr[30:34]
        k = (p, src, kp, dst, kd)
        f = tab.get(k)
        fwd = f is not None
        if f is None:
            f = tab.get((p, dst, kd, src, kp))
        if f is not None and (ts - f[_LAST] > idle[p]
                              or (p == 6 and flags & 0x12 == 0x02 and (f[_FO] | f[_FR]) & 0x05)):
            del tab[f[_KEY]]
            yield _record(f, table)
            f = None
        if f is None:
            f = tab[k] = [p, src, sp, dst, dp, ts, ts, 0, 0, 0, 0, 0, 0, 0, 0, n, n,
                          {} if body is not None else None, k]
            fwd = True
        if fwd:
            f[_OP] += 1
            f[_OI] += tl
            f[_OB] += pay
            f[_FO] |= flags
        else:
            f[_RP] += 1
            f[_RI] += tl
            f[_RB] += pay
            f[_FR] |= flags
        f[_LAST] = ts
        f[_LP] = n
        if body is not None:
            t = body[n - 1] if n <= nb else 255
            c = f[_TAGS]
            c[t] = c.get(t, 0) + 1
    if body is not None and n != nb:
        raise ValueError("tag sidecar has %d entries but the pcap has %d packets" % (nb, n))
    if stats is not None:
        stats["packets"], stats["unflowed"] = n, unflowed
    for f in tab.values():
        yield _record(f, table)
