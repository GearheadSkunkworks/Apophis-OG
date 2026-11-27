"""npm-wireless-degradation: the CAPWAP tunnels and the client storm are valid on the wire.

Generates the scenario and checks, for every packet to or from the controller, IPv4 (RFC 791), UDP (RFC 768),
CAPWAP (RFC 5415 / 5416: correct UDP checksum, ephemeral AP ports, DSCP CS6, clear-text Discovery only, data
channel keep-alive layout), DTLS record and handshake framing (RFC 6347: record numbers, fragment fields,
cookie echo, message_seq), the 3 s doubling retransmission of an unanswered Echo, the 5 s waits of a rejoin,
and that every DHCP exchange of the storm is answered. It also checks the storm is there at all."""
import collections
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import opengenerator_build  # noqa: E402 - sys.path is set up before the import

WLC = bytes([10, 10, 20, 50])
FIXED_GAPS = (3.0, 6.0, 12.0, 15.0)           # RETRANSMIT offsets 0, 3, 9, 21, 36, 51 -> gaps between copies
REF = b"CHG0031877"


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def check(path):
    d = open(path, "rb").read()
    off, errs, flows, prev = 24, collections.Counter(), collections.defaultdict(list), 0
    ref_seen, dhcp = 0, collections.defaultdict(list)
    last, icmps, sent = {}, [], set()
    while off < len(d):
        sec, frac, cl, _ = struct.unpack("<IIII", d[off:off + 16])
        off += 16
        fr = d[off:off + cl]
        off += cl
        t = sec + frac / 1e6
        if t < prev:
            errs["time order"] += 1
        prev = t
        if len(fr) < 42 or fr[12:14] != b"\x08\x00":
            continue
        ihl = (fr[14] & 15) * 4
        src, dst = fr[26:30], fr[30:34]
        if csum(fr[14:14 + ihl]) != 0 or fr[14] >> 4 != 4:
            errs["ip header"] += 1
        if fr[23] == 1 and WLC in (src, dst):
            body = fr[14 + ihl:14 + struct.unpack("!H", fr[16:18])[0]]
            if body[0] == 3 and body[1] == 3:
                icmps.append((body[8:], csum(body), dst == WLC))
            continue
        if fr[23] != 17:
            continue
        body = fr[14 + ihl:14 + struct.unpack("!H", fr[16:18])[0]]
        sp, dp, ul, uc = struct.unpack("!HHHH", body[:8])
        pl = body[8:]
        if ul != len(body):
            errs["udp length"] += 1
        if dp == 514 and REF in pl:
            ref_seen += 1
        if (dp == 67 and sp == 68) or (sp == 67 and dp == 68):
            dhcp[struct.unpack("!I", pl[4:8])[0]].append(pl[0])
        if src == WLC and {sp, dp} & {5246, 5247}:
            sent.add(fr[14:14 + 28])                   # IP header + 8 bytes of every datagram the controller sent
        if WLC not in (src, dst) or not ({sp, dp} & {5246, 5247}):
            continue
        to_ac = dst == WLC
        ap_port = sp if to_ac else dp
        chan = "c" if 5246 in (sp, dp) else "d"
        key = (src if to_ac else dst, ap_port, chan)
        who = "ap" if to_ac else "ac"
        if uc == 0 or csum(src + dst + b"\x00\x11" + struct.pack("!H", ul) + body) != 0:
            errs["capwap udp checksum must be correct and non-zero"] += 1
        if ap_port in (5246, 5247):
            errs["AP must use an ephemeral port"] += 1
        if (chan == "c") != (fr[15] == 0xC0):
            errs["control DSCP CS6 / data DSCP 0"] += 1
        if chan == "d":
            if pl[:8] != b"\x00\x10\x00\x08\x00\x00\x00\x00" or len(pl) != 30 or pl[8:14] != b"\x00\x16\x00\x23\x00\x10":
                errs["data keep-alive layout"] += 1
            flows[key].append((t, who, "ka", len(pl)))
            continue
        if pl[0] == 0:
            mtype, seq, mel, flg = struct.unpack("!IBHB", pl[8:16])
            if mtype not in (1, 2) or mel != len(pl) - 15 or flg:
                errs["clear text must be Discovery with a correct length"] += 1
            flows[key].append((t, who, "disc%d" % mtype, len(pl)))
            continue
        if pl[:4] != b"\x01\x00\x00\x00":
            errs["CAPWAP DTLS header"] += 1
            continue
        p = pl[4:]
        recs = []
        while p:
            ct, ver, ep = struct.unpack("!BHH", p[:5])
            seq = int.from_bytes(p[5:11], "big")
            ln = struct.unpack("!H", p[11:13])[0]
            if len(p) < 13 + ln or ver not in (0xFEFD, 0xFEFF):
                errs["DTLS record framing"] += 1
                break
            frag = p[13:13 + ln]
            k = (key, who, ep)
            if k in last and seq <= last[k]:
                errs["DTLS record numbers must increase"] += 1
            last[k] = seq
            if ep == 1 and frag[:8] != struct.pack("!H", 1) + seq.to_bytes(6, "big"):
                errs["DTLS explicit nonce"] += 1
            info = None
            if ct == 22 and ep == 0:
                tot, ms = int.from_bytes(frag[1:4], "big"), struct.unpack("!H", frag[4:6])[0]
                fo, fl = int.from_bytes(frag[6:9], "big"), int.from_bytes(frag[9:12], "big")
                if fl != len(frag) - 12 or fo + fl > tot:
                    errs["handshake fragment fields"] += 1
                info = (frag[0], ms, fo, frag[12:])
            recs.append((ct, ep, ln, info))
            p = p[13 + ln:]
        flows[key].append((t, who, "dtls", len(pl), recs))
    # handshakes: complete, message_seq per RFC 6347 4.2.2, cookie echoed
    hs = 0
    expect = {("ap", 1): {0, 1}, ("ac", 3): {0}, ("ac", 2): {1}, ("ac", 11): {2}, ("ac", 12): {3}, ("ac", 13): {4},
              ("ac", 14): {5}, ("ap", 11): {2}, ("ap", 16): {3}, ("ap", 15): {4}}
    for key, ev in flows.items():
        if key[2] != "c":
            continue
        msgs = collections.defaultdict(dict)
        for e in ev:
            if e[2] == "dtls":
                for _ct, _ep, _ln, info in e[4]:
                    if info:
                        msgs[(e[1], info[1], info[0])][info[2]] = info[3]
        if not msgs:
            continue
        hs += 1
        full = {k: b"".join(f[o] for o in sorted(f)) for k, f in msgs.items()}
        if not set(expect) <= {(k[0], k[2]) for k in full}:
            errs["handshake incomplete"] += 1
        for (who, ms, mt) in full:
            if ms not in expect[(who, mt)]:
                errs["handshake message_seq"] += 1
        hv = [v for k, v in full.items() if k[0] == "ac" and k[2] == 3]
        ck = hv[0][3:3 + hv[0][2]] if hv else b""
        if not any(v[34:35] == b"\x00" and v[36:36 + len(ck)] == ck and v[35] == len(ck)
                   for k, v in full.items() if k[0] == "ap" and k[2] == 1):
            errs["ClientHello must echo the cookie"] += 1
        # RFC 5415 4.7.5: the WTP waits DiscoveryInterval (5 s) after a Discovery Response before the handshake
        disc = [e for e in ev if e[2] == "disc2"]
        first_hs = min(e[0] for e in ev if e[2] == "dtls")
        if disc and first_hs - max(e[0] for e in disc) < 5.0:
            errs["DiscoveryInterval is 5 s"] += 1
    # an unanswered Echo is retransmitted on the 3 s doubling timer: AP packets of Echo size (57) with no
    # answer (an AC packet of that size) between them are copies of one Request
    for key, ev in flows.items():
        if key[2] != "c":
            continue
        t_prev = None
        for e in ev:
            if e[2] != "dtls" or e[3] != 57:
                continue
            if e[1] == "ac":
                t_prev = None
            elif t_prev is not None:
                if not any(abs(e[0] - t_prev - g) < 0.2 for g in FIXED_GAPS):
                    errs["Echo retransmission gaps (3, 6, 12, 15 s)"] += 1
                t_prev = e[0]
            else:
                t_prev = e[0]
    for quoted, ck, to_ac in icmps:                    # RFC 792: the ICMP error quotes the datagram that caused it
        if ck != 0 or not to_ac or quoted not in sent:
            errs["ICMP port unreachable must quote a captured controller datagram"] += 1
    unanswered = sum(1 for v in dhcp.values() if v and v[0] == 1 and 2 not in v)
    return errs, hs, len(dhcp), unanswered, ref_seen, len(icmps)


with tempfile.TemporaryDirectory() as td:
    pcap = os.path.join(td, "t.pcap")
    sys.argv = ["opengenerator_build.py", "--scale", "0.0005", "--module", "npm-wireless-degradation", "--out", pcap,
                "--no-certs", "--no-iocs"]
    opengenerator_build.main()
    errs, hs, dhcp_n, unanswered, ref_seen, n_icmp = check(pcap)
assert not errs, dict(errs)
assert hs >= 30, "expected the fleet to rejoin in waves, saw %d handshakes" % hs
assert dhcp_n >= 100 and unanswered == 0, (dhcp_n, unanswered)
assert n_icmp >= 10, "late replies to closed sockets should draw ICMP port unreachable (%d)" % n_icmp
assert ref_seen == 1, "the change record reference must appear once in the controller's syslog (%d)" % ref_seen
print("CAPWAP tunnels valid on the wire: %d DTLS handshakes, %d DHCP exchanges all answered" % (hs, dhcp_n))
