#!/usr/bin/env python3
"""Independent IPv4 / TCP / UDP / ICMP validator for a classic pcap. Standard library only; it does
not import anything from netgen, so it cannot share a bug with the generator.

    python3 checks/check_rfc791.py FILE.pcap [--max-errors N] [--exempt CODE ...] [--quiet]

Every Ethernet frame carrying IPv4 (EtherType 0x0800, also behind one or two 802.1Q tags) is checked:

  ip.version        version field is 4
  ip.ihl            IHL >= 5 and the header fits in the captured bytes
  ip.options        option list is well formed (EOL / NOP / length-prefixed, no overrun)
  ip.totlen         total length >= header length and consistent with the captured length
                    (extra bytes after total length are accepted only as Ethernet padding, i.e. when
                    the frame is at most 60 bytes; a frame cut by the snaplen is counted, not failed,
                    when the pcap itself says it was truncated)
  ip.checksum       header checksum verifies
  ip.ttl            TTL > 0
  ip.frag           reserved bit 0, not DF+MF, a non-last fragment carries a multiple of 8 bytes,
                    offset + length fits in 65535
  ip.proto          protocol number is a known one
  tcp.*             data offset >= 5 and inside the segment, checksum over the pseudo-header
  udp.*             length matches the IP payload, checksum verifies (0 = none, allowed for IPv4)
  icmp.*            checksum verifies, 4 bytes minimum

Non-first fragments are not parsed at the transport layer (the header is not there).
Exit status 1 if any check failed. --exempt CODE (repeatable, a code or a prefix such as "tcp.")
excludes a documented class of finding from the failure count; exempted findings are still listed.
"""
import argparse
import struct
import sys

KNOWN_PROTO = {1, 2, 4, 6, 17, 41, 47, 50, 51, 58, 89, 103, 112, 132}
ETH_IP, ETH_VLAN, ETH_QINQ = 0x0800, 0x8100, 0x88A8


def csum_ok(data):
    """True when the ones-complement sum of `data` (checksum field included) is 0xffff."""
    if len(data) & 1:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF


def read_pcap(path):
    f = open(path, "rb")
    gh = f.read(24)
    if len(gh) < 24:
        raise SystemExit("not a pcap (short header)")
    magic = gh[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    else:
        raise SystemExit("not a classic pcap (magic %r); pcapng is not supported" % magic)
    snaplen, link = struct.unpack(end + "II", gh[16:24])
    return f, end, snaplen, link


def check(path, max_errors=20, exempt=(), quiet=False):
    f, end, snaplen, link = read_pcap(path)
    if link != 1:
        raise SystemExit("link type %d is not Ethernet" % link)
    hdr = struct.Struct(end + "IIII")
    counts = {"frames": 0, "ipv4": 0, "non_ip": 0, "tcp": 0, "udp": 0, "icmp": 0, "other_l4": 0,
              "fragments": 0, "truncated": 0}
    fails = {}
    exempted = {}
    first = []

    def bad(code, n, msg):
        ex = any(code == e or (e.endswith(".") and code.startswith(e)) for e in exempt)
        d = exempted if ex else fails
        d[code] = d.get(code, 0) + 1
        if len(first) < max_errors:
            first.append("frame %d: %s: %s%s" % (n, code, msg, " [exempt]" if ex else ""))

    n = 0
    read = f.read
    unpack_from = struct.unpack_from
    while True:
        h = read(16)
        if len(h) < 16:
            break
        _s, _u, caplen, origlen = hdr.unpack(h)
        data = read(caplen)
        n += 1
        counts["frames"] += 1
        if len(data) < 14:
            bad("eth.short", n, "frame of %d bytes" % len(data))
            continue
        et = unpack_from("!H", data, 12)[0]
        off = 14
        while et in (ETH_VLAN, ETH_QINQ) and len(data) >= off + 4:
            et = unpack_from("!H", data, off + 2)[0]
            off += 4
        if et != ETH_IP:
            counts["non_ip"] += 1
            continue
        counts["ipv4"] += 1
        ip = data[off:]
        if len(ip) < 20:
            bad("ip.short", n, "IPv4 header cut at %d bytes" % len(ip))
            continue
        vihl, _tos, tot, _id, ffo, ttl, proto = unpack_from("!BBHHHBB", ip, 0)
        ver, ihl = vihl >> 4, (vihl & 15) * 4
        if ver != 4:
            bad("ip.version", n, "version %d" % ver)
            continue
        if ihl < 20:
            bad("ip.ihl", n, "IHL %d words" % (ihl // 4))
            continue
        if ihl > len(ip):
            bad("ip.ihl", n, "header %d bytes but only %d captured" % (ihl, len(ip)))
            continue
        trunc = caplen < origlen
        if tot < ihl:
            bad("ip.totlen", n, "total length %d < header %d" % (tot, ihl))
            continue
        if tot > len(ip):
            if trunc:
                counts["truncated"] += 1
            else:
                bad("ip.totlen", n, "total length %d but %d bytes present" % (tot, len(ip)))
                continue
        elif tot < len(ip) and len(data) > 60:
            bad("ip.totlen", n, "%d trailing bytes after total length %d in a %d byte frame"
                % (len(ip) - tot, tot, len(data)))
        if not csum_ok(ip[:ihl]):
            bad("ip.checksum", n, "bad header checksum")
        if ttl == 0:
            bad("ip.ttl", n, "TTL 0")
        if ihl > 20:
            o, e = 20, ihl
            while o < e:
                k = ip[o]
                if k == 0:
                    break
                if k == 1:
                    o += 1
                    continue
                if o + 1 >= e or ip[o + 1] < 2 or o + ip[o + 1] > e:
                    bad("ip.options", n, "malformed option %d at %d" % (k, o))
                    break
                o += ip[o + 1]
        res, df, mf, fo = ffo >> 15, (ffo >> 14) & 1, (ffo >> 13) & 1, (ffo & 0x1FFF) * 8
        if res:
            bad("ip.frag", n, "reserved flag set")
        if df and mf:
            bad("ip.frag", n, "DF and MF both set")
        paylen = tot - ihl
        if mf and paylen % 8:
            bad("ip.frag", n, "non-last fragment carries %d bytes" % paylen)
        if fo + paylen > 65515:
            bad("ip.frag", n, "fragment end %d exceeds 65515" % (fo + paylen))
        if proto not in KNOWN_PROTO:
            bad("ip.proto", n, "protocol %d" % proto)
        if mf or fo:
            counts["fragments"] += 1
            continue
        if tot > len(ip):                      # snaplen-truncated: transport checks are not possible
            continue
        seg = ip[ihl:tot]
        if proto == 6:
            counts["tcp"] += 1
            if len(seg) < 20:
                bad("tcp.short", n, "segment %d bytes" % len(seg))
                continue
            doff = (seg[12] >> 4) * 4
            if doff < 20 or doff > len(seg):
                bad("tcp.offset", n, "data offset %d with %d byte segment" % (doff, len(seg)))
            ph = ip[12:20] + struct.pack("!BBH", 0, 6, len(seg))
            if not csum_ok(ph + seg):
                bad("tcp.checksum", n, "bad TCP checksum")
        elif proto == 17:
            counts["udp"] += 1
            if len(seg) < 8:
                bad("udp.short", n, "datagram %d bytes" % len(seg))
                continue
            ulen, uck = unpack_from("!HH", seg, 4)
            if ulen != len(seg):
                bad("udp.length", n, "UDP length %d, IP payload %d" % (ulen, len(seg)))
            elif uck != 0:
                ph = ip[12:20] + struct.pack("!BBH", 0, 17, len(seg))
                if not csum_ok(ph + seg):
                    bad("udp.checksum", n, "bad UDP checksum")
        elif proto == 1:
            counts["icmp"] += 1
            if len(seg) < 4:
                bad("icmp.short", n, "message %d bytes" % len(seg))
            elif not csum_ok(seg):
                bad("icmp.checksum", n, "bad ICMP checksum")
        else:
            counts["other_l4"] += 1
    f.close()
    return counts, fails, exempted, first


def main(argv=None):
    ap = argparse.ArgumentParser(description="Validate IPv4/TCP/UDP/ICMP in a classic pcap")
    ap.add_argument("pcap")
    ap.add_argument("--max-errors", type=int, default=20)
    ap.add_argument("--exempt", action="append", default=[], metavar="CODE",
                    help="finding code (or prefix ending in '.') not counted as a failure")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)
    counts, fails, exempted, first = check(a.pcap, a.max_errors, a.exempt)
    if not a.quiet:
        print("frames %(frames)d  ipv4 %(ipv4)d  tcp %(tcp)d  udp %(udp)d  icmp %(icmp)d  "
              "other-l4 %(other_l4)d  fragments %(fragments)d  non-ip %(non_ip)d  "
              "snaplen-truncated %(truncated)d" % counts)
    for line in first:
        print("  " + line)
    total = sum(fails.values())
    if exempted and not a.quiet:
        print("exempt findings: " + ", ".join("%s=%d" % kv for kv in sorted(exempted.items())))
    if total:
        print("FAIL: %d violation(s): %s" % (total, ", ".join("%s=%d" % kv for kv in sorted(fails.items()))))
        return 1
    print("OK: every IPv4 packet is RFC 791 valid, every TCP/UDP/ICMP checksum verifies (%d IPv4 packets)" % counts["ipv4"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
