#!/usr/bin/env python3
"""Independent IPv6 / TCP / UDP / ICMPv6 validator for a classic pcap. Standard library only; it does
not import anything from netgen, so it cannot share a bug with the generator.

    python3 checks/check_ipv6.py FILE.pcap [--max-errors N] [--exempt CODE ...] [--quiet]

Every Ethernet frame carrying IPv6 (EtherType 0x86DD, also behind one or two 802.1Q / 802.1ad tags)
is checked; IPv4 and other frames are only counted, so an all-IPv4 capture passes with zero IPv6 frames.

  ip6.short       fixed header cut
  ip6.version     version field is 6
  ip6.hoplimit    hop limit > 0
  ip6.plen        payload length consistent with the captured frame (extra bytes are accepted only as
                  Ethernet padding, i.e. a frame of at most 60 bytes; a snaplen-cut frame is counted)
  ip6.exthdr      extension-header chain (hop-by-hop, routing, fragment, destination, AH) fits in the payload
  ip6.mcastmac    destination MAC of a ff00::/8 address is 33:33 + the low 32 bits of the address
  tcp.*           data offset inside the segment, checksum over the 40-byte pseudo-header
  udp.*           length matches the payload, checksum verifies; checksum 0 is an error over IPv6
  icmp6.*         checksum verifies over the pseudo-header, 4 bytes minimum
  ndp.hoplimit    NS/NA/RS/RA/Redirect must carry hop limit 255
  ndp.option      NDP options have nonzero length (8-byte units) and fit; NS/NA target vs
                  solicited-node destination address agree

Non-first fragments are not parsed at the transport layer. Shortcut: the pseudo-header uses the IPv6
destination field, not the final routing-header destination; upgrade if routing type 0/2/4 appears.
Exit status 1 if any check failed. --exempt CODE (repeatable, a code or a prefix ending in ".")
excludes a documented class of finding from the failure count; exempted findings are still listed.
--decap gre,vxlan,6in4 also validates the packets inside tunnels (see decap.py); a tunnel envelope problem
is a finding with its own code (gre.*, vxlan.*, 6in4.*, tunnel.fragment).
"""
import argparse
import struct
import sys

try:                                # run as a script (checks/ on the path) or imported as checks.<name>
    from decap import Decap
except ImportError:
    from .decap import Decap

ETH_IP6, ETH_VLAN, ETH_QINQ = 0x86DD, 0x8100, 0x88A8
EXT_SIMPLE = {0, 43, 60}          # hop-by-hop, routing, destination options: (len+1)*8 bytes
NDP_HDR = {133: 8, 134: 16, 135: 24, 136: 24, 137: 40}   # ICMPv6 type -> bytes before options


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


def walk_ext(ip, plen):
    """Follow the extension chain. Returns (final next-header, offset of upper layer in ip,
    is_nonfirst_fragment, error string or None)."""
    nh, off, end = ip[6], 40, 40 + plen
    frag = False
    while True:
        if nh in EXT_SIMPLE or nh == 51:
            if off + 2 > end:
                return nh, off, frag, "extension header %d cut" % nh
            n = (ip[off + 1] + 2) * 4 if nh == 51 else (ip[off + 1] + 1) * 8
        elif nh == 44:
            if off + 8 > end:
                return nh, off, frag, "fragment header cut"
            n = 8
            if struct.unpack_from("!H", ip, off + 2)[0] >> 3:
                frag = True
        else:
            return nh, off, frag, None
        if off + n > end:
            return nh, off, frag, "extension header %d of %d bytes overruns payload" % (nh, n)
        nh, off = ip[off], off + n


def check(path, max_errors=20, exempt=(), quiet=False, decap=None):
    f, end, snaplen, link = read_pcap(path)
    if link != 1:
        raise SystemExit("link type %d is not Ethernet" % link)
    hdr = struct.Struct(end + "IIII")
    counts = {"frames": 0, "ipv6": 0, "non_ip6": 0, "tcp": 0, "udp": 0, "icmp6": 0, "ndp": 0,
              "other_l4": 0, "fragments": 0, "truncated": 0}
    fails, exempted, first = {}, {}, []

    def bad(code, n, msg):
        ex = any(code == e or (e.endswith(".") and code.startswith(e)) for e in exempt)
        d = exempted if ex else fails
        d[code] = d.get(code, 0) + 1
        if len(first) < max_errors:
            first.append("frame %d: %s: %s%s" % (n, code, msg, " [exempt]" if ex else ""))

    def records():
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            _s, _u, caplen, origlen = hdr.unpack(h)
            yield caplen, origlen, f.read(caplen)

    dec = Decap.parse(decap)
    n = 0
    for caplen, origlen, data in dec.records(records()) if dec else records():
        n += 1
        counts["frames"] += 1
        if len(data) < 14:
            counts["non_ip6"] += 1
            continue
        et = struct.unpack_from("!H", data, 12)[0]
        off = 14
        while et in (ETH_VLAN, ETH_QINQ) and len(data) >= off + 4:
            et = struct.unpack_from("!H", data, off + 2)[0]
            off += 4
        if et != ETH_IP6:
            counts["non_ip6"] += 1
            continue
        counts["ipv6"] += 1
        ip = data[off:]
        if len(ip) < 40:
            bad("ip6.short", n, "IPv6 header cut at %d bytes" % len(ip))
            continue
        ver = ip[0] >> 4
        plen, nxt, hop = struct.unpack_from("!HBB", ip, 4)
        if ver != 6:
            bad("ip6.version", n, "version %d" % ver)
            continue
        if hop == 0:
            bad("ip6.hoplimit", n, "hop limit 0")
        trunc = caplen < origlen
        if 40 + plen > len(ip):
            if trunc:
                counts["truncated"] += 1
            else:
                bad("ip6.plen", n, "payload length %d but %d bytes present" % (plen, len(ip) - 40))
                continue
        elif 40 + plen < len(ip) and len(data) > 60:
            bad("ip6.plen", n, "%d trailing bytes after payload length %d in a %d byte frame"
                % (len(ip) - 40 - plen, plen, len(data)))
        src, dst = ip[8:24], ip[24:40]
        if dst[0] == 0xFF and data[0:6] != b"\x33\x33" + dst[12:16]:
            bad("ip6.mcastmac", n, "dst %s but MAC %s" % (dst.hex(), data[0:6].hex()))
        if trunc and 40 + plen > len(ip):
            continue
        nh, uo, frag, err = walk_ext(ip, plen)
        if err:
            bad("ip6.exthdr", n, err)
            continue
        if frag:
            counts["fragments"] += 1
            continue
        seg = ip[uo:40 + plen]
        ph = src + dst + struct.pack("!IBBBB", len(seg), 0, 0, 0, nh)
        if nh == 6:
            counts["tcp"] += 1
            if len(seg) < 20:
                bad("tcp.short", n, "segment %d bytes" % len(seg))
                continue
            doff = (seg[12] >> 4) * 4
            if doff < 20 or doff > len(seg):
                bad("tcp.offset", n, "data offset %d with %d byte segment" % (doff, len(seg)))
            if not csum_ok(ph + seg):
                bad("tcp.checksum", n, "bad TCP checksum")
        elif nh == 17:
            counts["udp"] += 1
            if len(seg) < 8:
                bad("udp.short", n, "datagram %d bytes" % len(seg))
                continue
            ulen, uck = struct.unpack_from("!HH", seg, 4)
            if ulen != len(seg):
                bad("udp.length", n, "UDP length %d, IP payload %d" % (ulen, len(seg)))
            elif uck == 0:
                bad("udp.checksum", n, "UDP checksum 0 is not allowed over IPv6")
            elif not csum_ok(ph + seg):
                bad("udp.checksum", n, "bad UDP checksum")
        elif nh == 58:
            counts["icmp6"] += 1
            if len(seg) < 4:
                bad("icmp6.short", n, "message %d bytes" % len(seg))
                continue
            if not csum_ok(ph + seg):
                bad("icmp6.checksum", n, "bad ICMPv6 checksum")
            t = seg[0]
            if t in NDP_HDR:
                counts["ndp"] += 1
                if hop != 255:
                    bad("ndp.hoplimit", n, "type %d with hop limit %d" % (t, hop))
                fixed = NDP_HDR[t]
                if len(seg) < fixed:
                    bad("ndp.option", n, "type %d message %d bytes, needs %d" % (t, len(seg), fixed))
                    continue
                if t == 135 and dst[:13] == bytes.fromhex("ff0200000000000000000001ff") \
                        and seg[8:24][13:] != dst[13:]:
                    bad("ndp.option", n, "NS target does not match solicited-node destination")
                o = fixed
                while o < len(seg):
                    if o + 2 > len(seg) or seg[o + 1] == 0 or o + seg[o + 1] * 8 > len(seg):
                        bad("ndp.option", n, "option type %d at %d has bad length" % (seg[o], o))
                        break
                    o += seg[o + 1] * 8
        elif nh != 59:
            counts["other_l4"] += 1
    f.close()
    for dn, code, msg in dec.problems if dec else ():
        bad(code, dn, msg)
    return counts, fails, exempted, first


def main(argv=None):
    ap = argparse.ArgumentParser(description="Validate IPv6/TCP/UDP/ICMPv6/NDP in a classic pcap")
    ap.add_argument("pcap")
    ap.add_argument("--max-errors", type=int, default=20)
    ap.add_argument("--exempt", action="append", default=[], metavar="CODE",
                    help="finding code (or prefix ending in '.') not counted as a failure")
    ap.add_argument("--decap", metavar="KINDS", help="also validate the packets inside tunnels: gre, vxlan, 6in4 (comma-separated)")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)
    try:
        counts, fails, exempted, first = check(a.pcap, a.max_errors, a.exempt, decap=a.decap)
    except ValueError as e:
        ap.error(str(e))
    if not a.quiet:
        print("frames %(frames)d  ipv6 %(ipv6)d  tcp %(tcp)d  udp %(udp)d  icmp6 %(icmp6)d  ndp %(ndp)d  "
              "other-l4 %(other_l4)d  fragments %(fragments)d  non-ipv6 %(non_ip6)d  "
              "snaplen-truncated %(truncated)d" % counts)
    for line in first:
        print("  " + line)
    total = sum(fails.values())
    if exempted and not a.quiet:
        print("exempt findings: " + ", ".join("%s=%d" % kv for kv in sorted(exempted.items())))
    if total:
        print("FAIL: %d violation(s): %s" % (total, ", ".join("%s=%d" % kv for kv in sorted(fails.items()))))
        return 1
    print("OK: every IPv6 packet is valid (%d IPv6 packets)" % counts["ipv6"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
