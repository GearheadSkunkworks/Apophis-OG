"""Pure frame builders for IPv6, 802.1Q/802.1ad VLAN tags and GRE/VXLAN carriers, plus zero-draw
IPv6 address derivation.

Nothing here draws from a random stream, keeps state, or creates a ``Host``: every function maps
its arguments to bytes (or an address) deterministically. The module deliberately declares no
``rng``/``SEED`` pair and no ``random.Random`` instance, so ``netgen.reseed_all()`` and
``incidents._isolated_rng()`` (which both auto-discover modules by those names) do not see it.
Nothing in the default day calls it; it only becomes reachable through later opt-in stages.

Addresses are 16-byte ``bytes``; MACs are 6-byte ``bytes``. ``tcp6``/``udp6``/``icmpv6`` return
the transport segment with its checksum over the 40-byte pseudo-header filled in; ``ipv6()`` wraps a
segment, and the ``ns``/``na``/``rs``/``ra``/``mld_report`` builders return complete Ethernet frames.

MSS arithmetic (path MTU 1500; the TCP MSS option is MTU minus every header in the way):

* plain IPv6:      1500 - 40 (IPv6) - 20 (TCP)                                   = 1440  (``MSS_V6``)
* GRE over IPv4:   1500 - 20 (outer IPv4) - 4 (GRE) - 20 (inner IPv4) - 20 (TCP) = 1436  (``MSS_GRE``);
                   a GRE key or sequence number each add 4 more header bytes, so 1432 with one, 1428 with both
* VXLAN over IPv4: 1500 - 20 (outer IPv4) - 8 (UDP) - 8 (VXLAN) - 14 (inner Ethernet)
                   - 20 (inner IPv4) - 20 (TCP)                                  = 1410  (``MSS_VXLAN``)

A session that ignores these emits a packet no real link carries without fragmenting.
"""
import hashlib
import struct
import zlib

from .core import eth

ETH_IPV6, ETH_VLAN, ETH_QINQ = 0x86DD, 0x8100, 0x88A8
NH_HOPOPT, NH_TCP, NH_UDP, NH_FRAG, NH_GRE, NH_ICMPV6 = 0, 6, 17, 44, 47, 58
MSS_V6, MSS_GRE, MSS_VXLAN = 1440, 1436, 1410
UNSPECIFIED = bytes(16)
ALL_NODES = bytes.fromhex("ff020000000000000000000000000001")
ALL_ROUTERS = bytes.fromhex("ff020000000000000000000000000002")
MLDV2_ROUTERS = bytes.fromhex("ff020000000000000000000000000016")
NS, NA, RS, RA, MLDV2_REPORT = 135, 136, 133, 134, 143          # ICMPv6 types
NA_ROUTER, NA_SOLICITED, NA_OVERRIDE = 0x80000000, 0x40000000, 0x20000000
_SOLICITED_PREFIX = bytes.fromhex("ff0200000000000000000001ff")


def _csum(data):
    """RFC 1071 checksum in network order, independent of the host byte order. 65535 is its own
    ones'-complement zero, so a nonzero sum that divides evenly maps to 65535, not 0."""
    if len(data) & 1:
        data += b"\0"
    s = int.from_bytes(data, "big") % 65535
    if not s and any(data):
        s = 65535
    return (~s) & 0xFFFF


def _check(name, value, bits):
    if not 0 <= value < (1 << bits):
        raise ValueError("%s %d does not fit in %d bits" % (name, value, bits))


def _with_csum(src, dst, nh, seg, at):
    """``seg`` with the checksum at byte offset ``at`` computed over the 40-byte pseudo-header
    (src, dst, 32-bit upper-layer length, three zero bytes, next header)."""
    seg = seg[:at] + b"\0\0" + seg[at + 2:]
    pseudo = src + dst + struct.pack("!IBBBB", len(seg), 0, 0, 0, nh)
    return seg[:at] + struct.pack("!H", _csum(pseudo + seg)) + seg[at + 2:]


# ------------------------------------------------------------------ IPv6 header and extension chain
def _hbh_body(options):
    """Hop-by-hop body after the next-header byte: length byte plus options padded to a multiple of 8
    in total (Pad1 for one byte, PadN for more), so the whole header is (len+1)*8 bytes."""
    pad = -(2 + len(options)) % 8
    if pad == 1:
        options += b"\0"
    elif pad:
        options += bytes([1, pad - 2]) + bytes(pad - 2)
    return bytes([(2 + len(options)) // 8 - 1]) + options


def ipv6(src, dst, nh, payload, hop=64, tc=0, flow=0, ext=()):
    """A 40-byte IPv6 header followed by the extension-header chain and ``payload``.

    ``nh`` is the protocol of ``payload`` (the last header in the chain). ``ext`` is a sequence of
    ``("hbh", options_bytes)`` (hop-by-hop; must come first, RFC 8200 4.1) and
    ``("frag", offset_in_8_byte_units, more_fragments, identification)`` entries, in wire order;
    the next-header fields are chained for you. The upper-layer checksum covers the whole
    unfragmented segment, so compute it before splitting a datagram into fragments.
    """
    _check("flow label", flow, 20)
    _check("traffic class", tc, 8)
    _check("hop limit", hop, 8)
    types, bodies = [], []
    for i, e in enumerate(ext):
        if e[0] == "hbh":
            if i:
                raise ValueError("hop-by-hop options header must come first")
            types.append(NH_HOPOPT)
            bodies.append(_hbh_body(e[1]))
        elif e[0] == "frag":
            _, off, more, ident = e
            _check("fragment offset", off, 13)
            types.append(NH_FRAG)
            bodies.append(struct.pack("!BHI", 0, (off << 3) | (1 if more else 0), ident))
        else:
            raise ValueError("unknown extension header %r" % (e[0],))
    chain = b"".join(bytes([t]) + b for t, b in zip(types[1:] + [nh], bodies))
    plen = len(chain) + len(payload)
    _check("payload length", plen, 16)
    first = types[0] if types else nh
    return struct.pack("!IHBB", 0x60000000 | tc << 20 | flow, plen, first, hop) + src + dst + chain + payload


def tcp6(src, dst, sport, dport, seq, ack, flags, window, payload=b"", options=b""):
    """A TCP segment with the IPv6 pseudo-header checksum (options zero-padded to 4 bytes)."""
    if len(options) % 4:
        options += b"\0" * (4 - len(options) % 4)
    doff = (5 + len(options) // 4) << 12
    seg = struct.pack("!HHIIHHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, doff | flags, window, 0, 0) \
        + options + payload
    return _with_csum(src, dst, NH_TCP, seg, 16)


def udp6(src, dst, sport, dport, payload):
    """A UDP datagram. The checksum is mandatory over IPv6 (RFC 8200 8.1); a computed 0 goes out as 0xFFFF."""
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    seg = _with_csum(src, dst, NH_UDP, seg, 6)
    return seg if seg[6:8] != b"\0\0" else seg[:6] + b"\xff\xff" + seg[8:]


def icmpv6(src, dst, typ, code, body):
    """An ICMPv6 message: type, code, checksum, then ``body`` (everything after the 4-byte header)."""
    return _with_csum(src, dst, NH_ICMPV6, struct.pack("!BBH", typ, code, 0) + body, 2)


def echo6(src, dst, ident, seq, data=b"", reply=False):
    """ICMPv6 echo request (type 128) or reply (129)."""
    return icmpv6(src, dst, 129 if reply else 128, 0, struct.pack("!HH", ident, seq) + data)


# ------------------------------------------------------------------ addressing helpers
def solicited_node(addr):
    """ff02::1:ffXX:XXXX built from the low 24 bits of a unicast address (RFC 4291 2.7.1)."""
    return _SOLICITED_PREFIX + addr[13:]


def mcast_mac6(addr):
    """The Ethernet destination for an IPv6 multicast address: 33:33 plus its low 32 bits (RFC 2464 7)."""
    if addr[0] != 0xFF:
        raise ValueError("not a multicast address")
    return b"\x33\x33" + addr[12:]


def _frame(smac, src, dst, nh, seg, dmac=None, hop=64, ext=()):
    if dmac is None:
        dmac = mcast_mac6(dst)
    return eth(dmac, smac, ETH_IPV6, ipv6(src, dst, nh, seg, hop=hop, ext=ext))


# ------------------------------------------------------------------ NDP and MLD (all hop limit 255 except MLD)
def _lla(kind, mac):
    return bytes([kind, 1]) + mac          # source (1) / target (2) link-layer address option


def ns(smac, src, target, dst=None, slla=True):
    """Neighbor Solicitation for ``target``. ``dst`` defaults to its solicited-node multicast address
    (so the frame goes to 33:33:ff:xx:xx:xx). Pass ``src=UNSPECIFIED, slla=False`` for duplicate address detection."""
    dst = dst or solicited_node(target)
    body = struct.pack("!I", 0) + target + (_lla(1, smac) if slla else b"")
    return _frame(smac, src, dst, NH_ICMPV6, icmpv6(src, dst, NS, 0, body), hop=255)


def na(smac, dmac, src, dst, target=None, flags=NA_SOLICITED | NA_OVERRIDE, tlla=True):
    """Neighbor Advertisement (unicast reply by default: solicited + override, target link-layer option)."""
    body = struct.pack("!I", flags) + (target or src) + (_lla(2, smac) if tlla else b"")
    return _frame(smac, src, dst, NH_ICMPV6, icmpv6(src, dst, NA, 0, body), dmac=dmac, hop=255)


def rs(smac, src, dst=ALL_ROUTERS, slla=True):
    """Router Solicitation to all-routers with a source link-layer option."""
    body = struct.pack("!I", 0) + (_lla(1, smac) if slla else b"")
    return _frame(smac, src, dst, NH_ICMPV6, icmpv6(src, dst, RS, 0, body), hop=255)


def ra(smac, src, dst=ALL_NODES, dmac=None, prefixes=(), mtu=None, lifetime=1800, cur_hop=64, flags=0,
       reachable=0, retrans=0, slla=True):
    """Router Advertisement. Options in order: source link-layer address, MTU, then one prefix-information
    option per ``(prefix16, prefix_len, valid, preferred[, flags])`` (flags default 0xC0 = on-link + autonomous)."""
    opts = _lla(1, smac) if slla else b""
    if mtu is not None:
        opts += struct.pack("!BBHI", 5, 1, 0, mtu)
    for p in prefixes:
        prefix, plen, valid, pref = p[:4]
        opts += struct.pack("!BBBBIII", 3, 4, plen, p[4] if len(p) > 4 else 0xC0, valid, pref, 0) + prefix
    body = struct.pack("!BBHII", cur_hop, flags, lifetime, reachable, retrans) + opts
    return _frame(smac, src, dst, NH_ICMPV6, icmpv6(src, dst, RA, 0, body), dmac=dmac, hop=255)


def mld_report(smac, src, groups, rtype=4):
    """MLDv2 Listener Report (RFC 3810) to ff02::16, hop limit 1, with the hop-by-hop Router Alert option.
    One record per group in ``groups``; ``rtype`` 4 is CHANGE_TO_EXCLUDE_MODE with no sources (a join)."""
    body = struct.pack("!HH", 0, len(groups)) + b"".join(struct.pack("!BBH", rtype, 0, 0) + g for g in groups)
    seg = icmpv6(src, MLDV2_ROUTERS, MLDV2_REPORT, 0, body)
    return _frame(smac, src, MLDV2_ROUTERS, NH_ICMPV6, seg, hop=1, ext=[("hbh", b"\x05\x02\x00\x00")])


# ------------------------------------------------------------------ VLAN tags
def eth_tag(frame, vid, pcp=0, dei=0, tpid=ETH_VLAN):
    """Insert a 4-byte VLAN tag (TPID, then PCP/DEI/VID) between the source MAC and the EtherType.

    A pure bytes transform: the result is exactly ``len(frame) + 4`` bytes, the tag is never padded
    or stripped, and no other byte changes. It must be applied to the frame as the engine builds it,
    BEFORE ``PcapWriter`` pads to its 60-byte minimum: the writer then pads the tagged frame, so a
    short frame costs no extra on-wire bytes (a 56-byte frame is 60 tagged or untagged) and the
    result still satisfies "padding only on frames of 60 bytes or fewer". Tagging a frame that is
    already padded would leave the padding inside the payload at 64 bytes, which is wrong.
    ``tpid`` 0x88A8 makes an 802.1ad service tag (see ``eth_qinq``).
    """
    _check("vid", vid, 12)
    _check("pcp", pcp, 3)
    _check("dei", dei, 1)
    return frame[:12] + struct.pack("!HH", tpid, pcp << 13 | dei << 12 | vid) + frame[12:]


def eth_qinq(frame, svid, cvid, spcp=0, cpcp=0):
    """802.1ad double tag: outer service tag (0x88A8, ``svid``) then inner customer tag (0x8100, ``cvid``)."""
    return eth_tag(eth_tag(frame, cvid, cpcp), svid, spcp, tpid=ETH_QINQ)


# ------------------------------------------------------------------ tunnel carriers
def gre(payload, proto=0x0800, key=None, seq=None):
    """GRE header (RFC 2784 with the RFC 2890 key and sequence extensions) followed by ``payload``.

    ``proto`` is the EtherType of ``payload`` (0x0800 IPv4, 0x86DD IPv6). The result is the body of
    an IPv4 packet with protocol 47; build the outer packet with ``ipv4_raw``. Inner TCP MSS: see ``MSS_GRE``.
    """
    flags = (0x2000 if key is not None else 0) | (0x1000 if seq is not None else 0)
    hdr = struct.pack("!HH", flags, proto)
    if key is not None:
        hdr += struct.pack("!I", key)
    if seq is not None:
        hdr += struct.pack("!I", seq)
    return hdr + payload


def vxlan(inner_frame, vni):
    """VXLAN header (RFC 7348: I flag set, 24-bit VNI) followed by the inner Ethernet frame. The result is
    the body of a UDP datagram to port 4789 (``udp_nocsum``); inner TCP MSS: see ``MSS_VXLAN``."""
    _check("vni", vni, 24)
    return struct.pack("!II", 0x08000000, vni << 8) + inner_frame


def vxlan_sport(inner_frame):
    """Source port with per-flow entropy in 49152-65535 from a CRC of the inner headers (RFC 7348 5)."""
    return 49152 + zlib.crc32(inner_frame[:54]) % 16384


def ipv4_raw(src, dst, proto, payload, ttl=64, ident=0, df=True, tos=0):
    """An IPv4 packet from 4-byte addresses: for outer tunnel headers, where no ``Host`` exists."""
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, tos, 20 + len(payload), ident, 0x4000 if df else 0, ttl, proto, 0, src, dst)
    return hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:] + payload


def udp_nocsum(sport, dport, payload):
    """A UDP datagram with checksum 0, which RFC 768 allows over IPv4 and RFC 7348 recommends for the outer VXLAN header."""
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


# ------------------------------------------------------------------ zero-draw address derivation
def _gid(ident):
    """The 40-bit ULA global ID (RFC 4193): a hash of the company identity (name and industry)."""
    return hashlib.sha256(("%s\n%s" % (ident.name, ident.industry)).encode()).digest()[:5]


def eui64(mac):
    """Modified EUI-64 interface ID (RFC 4291 Appendix A): ff:fe in the middle, universal/local bit flipped."""
    return bytes([mac[0] ^ 0x02]) + mac[1:3] + b"\xff\xfe" + mac[3:]


def ula(ident, subnet_id, mac):
    """A /64 ULA host address: fd + 40-bit global ID from the identity, 16-bit subnet ID (the third
    octet of the IPv4 subnet, or the VLAN id), interface ID by modified EUI-64 from the MAC."""
    _check("subnet id", subnet_id, 16)
    return b"\xfd" + _gid(ident) + struct.pack("!H", subnet_id) + eui64(mac)


def link_local(mac):
    """fe80::/64 link-local address with the modified EUI-64 interface ID from the MAC."""
    return b"\xfe\x80" + bytes(6) + eui64(mac)


def external(key):
    """A documentation-prefix (2001:db8::/32) address for an external host, the rest from a hash of ``key``."""
    return bytes.fromhex("20010db8") + hashlib.sha256(key.encode()).digest()[:12]
