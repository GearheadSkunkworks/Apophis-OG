"""Tunnel decapsulation for the independent checkers (--decap gre,vxlan,6in4). Standard library only; it does not
import anything from netgen, so it cannot share a bug with the generator.

``Decap(kinds).records(records)`` takes the checkers' (caplen, origlen, data) records and yields every one of
them unchanged, then, behind each tunnel packet, the packet it carries as one more record, so the checker
validates inner frames exactly as it does plain ones (and again for a tunnel inside a tunnel, up to 4 deep).

  gre    IP protocol 47: version 0, optional checksum/key/sequence, protocol 0x0800 or 0x86DD (a payload
         that is not IP is left alone); the inner packet gets a placeholder Ethernet header
  6in4   IP protocol 41 carrying IPv6; the inner packet gets a placeholder Ethernet header
  vxlan  UDP port 4789: flags 0x08 (I bit), reserved bytes zero; the inner Ethernet frame is yielded as it is

The tunnel envelope itself is checked and reported in ``problems`` as (record number, code, message):
gre.version, gre.checksum, gre.short, 6in4.version, vxlan.flags, vxlan.short, tunnel.fragment (a fragmented
tunnel packet that never completed). An outer IPv4 packet in fragments is reassembled first (offset, length
and the last fragment must tile the datagram; the first fragment must come before the rest); only datagrams
that start like a tunnel are held. Inner records are numbered after the file's own, so a finding in one reads
as "frame N" with N past the file's frame count.
"""
import struct

KINDS = ("gre", "vxlan", "6in4")
_PLACEHOLDER_MAC = b"\x02\x00\x00\x00\x00\x00" * 2
_MAX_DEPTH = 4


def _csum_ok(data):
    if len(data) & 1:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF


def _eth_for(pt, packet):
    """A placeholder Ethernet header for an inner IP packet. An IPv6 multicast destination gets its RFC 2464 MAC
    (33:33 plus the last 4 address bytes) so the IPv6 checker's multicast-MAC rule sees a consistent frame."""
    dst = b"\x33\x33" + packet[36:40] if pt == 0x86DD and len(packet) >= 40 and packet[24] == 0xFF else _PLACEHOLDER_MAC[:6]
    return dst + _PLACEHOLDER_MAC[6:] + struct.pack("!H", pt) + packet


class Decap:
    def __init__(self, kinds):
        kinds = set(kinds)
        if kinds - set(KINDS):
            raise ValueError("unknown tunnel kind(s): %s (known: %s)" % (", ".join(sorted(kinds - set(KINDS))), ", ".join(KINDS)))
        self.kinds, self.problems, self.decapped = kinds, [], 0
        self._frags = {}                    # (src, dst, proto, id) -> {"parts": {offset: bytes}, "end": int|None}

    @classmethod
    def parse(cls, text):
        """``Decap`` for a comma-separated kind list ("gre,vxlan"), or None for an empty one."""
        kinds = [k.strip() for k in (text or "").split(",") if k.strip()]
        return cls(kinds) if kinds else None

    def records(self, records, outer=True):
        """Every record, each followed by the packets it carries (``outer=False``: only the carried packets)."""
        self.n = 0
        for rec in records:
            self.n += 1
            if outer:
                yield rec
            yield from self._inner(rec[2], self.n, 0)
        for key in self._frags:
            self.problems.append((self.n, "tunnel.fragment", "a fragmented tunnel packet from %s never completed" % ".".join(map(str, key[0]))))

    def _inner(self, data, n, depth):
        """Yield the records carried by one Ethernet frame (and theirs, to _MAX_DEPTH)."""
        if depth >= _MAX_DEPTH or len(data) < 34:
            return
        et, off = struct.unpack_from("!H", data, 12)[0], 14
        while et in (0x8100, 0x88A8) and len(data) >= off + 4:
            et, off = struct.unpack_from("!H", data, off + 2)[0], off + 4
        if et != 0x0800 or len(data) < off + 20:
            return
        ip = data[off:]
        ihl, proto = (ip[0] & 15) * 4, ip[9]
        tot, ident, ffo = struct.unpack_from("!HHH", ip, 2)
        if ip[0] >> 4 != 4 or ihl < 20 or not ihl <= tot <= len(ip):
            return                          # the plain checker reports a malformed outer header
        if ffo & 0x3FFF:                    # a fragment (MF or offset)
            body = self._reassemble(ip, ihl, tot, ident, ffo, proto)
            if body is None:
                return
            ip, tot = ip[:ihl] + body, ihl + len(body)
        body = ip[ihl:tot]
        if proto == 47 and "gre" in self.kinds:
            yield from self._emit(self._gre(body, n), n, depth)
        elif proto == 41 and "6in4" in self.kinds:
            if body[:1] and body[0] >> 4 == 6:
                yield from self._emit(_eth_for(0x86DD, body), n, depth)
            else:
                self.problems.append((n, "6in4.version", "protocol 41 payload is not an IPv6 packet"))
        elif proto == 17 and "vxlan" in self.kinds and len(body) >= 8 and struct.unpack_from("!H", body, 2)[0] == 4789:
            if len(body) < 24:
                self.problems.append((n, "vxlan.short", "VXLAN datagram of %d bytes" % len(body)))
            elif body[8] != 0x08 or body[9:12] != b"\0\0\0" or body[15] != 0:
                self.problems.append((n, "vxlan.flags", "flags %#04x, reserved bytes must be zero and the I bit set" % body[8]))
            else:
                yield from self._emit(body[16:], n, depth)

    def _emit(self, frame, n, depth):
        if frame is None:
            return
        self.decapped += 1
        yield len(frame), len(frame), frame
        yield from self._inner(frame, n, depth + 1)

    def _gre(self, body, n):
        """The inner IP packet of a GRE payload as an Ethernet frame, or None (problem recorded, or not IP)."""
        if len(body) < 4:
            self.problems.append((n, "gre.short", "GRE header of %d bytes" % len(body)))
            return None
        flags, pt = struct.unpack_from("!HH", body, 0)
        hlen = 4 + 4 * bool(flags & 0x8000) + 4 * bool(flags & 0x2000) + 4 * bool(flags & 0x1000)
        if flags & 0x0007:
            self.problems.append((n, "gre.version", "GRE version %d" % (flags & 7)))
            return None
        if len(body) < hlen:
            self.problems.append((n, "gre.short", "GRE header needs %d bytes, %d present" % (hlen, len(body))))
            return None
        if flags & 0x8000 and not _csum_ok(body):
            self.problems.append((n, "gre.checksum", "bad GRE checksum"))
        if pt not in (0x0800, 0x86DD):
            return None
        return _eth_for(pt, body[hlen:])

    def _reassemble(self, ip, ihl, tot, ident, ffo, proto):
        """Add one fragment; return the whole datagram payload when it completes, else None. Only datagrams whose
        first fragment starts a tunnel (GRE, 6in4, or UDP to port 4789) are held."""
        key, mf, fo = (ip[12:16], ip[16:20], proto, ident), ffo & 0x2000, (ffo & 0x1FFF) * 8
        pl = ip[ihl:tot]
        g = self._frags.get(key)
        if g is None:
            tunnel = fo == 0 and ((proto == 47 and "gre" in self.kinds) or (proto == 41 and "6in4" in self.kinds)
                                  or (proto == 17 and "vxlan" in self.kinds and len(pl) >= 4 and struct.unpack_from("!H", pl, 2)[0] == 4789))
            if not tunnel:
                return None
            g = self._frags[key] = {"parts": {}, "end": None}
        g["parts"][fo] = pl
        if not mf:
            g["end"] = fo + len(pl)
        if g["end"] is None:
            return None
        out, pos = b"", 0
        for o in sorted(g["parts"]):
            if o != pos:
                return None                 # a hole (or overlap): keep waiting
            out += g["parts"][o]
            pos += len(g["parts"][o])
        if pos != g["end"]:
            return None
        del self._frags[key]
        return out
