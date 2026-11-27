"""Classic pcap -> pcapng converter (stdlib only), written beside the pcap after the build.

convert(pcap_path, out_path, ...) streams the capture once and writes a single-section little-endian
pcapng file: one Section Header Block, one Interface Description Block (Ethernet, microsecond
resolution, if_name/if_tsresol/if_fcslen set) and one Enhanced Packet Block per packet, in file order.
Timestamps are the pcap's own seconds + microseconds, so first/last time and packet count are equal to
the pcap's (the converter never rounds or reorders).

Options (both off by default):
  tags_path + comments  one opt_comment per packet carrying the scenario tag of that packet, read from
                        the tag sidecar (build_manifest.read_tags). A packet whose sidecar byte is not in
                        the table (the 255 overflow marker) gets no comment. The sidecar must have exactly
                        one byte per packet or ValueError is raised.
  keylog_path + embed_keys  embed the TLS key log as a Decryption Secrets Block (type "TLSK") so one file
                        decrypts in Wireshark. Off by default: the key log stays a separate file and the
                        pcapng then carries no secrets. Capped at MAX_KEYLOG bytes.
A nanosecond-magic classic pcap is read (ns -> us, truncating); a big-endian one is read too.

The result is a pure function of (pcap, sidecar, key log, options): same inputs, same bytes.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import safeio  # noqa: E402 - sys.path is set up first
import build_manifest as BM  # noqa: E402 - sys.path is set up first
MAX_KEYLOG = 64 << 20
SNAPLEN_CAP = 0xFFFFFFFF

# magic -> (byte order, divisor that turns the fraction field into microseconds)
_MAGICS = {b"\xd4\xc3\xb2\xa1": ("<", 1), b"\x4d\x3c\xb2\xa1": ("<", 1000),
           b"\xa1\xb2\xc3\xd4": (">", 1), b"\xa1\xb2\x3c\x4d": (">", 1000)}


def _pad(b):
    return b + b"\0" * (-len(b) & 3)


def _opt(code, val):
    return struct.pack("<HH", code, len(val)) + _pad(val)


def _block(typ, body):
    n = 12 + len(body)
    return struct.pack("<II", typ, n) + body + struct.pack("<I", n)


def _shb(comment):
    opts = _opt(4, b"OpenGenerator pcap-to-pcapng converter") + (_opt(1, comment.encode()) if comment else b"")
    return _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + opts + struct.pack("<HH", 0, 0))


def _idb(link, snaplen, name):
    opts = _opt(2, name.encode()) + _opt(9, b"\x06") + _opt(13, b"\x00") + struct.pack("<HH", 0, 0)
    return _block(1, struct.pack("<HHI", link, 0, snaplen) + opts)


def _dsb(keylog):
    return _block(0x0A, struct.pack("<II", 0x544C534B, len(keylog)) + _pad(keylog))


def convert(pcap_path, out_path, tags_path=None, comments=False, keylog_path=None, embed_keys=False,
            comment="", if_name="capture"):
    """Write out_path (atomically) and return {"packets", "first_ts", "last_ts", "comments", "embedded_keylog_bytes"}.
    first_ts/last_ts are (seconds, microseconds) tuples of the first and last packet, or None when empty."""
    table, body = (None, None)
    if comments:
        if not tags_path:
            raise ValueError("per-packet comments need the tag sidecar")
        table, body = BM.read_tags(tags_path)
    cbytes = {i: _opt(1, t.encode()) + struct.pack("<HH", 0, 0) for i, t in enumerate(table or ())}
    keys = b""
    if embed_keys:
        if not keylog_path or not os.path.isfile(keylog_path):
            raise ValueError("embedding the key log needs the key log file")
        if os.path.getsize(keylog_path) > MAX_KEYLOG:
            raise ValueError("key log is larger than %d bytes" % MAX_KEYLOG)
        with open(keylog_path, "rb") as k:
            keys = k.read()
    tmp = out_path + ".tmp"
    n = ncom = 0
    first = last = None
    try:
        with open(pcap_path, "rb") as src, safeio.create_new(tmp, "wb", buffering=1 << 20) as out:
            gh = src.read(24)
            if len(gh) < 24 or gh[:4] not in _MAGICS:
                raise ValueError("not a classic pcap")
            end, div = _MAGICS[gh[:4]]
            snaplen, link = struct.unpack(end + "II", gh[16:24])
            out.write(_shb(comment) + _idb(link, snaplen, if_name) + (_dsb(keys) if keys else b""))
            rec = struct.Struct(end + "IIII")
            head = struct.Struct("<IIIIIII")
            read, write, nb = src.read, out.write, len(body) if body is not None else 0
            while True:
                h = read(16)
                if len(h) < 16:
                    if h:
                        raise ValueError("truncated record header at packet %d" % (n + 1))
                    break
                s, f, cap, orig = rec.unpack(h)
                data = read(cap)
                if len(data) < cap:
                    raise ValueError("truncated packet %d" % (n + 1))
                us = s * 1000000 + f // div
                opt = b""
                if body is not None and n < nb and body[n] in cbytes:
                    opt = cbytes[body[n]]
                    ncom += 1
                pad = -cap & 3
                tot = 32 + cap + pad + len(opt)
                write(head.pack(6, tot, 0, us >> 32, us & 0xFFFFFFFF, cap, orig) + data + b"\0" * pad + opt
                      + struct.pack("<I", tot))
                if first is None:
                    first = (s, f // div)
                last = (s, f // div)
                n += 1
        if body is not None and nb != n:
            raise ValueError("tag sidecar has %d entries but the pcap has %d packets" % (nb, n))
        os.replace(tmp, out_path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass                                         # the temp file may not have been created
        raise
    return {"packets": n, "first_ts": first, "last_ts": last, "comments": ncom, "embedded_keylog_bytes": len(keys)}
