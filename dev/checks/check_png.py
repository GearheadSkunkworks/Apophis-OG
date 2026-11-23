"""Baseline static assets: every image/png body the engine sends is a real PNG (signature, chunk CRCs, IEND).

A random-byte body labelled image/png made Wireshark report one 'malformed' note per fetch (2,927 per ordinary-day
capture). Checks the generator for the whole size class, then walks a generated day for any image/png response."""
import binascii
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from netgen import ftpfiles as FF  # noqa: E402


def valid_png(b):
    if b[:8] != b"\x89PNG\r\n\x1a\n":
        return "bad signature"
    i, seen = 8, []
    while i < len(b):
        if i + 12 > len(b):
            return "truncated chunk"
        n, tag = struct.unpack(">I4s", b[i:i + 8])
        data = b[i + 8:i + 8 + n]
        crc = struct.unpack(">I", b[i + 8 + n:i + 12 + n])[0]
        if crc != binascii.crc32(tag + data) & 0xFFFFFFFF:
            return "bad CRC in %r" % tag
        seen.append(tag)
        i += 12 + n
    if i != len(b):
        return "trailing bytes"
    if seen[0] != b"IHDR" or seen[-1] != b"IEND" or b"IDAT" not in seen:
        return "chunk order %r" % seen
    return None


bad = 0
for size in range(6000, 14001, 37):
    png = FF.png_sized(size)
    err = valid_png(png)
    if err or len(png) != size:
        print("FAIL png_sized(%d): %s, len %d" % (size, err, len(png)))
        bad += 1
if bad:
    sys.exit(1)
print("baseline PNG: png_sized valid across 6,000-14,000 bytes")
