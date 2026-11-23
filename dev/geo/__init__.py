"""Offline IPv4 -> country lookup (country level only, standard library only).

    geo.lookup("8.8.8.8")        -> {"cc": "US", "country": "United States of America", "lat": ..., "lon": ...}
    geo.lookup("10.0.0.1")       -> None   (reserved, private, benchmark, documentation, multicast, unallocated)
    geo.lookup_many(["1.1.1.1"]) -> {"1.1.1.1": {...}}

lat/lon is a representative point for the country (area-weighted centroid of its largest polygon), not the
location of the address. IPv6 and malformed input return None.

Data file `ipv4_country.bin` (written by tools/build_geo.py), all little-endian:
    4 bytes   magic "GEO4"
    4 bytes   N, length of the JSON header
    N bytes   JSON header {"built": date, "ranges": R, "countries": [[cc, name, lat, lon], ...]}
    rest      zlib stream holding R uint32 values (each range start, stored as the delta from the previous
              start) followed by R bytes (0 = no country, k = countries[k-1]).
A range runs from its start to the next start - 1. The table is decoded once, on first use.
"""
import json
import os
import struct
import threading
import zlib
from array import array
from bisect import bisect_right

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ipv4_country.bin")
_MAGIC = b"GEO4"

# (network, prefix length): never mapped to a country, whatever the registry data says.
_RESERVED = [
    (0x00000000, 8),     # 0/8 "this network"
    (0x0A000000, 8),     # 10/8 private
    (0x64400000, 10),    # 100.64/10 shared address space
    (0x7F000000, 8),     # 127/8 loopback
    (0xA9FE0000, 16),    # 169.254/16 link local
    (0xAC100000, 12),    # 172.16/12 private
    (0xC0000000, 24),    # 192.0.0/24 protocol assignments
    (0xC0000200, 24),    # 192.0.2/24 documentation
    (0xC0A80000, 16),    # 192.168/16 private
    (0xC6120000, 15),    # 198.18/15 benchmarking
    (0xC6336400, 24),    # 198.51.100/24 documentation
    (0xCB007100, 24),    # 203.0.113/24 documentation
    (0xE0000000, 4),     # 224/4 multicast
    (0xF0000000, 4),     # 240/4 reserved (includes broadcast)
]
_RESERVED_SPANS = [(n, n + (1 << (32 - p)) - 1) for n, p in _RESERVED]

_lock = threading.Lock()
_table = None  # (starts, codes, countries, built)


def _load():
    global _table
    if _table is not None:
        return _table
    with _lock:
        if _table is not None:
            return _table
        with open(_PATH, "rb") as fh:
            blob = fh.read()
        if blob[:4] != _MAGIC:
            raise ValueError("geo data file has a bad header")
        (hlen,) = struct.unpack_from("<I", blob, 4)
        head = json.loads(blob[8:8 + hlen].decode("utf-8"))
        body = zlib.decompress(blob[8 + hlen:])
        n = head["ranges"]
        deltas = array("I")
        deltas.frombytes(body[:4 * n])
        if struct.pack("=I", 1) != struct.pack("<I", 1):   # big-endian host
            deltas.byteswap()
        starts, acc = [], 0
        for d in deltas:
            acc += d
            starts.append(acc)
        codes = body[4 * n:5 * n]
        countries = [None] + [
            {"cc": c[0], "country": c[1], "lat": c[2], "lon": c[3]} for c in head["countries"]]
        _table = (starts, codes, countries, head.get("built"))
        return _table


def _parse(ip):
    """Strict dotted quad -> int, or None."""
    if not isinstance(ip, str):
        return None
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return None
    v = 0
    for p in parts:
        if not p.isascii() or not p.isdigit() or len(p) > 3:
            return None
        o = int(p)
        if o > 255:
            return None
        v = (v << 8) | o
    return v


def lookup(ip):
    """Return {"cc","country","lat","lon"} for a public IPv4 address string, else None."""
    v = _parse(ip)
    if v is None:
        return None
    for lo, hi in _RESERVED_SPANS:
        if lo <= v <= hi:
            return None
    starts, codes, countries, _ = _load()
    code = codes[bisect_right(starts, v) - 1]
    if code == 0:
        return None
    return dict(countries[code])


def lookup_many(ips):
    """Map each address in `ips` to its lookup() result (None where unknown)."""
    return {ip: lookup(ip) for ip in ips}


def info():
    """Dataset facts: build date, number of ranges and countries."""
    starts, _codes, countries, built = _load()
    return {"built": built, "ranges": len(starts), "countries": len(countries) - 1}
