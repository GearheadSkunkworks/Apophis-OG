#!/usr/bin/env python3
"""Rebuild the bundled geography data (developer tool; run time never needs the network).

Outputs:
  dev/geo/ipv4_country.bin   zlib-compressed sorted range table (see dev/geo/__init__.py for the layout)
  dev/ui/geo-world.json      simplified country outlines for the map

Inputs (give a directory, or let --download fetch them once):
  delegated-{apnic,ripencc,arin,lacnic,afrinic}-extended-latest   (the five regional registry delegation files)
  ne_10m_admin_0_countries.geojson                                (public-domain world-countries dataset)

Usage:  python tools/build_geo.py --src /path/to/scratch [--download]
"""
import argparse
import datetime
import json
import math
import os
import struct
import sys
import urllib.request
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)

SOURCES = {
    "delegated-apnic-extended-latest": "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "delegated-ripencc-extended-latest": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
    "delegated-arin-extended-latest": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "delegated-lacnic-extended-latest": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "delegated-afrinic-extended-latest": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
    "ne_10m_admin_0_countries.geojson":
        "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_10m_admin_0_countries.geojson",
}

MAGIC = b"GEO4"
TOLERANCE = 0.2       # degrees, Douglas-Peucker
MIN_AREA = 0.15       # square degrees; smaller islands are dropped (the largest polygon is always kept)


def download(src):
    os.makedirs(src, exist_ok=True)
    for name, url in SOURCES.items():
        path = os.path.join(src, name)
        if not os.path.exists(path):
            print("downloading", url)
            urllib.request.urlretrieve(url, path)


# ---------------------------------------------------------------- IPv4 ranges
def read_delegations(src):
    """Return sorted [(start, count, cc)] for allocated/assigned IPv4 blocks."""
    rows = []
    for name in SOURCES:
        if not name.startswith("delegated-"):
            continue
        with open(os.path.join(src, name), encoding="ascii", errors="replace") as fh:
            for line in fh:
                if line.startswith("#"):
                    continue
                p = line.rstrip("\n").split("|")
                if len(p) < 7 or p[2] != "ipv4" or p[6] not in ("allocated", "assigned"):
                    continue
                cc = p[1].strip().upper()
                if len(cc) != 2 or not cc.isalpha():
                    continue
                parts = [int(x) for x in p[3].split(".")]
                start = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
                rows.append((start, int(p[4]), cc))
    rows.sort()
    return rows


def build_table(rows):
    """Flatten to boundaries: starts[i] begins a run with code codes[i] (0 = no country)."""
    ccs = sorted({r[2] for r in rows})
    index = {cc: i + 1 for i, cc in enumerate(ccs)}
    starts, codes = [], []
    cursor = 0

    def push(s, c):
        if codes and codes[-1] == c:
            return
        starts.append(s)
        codes.append(c)

    push(0, 0)
    for s, n, cc in rows:
        if s < cursor:           # overlap (should not happen); keep first
            continue
        if s > cursor:
            push(cursor, 0)
        push(s, index[cc])
        cursor = s + n
    if cursor < 1 << 32:
        push(cursor, 0)
    return ccs, starts, codes


# Territories the outline dataset does not carry as separate shapes (approximate representative points).
FALLBACK = {
    "BQ": ("Bonaire, Sint Eustatius and Saba", 12.2, -68.3), "EU": ("European Union (unspecified)", 50.0, 10.0),
    "GF": ("French Guiana", 4.0, -53.0), "GP": ("Guadeloupe", 16.2, -61.6), "MQ": ("Martinique", 14.6, -61.0),
    "RE": ("Reunion", -21.1, 55.5), "TK": ("Tokelau", -9.2, -171.8), "YT": ("Mayotte", -12.8, 45.2),
}


def write_table(path, ccs, starts, codes, built, world):
    by = {c["cc"]: c for c in world}
    info = []
    for cc in ccs:
        if cc in by:
            info.append([cc, by[cc]["name"], by[cc]["lat"], by[cc]["lon"]])
        elif cc in FALLBACK:
            info.append([cc] + list(FALLBACK[cc]))
        else:
            info.append([cc, cc, None, None])
    meta = json.dumps({"built": built, "countries": info, "ranges": len(starts)},
                       separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    # starts are stored as 32-bit deltas from the previous start so zlib compresses them well
    deltas = [starts[0]] + [starts[i] - starts[i - 1] for i in range(1, len(starts))]
    body = struct.pack("<%dI" % len(deltas), *deltas) + bytes(codes)
    blob = MAGIC + struct.pack("<I", len(meta)) + meta + zlib.compress(body, 9)
    with open(path, "wb") as fh:
        fh.write(blob)
    return len(blob)


# ---------------------------------------------------------------- outlines
def dp(points, tol):
    if len(points) < 3:
        return points
    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]
    while stack:
        a, b = stack.pop()
        ax, ay = points[a]
        bx, by = points[b]
        dx, dy = bx - ax, by - ay
        norm = math.hypot(dx, dy)
        best, bi = -1.0, -1
        for i in range(a + 1, b):
            px, py = points[i]
            d = (math.hypot(px - ax, py - ay) if norm == 0
                 else abs(dy * (px - ax) - dx * (py - ay)) / norm)
            if d > best:
                best, bi = d, i
        if best > tol:
            keep[bi] = True
            stack += [(a, bi), (bi, b)]
    return [p for p, k in zip(points, keep, strict=False) if k]


def ring_area_centroid(ring):
    a = cx = cy = 0.0
    for i in range(len(ring) - 1):
        x0, y0 = ring[i]
        x1, y1 = ring[i + 1]
        c = x0 * y1 - x1 * y0
        a += c
        cx += (x0 + x1) * c
        cy += (y0 + y1) * c
    a /= 2
    if abs(a) < 1e-12:
        xs = [p[0] for p in ring]
        ys = [p[1] for p in ring]
        return 0.0, (min(xs) + max(xs)) / 2, (min(ys) + max(ys)) / 2
    return abs(a), cx / (6 * a), cy / (6 * a)


def build_world(path_in):
    with open(path_in, encoding="utf-8") as fh:
        data = json.load(fh)
    out = {}
    for ft in data["features"]:
        pr = ft["properties"]
        cc = None
        for key in ("ISO_A2_EH", "ISO_A2", "WB_A2", "POSTAL"):
            v = pr.get(key)
            if v and v != "-99" and len(v) == 2:
                cc = v.upper()
                break
        if not cc:
            continue
        g = ft["geometry"]
        polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
        outer = [p[0] for p in polys if p]
        if not outer:
            continue
        sized = sorted(((ring_area_centroid(r), r) for r in outer), key=lambda t: -t[0][0])
        (_, clon, clat), _big = sized[0]
        keep = []
        for (area, _, _), ring in sized:
            if area < MIN_AREA and keep:
                continue
            pts = [tuple(p[:2]) for p in ring]
            span = max(max(x for x, _ in pts) - min(x for x, _ in pts), max(y for _, y in pts) - min(y for _, y in pts))
            s = dp(pts, min(TOLERANCE, span / 12))
            if len(s) >= 4:
                keep.append([[round(x, 2), round(y, 2)] for x, y in s])
        if not keep:
            continue
        ent = out.setdefault(cc, {"cc": cc, "name": pr.get("NAME") or pr.get("ADMIN") or cc,
                                  "lat": round(clat, 2), "lon": round(clon, 2), "polygons": []})
        ent["polygons"] += keep
    return sorted(out.values(), key=lambda c: c["cc"])


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", required=True, help="directory holding (or receiving) the source files")
    ap.add_argument("--download", action="store_true", help="fetch missing source files first")
    args = ap.parse_args(argv)
    if args.download:
        download(args.src)
    built = datetime.date.today().isoformat()

    world = build_world(os.path.join(args.src, "ne_10m_admin_0_countries.geojson"))
    rows = read_delegations(args.src)
    ccs, starts, codes = build_table(rows)
    size = write_table(os.path.join(DEV, "geo", "ipv4_country.bin"), ccs, starts, codes, built, world)
    print("ranges: %d (from %d delegations), countries: %d, ipv4_country.bin: %d bytes"
          % (len(starts), len(rows), len(ccs), size))

    with open(os.path.join(DEV, "ui", "geo-world.json"), "w", encoding="utf-8") as fh:
        json.dump({"countries": world}, fh, separators=(",", ":"), ensure_ascii=False)
    print("outline countries: %d, geo-world.json: %d bytes"
          % (len(world), os.path.getsize(os.path.join(DEV, "ui", "geo-world.json"))))
    have = {c["cc"] for c in world}
    print("registry countries without an outline:", " ".join(c for c in ccs if c not in have) or "none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
