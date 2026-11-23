# geo: offline IPv4 country lookup

Country-level lookup for IPv4 addresses, used by the campaign board to place indicators on a map. No network access
at run time; standard library only.

    import geo
    geo.lookup("8.8.8.8")     # {"cc": "US", "country": "...", "lat": 39.53, "lon": -99.14}
    geo.lookup("10.0.0.1")    # None (private, loopback, link local, shared, benchmark, documentation, multicast, 240/4)
    geo.lookup_many(ips)      # {ip: result or None}
    geo.info()                # build date, number of ranges and countries

`lat`/`lon` is a representative point for the country (area-weighted centroid of its largest polygon), not the
position of the address. IPv6 and malformed input return None. The table decodes lazily on first use (about 0.2 s,
about 150,000 ranges) and a lookup is a binary search (roughly 600,000 per second on a laptop).

## Files

| file | purpose | size |
|---|---|---|
| `geo/__init__.py` | lookup module; the file layout is described in its docstring | 4 KB |
| `geo/ipv4_country.bin` | sorted range table, delta-coded and zlib-compressed, with country names and points | 176 KB |
| `ui/geo-world.json` | simplified country outlines for the map: `{"countries": [{cc, name, lat, lon, polygons}]}` | 212 KB |
| `tools/build_geo.py` | rebuilds both files from the source files below | |

## Sources and licences

Build date: 2026-11-19 (the date the sources were downloaded and the files generated).

- IPv4 ranges: the "extended latest" delegation files published by the five regional internet registries, APNIC,
  RIPE NCC, ARIN, LACNIC and AFRINIC (`delegated-<registry>-extended-latest`). Only `allocated` and `assigned` IPv4
  records are used; adjacent blocks with the same country are merged, and gaps are stored as "no country". The
  registries publish these statistics for public use; keep the source attribution when redistributing.
- Outlines and names: Natural Earth 1:10m Cultural Vectors, Admin 0 Countries (`ne_10m_admin_0_countries.geojson`,
  from the public `natural-earth-vector` repository). Natural Earth is in the public domain. Outlines are simplified
  (Douglas-Peucker, 0.2 degree tolerance, 2 decimals, islands under 0.15 square degrees dropped except a country's
  largest piece), so they are for display only.
- Eight registry codes have no separate outline in that dataset (BQ, EU, GF, GP, MQ, RE, TK, YT). They get an
  approximate hand-set point in `tools/build_geo.py`. `EU` is the registry's placeholder for pan-European blocks,
  not a country.

## Limits

- The registry country is where the block was allocated or assigned, not where a given host sits. Anycast, cloud and
  transferred blocks can differ from physical location.
- The data is a snapshot; it ages as blocks are transferred. Rebuild when it matters.

## Rebuilding

    python tools/build_geo.py --src /path/to/scratch --download

`--download` fetches the six source files into the scratch directory once (do not point it inside the repository).
Without it the script reads files already there.
