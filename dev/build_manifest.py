"""Per-scenario counters and the per-build manifest (<stem>.manifest.json).

Counters come from Engine.stats, which the engine already updates once per packet in its single
write path, so there is no extra pass. Bytes are pcap bytes (padded frame + 16-byte record header),
the same figure as PcapWriter.bytes, so the buckets sum exactly to the build total.

The manifest records what was placed, never where: no hosts, addresses, credentials or indicator
values. The threat collection is referenced by file name and hash only. `manifest_sha256` covers the
canonical JSON of everything else, so an edit is detectable (tools/verify_manifest.py checks it).
"""
import hashlib
import json
import os
import time

SCHEMA_VERSION = 1
NORMAL_DAY = "normal-day"
SLACK_BEFORE_S = 300                    # a scenario may start this long before its window (set-up traffic)
SLACK_AFTER_S = 1800                    # and run this long after it (retries, follow-on traffic, clean-up)


def by_scenario(stats, selected, total_packets, total_bytes):
    """-> (by_scenario dict, consistency dict). Never raises."""
    out = {n: {"packets": 0, "bytes": 0, "first_ts": None, "last_ts": None} for n in [NORMAL_DAY] + list(selected)}
    for tag, st in stats.items():
        name = tag[len("incident:"):] if tag.startswith("incident:") else NORMAL_DAY
        b = out.setdefault(name, {"packets": 0, "bytes": 0, "first_ts": None, "last_ts": None})
        b["packets"] += st[0]
        b["bytes"] += st[2]
        b["first_ts"] = st[3] if b["first_ts"] is None else min(b["first_ts"], st[3])
        b["last_ts"] = st[4] if b["last_ts"] is None else max(b["last_ts"], st[4])
    dp = sum(b["packets"] for b in out.values()) - total_packets
    db = sum(b["bytes"] for b in out.values()) - total_bytes
    ok = dp == 0 and db == 0
    return out, ({"counters_consistent": True} if ok else
                 {"counters_consistent": False, "counters_delta": {"packets": dp, "bytes": db}})


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def seal(m):
    m = {k: v for k, v in m.items() if k != "manifest_sha256"}
    m["manifest_sha256"] = hashlib.sha256(canonical(m)).hexdigest()
    return m


def _outputs(base_dir, paths):
    rows, seen = [], set()
    for p in paths:
        if not p or not os.path.isfile(p):
            continue
        rel = os.path.relpath(os.path.realpath(p), os.path.realpath(base_dir))
        if rel.startswith("..") or rel in seen:
            continue
        seen.add(rel)
        rows.append({"name": rel, "bytes": os.path.getsize(p), "sha256": sha256_file(p)})
    return sorted(rows, key=lambda r: r["name"])


def write(out, version, parameters, selected, registry, resolve_window, day_start, buckets, consistency,
          totals, extra_paths, meta_get):
    """Write <stem>.manifest.json atomically beside `out`; returns its path."""
    base_dir = os.path.dirname(os.path.abspath(out))
    scenarios = []
    for n in selected:
        inc = registry[n]
        w0, w1 = resolve_window(inc.window)
        pw = {"start_min": round((w0 - day_start) / 60), "end_min": round((w1 - day_start) / 60)}
        ob = buckets.get(n) or {"packets": 0, "bytes": 0, "first_ts": None, "last_ts": None}
        inside = (ob["first_ts"] is not None and ob["first_ts"] >= w0 - SLACK_BEFORE_S
                  and ob["last_ts"] <= w1 + SLACK_AFTER_S)
        try:
            meta = meta_get(n) or {}
        except Exception:                                    # noqa: BLE001 -- metadata is descriptive only
            meta = {}
        scenarios.append({"id": n, "family": inc.prefix, "title": inc.title, "planned_window": pw,
                          "observed": dict(ob), "declared_protocols": list(meta.get("protocols") or []),
                          "size_behaviour": (meta.get("scale") or {}).get("behaviour"),
                          "emitted_in_window": bool(inside)})
    m = {"schema_version": SCHEMA_VERSION, "generator": version,
         "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "parameters": parameters, "window_slack_s": {"before": SLACK_BEFORE_S, "after": SLACK_AFTER_S},
         "outputs": _outputs(base_dir, [out] + list(extra_paths)),
         "totals": totals, "scenarios": scenarios, "normal_day": dict(buckets[NORMAL_DAY])}
    m.update(consistency)
    m = seal(m)
    path = (out[:-5] if out.endswith(".pcap") else out) + ".manifest.json"
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(m, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)
    return path
