#!/usr/bin/env python3
"""Cut a time/tag slice of one scenario out of a finished build (stdlib only, imports nothing from netgen).

Records are copied VERBATIM (header and bytes) from a classic pcap into a new classic pcap; the source
pcap, manifest and tag sidecar are only read. All time handling is by epoch seconds.

Kinds
  A  window slice   every packet in [first_ts - ctx, last_ts + ctx] of the scenario's `observed` span.
                    No tag sidecar needed. Includes concurrent scenarios (a "does the sensor see it" cut).
  B  pure slice     baseline packets plus ONLY the target scenario's packets, inside the union of its
                    manifest `active_spans` (+ctx). Needs <stem>.tags.
  C  scenario-only  only the scenario's packets (baseline policy defaults to none). Needs <stem>.tags.
Baseline = any tag not starting with "incident:". --baseline picks how much context B/C carry:
  none = no baseline, window = baseline inside the padded spans (B default), full = every baseline packet.
B and C are experiments: the sensor sees a different traffic mix than the all-in-one capture.

Output: <stem>.slice.<scenario>.<kind>.pcap + a .json sidecar citing the source pcap sha256 and
manifest_sha256 (both read from the manifest, never computed over the pcap), the spans used and the
original packet numbers (1-based) of each kept span, so tcpreplay --include=FIRST-LAST can do it by hand.
"""
import argparse
import bisect
import hashlib
import json
import os
import struct
import re
import sys
import tempfile

SCENARIO_ID_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")   # no slash, no leading dot: safe in a file name
PAD_S = 1.0                    # the writer truncates to microseconds; bounds from the manifest can miss by < 1 us
DEFAULT_CTX_S = 300.0
MAGICS = {0xA1B2C3D4: ("<", 1e-6), 0xD4C3B2A1: (">", 1e-6), 0xA1B23C4D: ("<", 1e-9), 0x4D3CB2A1: (">", 1e-9)}
CHUNK = 8 << 20
MAX_REC = 16 + 262144 * 4      # keep at least one whole record in the buffer


class SliceError(ValueError):
    pass


def load_manifest(path):
    with open(path, encoding="utf-8") as f:
        m = json.load(f)
    want = m.get("manifest_sha256")
    body = {k: v for k, v in m.items() if k != "manifest_sha256"}
    got = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    if not want or got != want:
        raise SliceError("manifest_sha256 missing or does not match the manifest content (edited?): %s" % path)
    return m


def load_tags(path):
    """-> (tag table, bytes of tag ids). Same format as build_manifest.read_tags."""
    with open(path, "rb") as f:
        if f.readline() != b"OGTAGS1\n":
            raise SliceError("not a tag sidecar: %s" % path)
        h = json.loads(f.readline())
        body = f.read()
    if len(body) != h["packets"]:
        raise SliceError("tag sidecar truncated: %s" % path)
    return h["tags"], body


def _intervals(spans, ctx):
    """Pad [t0, t1] spans by ctx + PAD_S and merge overlaps -> sorted [[lo, hi], ...]."""
    out = []
    for t0, t1 in sorted((s[0], s[1]) for s in spans):
        lo, hi = t0 - ctx - PAD_S, t1 + ctx + PAD_S
        if out and lo <= out[-1][1]:
            out[-1][1] = max(out[-1][1], hi)
        else:
            out.append([lo, hi])
    return out


def slice_pcap(pcap, kind, scenario, manifest=None, tags=None, ctx=DEFAULT_CTX_S, baseline=None, out_dir=None):
    """Write the slice and its sidecar; return the sidecar dict plus "pcap_out"/"json_out" paths."""
    kind = kind.upper()
    if kind not in ("A", "B", "C"):
        raise SliceError("kind must be A, B or C")
    if ctx < 0:
        raise SliceError("ctx must be >= 0")
    base = pcap[:-5] if pcap.endswith(".pcap") else pcap
    m = load_manifest(manifest or base + ".manifest.json")
    scs = m.get("scenarios", [])
    sc = next((s for s in scs if s.get("id") == scenario), None)
    if sc is None:
        raise SliceError("scenario %r is not in the manifest (have: %s)" % (scenario, ", ".join(s["id"] for s in scs)))
    if not SCENARIO_ID_RE.fullmatch(sc["id"]):      # the manifest seal is a self-hash: its ids are untrusted
        raise SliceError("scenario id %r is not a plain name (letters, digits, '_', '.', '-'), so no file is named after it"
                         % sc["id"][:70])
    baseline = baseline or ("none" if kind == "C" else "window")
    if baseline not in ("none", "window", "full"):
        raise SliceError("baseline must be none, window or full")

    name = os.path.basename(pcap)
    row = next((o for o in m.get("outputs", []) if os.path.basename(o["name"]) == name), None)
    if row is None or not row.get("sha256"):
        raise SliceError("pcap %s is not listed in the manifest outputs (wrong manifest?)" % name)
    if os.path.getsize(pcap) != row["bytes"]:
        raise SliceError("pcap size %d differs from the manifest (%d): not the pcap this manifest describes"
                         % (os.path.getsize(pcap), row["bytes"]))
    total = (m.get("totals") or {}).get("packets")

    cls, tag_body = None, b""
    if kind == "A":
        ob = sc.get("observed") or {}
        if ob.get("first_ts") is None:
            raise SliceError("scenario %r emitted no packets" % scenario)
        spans = [[ob["first_ts"], ob["last_ts"]]]
    else:
        if not sc.get("active_spans"):
            raise SliceError("manifest has no active_spans for %r: rebuild with the tag sidecar option (tag_sidecar) "
                             "so kinds B and C can be cut" % scenario)
        spans = [[s[0], s[1]] for s in sc["active_spans"]]
        tags = tags or base + ".tags"
        if not os.path.isfile(tags):
            raise SliceError("tag sidecar not found: %s (rebuild with the tag sidecar option)" % tags)
        table, tag_body = load_tags(tags)
        if total is not None and len(tag_body) != total:
            raise SliceError("tag sidecar has %d packets, manifest says %d" % (len(tag_body), total))
        target = "incident:" + scenario
        if target not in table:
            raise SliceError("tag table has no %r tag" % target)
        cls = [3] * 256                                              # 3 = unknown id: dropped
        for i, t in enumerate(table):
            cls[i] = 2 if t == target else (0 if t.startswith("incident:") else 1)   # 0 other incident, 1 baseline, 2 target
    iv = _intervals(spans, ctx)
    los = [x[0] for x in iv]
    stats = [[0, None, None] for _ in iv]                            # kept, first_no, last_no per interval
    outside = kept = no = 0                                          # outside: baseline=full packets beyond every interval
    first_ts = last_ts = None

    out_dir = out_dir or os.path.dirname(os.path.abspath(pcap))
    stem = "%s.slice.%s.%s" % (os.path.basename(base), scenario, kind)
    p_out, j_out = os.path.join(out_dir, stem + ".pcap"), os.path.join(out_dir, stem + ".json")
    fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".slice-", suffix=".tmp")
    try:
        with open(pcap, "rb") as fi, os.fdopen(fd, "wb") as fo:
            hdr = fi.read(24)
            if len(hdr) < 24 or struct.unpack("<I", hdr[:4])[0] not in MAGICS:
                raise SliceError("not a classic pcap (pcapng is not supported): %s" % pcap)
            end, res = MAGICS[struct.unpack("<I", hdr[:4])[0]]
            unpack = struct.Struct(end + "IIII").unpack_from
            fo.write(hdr)
            buf, pos, eof = b"", 0, False
            while True:
                if len(buf) - pos < MAX_REC and not eof:
                    more = fi.read(CHUNK)
                    if more:
                        buf, pos = buf[pos:] + more, 0
                    else:
                        eof = True
                if len(buf) - pos < 16:
                    if len(buf) - pos:
                        raise SliceError("truncated record header after packet %d" % no)
                    break
                s, f, incl, _orig = unpack(buf, pos)
                nxt = pos + 16 + incl
                if nxt > len(buf):
                    raise SliceError("truncated record at packet %d" % (no + 1))
                no += 1
                ts = s + f * res
                k = bisect.bisect_right(los, ts) - 1
                inside = k >= 0 and ts <= iv[k][1]
                if cls is None:
                    keep = inside
                else:
                    c = cls[tag_body[no - 1]] if no <= len(tag_body) else 3
                    keep = inside if c == 2 else (c == 1 and (baseline == "full" or (baseline == "window" and inside)))
                if keep:
                    fo.write(buf[pos:nxt])
                    kept += 1
                    if first_ts is None:
                        first_ts = ts
                    last_ts = ts
                    if inside:
                        st = stats[k]
                        st[0] += 1
                        if st[1] is None:
                            st[1] = no
                        st[2] = no
                    else:
                        outside += 1
                pos = nxt
        if total is not None and no != total:
            raise SliceError("pcap has %d packets, manifest says %d" % (no, total))
        if cls is not None and len(tag_body) != no:
            raise SliceError("tag sidecar has %d packets, pcap has %d" % (len(tag_body), no))
        os.chmod(tmp, 0o644)                        # mkstemp makes 0600; a capture is shared with other tools
        os.replace(tmp, p_out)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

    side = {"schema_version": 1, "kind": kind, "scenario": scenario,
            "baseline": baseline if kind != "A" else "n/a (all packets in window)",
            "ctx_s": ctx, "pad_s": PAD_S, "source_pcap": name, "source_pcap_sha256": row["sha256"],
            "manifest_sha256": m["manifest_sha256"], "source_packets": no, "kept_packets": kept,
            "first_ts": first_ts, "last_ts": last_ts, "spans_used": spans,
            "kept_spans": [{"from_ts": a, "to_ts": b, "kept_packets": st[0], "first_packet_no": st[1], "last_packet_no": st[2]}
                           for (a, b), st in zip(iv, stats)],
            "kept_outside_spans": outside}
    fd, jtmp = tempfile.mkstemp(dir=out_dir, prefix=".slice-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(side, f, indent=2)
            f.write("\n")
        os.chmod(jtmp, 0o644)
        os.replace(jtmp, j_out)
    finally:
        if os.path.exists(jtmp):
            os.remove(jtmp)
    return dict(side, pcap_out=p_out, json_out=j_out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("pcap")
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--kind", required=True, choices=["A", "B", "C", "a", "b", "c"])
    ap.add_argument("--ctx", type=float, default=DEFAULT_CTX_S, help="context seconds around the span(s), default 300")
    ap.add_argument("--baseline", choices=["none", "window", "full"], help="B/C baseline context (B: window, C: none)")
    ap.add_argument("--manifest", help="default <stem>.manifest.json")
    ap.add_argument("--tags", help="default <stem>.tags (B and C)")
    ap.add_argument("--out-dir", help="default: beside the pcap")
    a = ap.parse_args(argv)
    try:
        r = slice_pcap(a.pcap, a.kind, a.scenario, a.manifest, a.tags, a.ctx, a.baseline, a.out_dir)
    except (SliceError, OSError, ValueError) as e:
        print("slice_pcap: %s" % e, file=sys.stderr)
        return 1
    print("%s: %d of %d packets" % (r["pcap_out"], r["kept_packets"], r["source_packets"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
