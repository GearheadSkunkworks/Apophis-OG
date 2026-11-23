#!/usr/bin/env python3
"""Verify a build manifest: file sizes and hashes, manifest_sha256, and the counter sums.

    python3 tools/verify_manifest.py <stem>.manifest.json

Exit 0 when everything matches; 1 with one line per problem otherwise. Files are resolved beside the
manifest and hashed in chunks.
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from build_manifest import canonical, sha256_file  # noqa: E402


def verify(path):
    problems = []
    with open(path, encoding="utf-8") as f:
        m = json.load(f)
    body = {k: v for k, v in m.items() if k != "manifest_sha256"}
    if hashlib.sha256(canonical(body)).hexdigest() != m.get("manifest_sha256"):
        problems.append("manifest_sha256 mismatch: the manifest was edited after it was written")
    base = os.path.dirname(os.path.abspath(path))
    for o in m.get("outputs", []):
        p = os.path.join(base, o["name"])
        if not os.path.isfile(p):
            problems.append("missing output: %s" % o["name"])
        elif os.path.getsize(p) != o["bytes"]:
            problems.append("size mismatch: %s (manifest %d, file %d)" % (o["name"], o["bytes"], os.path.getsize(p)))
        elif sha256_file(p) != o["sha256"]:
            problems.append("sha256 mismatch: %s" % o["name"])
    buckets = [s["observed"] for s in m.get("scenarios", [])] + [m.get("normal_day", {})]
    t = m.get("totals", {})
    for k in ("packets", "bytes"):
        if sum(b.get(k, 0) for b in buckets) != t.get(k):
            problems.append("%s: scenario buckets sum to %d, totals say %s"
                            % (k, sum(b.get(k, 0) for b in buckets), t.get(k)))
    return problems


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: verify_manifest.py <manifest.json>")
    try:
        bad = verify(sys.argv[1])
    except (OSError, ValueError, KeyError) as e:
        bad = ["cannot read manifest: %s" % e]
    for b in bad:
        print("FAIL:", b)
    print("OK: manifest verified" if not bad else "%d problem(s)" % len(bad))
    sys.exit(1 if bad else 0)
