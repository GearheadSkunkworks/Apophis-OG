#!/usr/bin/env python3
"""Deterministic, stdlib-only fuzz harness for the untrusted-input parsers.

Targets: intel.parsers (text/CSV/STIX/MISP/OTX/ThreatFox/auto), intel.classify, intel.filters,
every feed's `parse` in intel.sources.FEEDS (and the fetch pipeline with the network stubbed),
netgen.campaign.schema (load/validate/normalise), the compiler, and the campaign_api route
functions for the intel and campaign routes.

Every call must (a) raise nothing except ValueError/CampaignError/FeedError/ApiError, (b) finish in
under TIME_BUDGET seconds, (c) stay inside a tracemalloc peak budget, and (d) return IOC records
that satisfy dev/docs/campaign-m1-contracts.md section 1 with no control characters in `value`.

    python tools/fuzz.py --iterations 20000 --seed 1
    python tools/fuzz.py --hostile-only
Exit status 1 when any failure is found; failures print the target, a reason and a repro head.
No network, no git; the only files written are in a temp directory.
"""
import argparse
import json
import os
import random
import signal
import sys
import tempfile
import time
import tracemalloc
import unicodedata
import zlib
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
if DEV not in sys.path:
    sys.path.insert(0, DEV)

_TMP = tempfile.mkdtemp(prefix="ogfuzz-")
os.environ["OPENGENERATOR_CACHE"] = os.path.join(_TMP, "cache")
os.environ["OPENGENERATOR_CAMPAIGNS"] = os.path.join(_TMP, "lib")

import campaign_api                                    # noqa: E402
from intel import classify, filters, model, parsers, sources   # noqa: E402
from netgen.campaign import compiler, schema           # noqa: E402

TIME_BUDGET = 2.0
HANG_ALARM = 20           # seconds; a call that does not return is aborted and reported
BASE_MEM = 96 * 1024 * 1024
MEM_PER_BYTE = 40
FIXTURES = os.path.join(DEV, "tests", "fixtures")
ALLOWED = (ValueError, sources.FeedError, campaign_api.ApiError)   # CampaignError is a ValueError

TYPES = set(model.TYPES)
ROLES = set(model.ROLES)
IOC_KEYS = {"type", "value", "role", "confidence", "source", "tags", "techniques", "first_seen", "note", "why"}
ROUTES = ("/api/intel/parse", "/api/intel/fetch", "/api/campaign/compile", "/api/campaign/validate",
          "/api/campaign/estimate", "/api/campaign/library/import", "/api/campaign/library/save",
          "/api/campaign/library/load", "/api/campaign/library/delete", "/api/campaign/diagram")


# ---------------------------------------------------------------- contract
def contract_problems(rec, strict=True):
    """Problems with one IOC record versus contract section 1 (empty list = fine).

    strict=False is for campaign-compiler output: values are schema-valid but need not re-classify
    (a hand-written filename may be anything), and note/why may keep tab/newline."""
    p = []
    if not isinstance(rec, dict):
        return ["record is not a dict"]
    if set(rec) != IOC_KEYS:
        p.append("keys differ: %s" % sorted(set(rec) ^ IOC_KEYS))
    t, v = rec.get("type"), rec.get("value")
    if t not in TYPES:
        p.append("bad type %r" % (t,))
    if not isinstance(v, str) or not v:
        p.append("value is not a non-empty string")
    else:
        bad = [c for c in v if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp", "Cs")]
        if bad:
            p.append("control/format character in value: %r" % ("".join(bad[:4]),))
        if len(v) > 2048:
            p.append("value longer than 2048")
        if t in ("domain", "md5", "sha1", "sha256") and v != v.lower():
            p.append("value not lower case")
        if strict and t in TYPES:
            ct, canon = classify.classify_value(v)
            if ct != t:
                p.append("value %r does not re-classify as %s (got %s)" % (v[:60], t, ct))
    if rec.get("role") not in ROLES:
        p.append("bad role %r" % (rec.get("role"),))
    c = rec.get("confidence")
    if not (isinstance(c, int) and not isinstance(c, bool) and 0 <= c <= 100):
        p.append("bad confidence %r" % (c,))
    if not isinstance(rec.get("source"), str):
        p.append("source not str")
    for k in ("tags", "techniques"):
        if not (isinstance(rec.get(k), list) and all(isinstance(x, str) for x in rec[k])):
            p.append("%s not list of str" % k)
    for x in rec.get("techniques") or []:
        if isinstance(x, str) and not model._TECH.match(x):
            p.append("bad technique %r" % x[:20])
    fs = rec.get("first_seen")
    if fs is not None and not isinstance(fs, str):
        p.append("first_seen not str/None")
    for k, n in (("note", 200), ("why", 300)):
        s = rec.get(k)
        if not isinstance(s, str) or len(s) > n:
            p.append("%s not str or too long" % k)
        elif any(unicodedata.category(c) == "Cc" and (strict or c not in "\t\n") for c in s):
            p.append("control character in %s" % k)
    try:
        json.dumps(rec)
    except (TypeError, ValueError):
        p.append("not JSON serialisable")
    return p


def check_records(res, limit_records=60000, strict=True):
    if not isinstance(res, list):
        return ["result is not a list"]
    if len(res) > limit_records:
        return ["too many records: %d" % len(res)]
    problems = []
    step = max(1, len(res) // 400)          # full check on small outputs, strided on huge ones
    for r in res[::step]:
        problems += contract_problems(r, strict)
        if len(problems) > 3:
            break
    return problems


# Defects outside the files this harness's owner may edit; reported as "known open", not as failures.
# compiler.compile_campaign: a `name` made only of control characters yields meta.name that validate() rejects.
KNOWN_OPEN = ()      # nothing known open: control-character-only names are now stripped by the compiler


# ---------------------------------------------------------------- hostile corpus
def _nested(n, a="[", b="]", leaf="1"):
    return a * n + leaf + b * n


FAST_HOSTILE = ("nest-35-campaign", "nest-100-misp", "nest-900-list", "nest-990-misp-list", "nest-900-stix", "nest-5000-list", "nest-5000-dict", "nest-5000-stix", "nest-5000-misp", "nest-5000-otx", "nest-5000-campaign",
                "huge-int", "huge-int-ioc", "huge-float", "nan-inf", "nan-list", "dup-keys", "trunc-json", "trunc-csv", "trunc-xml",
                "nul-bytes", "ctrl-all", "bidi", "zero-width", "overlong-utf8", "mixed-enc", "utf16-be", "utf16-odd", "lone-surrogate",
                "defang-ctrl", "defang-ctrl-tail", "long-label", "domain-255", "ipv4-edge", "ipv6-edge", "cve-like", "regex-aaa",
                "regex-defang-tail", "regex-brackets", "regex-colons", "regex-at", "regex-email", "regex-scheme", "regex-hex",
                "regex-stix-pattern", "regex-tech", "csv-wide", "csv-quotes", "csv-nuls", "csv-delims", "json-weird-types", "json-keys",
                "empty", "whitespace", "bom-only")


def hostile_corpus(names=None):
    """(name, bytes) pairs. Deterministic. `names` limits the set (FAST_HOSTILE is the quick subset)."""
    c = []

    def add(name, data):
        c.append((name, data if isinstance(data, bytes) else data.encode("utf-8", "surrogatepass")))

    add("single-line-4.9MB", ("a" * 60 + ".example.com ") * (4900000 // 73))
    add("single-line-10MB", "x" * (10 * 1024 * 1024))
    add("one-token-4MB", "1" * (4 * 1024 * 1024))
    add("dots-4MB", "." * (4 * 1024 * 1024))
    add("100k-tiny-lines", "\n".join("10.%d.%d.%d" % (i >> 16 & 255, i >> 8 & 255, i & 255) for i in range(100000)))
    add("100k-tiny-json", json.dumps([{"type": "ipv4", "value": "198.51.%d.%d" % (i >> 8 & 255, i & 255)} for i in range(100000)]))
    add("100k-tiny-csv", "indicator,type\n" + "\n".join("h%d.example.org,domain" % i for i in range(100000)))
    add("100k-tiny-domains", "\n".join("a%d.io" % i for i in range(100000)))
    add("100k-cves", "\n".join("CVE-2026-%04d%d" % (i % 10000, i % 10) for i in range(100000)))
    add("nest-5000-list", _nested(5000))
    add("nest-5000-dict", '{"a":' * 5000 + "1" + "}" * 5000)
    add("nest-100000-list", _nested(100000))
    add("nest-5000-stix", '{"type":"bundle","objects":' + _nested(5000) + "}")
    add("nest-5000-misp", '{"Event":' * 5000 + "{}" + "}" * 5000)
    add("nest-5000-otx", '{"results":[{"indicators":' + _nested(5000) + "}]}")
    add("nest-5000-campaign", '{"schema":"opengenerator.campaign/1","stages":' + _nested(5000) + "}")
    for depth in (35, 100, 900, 990):
        add("nest-%d-list" % depth, _nested(depth))
        add("nest-%d-dict" % depth, '{"a":' * depth + "1" + "}" * depth)
        add("nest-%d-misp" % depth, '{"response":' * depth + "[{}]" + "}" * depth)
        add("nest-%d-misp-list" % depth, _nested(depth, leaf='{"Event":{"Attribute":[{"type":"ip-dst","value":"203.0.113.9"}]}}'))
        add("nest-%d-stix" % depth, '{"type":"bundle","objects":' + _nested(depth) + "}")
        add("nest-%d-campaign" % depth, '{"schema":"opengenerator.campaign/1","stages":' + _nested(depth) + "}")
        add("nest-%d-otx" % depth, '{"results":[{"indicators":' + _nested(depth) + "}]}")
    add("huge-int", '{"confidence": %s, "first_seen": %s}' % ("9" * 5000, "9" * 400))
    add("huge-int-ioc", '[{"type":"ipv4","value":"203.0.113.9","confidence":%s,"first_seen":%s}]' % ("9" * 400, "9" * 400))
    add("huge-float", '{"confidence": 1e999, "first_seen": -1e999, "x": 1e-999}')
    add("nan-inf", '{"confidence": NaN, "first_seen": Infinity, "n": -Infinity}')
    add("nan-list", "[NaN, Infinity, -Infinity, 1e400]")
    add("dup-keys", '{"type":"bundle","type":"x","objects":[],"objects":[{"type":"indicator","pattern":"[ipv4-addr:value = \'203.0.113.9\']","pattern":"[domain-name:value = \'a.b.com\']"}]}')
    add("trunc-json", '{"type":"bundle","objects":[{"type":"indicator","pattern":"[ipv4-addr:value = \'203.0.1')
    add("trunc-csv", 'indicator,type\n"203.0.113.9,ipv4\n"unterminated')
    add("trunc-xml", "<?xml version='1.0'?><root><ioc>203.0.113.9</ioc><ioc")
    add("nul-bytes", b"203.0.113.9\x00\x00\nexample.com\x00\nhxxp://a.b\x00c/")
    add("nul-only", b"\x00" * 100000)
    add("ctrl-all", bytes(range(256)) * 200)
    add("bidi", "evil\u202e.example.com\u202d http://\u202eexample.org/\u2066x\u2069 203.0.113.\u200b5 a\u200b.b.com")
    add("zero-width", "ex\u200bam\u200dple\u2060.c\ufeffom 1\u200b0.0.0.1 CVE\u200b-2026-1234")
    add("overlong-utf8", b"\xc0\xaf\xc0\xae\xc0\xae\xe0\x80\xaf example.com \xf8\x80\x80\x80\xaf 203.0.113.9")
    add("mixed-enc", b"\xff\xfe" + "203.0.113.9\nexample.com\n".encode("utf-16-le") + b"\xff\xff\xfe\x80 abc.example.com")
    add("utf16-be", b"\xfe\xff" + "198.51.100.1\n".encode("utf-16-be"))
    add("utf16-odd", b"\xff\xfe\x32\x00\x30")
    add("lone-surrogate", "a\ud800b.example.com \udfff 203.0.113.9")
    add("defang-ctrl", "hxxp://evil[.]example[.]com/a\x00\x01\x02\r\x1b[31m\nhxxps[:]//a\x7f.b.com/\x85x\nhXXp://x.y/\u2028z")
    add("defang-ctrl-tail", "hxxp://evil[.]example[.]com/\x01\x02\x03\n hxxp://1[.]2[.]3[.]4/\x0b\x0c\n hxxp://a.example/\x00 hxxp://\x01")
    add("defang-nested", "hxxp://" + "[.]" * 20000 + "com")
    add("defang-brackets", "[" * 50000 + "." + "]" * 50000)
    add("defang-at", "a" + "[at]" * 30000 + "b.com")
    add("long-label", "http://" + "a" * 70 + ".example.com/ " + "b" * 63 + "." + "c" * 63 + "." + "d" * 63 + "." + "e" * 63 + ".com")
    add("long-label-4MB", "a" * 4000000 + ".com")
    add("many-labels", ".".join("a" for _ in range(100000)) + ".com")
    add("domain-255", ".".join(["a" * 63] * 4) + ".com")
    add("ipv4-edge", "\n".join(["0177.0.0.1", "0x7f.0.0.1", "2130706433", "0x7f000001", "127.1", "1.1.1.256", "01.2.3.4",
                                "::ffff:127.0.0.1", "::ffff:7f00:1", "::FFFF:203.0.113.9", "1.2.3.4.5", "1.2.3", "1.2.3.4/33",
                                "203.0.113.9/0", "10.0.0.0/8", "256.256.256.256", "-1.2.3.4", "+1.2.3.4", "1.2.3.4:99999",
                                "0.0.0.0", "255.255.255.255", "224.0.0.1", "169.254.169.254", "\uff11\uff12\uff17.0.0.1", "1\u30022\u30023\u30024"]))
    add("ipv6-edge", "\n".join(["::", "::1", "2001:db8::", "2001:db8:0:0:0:0:0:1", "fe80::1%eth0", "fe80::1%", "[2001:db8::1]:443",
                                "2001:db8::1/129", "2001:db8::/32", "1:2:3:4:5:6:7:8:9", ":::", "::ffff:1.2.3.4", "64:ff9b::1.2.3.4",
                                "g::1", "12345::1", "2001:db8::1%" + "x" * 5000, "[::1", "::1]"]))
    add("cve-like", "\n".join(["CVE-2026-1234", "cve-1999-0001", "CVE-2026-12345678", "CVE-20261-1234", "CVE-2026-123",
                               "CVE--2026-1234", "CVE-2026-" + "9" * 5000, "CVE-" + "9" * 5000 + "-1", "CVE-2026-1234a", "\uff23\uff36\uff25-2026-1234"]))
    add("regex-aaa", "a" * 50000 + "!")
    add("regex-aaa-dots", "a." * 50000 + "!")
    add("regex-spaces", " " * 100000 + "x")
    add("regex-defang-tail", "[" + " " * 100000)
    add("regex-defang-tail2", "(" + " " * 100000 + "x")
    add("regex-brackets", "[.][.][.]" * 30000)
    add("regex-slashes", "http://" + "/" * 100000)
    add("regex-colons", ":" * 100000 + "1")
    add("regex-at", "a@" * 50000 + "b")
    add("regex-email", "a" * 30000 + "@" + "b" * 30000)
    add("regex-scheme", "a" * 15 + "://" + "x" * 100000)
    add("regex-hex", "0" * 31 + "g" + "0" * 100000)
    add("regex-path", "C:\\" + "a\\" * 50000)
    add("regex-stix-pattern", "[" + "ipv4-addr:value = '1.1.1.1' OR " * 20000 + "]")
    add("regex-stix-pattern2", "[" + "a:b = '" * 30000)
    add("regex-tech", "T" + "1" * 100000)
    add("csv-wide", ",".join("c%d" % i for i in range(50000)) + "\n" + ",".join("v%d" % i for i in range(50000)))
    add("csv-bigfield", 'indicator,type\n"' + "a" * 3000000 + '",domain')
    add("csv-quotes", 'a,b\n' + '""' * 500000)
    add("csv-nuls", 'indicator\n1.2.3.4\x00\n"a\x00b.com"')
    add("csv-delims", "\n".join("|".join(["1.2.3.4"] * 50) for _ in range(2000)))
    add("json-strings-big", json.dumps({"results": [{"indicators": [{"indicator": "x" * 2000000, "type": "domain"}]}]}))
    add("json-weird-types", json.dumps({"results": [None, 1, "a", [], {"indicators": None}, {"indicators": [None, 1, [], {"indicator": [], "type": {}}]}],
                                         "data": 5, "objects": "x", "Event": [], "vulnerabilities": [1, None, {"cveID": 5}], "urls": 1}))
    add("json-keys", json.dumps({"type": "bundle", "objects": [{"type": "indicator", "pattern": "[url:value = 'http://a.example/%s']" % ("%" * 200)},
                                                                {"type": "ipv4-addr", "value": "203.0.113.9", "x": {"y": [1] * 1000}},
                                                                {"type": "domain-name", "value": "\u202eexample.com"}]}))
    add("empty", "")
    add("whitespace", " \n\t\r\n" * 1000)
    add("bom-only", b"\xef\xbb\xbf")
    add("bom-many", b"\xef\xbb\xbf" * 100000 + b"203.0.113.9")
    add("misp-attrs", json.dumps({"Event": {"info": "x", "Attribute": [{"type": "ip-dst", "value": "203.0.113.%d" % (i % 250), "to_ids": True,
                                   "Tag": [{"name": "misp-galaxy:mitre-attack-pattern=\"T%04d\"" % i}]} for i in range(20000)]}}))
    add("stix-many", json.dumps({"type": "bundle", "objects": [{"type": "indicator", "id": "indicator--%d" % i, "pattern_type": "stix",
                                  "pattern": "[domain-name:value = 'h%d.example.org']" % i} for i in range(30000)]}))
    return [x for x in c if names is None or x[0] in names]


# ---------------------------------------------------------------- mutation
_TOKENS = [b"hxxp://", b"[.]", b"(dot)", b"{.}", b"[at]", b"[://]", b"\x00", b"\r\n", b"\x1b[0m", b"\xe2\x80\xae", b"\xe2\x80\x8b",
           b"\xef\xbb\xbf", b"\xc0\xaf", b"::ffff:", b"0x7f", b"0177", b"CVE-2026-", b"T1059.001", b"1e999", b"NaN", b"Infinity",
           b'","', b'":', b"[", b"]", b"{", b"}", b'"', b"'", b"\\u0000", b"\\ud800", b"%00", b"..", b"/", b":", b"@", b",", b";", b"\t", b"|",
           b"203.0.113.9", b"example.com", b"a" * 64 + b".com", b"999999999999999999999", b"-1", b"c2", b"ransomware", b"tor exit",
           b"\x01", b"\x0b", b"\x0c", b"\x7f", b"\xc2\x85", b"\xe2\x80\xa8"]


def mutate_bytes(rng, data, rounds=None):
    b = bytearray(data[:200000])
    for _ in range(rounds or rng.randint(1, 6)):
        op = rng.randrange(9)
        n = len(b)
        if op == 0 and n:
            b[rng.randrange(n)] ^= 1 << rng.randrange(8)
        elif op == 1 and n:
            i = rng.randrange(n)
            del b[i:i + rng.randint(1, 40)]
        elif op == 2:
            i = rng.randrange(n + 1)
            b[i:i] = rng.choice(_TOKENS)
        elif op == 3 and n:
            i = rng.randrange(n)
            j = min(n, i + rng.randint(1, 500))
            k = rng.randrange(n)
            b[k:k] = b[i:j] * rng.randint(1, 30)
        elif op == 4 and n:
            del b[rng.randrange(n):]
        elif op == 5 and n:
            b[rng.randrange(n)] = rng.randrange(256)
        elif op == 6:
            i = rng.randrange(n + 1)
            b[i:i] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 30)))
        elif op == 7 and n:
            i = rng.randrange(n)
            b[i:i] = b[i:i + rng.randint(1, 20)] * rng.randint(2, 400)
        elif op == 8 and n:
            lines = bytes(b).split(b"\n")
            rng.shuffle(lines)
            b = bytearray(b"\n".join(lines))
    return bytes(b)


_BAD_VALUES = [None, True, False, 0, -1, 1.5, 1e308, float("nan"), float("inf"), 10 ** 40, "", " ", "\x00", "\u202e", "a" * 5000, "NaN",
               [], {}, [[]], {"a": None}, "203.0.113.9", "example.com", "0x7f000001", "CVE-2026-1", "T1059", "2026-13-45", "9" * 30,
               -(10 ** 20), "hxxp://a[.]b", "10.0.0.1", "::ffff:10.0.0.1", "a\x01b.com", "a.com\x0b"]


def mutate_json(rng, obj):
    """Return a mutated deep copy (random value swaps, key drops/dups, type confusion)."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            r = rng.random()
            if r < 0.06:
                continue
            if r < 0.12:
                out[k] = rng.choice(_BAD_VALUES)
            elif r < 0.15:
                out[k + rng.choice(["", "x", "\u202e", "\x00"])] = mutate_json(rng, v)
            else:
                out[k] = mutate_json(rng, v)
        if rng.random() < 0.05:
            out[rng.choice(["type", "value", "Event", "objects", "results", "indicators", "stages", "iocs", "x"])] = rng.choice(_BAD_VALUES)
        return out
    if isinstance(obj, list):
        out = [mutate_json(rng, v) for v in obj]
        r = rng.random()
        if out and r < 0.1:
            out.append(rng.choice(out))
        elif r < 0.15:
            out.append(rng.choice(_BAD_VALUES))
        elif out and r < 0.2:
            out.pop(rng.randrange(len(out)))
        elif out and r < 0.25:
            out = out * rng.randint(2, 60)
        return out
    if isinstance(obj, str):
        r = rng.random()
        if r < 0.1:
            return rng.choice(_BAD_VALUES)
        if r < 0.2:
            return mutate_bytes(rng, obj.encode("utf-8"), 2).decode("utf-8", "replace")
        return obj
    if isinstance(obj, (int, float)) and rng.random() < 0.15:
        return rng.choice(_BAD_VALUES)
    return obj


def load_seeds():
    """'dir/name' -> bytes for every fixture file under tests/fixtures/{intel,campaigns,intel/snapshots}."""
    seeds = {}
    for sub in ("intel", "campaigns", os.path.join("intel", "snapshots")):
        d = os.path.join(FIXTURES, sub)
        if not os.path.isdir(d):
            continue
        for n in sorted(os.listdir(d)):
            p = os.path.join(d, n)
            if os.path.isfile(p) and os.path.getsize(p) < 400000:
                with open(p, "rb") as f:
                    seeds["%s/%s" % (sub, n)] = f.read()
    return seeds


# ---------------------------------------------------------------- targets
def _opts_from(rng):
    cands = [None, {}, {"address_mode": "real"}, {"include": ["impact", "execution", "collection"]}, {"beacons_per_c2": 50},
             {"beacons_per_c2": 10 ** 30}, {"start": "99:99"}, {"compromised": "host:" + "A" * 200}, {"family": "zzz"},
             {"include": ["discovery"] * 5}, {"include": 7}, "x", [], {"unknown": 1}, {"speed": "fast", "lateral_target": "FILE1"},
             {"compromised": "\x00"}, {"start": "10:00\n"}, {"family": "none"}]
    return rng.choice(cands)


def _as_iocs(raw, rng):
    """IOC-ish dicts from raw bytes: parse them, then often mutate into hostile shapes."""
    try:
        recs = parsers.parse_any(raw, source="fz")
    except ValueError:
        recs = []
    recs = [dict(r) for r in recs[:400]]
    if recs and rng.random() < 0.6:
        recs = mutate_json(rng, recs)
        if not isinstance(recs, list):
            recs = [recs]
    return [r for r in recs if isinstance(r, dict)] if rng.random() < 0.7 else recs


def engine_available():
    """False when the campaign engine cannot be imported here (for example no `cryptography` package)."""
    try:
        campaign_api._engine()
        return True
    except campaign_api.ApiError:
        return False


def _rng_for(raw):
    """Per-input generator so every target call is reproducible from its input alone."""
    b = raw if isinstance(raw, bytes) else raw.encode("utf-8", "replace")
    return random.Random(zlib.crc32(b))


def make_targets(rng):
    """(name, fn(raw), kind). kind 'records' = the result is a list of IOCs to check."""
    T = []
    for nm, fn in (("parse_text", parsers.parse_text), ("parse_csv", parsers.parse_csv), ("parse_stix", parsers.parse_stix),
                   ("parse_misp", parsers.parse_misp), ("parse_otx", parsers.parse_otx), ("parse_threatfox", parsers.parse_threatfox),
                   ("parse_any", parsers.parse_any)):
        T.append(("parsers." + nm, fn, "records"))
    for fid, feed in sources.FEEDS.items():
        if feed.parse is not None:
            T.append(("feed.parse:" + fid, feed.parse, "records"))

    def classify_t(raw):
        s = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        out = []
        for tok in s.split()[:500] + [s[:3000]]:
            classify.refang(tok)
            t, canon = classify.classify_value(tok)
            classify.split_port(tok)
            if t is not None:
                out.append(model.new_ioc(t, canon))
        return out
    T.append(("classify", classify_t, "records"))

    def filters_t(raw):
        recs = parsers.parse_any(raw, source="fz")
        kept, _dropped = filters.clean(recs)
        kept2, _ = filters.clean(recs, allow_private=True, drop_documentation=True, allow_list=False)
        probs = check_records(kept2, limit_records=10 ** 6)
        assert not probs, "filters.clean(allow_private): " + "; ".join(probs)
        return kept
    T.append(("filters.clean", filters_t, "records"))

    def pipeline(raw):
        """fetch() with the network stubbed to return `raw`, for every feed kind."""
        rng = _rng_for(raw)
        feed_id = rng.choice([f for f in sorted(sources.FEEDS) if f != "url"])
        data = raw if isinstance(raw, bytes) else raw.encode("utf-8", "replace")
        with mock.patch.object(sources, "http_get", lambda *a, **k: data[:sources.FETCH_MAX]):
            return sources.fetch(feed_id, limit=rng.choice([1, 50, 5000]), key="k" * 10, cache=False)
    T.append(("sources.fetch(stub)", pipeline, "records"))

    T.append(("schema.load", lambda raw: schema.load(raw), "any"))

    def schema_obj(raw):
        try:
            d = json.loads(raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw)
        except (ValueError, RecursionError):
            return []
        n = schema.normalise(d)
        errs = schema.validate(n)
        assert isinstance(errs, list) and all(isinstance(e, str) for e in errs), "validate must return list of str"
        schema.validate(d)
        return []
    T.append(("schema.normalise+validate", schema_obj, "any"))

    def compile_t(raw):
        rng = _rng_for(raw)
        iocs = _as_iocs(raw, rng)
        opts, name = _opts_from(rng), rng.choice([None, "", "x" * 500, "\x00\u202e", "Name"])
        camp = compiler.compile_campaign(iocs, options=opts, name=name)
        errs = schema.validate(camp)
        assert errs == [], "compiled campaign does not validate: %s" % errs[:3]
        compiler.explain_campaign(camp)
        again = compiler.compile_campaign(iocs, options=opts, name=name)
        assert json.dumps(camp, sort_keys=True) == json.dumps(again, sort_keys=True), "compile is not deterministic"
        return camp["iocs"]
    T.append(("compiler.compile_campaign", compile_t, "schema-records"))

    def api_t(raw):
        rng = _rng_for(raw)
        s = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        try:
            body = json.loads(s)
        except (ValueError, RecursionError):
            body = None
        camp_like = body if isinstance(body, dict) else {"meta": {"name": s[:80]}}
        bodies = [body, {"text": s}, {"text": s, "source": s[:90]}, {"campaign": body}, {"campaign": camp_like, "overwrite": True},
                  {"iocs": body if isinstance(body, list) else [body], "options": _opts_from(rng), "name": s[:50]},
                  {"feed": s[:70], "limit": s[:20], "days": s[:5], "q": s[:300], "url": s[:2100], "key": s[:300], "offline": True},
                  {"id": s[:70], "text": s[:5000], "scale": s[:10]}, {"campaign": camp_like, "scale": rng.choice([0, -1, 1e308, 1, "x", None, True])}]
        if len(s) > 200000:               # one pass per route is enough for big bodies; keeps the 2 s budget about one call
            bodies = bodies[:2]
        for b in bodies:
            for path in ROUTES:
                r = campaign_api.route_post(path, b)
                if r is None:
                    continue
                st, payload, _ctype, _hdr = r
                if st >= 500:
                    raise AssertionError("route %s returned %s" % (path, st))
                if path == "/api/intel/parse" and st == 200:
                    probs = check_records(json.loads(payload).get("iocs"))
                    if probs:
                        raise AssertionError("api parse: " + "; ".join(probs))
        for q in ("q=" + s[:120], "q=%00%ff" + s[:20]):
            r = campaign_api.route_get("/api/campaign/attack", q, ".")
            if r is not None and r[0] >= 500:
                raise AssertionError("attack route %s" % r[0])
        return []
    if engine_available():
        T.append(("campaign_api.routes", api_t, "any"))
    else:
        print("warning: campaign engine not importable; campaign_api routes are not fuzzed", file=sys.stderr)
    return T


# ---------------------------------------------------------------- runner
class Hang(Exception):
    pass


def _alarm(signum, frame):
    raise Hang("no result after %ds" % HANG_ALARM)


def run_one(name, fn, raw, kind, trace):
    """None when fine, else a failure string."""
    use_alarm = hasattr(signal, "SIGALRM")
    if use_alarm:
        signal.alarm(HANG_ALARM)
    t0 = time.perf_counter()
    res = None
    try:
        res = fn(raw)
    except ALLOWED:
        pass
    except Hang as e:
        return "HANG %s" % e
    except RecursionError:
        return "uncaught RecursionError"
    except MemoryError:
        return "MemoryError"
    except Exception as e:                       # noqa: BLE001
        import traceback
        tb = traceback.extract_tb(e.__traceback__)[-1]
        return "uncaught %s: %s (at %s:%d)" % (type(e).__name__, str(e)[:100], os.path.basename(tb.filename), tb.lineno)
    finally:
        if use_alarm:
            signal.alarm(0)
    dt = time.perf_counter() - t0
    if dt > TIME_BUDGET:
        return "SLOW %.2fs (budget %.1fs)" % (dt, TIME_BUDGET)
    if kind in ("records", "schema-records") and res is not None:
        probs = check_records(res, strict=(kind == "records"))
        if probs:
            return "contract: " + "; ".join(probs[:3])
    if trace:
        budget = BASE_MEM + MEM_PER_BYTE * len(raw)
        peak = 0
        tracemalloc.start()
        try:
            if use_alarm:
                signal.alarm(HANG_ALARM * 3)
            try:
                fn(raw)
            except ALLOWED:
                pass
            except Exception:                    # noqa: BLE001 -- reported by the first pass (or random-state dependent)
                pass
            finally:
                if use_alarm:
                    signal.alarm(0)
            peak = tracemalloc.get_traced_memory()[1]
        except Hang:
            peak = 0
        finally:
            tracemalloc.stop()
        if peak > budget:
            return "MEMORY peak %.0f MB (budget %.0f MB)" % (peak / 1e6, budget / 1e6)
    return None


def fuzz(iterations, seed, hostile=True, only=None, progress=False, trace_every=4, quiet=False, save_dir=None, hostile_names=None):
    """Run the harness; returns a list of failure dicts. Deterministic for a given (iterations, seed)."""
    rng = random.Random(seed)
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _alarm)
    targets = make_targets(rng)
    if only:
        targets = [t for t in targets if any(o in t[0] for o in only)]
    seeds = load_seeds()
    seed_names = sorted(seeds)
    failures, seen_keys = [], set()
    known_open = fuzz.known_open = []

    def record(name, src, raw, why):
        if any(k in why for k in KNOWN_OPEN):
            known_open.append(why)
            return
        key = (name, why.split(" (")[0][:70])
        if key in seen_keys:
            return
        seen_keys.add(key)
        head = raw[:160] if isinstance(raw, (bytes, str)) else repr(raw)[:160]
        failures.append({"target": name, "input": src, "why": why, "head": head})
        if save_dir and isinstance(raw, (bytes, str)):
            os.makedirs(save_dir, exist_ok=True)
            fname = "%03d-%s.bin" % (len(failures), "".join(ch if ch.isalnum() else "_" for ch in name))
            with open(os.path.join(save_dir, fname), "wb") as fh:
                fh.write(raw if isinstance(raw, bytes) else raw.encode("utf-8", "surrogatepass"))
        if not quiet:
            print("FAIL [%s] %s  input=%s head=%r" % (name, why, src, head), flush=True)

    if hostile:
        for hname, data in hostile_corpus(hostile_names):
            forms = [data] if len(data) > 3_000_000 else [data, data.decode("utf-8", "replace")]
            for tname, fn, kind in targets:
                for form in forms[:1] if tname != "parsers.parse_any" else forms:
                    why = run_one(tname, fn, form, kind, trace=True)
                    if why:
                        record(tname, "hostile:" + hname, form, why)
    for i in range(iterations):
        sname = seed_names[rng.randrange(len(seed_names))] if seed_names else None
        base = seeds[sname] if sname else b""
        r = rng.random()
        if r < 0.5 or not sname:
            raw = mutate_bytes(rng, base)
        elif r < 0.85 and sname.endswith(".json"):
            try:
                raw = json.dumps(mutate_json(rng, json.loads(base.decode("utf-8", "replace")))).encode("utf-8", "replace")
            except (ValueError, RecursionError):
                raw = mutate_bytes(rng, base)
        else:
            raw = mutate_bytes(rng, base, rng.randint(6, 20))
        tname, fn, kind = targets[rng.randrange(len(targets))]
        form = raw if rng.random() < 0.7 else raw.decode("utf-8", "replace")
        why = run_one(tname, fn, form, kind, trace=(i % trace_every == 0))
        if why:
            record(tname, "mutant#%d of %s" % (i, sname), form, why)
        if progress and i and i % 2000 == 0:
            print("  %d / %d, %d distinct failures" % (i, iterations, len(failures)), flush=True)
    return failures


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--iterations", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--hostile-only", action="store_true", help="only the fixed hostile corpus")
    ap.add_argument("--no-hostile", action="store_true", help="skip the fixed hostile corpus")
    ap.add_argument("--only", action="append", help="substring of a target name (repeatable)")
    ap.add_argument("--save-failures", metavar="DIR", help="write each failing input to DIR (replay with --replay)")
    ap.add_argument("--replay", metavar="FILE", help="run every target on one saved input and print the results")
    a = ap.parse_args(argv)
    if a.replay:
        with open(a.replay, "rb") as fh:
            data = fh.read()
        if hasattr(signal, "SIGALRM"):
            signal.signal(signal.SIGALRM, _alarm)
        for tname, fn, kind in make_targets(random.Random(0)):
            if a.only and not any(o in tname for o in a.only):
                continue
            print("%-34s %s" % (tname, run_one(tname, fn, data, kind, trace=True) or "ok"))
        return 0
    t0 = time.time()
    fails = fuzz(0 if a.hostile_only else a.iterations, a.seed, hostile=not a.no_hostile, only=a.only, progress=True, save_dir=a.save_failures)
    if getattr(fuzz, "known_open", None):
        print("%d known-open hit(s) (compiler name made of control characters)" % len(fuzz.known_open))
    print("%d distinct failure(s) in %.1fs (iterations=%d seed=%d)" % (len(fails), time.time() - t0, a.iterations, a.seed))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
