#!/usr/bin/env python3
"""Check the DRAFT scenario metadata (scenario_meta.json) against what the engine really emits.

For every scenario id the tool builds a tiny capture holding ONLY that scenario (the normal-day baseline is
switched off for the run, so nothing the baseline already carries can mask a missing protocol), profiles the pcap
with the repo's own ``pcapprofile`` and compares the protocols the metadata declares with the protocol table.

    python tools/verify_scenario_meta.py                 # all scenarios, resumable
    python tools/verify_scenario_meta.py --only ndr-recon --only npm-voip-quality
    python tools/verify_scenario_meta.py --limit 5       # first five not yet done
    python tools/verify_scenario_meta.py --force         # redo scenarios already in the JSON
    python tools/verify_scenario_meta.py --report-only   # rewrite the Markdown from the JSON

Each build runs in its own subprocess (the engine's build state is process-global) with a timeout, one at a
time. Results go to docs/redesign/meta-verification.json (updated after every scenario, so an interrupted run
resumes) and docs/redesign/meta-verification.md.

What is and is not checked
  * Declared protocols: each label is mapped (ALIASES) to the names ``pcapprofile`` uses; a label is verified
    when any mapped name is in the scenario's protocol table (or, for generic L4 labels, that transport is seen).
  * Scenario adds packets: the scenario-only build must contain at least one packet.
  * Hosts, zone_path, steps and expected_observation are prose and cannot be verified mechanically.
Report-only: nothing in the metadata is changed.
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
DOCS = os.path.join(DEV, "docs", "redesign")
OUT_JSON = os.path.join(DOCS, "meta-verification.json")
OUT_MD = os.path.join(DOCS, "meta-verification.md")
META = os.path.join(DEV, "scenario_meta.json")
SCALE = 0.004
TIMEOUT = 60

# --------------------------------------------------------------------------- label -> observed-name mapping
# Declared label (lower case, text after the first " (" removed unless the full label is listed) ->
# (kind, names). kind "direct": the label IS a protocol pcapprofile reports; "carrier": the label is a feature
# or sub-protocol that rides inside the listed protocols, so the check only proves the carrier is present;
# "l4": a transport, verified when that transport is seen; "none": a feature or placeholder with no protocol-table
# name (reported as unverifiable, never as missing).
ALIASES = {
    "icmp": ("direct", ["ICMP"]),
    "tcp": ("l4", ["tcp"]),
    "ldap": ("direct", ["LDAP", "LDAPS"]),
    "ldap simple bind": ("carrier", ["LDAP"]),
    "smb": ("direct", ["SMB2", "SMB", "NetBIOS-SSN"]),
    "smb (named pipe)": ("carrier", ["SMB2", "SMB"]),
    "smb/ms-efsr": ("carrier", ["SMB2", "DCE/RPC"]),
    "dce/rpc": ("direct", ["DCE/RPC"]),
    "wmi/dcom": ("carrier", ["DCE/RPC", "DCOM"]),
    "rdp": ("direct", ["RDP"]),
    "kerberos": ("direct", ["Kerberos"]),
    "kerberos pkinit": ("carrier", ["Kerberos"]),
    "ntlm": ("carrier", ["SMB2", "HTTP", "HTTPS", "LDAP", "DCE/RPC", "RDP", "NTLM"]),
    "dns": ("direct", ["DNS"]),
    "tls": ("carrier", ["HTTPS", "TLS", "LDAPS", "DTLS"]),
    "tls 1.0": ("carrier", ["HTTPS", "TLS"]),
    "tls 1.3": ("carrier", ["HTTPS", "TLS", "QUIC"]),
    "tls/https": ("direct", ["HTTPS", "TLS"]),
    "https": ("direct", ["HTTPS", "TLS"]),
    "http(s)": ("direct", ["HTTP", "HTTPS", "TLS"]),
    "http(s) to ad cs": ("carrier", ["HTTP", "HTTPS"]),
    "https (multipart post)": ("carrier", ["HTTPS"]),
    "websocket upgrade": ("carrier", ["HTTP", "HTTPS"]),
    "http": ("direct", ["HTTP"]),
    "http basic": ("carrier", ["HTTP"]),
    "http put": ("carrier", ["HTTP", "HTTPS"]),
    "dtls": ("direct", ["DTLS"]),
    "tds": ("direct", ["TDS"]),
    "mysql": ("direct", ["MySQL"]),
    "ssh": ("direct", ["SSH"]),
    "dhcp": ("direct", ["DHCP"]),
    "snmp": ("direct", ["SNMP"]),
    "ftp": ("direct", ["FTP"]),
    "arp": ("direct", ["ARP"]),
    "modbus/tcp": ("direct", ["Modbus", "Modbus/TCP"]),
    "dnp3": ("direct", ["DNP3"]),
    "bacnet": ("direct", ["BACnet"]),
    "ipsec/ike": ("direct", ["IKE", "IPsec", "ISAKMP"]),
    "nat keepalive": ("carrier", ["IKE", "IPsec", "ISAKMP"]),
    "capwap": ("direct", ["CAPWAP"]),
    "syslog": ("direct", ["Syslog"]),
    "sip": ("direct", ["SIP"]),
    "rtp": ("direct", ["RTP"]),
    "rtcp": ("direct", ["RTCP"]),
    "ntp": ("direct", ["NTP"]),
    "radius": ("direct", ["RADIUS"]),
    "eap/peap": ("carrier", ["RADIUS"]),
    "nfs v3": ("direct", ["NFS"]),
    "rpc": ("carrier", ["NFS", "RPC", "Portmap", "DCE/RPC"]),
    "smtp": ("direct", ["SMTP"]),
    "llmnr/nbns": ("direct", ["LLMNR", "NBNS"]),
    "vsphere api": ("carrier", ["HTTPS", "HTTP"]),
    "esxi agent": ("carrier", []),
    "ipv4 options": ("none", []),
    "mptcp": ("none", []),
    "depends on the campaign": ("none", []),
    "depends on the recipe": ("none", []),
}

# Extra evidence by transport port, for protocols pcapprofile does not name (it lists them as TCP-other/UDP-other).
# Label key -> ["tcp/3306", "udp/500", ...]. A port-only hit is recorded as carrier-only (weaker than a decode).
PORTS = {
    "ipsec/ike": ["udp/500", "udp/4500"],
    "nat keepalive": ["udp/4500"],
    "mysql": ["tcp/3306"],
    "dtls": ["udp/443", "udp/4433", "udp/5247"],
    "capwap": ["udp/5246", "udp/5247"],
    "esxi agent": ["tcp/902"],
    "rpc": ["tcp/111", "udp/111"],
}

WATCH_PORTS = {p for v in PORTS.values() for p in v}

# Observed protocols that are ambient (link-layer chatter any capture carries); never listed as "extra".
AMBIENT = {"ARP"}


def label_key(label):
    """Lower-case lookup key for a declared label: the full label if listed, else the text before ' ('."""
    k = " ".join(str(label).lower().split())
    if k in ALIASES:
        return k
    base = k.split(" (")[0].strip()
    return base if base in ALIASES else k


def resolve(label):
    """(kind, names) for a declared label; kind 'unknown' (names []) when the alias map does not know it."""
    k = label_key(label)
    if k in ALIASES:
        kind, names = ALIASES[k]
        return kind, list(names)
    return "unknown", []


def compare(declared, observed, l4=None, ports=None):
    """Compare declared protocol labels with an observed ``{protocol: packets}`` table.

    ``l4`` is an optional ``{"tcp": n, "udp": n}`` for the generic transport labels; ``ports`` an optional
    ``{"udp/500": packets, ...}`` used as weaker evidence (PORTS) for protocols the profiler does not name.
    Returns ``{verified, carrier_only, missing, unverifiable, extra}`` (lists of labels, or of observed protocol
    names for ``extra``). ``carrier_only`` labels are verified but only through the protocol that carries them.
    """
    l4, ports = l4 or {}, ports or {}
    seen = {k.lower(): k for k, v in observed.items() if v}
    verified, carrier_only, missing, unverifiable, explained = [], [], [], [], set()
    for label in declared:
        kind, names = resolve(label)
        if kind in ("none", "unknown") and not PORTS.get(label_key(label)):
            unverifiable.append(label)
            continue
        if kind == "l4":
            ok = [n for n in names if l4.get(n)]
            (verified if ok else missing).append(label)
            continue
        hit = [seen[n.lower()] for n in names if n.lower() in seen]
        explained.update(hit)
        by_port = [p for p in PORTS.get(label_key(label), []) if ports.get(p)]
        if not hit and by_port:
            carrier_only.append(label)
        elif not hit:
            missing.append(label)
        elif kind == "carrier":
            carrier_only.append(label)
        else:
            verified.append(label)
    extra = sorted(p for p in observed if observed[p] and p not in explained and p not in AMBIENT)
    return {"verified": verified, "carrier_only": carrier_only, "missing": missing,
            "unverifiable": unverifiable, "extra": extra}


def verdict(cmp, packets, recipe_driven=False, error=None):
    """('pass'|'fail'|'inconclusive', reason). Order matters: errors and recipe-driven entries are never judged."""
    if error:
        return "inconclusive", "build error: " + str(error)[:120]
    if recipe_driven:
        return "inconclusive", "recipe-driven: traffic depends on user input, nothing to build standalone"
    if not packets:
        return "fail", "the scenario-only build produced no packets"
    if cmp["missing"]:
        return "fail", "declared but absent: " + ", ".join(cmp["missing"])
    if not (cmp["verified"] or cmp["carrier_only"]):
        return "inconclusive", "no declared protocol could be checked against the protocol table"
    return "pass", ""


# --------------------------------------------------------------------------- worker (one build, one process)
def worker(sid, ot=False):
    """Build only scenario `sid` (no baseline day) and print one JSON line of facts. Runs in a child process.
    ``sid == "BASELINE"`` builds the normal day alone instead (modules=[]), for the baseline-only annotation."""
    import tempfile
    sys.path.insert(0, DEV)
    import opengenerator_build as OGB
    import pcapprofile as PP

    baseline = sid == "BASELINE"

    class NoDay(OGB.Day):            # the scheduled normal day is skipped: only the scenario's own traffic remains
        def build(self):
            pass
    if not baseline:
        OGB.Day = NoDay
    d = tempfile.mkdtemp(prefix="og-metaverify-")
    try:
        pcap = os.path.join(d, "s.pcap")
        r = OGB.build(scale=SCALE, out=pcap, keylog=os.path.join(d, "s.keys"),
                      inventory=os.path.join(DEV, "inventory.json"), certs_dir=None, iocs_prefix=None,
                      modules=[] if baseline else [sid], progress=False, ot_nets=dict(OGB.OT_DEFAULTS) if ot else None)
        names = r.get("module_names", [])
        if not r["packets"]:
            print(json.dumps({"packets": 0, "protocols": {}, "l4": {}, "modules_built": names}))
            return
        prof = PP.profile(pcap)
        l4 = {"tcp": 0, "udp": 0}
        ports = {}
        for (a, b, proto), v in prof["convos"].items():
            for ep in (a, b):
                key = ("tcp/" if proto == 6 else "udp/") + ep.rsplit(":", 1)[-1]
                ports[key] = ports.get(key, 0) + v[0]
        for (_a, _b, proto), v in prof["convos"].items():
            l4["tcp" if proto == 6 else "udp" if proto == 17 else "other"] = \
                l4.get("tcp" if proto == 6 else "udp" if proto == 17 else "other", 0) + v[0]
        print(json.dumps({"packets": r["packets"], "protocols": prof["protocols"], "l4": l4,
                          "ports": {k: v for k, v in ports.items() if k in WATCH_PORTS},
                          "modules_built": names}))
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def run_worker(sid, ot=False, timeout=TIMEOUT):
    """Run the worker subprocess with a timeout; returns (facts|None, error|None, seconds)."""
    t0 = time.time()
    cmd = [sys.executable, os.path.abspath(__file__), "--worker", sid] + (["--ot"] if ot else [])
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, "timeout after %ds" % timeout, time.time() - t0
    secs = time.time() - t0
    if p.returncode != 0:
        tail = (p.stderr.strip().splitlines() or ["exit %d" % p.returncode])[-1]
        return None, tail, secs
    try:
        return json.loads(p.stdout.strip().splitlines()[-1]), None, secs
    except (ValueError, IndexError):
        return None, "unparseable worker output", secs


# --------------------------------------------------------------------------- driver and report
def load_meta():
    with open(META, encoding="utf-8") as f:
        return json.load(f)["scenarios"]


def load_results():
    try:
        with open(OUT_JSON, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"scale": SCALE, "results": {}}


def save_results(doc):
    os.makedirs(DOCS, exist_ok=True)
    tmp = OUT_JSON + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=False)
        f.write("\n")
    os.replace(tmp, OUT_JSON)


def baseline_protocols(doc):
    """Protocol table of the normal-day baseline alone (built once, cached in the JSON); {} if it cannot be built."""
    if "baseline_protocols" not in doc:
        facts, err, _ = run_worker("BASELINE", timeout=180)
        doc["baseline_protocols"] = (facts or {}).get("protocols", {})
    return doc["baseline_protocols"]


def verify_one(entry, doc=None):
    declared = entry.get("protocols", [])
    facts, err, secs = run_worker(entry["id"], bool(entry.get("ot_only")))
    observed = (facts or {}).get("protocols", {})
    cmp = compare(declared, observed, (facts or {}).get("l4"), (facts or {}).get("ports"))
    # a missing label the always-on baseline does carry is still absent from the scenario itself: annotate it
    baseline_only = []
    if cmp["missing"] and doc is not None:
        base = baseline_protocols(doc)
        baseline_only = compare(cmp["missing"], base)["verified"] + compare(cmp["missing"], base)["carrier_only"]
    v, why = verdict(cmp, (facts or {}).get("packets", 0), bool(entry.get("recipe_driven")), err)
    return {"id": entry["id"], "family": entry.get("family", ""), "verdict": v, "reason": why,
            "declared": declared, "packets": (facts or {}).get("packets", 0),
            "verified": cmp["verified"], "carrier_only": cmp["carrier_only"], "missing": cmp["missing"],
            "unverifiable": cmp["unverifiable"], "extra": cmp["extra"], "baseline_only": baseline_only,
            "observed": observed, "seconds": round(secs, 1), "error": err}


def write_report(doc, total_secs=None):
    rows = [doc["results"][k] for k in doc["results"]]
    cnt = {}
    for r in rows:
        cnt[r["verdict"]] = cnt.get(r["verdict"], 0) + 1
    L = ["# Scenario metadata verification (report only)", "",
         "Generated by `dev/tools/verify_scenario_meta.py` from `dev/scenario_meta.json` (status draft-unverified). "
         "Nothing in the metadata was changed. Raw data: `meta-verification.json` beside this file.", "",
         "## Method", "",
         "- Each scenario is built alone at scale %s (`modules=[id]`, normal-day baseline switched off, so baseline "
         "traffic cannot mask a missing protocol) in its own subprocess with a %d s timeout, then profiled with "
         "`pcapprofile`. The OT-only scenarios get the OT subnet. Scenarios that the engine auto-pairs with a "
         "dependency scenario include that dependency's traffic." % (doc.get("scale", SCALE), TIMEOUT),
         "- A declared protocol is mapped to the names `pcapprofile` reports (alias map in the tool). "
         "`direct` = the label is a protocol in the table. `carrier-only` = the label is a feature or sub-protocol "
         "(for example NTLM, WebSocket upgrade, EAP/PEAP) that rides inside another protocol, so only the carrier "
         "is proven. `unverifiable` = no protocol-table name exists (IPv4 options, MPTCP, recipe placeholders).",
         "- Scenario adds packets: the scenario-only build must contain at least one packet.",
         "- Hosts, zone path, steps and expected observation are prose; they cannot be verified mechanically and are "
         "not checked.",
         "- Verdict: fail = no packets, or a mappable declared protocol is absent; inconclusive = build error, "
         "recipe-driven, or nothing checkable; pass otherwise (unverifiable and carrier-only labels are listed, "
         "not failed). `extra` is observed traffic no declared label explains (ARP excluded); it is a hint that the "
         "metadata under-declares, not a failure.", "",
         "## Summary", "",
         "Scenarios: %d. Pass: %d. Fail: %d. Inconclusive: %d." % (
             len(rows), cnt.get("pass", 0), cnt.get("fail", 0), cnt.get("inconclusive", 0))]
    if total_secs is not None:
        L.append("Wall time for the last run: %.0f s." % total_secs)
    fails = [r for r in rows if r["verdict"] == "fail"]
    L += ["", "## Findings: declared protocols missing or no packets", ""]
    if not fails:
        L.append("None.")
    for r in fails:
        L.append("- `%s`: %s%s" % (r["id"], r["reason"], (" (present in the always-on baseline traffic: %s; "
                 "the scenario itself does not emit it)" % ", ".join(r["baseline_only"])) if r.get("baseline_only") else ""))
    inc = [r for r in rows if r["verdict"] == "inconclusive"]
    L += ["", "## Inconclusive", ""]
    if not inc:
        L.append("None.")
    for r in inc:
        L.append("- `%s`: %s" % (r["id"], r["reason"]))
    L += ["", "## Per scenario", "",
          "| id | verdict | packets | verified | carrier-only | missing | unverifiable | extra |",
          "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        f = lambda xs: ", ".join(x.replace("|", "/") for x in xs) or "-"
        L.append("| %s | %s | %d | %s | %s | %s | %s | %s |" % (
            r["id"], r["verdict"], r["packets"], f(r["verified"]), f(r["carrier_only"]), f(r["missing"]),
            f(r["unverifiable"]), f(r["extra"])))
    with open(OUT_MD, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--only", action="append", help="scenario id (repeatable)")
    ap.add_argument("--limit", type=int, help="stop after this many scenarios verified in this run")
    ap.add_argument("--force", action="store_true", help="re-verify scenarios already in the JSON")
    ap.add_argument("--report-only", action="store_true", help="rewrite the Markdown from the JSON, build nothing")
    ap.add_argument("--worker", help=argparse.SUPPRESS)
    ap.add_argument("--ot", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.worker:
        worker(a.worker, a.ot)
        return 0
    doc = load_results()
    if a.report_only:
        write_report(doc)
        return 0
    entries = load_meta()
    ids = [e["id"] for e in entries]
    if a.only:
        bad = [i for i in a.only if i not in ids]
        if bad:
            ap.error("unknown scenario id(s): " + ", ".join(bad))
        entries = [e for e in entries if e["id"] in a.only]
    todo = [e for e in entries if a.force or e["id"] not in doc["results"]]
    if a.limit is not None:
        todo = todo[:a.limit]
    t0 = time.time()
    for i, e in enumerate(todo, 1):
        r = verify_one(e, doc)
        doc["results"][e["id"]] = r
        doc["scale"] = SCALE
        # keep the file in metadata order regardless of run order
        order = {k: n for n, k in enumerate(ids)}
        doc["results"] = dict(sorted(doc["results"].items(), key=lambda kv: order.get(kv[0], 1 << 30)))
        save_results(doc)
        print("[%d/%d] %-34s %-12s %6d pkts  %4.1fs  %s" % (i, len(todo), e["id"], r["verdict"], r["packets"],
                                                           r["seconds"], r["reason"]), flush=True)
    write_report(doc, time.time() - t0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
