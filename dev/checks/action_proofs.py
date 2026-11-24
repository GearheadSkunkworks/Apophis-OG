#!/usr/bin/env python3
"""Per-action proofs for the campaign builder.

Builds one example of every registered campaign action in a real engine context (the test world from
``tests/test_actions_a.py``), then checks it with independent tools:

  * RFC 791 / TCP / UDP / ICMP validity: ``checks/check_rfc791.py`` on a pcap written from the action's packets
  * tshark (when installed): protocols seen, and a count of malformed frames, bad checksums and expert errors

and writes ``docs/action-proofs.md`` (one table row per action) plus, with ``--json PATH``, the same data as JSON.

    python checks/action_proofs.py                 # run everything registered, write docs/action-proofs.md
    python checks/action_proofs.py --json out.json
    python checks/action_proofs.py --only dns_beacon --only winrm_exec --no-write
    python checks/action_proofs.py --list-gaps     # tactics with fewer than two actions

Exit status is 1 when any action produced no packets, raised, failed the RFC 791 check, or showed tshark errors.
Actions are example-sized (default parameters except where noted in ``EXAMPLE_PARAMS``) and all traffic is the
benign look-alike traffic the actions always emit.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
sys.path.insert(0, DEV)
sys.path.insert(0, HERE)

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
DOC = os.path.join(DEV, "docs", "action-proofs.md")
T0 = 1773489600.0                      # same pinned capture instant as the action tests
# Smaller-than-default examples keep a full run short; anything not listed runs with its defaults.
EXAMPLE_PARAMS = {
    "https_beacon": dict(count=2, interval_s=5.0), "http_beacon": dict(count=2, interval_s=5.0),
    "dns_beacon": dict(count=3, interval_s=5.0), "dns_tunnel": dict(bursts=1, per_burst=6),
    "tor_connect": dict(duration_s=20.0, records=8), "payload_download": dict(size=60000),
    "https_upload": dict(total_bytes=400000), "dga_lookup": dict(count=5),
}
_FLAGGED = ('_ws.malformed || ip.checksum.status == "Bad" || tcp.checksum.status == "Bad" || '
            'udp.checksum.status == "Bad" || _ws.expert.severity == "Error"')
_SKIP_PROTOS = {"eth", "ethertype", "ip", "tcp", "udp", "data", "frame", "vlan", "ipv6"}


def _ext(F, Host, ip, fqdn, hops=9):
    h = Host(fqdn.split(".")[0].upper() if fqdn else "EXT", ip,
             "02:00:5e:%02x:%02x:%02x" % tuple(F.rng.randrange(256) for _ in range(3)),
             "linux", "external", ip.rsplit(".", 1)[0] + ".0/24", fqdn)
    h.hops = hops
    return h


def tactic_gaps(registry=None):
    """[(slug, name, count)] for every ATT&CK tactic with fewer than two registered actions."""
    from netgen.campaign import actions, attack
    actions.load_all()
    reg = registry if registry is not None else actions.all_specs()
    counts = {}
    for spec in reg.values():
        counts[spec.tactic] = counts.get(spec.tactic, 0) + 1
    return [(t["slug"], t["name"], counts.get(t["slug"], 0)) for t in attack.tactics() if counts.get(t["slug"], 0) < 2]


def _tshark(path):
    """(available, protocols, problems, error) for one pcap."""
    if not os.path.exists(TSHARK):
        return False, [], 0, None
    base = [TSHARK, "-r", path, "-o", "tcp.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE",
            "-o", "ip.check_checksum:TRUE"]
    try:
        r = subprocess.run(base + ["-T", "fields", "-e", "frame.protocols"], capture_output=True, text=True, timeout=300)
        protos = []
        for line in r.stdout.splitlines():
            for p in line.strip().split(":"):
                if p and p not in _SKIP_PROTOS and p not in protos:
                    protos.append(p)
        f = subprocess.run(base + ["-Y", _FLAGGED, "-T", "fields", "-e", "frame.number", "-e", "_ws.col.Protocol",
                                   "-e", "_ws.col.Info"], capture_output=True, text=True, timeout=300)
        if r.returncode or f.returncode:
            return True, protos, 0, (r.stderr or f.stderr)[-300:]
        bad = [x for x in f.stdout.splitlines() if x.strip()]
        return True, protos, len(bad), ("; ".join(bad[:3]) if bad else None)
    except Exception as e:                                         # noqa: BLE001
        return True, [], 0, "%s: %s" % (type(e).__name__, e)


def _candidates(ctx, spec, H):
    """Internal destination candidates, best guess first: the action's required hosts, then common servers."""
    order = []
    for suffix in list(spec.needs) + ["FILE1", "DC1", "SQL1", "WEB1", "WS-010", "WS-011"]:
        name = H(suffix)
        if name in ctx.h and ctx.h[name] not in order:
            order.append(ctx.h[name])
    return order


def run(only=None, keep=None):
    import io
    from netgen import flows as F
    from netgen.campaign import actions
    from netgen.core import Host, PcapWriter
    from netgen.identity import H
    import check_rfc791
    from tests.test_actions_a import make_world
    actions.load_all()
    reg = actions.all_specs()
    ctx = make_world()
    internal_src = ctx.h[H("WS-009")]
    tmp = tempfile.mkdtemp(prefix="action-proofs-")
    rows = []
    t = T0
    try:
        for tok, spec in reg.items():
            if only and tok not in only:
                continue
            row = {"token": tok, "title": spec.title, "tactic": spec.tactic, "techniques": list(spec.techniques),
                   "declared_protocols": list(spec.protocols), "packets": 0, "protocols": [], "rfc791": False,
                   "tshark": None, "tshark_problems": 0, "dst": None, "note": None}
            rows.append(row)
            try:
                ctx.keylog = io.StringIO()
                src = (_ext(F, Host, "198.18.30.9", "scanner.example.test") if spec.src == "external" else internal_src)
                if spec.dst == "internal":
                    dsts = [d for d in _candidates(ctx, spec, H) if d is not src]
                elif spec.token == "tor_connect":
                    dsts = [_ext(F, Host, "198.18.21.7", "", 11)]
                else:
                    dsts = [_ext(F, Host, "198.18.20.5", "update-check.c2.example.test")]
                pk, tried = [], []
                for dst in dsts:
                    tried.append(dst.name)
                    pk = actions.get(tok).fn(ctx, src, dst, ts=t, **EXAMPLE_PARAMS.get(tok, {})) or []
                    if pk:
                        row["dst"] = dst.name
                        break
                t += 600.0
                if not pk:
                    row["note"] = "no packets (tried %s)" % ", ".join(tried)
                    continue
                pk = sorted(pk, key=lambda p: p[0])
                row["packets"] = len(pk)
                path = os.path.join(tmp, tok + ".pcap")
                w = PcapWriter(path)
                for ts, fr in pk:
                    w.write(ts, fr)
                w.close()
                counts, fails, _ex, first = check_rfc791.check(path, quiet=True)
                row["rfc791"] = not sum(fails.values())
                if not row["rfc791"]:
                    row["note"] = "RFC 791: " + "; ".join(first[:2])
                avail, protos, bad, err = _tshark(path)
                row["protocols"] = protos
                row["tshark"] = (not bad and err is None) if avail else None
                row["tshark_problems"] = bad
                if avail and not row["tshark"]:
                    row["note"] = ((row["note"] + " | ") if row["note"] else "") + "tshark: " + str(err)
                if keep:
                    os.makedirs(keep, exist_ok=True)
                    shutil.copy(path, os.path.join(keep, tok + ".pcap"))
            except Exception as e:                                 # noqa: BLE001
                row["note"] = "raised %s: %s" % (type(e).__name__, e)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return rows


def passed(row):
    return bool(row["packets"] and row["rfc791"] and row["tshark"] is not False and not row["note"])


def markdown(rows):
    tsk = os.path.exists(TSHARK)
    L = ["# Campaign action proofs", "",
         "Generated by `checks/action_proofs.py`; do not edit by hand. One example of every registered action, "
         "built in the engine's test world, checked with `checks/check_rfc791.py` (IPv4 header, TCP/UDP/ICMP "
         "checksums) and%s." % (" tshark (protocols seen; malformed frames, bad checksums and expert errors "
                                 "must be zero)" if tsk else " tshark (not installed when this was generated: column shows n/a)"),
         "", "%d action(s), %d passing." % (len(rows), sum(1 for r in rows if passed(r))), "",
         "| Token | Tactic | Techniques | Packets | Protocols seen | RFC 791 | tshark | Note |",
         "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        ts = {True: "pass", False: "FAIL", None: "n/a"}[r["tshark"]]
        L.append("| `%s` | %s | %s | %d | %s | %s | %s | %s |" % (
            r["token"], r["tactic"], ", ".join(r["techniques"]), r["packets"],
            ", ".join(r["protocols"]) or "-", "pass" if r["rfc791"] else "FAIL", ts,
            (r["note"] or "").replace("|", "/")))
    gaps = tactic_gaps()
    L += ["", "## Tactic coverage", ""]
    L.append("Every tactic has at least two actions." if not gaps else
             "Tactics with fewer than two actions: " + ", ".join("%s (%d)" % (g[0], g[2]) for g in gaps) + ".")
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build, validate and document one example of every campaign action")
    ap.add_argument("--json", metavar="PATH", help="also write the results as JSON")
    ap.add_argument("--list-gaps", action="store_true", help="print tactics with fewer than two actions and exit")
    ap.add_argument("--only", action="append", default=[], metavar="TOKEN", help="run only this action (repeatable)")
    ap.add_argument("--no-write", action="store_true", help="do not write docs/action-proofs.md")
    ap.add_argument("--keep", metavar="DIR", help="copy each action's pcap into DIR")
    a = ap.parse_args(argv)
    if a.list_gaps:
        gaps = tactic_gaps()
        if not gaps:
            print("every tactic has at least two actions")
        for slug, name, n in gaps:
            print("%-22s %-22s %d action(s)" % (slug, name, n))
        return 0
    rows = run(set(a.only) or None, a.keep)
    for r in rows:
        print("%-24s %-5s packets=%-5d %s%s" % (r["token"], "ok" if passed(r) else "FAIL", r["packets"],
                                                 ",".join(r["protocols"][:6]), "  " + r["note"] if r["note"] else ""))
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"actions": rows, "gaps": [dict(zip(("tactic", "name", "count"), g, strict=False)) for g in tactic_gaps()],
                       "tshark": os.path.exists(TSHARK)}, f, indent=1)
    if not a.no_write and not a.only:
        with open(DOC, "w") as f:
            f.write(markdown(rows))
        print("wrote", DOC)
    bad = [r["token"] for r in rows if not passed(r)]
    print("%d action(s), %d failing%s" % (len(rows), len(bad), ": " + ", ".join(bad) if bad else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
