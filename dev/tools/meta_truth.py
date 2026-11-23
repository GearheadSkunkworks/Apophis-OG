#!/usr/bin/env python3
"""Prove every campaign-action display filter (netgen.campaign.actions.meta) matches the traffic its action emits.

Builds one example of each action exactly as ``checks/action_proofs.py`` does (same world, hosts and example
parameters), writes the packets to a pcap and the TLS key log next to it, renders each filter template with that
flow's real values (``{src_ip}`` ``{dst_ip}`` ``{fqdn}`` ``{p:NAME}`` = the effective parameter) and runs tshark.

    python tools/meta_truth.py                    # all actions, one line per filter
    python tools/meta_truth.py --only dns_beacon

Each result is one of: match, nomatch, invalid (tshark rejected the filter), unrendered (placeholder with no value),
nopackets, error.
"""
import argparse
import io
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
sys.path.insert(0, DEV)
sys.path.insert(0, os.path.join(DEV, "checks"))

TSHARK = "/Applications/Wireshark.app/Contents/MacOS/tshark"
# Filters that describe an option the default example does not exercise are also tried against these variants
# (extra parameter sets, built as separate examples); a filter matches when any variant matches.
ALT_PARAMS = {
    "exposed_service_login": [dict(service="ssh", attempts=3, successes=1)],
    "lolbin_fetch": [dict(component="bitsadmin")],
}
_PH = re.compile(r"\{(src_ip|dst_ip|fqdn|p:[A-Za-z0-9_]+)\}")


def render(template, src, dst, spec, example):
    """Fill a template; None when a placeholder has no value."""
    vals = {"src_ip": src.ip, "dst_ip": dst.ip, "fqdn": getattr(dst, "fqdn", "") or ""}
    missing = []

    def sub(m):
        k = m.group(1)
        if k.startswith("p:"):
            n = k[2:]
            if n in example:
                v = example[n]
            elif n in spec.params and "default" in spec.params[n]:
                v = spec.params[n]["default"]
            else:
                missing.append(k)
                return k
            return str(v)
        v = vals[k]
        if v == "":
            missing.append(k)
        return str(v)
    out = _PH.sub(sub, template)
    return None if missing else out


def tshark_count(pcap, keylog, flt):
    """(status, detail): status 'match' / 'nomatch' / 'invalid'."""
    cmd = [TSHARK, "-r", pcap, "-o", "tls.keylog_file:" + keylog, "-Y", flt, "-T", "fields", "-e", "frame.number"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if r.returncode == 2 or ("isn't a valid display filter" in r.stderr) or ("is neither a field" in r.stderr):
        return "invalid", r.stderr.strip()[-200:]
    n = len([x for x in r.stdout.splitlines() if x.strip()])
    return ("match" if n else "nomatch"), "%d frame(s)" % n


def run(only=None, keep=None):
    """[{token, what, template, rendered, expect, status, detail}] for every filter of every action."""
    from netgen import flows as F
    from netgen.campaign import actions
    from netgen.campaign.actions import meta
    from netgen.core import Host, PcapWriter
    from netgen.identity import H
    import action_proofs as AP
    from tests.test_actions_a import make_world
    actions.load_all()
    reg = actions.all_specs()
    ctx = make_world()
    internal_src = ctx.h[H("WS-009")]
    rows = []
    t = AP.T0
    with tempfile.TemporaryDirectory(prefix="meta-truth-") as tmp:
        for tok, spec in reg.items():
            if only and tok not in only:
                continue
            rec = meta.get(tok)
            if not rec:
                continue
            base = {"token": tok}
            try:
                ctx.keylog = io.StringIO()
                src = (AP._ext(F, Host, "198.18.30.9", "scanner.example.test") if spec.src == "external" else internal_src)
                if spec.dst == "internal":
                    dsts = [d for d in AP._candidates(ctx, spec, H) if d is not src]
                elif tok == "tor_connect":
                    dsts = [AP._ext(F, Host, "198.18.21.7", "", 11)]
                else:
                    dsts = [AP._ext(F, Host, "198.18.20.5", "update-check.c2.example.test")]
                base_ex = AP.EXAMPLE_PARAMS.get(tok, {})
                variants = [base_ex] + [dict(base_ex, **alt) for alt in ALT_PARAMS.get(tok, [])]
                built = []
                for vi, example in enumerate(variants):
                    ctx.keylog = io.StringIO()
                    pk, used = [], None
                    for dst in dsts:
                        pk = actions.get(tok).fn(ctx, src, dst, ts=t, **example) or []
                        if pk:
                            used = dst
                            break
                    t += 600.0
                    if not pk:
                        continue
                    pcap, key = os.path.join(tmp, "%s.%d.pcap" % (tok, vi)), os.path.join(tmp, "%s.%d.keys" % (tok, vi))
                    w = PcapWriter(pcap)
                    for ts, fr in sorted(pk, key=lambda p: p[0]):
                        w.write(ts, fr)
                    w.close()
                    with open(key, "w") as f:
                        f.write(ctx.keylog.getvalue())
                    if keep:
                        import shutil
                        os.makedirs(keep, exist_ok=True)
                        shutil.copy(pcap, os.path.join(keep, "%s.%d.pcap" % (tok, vi)))
                        shutil.copy(key, os.path.join(keep, "%s.%d.keys" % (tok, vi)))
                    built.append((pcap, key, used, example))
                if not built:
                    for what, tpl, exp in rec["filters"]:
                        rows.append(dict(base, what=what, template=tpl, rendered=None, expect=exp, status="nopackets", detail=""))
                    continue
                for what, tpl, exp in rec["filters"]:
                    inverse = exp.lower().startswith("no packet")
                    best = None
                    for pcap, key, used, example in built:
                        flt = render(tpl, src, used, spec, example)
                        if flt is None:
                            cand = ("unrendered", "", None)
                        else:
                            st, det = tshark_count(pcap, key, flt)
                            cand = (st, det, flt)
                        if cand[0] == "match" or best is None or best[0] in ("nomatch", "unrendered") and cand[0] == "invalid":
                            best = cand
                        if best[0] == "match":
                            break
                    st, det, flt = best
                    if inverse and st == "nomatch":
                        st = "match"
                        det = "absent, as expected"
                    elif inverse and st == "match":
                        st, det = "nomatch", "expected no packets but " + det
                    rows.append(dict(base, what=what, template=tpl, rendered=flt, expect=exp, status=st, detail=det))
            except Exception as e:                                 # noqa: BLE001
                for what, tpl, exp in rec["filters"]:
                    rows.append(dict(base, what=what, template=tpl, rendered=None, expect=exp, status="error",
                                     detail="%s: %s" % (type(e).__name__, e)))
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--only", action="append", default=[], metavar="TOKEN")
    ap.add_argument("--keep", metavar="DIR", help="copy each action's pcap and key log into DIR")
    a = ap.parse_args(argv)
    if not os.path.exists(TSHARK):
        print("tshark not found at", TSHARK)
        return 2
    rows = run(set(a.only) or None, a.keep)
    for r in rows:
        print("%-9s %-22s %s  [%s]" % (r["status"], r["token"], r["rendered"] or r["template"], r["detail"]))
    ok = sum(1 for r in rows if r["status"] == "match")
    print("%d filter(s), %d match, %d other" % (len(rows), ok, len(rows) - ok))
    return 0 if ok == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
