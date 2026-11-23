#!/usr/bin/env python3
"""Measure how every scenario's own traffic changes with the size setting.

    python3.14 tools/measure_scenario_scale.py [--only ID ...] [--workers 6] [--force]

Each scenario is built alone (normal day switched off) at the anchor scales, in a child process, and its packets and
pcap bytes are recorded in dev/scenario_scale.json. The page uses the table to estimate a capture's size and to say
whether a scenario is fixed in size or grows with the setting. Resumable: scenarios already in the file are skipped
unless --force. Re-run after changing a scenario builder.
"""
import argparse
import concurrent.futures as cf
import json
import os
import subprocess
import sys
import tempfile
import time

DEV = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(DEV, "scenario_scale.json")
ANCHORS = [0.004, 0.02, 0.1, 0.5, 1.0]
TIMEOUT = 900
CHILD = """
import sys, json
sys.path.insert(0, %r)
import opengenerator_build as OGB
sid, scale, ot = sys.argv[2], float(sys.argv[3]), sys.argv[4] == "1"
class NoDay(OGB.Day):
    def build(self): pass
OGB.Day = NoDay
s = OGB.build(scale=scale, out=sys.argv[1], keylog=sys.argv[1] + ".k", inventory=%r, certs_dir=None, iocs_prefix=None,
              modules=[sid], progress=False, ot_nets=dict(OGB.OT_DEFAULTS) if ot else None)
print(json.dumps({"packets": s["packets"], "bytes": s["bytes"]}))
""" % (DEV, os.path.join(DEV, "inventory.json"))


def scenario_ids():
    sys.path.insert(0, DEV)
    from netgen import incidents as INC
    skip = {"campaign", "custom-import"}                      # recipe-driven: nothing to build alone
    return [(n, n in getattr(INC, "OT_SCENARIOS", set())) for n in INC.REGISTRY if n not in skip]


def measure(sid, scale, ot):
    d = tempfile.mkdtemp(prefix="og-scale-")
    try:
        r = subprocess.run([sys.executable, "-c", CHILD, os.path.join(d, "s.pcap"), sid, str(scale), "1" if ot else "0"],
                           capture_output=True, text=True, timeout=TIMEOUT)
        if r.returncode != 0:
            return None, r.stderr.strip().splitlines()[-1][:200] if r.stderr.strip() else "failed"
        return json.loads(r.stdout.strip().splitlines()[-1]), None
    except subprocess.TimeoutExpired:
        return None, "timeout"
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    data = {"anchors": ANCHORS, "scenarios": {}}
    if os.path.exists(OUT) and not a.force:
        with open(OUT, encoding="utf-8") as f:
            data = json.load(f)
    todo = [(n, ot) for n, ot in scenario_ids() if (not a.only or n in a.only) and (a.force or n not in data["scenarios"])]
    t0 = time.time()

    def job(item):
        n, ot = item
        pk, by, errs = [], [], []
        for sc in ANCHORS:
            m, e = measure(n, sc, ot)
            pk.append(m["packets"] if m else None)
            by.append(m["bytes"] if m else None)
            if e:
                errs.append("%s: %s" % (sc, e))
        return n, {"packets": pk, "bytes": by, **({"errors": errs} if errs else {})}

    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        for n, row in ex.map(job, todo):
            data["scenarios"][n] = row
            data["generated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            tmp = OUT + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=1)
            os.replace(tmp, OUT)
            print("%-34s %s%s" % (n, row["packets"], "  ERRORS" if "errors" in row else ""), flush=True)
    print("done: %d scenarios in %.0f s" % (len(todo), time.time() - t0))


if __name__ == "__main__":
    main()
