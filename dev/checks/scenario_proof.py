#!/usr/bin/env python3
"""Scenario proof harness: the checks that must pass BEFORE an independent validator is asked to look.

Usage: scenario_proof.py PROOF.json [--main-root DIR] [--branch-root DIR] [--out DIR] [--tshark PATH] [--skip-pin]
       scenario_proof.py --selftest

PROOF.json (worked examples: ir-ipopt-tcp-uaf.proof.json, ip-options-engine.proof.json):
  {"scenario": "ir-x",
   "build": {"module": "ir-x", "scale": 1.0, "date": "2026-11-04"},        # scenario build, from the branch
   "pin":   {"scale": 0.05, "date": "2026-11-04", "margin": 1.25},          # optional; baseline-only builds
   "slice": {"hosts": ["10.10.20.43", "203.0.113.121"]},                    # optional but use it: ONE pass cuts the scenario's
                                                                            # traffic into a small pcap, all checks read that
   "checks": [ {"id": "F1", "type": "count",    "filter": "...", "min": 1, "max": 9},
               {"id": "F2", "type": "distinct", "filter": "...", "field": "ip.src", "min": 2, "max": 4},
               {"id": "O1", "type": "order",    "before": "<filter>", "after": "<filter>", "before_at": "last"},
               {"id": "O2", "type": "precedes", "before": "<filter>", "after": "<filter>", "max_gap": 5},
               {"id": "P1", "type": "http_status_by_path", "path_contains": "/a/b", "sequence": [404, 200, 404],
                "winner_code": 200, "winner_count": 1} ]}

What it proves, and what it does not:
  * pin-safety: a `--no-modules` build on main versus the branch (any `--module X` build shifts the shared random stream, so
    a with/without comparison proves nothing), compared with a same-code rerun as the noise floor.
  * count / distinct: a filter reproduces by construction, so these are necessary, never sufficient.
  * order, precedes, http_status_by_path: the checks that caught the WordPress pilot's blockers (the same path 404 -> 200 -> 404; phase
    ordering; which source got the 200). Each is the author's claim about the wire, so a pass means "self-consistent", not
    "realistic". Realism stays with the independent validator, which this tool must not replace.
Speed: every check is a tshark scan, and a scan of a full-day scale-1.0 pcap (7.6 GB) takes minutes, so twenty checks on the full
pcap take 20+ minutes. With a `slice` block the harness reads the full pcap ONCE and runs the checks on the slice in seconds
(a check that must see baseline traffic outside the slice says "on": "full"). Iterate with `--scale 0.1` and `--pcap`; run the
proof file's own scale once before hand-off; `--cleanup` deletes the full pcap afterwards (agents' deletes are blocked, python's are not).
Exit 0 only when every check passes."""
import argparse, collections, json, os, subprocess, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent      # dev/
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tshark_locate import find_tshark  # noqa: E402 - sys.path is set up first
TSHARK_DEFAULT = find_tshark() or "tshark"
SIG_FIELDS = ["frame.len", "ip.src", "ip.dst", "ip.proto", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport"]


# ------------------------------------------------------------------ pure evaluators (unit-tested without tshark)
def fmt_range(spec):
    if "exact" in spec:
        return f"exactly {spec['exact']}"
    return f"{spec.get('min', '-')}..{spec.get('max', '-')}"


def in_range(n, spec):
    if "exact" in spec:
        return n == spec["exact"]
    lo, hi = spec.get("min"), spec.get("max")
    return (lo is None or n >= lo) and (hi is None or n <= hi)


def eval_count(n, spec):
    return in_range(n, spec), f"{n} frames (want {fmt_range(spec)})"


def eval_distinct(values, spec):
    n = len({v for v in values if v != ""})
    return in_range(n, spec), f"{n} distinct (want {fmt_range(spec)})"


def pick(ts, at):
    """The first or last time of a list (`at` is "first" or "last"); None when the filter matched nothing."""
    return None if not ts else (min(ts) if at == "first" else max(ts))


def eval_order(first_before, first_after):
    """Both filters must match, and the chosen time of `before` must precede the chosen time of `after`
    (use before_at "last" to prove a phase has ended before the next one starts, for example a download before a window)."""
    if first_before is None or first_after is None:
        return False, f"missing: before={first_before} after={first_after}"
    return first_before < first_after, f"before at {first_before:.3f} vs after at {first_after:.3f}"


def eval_precedes(before_times, after_times, max_gap):
    """Pairing check: every `after` frame must have a `before` frame ahead of it, at most `max_gap` seconds earlier
    (None = any gap). A first-time comparison cannot catch an event pair that is out of order in the middle of a day."""
    if not after_times:
        return False, "no `after` frames matched"
    bs = sorted(before_times)
    bad, i, latest = 0, 0, None
    for t in sorted(after_times):
        while i < len(bs) and bs[i] <= t:
            latest, i = bs[i], i + 1
        if latest is None or (max_gap is not None and t - latest > max_gap):
            bad += 1
    return bad == 0, f"{len(after_times) - bad}/{len(after_times)} `after` frames have a `before` within {max_gap}s"


def collapse(seq):
    out = []
    for s in seq:
        if not out or out[-1] != s:
            out.append(s)
    return out


def eval_status_by_path(responses, spec):
    """responses: [(time, path, code, client)]. Pass when, over responses whose path contains `path_contains` and sorted by
    time, the collapsed code sequence equals spec['sequence'] and (optional) the winner count matches."""
    sel = sorted((r for r in responses if spec["path_contains"] in r[1]), key=lambda r: r[0])
    seq = collapse([r[2] for r in sel])
    ok = seq == spec["sequence"]
    msg = f"sequence {seq} (want {spec['sequence']}) over {len(sel)} responses"
    if "winner_code" in spec:
        winners = collections.Counter(r[3] for r in sel if r[2] == spec["winner_code"])
        want = spec.get("winner_count")
        ok = ok and ((len(winners) == want) if want is not None else bool(winners))
        msg += f"; {spec['winner_code']} went to {len(winners)} source(s) {dict(winners)} (want {want})"
    return ok, msg


def sig_diff(a, b):
    """Size of the multiset symmetric difference of two signature-line lists."""
    ca, cb = collections.Counter(a), collections.Counter(b)
    return sum(((ca - cb) + (cb - ca)).values())


def eval_pin(main_sig, branch_sig, rerun_sig, margin):
    """Same frame count; main-vs-branch diff no larger than the same-code noise floor times the margin (+ a small constant)."""
    noise = sig_diff(branch_sig, rerun_sig)
    diff = sig_diff(main_sig, branch_sig)
    ok = len(main_sig) == len(branch_sig) and diff <= noise * margin + 10
    return ok, f"frames main {len(main_sig)} / branch {len(branch_sig)}; signature diff {diff} vs same-code noise {noise} (margin {margin})"


# ------------------------------------------------------------------ tshark / build plumbing
def tshark(tsh, pcap, display_filter, fields):
    cmd = [tsh, "-r", str(pcap), "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
    if display_filter:
        cmd += ["-Y", display_filter]
    for f in fields:
        cmd += ["-e", f]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"tshark failed ({display_filter!r}): {r.stderr.strip()[:300]}")
    return [line.split("\t") for line in r.stdout.splitlines()]


def times(tsh, pcap, flt):
    return [float(r[0]) for r in tshark(tsh, pcap, flt, ["frame.time_epoch"])]


def http_responses(tsh, pcap):
    """Pair each HTTP response with its request through http.request_in: [(time, path, code, client)]."""
    rows = tshark(tsh, pcap, "http", ["frame.number", "frame.time_epoch", "http.request.uri", "http.response.code",
                                       "http.request_in", "ip.src", "ip.dst"])
    rows = [r + [""] * (7 - len(r)) for r in rows]
    req_path = {r[0]: r[2] for r in rows if r[2]}
    return [(float(r[1]), req_path[r[4]], int(r[3]), r[6]) for r in rows if r[3] and r[4] in req_path]  # client = response dst


def build(py, root, pcap, scale, date, modules=None, no_modules=False):
    eng = Path(root) / "dev"
    cmd = [str(py), "opengenerator_build.py", "--scale", str(scale), "--out", str(pcap), "--no-certs", "--no-iocs"]
    if date:
        cmd += ["--date", date]
    if no_modules:
        cmd += ["--no-modules"]
    for m in modules or []:
        cmd += ["--module", m]
    r = subprocess.run(cmd, cwd=eng, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"build failed in {eng}: {(r.stderr or r.stdout)[-400:]}")


def signature(tsh, pcap):
    return ["\t".join(r) for r in tshark(tsh, pcap, None, SIG_FIELDS)]


def slice_filter(spec):
    """The display filter that cuts the scenario's own traffic out of the full-day pcap. `hosts` is a list of IPs (every frame with
    one of them as an endpoint is kept, so whole conversations stay together); `filter` is a raw display filter."""
    if spec.get("filter"):
        return spec["filter"]
    hosts = spec.get("hosts") or []
    if not hosts:
        raise ValueError("slice needs `hosts` or `filter`")
    return "ip.addr in {" + ", ".join(hosts) + "}"


def make_slice(tsh, pcap, spec, out):
    """ONE pass over the full-day pcap writes a small slice; every check then reads the slice (seconds) instead of the full
    pcap (minutes per check on a 7.6 GB day). Reused when the slice is newer than the pcap."""
    out = Path(out)
    if out.exists() and out.stat().st_mtime >= Path(pcap).stat().st_mtime:
        return out
    r = subprocess.run([tsh, "-r", str(pcap), "-Y", slice_filter(spec), "-w", str(out)], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"slice failed: {r.stderr.strip()[:300]}")
    return out


# ------------------------------------------------------------------ run
def run_checks(tsh, pcap, checks, slice_pcap=None):
    """Each check reads the slice when there is one; a check with "on": "full" reads the full pcap (needed only when it must see
    baseline traffic outside the slice)."""
    results = []
    full = pcap
    for c in checks:
        pcap = full if (slice_pcap is None or c.get("on") == "full") else slice_pcap
        t = c["type"]
        try:
            if t == "count":
                ok, msg = eval_count(len(tshark(tsh, pcap, c["filter"], ["frame.number"])), c)
            elif t == "distinct":
                ok, msg = eval_distinct([r[0] for r in tshark(tsh, pcap, c["filter"], [c["field"]])], c)
            elif t == "order":
                ok, msg = eval_order(pick(times(tsh, pcap, c["before"]), c.get("before_at", "first")),
                                     pick(times(tsh, pcap, c["after"]), c.get("after_at", "first")))
            elif t == "precedes":
                ok, msg = eval_precedes(times(tsh, pcap, c["before"]), times(tsh, pcap, c["after"]), c.get("max_gap"))
            elif t == "http_status_by_path":
                ok, msg = eval_status_by_path(http_responses(tsh, pcap), c)
            else:
                ok, msg = False, f"unknown check type {t!r}"
        except Exception as e:  # a broken filter is a failed check, not a crash
            ok, msg = False, f"error: {e}"
        results.append((c["id"], t, ok, msg))
    return results


def selftest():
    assert eval_count(5, {"min": 1, "max": 9})[0] and not eval_count(0, {"min": 1})[0] and eval_count(3, {"exact": 3})[0]
    assert eval_distinct(["a", "b", "a", ""], {"min": 2, "max": 2})[0]
    assert pick([3, 1, 2], "first") == 1 and pick([3, 1, 2], "last") == 3 and pick([], "first") is None
    assert eval_order(1.0, 2.0)[0] and not eval_order(2.0, 1.0)[0] and not eval_order(None, 1.0)[0]
    resp = [(1, "/w/setup", 404, "10.0.0.1"), (2, "/w/setup", 404, "10.0.0.2"), (3, "/w/setup", 200, "10.0.0.2"),
            (4, "/w/setup", 404, "10.0.0.1"), (5, "/other", 200, "10.0.0.9")]
    spec = {"path_contains": "/w/setup", "sequence": [404, 200, 404], "winner_code": 200, "winner_count": 1}
    assert eval_status_by_path(resp, spec)[0]
    assert not eval_status_by_path(resp, {**spec, "sequence": [404, 200]})[0]
    assert not eval_status_by_path(resp, {**spec, "winner_count": 2})[0]
    assert collapse([1, 1, 2, 2, 1]) == [1, 2, 1]
    assert eval_precedes([1, 10], [2, 11], 5)[0] and not eval_precedes([1], [2, 11], 5)[0] and eval_precedes([1], [2, 11], None)[0]
    assert not eval_precedes([5], [2], None)[0] and not eval_precedes([1], [], None)[0]
    assert slice_filter({"hosts": ["10.0.0.1", "203.0.113.5"]}) == "ip.addr in {10.0.0.1, 203.0.113.5}"
    assert slice_filter({"filter": "tcp.port == 9", "hosts": ["1.1.1.1"]}) == "tcp.port == 9"
    try:
        slice_filter({})
        raise AssertionError("empty slice accepted")
    except ValueError:
        pass
    a = ["x"] * 100
    assert eval_pin(a, a[:], a[:], 1.25)[0]                                        # identical
    assert not eval_pin(a, a + ["y"], a[:], 1.25)[0]                               # frame count differs
    drift = ["z"] * 50 + a[:50]
    assert not eval_pin(a, drift, drift[:], 1.25)[0]                               # drift beyond a quiet noise floor
    assert eval_pin(a, drift, ["w"] * 50 + a[:50], 1.25)[0]                        # same drift inside a noisy floor
    print("scenario_proof selftest: ok")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("proof", nargs="?")
    ap.add_argument("--main-root", default=None, help="main checkout for the pin build (default: git's main worktree)")
    ap.add_argument("--branch-root", default=str(HERE.parent), help="the checkout holding the scenario under test (default: this one)")
    ap.add_argument("--out", default=None, help="folder for pcaps (default: a temp folder)")
    ap.add_argument("--tshark", default=os.environ.get("TSHARK", TSHARK_DEFAULT))
    ap.add_argument("--skip-pin", action="store_true")
    ap.add_argument("--pcap", default=None, help="evaluate the checks on an existing scenario pcap; no builds, no pin test")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--scale", type=float, default=None,
                    help="override the scenario build's scale for an ITERATION run (e.g. 0.1); counts are then not final, run at the "
                         "proof file's scale once before hand-off")
    ap.add_argument("--no-slice", action="store_true", help="read the full pcap for every check even when the proof file has a slice")
    ap.add_argument("--cleanup", action="store_true",
                    help="delete the full scenario pcap this run built once the checks are done (the slice and --pcap files are kept)")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.proof:
        ap.error("PROOF.json required")
    proof = json.loads(Path(a.proof).read_text())
    if a.pcap:
        a.skip_pin = True
    py = Path(sys.executable)
    out = Path(a.out or tempfile.mkdtemp(prefix="scenario-proof-"))
    out.mkdir(parents=True, exist_ok=True)
    rows, phases, t0 = [], [], time.time()

    def lap(name):
        nonlocal t0
        phases.append((name, time.time() - t0))
        t0 = time.time()

    if proof.get("pin") and not a.skip_pin:
        p = proof["pin"]
        main_root = a.main_root or subprocess.run(["git", "-C", a.branch_root, "worktree", "list", "--porcelain"],
                                                  capture_output=True, text=True).stdout.split("\n")[0].split(" ", 1)[1]
        sigs = {}
        for name, root in (("main", main_root), ("branch", a.branch_root), ("rerun", a.branch_root)):
            pc = out / f"pin-{name}.pcap"
            build(py, root, pc, p.get("scale", 0.05), p.get("date"), no_modules=True)
            sigs[name] = signature(a.tshark, pc)
            pc.unlink()  # the signature is all that is kept; the pin pcaps are never needed again
        ok, msg = eval_pin(sigs["main"], sigs["branch"], sigs["rerun"], p.get("margin", 1.25))
        rows.append(("PIN", "pin_safety", ok, msg))
        lap("pin test (3 baseline builds)")
    b = proof["build"]
    scale = a.scale if a.scale is not None else b.get("scale", 1.0)
    pc = Path(a.pcap) if a.pcap else out / "scenario.pcap"
    if not a.pcap:
        build(py, a.branch_root, pc, scale, b.get("date"), modules=[b["module"]])
        lap(f"scenario build (scale {scale})")
    slice_pc = None
    if proof.get("slice") and not a.no_slice:
        slice_pc = make_slice(a.tshark, pc, proof["slice"], out / (pc.stem + ".slice.pcap"))
        lap("slice (one pass)")
    rows += run_checks(a.tshark, pc, proof["checks"], slice_pc)
    lap(f"{len(proof['checks'])} checks on the {'slice' if slice_pc else 'full pcap'}")
    failed = 0
    if a.scale is not None:
        print(f"ITERATION RUN at scale {scale}: counts are not final; rerun at scale {b.get('scale', 1.0)} before hand-off")
    for cid, t, ok, msg in rows:
        print(f"{'PASS' if ok else 'FAIL'}  {cid:<6} {t:<20} {msg}")
        failed += 0 if ok else 1
    print("time: " + "; ".join(f"{n} {s:.0f}s" for n, s in phases))
    if a.cleanup and not a.pcap and pc.exists():
        pc.unlink()
        print(f"deleted {pc}")
    print(f"{len(rows) - failed}/{len(rows)} passed; files in {out}" + ("" if a.cleanup else " (delete them when done, or use --cleanup)"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main() or 0)
