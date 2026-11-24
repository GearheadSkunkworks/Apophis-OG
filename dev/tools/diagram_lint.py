#!/usr/bin/env python3
"""Lint the SVG of registered diagrams or campaign pages (developer tool, M4b).

    python3 tools/diagram_lint.py --all                       every registered diagram
    python3 tools/diagram_lint.py topology timeline           named diagrams
    python3 tools/diagram_lint.py --campaign FILE [FILE ...]  campaign pages (plan mode, or run mode when FILE's
                                                              sibling NAME.summary.json exists; NAME.score.json adds a score)
    options: --top N (worst offenders listed, default 10)  --quiet (summary only)  --kind overlap,clip,... (filter)

Prints each finding, then a count by kind and the worst offenders. Exit status 1 when any finding remains.
"""
import argparse
import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from diagrams.campaign.lint import lint_html  # noqa: E402


def _campaign_page(path):
    """HTML for a campaign file. A JSON list is several campaigns (form 10): their pages are joined for linting."""
    from diagrams.campaign import page
    with open(path, encoding="utf-8") as f:
        camp = json.load(f)
    base = path[:-5] if path.endswith(".json") else path
    summary = score = None
    for suffix, slot in ((".summary.json", "summary"), (".score.json", "score")):
        if os.path.exists(base + suffix):
            with open(base + suffix, encoding="utf-8") as f:
                data = json.load(f)
            if slot == "summary":
                summary = data
            else:
                score = data
    if isinstance(camp, list):
        sums = summary if isinstance(summary, list) else [summary] * len(camp)
        return "\n".join(page.render(c, summary=s, score=score) for c, s in zip(camp, sums, strict=False))
    return page.render(camp, summary=summary, score=score)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("names", nargs="*", help="registered diagram names")
    ap.add_argument("--all", action="store_true", help="every registered diagram, scenario diagrams included")
    ap.add_argument("--campaign", nargs="+", metavar="FILE", default=[], help="campaign JSON files")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--kind", default="", help="comma list of kinds to keep")
    a = ap.parse_args(argv)
    if not (a.all or a.names or a.campaign):
        ap.error("name a diagram, or pass --all or --campaign")
    keep = {k for k in a.kind.split(",") if k}
    jobs = []
    if a.all or a.names:
        import make_diagram
        names = sorted(make_diagram.DIAGRAMS) if a.all else a.names
        for n in names:
            jobs.append((n, lambda n=n: make_diagram.render(n)))
    for p in a.campaign:
        jobs.append((os.path.basename(p), lambda p=p: _campaign_page(p)))
    by_kind, per = Counter(), {}
    for name, make in jobs:
        try:
            fs = lint_html(make())
        except Exception as e:                                   # noqa: BLE001
            print("%s: could not render: %s: %s" % (name, type(e).__name__, e))
            per[name] = [None]
            continue
        if keep:
            fs = [f for f in fs if f.kind in keep]
        per[name] = fs
        for f in fs:
            by_kind[f.kind] += 1
            if not a.quiet:
                print("%s: %s %s: %s" % (name, f.kind, f.element, f.detail))
    bad = {n: v for n, v in per.items() if v}
    print("-- %d diagram(s) linted, %d with findings, %d finding(s): %s" % (
        len(per), len(bad), sum(by_kind.values()), ", ".join("%s %d" % kv for kv in sorted(by_kind.items())) or "none"))
    worst = sorted(bad.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:a.top]
    for n, v in worst:
        print("   %-28s %d" % (n, len(v)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
