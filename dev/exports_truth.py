"""Post-build exporter "truth": <stem>-truth.jsonl, one JSON line per flow in the finished capture.

Each line is the flowtable record plus `scenario` (the tag without its "incident:" prefix; baseline
tags are kept as "baseline:<tag>"), `benign` (true for baseline tags) and the `rules` used. Plain data
about what the generator put on the wire: no scoring, no sensor knowledge, no verdicts.

Registered by opengenerator_build; runs only when the build option exports contains "truth", which
also turns the tag sidecar on. Never raises: a failure is recorded in the returned block and the
capture is kept. exports_consistent is True when flow packets plus unflowed frames equal the number
of packets the main writer wrote.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import safeio  # noqa: E402 - sys.path is set up before the import
import build_manifest as BM  # noqa: E402 - sys.path is set up before the import
import flowtable             # noqa: E402 - sys.path is set up before the import

KIND = "flow-truth"


def truth_path(out):
    return (out[:-5] if out.endswith(".pcap") else out) + "-truth.jsonl"


def export(e):
    """_ExportCtx -> {"truth": block} (or {} when not requested). Needs e.exports and e.tags_path."""
    if "truth" not in (getattr(e, "exports", None) or ()):
        return {}
    path = truth_path(e.out)
    block = {"kind": KIND, "file": os.path.basename(path), "rules": dict(flowtable.RULES)}
    tmp = path + ".tmp"
    try:
        if not getattr(e, "tags_path", None):
            raise ValueError("the tag sidecar is missing")
        stats = {}
        n = flow_pkts = 0
        rules = json.dumps({k: v for k, v in flowtable.RULES.items() if k.endswith("_idle")})
        with safeio.create_new(tmp, "w", encoding="utf-8") as f:
            for r in flowtable.export_flows(e, stats):
                tag = r["tag"]
                benign = not tag.startswith("incident:")
                r = {**r, "scenario": ("baseline:" + tag) if benign else tag[len("incident:"):],
                     "benign": benign, "rules": json.loads(rules)}
                f.write(json.dumps(r, separators=(",", ":")) + "\n")
                n += 1
                flow_pkts += r["orig_pkts"] + r["resp_pkts"]
        os.replace(tmp, path)
        block.update(records=n, flow_packets=flow_pkts, unflowed_frames=stats["unflowed"],
                     packets=e.writer.n, tags_sha256=BM.sha256_file(e.tags_path),
                     exports_consistent=flow_pkts + stats["unflowed"] == e.writer.n)
    except Exception as ex:                              # noqa: BLE001 -- never discard a finished capture
        block.pop("file")
        block["error"] = BM.export_error(ex)
        try:
            os.remove(tmp)
        except OSError:
            pass
    return {"truth": block}
