"""capture_summary — a real (non-demo) capability module of kind ``exporter``.

Writes a machine-readable ``<capture>-summary.json`` sidecar next to the pcap every time a
build runs while this module is loaded. It is the JSON companion to the built-in CSV
generation report: a single object a CI job or sensor-test harness can ingest without parsing
a pcap — what generated the capture, which fictional company it portrays, how big it is, the
per-protocol packet breakdown, and which scenarios were injected.

As an *exporter* it runs after the capture is written and only reads the finished build
artifacts (``ectx``); it never puts a packet on the wire, so it cannot move the baseline
baseline whether loaded or not. Loading it simply adds one more output file.

Contract touched: ``opengenerator_build.register_exporter(name, fn)`` — ``fn(ectx)`` returns a
dict merged into the build summary. Teardown removes exactly the entry we appended, so an
unload leaves ``EXPORTERS`` as it was.
"""
import datetime
import json
import os

import opengenerator_build as OGB
from netgen import identity as IDENT
import branding

EXPORTER = "capture-summary"       # name under which we register into EXPORTERS


def _summary(e):
    """Exporter fn: write ``<out>-summary.json`` and return ``{"summary_json": path}``.

    Reads only the documented ExportCtx surface: ``out`` (pcap path), ``writer`` (``.n``,
    ``.bytes``, ``.protocols``), ``ctx`` (``.h`` host map), and ``selected`` (scenario names)."""
    ident = IDENT.get_current()
    w = e.writer
    base = e.out[:-5] if e.out.endswith(".pcap") else e.out
    path = base + "-summary.json"

    doc = {
        "generator": {
            "product": branding.PRODUCT_NAME,
            "version": branding.VERSION,
            "codename": branding.CODENAME,
        },
        "generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "company": {
            "name": ident.name,
            "industry": ident.industry,
            "domain": ident.domain,
            "host_prefix": ident.prefix,
        },
        "capture": {
            "path": os.path.basename(e.out),
            "packets": w.n,
            "bytes": w.bytes,
            "devices": len(getattr(e.ctx, "h", {}) or {}),
        },
        # per-protocol counts, most frequent first
        "protocols": [
            {"protocol": name, "packets": n}
            for name, n in sorted(w.protocols.items(), key=lambda kv: -kv[1])
        ],
        "scenarios": list(e.selected or []),
    }
    try:
        with open(path, "w") as f:
            json.dump(doc, f, indent=2)
    except OSError:
        return {"summary_json": None}
    return {"summary_json": path}


def register(kernel):
    """Append the exporter to the build's EXPORTERS registry; remove exactly it on unload."""
    OGB.register_exporter(EXPORTER, _summary)

    def _undo():
        # drop the (name, fn) tuple we added, matched by identity so we never touch another's
        for i in range(len(OGB.EXPORTERS) - 1, -1, -1):
            nm, fn = OGB.EXPORTERS[i]
            if nm == EXPORTER and fn is _summary:
                OGB.EXPORTERS.pop(i)
                break

    kernel.on_unload(_undo)


def self_test():
    """Build a minimal fake ExportCtx, run the exporter to a temp file, and confirm it wrote
    valid JSON carrying the expected top-level keys and the packet total we fed it."""
    import tempfile

    class _W:
        n = 1234
        bytes = 567890
        protocols = {"TCP": 1000, "DNS": 200, "TLS": 34}

    class _Ctx:
        h = {"EXL-DC1": object(), "EXL-WS-001": object()}

    d = tempfile.mkdtemp(prefix="capsum-")
    try:
        out = os.path.join(d, "probe.pcap")
        e = OGB._ExportCtx(out=out, writer=_W(), ctx=_Ctx(), selected=["ndr-recon"])
        res = _summary(e)
        p = res.get("summary_json")
        if not p or not os.path.isfile(p):
            return {"ok": False, "detail": "no summary.json written"}
        with open(p) as f:
            doc = json.load(f)
        need = {"generator", "generated_at", "company", "capture", "protocols", "scenarios"}
        missing = need - set(doc)
        ok = not missing and doc["capture"]["packets"] == 1234 and doc["scenarios"] == ["ndr-recon"]
        return {"ok": ok,
                "detail": "wrote %s (%d protocols, packets=%s)"
                          % (os.path.basename(p), len(doc.get("protocols", [])),
                             doc.get("capture", {}).get("packets"))
                          if ok else "missing keys: %s" % sorted(missing)}
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)
