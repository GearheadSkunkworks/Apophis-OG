"""Post-build exporters "ssl" and "http": Zeek-style <stem>-ssl.log + <stem>-x509.log and <stem>-http.log.

Built from the finished pcap by zeekapp.analyze (one pass shared by both when both are requested).
Registered by opengenerator_build as one function; each export runs only when the build option exports
contains its name. Never raises: a failure is recorded in the returned block (no "files" key) and the
capture is kept. These exports do not need the tag sidecar, so a sidecar overflow does not stop them.

Each block: kind, files (base names beside the pcap), records, rules (reassembly cap, flow idle time),
stats (flows seen, TLS flows whose certificates were not in the clear, broken/capped streams, messages
over the cap), packets, exports_consistent (the pass saw exactly the packets the writer wrote). Files
and their sha256 are listed in the manifest outputs. "Zeek-style": no claim of byte-identical Zeek output.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zeekapp  # noqa: E402 - sys.path is set up first
KIND_SSL = "zeek-style-ssl-x509"
KIND_HTTP = "zeek-style-http"


def _base(out):
    return out[:-5] if out.endswith(".pcap") else out


def ssl_path(out):
    return _base(out) + "-ssl.log"


def x509_path(out):
    return _base(out) + "-x509.log"


def http_path(out):
    return _base(out) + "-http.log"


def _remove(*paths):
    for p in paths:
        try:
            os.remove(p)
        except OSError:
            pass                                         # not written yet: nothing to clean


def _analysis(e):
    """Run zeekapp.analyze once per build and keep the result on the export context."""
    if getattr(e, "_zeekapp", None) is None:
        stats = {}
        e._zeekapp = (zeekapp.analyze(e.out, stats=stats), stats)
    return e._zeekapp


def _block(kind, e, stats, **kw):
    return dict(kind=kind, rules=dict(zeekapp.RULES), stats=dict(stats), packets=e.writer.n,
                exports_consistent=stats["packets"] == e.writer.n, **kw)


def export(e):
    """_ExportCtx -> {"ssl": block, "http": block} for the requested ones ({} when none)."""
    want = getattr(e, "exports", None) or ()
    res = {}
    if "ssl" in want:
        paths = (ssl_path(e.out), x509_path(e.out))
        try:
            (ssl, x509, _), stats = _analysis(e)
            zeekapp.write_ssl_log(ssl, paths[0])
            zeekapp.write_x509_log(x509, paths[1])
            res["ssl"] = _block(KIND_SSL, e, stats, files=[os.path.basename(p) for p in paths],
                                records={"ssl": len(ssl), "x509": len(x509)})
        except Exception as ex:                          # noqa: BLE001 - never discard a finished capture
            _remove(*paths)
            res["ssl"] = {"kind": KIND_SSL, "error": "%s: %s" % (type(ex).__name__, ex)}
    if "http" in want:
        path = http_path(e.out)
        try:
            (_, _, http), stats = _analysis(e)
            zeekapp.write_http_log(http, path)
            res["http"] = _block(KIND_HTTP, e, stats, files=[os.path.basename(path)], records={"http": len(http)})
        except Exception as ex:                          # noqa: BLE001 - never discard a finished capture
            _remove(path)
            res["http"] = {"kind": KIND_HTTP, "error": "%s: %s" % (type(ex).__name__, ex)}
    return res
