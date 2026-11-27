"""Post-build exporter "pcapng": <stem>.pcapng beside the pcap, converted from it by pcapngconv.

A converter beside the classic pcap, never a replacement writer: the pcap stays the primary output and
is not touched. Runs only when the build option exports contains "pcapng". Options (build kwargs
pcapng_comments / pcapng_embed_keys, both default off) arrive on the export context as
e.pcapng_options = {"comments": bool, "embed_keys": bool}. Comments need the tag sidecar: when it is
missing (more than 256 distinct tags, or the write failed) the block carries an error instead of a file.
The key log stays a separate file unless embed_keys is set; the block records whether it was embedded.
Never raises: a failure is recorded in the returned block and the capture is kept.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_manifest as BM  # noqa: E402 - sys.path is set up first
import pcapngconv  # noqa: E402 - sys.path is set up first
KIND = "pcapng-converter"


def pcapng_path(out):
    return (out[:-5] if out.endswith(".pcap") else out) + ".pcapng"


def export(e):
    """_ExportCtx -> {"pcapng": block} (or {} when not requested)."""
    if "pcapng" not in (getattr(e, "exports", None) or ()):
        return {}
    opts = getattr(e, "pcapng_options", None) or {}
    path = pcapng_path(e.out)
    block = {"kind": KIND, "files": [os.path.basename(path)], "comments": bool(opts.get("comments")),
             "keylog_embedded": bool(opts.get("embed_keys"))}
    try:
        if opts.get("comments") and not getattr(e, "tags_path", None):
            raise ValueError("the tag sidecar is missing, so per-packet scenario comments cannot be written")
        note = "OpenGenerator %s; build parameters sha256 %s" % (getattr(e, "generator", ""), getattr(e, "params_sha256", ""))
        r = pcapngconv.convert(e.out, path, tags_path=e.tags_path if opts.get("comments") else None,
                               comments=bool(opts.get("comments")), keylog_path=getattr(e, "keylog", None),
                               embed_keys=bool(opts.get("embed_keys")), comment=note)
        block.update(packets=r["packets"], first_ts=r["first_ts"], last_ts=r["last_ts"],
                     comment_count=r["comments"], embedded_keylog_bytes=r["embedded_keylog_bytes"],
                     writer_packets=e.writer.n, exports_consistent=r["packets"] == e.writer.n)
    except Exception as ex:                              # noqa: BLE001 - never discard a finished capture
        block.pop("files")
        block["error"] = BM.export_error(ex)
    return {"pcapng": block}
