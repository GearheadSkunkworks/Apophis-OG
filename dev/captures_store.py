"""Safe delete/restore for the Captures library. Nothing is ever permanently deleted: a capture and its
sibling outputs move into <out_dir>/.trash/<UTC stamp>-<stem>/ with a manifest, and move back on restore.
Stdlib only. Holding folders are never pruned automatically."""
import json
import os
import re
import time
from urllib.parse import parse_qs

BODY_CAP = 4096
TRASH = ".trash"
_JSON = "application/json"
_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[A-Za-z0-9._-]{1,200}(?:-\d+)?$")


class StoreError(Exception):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


def _base(out_dir):
    d = os.path.realpath(os.path.expanduser(str(out_dir or "").strip()))
    if not os.path.isdir(d):
        raise StoreError("The output folder does not exist: %s" % (out_dir or "(empty)"))
    return d


def _bare(name):
    if (not isinstance(name, str) or not name or name in (".", "..") or "\x00" in name
            or "/" in name or "\\" in name or os.path.isabs(name) or os.path.basename(name) != name
            or name.startswith(".")):
        raise StoreError("Not a bare file name: %r" % (name,))
    return name


def _siblings(base, name):
    """Other files a build wrote for this capture: key log, campaign/report exports, the recipe, and the
    company's threat collection. The shared certs/ folder is deliberately left alone (other captures use it)."""
    stem = os.path.splitext(name)[0]
    cand = [stem + s for s in ("-tls-keys.log", ".campaign.json", ".campaign-iocs.stix.json",
                               "-custom-report.json", "-recipe.json", ".recipe.json", ".manifest.json")]
    if stem.endswith("-all-in-one"):
        pre = stem[:-len("-all-in-one")] + "-threat-collection"
        cand += [pre + ".stix.json", pre + ".csv"]
    out = []
    for c in cand:
        p = os.path.join(base, c)
        if os.path.isfile(p) and not os.path.islink(p):
            out.append(c)
    return out


def _undo(moves):
    for src, dst in reversed(moves):          # put back what already moved
        try:
            os.rename(dst, src)
        except OSError:
            pass


def trash(out_dir, name, busy=None):
    why = busy() if busy else None
    if why:
        raise StoreError("Not now: %s." % why, 409)
    base = _base(out_dir)
    name = _bare(name)
    if not name.lower().endswith((".pcap", ".pcapng")):
        raise StoreError("Only .pcap and .pcapng captures can be moved to the holding folder.")
    src = os.path.join(base, name)
    if os.path.islink(src) or not os.path.isfile(src):
        raise StoreError("No capture named %s in that folder." % name, 404)
    names = [name] + _siblings(base, name)
    tid = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + os.path.splitext(name)[0]
    root, n = os.path.join(base, TRASH), 1
    dest = os.path.join(root, tid)
    while os.path.exists(dest):
        n += 1
        dest = os.path.join(root, "%s-%d" % (tid, n))
    tid = os.path.basename(dest)
    moves = []
    try:
        os.makedirs(dest)
        for nm in names:
            os.rename(os.path.join(base, nm), os.path.join(dest, nm))
            moves.append((os.path.join(base, nm), os.path.join(dest, nm)))
        size = sum(os.path.getsize(d) for _s, d in moves)
        with open(os.path.join(dest, "manifest.json"), "w") as fh:
            json.dump({"name": name, "files": names, "size": size, "trashed_at": int(time.time()),
                       "original_dir": base}, fh, indent=1)
    except OSError as e:
        _undo(moves)
        try:
            for f in os.listdir(dest):
                os.remove(os.path.join(dest, f))
            os.rmdir(dest)                      # only our own empty staging folder
        except OSError:
            pass
        raise StoreError("Could not move the capture, nothing was changed: %s" % (e.strerror or e), 500)
    return {"ok": True, "trash_id": tid, "moved": names}


def restore(out_dir, trash_id, busy=None):
    why = busy() if busy else None
    if why:
        raise StoreError("Not now: %s." % why, 409)
    base = _base(out_dir)
    if not isinstance(trash_id, str) or not _ID_RE.match(trash_id) or ".." in trash_id:
        raise StoreError("Not a valid holding entry id.")
    dest = os.path.join(base, TRASH, trash_id)
    if os.path.islink(dest) or not os.path.isdir(dest):
        raise StoreError("No such holding entry.", 404)
    try:
        with open(os.path.join(dest, "manifest.json")) as fh:
            files = [_bare(f) for f in json.load(fh)["files"]]
    except (OSError, ValueError, KeyError, TypeError):
        raise StoreError("The holding entry's manifest is missing or unreadable; nothing was restored.", 500)
    taken = [f for f in files if os.path.lexists(os.path.join(base, f))]
    if taken:
        raise StoreError("Cannot restore: %s already exist%s in the folder. Nothing was restored."
                         % (", ".join(taken), "s" if len(taken) == 1 else ""), 409)
    moves = []
    try:
        for f in files:
            os.rename(os.path.join(dest, f), os.path.join(base, f))
            moves.append((os.path.join(dest, f), os.path.join(base, f)))
    except OSError as e:
        _undo(moves)
        raise StoreError("Could not restore, nothing was changed: %s" % (e.strerror or e), 500)
    try:                                         # leave the manifest folder only if it is now empty of captures
        os.rename(os.path.join(dest, "manifest.json"), os.path.join(dest, "manifest.json.restored"))
    except OSError:
        pass
    return {"ok": True, "restored": files}


def listing(out_dir):
    base = _base(out_dir)
    root, items = os.path.join(base, TRASH), []
    if os.path.isdir(root) and not os.path.islink(root):
        for tid in sorted(os.listdir(root), reverse=True):
            try:
                with open(os.path.join(root, tid, "manifest.json")) as fh:
                    m = json.load(fh)
                items.append({"trash_id": tid, "name": m["name"], "size": m.get("size", 0),
                              "trashed_at": m.get("trashed_at", 0)})
            except (OSError, ValueError, KeyError):
                continue                          # restored or foreign folder: not listed
    return {"dir": base, "items": items}


def _res(status, obj):
    return status, json.dumps(obj), _JSON, None


def route_get(path, query, busy=None):
    if path != "/api/captures/trash":
        return None
    try:
        return _res(200, listing((parse_qs(query).get("out_dir") or [""])[0]))
    except StoreError as e:
        return _res(e.status, {"error": str(e)})


def route_post(path, data, bad_json=False, busy=None):
    if path not in ("/api/captures/trash", "/api/captures/restore"):
        return None
    if bad_json or not isinstance(data, dict):
        return _res(400, {"error": "request body is not valid JSON"})
    try:
        if path.endswith("/trash"):
            return _res(200, trash(data.get("out_dir"), data.get("name"), busy))
        return _res(200, restore(data.get("out_dir"), data.get("trash_id"), busy))
    except StoreError as e:
        return _res(e.status, {"error": str(e)})
