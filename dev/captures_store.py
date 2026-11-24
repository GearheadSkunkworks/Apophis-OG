"""Safe delete/restore for the Captures library. Nothing is ever permanently deleted: a capture and its
sibling outputs move into <out_dir>/.trash/<UTC stamp>-<stem>/ with a manifest, and move back on restore.
Stdlib only. Holding folders are never pruned automatically."""
import json
import os
import re
import shutil
import time
from urllib.parse import parse_qs

BODY_CAP = 4096
TRASH = ".trash"
KEPT = "earlier-builds"              # <out_dir>/earlier-builds/<UTC stamp>-<stem>/ holds builds a newer build displaced
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
                               "-custom-report.json", "-generation-report.csv", "-recipe.json", ".recipe.json", ".manifest.json")]
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
    tid = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + re.sub(r"[^A-Za-z0-9._-]", "_", os.path.splitext(name)[0])[:200]
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
        raise StoreError("Could not move the capture, nothing was changed: %s" % (e.strerror or e), 500) from e
    return {"ok": True, "trash_id": tid, "moved": names}


def restore(out_dir, trash_id, busy=None):
    why = busy() if busy else None
    if why:
        raise StoreError("Not now: %s." % why, 409)
    base = _base(out_dir)
    if not isinstance(trash_id, str) or not _ID_RE.fullmatch(trash_id) or ".." in trash_id:
        raise StoreError("Not a valid holding entry id.")
    dest = os.path.join(base, TRASH, trash_id)
    if os.path.islink(dest) or not os.path.isdir(dest):
        raise StoreError("No such holding entry.", 404)
    try:
        with open(os.path.join(dest, "manifest.json")) as fh:
            files = [_bare(f) for f in json.load(fh)["files"]]
    except (OSError, ValueError, KeyError, TypeError):
        raise StoreError("The holding entry's manifest is missing or unreadable; nothing was restored.", 500) from None
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
        raise StoreError("Could not restore, nothing was changed: %s" % (e.strerror or e), 500) from e
    try:                                         # leave the manifest folder only if it is now empty of captures
        os.rename(os.path.join(dest, "manifest.json"), os.path.join(dest, "manifest.json.restored"))
    except OSError:
        pass
    return {"ok": True, "restored": files}


def listing(out_dir):
    base = _base(out_dir)
    items = []
    # kept-build folders have their own holding folder; "out_dir" (additive) tells the caller what to pass
    # to restore for those entries
    for d, tag in [(base, None)] + [(k, k) for k in kept_dirs(base)]:
        root = os.path.join(d, TRASH)
        if not os.path.isdir(root) or os.path.islink(root):
            continue
        for tid in sorted(os.listdir(root), reverse=True):
            try:
                with open(os.path.join(root, tid, "manifest.json")) as fh:
                    m = json.load(fh)
                it = {"trash_id": tid, "name": m["name"], "size": m.get("size", 0), "trashed_at": m.get("trashed_at", 0)}
                if tag:
                    it["out_dir"] = tag
                items.append(it)
            except (OSError, ValueError, KeyError):
                continue                          # restored or foreign folder: not listed
    return {"dir": base, "items": items}


# ---- earlier builds: never overwrite a different build's files ------------------------------------------

def kept_dirs(base):
    """Absolute paths of the kept-build folders under base (real directories only, newest first)."""
    root = os.path.join(base, KEPT)
    if not os.path.isdir(root) or os.path.islink(root):
        return []
    return [os.path.join(root, n) for n in sorted(os.listdir(root), reverse=True)
            if not n.startswith(".") and os.path.isdir(os.path.join(root, n)) and not os.path.islink(os.path.join(root, n))]


def info(pcap_path):
    """Manifest facts for a capture, {} when there is no readable manifest: scenario count and capture day."""
    m = _manifest(os.path.splitext(pcap_path)[0] + ".manifest.json")
    if not m:
        return {}
    return {"scenarios": len(m.get("scenarios") or []), "capture_date": (m.get("parameters") or {}).get("date")}


def _manifest(path):
    try:
        with open(path, encoding="utf-8") as fh:
            m = json.load(fh)
        return m if isinstance(m, dict) else None
    except (OSError, ValueError):
        return None


def _in(base, path):
    """True when path (symlinks resolved) is strictly inside base."""
    return os.path.realpath(path).startswith(base + os.sep)


def _regular(base, rel):
    """A relative name that is a real file (not a link) staying inside base, else None."""
    if (not isinstance(rel, str) or not rel or os.path.isabs(rel) or "\x00" in rel or ".." in rel.split("/")
            or rel.startswith(KEPT + "/") or rel.startswith(TRASH + "/")):
        return None
    p = os.path.join(base, rel)
    return rel if os.path.isfile(p) and not os.path.islink(p) and _in(base, p) and not os.path.islink(os.path.dirname(p)) else None


class Held:
    """A displaced build's files, moved into dir. commit() ends it (a rebuild with the same settings just
    replaces; a different build stays kept); rollback() puts everything back, for a failed or stopped build."""

    def __init__(self, base, dir, moves, same):
        self.base, self.dir, self.moves, self.same = base, dir, moves, same
        self.files = [os.path.relpath(s, base) for s, _d in moves]

    def rollback(self):
        for src, dst in reversed(self.moves):
            try:
                os.makedirs(os.path.dirname(src), exist_ok=True)
                os.replace(dst, src)              # replaces whatever partial file the failed build left
            except OSError:
                pass
        self._tidy()

    def commit(self):
        if self.same:
            shutil.rmtree(self.dir, ignore_errors=True)   # identical settings: the old copy is simply replaced
            self._tidy()

    def _tidy(self):
        for root, dirs, _f in os.walk(self.dir, topdown=False):
            for d in dirs:
                try:
                    os.rmdir(os.path.join(root, d))
                except OSError:
                    pass
        for d in (self.dir, os.path.dirname(self.dir)):
            try:
                os.rmdir(d)                        # only if now empty
            except OSError:
                pass


def hold_previous(out, keylog, certs_dir, signature, write_certs=True):
    """Before a build writes `out`, move the build that is already there aside.

    signature = {"generator": ..., "parameters": {...}} of the NEW build. If the existing build's manifest
    carries the same signature it is a plain re-run: its files are held in a hidden staging folder and
    dropped on commit(). Otherwise (different settings, no readable manifest, or only certs left over) they
    go to <dir>/earlier-builds/<when it was built>-<stem>/ and stay. Moves only; nothing is ever deleted
    except the identical copy a same-settings rebuild replaces. Returns a Held, or None if nothing to hold."""
    out = os.path.abspath(out)
    base, name = os.path.dirname(out), os.path.basename(out)
    base = os.path.realpath(base)
    stem = os.path.splitext(name)[0]
    mpath = os.path.join(base, stem + ".manifest.json")
    prior = _manifest(mpath) or {}
    rels = []
    if os.path.isfile(out) and not os.path.islink(out):
        rels = [name, stem + ".manifest.json", stem + "-generation-report.csv", stem + "-custom-report.json"]
        rels += [stem + sfx for sfx in ("-tls-keys.log", ".campaign.json", ".campaign-iocs.stix.json")]
        if keylog and _in(base, keylog) and os.path.dirname(os.path.realpath(keylog)) == base:
            rels.append(os.path.basename(keylog))
        rels += [str(o.get("name")) for o in (prior.get("outputs") or []) if isinstance(o, dict)]
    pems = []
    if write_certs and certs_dir and os.path.isdir(certs_dir) and not os.path.islink(certs_dir) and _in(base, certs_dir):
        cd = os.path.relpath(os.path.realpath(certs_dir), base)
        pems = [cd + "/" + f for f in sorted(os.listdir(certs_dir))]
    seen, files = set(), []
    for r in rels + pems:
        r = _regular(base, r)
        if r and r not in seen:
            seen.add(r)
            files.append(r)
    if not files:
        return None
    same = bool(prior) and (prior.get("generator"), json.dumps(prior.get("parameters"), sort_keys=True)) == \
        (signature.get("generator"), json.dumps(signature.get("parameters"), sort_keys=True)) and name in files
    when = str(prior.get("created_utc") or "")
    if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", when):
        try:
            when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(os.path.join(base, files[0]))))
        except OSError:
            when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    tid = re.sub(r"[-:]", "", when) + "-" + re.sub(r"[^A-Za-z0-9._-]", "_", stem)[:100]
    root = os.path.join(base, KEPT)
    if os.path.islink(root):
        raise RuntimeError("%s is a link; cannot keep the earlier build there. Nothing was changed." % root)
    dest, n = os.path.join(root, ("." + "replacing-" + tid) if same else tid), 1
    while os.path.exists(dest):
        n += 1
        dest = os.path.join(root, ("." + "replacing-" + tid if same else tid) + "-%d" % n)
    moves = []
    held = Held(base, dest, moves, same)
    try:
        for r in files:
            d = os.path.join(dest, r)
            os.makedirs(os.path.dirname(d), exist_ok=True)
            os.rename(os.path.join(base, r), d)
            moves.append((os.path.join(base, r), d))
    except OSError as e:
        held.rollback()
        raise RuntimeError("Could not keep the earlier build, nothing was changed: %s" % (e.strerror or e)) from e
    held.files = [os.path.relpath(s, base) for s, _d in moves]
    return held


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
