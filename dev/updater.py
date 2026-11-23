"""In-app update. A patch (X.Y.Z, Z above 0) is fetched from the project's GitHub Releases and installed as an overlay.

Check: list releases, find the newest patch on this build's MAJOR.MINOR line (and note a newer minor or major, which is
a full download from the Releases page, never installed by the app). Install: download the patch's three files
(og-patch-<v>.json manifest, .sig, .zip), verify the Ed25519 signature on the manifest with the public key below, check
the zip's sha256 against the manifest, unpack safely, then swap it into <settings dir>/overlay/current (the previous
one is kept). overlay.py loads it at the next start. Only the manifest, signature and zip are fetched; nothing about the
user or their captures is sent. Needs a frozen build: from source, the answer is to pull the repo.
Stdlib plus `cryptography` (already a dependency of the app).
"""
import hashlib
import io
import json
import os
import re
import shutil
import ssl
import stat
import sys
import urllib.parse
import urllib.request
import zipfile

import overlay

REPO = os.environ.get("OG_UPDATE_REPO", "GearheadSkunkworks/Apophis-OG")
LIST_URL = os.environ.get("OG_UPDATE_URL", "https://api.github.com/repos/%s/releases?per_page=30" % REPO)
RELEASES_PAGE = "https://github.com/%s/releases" % REPO
# The Ed25519 public key lives in overlay.py (PUBLIC_KEY); the private half stays with the maintainer.
HOSTS = ("api.github.com", "github.com")                      # plus *.github.com and *.githubusercontent.com (release downloads redirect there)
MAX_JSON, MAX_ZIP, MAX_UNPACKED, MAX_FILES = 256 * 1024, 25 * 1024 * 1024, 80 * 1024 * 1024, 4000
TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


class UpdateError(Exception):
    pass


def allowed_url(url):
    """https to a GitHub host, or plain http to exactly 127.0.0.1 (local testing). Compared on the parsed host, never by prefix."""
    p = urllib.parse.urlsplit(url)
    host = (p.hostname or "").lower()
    if p.scheme == "http":
        return host == "127.0.0.1"
    return p.scheme == "https" and (host in HOSTS or host.endswith((".github.com", ".githubusercontent.com")))


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_url(newurl) or newurl.lower().startswith("http://"):
            raise UpdateError("The update server redirected somewhere it should not; nothing was changed.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener():
    """An opener that follows only safe redirects and verifies HTTPS with a certificate bundle even when Python has
    none (a python.org Python, or the packaged app): the feed fetcher already knows where the system bundle lives."""
    handlers = [_SafeRedirect()]
    try:
        from intel.sources import _ssl_context
        handlers.insert(0, urllib.request.HTTPSHandler(context=_ssl_context()))
    except Exception:                                            # noqa: BLE001 - fall back to Python's own default
        pass
    return urllib.request.build_opener(*handlers)


def _accept(url):
    """GitHub's API insists on a JSON Accept header (it answers 415 to anything else); file downloads take anything."""
    return "application/vnd.github+json" if (urllib.parse.urlsplit(url).hostname or "").lower() == "api.github.com" else "*/*"


def _get(url, cap):
    if not allowed_url(url):
        raise UpdateError("The update address is not allowed; nothing was changed.")
    req = urllib.request.Request(url, headers={"User-Agent": "OpenGenerator-updater", "Accept": _accept(url)})
    try:
        with _opener().open(req, timeout=20) as r:
            data = r.read(cap + 1)
    except UpdateError:
        raise
    except Exception as e:                                       # noqa: BLE001 - any network failure reads the same to the user
        if isinstance(getattr(e, "reason", None), ssl.SSLError):
            raise UpdateError("The secure connection to the update server could not be verified (no certificate bundle found on this Mac).") from e
        raise UpdateError("Could not reach the update server. Check your connection and try again.") from e
    if len(data) > cap:
        raise UpdateError("The update is larger than expected; nothing was changed.")
    return data


def current_version(app_dir):
    return overlay._read(os.path.join(app_dir, "VERSION")) or "0"


def check(current, get=_get):
    """What a check finds. state: current | patch | newer | error. `get(url, cap)` is injectable for tests."""
    cur = overlay.parse(current)
    try:
        releases = json.loads(get(LIST_URL, MAX_JSON * 8))
    except (ValueError, UpdateError) as e:
        return {"state": "error", "current": current, "message": str(e) if isinstance(e, UpdateError) else "The update server sent something unexpected."}
    best, newer = None, None
    for rel in releases if isinstance(releases, list) else []:
        m = TAG.match(str(rel.get("tag_name", "")))
        if not m or rel.get("draft") or rel.get("prerelease"):
            continue
        v = tuple(int(x) for x in m.groups())
        if v[:2] == cur[:2] and v > cur and (best is None or v > best[0]):
            assets = {a.get("name"): a.get("browser_download_url") for a in rel.get("assets", [])}
            if all(("og-patch-%d.%d.%d.%s" % (v + (x,))) in assets for x in ("json", "sig", "zip")):
                best = (v, rel, assets)
        elif v[:2] > cur[:2] and (newer is None or v > newer):
            newer = v
    if best:
        v = ".".join(map(str, best[0]))
        assets = {x: best[2]["og-patch-%s.%s" % (v, x)] for x in ("json", "sig", "zip")}
        try:                                                      # offer nothing that is not signed; show only the signed notes
            m = verify_manifest(get(assets["json"], MAX_JSON), get(assets["sig"], MAX_JSON))
        except UpdateError as e:
            return {"state": "error", "current": current, "message": str(e)}
        if m.get("version") != v:
            return {"state": "error", "current": current, "message": "The update's details do not match its release; nothing was changed."}
        return {"state": "patch", "current": current, "latest": v, "notes": str(m.get("notes") or "")[:2000], "assets": assets}
    if newer:
        return {"state": "newer", "current": current, "latest": ".".join(map(str, newer)), "page": RELEASES_PAGE}
    return {"state": "current", "current": current}


def verify_manifest(manifest_bytes, sig_bytes):
    try:
        return overlay.verify_signed(manifest_bytes, sig_bytes)
    except ValueError:
        raise UpdateError("The update's signature did not check out; nothing was changed.") from None


def unpack(zip_bytes, dest):
    """Extract into dest, refusing anything that could write outside it or is not a plain file."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        infos = z.infolist()
        if len(infos) > MAX_FILES or sum(i.file_size for i in infos) > MAX_UNPACKED:
            raise UpdateError("The update is larger than expected; nothing was changed.")
        root = os.path.realpath(dest)
        for i in infos:
            target = os.path.realpath(os.path.join(dest, i.filename))
            mode = i.external_attr >> 16
            if os.path.isabs(i.filename) or not target.startswith(root + os.sep) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
                raise UpdateError("The update contains an unsafe path; nothing was changed.")
        z.extractall(dest)


def install(info, app_dir, base=None, get=_get):
    """Download, verify and install the patch `check` found. Returns the new version. Nothing changes on any failure."""
    if not getattr(sys, "frozen", False) and base is None:
        raise UpdateError("This copy runs from source; update it with git pull instead.")
    a = info["assets"]
    manifest_bytes, sig = get(a["json"], MAX_JSON), get(a["sig"], MAX_JSON)
    m = verify_manifest(manifest_bytes, sig)
    v, cur = overlay.parse(m.get("version", "")), overlay.parse(current_version(app_dir))
    if m.get("version") != info["latest"] or v[:2] != cur[:2] or not v > cur or m.get("product") != "opengenerator":
        raise UpdateError("This update is not for this version; nothing was changed.")
    zbytes = get(a["zip"], MAX_ZIP)
    if hashlib.sha256(zbytes).hexdigest() != m.get("sha256"):
        raise UpdateError("The download did not match its checksum; nothing was changed.")
    base = base or overlay.base_dir()
    new = os.path.join(base, "new")
    shutil.rmtree(new, ignore_errors=True)
    os.makedirs(new)
    try:
        unpack(zbytes, new)
        if overlay._read(os.path.join(new, "VERSION")) != m["version"] or not os.path.isfile(os.path.join(new, "server.py")):
            raise UpdateError("The update is incomplete; nothing was changed.")
        try:
            overlay.check_tree(new, m)                            # exactly the signed files, byte for byte
        except (ValueError, KeyError, TypeError):
            raise UpdateError("The update's files do not match its signed list; nothing was changed.") from None
        for name, data in zip(overlay.SIGNED, (manifest_bytes, sig)):   # kept so every start can re-verify
            with open(os.path.join(new, name), "wb") as fh:
                fh.write(data)
        cur_dir, prev = os.path.join(base, "current"), os.path.join(base, "previous")
        shutil.rmtree(prev, ignore_errors=True)
        if os.path.isdir(cur_dir):
            os.replace(cur_dir, prev)
        os.replace(new, cur_dir)
    except BaseException:
        shutil.rmtree(new, ignore_errors=True)
        raise
    return m["version"]


# ---- HTTP routes (server.py)
_LAST = {}


def route_get(path, app_dir, get=_get):
    if path != "/api/update/check":
        return None
    info = check(current_version(app_dir), get)
    _LAST.clear()
    _LAST.update(info)
    out = {k: v for k, v in info.items() if k != "assets"}
    out["frozen"] = bool(getattr(sys, "frozen", False))
    return 200, json.dumps(out), "application/json", None


def route_post(path, app_dir, busy, get=_get):
    """(status, body, ctype, headers) for POST /api/update/install, else None. `busy()` names work in flight, or is falsy."""
    if path != "/api/update/install":
        return None
    def fail(code, msg):
        return code, json.dumps({"ok": False, "error": msg}), "application/json", None
    if _LAST.get("state") != "patch":
        return fail(409, "Check for updates first.")
    why = busy()
    if why:
        return fail(409, "Finish first: %s." % why)
    try:
        v = install(_LAST, app_dir, get=get)
    except UpdateError as e:
        return fail(400, str(e))
    return 200, json.dumps({"ok": True, "version": v, "restarting": True}), "application/json", None
