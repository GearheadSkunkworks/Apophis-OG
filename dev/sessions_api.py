#!/usr/bin/env python3
"""
OpenGenerator -- saved sessions (the state of the form, so a run can be recreated exactly).

A *session* is the value of every input the user can set on the main page: company, industry,
networks, scale, output folder, which scenarios are ticked, the OT options and the replay
settings. Two kinds live in one folder:

* ``last``  -- written automatically as the form changes; restored on the next launch.
* named     -- saved and loaded on request ("Weekly demo", "OT only", ...).

Rules this module enforces, because the browser cannot be trusted to:

* **No secrets ever reach disk.** API keys, passwords and tokens are dropped by name, whatever the
  page sends. The page also leaves them out; this is the second lock.
* **Acknowledgements are never saved.** An "I understand" tick must be given afresh every time.
* The body is re-validated into a fixed shape (known keys, bounded sizes); anything else is dropped.
* Files are private (0700 folder, 0600 files) and written atomically.

Same HTTP style as campaign_api.py / keys_api.py: every handler returns ``(status, object)`` and
``route_get`` / ``route_post`` wrap that in the server's reply tuple. Stdlib only.
"""
import json
import os
import re
import tempfile
import threading
import time
from urllib.parse import parse_qs

import campaign_api
from campaign_api import ApiError

SESSION_VERSION = 1
MAX_NAME = 80
MAX_CONTROLS = 200
MAX_STR = 2000
MAX_LIST = 400
MAX_SESSIONS = 200
SLUG = re.compile(r"[a-z0-9_-]{1,64}")

# Never stored, whatever the client sends: secrets and one-shot acknowledgements.
_SECRET = re.compile(r"(key|pass|secret|token|cred|auth)", re.I)
_ACK = re.compile(r"ack$", re.I)                        # sensorack, rack, ... any id ending in "ack"

_LOCK = threading.Lock()


def sessions_dir(create=True):
    base = os.environ.get("OPENGENERATOR_SESSIONS") or os.path.join(
        os.path.expanduser("~"), "Documents", "OpenGenerator", "Sessions")
    base = os.path.abspath(os.path.expanduser(base))
    if create:
        try:
            os.makedirs(base, mode=0o700, exist_ok=True)
            os.chmod(base, 0o700)
        except OSError:
            raise ApiError(500, "the sessions folder could not be created") from None
    return base


def _slug(name):
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:60]
    return "session-last" if s == "last" else (s or "session")    # "last" is the autosave file's id


def _path(kind_id):
    """last.json or s-<slug>.json inside the sessions folder; the id is validated, never joined raw."""
    if kind_id == "last":
        return os.path.join(sessions_dir(), "last.json")
    if not isinstance(kind_id, str) or not SLUG.fullmatch(kind_id):
        raise ApiError(400, "a session id must be 1-64 characters of a-z, 0-9, '-' or '_'")
    return os.path.join(sessions_dir(), "s-%s.json" % kind_id)


def clean_state(state):
    """Reduce whatever the page sent to the fixed session shape. Raises ApiError(400) if unusable."""
    if not isinstance(state, dict):
        raise ApiError(400, "'state' must be an object")
    out = {"v": SESSION_VERSION, "controls": {}, "otp": {}, "scenarios": None, "recipes": []}
    ctl = state.get("controls")
    if isinstance(ctl, dict):
        for k, v in list(ctl.items())[:MAX_CONTROLS]:
            if not isinstance(k, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", k):
                continue
            if _SECRET.search(k) or _ACK.search(k):
                continue
            if isinstance(v, bool) or isinstance(v, (int, float)):
                out["controls"][k] = v
            elif isinstance(v, str):
                out["controls"][k] = v[:MAX_STR]
    otp = state.get("otp")
    if isinstance(otp, dict):
        for k, v in list(otp.items())[:64]:
            if isinstance(k, str) and re.fullmatch(r"[a-z0-9_-]{1,32}", k) and isinstance(v, bool):
                out["otp"][k] = v
    sc = state.get("scenarios")
    if isinstance(sc, list):
        out["scenarios"] = [x[:120] for x in sc[:MAX_LIST] if isinstance(x, str)]
    rc = state.get("recipes")
    if isinstance(rc, list):
        out["recipes"] = [x[:MAX_STR] for x in rc[:50] if isinstance(x, str)]
    if not (out["controls"] or out["otp"] or out["scenarios"] is not None or out["recipes"]):
        raise ApiError(400, "the session holds nothing to save")
    return out


def _write(path, doc):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise ApiError(500, "the session could not be written") from None


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        raise ApiError(500, "the saved session could not be read") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("state"), dict):
        return None
    return doc


# ---------------------------------------------------------------- handlers
def session_last_get(_q=None):
    with _LOCK:
        doc = _read(_path("last"))
    if not doc:
        return 200, {"state": None}
    return 200, {"state": doc["state"], "saved_at": doc.get("saved_at")}


def session_last_put(data):
    state = clean_state(campaign_api._need_obj(data).get("state"))
    with _LOCK:
        _write(_path("last"), {"saved_at": time.time(), "state": state})
    return 200, {"ok": True}


def session_last_clear(_data=None):
    with _LOCK:
        try:
            os.unlink(_path("last"))
        except FileNotFoundError:
            pass
        except OSError:
            raise ApiError(500, "the last session could not be cleared") from None
    return 200, {"ok": True}


def session_list(_q=None):
    rows = []
    with _LOCK:
        d = sessions_dir()
        for fn in os.listdir(d):
            if not (fn.startswith("s-") and fn.endswith(".json")):
                continue
            doc = _read(os.path.join(d, fn))
            if doc:
                rows.append({"id": fn[2:-5], "name": str(doc.get("name") or fn[2:-5])[:MAX_NAME],
                             "saved_at": doc.get("saved_at")})
    rows.sort(key=lambda r: r.get("saved_at") or 0, reverse=True)
    return 200, {"sessions": rows[:MAX_SESSIONS]}


def _other_name(p, name):
    try:
        old = (_read(p) or {}).get("name")                         # a case-only difference is the same session
        return isinstance(old, str) and old.casefold() != name.casefold()
    except ApiError:                                             # unreadable: overwrite, as before
        return False


def session_save(data):
    data = campaign_api._need_obj(data)
    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ApiError(400, "give the session a name")
    name = re.sub(r"[\x00-\x1f\x7f]+", " ", name).strip()[:MAX_NAME]
    state = clean_state(data.get("state"))
    sid = _slug(name)
    with _LOCK:
        p, n = _path(sid), 1
        while os.path.exists(p) and _other_name(p, name):          # a different name with this slug
            n += 1
            sid = "%s-%d" % (_slug(name)[:56], n)
            p = _path(sid)
        if not os.path.exists(p) and len([f for f in os.listdir(sessions_dir()) if f.startswith("s-")]) >= MAX_SESSIONS:
            raise ApiError(400, "too many saved sessions; delete some first")
        _write(p, {"name": name, "saved_at": time.time(), "state": state})
    return 200, {"id": sid, "name": name}


def session_load(q):
    sid = (q.get("id") or [""])[0] if isinstance(q, dict) else ""
    with _LOCK:
        doc = _read(_path(sid))
    if not doc:
        raise ApiError(404, "that session was not found")
    return 200, {"id": sid, "name": doc.get("name"), "state": doc["state"], "saved_at": doc.get("saved_at")}


def session_delete(data):
    sid = campaign_api._need_obj(data).get("id")
    if sid == "last":
        raise ApiError(400, "use the clear action for the last session")
    with _LOCK:
        try:
            os.unlink(_path(sid))
        except FileNotFoundError:
            raise ApiError(404, "that session was not found") from None
        except OSError:
            raise ApiError(500, "the session could not be deleted") from None
    return 200, {"ok": True}


# ---------------------------------------------------------------- routing
_GET = {
    "/api/session/last": session_last_get,
    "/api/session/list": session_list,
    "/api/session/load": session_load,
}
_POST = {
    "/api/session/last": session_last_put,
    "/api/session/clear": session_last_clear,
    "/api/session/save": session_save,
    "/api/session/delete": session_delete,
}


def _reply(status, obj):
    return status, json.dumps(obj).encode(), "application/json", {}


def route_get(path, query_string):
    """None if the path is not ours, else (status, body_bytes, content_type, headers)."""
    fn = _GET.get(path)
    if fn is None:
        return None
    try:
        if len(query_string or "") > campaign_api.MAX_QUERY:
            raise ApiError(414, "the request address is too long")
        status, obj = fn(parse_qs(query_string or "", max_num_fields=8))
        return _reply(status, obj)
    except ApiError as e:
        return _reply(e.status, dict(e.extra, error=e.message))
    except Exception:                                                  # noqa: BLE001
        return _reply(500, {"error": "the request could not be completed"})


def route_post(path, data, bad_json=False):
    """None if the path is not ours, else (status, body_bytes, content_type, headers)."""
    fn = _POST.get(path)
    if fn is None:
        return None
    try:
        if bad_json:
            raise ApiError(400, "the request body is not valid JSON")
        campaign_api.check_shape(data)
        status, obj = fn(data)
        return _reply(status, obj)
    except ApiError as e:
        return _reply(e.status, dict(e.extra, error=e.message))
    except Exception:                                                  # noqa: BLE001
        return _reply(500, {"error": "the request could not be completed"})
