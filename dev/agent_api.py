"""
OpenGenerator -- agent API (/agent/v1/): lets an outside assistant drive the app through a short allow-list of verbs.

Stdlib only. The control is SCOPE, not a hidden endpoint:

* A request carrying ``Authorization: Bearer <token>`` is an *agent* request. It may only reach ``/agent/v1/<verb>``;
  the verb table below is the whole surface. There is no verb for replaying to a network or for pushing to a sensor,
  and the server refuses a bearer token on every other path (403).
* The routes that replay or push (``HUMAN_ONLY``) also require the per-process browser-session cookie the app hands to
  its own page, so a plain HTTP client that simply leaves the token off cannot reach them either.
  shortcut: the cookie is readable by anything that can fetch ``/`` over loopback, so this stops an agent tool that
  speaks HTTP, not a local process with shell access (which could run tcpreplay itself); upgrade if that threat matters.
* ``sensor/stage`` records a *pending* request (host, certificate folder) and executes nothing; a person reviews it in
  the app and presses the existing confirm button. The sensor key never travels through the agent: the server reads it
  from the Keychain.
* Every agent call is appended to ``agent-audit.log`` (verb, status, argument names; secret values never).

The token lives in the Keychain on macOS (account ``agent:token``), else in a 0600 file beside the settings.
"""
import hmac
import json
import os
import secrets
import threading
import time

import keystore
import settings_store

PREFIX = "/agent/v1/"
TOKEN_ID = "agent:token"
TOKEN_FILE = "agent-token"
AUDIT_FILE = "agent-audit.log"
AUDIT_MAX = 2 * 1024 * 1024            # the log is cut to its newest half beyond this size
STAGE_TTL = 15 * 60                    # a staged push expires; a person must act within 15 minutes
STAGE_MAX = 8
_LOCK = threading.Lock()
_PENDING = {}                          # id -> staged request

# POST routes only a person at the app may use: the session cookie is required for each, and a token is never enough.
HUMAN_ONLY = frozenset((
    "/api/replay/start", "/api/replay/stop",
    "/api/sensor/push", "/api/sensor/stop",
    "/api/sensor/collection/push", "/api/sensor/collection/stop",
    "/api/agent/status", "/api/agent/token", "/api/agent/off", "/api/agent/dismiss",    # the app's own controls
))

# (method, verb) -> internal path, or ("local", name) for verbs answered here that run no existing handler.
VERBS = {
    ("GET", "catalog/actions"): "/api/campaign/actions",
    ("GET", "catalog/attack"): "/api/campaign/attack",
    ("GET", "catalog/templates"): "/api/campaign/templates",
    ("GET", "catalog/feeds"): "/api/intel/feeds",
    ("GET", "catalog/modules"): "/api/modules",
    ("GET", "catalog/capabilities"): "/api/capabilities",
    ("POST", "intel/fetch"): "/api/intel/fetch",
    ("POST", "intel/parse"): "/api/intel/parse",
    ("POST", "campaign/compile"): "/api/campaign/compile",
    ("POST", "campaign/validate"): "/api/campaign/validate",
    ("POST", "campaign/estimate"): "/api/campaign/estimate",
    ("POST", "campaign/preview"): "/api/campaign/preview",
    ("POST", "campaign/run"): "/api/campaign/run",
    ("GET", "library/list"): "/api/campaign/library",
    ("POST", "library/save"): "/api/campaign/library/save",
    ("POST", "library/load"): "/api/campaign/library/load",
    ("POST", "library/import"): "/api/campaign/library/import",
    ("POST", "build/submit"): "/api/generate",
    ("GET", "build/status"): "/api/status",
    ("POST", "build/cancel"): "/api/generate/stop",
    ("GET", "capture/list"): "/api/captures",
    ("GET", "capture/manifest"): "/api/manifest",
    ("POST", "sensor/check"): "/api/sensor/check",
    ("POST", "sensor/preflight"): "/api/sensor/preflight",
    ("POST", "sensor/stage"): ("local", "stage"),
    ("GET", "sensor/pending"): ("local", "pending"),
    ("GET", "verbs"): ("local", "verbs"),
}
_SENSOR_VERBS = ("sensor/check", "sensor/preflight", "sensor/stage")
_SECRET_NAMES = ("key", "apikey", "token", "password", "secret")


class AgentError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


# ---------------------------------------------------------------- token
def _token_path():
    return os.path.join(settings_store.settings_dir(), TOKEN_FILE)


def _read_token():
    if keystore.available():
        try:
            return keystore.load(TOKEN_ID) or ""
        except keystore.KeystoreError:
            return ""
    try:
        with open(_token_path()) as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _write_token(tok):
    if keystore.available():
        keystore.save(TOKEN_ID, tok)
        return
    os.makedirs(settings_store.settings_dir(), exist_ok=True)
    fd = os.open(_token_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(tok)


def enabled():
    return bool(_read_token())


def create_token():
    """Make (or replace) the token; the old one stops working at once. Returns the new token."""
    tok = "ogagent_" + secrets.token_urlsafe(32)
    _write_token(tok)
    return tok


def show_token():
    return _read_token()


def revoke_token():
    if keystore.available():
        try:
            keystore.forget(TOKEN_ID)
        except keystore.KeystoreError:
            pass
    try:
        os.remove(_token_path())
    except OSError:
        pass
    with _LOCK:
        _PENDING.clear()


def check_bearer(header):
    """True when `header` is 'Bearer <the current token>'. Constant-time; False when the API is off."""
    tok = _read_token()
    if not tok or not isinstance(header, str) or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header[7:].strip().encode(), tok.encode())


# ---------------------------------------------------------------- audit
def audit(verb, status, body=None):
    """Append one line. Argument NAMES are logged; values only for short non-secret scalars."""
    args = {}
    if isinstance(body, dict):
        for k, v in body.items():
            k = str(k)[:40]
            if any(s in k.lower() for s in _SECRET_NAMES):
                args[k] = "<hidden>"
            elif isinstance(v, (int, float, bool)) or (isinstance(v, str) and len(v) <= 80):
                args[k] = v
            else:
                args[k] = "<%s>" % type(v).__name__
    line = json.dumps({"t": time.strftime("%Y-%m-%dT%H:%M:%S"), "verb": verb, "status": status, "args": args})
    path = os.path.join(settings_store.settings_dir(), AUDIT_FILE)
    try:
        os.makedirs(settings_store.settings_dir(), exist_ok=True)
        with _LOCK:
            try:
                if os.path.getsize(path) > AUDIT_MAX:
                    with open(path, "rb") as fh:
                        fh.seek(-(AUDIT_MAX // 2), 2)
                        fh.readline()
                        keep = fh.read()
                    with open(path, "wb") as fh:
                        fh.write(keep)
            except OSError:
                pass
            with open(path, "a") as fh:
                fh.write(line + "\n")
    except OSError:
        pass                              # an unwritable log must not break the call


# ---------------------------------------------------------------- verbs
def resolve(method, path):
    """(verb, target) for an /agent/v1/ path (no query string), or None."""
    verb = path[len(PREFIX):].strip("/")
    target = VERBS.get((method, verb))
    return (verb, target) if target else None


def prepare(verb, data):
    """Body for a proxied verb: sensor calls get the saved key and may not carry one of their own."""
    if verb not in _SENSOR_VERBS:
        return data
    if not isinstance(data, dict):
        raise AgentError(400, "the request body must be a JSON object")
    for k in ("key", "apikey"):
        if data.get(k):
            raise AgentError(400, "do not send a sensor key; the app uses the one saved for this sensor")
    sensor = str(data.get("sensor") or "").strip().lower()
    if not sensor:
        raise AgentError(400, "'sensor' is required")
    import keys_api
    try:
        key = keys_api.resolve_key("sensor:" + sensor, "", True)
    except keystore.KeystoreError as e:
        raise AgentError(409, "%s (save the key for %s in the app first)" % (e, sensor))
    out = dict(data)
    out["use_stored"] = True
    if verb == "sensor/preflight":
        out["apikey"] = key
    return out


def _expire(now):
    for k in [k for k, v in _PENDING.items() if v["expires"] < now]:
        del _PENDING[k]


def stage(data):
    """sensor/stage: remember a push for a person to review. Runs nothing and sends nothing to the sensor."""
    if not isinstance(data, dict):
        raise AgentError(400, "the request body must be a JSON object")
    for k in ("key", "apikey"):
        if data.get(k):
            raise AgentError(400, "do not send a sensor key; the app uses the one saved for this sensor")
    sensor = str(data.get("sensor") or "").strip().lower()
    certs_dir = os.path.expanduser(str(data.get("certs_dir") or "").strip())
    if not sensor or not certs_dir:
        raise AgentError(400, "'sensor' and 'certs_dir' are required")
    if not os.path.isdir(certs_dir):
        raise AgentError(400, "that certificate folder does not exist")
    try:
        port = int(data.get("port") or 443)
    except (TypeError, ValueError):
        raise AgentError(400, "'port' must be a number")
    now = time.time()
    with _LOCK:
        _expire(now)
        if len(_PENDING) >= STAGE_MAX:
            raise AgentError(429, "too many staged pushes are waiting for review")
        sid = secrets.token_hex(6)
        _PENDING[sid] = {"id": sid, "sensor": sensor, "certs_dir": certs_dir,
                         "protocol": str(data.get("protocol") or "http").lower()[:5], "port": port,
                         "note": str(data.get("note") or "")[:200], "staged": now, "expires": now + STAGE_TTL}
        return dict(_PENDING[sid])


def pending():
    """Staged pushes still waiting for a person (the app's own page reads this too)."""
    with _LOCK:
        _expire(time.time())
        return [dict(v) for v in sorted(_PENDING.values(), key=lambda v: v["staged"])]


def dismiss(sid):
    with _LOCK:
        return _PENDING.pop(str(sid), None) is not None


def run_local(name, data):
    if name == "stage":
        return 200, {"ok": True, "pending": stage(data),
                     "next": "A person must review and confirm this push in the app; the agent cannot run it."}
    if name == "verbs":
        return 200, {"verbs": [{"method": m, "verb": v} for (m, v) in VERBS if v != "verbs"]}
    return 200, {"pending": pending()}


def route_ui(path, data):
    """The app's own Settings controls (/api/agent/*). The server only calls this for a request that carries the
    session cookie. Returns (status, dict). A token is shown to the person who asks, never to an agent."""
    if path == "/api/agent/status":
        return 200, {"enabled": enabled(), "pending": pending(), "keychain": keystore.available()}
    if path == "/api/agent/token":
        return 200, {"token": create_token(), "enabled": True}
    if path == "/api/agent/off":
        revoke_token()
        return 200, {"enabled": False}
    if path == "/api/agent/dismiss":
        return 200, {"ok": dismiss((data or {}).get("id") if isinstance(data, dict) else "")}
    return 404, {"error": "unknown"}
