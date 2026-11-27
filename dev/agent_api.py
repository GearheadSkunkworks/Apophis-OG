"""
OpenGenerator -- agent API (/agent/v1/): lets an outside assistant drive the app through a short allow-list of verbs.

Stdlib only. The control is SCOPE, not a hidden endpoint:

* A request carrying ``Authorization: Bearer <token>`` is an *agent* request. It may only reach ``/agent/v1/<verb>``;
  the verb table below is the whole surface. There is no verb for replaying to a network or for pushing to a sensor,
  and the server refuses a bearer token on every other path (403).
* Every other POST requires the per-process browser-session cookie, which the server gives once, to the request that
  carries the launch nonce from the address the app opens itself. A client that leaves the token off, or fetches ``/``,
  gets no cookie. shortcut: the nonce is in the opened URL, so a same-user process that reads the browser's command
  line in that instant could take it; upgrade to an OS confirmation dialog for replay and push if that matters.
* ``sensor/stage`` records a *pending* request (host, certificate folder) and executes nothing; a person reviews it in
  the app and presses the existing confirm button. The sensor key never travels through the agent: the server reads it
  from the Keychain.
* Every agent call is appended to ``agent-audit.log`` (verb, status and argument NAMES; never a value). The settings
  folder is 0700 and the log 0600.

The token lives in the keystore (``agent:token``): the Keychain on macOS, the desktop keyring or a 0600 file on Linux.
"""
import base64
import hmac
import json
import os
import re
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
    "/api/replay/start", "/api/replay/stop", "/api/replay/records",
    "/api/sensor/push", "/api/sensor/stop",
    "/api/sensor/collection/push", "/api/sensor/collection/stop",
    "/api/agent/status", "/api/agent/token", "/api/agent/off", "/api/agent/dismiss",    # the app's own controls
))

# Routes that can use the stored sensor key (use_stored). A client with no agent token must carry the page cookie, so another
# local program cannot drive them. Unlike HUMAN_ONLY, an agent verb may proxy to these (sensor/check), because that call
# arrives with a token and is audited.
PAGE_ONLY = frozenset(("/api/sensor/check", "/api/campaign/feedback"))

# GET routes that act, reveal what is installed, or answer for any local path (an existence oracle), and so also need
# the page cookie. Every POST needs it by default.
COOKIE_GET = frozenset(("/api/update/check", "/api/replay/preflight", "/profile", "/recipe", "/profile/export",
                        "/profile/compare", "/profile/check", "/profile/summary"))

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


class AgentError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


# ---------------------------------------------------------------- token
def _token_path():
    return os.path.join(settings_store.settings_dir(), TOKEN_FILE)      # only the pre-keystore file, removed on revoke


# The keystore may start a helper process (security, secret-tool), so one request must not cost one process:
# the token is kept in memory, dropped on create/revoke, and re-read at most every TOKEN_TTL seconds so a change made
# through the key routes still takes effect.
TOKEN_TTL = 5.0
_TOKEN = {"value": "", "at": None}
_TOKEN_LOCK = threading.Lock()


def _forget_cached_token():
    with _TOKEN_LOCK:
        _TOKEN["at"] = None


def _read_token():
    with _TOKEN_LOCK:
        if _TOKEN["at"] is not None and time.monotonic() - _TOKEN["at"] < TOKEN_TTL:
            return _TOKEN["value"]
        try:
            _TOKEN["value"] = keystore.load(TOKEN_ID) or ""
        except keystore.KeystoreError:
            _TOKEN["value"] = ""
        _TOKEN["at"] = time.monotonic()
        return _TOKEN["value"]


def _write_token(tok):
    keystore.save(TOKEN_ID, tok)
    _forget_cached_token()


def enabled():
    return bool(_read_token())


def create_token():
    """Make (or replace) the token; the old one stops working at once. Returns the new token."""
    tok = "ogagent_" + base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    _write_token(tok)
    return tok


def show_token():
    return _read_token()


def revoke_token():
    try:
        keystore.forget(TOKEN_ID)
    except keystore.KeystoreError:
        pass
    _forget_cached_token()
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
    """Append one line: time, verb, status and the argument NAMES. Values are never logged (a short value can still
    be a URL carrying a key, a folder or a host)."""
    names = sorted({re.sub(r"[^A-Za-z0-9_.-]", "?", str(k))[:40] for k in body}) if isinstance(body, dict) else []
    line = json.dumps({"t": time.strftime("%Y-%m-%dT%H:%M:%S"), "verb": verb, "status": status, "args": names})
    path = os.path.join(settings_store.settings_dir(), AUDIT_FILE)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        settings_store.ensure_private_dir()
        with _LOCK:
            try:
                if os.path.getsize(path) > AUDIT_MAX:
                    with open(path, "rb") as fh:
                        fh.seek(-(AUDIT_MAX // 2), 2)
                        fh.readline()
                        keep = fh.read()
                    with os.fdopen(os.open(path, os.O_WRONLY | os.O_TRUNC | nofollow, 0o600), "wb") as fh:
                        fh.write(keep)
            except OSError:
                pass
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | nofollow, 0o600)
            with os.fdopen(fd, "a") as fh:
                os.fchmod(fh.fileno(), 0o600)          # a log made by an older version may be world-readable
                fh.write(line + "\n")
    except OSError:
        pass                              # an unwritable log must not break the call


# ---------------------------------------------------------------- verbs
def resolve(method, path):
    """(verb, target) for an /agent/v1/ path (no query string), or None."""
    verb = path[len(PREFIX):].strip("/")
    target = VERBS.get((method, verb))
    return (verb, target) if target else None


# Body fields an agent may not set: where files are written or read, and the person's confirmation for real addresses
# (a capture made that way can later be replayed, so the confirmation must come from a person).
REFUSED_FIELDS = ("out_dir", "recipe", "recipes", "confirm_real_addresses")


def scrub(text):
    """Reply text for an agent: the person's home folder (and so the account name) becomes '~'."""
    home = os.path.expanduser("~")
    return text.replace(home, "~") if len(home) > 1 else text


def prepare(verb, data):
    """Body for a proxied verb: sensor calls get the saved key and may not carry one of their own; no verb may name
    an output or recipe path or confirm real addresses."""
    if isinstance(data, dict):
        for k in REFUSED_FIELDS:
            if k in data:
                raise AgentError(400, "'%s' is chosen by a person in the app, not through the agent API" % k)
        if data.get("address_mode") == "real":
            raise AgentError(400, "real-address mode is chosen by a person in the app, not through the agent API")
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
        sid = os.urandom(6).hex()
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
