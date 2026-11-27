"""Persistent UI settings: a small JSON file in a per-user config directory.

Stdlib only. A missing or corrupt file degrades to defaults and never raises on read.
The directory is OG_SETTINGS_DIR when set (tests), else the platform's per-user config dir.
"""
import json
import os
import stat
import sys
import tempfile
import threading

BODY_CAP = 4096
FILE_NAME = "settings.json"

DEFAULTS = {
    "palette": "slate",
    "theme": "dark",
    "lab_tools": False,
    "first_run_done": False,
    "choose_mode": "timeline",
    "restore_last_session": True,
    "default_size": "standard",
    "out_dir": "",
}
_ENUMS = {
    "palette": ("slate", "forge", "teal", "sage", "clay"),
    "theme": ("dark", "light", "system"),
    "choose_mode": ("timeline", "list", "map"),
    "default_size": ("quick", "standard", "full"),      # Quick sample 0.02x, Standard 0.1x, Full day 1.0x
}
_BOOLS = ("lab_tools", "first_run_done", "restore_last_session")
_LOCK = threading.Lock()


class SettingsError(ValueError):
    pass


def settings_dir():
    env = os.environ.get("OG_SETTINGS_DIR")
    if env:
        return env
    home = os.path.expanduser("~")
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support", "OpenGenerator")
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    return os.path.join(base, "opengenerator")


def ensure_private_dir(d=None):
    """Create the settings folder 0700 (secrets and logs live there) and return it. An existing default folder that
    we own and that others can enter is tightened to 0700; a folder chosen with OG_SETTINGS_DIR is left as the person made it."""
    d = d or settings_dir()
    os.makedirs(d, mode=0o700, exist_ok=True)
    if "OG_SETTINGS_DIR" not in os.environ and hasattr(os, "geteuid"):
        st = os.lstat(d)                                # lstat: a symlink in its place is not followed or chmod-ed
        if stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) & 0o077:
            os.chmod(d, 0o700)
    return d


def settings_path():
    return os.path.join(settings_dir(), FILE_NAME)


def validate(updates):
    """Return a cleaned copy of `updates`; raise SettingsError on unknown keys or bad values."""
    if not isinstance(updates, dict):
        raise SettingsError("settings must be a JSON object")
    out = {}
    for key, val in updates.items():
        if key not in DEFAULTS:
            raise SettingsError("unknown setting: %s" % key)
        if key in _ENUMS:
            if not isinstance(val, str) or val not in _ENUMS[key]:
                raise SettingsError("%s must be one of: %s" % (key, ", ".join(_ENUMS[key])))
        elif key in _BOOLS:
            if not isinstance(val, bool):
                raise SettingsError("%s must be true or false" % key)
        elif key == "out_dir":                       # "" means the app's own default folder
            if not isinstance(val, str) or len(val) > 1024 or "\x00" in val:
                raise SettingsError("out_dir must be a folder path of at most 1024 characters")
            val = val.strip()
        out[key] = val
    return out


def load():
    """Defaults overlaid with whatever valid values the file holds. Never raises."""
    merged = dict(DEFAULTS)
    try:
        with open(settings_path(), "r", encoding="utf-8") as f:
            stored = json.load(f)
    except (OSError, ValueError, RecursionError):
        return merged
    if not isinstance(stored, dict):
        return merged
    for key, val in stored.items():
        try:
            merged.update(validate({key: val}))     # a bad stored value falls back to its default
        except SettingsError:
            pass
    return merged


def _write(settings):
    d = ensure_private_dir()
    fd, tmp = tempfile.mkstemp(prefix=".settings-", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, settings_path())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def update(updates):
    """Validate, merge into the stored settings, write atomically, return the full settings."""
    clean = validate(updates)
    with _LOCK:
        merged = load()
        merged.update(clean)
        _write(merged)
    return merged


def get_payload():
    return {"settings": load(), "defaults": dict(DEFAULTS)}


def route_get(path):
    """(status, body, ctype, headers) for GET /api/settings, else None."""
    if path != "/api/settings":
        return None
    return 200, json.dumps(get_payload()), "application/json", None


def route_post(path, data, bad_json=False):
    """(status, body, ctype, headers) for POST /api/settings, else None."""
    if path != "/api/settings":
        return None
    if bad_json:
        return 400, json.dumps({"error": "request body is not valid JSON"}), "application/json", None
    try:
        merged = update(data)
    except SettingsError as e:
        return 400, json.dumps({"error": str(e)}), "application/json", None
    except OSError as e:
        return 500, json.dumps({"error": "could not save settings: %s" % e.strerror}), "application/json", None
    return 200, json.dumps({"settings": merged, "defaults": dict(DEFAULTS)}), "application/json", None
