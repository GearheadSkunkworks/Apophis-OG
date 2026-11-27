"""
OpenGenerator -- storage for API keys and the agent token, with one backend chosen at runtime (stdlib only).

Backends (all expose available/save/load/forget/stored_ids):
  keychain        macOS Keychain through ``/usr/bin/security -i``; unchanged behaviour.
  secret-service  Linux, through the ``secret-tool`` CLI, used only when a Secret Service answers a probe.
  file            fallback everywhere else: ``keystore.json`` in the settings folder, mode 0600, plain text.

Items are keyed by service ``opengenerator`` and an item id such as ``feed:otx`` or ``sensor:10.0.0.5``.
A secret is never placed on a command line (it would show in ``ps``): ``security`` gets it as hex on the
stdin of ``security -i``, ``secret-tool`` gets it raw on stdin. Every subprocess is a list with a timeout.
``stored_ids()`` lists ids; ``status()`` says which backend is active and why. Every failure becomes a
KeystoreError whose one-line message never contains a secret.
"""
import binascii
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import threading

import settings_store

SERVICE = "opengenerator"
SECURITY = "/usr/bin/security"
ID_RE = re.compile(r"[a-z0-9._:-]{1,64}")
SECRET_MAX = 300
TIMEOUT = 15
_NOT_FOUND = 44                    # `security` exit status: item not found
SECRET_TOOL = "secret-tool"
SYSTEM_DIRS = ("/usr/bin", "/bin", "/run/current-system/sw/bin")   # secret-tool is found here, never through PATH
PROBE_TIMEOUT = 5                  # seconds; a locked keyring that waits for a prompt counts as unreachable
FILE_NAME = "keystore.json"
FILE_MAX = 1_000_000
BAD_MODE = 0o177                   # any permission bit beyond owner read/write


class KeystoreError(Exception):
    """A one-line message, safe to show; never contains a secret."""


def _kc_available():
    return sys.platform == "darwin" and os.access(SECURITY, os.X_OK)


def valid_id(item_id):
    return isinstance(item_id, str) and bool(ID_RE.fullmatch(item_id))


def _check_id(item_id):
    if not valid_id(item_id):
        raise KeystoreError("the key name must be 1-64 characters of a-z, 0-9, '.', '_', ':' or '-'")
    return item_id


def _check_secret(secret):
    if (not isinstance(secret, str) or not 1 <= len(secret) <= SECRET_MAX
            or any(not 32 <= ord(c) < 127 for c in secret)):
        raise KeystoreError("a key must be 1-%d printable ASCII characters on one line" % SECRET_MAX)
    return secret


def _need_available():
    if not available():
        raise KeystoreError("the macOS Keychain is not available on this computer")


def _run(command_line):
    """Run one `security -i` command given on stdin; returns (returncode, stdout). The command line may
    hold a hex-encoded secret but is never an argv element."""
    try:
        p = subprocess.run([SECURITY, "-i"], input=command_line + "\n", capture_output=True,
                           text=True, timeout=TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        raise KeystoreError("the macOS Keychain could not be reached") from None
    return p.returncode, p.stdout


def _kc_save(item_id, secret):
    _check_id(item_id)
    _check_secret(secret)
    _need_available()
    hexed = binascii.hexlify(secret.encode("ascii")).decode("ascii")
    rc, _ = _run("add-generic-password -U -s %s -a %s -X %s" % (SERVICE, item_id, hexed))
    if rc != 0:
        raise KeystoreError("the key could not be saved to the Keychain")


def _kc_load(item_id):
    """The stored secret, or None when there is none."""
    _check_id(item_id)
    _need_available()
    rc, out = _run("find-generic-password -s %s -a %s -w" % (SERVICE, item_id))
    if rc == _NOT_FOUND:
        return None
    if rc != 0:
        raise KeystoreError("the key could not be read from the Keychain")
    secret = out.rstrip("\n")
    return secret or None


def _kc_forget(item_id):
    _check_id(item_id)
    _need_available()
    rc, _ = _run("delete-generic-password -s %s -a %s" % (SERVICE, item_id))
    if rc not in (0, _NOT_FOUND):
        raise KeystoreError("the key could not be removed from the Keychain")


def _kc_stored_ids():
    """Ids stored under our service. Reads attributes only (no -d / -w), so no secret is touched."""
    _need_available()
    rc, out = _run("dump-keychain")
    if rc != 0:
        raise KeystoreError("the Keychain list could not be read")
    ids, svce, acct = set(), None, None
    for line in out.splitlines() + ['keychain: "end"']:
        if line.startswith("keychain:"):
            if svce == SERVICE and acct and valid_id(acct):
                ids.add(acct)
            svce = acct = None
            continue
        m = re.match(r'\s*"(svce|acct)"<blob>="([^"]*)"', line)
        if m:
            if m.group(1) == "svce":
                svce = m.group(2)
            else:
                acct = m.group(2)
    return sorted(ids)


# ------------------------------------------------------------------------------------ secret-service
def _exec(argv, stdin, runner=None, timeout=TIMEOUT):
    """Run argv (a list) with a timeout; returns (returncode, stdout, stderr). The secret, if any, is stdin."""
    try:
        p = (runner or subprocess.run)(argv, input=stdin, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        raise KeystoreError("the desktop keyring could not be reached") from None
    return p.returncode, p.stdout or "", p.stderr or ""


def _quiet_miss(rc, err):
    """secret-tool exits 1 with nothing on stderr when the item simply is not there."""
    return rc == 1 and not err.strip()


def system_tool(name, dirs=SYSTEM_DIRS):
    """Absolute path of `name` in a fixed system directory, else None. The keyring items travel on this program's
    stdin, so a user-writable PATH entry must not be able to stand in for it."""
    for d in dirs:
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def probe_secret_service(runner=None, which=system_tool):
    """'ok', 'no-tool' or 'unreachable'. Looks up a name that never exists: a reachable, unlocked service
    answers with a quiet miss; no D-Bus, no service or a locked keyring (prompt, timeout) is 'unreachable'."""
    tool = which(SECRET_TOOL)
    if not tool:
        return "no-tool"
    try:
        rc, _, err = _exec([tool, "lookup", "service", SERVICE, "account", "probe:absent"], None, runner, PROBE_TIMEOUT)
    except KeystoreError:
        return "unreachable"
    return "ok" if rc == 0 or _quiet_miss(rc, err) else "unreachable"


def select_backend(platform, probe):
    """Pure: (backend name, why) from sys.platform and a probe_secret_service() result."""
    if platform == "darwin":
        return "keychain", "the macOS Keychain"
    if probe == "ok":
        return "secret-service", "the desktop keyring (Secret Service)"
    if probe == "no-tool":
        return "file", "the secret-tool command is not installed, so keys are kept in a file readable only by you"
    return "file", "no desktop keyring answered, so keys are kept in a file readable only by you"


class _SecretService:
    name, secure = "secret-service", True

    def __init__(self, runner=None, tool=SECRET_TOOL):
        self.runner, self.tool = runner, tool

    def available(self):
        return True

    def _attrs(self, item_id):
        return ["service", SERVICE, "account", item_id]

    def save(self, item_id, secret):
        rc, _, _ = _exec([self.tool, "store", "--label=OpenGenerator key"] + self._attrs(item_id), secret, self.runner)
        if rc != 0:
            raise KeystoreError("the key could not be saved to the desktop keyring")

    def load(self, item_id):
        rc, out, err = _exec([self.tool, "lookup"] + self._attrs(item_id), None, self.runner)
        if _quiet_miss(rc, err):
            return None
        if rc != 0:
            raise KeystoreError("the key could not be read from the desktop keyring")
        return out.rstrip("\n") or None

    def forget(self, item_id):
        rc, _, err = _exec([self.tool, "clear"] + self._attrs(item_id), None, self.runner)
        if rc != 0 and not _quiet_miss(rc, err):
            raise KeystoreError("the key could not be removed from the desktop keyring")

    def stored_ids(self):
        rc, out, err = _exec([self.tool, "search", "--all", "service", SERVICE], None, self.runner)
        if rc != 0 and not _quiet_miss(rc, err):
            raise KeystoreError("the desktop keyring list could not be read")
        # search prints each secret too; only the account attribute lines are read and the rest is dropped
        ids = {m.group(1) for m in re.finditer(r"^attribute\.account = (.*)$", out, re.M) if valid_id(m.group(1))}
        return sorted(ids)


# ------------------------------------------------------------------------------------------- file
_file_lock = threading.Lock()


class _File:
    name, secure = "file", False

    def available(self):
        return True

    @staticmethod
    def _path():
        return os.path.join(settings_store.settings_dir(), FILE_NAME)

    def _read(self):
        """The stored items; {} when there is no file. Refuses a file others could read or that is not ours."""
        try:
            fd = os.open(self._path(), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return {}
        except OSError:
            raise KeystoreError("the key file %s could not be opened" % FILE_NAME) from None
        with os.fdopen(fd, "r", encoding="utf-8") as fh:
            st = os.fstat(fh.fileno())
            if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
                raise KeystoreError("the key file %s belongs to another user, so it was not read" % FILE_NAME)
            if stat.S_IMODE(st.st_mode) & BAD_MODE:
                raise KeystoreError("the key file %s can be read by other users; run chmod 600 on it" % FILE_NAME)
            try:
                items = json.loads(fh.read(FILE_MAX + 1))
            except (OSError, ValueError):
                raise KeystoreError("the key file %s is damaged" % FILE_NAME) from None
        if not isinstance(items, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in items.items()):
            raise KeystoreError("the key file %s is damaged" % FILE_NAME)
        return items

    def _write(self, items):
        """Atomic: a 0600 temp file in the same folder, flushed to disk, then renamed over the old one."""
        folder = os.path.dirname(self._path())
        try:
            settings_store.ensure_private_dir(folder)
            fd, tmp = tempfile.mkstemp(dir=folder, prefix=".keystore-")
        except OSError:
            raise KeystoreError("the key file %s could not be written" % FILE_NAME) from None
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(items, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path())
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass  # the temp file is already gone; the write error below is what matters
            raise KeystoreError("the key file %s could not be written" % FILE_NAME) from None

    def save(self, item_id, secret):
        with _file_lock:
            items = self._read()
            items[item_id] = secret
            self._write(items)

    def load(self, item_id):
        with _file_lock:
            return self._read().get(item_id) or None

    def forget(self, item_id):
        with _file_lock:
            items = self._read()
            if items.pop(item_id, None) is not None:
                self._write(items)

    def stored_ids(self):
        with _file_lock:
            return sorted(k for k in self._read() if valid_id(k))


class _Keychain:
    name, secure = "keychain", True
    available = staticmethod(_kc_available)
    save = staticmethod(_kc_save)
    load = staticmethod(_kc_load)
    forget = staticmethod(_kc_forget)
    stored_ids = staticmethod(_kc_stored_ids)


# -------------------------------------------------------------------------------- public interface
_state = {}                        # the Linux probe runs once per process; reset() forgets it


def reset():
    _state.clear()


def _backend():
    if "backend" not in _state:
        name, why = select_backend(sys.platform, None if sys.platform == "darwin" else probe_secret_service())
        _state["backend"] = {"keychain": _Keychain(), "secret-service": _SecretService(tool=system_tool(SECRET_TOOL) or SECRET_TOOL), "file": _File()}[name]
        _state["why"] = why
    return _state["backend"]


def available():
    return _backend().available()


def status():
    """Which backend is active and why, for the UI. No secret and no path."""
    b = _backend()
    return {"backend": b.name, "secure": b.secure, "available": b.available(), "why": _state["why"]}


def save(item_id, secret):
    _check_id(item_id)
    _check_secret(secret)
    _backend().save(item_id, secret)


def load(item_id):
    """The stored secret, or None when there is none."""
    _check_id(item_id)
    return _backend().load(item_id)


def forget(item_id):
    _check_id(item_id)
    _backend().forget(item_id)


def stored_ids():
    return _backend().stored_ids()
