"""
OpenGenerator -- optional macOS Keychain storage for API keys (stdlib only).

Keys are stored as generic passwords: service ``opengenerator``, account = an item id such as
``feed:otx`` or ``sensor:10.0.0.5``. A secret is never placed on a command line (it would show in
``ps``): commands are written to the stdin of ``security -i`` and the secret travels as hex (-X), so
no quoting or escaping of the secret is needed. ``stored_ids()`` lists accounts without reading any
secret. Every failure becomes a KeystoreError whose one-line message never contains the secret.
"""
import binascii
import os
import re
import subprocess
import sys

SERVICE = "opengenerator"
SECURITY = "/usr/bin/security"
ID_RE = re.compile(r"[a-z0-9._:-]{1,64}")
SECRET_MAX = 300
TIMEOUT = 15
_NOT_FOUND = 44                    # `security` exit status: item not found


class KeystoreError(Exception):
    """A one-line message, safe to show; never contains a secret."""


def available():
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


def save(item_id, secret):
    _check_id(item_id)
    _check_secret(secret)
    _need_available()
    hexed = binascii.hexlify(secret.encode("ascii")).decode("ascii")
    rc, _ = _run("add-generic-password -U -s %s -a %s -X %s" % (SERVICE, item_id, hexed))
    if rc != 0:
        raise KeystoreError("the key could not be saved to the Keychain")


def load(item_id):
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


def forget(item_id):
    _check_id(item_id)
    _need_available()
    rc, _ = _run("delete-generic-password -s %s -a %s" % (SERVICE, item_id))
    if rc not in (0, _NOT_FOUND):
        raise KeystoreError("the key could not be removed from the Keychain")


def stored_ids():
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
