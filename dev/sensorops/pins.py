"""Trust-on-first-use pins for sensor certificates.

A lab sensor presents a self-signed certificate, so it cannot be verified against a CA. Instead the SHA-256 of the
certificate seen on first contact is stored per sensor (host[:port]) in the settings folder, and every later
connection must present the same one. The check runs right after the TLS handshake, before any request (and so the
API key) is sent. A changed certificate is refused until the person removes that sensor's entry from the pin file.
"""
import json
import os
import re
import ssl
import tempfile
import threading

import settings_store

PIN_FILE = "sensor-pins.json"
_LOCK = threading.Lock()
_HEX = re.compile(r"[0-9a-f]{64}")


def _path():
    return os.path.join(settings_store.settings_dir(), PIN_FILE)


def _load():
    try:
        with open(_path(), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError, RecursionError):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, str) and _HEX.fullmatch(v)} \
        if isinstance(data, dict) else {}


def _save(pins):
    d = settings_store.ensure_private_dir()
    fd, tmp = tempfile.mkstemp(prefix=".pins-", suffix=".tmp", dir=d)        # mkstemp is 0600 and exclusive
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(pins, fh, indent=1, sort_keys=True)
        os.replace(tmp, _path())
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def check(sensor, fingerprint):
    """Pin `fingerprint` (hex SHA-256) for `sensor` on first use; later calls must match. Raises ssl.SSLError."""
    key, fp = str(sensor).strip().lower(), str(fingerprint).lower()
    with _LOCK:
        pins = _load()
        if key not in pins:
            pins[key] = fp
            try:
                _save(pins)
            except OSError:
                raise ssl.SSLError("the sensor's certificate could not be pinned (the settings folder is not writable)") from None
            return
        if pins[key] != fp:
            raise ssl.SSLError("the certificate of %s is not the one trusted when it was first contacted. Nothing was sent. "
                               "If it was replaced on purpose, remove that sensor's entry from %s in the settings folder."
                               % (key, PIN_FILE))
