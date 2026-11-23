"""On-disk feed cache.

Directory: $OPENGENERATOR_CACHE or ~/.opengenerator/intel-cache. Files are written atomically
(temp file + rename) with mode 600; the directory is 700. Cache key = feed id + sorted params
(never an API key: callers must not pass secrets in params; keys named like key/token/auth are
rejected). `get(feed_id, params, ttl)` returns the cached payload (str) or None when absent or older
than ttl seconds (ttl=None ignores age: used for offline mode). A `manifest.json` snapshot manifest
records feed, params, fetched_at, bytes and sha256 for every entry.
"""
import hashlib
import json
import os
import re
import tempfile
import time


def cache_dir():
    d = os.environ.get("OPENGENERATOR_CACHE") or os.path.join(os.path.expanduser("~"), ".opengenerator", "intel-cache")
    return d


_SECRET = re.compile(r"key|token|auth|secret|password", re.I)


def key_for(feed_id, params=None):
    params = params or {}
    for k in params:
        if _SECRET.search(str(k)):
            raise ValueError("refusing to cache a secret-looking parameter %r" % k)
    canon = json.dumps({"f": feed_id, "p": params}, sort_keys=True, default=str)
    return re.sub(r"[^A-Za-z0-9_.-]", "_", feed_id)[:40] + "-" + hashlib.sha256(canon.encode()).hexdigest()[:16]


def _paths(key):
    d = cache_dir()
    return d, os.path.join(d, key + ".json")


def _ensure(d):
    os.makedirs(d, mode=0o700, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass


def _atomic_write(path, text):
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def put(feed_id, params, payload, now=None):
    """Store payload (str) under feed id + params; updates the manifest. Returns the entry key."""
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")
    d = cache_dir()
    _ensure(d)
    key = key_for(feed_id, params)
    now = time.time() if now is None else now
    _atomic_write(os.path.join(d, key + ".json"),
                  json.dumps({"feed": feed_id, "params": params or {}, "fetched_at": now, "payload": payload}))
    man = manifest()
    man[key] = {"feed": feed_id, "params": params or {}, "fetched_at": now, "bytes": len(payload),
                "sha256": hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()}
    _atomic_write(os.path.join(d, "manifest.json"), json.dumps(man, indent=1, sort_keys=True))
    return key


def get(feed_id, params=None, ttl=3600, now=None):
    """Cached payload string, or None if missing/expired/corrupt."""
    _, path = _paths(key_for(feed_id, params))
    try:
        with open(path, encoding="utf-8") as f:
            rec = json.load(f)
        age = (time.time() if now is None else now) - float(rec["fetched_at"])
        if ttl is not None and age > ttl:
            return None
        return rec["payload"]
    except (OSError, ValueError, KeyError, TypeError):
        return None


def manifest():
    try:
        with open(os.path.join(cache_dir(), "manifest.json"), encoding="utf-8") as f:
            m = json.load(f)
        return m if isinstance(m, dict) else {}
    except (OSError, ValueError):
        return {}


def clear():
    d = cache_dir()
    n = 0
    if os.path.isdir(d):
        for f in os.listdir(d):
            if f.endswith(".json"):
                os.unlink(os.path.join(d, f))
                n += 1
    return n
