"""IOC record model (contract section 1).

An IOC is a plain JSON-serialisable dict:
  type, value, role, confidence (0-100), source, tags, techniques,
  first_seen (ISO-8601 or None), note (<= 500 chars), why (one sentence).
Nothing here touches the network or the packet engine.
"""
import re
from datetime import datetime, timezone

ROLES = ("c2", "payload", "exfil", "scanner", "brute", "phishing", "tor", "compromised", "vulnerability", "unknown")
TYPES = ("ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "cve", "filename", "cidr")

NOTE_MAX = 200
_TECH = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]+")


def clean_text(s, limit=NOTE_MAX):
    """Collapse control characters/whitespace and trim to `limit` characters."""
    if s is None:
        return ""
    if not isinstance(s, str):
        s = str(s)
    s = s[:max(limit, 0) * 20 + 64]          # bounded work on huge inputs; whitespace-heavy text can end up shorter
    s = _CTRL.sub(" ", s)
    s = " ".join(s.split())
    return s[:limit]


def _confidence(v, default=50):
    try:
        v = int(round(float(v)))
    except (TypeError, ValueError, OverflowError):
        return default
    return max(0, min(100, v))


def _iso(v):
    """Best-effort ISO-8601 normalisation; returns None when unparseable."""
    if v is None or v == "":
        return None
    try:
        if isinstance(v, (int, float)) or (isinstance(v, str) and v.strip().isdigit()):
            n = float(v)
            if n > 1e11:  # milliseconds
                n /= 1000.0
            return datetime.fromtimestamp(n, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        s = str(v).strip()
        if len(s) > 40:
            return None
        s2 = s.replace(" UTC", "Z").replace("Z", "+00:00")
        if re.match(r"^\d{4}-\d{2}-\d{2}$", s2):
            return s2
        s2 = s2.replace(" ", "T", 1) if re.match(r"^\d{4}-\d{2}-\d{2} \d", s2) else s2
        dt = datetime.fromisoformat(s2)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OverflowError, OSError):
        return None


def norm_techniques(items):
    out = []
    for t in (items if isinstance(items, (list, tuple, set)) else []):
        t = str(t).strip().upper()
        if _TECH.match(t) and t not in out:
            out.append(t)
    return out[:40]


def norm_tags(items):
    out = []
    for t in (items if isinstance(items, (list, tuple, set)) else []):
        t = clean_text(t, 60).lower()
        if t and t not in out:
            out.append(t)
    return out[:20]


def new_ioc(type, value, *, role="unknown", confidence=50, source="", tags=None,
            techniques=None, first_seen=None, note="", why=""):
    """Build a validated IOC dict. Raises ValueError for a bad type/role/value.

    The value is canonicalised with intel.classify and must classify as `type`.
    """
    from . import classify
    if type not in TYPES:
        raise ValueError("unknown IOC type %r" % (type,))
    if role not in ROLES:
        raise ValueError("unknown IOC role %r" % (role,))
    if not isinstance(value, str) or not value.strip():
        raise ValueError("empty IOC value")
    t, canon = classify.classify_value(value)
    if t is None:
        raise ValueError("value %r is not a valid %s" % (value[:60], type))
    if t != type:
        raise ValueError("value %r classifies as %s, not %s" % (value[:60], t, type))
    return {
        "type": type,
        "value": canon,
        "role": role,
        "confidence": _confidence(confidence),
        "source": clean_text(source, 80),
        "tags": norm_tags(tags),
        "techniques": norm_techniques(techniques),
        "first_seen": _iso(first_seen),
        "note": clean_text(note, 500),
        "why": clean_text(why, 160),
    }


def ioc_key(ioc):
    """Dedupe key: (type, canonical value)."""
    return (ioc.get("type"), str(ioc.get("value", "")).lower() if ioc.get("type") != "url"
            else _url_key(str(ioc.get("value", ""))))


def _url_key(u):
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(.*)$", u)
    if not m:
        return u
    return m.group(1).lower() + "://" + m.group(2).lower() + m.group(3)


def merge(a, b):
    """Merge IOC b into a (in place): keep the higher-confidence role/why, union tags/techniques."""
    if b.get("confidence", 0) > a.get("confidence", 0) or (
            a.get("role") == "unknown" and b.get("role") != "unknown"):
        for k in ("role", "why", "source", "note"):
            if b.get(k) and (k != "note" or not a.get(k) or b.get("confidence", 0) > a.get("confidence", 0)):
                a[k] = b[k]
        a["confidence"] = max(a.get("confidence", 0), b.get("confidence", 0))
    a["tags"] = norm_tags(list(a.get("tags", [])) + list(b.get("tags", [])))
    a["techniques"] = norm_techniques(list(a.get("techniques", [])) + list(b.get("techniques", [])))
    if not a.get("first_seen"):
        a["first_seen"] = b.get("first_seen")
    elif b.get("first_seen") and b["first_seen"] < a["first_seen"]:
        a["first_seen"] = b["first_seen"]
    return a


def dedupe(iocs):
    """Order-preserving dedupe by ioc_key, merging duplicates."""
    seen, out = {}, []
    for i in iocs:
        k = ioc_key(i)
        if k in seen:
            merge(seen[k], i)
        else:
            seen[k] = i
            out.append(i)
    return out
