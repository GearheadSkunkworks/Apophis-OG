"""Campaign file v1: validation, defaults, canonical load/dump and the JSON Schema document.

The definitions below (enumerations, option table, caps) drive both ``validate`` and the generated
``campaign.schema.json`` so documentation and validator cannot drift. ``validate`` additionally checks things a
static schema cannot: action tokens and their params against the action registry, ATT&CK ids against the bundled
catalog, endpoint references against the IOC list, and (in real address mode) that public IPv4 is used.

Input is hostile by assumption: JSON only, 5 MB cap, unknown keys rejected, control characters rejected, every
size capped. Standard library only.
"""
import copy
import ipaddress
import json
import math
import os
import re
import unicodedata

from . import addressing, attack

SCHEMA_ID = "opengenerator.campaign/1"
MAX_BYTES = 5 * 1024 * 1024
MAX_IOCS, MAX_STAGES, MAX_ACTIONS = 5000, 60, 400
MAX_STR = 2000

IOC_TYPES = ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email", "cve", "filename", "cidr"]
ROLES = ["c2", "payload", "exfil", "scanner", "brute", "phishing", "tor", "compromised", "vulnerability", "unknown"]
ADDRESS_MODES = ["mapped", "real"]
SPEEDS = ["realistic", "fast"]
IP_FAMILIES = ["v4", "v6", "dual"]           # v4 default; v6 runs every action over IPv6; dual alternates per action
INCLUDES = ["discovery", "credential_access", "lateral_movement", "exfiltration", "impact"]
# M3 adds one option per further tactic; they are opt-in (the default list below is unchanged)
INCLUDES_M3 = ["execution", "persistence", "privilege_escalation", "stealth", "defense_impairment", "collection",
               "reconnaissance", "resource_development", "initial_access"]
ALL_INCLUDES = INCLUDES + INCLUDES_M3
SOURCE_KINDS = ["iocs", "hand", "feed"]
INTERNAL_ROLES = ["ws", "ws2", "server", "dc", "file", "sql", "web", "fw", "any_ws"]
EXTERNAL_ROLES = ["c2", "exfil", "payload", "scanner", "phish", "tor", "brute"]   # reference prefix -> IOC role
_PREFIX_ROLE = {"c2": "c2", "exfil": "exfil", "payload": "payload", "scanner": "scanner", "phish": "phishing",
                "tor": "tor", "brute": "brute"}

# option name -> (json type, default, extra constraint dict for the JSON Schema)
OPTIONS = {
    "address_mode": ("string", "mapped", {"enum": ADDRESS_MODES}),
    "start": ("string", "10:00", {"pattern": r"^([01][0-9]|2[0-3]):[0-5][0-9]$"}),
    "speed": ("string", "realistic", {"enum": SPEEDS}),
    "ip_family": ("string", "v4", {"enum": IP_FAMILIES}),
    "compromised": ("string", "ws", {"pattern": r"^[A-Za-z][A-Za-z0-9_:-]{0,39}$"}),
    "lateral_target": ("string", "server", {"pattern": r"^[A-Za-z][A-Za-z0-9_:-]{0,39}$"}),
    "beacons_per_c2": ("integer", 4, {"minimum": 1, "maximum": 50}),
    "family": ("string", "auto", {"pattern": r"^[a-z0-9-]{1,40}$"}),      # auto | none | a families.py id
    "include": ("array", ["discovery", "credential_access", "lateral_movement", "exfiltration"],
                {"items": {"enum": ALL_INCLUDES}, "uniqueItems": True}),
}
META_KEYS = {"name": "", "id": "", "description": "", "actor": "Unattributed", "origin_country": "",
             "created": "", "seed": 1, "source": None}
IOC_KEYS = ("type", "value", "role", "confidence", "source", "tags", "techniques", "first_seen", "note", "why")
STAGE_KEYS = ("id", "name", "tactic", "techniques", "narrative", "duration_s", "fast_s", "actions")
ACTION_KEYS = ("action", "from", "to", "params", "at", "ioc", "explain")
TOP_KEYS = ("schema", "meta", "options", "iocs", "stages", "expect", "explain")

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029]")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
_DATE = re.compile(r"^(\d{4}-\d{2}-\d{2})?$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_HEX = {"md5": 32, "sha1": 40, "sha256": 64}
_SUFFIX = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
_REF = re.compile(r"^(%s):(\d{1,6})$" % "|".join(EXTERNAL_ROLES + ["ioc"]))
_HOSTREF = re.compile(r"^host:[A-Za-z][A-Za-z0-9_-]{0,31}$")


class CampaignError(ValueError):
    """Raised by ``load`` for unreadable or invalid campaign input; ``.errors`` lists the problems."""

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors[:5]) + (" (+%d more)" % (len(self.errors) - 5) if len(self.errors) > 5 else ""))


# ---------------------------------------------------------------- endpoint grammar
def endpoint_kind(ref):
    """'internal', 'external' or None (invalid reference)."""
    if not isinstance(ref, str):
        return None
    if ref in INTERNAL_ROLES or _HOSTREF.match(ref):
        return "internal"
    if ref == "attacker" or _REF.match(ref):
        return "external"
    return None


def _num(v):
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True               # math.isfinite would raise OverflowError on a huge int
    return isinstance(v, float) and math.isfinite(v)


MAX_DEPTH = 40


def too_deep(obj, limit=MAX_DEPTH):
    """True when lists/dicts nest deeper than `limit` (iterative, so hostile depth cannot recurse)."""
    stack = [(obj, 1)]
    while stack:
        v, d = stack.pop()
        if isinstance(v, dict):
            kids = v.values()
        elif isinstance(v, list):
            kids = v
        else:
            continue
        if d > limit:
            return True
        stack.extend((k, d + 1) for k in kids if isinstance(k, (dict, list)))
    return False


def _int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _str(v, maxlen=MAX_STR):
    return isinstance(v, str) and len(v) <= maxlen and not _CTRL.search(v)


# ---------------------------------------------------------------- options
def normalise_options(options):
    """(options_with_defaults, errors). Unknown keys and bad values are reported."""
    errs, out = [], {}
    if options is None:
        options = {}
    if not isinstance(options, dict):
        return {k: copy.deepcopy(v[1]) for k, v in OPTIONS.items()}, ["options must be an object"]
    for k in options:
        if k not in OPTIONS:
            errs.append("options: unknown key %r" % str(k)[:40])
    for k, (typ, default, extra) in OPTIONS.items():
        v = options.get(k, copy.deepcopy(default))
        ok = True
        if typ == "string":
            ok = _str(v, 64)
            if ok and "enum" in extra:
                ok = v in extra["enum"]
            if ok and "pattern" in extra:
                ok = re.match(extra["pattern"], v) is not None
        elif typ == "integer":
            ok = _int(v) and extra["minimum"] <= v <= extra["maximum"]
        elif typ == "array":
            ok = isinstance(v, list) and all(isinstance(x, str) and x in extra["items"]["enum"] for x in v) \
                and len(set(v)) == len(v)
        if not ok:
            errs.append("options.%s: invalid value %r" % (k, v if _str(v, 40) or _num(v) else "<?>"))
            v = copy.deepcopy(default)
        out[k] = v
    if out["compromised"] not in INTERNAL_ROLES and not _HOSTREF.match(out["compromised"]):
        errs.append("options.compromised: must be an internal role (%s) or host:SUFFIX" % ", ".join(INTERNAL_ROLES))
    return out, errs


# ---------------------------------------------------------------- IOC
def clean_ioc(ioc):
    """Sanitise one IOC to the section-1 shape: known keys only, defaults filled, strings trimmed."""
    if not isinstance(ioc, dict):
        return None
    o = {k: ioc.get(k) for k in IOC_KEYS if k in ioc}
    o["type"] = str(o.get("type", ""))
    o["value"] = str(o.get("value", "")).strip()
    o["role"] = o.get("role") if o.get("role") in ROLES else "unknown"
    c = o.get("confidence", 50)
    o["confidence"] = int(c) if _num(c) and 0 <= c <= 100 else 50
    o["source"] = _CTRL.sub(" ", str(o.get("source") or ""))[:80]
    tags, techs = o.get("tags"), o.get("techniques")
    o["tags"] = [_CTRL.sub(" ", t)[:40] for t in (tags if isinstance(tags, list) else []) if isinstance(t, str)][:20]
    o["techniques"] = [t for t in (techs if isinstance(techs, list) else []) if isinstance(t, str) and not attack.validate_ids([t])][:20]
    fs = o.get("first_seen")
    o["first_seen"] = _CTRL.sub(" ", fs)[:40] if isinstance(fs, str) else None
    o["note"] = _CTRL.sub(" ", str(o.get("note") or ""))[:200]
    o["why"] = _CTRL.sub(" ", str(o.get("why") or ""))[:300]
    return o


def _hidden_chars(v):
    """True when v holds a control, format (zero-width, bidi, BOM), separator or surrogate character."""
    if v.isascii():
        return _CTRL.search(v) is not None
    return any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp", "Cs") for c in v)


def _check_value(t, v):
    if not isinstance(v, str) or _hidden_chars(v):
        return False
    if t == "ipv4":
        try:
            return ipaddress.IPv4Address(v) is not None
        except ValueError:
            return False
    if t == "ipv6":
        try:
            return ipaddress.IPv6Address(v) is not None
        except ValueError:
            return False
    if t == "cidr":
        try:
            ipaddress.ip_network(v, strict=False)
            return True
        except ValueError:
            return False
    if t in _HEX:
        return len(v) == _HEX[t] and re.fullmatch(r"[0-9a-fA-F]+", v) is not None
    if t == "domain":
        return _DOMAIN.match(v) is not None
    if t == "url":
        return re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]{1,9}://[^\s]+$", v) is not None
    if t == "cve":
        return re.match(r"^CVE-\d{4}-\d{4,7}$", v, re.I) is not None
    if t == "email":
        return re.match(r"^[^@\s]{1,64}@[^@\s]{1,255}$", v) is not None
    return 0 < len(v) <= 260    # filename


def _validate_ioc(i, ioc, errs):
    p = "iocs[%d]" % i
    if not isinstance(ioc, dict):
        errs.append("%s: must be an object" % p)
        return
    for k in ioc:
        if k not in IOC_KEYS:
            errs.append("%s: unknown key %r" % (p, str(k)[:40]))
    t, v = ioc.get("type"), ioc.get("value")
    if t not in IOC_TYPES:
        errs.append("%s.type: must be one of %s" % (p, ", ".join(IOC_TYPES)))
    if not _str(v, 2048) or not v.strip():
        errs.append("%s.value: must be a non-empty string (max 2048, no control characters)" % p)
    elif t in IOC_TYPES and not _check_value(t, v):
        errs.append("%s.value: not a valid %s" % (p, t))
    if ioc.get("role", "unknown") not in ROLES:
        errs.append("%s.role: must be one of %s" % (p, ", ".join(ROLES)))
    c = ioc.get("confidence", 50)
    if not _num(c) or not 0 <= c <= 100:
        errs.append("%s.confidence: must be a number 0-100" % p)
    for k, mx in (("source", 200), ("note", 500), ("why", 500)):
        if k in ioc and not _str(ioc[k], mx):
            errs.append("%s.%s: must be a string (max %d)" % (p, k, mx))
    if "first_seen" in ioc and ioc["first_seen"] is not None and not _str(ioc["first_seen"], 40):
        errs.append("%s.first_seen: must be a string or null" % p)
    for k in ("tags", "techniques"):
        if k in ioc:
            x = ioc[k]
            if not isinstance(x, list) or len(x) > 50 or not all(_str(s, 80) for s in x):
                errs.append("%s.%s: must be a list of up to 50 strings" % (p, k))
            elif k == "techniques":
                errs += ["%s.techniques: %s" % (p, e) for e in attack.validate_ids(x)]


# ---------------------------------------------------------------- actions
def _registry():
    try:
        from .actions import load_all
        return load_all()
    except Exception:
        return {}


_PTYPES = {"int": lambda v: _int(v), "float": lambda v: _num(v), "str": lambda v: isinstance(v, str) and len(v) <= MAX_STR
           and not _CTRL.search(v), "bool": lambda v: isinstance(v, bool),
           "list": lambda v: isinstance(v, list) and len(v) <= 1000}


def _validate_params(p, params, spec, errs):
    if not isinstance(params, dict):
        errs.append("%s.params: must be an object" % p)
        return
    for k, v in params.items():
        d = spec.params.get(k) if spec is not None else None
        if spec is not None and d is None:
            errs.append("%s.params: unknown parameter %r for action %s" % (p, str(k)[:40], spec.token))
            continue
        if spec is None:
            if not _str(k, 40):
                errs.append("%s.params: bad parameter name" % p)
            continue
        chk = _PTYPES.get(d.get("type", "str"), _PTYPES["str"])
        ok = chk(v) or (d.get("type") == "float" and _int(v))
        if not ok:
            errs.append("%s.params.%s: expected %s" % (p, k, d.get("type", "str")))


def _validate_endpoint(p, key, ref, iocs, role_counts, errs):
    kind = endpoint_kind(ref)
    if kind is None:
        errs.append("%s.%s: invalid endpoint reference %r" % (p, key, ref if _str(ref, 40) else "<?>"))
        return None
    m = _REF.match(ref)
    if m:
        pre, n = m.group(1), int(m.group(2))
        if pre == "ioc":
            if n >= len(iocs):
                errs.append("%s.%s: %s is out of range (%d IOCs)" % (p, key, ref, len(iocs)))
        elif not role_counts.get(_PREFIX_ROLE[pre]):
            errs.append("%s.%s: %s needs an ipv4/domain IOC with role %s" % (p, key, ref, _PREFIX_ROLE[pre]))
    return kind


def validate(campaign):
    """List of error strings for a campaign dict (empty list = valid)."""
    errs = []
    if not isinstance(campaign, dict):
        return ["campaign must be a JSON object"]
    if too_deep(campaign):
        return ["campaign is nested more than %d levels deep" % MAX_DEPTH]
    for k in campaign:
        if k not in TOP_KEYS:
            errs.append("unknown top-level key %r" % str(k)[:40])
    if campaign.get("schema") != SCHEMA_ID:
        errs.append("schema must be %r" % SCHEMA_ID)

    # meta
    meta = campaign.get("meta")
    if not isinstance(meta, dict):
        errs.append("meta: required object")
        meta = {}
    else:
        for k in meta:
            if k not in META_KEYS:
                errs.append("meta: unknown key %r" % str(k)[:40])
        if not _str(meta.get("name"), 200) or not meta.get("name", "").strip():
            errs.append("meta.name: required non-empty string (max 200)")
        if "id" in meta and (not isinstance(meta["id"], str) or (meta["id"] and not _ID.match(meta["id"]))):
            errs.append("meta.id: letters, digits, '-' and '_' only (max 64)")
        for k in ("description", "actor", "origin_country"):
            if k in meta and not _str(meta[k], 2000 if k == "description" else 200):
                errs.append("meta.%s: must be a string" % k)
        if "created" in meta and not (isinstance(meta["created"], str) and _DATE.match(meta["created"])):
            errs.append("meta.created: must be YYYY-MM-DD or empty")
        if "seed" in meta and not (_int(meta["seed"]) and 0 <= meta["seed"] < 2 ** 63):
            errs.append("meta.seed: must be an integer 0 .. 2^63-1")
        src = meta.get("source")
        if src is not None:
            if not isinstance(src, dict):
                errs.append("meta.source: must be an object")
            else:
                for k in src:
                    if k not in ("kind", "feeds", "ioc_count"):
                        errs.append("meta.source: unknown key %r" % str(k)[:40])
                if src.get("kind") not in SOURCE_KINDS:
                    errs.append("meta.source.kind: must be one of %s" % ", ".join(SOURCE_KINDS))
                if "feeds" in src and not (isinstance(src["feeds"], list) and len(src["feeds"]) <= 50
                                           and all(_str(f, 80) for f in src["feeds"])):
                    errs.append("meta.source.feeds: must be a list of strings")
                if "ioc_count" in src and not (_int(src["ioc_count"]) and src["ioc_count"] >= 0):
                    errs.append("meta.source.ioc_count: must be a non-negative integer")

    opts, oerrs = normalise_options(campaign.get("options"))
    errs += oerrs

    # iocs
    iocs = campaign.get("iocs")
    if not isinstance(iocs, list):
        errs.append("iocs: required list")
        iocs = []
    elif len(iocs) > MAX_IOCS:
        errs.append("iocs: at most %d allowed (got %d)" % (MAX_IOCS, len(iocs)))
        iocs = iocs[:MAX_IOCS]
    role_counts = {}
    for i, ioc in enumerate(iocs):
        _validate_ioc(i, ioc, errs)
        if isinstance(ioc, dict) and ioc.get("type") in ("ipv4", "domain") and ioc.get("role") in ROLES:
            role_counts[ioc["role"]] = role_counts.get(ioc["role"], 0) + 1
            if opts["address_mode"] == "real" and ioc["type"] == "ipv4" and ioc["role"] not in ("unknown", "compromised") \
                    and _str(ioc.get("value"), 64):
                ok, why = addressing.real_mode_check(ioc["value"])
                if not ok:
                    errs.append("iocs[%d]: %s" % (i, why))

    # stages
    stages = campaign.get("stages")
    reg = _registry()
    stage_ids, total_actions = [], 0
    if not isinstance(stages, list) or not stages:
        errs.append("stages: required non-empty list")
        stages = []
    elif len(stages) > MAX_STAGES:
        errs.append("stages: at most %d allowed (got %d)" % (MAX_STAGES, len(stages)))
        stages = stages[:MAX_STAGES]
    for si, st in enumerate(stages):
        p = "stages[%d]" % si
        if not isinstance(st, dict):
            errs.append("%s: must be an object" % p)
            continue
        for k in st:
            if k not in STAGE_KEYS:
                errs.append("%s: unknown key %r" % (p, str(k)[:40]))
        sid = st.get("id")
        if not isinstance(sid, str) or not _ID.match(sid):
            errs.append("%s.id: required, letters/digits/-/_ (max 64)" % p)
        elif sid in stage_ids:
            errs.append("%s.id: duplicate stage id %r" % (p, sid))
        else:
            stage_ids.append(sid)
        if not _str(st.get("name"), 200) or not st.get("name", "").strip():
            errs.append("%s.name: required non-empty string" % p)
        if attack.tactic(st.get("tactic")) is None:
            errs.append("%s.tactic: unknown ATT&CK tactic slug %r" % (p, st.get("tactic") if _str(st.get("tactic"), 40) else "<?>"))
        t = st.get("techniques", [])
        if not isinstance(t, list) or len(t) > 100:
            errs.append("%s.techniques: must be a list" % p)
        else:
            errs += ["%s.techniques: %s" % (p, e) for e in attack.validate_ids(t)]
        if "narrative" in st and not _str(st["narrative"], 2000):
            errs.append("%s.narrative: must be a string" % p)
        for k in ("duration_s", "fast_s"):
            if k in st and not (_num(st[k]) and 0 < st[k] <= 86400):
                errs.append("%s.%s: must be a positive number of seconds (max 86400)" % (p, k))
        acts = st.get("actions")
        if not isinstance(acts, list) or not acts:
            errs.append("%s.actions: required non-empty list" % p)
            continue
        total_actions += len(acts)
        if total_actions > MAX_ACTIONS:
            if total_actions - len(acts) <= MAX_ACTIONS:
                errs.append("actions: at most %d in total" % MAX_ACTIONS)
            continue
        for ai, a in enumerate(acts):
            _validate_action("%s.actions[%d]" % (p, ai), a, reg, iocs, role_counts, errs)

    # expect
    exp = campaign.get("expect", [])
    if not isinstance(exp, list) or len(exp) > 1000:
        errs.append("expect: must be a list")
    else:
        for ei, e in enumerate(exp):
            p = "expect[%d]" % ei
            if not isinstance(e, dict):
                errs.append("%s: must be an object" % p)
                continue
            for k in e:
                if k not in ("technique", "stage", "detection", "cve"):
                    errs.append("%s: unknown key %r" % (p, str(k)[:40]))
            errs += ["%s.technique: %s" % (p, x) for x in attack.validate_ids([e.get("technique")])]
            if "stage" in e and e.get("stage") not in stage_ids:
                errs.append("%s.stage: must name an existing stage id" % p)
            if "stage" not in e and "cve" not in e:
                errs.append("%s: needs a stage or a cve" % p)
            if "cve" in e and not (isinstance(e["cve"], str) and re.fullmatch(r"CVE-\d{4}-\d{4,7}", e["cve"])):
                errs.append("%s.cve: must look like CVE-2024-12345" % p)
            if "detection" in e and not _str(e["detection"], 200):
                errs.append("%s.detection: must be a string" % p)
    ex = campaign.get("explain", [])
    if not isinstance(ex, list) or len(ex) > 1000 or not all(_str(x, 1000) for x in ex):
        errs.append("explain: must be a list of strings")
    return errs


def _validate_action(p, a, reg, iocs, role_counts, errs):
    if not isinstance(a, dict):
        errs.append("%s: must be an object" % p)
        return
    for k in a:
        if k not in ACTION_KEYS:
            errs.append("%s: unknown key %r" % (p, str(k)[:40]))
    tok = a.get("action")
    spec = None
    if not isinstance(tok, str) or not _TOKEN.match(tok):
        errs.append("%s.action: required token (lower_snake)" % p)
    elif tok not in reg:
        errs.append("%s.action: unknown action %r" % (p, tok))
    else:
        spec = reg[tok]
    kinds = {}
    for key in ("from", "to"):
        if key not in a:
            errs.append("%s.%s: required" % (p, key))
        else:
            kinds[key] = _validate_endpoint(p, key, a[key], iocs, role_counts, errs)
    if spec is not None:
        for key, want in (("from", spec.src), ("to", spec.dst)):
            k = kinds.get(key)
            if k and want in ("internal", "external") and k != want:
                errs.append("%s.%s: action %s needs an %s endpoint, got %s" % (p, key, tok, want, a[key]))
    _validate_params(p, a.get("params", {}), spec, errs)
    if "at" in a and not (_num(a["at"]) and 0 <= a["at"] <= 86400):
        errs.append("%s.at: must be seconds 0-86400" % p)
    il = a.get("ioc", [])
    if not isinstance(il, list) or len(il) > 500 or not all(_int(x) and 0 <= x < len(iocs) for x in il):
        errs.append("%s.ioc: must be a list of valid IOC indexes" % p)
    if "explain" in a and not _str(a["explain"], 1000):
        errs.append("%s.explain: must be a string" % p)


# ---------------------------------------------------------------- normalise / load / dump
def normalise(campaign):
    """Deep copy with defaults filled (options, meta, stage and action optionals). Never raises on junk:
    wrong-typed parts are left for ``validate`` to report."""
    if too_deep(campaign):          # hostile nesting: hand it back untouched, validate() reports it
        return campaign
    c = copy.deepcopy(campaign)
    if not isinstance(c, dict):
        return c
    c.setdefault("schema", SCHEMA_ID)
    if isinstance(c.get("meta"), dict):
        for k, v in META_KEYS.items():
            if k != "source":
                c["meta"].setdefault(k, v)
        if not c["meta"].get("id") and isinstance(c["meta"].get("name"), str):
            c["meta"]["id"] = re.sub(r"[^a-z0-9]+", "-", c["meta"]["name"].lower()).strip("-")[:64] or "campaign"
    opts, _ = normalise_options(c.get("options") if isinstance(c.get("options"), dict) else None)
    if isinstance(c.get("options"), dict):
        opts = {**opts, **{k: v for k, v in c["options"].items() if k in OPTIONS}}
    c["options"] = opts
    if isinstance(c.get("iocs"), list):
        c["iocs"] = [clean_ioc(i) if isinstance(i, dict) and all(k in IOC_KEYS for k in i) else i for i in c["iocs"]]
    c.setdefault("expect", [])
    c.setdefault("explain", [])
    for st in c.get("stages") if isinstance(c.get("stages"), list) else []:
        if not isinstance(st, dict):
            continue
        st.setdefault("techniques", [])
        st.setdefault("narrative", "")
        st.setdefault("duration_s", 60)
        st.setdefault("fast_s", max(1, round(st["duration_s"] / 3)) if _num(st["duration_s"]) else 20)
        for a in st.get("actions") if isinstance(st.get("actions"), list) else []:
            if isinstance(a, dict):
                a.setdefault("params", {})
                a.setdefault("ioc", [])
                a.setdefault("explain", "")
    return c


def load(path_or_text):
    """Parse (JSON only, max 5 MB), validate and normalise. Raises CampaignError."""
    if isinstance(path_or_text, (bytes, bytearray)):
        raw = bytes(path_or_text)
    elif isinstance(path_or_text, os.PathLike) or (isinstance(path_or_text, str) and not path_or_text.lstrip().startswith("{")):
        path = os.fspath(path_or_text)
        try:
            if os.path.getsize(path) > MAX_BYTES:
                raise CampaignError(["campaign file larger than %d MB" % (MAX_BYTES // 1048576)])
            with open(path, "rb") as f:
                raw = f.read(MAX_BYTES + 1)
        except OSError as e:
            raise CampaignError(["cannot read campaign file: %s" % e.strerror]) from None
    elif isinstance(path_or_text, str):
        raw = path_or_text.encode("utf-8", "replace")
    else:
        raise CampaignError(["campaign must be a path or JSON text"])
    if len(raw) > MAX_BYTES:
        raise CampaignError(["campaign larger than %d MB" % (MAX_BYTES // 1048576)])

    def _bad(name):
        raise ValueError("non-finite number " + name)
    try:
        data = json.loads(raw.decode("utf-8-sig"), parse_constant=_bad)
    except (ValueError, RecursionError, UnicodeDecodeError) as e:
        raise CampaignError(["not valid JSON: %s" % str(e)[:120]]) from None
    if too_deep(data):
        raise CampaignError(["campaign is nested more than %d levels deep" % MAX_DEPTH])
    c = normalise(data)
    errs = validate(c)
    if errs:
        raise CampaignError(errs)
    return c


def dump(campaign):
    """Canonical JSON text: sorted keys, 2-space indent, UTF-8 characters kept, trailing newline."""
    return json.dumps(campaign, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------- JSON Schema document
def json_schema():
    """JSON Schema (draft 2020-12) for the v1 file, built from the same tables the validator uses."""
    S = {"type": "string"}
    opt_props = {}
    for k, (typ, default, extra) in OPTIONS.items():
        d = {"type": typ, "default": default}
        d.update(extra)
        opt_props[k] = d
    ioc = {"type": "object", "additionalProperties": False, "required": ["type", "value"],
           "properties": {"type": {"enum": IOC_TYPES}, "value": {"type": "string", "minLength": 1, "maxLength": 2048},
                          "role": {"enum": ROLES, "default": "unknown"},
                          "confidence": {"type": "number", "minimum": 0, "maximum": 100, "default": 50},
                          "source": {"type": "string", "maxLength": 200},
                          "tags": {"type": "array", "items": S, "maxItems": 50},
                          "techniques": {"type": "array", "items": {"type": "string", "pattern": r"^T\d{4}(\.\d{3})?$"}, "maxItems": 50},
                          "first_seen": {"type": ["string", "null"], "maxLength": 40},
                          "note": {"type": "string", "maxLength": 500}, "why": {"type": "string", "maxLength": 500}}}
    ref = {"type": "string", "description": "internal role (%s), host:SUFFIX, attacker, or %s:N / ioc:N" % (
        ", ".join(INTERNAL_ROLES), ", ".join(c + ":N" for c in EXTERNAL_ROLES)),
        "pattern": r"^(%s|host:[A-Za-z][A-Za-z0-9_-]{0,31}|attacker|(%s|ioc):[0-9]{1,6})$" % (
            "|".join(INTERNAL_ROLES), "|".join(EXTERNAL_ROLES))}
    action = {"type": "object", "additionalProperties": False, "required": ["action", "from", "to"],
              "properties": {"action": {"type": "string", "pattern": r"^[a-z][a-z0-9_]{1,40}$",
                                        "description": "token from the action registry; params are checked per ActionSpec"},
                             "from": ref, "to": ref, "params": {"type": "object"},
                             "at": {"type": "number", "minimum": 0, "maximum": 86400},
                             "ioc": {"type": "array", "items": {"type": "integer", "minimum": 0}, "maxItems": 500},
                             "explain": {"type": "string", "maxLength": 1000}}}
    stage = {"type": "object", "additionalProperties": False, "required": ["id", "name", "tactic", "actions"],
             "properties": {"id": {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"},
                            "name": {"type": "string", "minLength": 1, "maxLength": 200},
                            "tactic": {"enum": [t["slug"] for t in attack.tactics()]},
                            "techniques": {"type": "array", "items": {"type": "string", "pattern": r"^T\d{4}(\.\d{3})?$"}},
                            "narrative": {"type": "string", "maxLength": 2000},
                            "duration_s": {"type": "number", "exclusiveMinimum": 0, "maximum": 86400},
                            "fast_s": {"type": "number", "exclusiveMinimum": 0, "maximum": 86400},
                            "actions": {"type": "array", "minItems": 1, "items": action}}}
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema", "$id": SCHEMA_ID,
        "title": "OpenGenerator campaign file v1", "type": "object", "additionalProperties": False,
        "required": ["schema", "meta", "iocs", "stages"],
        "properties": {
            "schema": {"const": SCHEMA_ID},
            "meta": {"type": "object", "additionalProperties": False, "required": ["name"], "properties": {
                "name": {"type": "string", "minLength": 1, "maxLength": 200},
                "id": {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$"},
                "description": {"type": "string", "maxLength": 2000}, "actor": {"type": "string", "maxLength": 200},
                "origin_country": {"type": "string", "maxLength": 200},
                "created": {"type": "string", "pattern": r"^(\d{4}-\d{2}-\d{2})?$"},
                "seed": {"type": "integer", "minimum": 0},
                "source": {"type": "object", "additionalProperties": False, "required": ["kind"], "properties": {
                    "kind": {"enum": SOURCE_KINDS}, "feeds": {"type": "array", "items": S, "maxItems": 50},
                    "ioc_count": {"type": "integer", "minimum": 0}}}}},
            "options": {"type": "object", "additionalProperties": False, "properties": opt_props},
            "iocs": {"type": "array", "items": ioc, "maxItems": MAX_IOCS},
            "stages": {"type": "array", "items": stage, "minItems": 1, "maxItems": MAX_STAGES},
            "expect": {"type": "array", "items": {"type": "object", "additionalProperties": False,
                                                  "required": ["technique"],
                                                  "properties": {"technique": {"type": "string", "pattern": r"^T\d{4}(\.\d{3})?$"},
                                                                 "stage": S, "detection": S,
                                                                 "cve": {"type": "string", "pattern": r"^CVE-\d{4}-\d{4,7}$"}}}},
            "explain": {"type": "array", "items": {"type": "string", "maxLength": 1000}, "description":
                        "compiler notes: skipped actions, unsupported indicators"},
        },
        "$comment": "At most %d actions in total across stages. The validator also checks action params, endpoint "
                    "references and technique ids." % MAX_ACTIONS,
    }


SCHEMA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "campaign.schema.json")


def write_json_schema(path=SCHEMA_FILE):
    with open(path, "w", encoding="utf-8") as f:
        f.write(dump(json_schema()))
    return path


if __name__ == "__main__":
    print(write_json_schema())
