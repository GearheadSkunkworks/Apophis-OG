"""
OpenGenerator -- HTTP API for the Campaign Builder (M2).

Plain functions that take parsed JSON and return ``(status, dict)`` so they can be unit-tested
without a socket; ``server.py`` only does the routing (``route_get`` / ``route_post``).

What this layer does: lets the browser fetch and parse threat-indicator lists, compile them into a
campaign file, edit/validate/estimate it, keep a small on-disk library, and hand the campaign to
the existing generator. It drives the existing engine (``intel.*``, ``netgen.campaign.*``) and adds
nothing to what the engine puts on the wire.

Rules every handler follows:
  * hostile input: types are checked, sizes are capped (413), the engine's ValueError /
    CampaignError becomes a 400 with a plain sentence (no traceback, no file path);
  * an API key sent to /api/intel/fetch is handed to ``intel.sources.fetch`` and dropped: it is
    never stored, logged, or echoed (error text is scrubbed of it);
  * library ids are slugs ``[a-z0-9_-]{1,64}`` only, so no path can be built from user input.
"""
import ipaddress
import json
import os
import re
import tempfile
import threading
import time
from urllib.parse import parse_qs

BODY_CAP = 2 * 1024 * 1024            # any request body
TEXT_CAP = 1024 * 1024                # pasted indicator text
FILE_CAP = 5 * 1024 * 1024            # one library file
MAX_CAMPAIGNS_PER_RUN = 4
MAX_DEPTH = 24                        # JSON nesting
MAX_NODES = 400000                    # values in one body
MAX_STR = 2 * 1024 * 1024             # one string
MAX_IOCS = 20000                      # indicators in one compile
MAX_QUERY = 4096                      # GET query string
SLUG = re.compile(r"[a-z0-9_-]{1,64}")
LIB_SUFFIX = ".campaign.json"

STATIC_FILES = {                      # exact-name allow-list for GET /ui/<name>
    "campaigns.js": "text/javascript; charset=utf-8",
    "campaigns-editor.js": "text/javascript; charset=utf-8",
    "campaigns-library.js": "text/javascript; charset=utf-8",
    "campaigns.css": "text/css; charset=utf-8",
    "campaigns-sensor.js": "text/javascript; charset=utf-8",
    "campaigns-sensor.css": "text/css; charset=utf-8",
    "campaigns-board.js": "text/javascript; charset=utf-8",
    "campaigns-board.css": "text/css; charset=utf-8",
    "theme.css": "text/css; charset=utf-8",          # colour tokens shared by the app, diagrams and About
    "app.css": "text/css; charset=utf-8",            # shell and component styles of the main page
    "gearhead-mark.png": "image/png",                          # the brand mark, used as a mask by theme.css
    "explainer.js": "text/javascript; charset=utf-8",         # animated explainer and zone map
    "timeline.js": "text/javascript; charset=utf-8",          # capture-day timeline
    "build-options.js": "text/javascript; charset=utf-8",     # Compose: network options and exports, from the table below
    "slice-preview.js": "text/javascript; charset=utf-8",     # Captures: what a slice will hold, from the manifest
    "build-options.json": "application/json; charset=utf-8",  # the options table: one row per opt-in build option
    "help.js": "text/javascript; charset=utf-8",              # in-app Help: search and article view
    "help.css": "text/css; charset=utf-8",
    "help-articles.json": "application/json; charset=utf-8",  # the how-to articles
    "scenario-cards.js": "text/javascript; charset=utf-8",   # category rail, chooser tools and scenario cards
    "scenario-cards.css": "text/css; charset=utf-8",
    "geo-world.json": "application/json; charset=utf-8",
    "source-sans-3-400.woff2": "font/woff2",
    "source-sans-3-700.woff2": "font/woff2",
    "source-sans-3-900.woff2": "font/woff2",
    "ibm-plex-sans-400.woff2": "font/woff2",
    "ibm-plex-sans-500.woff2": "font/woff2",
    "ibm-plex-sans-600.woff2": "font/woff2",
    "ibm-plex-sans-700.woff2": "font/woff2",
    "ibm-plex-mono-400.woff2": "font/woff2",
    "ibm-plex-mono-500.woff2": "font/woff2",
    "IBM-Plex-OFL.txt": "text/plain; charset=utf-8",
    "Source-Sans-OFL.txt": "text/plain; charset=utf-8",
}

# Which indicator roles each feed is expected to supply (display hint for the feed browser).
_FEED_ROLES = {
    "circl": ["c2", "payload", "exfil", "phishing"],
    "otx": ["c2", "payload", "exfil", "phishing"], "url": [], "threatfox": ["c2", "payload"],
    "urlhaus": ["payload"],
    "c2intel-ip": ["c2"], "c2intel-domain": ["c2"], "siberkapan": ["c2", "payload", "exfil", "phishing"], "infoblox": ["c2", "payload", "exfil", "phishing"],
    "honeynet-ssh": ["brute"],
    "honeynet-telnet": ["brute"], "honeynet-urls": ["payload"], "cert-pl": ["phishing"],
    "blocklist-ssh": ["brute"], "blocklist-login": ["brute"], "blocklist-mail": ["brute"],
    "tor-exit": ["tor"], "cins-army": ["scanner"], "ipsum": ["scanner"], "openphish": ["phishing"], "cisa-kev": ["cve"],
}

_LIB_LOCK = threading.Lock()
_BENCHMARK_NET = ipaddress.ip_network("198.18.0.0/15")


class ApiError(Exception):
    """Raised inside handlers; carries the HTTP status and the plain sentence for the client."""

    def __init__(self, status, message, **extra):
        super().__init__(message)
        self.status = status
        self.message = message
        self.extra = extra


# ---------------------------------------------------------------- small helpers
def _plain(text, secrets=()):
    """One short sentence safe to show: secrets and absolute paths removed, control characters gone."""
    s = str(text)
    for sec in secrets:
        if sec:
            s = s.replace(sec, "***")
    s = re.sub(r"(?:/[\w.\-@+ ]+){2,}", "<path>", s)
    s = re.sub(r"[\x00-\x1f\x7f]+", " ", s).strip()
    return s[:300] or "the request could not be completed"


def _need_obj(data, what="request body"):
    if not isinstance(data, dict):
        raise ApiError(400, "the %s must be a JSON object" % what)
    return data


def check_shape(obj):
    """Refuse bodies that are deeply nested, huge in count, or hold an oversized string. Iterative."""
    stack, nodes = [(obj, 1)], 0
    while stack:
        v, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise ApiError(413, "the request holds too many values")
        if depth > MAX_DEPTH:
            raise ApiError(400, "the request is nested too deeply")
        if isinstance(v, str):
            if len(v) > MAX_STR:
                raise ApiError(413, "a value in the request is too long")
        elif isinstance(v, dict):
            for k, x in v.items():
                if isinstance(k, str) and len(k) > 1024:
                    raise ApiError(400, "a field name in the request is too long")
                stack.append((x, depth + 1))
        elif isinstance(v, list):
            stack.extend((x, depth + 1) for x in v)


def _json_safe(obj):
    return json.loads(json.dumps(obj, default=str))


def _engine():
    """Import the campaign engine lazily so a broken engine reports cleanly instead of killing the server."""
    try:
        from netgen.campaign import actions, attack, schema, compiler, runner
        from intel import parsers, filters, sources
    except Exception as e:                                            # noqa: BLE001 - engine import failure is re-raised as a 503 ApiError
        raise ApiError(503, "The campaign engine is not available on this machine (%s)."
                       % type(e).__name__) from None
    return actions, attack, schema, compiler, runner, parsers, filters, sources


def _dropped_rows(dropped):
    rows = []
    for item in dropped[:2000]:
        try:
            ioc, reason = item
            rows.append({"value": str(ioc.get("value", ""))[:200], "reason": str(reason)})
        except (TypeError, ValueError, AttributeError):
            continue
    return rows


def _detect_format(text):
    """Best-effort label of what parse_any sniffed: text | csv | stix | misp | otx | threatfox."""
    s = text.lstrip()
    if s[:1] in "{[":
        try:
            d = json.loads(text)
        except (ValueError, RecursionError):
            return "text"
        blob = d if isinstance(d, dict) else (d[0] if d and isinstance(d[0], dict) else {})
        if isinstance(blob, dict):
            if blob.get("type") == "bundle" or "objects" in blob:
                return "stix"
            if "Event" in blob or "response" in blob or "Attribute" in blob:
                return "misp"
            if "results" in blob and any(k in blob for k in ("count", "next", "previous")):
                return "otx"
            if "ioc_value" in blob or "data" in blob and "query_status" in blob:
                return "threatfox"
        return "text"
    head = "\n".join(text.splitlines()[:30]).lower()
    if "ioc_value" in head and "threat_type" in head:
        return "threatfox"
    first = next((ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith(("#", ";"))), "")
    if first.count(",") >= 1 or first.count("\t") >= 1:
        return "csv"
    return "text"


# ---------------------------------------------------------------- intel endpoints
def intel_feeds():
    *_, sources = _engine()
    feeds = []
    for f in sources.FEEDS.values():
        feeds.append({"id": f.id, "title": f.title, "group": f.group, "url": f.url,
                      "needs_key": bool(f.needs_key), "key_env": f.key_env,
                      "roles": list(_FEED_ROLES.get(f.id, [])), "why": f.why, "gives": f.gives,
                      "note": " ".join(x for x in (f.why, f.gives) if x) or f.notes or f.terms or ""})
    return 200, {"feeds": feeds}


def intel_fetch(data):
    *_, filters, sources = _engine()
    data = _need_obj(data)
    feed = data.get("feed")
    if not isinstance(feed, str) or not feed or len(feed) > 64:
        raise ApiError(400, "'feed' must be a feed id such as 'urlhaus'")
    if feed not in sources.FEEDS:
        raise ApiError(400, "unknown feed '%s'" % _plain(feed))
    try:
        limit = int(data.get("limit", 50))
        days = int(data.get("days", 0) or 0)
    except (TypeError, ValueError):
        raise ApiError(400, "'limit' and 'days' must be whole numbers") from None
    limit = max(1, min(limit, 5000))
    days = max(0, min(days, 365))
    q = data.get("q", "") or ""
    url = data.get("url", "") or ""
    key = data.get("key", "") or ""
    if data.get("use_stored") is True and not (isinstance(key, str) and key.strip()):
        try:
            import keys_api
            key = keys_api.resolve_key("feed:" + feed, key, True)
        except Exception as e:                                         # noqa: BLE001 -- KeystoreError: safe one-liner
            raise ApiError(400, _plain(e)) from None
    for name, val, cap in (("q", q, 200), ("url", url, 2048), ("key", key, 300)):
        if not isinstance(val, str):
            raise ApiError(400, "'%s' must be a string" % name)
        if len(val) > cap:
            raise ApiError(400, "'%s' is too long" % name)
    offline = data.get("offline", False)
    fresh = data.get("fresh", False)
    if not isinstance(offline, bool) or not isinstance(fresh, bool):
        raise ApiError(400, "'offline' and 'fresh' must be true or false")
    if offline and fresh:
        raise ApiError(400, "'fresh' and 'offline' cannot be combined")
    params = {}
    if q.strip():
        params["q"] = q.strip()
    if url.strip():
        params["url"] = url.strip()
    if days:
        params["days"] = days
    secrets = (key.strip(),)
    try:
        # the key goes straight to fetch() and is not kept anywhere
        iocs = sources.fetch(feed, limit=limit, key=key.strip() or None, offline=offline,
                              fresh=fresh, **params)
        kept, dropped = filters.clean(iocs)
        from intel import describe
        kept, dropped = describe.annotate(kept, dropped)
    except Exception as e:                                            # noqa: BLE001 -- feed failures are shown inline
        name = type(e).__name__
        msg = _plain(e, secrets) if name in ("FeedError", "ValueError") else "the feed request failed (%s)" % name
        return 200, {"iocs": [], "count": 0, "dropped": [], "error": msg}
    finally:
        key = ""
        secrets = ()
    return 200, {"iocs": _json_safe(kept), "count": len(kept), "dropped": _dropped_rows(dropped), "error": None}


def intel_parse(data):
    _a, _t, _s, _c, _r, parsers, filters, _src = _engine()
    data = _need_obj(data)
    text = data.get("text")
    if not isinstance(text, str):
        raise ApiError(400, "'text' must be a string")
    if len(text.encode("utf-8", "replace")) > TEXT_CAP:
        raise ApiError(413, "the pasted text is larger than 1 MB")
    source = data.get("source") or data.get("filename") or "paste"
    if not isinstance(source, str):
        raise ApiError(400, "'source' must be a string")
    source = re.sub(r"[\x00-\x1f\x7f]", "", os.path.basename(source.replace("\\", "/")))[:80] or "paste"
    try:
        iocs = parsers.parse_any(text, source=source)
        kept, dropped = filters.clean(iocs)
        from intel import describe
        kept, dropped = describe.annotate(kept, dropped)
    except ValueError as e:
        raise ApiError(400, _plain(e)) from None
    return 200, {"iocs": _json_safe(kept), "count": len(kept), "dropped": _dropped_rows(dropped),
                 "formats": _detect_format(text), "report": parsers.looks_like_report(text)}


# ---------------------------------------------------------------- catalog endpoints
def campaign_actions():
    actions, attack, *_ = _engine()
    specs = actions.load_all()
    out = []
    for _token, sp in specs.items():
        out.append({"token": sp.token, "title": sp.title, "tactic": sp.tactic,
                    "techniques": list(sp.techniques), "protocols": list(sp.protocols),
                    "summary": sp.summary, "params": _json_safe(sp.params),
                    "src": sp.src, "dst": sp.dst, "needs": list(sp.needs), "ot": bool(sp.ot)})
    out.sort(key=lambda a: (a["tactic"], a["token"]))
    try:
        from netgen.campaign import families as _fam
        fams = [{"id": k, "name": v["name"], "kind": v["kind"], "notes": v.get("notes", "")} for k, v in _fam.FAMILIES.items()]
    except Exception:
        fams = []
    return 200, {"actions": out, "tactics": attack.tactics(), "families": fams}


def campaign_attack(query):
    _a, attack, *_ = _engine()
    q = (query.get("q", [""])[0] if isinstance(query, dict) else "")[:100].strip().lower()
    techs = attack._data()["techniques"]
    rows = []
    for tid in sorted(techs):
        t = techs[tid]
        if not q or q in tid.lower() or q in str(t.get("name", "")).lower():
            tac = list(t.get("tactics") or [])
            rows.append({"id": tid, "name": t["name"], "tactic": tac[0] if tac else None})
            if len(rows) >= 40:
                break
    return 200, {"techniques": rows}


# ---------------------------------------------------------------- campaign endpoints
def _norm_and_validate(campaign):
    """(normalised, errors). Never raises."""
    _a, _t, schema, *_ = _engine()
    try:
        norm = schema.normalise(campaign)
        errs = list(schema.validate(norm))
    except Exception:                                                 # noqa: BLE001 - a malformed campaign is reported to the caller as an error list
        return campaign, ["the campaign could not be read"]
    return norm, [str(e) for e in errs[:200]]


def _goals():
    _engine()                                  # reports a broken engine as a clean 503
    from netgen.campaign import goals
    return goals


def campaign_templates():
    """Goal modes and starter templates (no feed or network needed)."""
    return 200, _goals().catalog()


def campaign_compile(data):
    _a, _t, schema, compiler, *_ = _engine()
    data = _need_obj(data)
    iocs = data.get("iocs")
    if not isinstance(iocs, list) or not all(isinstance(i, dict) for i in iocs):
        raise ApiError(400, "'iocs' must be a list of indicator objects")
    if len(iocs) > MAX_IOCS:
        raise ApiError(400, "'iocs' can hold at most %d indicators" % MAX_IOCS)
    options = data.get("options")
    if options is not None and not isinstance(options, dict):
        raise ApiError(400, "'options' must be an object")
    name = data.get("name") or None
    if name is not None and (not isinstance(name, str) or len(name) > 200):
        raise ApiError(400, "'name' must be a string of at most 200 characters")
    goal = data.get("goal")
    if goal:
        try:
            options = dict(_goals().goal_options(goal), **(options or {}))     # explicit options win over the goal
        except (TypeError, ValueError):
            raise ApiError(400, "unknown goal '%s'" % _plain(goal)) from None
    try:
        camp = compiler.compile_campaign(iocs, options=options, name=name)
        explain = compiler.explain_campaign(camp)
    except ValueError as e:                    # includes CampaignError
        errors = getattr(e, "errors", None) or [str(e)]
        raise ApiError(400, _plain(errors[0]), errors=[_plain(x) for x in errors[:50]]) from None
    errs = [str(e) for e in schema.validate(camp)[:200]]
    stages = camp.get("stages") or []
    summary = {"stages": len(stages), "actions": sum(len(s.get("actions") or []) for s in stages),
               "iocs": len(camp.get("iocs") or []),
               "skipped": max(0, len(iocs) - len(camp.get("iocs") or []))}
    return 200, {"campaign": _json_safe(camp), "explain": [str(x) for x in explain],
                 "errors": errs, "summary": summary,
                 "observability": _json_safe(compiler.observability(camp))}


def campaign_observability(data):
    """Evaluate, per indicator, whether it is expected to produce observable traffic.

    Takes the same {iocs, options} the compile step takes, compiles them (pure: no engine run, no
    state change), and returns the engine's per-indicator verdict. The indicator selector calls this
    as the builder edits roles/options so each indicator can show whether it will appear on the wire
    -- e.g. a vulnerability (CVE) or a bare hash never does on its own; the exploitation/delivery that
    uses it does. The verdict is the compiler's own `used` relation, so it never drifts from output."""
    _a, _t, schema, compiler, *_ = _engine()
    data = _need_obj(data)
    iocs = data.get("iocs")
    if not isinstance(iocs, list) or not all(isinstance(i, dict) for i in iocs):
        raise ApiError(400, "'iocs' must be a list of indicator objects")
    if len(iocs) > MAX_IOCS:
        raise ApiError(400, "'iocs' can hold at most %d indicators" % MAX_IOCS)
    options = data.get("options")
    if options is not None and not isinstance(options, dict):
        raise ApiError(400, "'options' must be an object")
    try:
        camp = compiler.compile_campaign(iocs, options=options)
    except ValueError as e:                    # includes CampaignError
        errors = getattr(e, "errors", None) or [str(e)]
        raise ApiError(400, _plain(errors[0]), errors=[_plain(x) for x in errors[:50]]) from None
    rows = compiler.observability(camp)
    plan = [{"name": st.get("name"), "narrative": st.get("narrative", ""), "actions": len(st.get("actions") or [])}
            for st in camp.get("stages", [])]
    return 200, {"observability": _json_safe(rows), "plan": _json_safe(plan),
                 "observable": sum(1 for r in rows if r.get("observable")), "total": len(rows)}


def campaign_preview(data):
    """What one indicator alone will put on the wire: compile it by itself (no optional stages) and list the
    actions that used it, from the compiler's own output so the preview cannot drift from the capture."""
    actions, _t, _s, compiler, *_ = _engine()
    data = _need_obj(data)
    ioc = data.get("ioc")
    if not isinstance(ioc, dict):
        raise ApiError(400, "'ioc' must be an indicator object")
    opts = dict(data.get("options") if isinstance(data.get("options"), dict) else {}, include=[])
    try:
        camp = compiler.compile_campaign([ioc], options=opts)
    except ValueError as e:
        raise ApiError(400, _plain((getattr(e, "errors", None) or [str(e)])[0])) from None
    actions.load_all()
    rows = []
    for st in camp.get("stages", []):
        for a in st.get("actions", []):
            if 0 in a.get("ioc", []):
                sp = actions.get(a["action"])
                rows.append({"stage": st.get("name"), "action": a["action"], "title": sp.title if sp else a["action"],
                             "protocols": list(sp.protocols) if sp else [], "summary": sp.summary if sp else "",
                             "from": a["from"], "to": a["to"], "explain": a.get("explain", "")})
    return 200, {"actions": _json_safe(rows), "observable": bool(rows)}


def campaign_validate(data):
    data = _need_obj(data)
    if "campaign" not in data:
        raise ApiError(400, "'campaign' is required")
    norm, errs = _norm_and_validate(data["campaign"])
    return 200, {"errors": errs, "campaign": None if errs else _json_safe(norm)}


MAX_SCALE = 1.0          # the build route and the UI never go above 1; a token holder must not queue a bigger run under BUILD_LOCK


def campaign_estimate(data):
    _a, _t, _s, _c, runner, *_ = _engine()
    data = _need_obj(data)
    if "campaign" not in data:
        raise ApiError(400, "'campaign' is required")
    try:
        scale = float(data.get("scale", 1.0))
    except (TypeError, ValueError):
        raise ApiError(400, "'scale' must be a number") from None
    if not (0 < scale <= MAX_SCALE):                                   # also rejects NaN; the UI's own size limit is 1
        raise ApiError(400, "'scale' must be greater than 0 and at most %g" % MAX_SCALE)
    norm, errs = _norm_and_validate(data["campaign"])
    try:
        est = runner.estimate(norm, scale)
    except Exception:                                                 # noqa: BLE001 - estimate failure falls back to a zeroed estimate
        est = {"stages": 0, "actions": 0, "flows": 0, "scale": scale,
               "minutes_realistic": 0.0, "minutes_fast": 0.0}
    est = dict(_json_safe(est))
    est["errors"] = errs
    return 200, est


# server.py installs this: a function (campaign, scale, nets) -> (report, totals) that runs the
# campaign through the engine under the build lock. It lives in server.py because the engine and
# BUILD_LOCK do; this layer only validates and packages. None until the engine is available.
RUN_CAMPAIGN = None


def set_run_campaign(fn):
    """Install the engine hook that runs a campaign preview. The server calls this once at start-up,
    so this layer needs no engine or lock of its own."""
    global RUN_CAMPAIGN
    RUN_CAMPAIGN = fn


def campaign_run(data):
    """POST /api/campaign/run — run ONE campaign through the engine (campaign-only, no baseline,
    no file) and return its real records plus its exact packet/byte contribution to a capture.
    Feeds the board preview and the capture-size estimate; injects no packets and writes nothing."""
    data = _need_obj(data)
    if "campaign" not in data:
        raise ApiError(400, "'campaign' is required")
    if RUN_CAMPAIGN is None:
        raise ApiError(503, "the generator engine is not available on this machine")
    try:
        scale = float(data.get("scale", 1.0))
    except (TypeError, ValueError):
        raise ApiError(400, "'scale' must be a number") from None
    if not (0 < scale <= MAX_SCALE):                                   # also rejects NaN; the UI's own size limit is 1
        raise ApiError(400, "'scale' must be greater than 0 and at most %g" % MAX_SCALE)
    norm, errs = _norm_and_validate(data["campaign"])
    if errs:                                                          # the UI only reads `errors` from /estimate and /check
        raise ApiError(400, _plain(errs[0]), errors=[_plain(x) for x in errs[:50]])
    nets = {k: (data.get(k + "_net") or None) for k in ("user", "server")}
    nets["ot"] = data.get("ot_nets") or None
    report, totals = RUN_CAMPAIGN(norm, scale, nets)
    by = int(totals.get("bytes", 0))
    return 200, {"run": _json_safe(report), "errors": errs,
                 "packets": int(totals.get("packets", 0)), "bytes": by, "mb": by / 1e6}


# ---------------------------------------------------------------- library
def library_dir(create=True):
    base = os.environ.get("OPENGENERATOR_CAMPAIGNS") or os.path.join(
        os.path.expanduser("~"), "Documents", "OpenGenerator", "Campaigns")
    base = os.path.abspath(os.path.expanduser(base))
    if create:
        try:
            os.makedirs(base, mode=0o700, exist_ok=True)
            os.chmod(base, 0o700)
        except OSError:
            raise ApiError(500, "the campaign library folder could not be created") from None
    return base


def _slug_or_400(value):
    if not isinstance(value, str) or not SLUG.fullmatch(value):
        raise ApiError(400, "a campaign id must be 1-64 characters of a-z, 0-9, '-' or '_'")
    return value


def _file_for(cid, create_dir=True):
    return os.path.join(library_dir(create_dir), cid + LIB_SUFFIX)


def _slugify(text):
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-_")[:64].strip("-_")


def _iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))


def library_list():
    base = library_dir()
    rows = []
    try:
        names = os.listdir(base)
    except OSError:
        names = []
    for fn in names:
        if not fn.endswith(LIB_SUFFIX) or not SLUG.fullmatch(fn[:-len(LIB_SUFFIX)]):
            continue
        path = os.path.join(base, fn)
        try:
            st = os.lstat(path)
            if not os.path.isfile(path) or os.path.islink(path) or st.st_size > FILE_CAP:
                continue
            with open(path, "rb") as f:
                doc = json.loads(f.read(FILE_CAP + 1).decode("utf-8-sig"))
            meta = doc.get("meta") or {}
            rows.append({"id": fn[:-len(LIB_SUFFIX)], "name": str(meta.get("name", ""))[:200],
                         "description": str(meta.get("description", ""))[:500],
                         "stages": len(doc.get("stages") or []), "iocs": len(doc.get("iocs") or []),
                         "modified": _iso(st.st_mtime), "size": st.st_size, "_t": st.st_mtime})
        except (OSError, ValueError, AttributeError, RecursionError):
            continue
    rows.sort(key=lambda r: r["_t"], reverse=True)
    for r in rows:
        del r["_t"]
    return 200, {"dir": base, "campaigns": rows}


def library_save(data):
    _a, _t, schema, *_ = _engine()
    data = _need_obj(data)
    if "campaign" not in data:
        raise ApiError(400, "'campaign' is required")
    norm, errs = _norm_and_validate(data["campaign"])
    if errs:
        raise ApiError(400, "the campaign is not valid: " + _plain(errs[0]), errors=errs[:50])
    meta = norm.get("meta") or {}
    cid = meta.get("id") if isinstance(meta.get("id"), str) and SLUG.fullmatch(meta.get("id", "")) else None
    cid = cid or _slugify(meta.get("name", "")) or None
    if not cid:
        raise ApiError(400, "the campaign needs a name so it can be saved")
    norm["meta"]["id"] = cid
    text = schema.dump(norm)
    if len(text.encode("utf-8")) > FILE_CAP:
        raise ApiError(413, "the campaign is larger than 5 MB")
    overwrite = data.get("overwrite", False) is True
    base = library_dir()
    path = os.path.join(base, cid + LIB_SUFFIX)
    with _LIB_LOCK:
        if os.path.lexists(path) and not overwrite:
            raise ApiError(409, "a saved campaign with this id already exists; "
                                "choose another name or confirm overwrite")
        fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".part", dir=base)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise ApiError(500, "the campaign could not be written to the library folder") from None
    return 200, {"id": cid, "path": path}


def _read_saved(cid):
    _a, _t, schema, *_ = _engine()
    path = _file_for(_slug_or_400(cid), create_dir=False)
    try:
        if os.path.islink(path) or not os.path.isfile(path):
            raise FileNotFoundError
        if os.path.getsize(path) > FILE_CAP:
            raise ApiError(413, "that saved campaign is larger than 5 MB")
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        raise ApiError(404, "no saved campaign with that id") from None
    return raw, schema


def library_load(data):
    data = _need_obj(data)
    raw, schema = _read_saved(data.get("id"))
    try:
        camp = schema.load(raw)
    except ValueError as e:
        errors = getattr(e, "errors", None) or [str(e)]
        raise ApiError(400, "the saved campaign is not valid: " + _plain(errors[0])) from None
    return 200, {"campaign": _json_safe(camp)}


def library_delete(data):
    data = _need_obj(data)
    cid = _slug_or_400(data.get("id"))
    path = _file_for(cid, create_dir=False)
    with _LIB_LOCK:
        try:
            if os.path.isdir(path):
                raise OSError
            os.remove(path)
        except OSError:
            raise ApiError(404, "no saved campaign with that id") from None
    return 200, {"ok": True}


def library_import(data):
    _a, _t, schema, *_ = _engine()
    data = _need_obj(data)
    text = data.get("text")
    if not isinstance(text, str):
        raise ApiError(400, "'text' must be a string holding the campaign JSON")
    if len(text.encode("utf-8", "replace")) > BODY_CAP:
        raise ApiError(413, "the campaign text is larger than 2 MB")
    if not text.lstrip().startswith("{"):
        return 200, {"campaign": None, "id": None, "errors": ["a campaign file is a JSON object"]}
    try:
        camp = schema.load(text)
    except ValueError as e:
        errors = getattr(e, "errors", None) or [str(e)]
        return 200, {"campaign": None, "id": None, "errors": [_plain(x) for x in errors[:50]]}
    return 200, {"campaign": _json_safe(camp), "id": None, "errors": []}


def library_export(query):
    """(status, bytes, content_type, extra_headers) for GET /campaign/export?id=."""
    cid = (query.get("id") or [""])[0]
    try:
        raw, _schema = _read_saved(cid)
    except ApiError as e:
        return e.status, json.dumps({"error": e.message}).encode(), "application/json", {}
    return 200, raw, "application/json", {
        "Content-Disposition": 'attachment; filename="%s%s"' % (cid, LIB_SUFFIX)}


# ---------------------------------------------------------------- generate (extra fields)
def parse_generate_extras(data):
    """Validate the campaign fields of a POST /api/generate body BEFORE any thread starts.

    Returns (campaigns, address_mode, confirm). Raises ApiError(400, ..., errors=[...]).
    No campaign fields -> ([], None, False), i.e. the request behaves exactly as before."""
    raw = data.get("campaigns")
    mode = data.get("address_mode")
    confirm = data.get("confirm_real_addresses", False)
    if raw is None and mode is None and not confirm:
        return [], None, False
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise ApiError(400, "'campaigns' must be a list of campaign objects")
    if len(raw) > MAX_CAMPAIGNS_PER_RUN:
        raise ApiError(400, "at most %d campaigns can be run in one capture" % MAX_CAMPAIGNS_PER_RUN)
    if mode is not None and mode not in ("mapped", "real"):
        raise ApiError(400, "'address_mode' must be 'mapped' or 'real'")
    if not isinstance(confirm, bool):
        raise ApiError(400, "'confirm_real_addresses' must be true or false")
    campaigns, all_errors = [], []
    for n, c in enumerate(raw, 1):
        if not isinstance(c, dict):
            all_errors.append("campaign %d: must be a JSON object" % n)
            continue
        norm, errs = _norm_and_validate(c)
        if errs:
            all_errors += ["campaign %d: %s" % (n, e) for e in errs]
        else:
            campaigns.append(norm)
    if all_errors:
        raise ApiError(400, "the campaign is not valid: " + _plain(all_errors[0]), errors=all_errors[:100])
    if campaigns:
        real = mode == "real" or (mode is None and any(
            (c.get("options") or {}).get("address_mode") == "real" for c in campaigns))
        if real and not confirm:
            raise ApiError(400, "real address mode puts real indicator addresses in the packets; "
                                "confirm it by sending confirm_real_addresses true")
    return campaigns, mode, confirm


def status_extras(summary):
    """Fields to add to /api/status when a campaign ran, else {} (existing fields untouched)."""
    if not isinstance(summary, dict) or "campaign" not in summary:
        return {}
    camp = dict(summary.get("campaign") or {})
    camp["console"] = list(summary.get("campaign_console") or [])
    return {"campaign": camp}



# ---------------------------------------------------------------- campaign diagram (M4b)
def campaign_diagram(data):
    """POST /api/campaign/diagram {campaign, summary?, score?, company?} -> {"html": page}. The page is a static
    HTML+SVG document (no scripts); the GUI opens it in a new tab from a Blob URL."""
    data = _need_obj(data)
    camp = data.get("campaign")
    if not isinstance(camp, (dict, list)):
        raise ApiError(400, "'campaign' must be a campaign object (or a list of them)")
    for k in ("summary", "score"):
        if data.get(k) is not None and not isinstance(data.get(k), dict):
            raise ApiError(400, "'%s' must be an object" % k)
    company = data.get("company")
    if company is not None and (not isinstance(company, str) or len(company) > 80):
        raise ApiError(400, "'company' must be a short string")
    try:
        from diagrams.campaign import api as _dapi
        html = _dapi.campaign_diagram(data)
    except ValueError as e:
        raise ApiError(400, _plain(e)) from None
    except ImportError:
        raise ApiError(503, "the diagram engine is not available in this build") from None
    return 200, {"html": html}

# ---------------------------------------------------------------- static files
def static_file(name, ui_dir):
    """(status, bytes, content_type, headers) for GET /ui/<name>; allow-list only."""
    ctype = STATIC_FILES.get(name) if isinstance(name, str) else None
    if ctype is None:
        return 404, b"not found", "text/plain", {}
    try:
        with open(os.path.join(ui_dir, name), "rb") as f:
            body = f.read()
    except OSError:
        return 404, b"not found", "text/plain", {}
    return 200, body, ctype, {"Cache-Control": "no-cache"}


# ---------------------------------------------------------------- sensor feedback (M4)
FEEDBACK_CAP = 5000                   # entries / expectations / indicators accepted per request
GEO_CAP = 500


def _provider(sensor, key):
    """The sensor provider bound to (sensor, key); one place to patch in tests."""
    from sensorops import providers
    return providers.get_provider(sensor, key)


def _sensor_target(data):
    """The validated sensor address and key from a request body, else ApiError 400."""
    import socket
    from sensorops._util import valid_sensor
    sensor, key = data.get("sensor"), data.get("key")
    if not isinstance(sensor, str) or not sensor.strip() or len(sensor) > 255:
        raise ApiError(400, "'sensor' must be a host name or address with an optional port")
    if data.get("use_stored") is True and not (isinstance(key, str) and key.strip()):
        try:
            import keys_api
            key = keys_api.resolve_key("sensor:" + sensor.strip().lower(), key, True)
        except Exception as e:                                         # noqa: BLE001 -- KeystoreError: safe one-liner
            raise ApiError(400, _plain(e)) from None
    if not isinstance(key, str) or not key.strip():
        raise ApiError(400, "'key' must be the sensor's API key")
    if len(key) > 300:
        raise ApiError(400, "'key' is too long")
    try:
        sensor = valid_sensor(sensor)
    except ValueError as e:
        raise ApiError(400, _plain(e)) from None
    host = re.sub(r":\d{1,5}$", "", sensor) if not sensor.startswith("[") else sensor.rsplit("]", 1)[0][1:]
    bad = host.lower() == "localhost" or host.lower().endswith(".localhost")
    if not bad:
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            try:                                  # short or numeric spellings such as 127.1 or 2130706433
                addr = ipaddress.ip_address(socket.inet_aton(host))
            except (OSError, ValueError):
                addr = None
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        bad = addr is not None and (addr.is_loopback or addr.is_link_local or addr.is_unspecified)
    if not bad:
        # A name that RESOLVES to loopback / link-local is refused too. A name that does not resolve
        # here is let through (the provider reports it); the provider resolves again and connects to
        # the address it validated, so a later DNS change cannot redirect the request.
        from sensorops._util import resolve_sensor
        try:
            resolve_sensor(sensor)
        except ValueError:
            bad = True
        except LookupError:
            pass
    if bad:
        raise ApiError(400, "that sensor address is a loopback or link-local address; "
                            "use the address the sensor's management interface answers on")
    return sensor.strip(), key.strip()


def sensor_check(data):
    data = _need_obj(data)
    sensor, key = _sensor_target(data)
    secrets = (key,)
    prov = None
    try:
        prov = _provider(sensor, key)
        ident = prov.identity()
    except Exception as e:                                            # noqa: BLE001 -- shown inline
        try:
            msg = _plain(prov.explain(e) if prov else e, secrets)
        except Exception:                                             # noqa: BLE001 - failure is returned as a plain-language error reply
            msg = _plain(type(e).__name__)
        return 200, {"ok": False, "error": msg}
    finally:
        key = ""
        secrets = ()
    if not isinstance(ident, dict):
        return 200, {"ok": False, "error": "the address answered, but not like a sensor; "
                                           "check the address and the API key"}
    return 200, {"ok": True, "identity": {k: _plain(ident.get(k, "?")) for k in
                                          ("hostname", "platform", "version")}}


def _num_field(data, name, default, lo, hi):
    v = data.get(name, default)
    if v is None:
        v = default
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v:
        raise ApiError(400, "'%s' must be a number" % name)
    if not lo <= v <= hi:
        raise ApiError(400, "'%s' must be between %s and %s" % (name, lo, hi))
    return v


def campaign_feedback(data):
    from sensorops import feedback
    data = _need_obj(data)
    sensor, key = _sensor_target(data)
    lists = {}
    for name in ("entries", "iocs", "expect", "stages"):
        v = data.get(name, [])
        if not isinstance(v, list) or len(v) > FEEDBACK_CAP:
            raise ApiError(400, "'%s' must be a list of at most %d items" % (name, FEEDBACK_CAP))
        lists[name] = v
    offset = _num_field(data, "offset_s", 0, -7.0e8, 7.0e8)
    slack = _num_field(data, "slack_s", 600, 0, 86400)
    look = _num_field(data, "lookahead_s", 1800, 0, 7 * 86400)
    min_risk = _num_field(data, "min_risk", 0, 0, 100)
    win = feedback.query_window(lists["entries"], offset, slack, look)
    if win is None:
        return 200, {"ok": False, "error": "no action in this report ran with a time, so there is "
                                           "nothing to look for on the sensor"}
    secrets = (key,)
    try:
        prov = _provider(sensor, key)
        try:
            raw = prov.list_detections(win[0], win[1])
        except Exception as e:                                        # noqa: BLE001 -- shown inline
            if isinstance(e, NotImplementedError):
                return 200, {"ok": False, "error": "this sensor type cannot list detections"}
            return 200, {"ok": False, "error": _plain(prov.explain(e), secrets)}
    except Exception as e:                                            # noqa: BLE001 - failure is returned as a scrubbed error reply, secrets removed
        return 200, {"ok": False, "error": _plain(e, secrets)}
    finally:
        key = ""
        secrets = ()
    body = feedback.score(lists["entries"], lists["iocs"], lists["expect"], lists["stages"], raw,
                          offset_s=offset, slack_s=slack, min_risk=min_risk)
    import time as _time
    out = {"ok": True, "window": {"from_ms": win[0], "until_ms": win[1]},
           "scored_against": {"sensor": sensor, "time": _time.strftime("%Y-%m-%d %H:%M", _time.localtime())}}
    out.update(body)
    return 200, _json_safe(out)


def geo_lookup(data):
    data = _need_obj(data)
    ips = data.get("ips")
    if not isinstance(ips, list) or len(ips) > GEO_CAP:
        raise ApiError(400, "'ips' must be a list of at most %d addresses" % GEO_CAP)
    if not all(isinstance(i, str) and len(i) <= 64 for i in ips):
        raise ApiError(400, "'ips' must contain only address strings")
    results, ask = {}, []
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip.strip())
        except ValueError:
            results[ip] = None
            continue
        results[ip] = None
        if a.is_global and not a.is_multicast and not (a.version == 4 and a in _BENCHMARK_NET):
            ask.append((ip, str(a)))
    if not ask:
        return 200, {"results": results}
    try:
        import geo
        found = geo.lookup_many([a for _ip, a in ask])
    except Exception as e:                                            # noqa: BLE001 - lookup failure is reported as a plain-language message
        why = "the geography data is not installed" if isinstance(e, (ImportError, AttributeError)) \
            else "the geography lookup failed (%s)" % type(e).__name__
        return 200, {"results": results, "error": why}
    found = found if isinstance(found, dict) else {}
    for ip, norm in ask:
        r = found.get(norm, found.get(ip))
        if isinstance(r, dict) and r.get("cc"):
            results[ip] = {"cc": r.get("cc"), "country": r.get("country"),
                           "lat": r.get("lat"), "lon": r.get("lon")}
    return 200, {"results": results}


# ---------------------------------------------------------------- routing used by server.py
_POST = {
    "/api/intel/fetch": intel_fetch,
    "/api/intel/parse": intel_parse,
    "/api/campaign/compile": campaign_compile,
    "/api/campaign/observability": campaign_observability,
    "/api/campaign/preview": campaign_preview,
    "/api/campaign/validate": campaign_validate,
    "/api/campaign/estimate": campaign_estimate,
    "/api/campaign/run": campaign_run,
    "/api/campaign/library/save": library_save,
    "/api/campaign/library/load": library_load,
    "/api/campaign/library/delete": library_delete,
    "/api/campaign/library/import": library_import,
    "/api/sensor/check": sensor_check,
    "/api/campaign/diagram": campaign_diagram,
    "/api/campaign/feedback": campaign_feedback,
    "/api/geo/lookup": geo_lookup,
}
_GET = {
    "/api/intel/feeds": lambda q: intel_feeds(),
    "/api/campaign/actions": lambda q: campaign_actions(),
    "/api/campaign/templates": lambda q: campaign_templates(),
    "/api/campaign/attack": campaign_attack,
    "/api/campaign/library": lambda q: library_list(),
}


def _json_reply(status, obj):
    return status, json.dumps(obj).encode(), "application/json", {}


def route_get(path, query_string, ui_dir):
    """None if the path is not ours, else (status, body_bytes, content_type, headers)."""
    try:
        if len(query_string or "") > MAX_QUERY:
            raise ApiError(414, "the request address is too long")
        if path.startswith("/ui/"):
            return static_file(path[4:], ui_dir)
        if path == "/campaign/export":
            return library_export(parse_qs(query_string, keep_blank_values=True))
        fn = _GET.get(path)
        if fn is None:
            return None
        status, obj = fn(parse_qs(query_string, keep_blank_values=True))
        return _json_reply(status, obj)
    except ApiError as e:
        return _json_reply(e.status, dict(e.extra, error=e.message))
    except Exception:                                                 # noqa: BLE001 -- never raise to the socket
        return _json_reply(500, {"error": "the request could not be completed"})


def _keys_routes():
    try:
        import keys_api
        return dict(keys_api.ROUTES)
    except Exception:                                                  # noqa: BLE001 -- optional module
        return {}


def route_post(path, data, bad_json=False):
    """None if the path is not ours, else (status, body_bytes, content_type, headers)."""
    fn = _POST.get(path) or _keys_routes().get(path)
    if fn is None:
        return None
    try:
        if bad_json:
            raise ApiError(400, "the request body is not valid JSON")
        check_shape(data)
        status, obj = fn(data)
        return _json_reply(status, obj)
    except ApiError as e:
        return _json_reply(e.status, dict(e.extra, error=e.message))
    except Exception:                                                 # noqa: BLE001 - last-resort handler returns a generic 500 reply
        return _json_reply(500, {"error": "the request could not be completed"})
