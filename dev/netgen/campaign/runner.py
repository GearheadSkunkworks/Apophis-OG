"""The `campaign` scenario: place a campaign's stages and actions on the capture day.

What it does on the wire: nothing by itself. Each action registered in netgen.campaign.actions
builds real packets (TLS beacons, DNS, scans, authentication, transfers ...); the runner only
decides WHEN and between WHICH hosts, and records what each action actually emitted in
``ctx.campaign_report`` so the console, STIX bundle, Navigator layer and report can be derived
from the capture instead of from the plan.

Inert when no campaign is supplied (``ctx.campaigns`` empty), so the baseline never moves.
Randomness is the engine's reseeded generator (netgen.flows.rng) only.
"""
from .. import model
from ..flows import rng            # noqa: F401  (documented: the only random source in this package)
from . import hosts as HOSTS

STAGE_GAP_S = 10.0                 # quiet gap between stages


# ------------------------------------------------------------------ helpers
def _options(campaign):
    o = dict(campaign.get("options") or {})
    o.setdefault("address_mode", "mapped")
    o.setdefault("start", "10:00")
    o.setdefault("speed", "realistic")
    return o


def _start_ts(options):
    try:
        hh, mm = str(options.get("start", "10:00")).split(":")[:2]
        return model.local(int(hh), int(mm))
    except (ValueError, TypeError):
        return model.local(10, 0)


def _stage_len(stage, options):
    fast = options.get("speed") == "fast"
    full = float(stage.get("duration_s") or 60)
    if fast:
        return float(stage.get("fast_s") or max(10.0, full / 3)), full
    return full, full


_COUNT_KEYS = ("count", "sessions", "bursts", "attempts", "beacons", "queries")


def estimate(campaign, scale=1.0):
    """Counts and duration for a campaign without building it:
    {"stages", "actions", "flows", "minutes_realistic", "minutes_fast", "scale"}.
    `flows` counts one per action plus repeats where an action has a count-like parameter."""
    stages = campaign.get("stages") or []
    actions = flows = 0
    real = fast = 0.0
    for st in stages:
        real += float(st.get("duration_s") or 60) + STAGE_GAP_S
        fast += float(st.get("fast_s") or max(10.0, float(st.get("duration_s") or 60) / 3)) + STAGE_GAP_S
        for a in st.get("actions") or []:
            actions += 1
            n = 1
            for k in _COUNT_KEYS:
                v = (a.get("params") or {}).get(k)
                if isinstance(v, int) and v > 1:
                    n = v
                    break
            flows += n
    return {"stages": len(stages), "actions": actions, "flows": flows, "scale": scale,
            "minutes_realistic": round(real / 60.0, 1), "minutes_fast": round(fast / 60.0, 1)}


def _validate(campaign):
    """(errors, normalised campaign). Uses campaign.schema when present."""
    try:
        from . import schema
    except ImportError:
        return ["campaign.schema is not available"], campaign
    errs = list(schema.validate(campaign) or [])
    if errs:
        return errs, campaign
    norm = getattr(schema, "normalise", None)
    if norm:
        try:
            out = norm(campaign)
            if isinstance(out, dict):
                campaign = out
        except Exception as e:                                    # noqa: BLE001
            return ["normalise failed: %s" % e], campaign
    return [], campaign


def _ioc_table(campaign):
    rows = []
    for i, ioc in enumerate(campaign.get("iocs") or []):
        row = {"index": i, "type": ioc.get("type"), "value": ioc.get("value"),
               "role": ioc.get("role"), "address": None, "note": ioc.get("note", "")}
        if ioc.get("type") in HOSTS.ADDRESSABLE:
            try:
                row["address"] = HOSTS.address_for(ioc, campaign)
            except Exception as e:                                # noqa: BLE001
                row["address_error"] = str(e)
        rows.append(row)
    return rows


# ------------------------------------------------------------------ the scenario
def campaign_scenario(ctx, eng, tag, win):
    """Schedule every supplied campaign. Never raises for a bad campaign: it is skipped and the
    reason recorded in ``ctx.campaign_report["errors"]``."""
    campaigns = [c for c in (getattr(ctx, "campaigns", None) or []) if c]
    if not campaigns:
        ctx.campaign_report = None
        return
    from . import actions as ACT
    ACT.load_all()
    report = {"campaigns": [], "entries": [], "errors": []}
    ctx.campaign_report = report
    for idx, raw in enumerate(campaigns):
        meta = (raw.get("meta") or {}) if isinstance(raw, dict) else {}
        label = meta.get("id") or meta.get("name") or "campaign-%d" % (idx + 1)
        if not isinstance(raw, dict):
            report["errors"].append({"campaign": label, "error": "not a campaign object"})
            continue
        errs, camp = _validate(raw)
        if errs:
            report["errors"].append({"campaign": label, "error": "invalid campaign", "details": errs})
            continue
        try:
            _schedule_campaign(ctx, eng, tag, camp, label, report, ACT)
        except Exception as e:                                    # noqa: BLE001  never break a build
            report["errors"].append({"campaign": label, "error": "%s: %s" % (type(e).__name__, e)})


def _schedule_campaign(ctx, eng, tag, camp, label, report, ACT):
    from . import addressing
    options = _options(camp)
    camp = dict(camp, options=options)                       # runtime copy; the caller's dict is untouched
    camp["_map"] = addressing.mapped_table(camp.get("iocs") or [], HOSTS._seed(camp))
    if options["address_mode"] == "real":
        for ioc in camp.get("iocs") or []:
            ip, _dom = HOSTS.ioc_host_text(ioc)
            if ip:
                ok, why = addressing.real_mode_check(ip)
                if not ok:
                    raise ValueError("real address mode refused: %s" % why)
    crep = {"id": label, "name": (camp.get("meta") or {}).get("name") or label,
            "meta": camp.get("meta") or {}, "options": options, "stages": [], "entries": [],
            "iocs": _ioc_table(camp), "estimate": estimate(camp), "errors": []}
    for v6 in addressing.unsupported_ipv6(camp.get("iocs") or []):
        crep["errors"].append({"error": "IPv6 indicator %s is carried but not placed in the capture" % v6})
    report["campaigns"].append(crep)

    t = _start_ts(options)
    end_of_day = model.local(21)
    placed = []                         # (ts, entry, spec, src, dst, params)
    for st in camp.get("stages") or []:
        length, full = _stage_len(st, options)
        ratio = length / full if full else 1.0
        crep["stages"].append({"id": st.get("id"), "name": st.get("name"), "tactic": st.get("tactic"),
                               "techniques": list(st.get("techniques") or []),
                               "narrative": st.get("narrative", ""), "start": t, "length_s": length})
        acts = st.get("actions") or []
        n = max(1, len(acts))
        for i, a in enumerate(acts):
            entry = {"campaign": label, "stage": st.get("id"), "stage_name": st.get("name"),
                     "action": a.get("action"), "from": a.get("from"), "to": a.get("to"),
                     "ioc": [], "explain": a.get("explain", ""), "params": dict(a.get("params") or {}),
                     "ts": None, "packets": 0, "bytes": 0, "protocols": [], "techniques": [],
                     "status": "scheduled", "error": None}
            crep["entries"].append(entry)
            report["entries"].append(entry)
            try:
                spec = ACT.get(a.get("action"))
                entry["params"] = dict({k: d.get("default") for k, d in spec.params.items()},
                                       **(a.get("params") or {}))         # effective values, defaults filled
                entry["techniques"] = list(spec.techniques)
                entry["protocols"] = list(spec.protocols)
                missing = [s for s in spec.needs if HOSTS.H(s) not in ctx.h]
                if missing:
                    raise HOSTS.EndpointError("missing host(s) %s" % ", ".join(HOSTS.H(s) for s in missing))
                src, sidx, sext = HOSTS.resolve_endpoint(ctx, a["from"], camp)
                dst, didx, dext = HOSTS.resolve_endpoint(ctx, a["to"], camp)
                for side, want, ext_ in (("from", spec.src, sext), ("to", spec.dst, dext)):
                    if want == "internal" and ext_ or want == "external" and not ext_:
                        raise HOSTS.EndpointError("%s of %s must be %s" % (side, spec.token, want))
                entry["ioc"] = sorted(set(list(a.get("ioc") or []) + sidx + didx))
                entry["from_host"] = {"name": src.name, "ip": src.ip}
                entry["to_host"] = {"name": dst.name, "ip": dst.ip}
                at = a.get("at")
                ts = t + (float(at) * ratio if at is not None else (i / n) * length * 0.9)
                entry["ts"] = ts
                if ts > end_of_day:
                    raise ValueError("falls after the end of the capture day")
                placed.append((ts, entry, spec, src, dst, dict(a.get("params") or {})))
            except Exception as e:                                # noqa: BLE001
                entry["status"] = "skipped"
                entry["error"] = "%s" % e
                crep["errors"].append({"stage": st.get("id"), "action": a.get("action"), "error": str(e)})
        t += length + STAGE_GAP_S

    if not placed:
        return
    lo = min(p[0] for p in placed)
    hi = max(p[0] for p in placed)
    from ..incidents import sched_factory
    sched = sched_factory(eng, ctx, tag, (lo, hi))
    for ts, entry, spec, src, dst, params in placed:
        sched(ts, _wrap(spec.fn, entry), src, dst, **params)


def _wrap(fn, entry):
    """Run the action and record what it emitted. A failing action is recorded, not raised, so
    one bad action cannot abort the whole capture."""
    def run(ctx, src, dst, *, ts, **params):
        try:
            pkts = fn(ctx, src, dst, ts=ts, **params) or []
        except Exception as e:                                    # noqa: BLE001
            entry["status"] = "failed"
            entry["error"] = "%s: %s" % (type(e).__name__, e)
            return []
        pkts = sorted(pkts, key=lambda p: p[0])
        entry["status"] = "ok"
        entry["packets"] = len(pkts)
        entry["bytes"] = sum(len(p[1]) for p in pkts)
        if pkts:
            entry["first_ts"], entry["last_ts"] = pkts[0][0], pkts[-1][0]
        return pkts
    return run
