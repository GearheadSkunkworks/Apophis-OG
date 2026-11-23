#!/usr/bin/env python3
"""
opengenerator_build.py — single-stage OpenGenerator capture generator.

ONE command builds ONE pcap containing the full normal business day plus the selected
incident modules, time-ordered into a single capture. No merge step. Alongside the pcap
it writes the TLS key log, exports each TLS server's certificate + RSA private key (for
the platform decryption), and writes the importable threat-intel collection.

**Selection** (added in Phase 3c; the default is still every module): pass `modules=[...]`
to build(), or use --module / --exclude / --only on the CLI. Every registry entry is
self-contained — the actor kill chains compose the technique builders internally under
their own tag — so any subset produces a valid capture. The threat collection is filtered
to the indicators the selected modules actually emit, so importing it never yields
indicators that match nothing.

The normal business day is always included: it is the baseline the incidents deviate from,
and a capture of bare attack traffic is not useful to a sensor. Selecting no modules is
allowed and gives a clean baseline day.

Usage:
    pip install -r requirements.txt
    python3 opengenerator_build.py                         # full scale, every module
    python3 opengenerator_build.py --scale 0.05            # a smaller sample
    python3 opengenerator_build.py --list-modules          # names, categories, windows
    python3 opengenerator_build.py --only NDR              # one whole category
    python3 opengenerator_build.py --module ndr-akira --module npm-voip-quality
    python3 opengenerator_build.py --exclude ndr-scattered-spider
    python3 opengenerator_build.py --no-modules            # baseline business day only

Outputs (defaults, next to --out):
    example-all-in-one.pcap                  the single capture (day + all modules)
    example-all-in-one-tls-keys.log          NSS TLS key log (Wireshark/tshark)
    certs/                                      per-server cert + key PEMs (+ CA) for the platform
    example-threat-collection.stix.json/.csv  embedded IOCs, importable into the platform
"""
import argparse
import ipaddress
import json
import os
import subprocess
import sys
import time

import netgen
from netgen import identity                    # emulated-company identity (v5.0)
from netgen.model import build_hosts, Day, set_capture_day, local
import build_manifest as BM
import scenario_meta

# Sentinel for build(iocs_prefix=...): distinguishes "caller said nothing, derive the name from
# the company" from None ("skip the threat-collection export") and from an explicit string.
_DERIVE = object()
from netgen.core import ArpModel, PcapWriter, Engine, Cancelled
from netgen.tls import PKI
from netgen import flows as F
from netgen import incidents as INC
from netgen.accounts import Directory
from netgen import protocols as P


# Address space the generator uses for things that are NOT the two emulated LANs. A chosen
# LAN must not collide with any of it, or the capture becomes self-contradictory.
RESERVED_NETS = {
    "198.51.100.0/24": "the simulated external internet hosts and ISP resolvers",
    "203.0.113.0/24": "the WAN / NAT outside interface",
}


def normalize_net(value, label="network"):
    """Accept '192.168.10.0/24', '192.168.10.0' or '192.168.10' -> '192.168.10.0/24'.

    Only /24s ("class C" sized) are allowed: the generator's subnet membership test is a
    three-byte prefix compare, and every host keeps its own last octet when re-addressed,
    so a /24 is what the topology is shaped for.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if "/" not in text:
        parts = text.split(".")
        if len(parts) == 3:
            text += ".0"
        text += "/24"
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError as e:
        raise ValueError(f"{label}: '{value}' is not a valid IPv4 network ({e})")
    if net.version != 4:
        raise ValueError(f"{label}: '{value}' is not IPv4")
    if net.prefixlen != 24:
        raise ValueError(f"{label}: '{value}' is a /{net.prefixlen}; a /24 (class C) is required")
    if net.is_loopback or net.is_multicast or net.is_link_local or net.is_reserved:
        raise ValueError(f"{label}: '{net}' is in a reserved range and cannot be used")
    for cidr, why in RESERVED_NETS.items():
        if net.overlaps(ipaddress.ip_network(cidr)):
            raise ValueError(f"{label}: '{net}' collides with {cidr}, which the capture uses for {why}")
    bad = [ip for ip in (i[0] for i in INC.INDICATORS)
           if ipaddress.ip_address(ip) in net]
    if bad:
        raise ValueError(f"{label}: '{net}' contains real threat-intel indicator(s) "
                         f"({', '.join(bad)}) used by the incident modules; choose another range")
    return str(net)


# The OT subnet is three /24s, not one: the cell/area zone (Purdue 0-2), site operations
# (level 3) and the IDMZ (level 3.5). Collapsing the IDMZ into operations would remove the
# single most important boundary in the model, so they stay separate.
OT_DEFAULTS = {"ot": "10.10.30.0/24", "ops": "10.10.40.0/24", "idmz": "10.10.50.0/24"}


def validate_nets(user_net=None, server_net=None, ot_nets=None):
    """Normalize and cross-check the emulated LANs. Returns (user, server, ot) where ot is a
    dict of the three OT /24s, or None when the OT subnet is off."""
    u = normalize_net(user_net, "user network")
    s_ = normalize_net(server_net, "server network")
    if u and s_ and u == s_:
        raise ValueError("the user and server networks must be two distinct /24s")
    if not ot_nets:
        return u, s_, None
    out = {}
    for key, label in (("ot", "OT network"), ("ops", "OT operations network"),
                       ("idmz", "OT IDMZ network")):
        out[key] = normalize_net(ot_nets.get(key) or OT_DEFAULTS[key], label)
    seen = [n for n in (u, s_) if n] + list(out.values())
    if len(set(seen)) != len(seen):
        raise ValueError("every emulated network must be a distinct /24 "
                         f"(got {', '.join(seen)})")
    return u, s_, out


def select_modules(modules=None, exclude=None, only=None):
    """Resolve a module selection to an ordered list of registry names.

    modules: explicit names to include (None = all).
    exclude: names to drop afterwards.
    only:    category prefixes to keep, e.g. ["NDR", "CRP"].
    Registry order is preserved so builds stay deterministic. Unknown names raise, rather
    than being silently dropped — a typo in a scenario name should not quietly produce a
    capture that is missing the very scenario you are demoing.
    """
    known = list(INC.REGISTRY)
    baseline = set(INC.BASELINE_MODULES)
    if modules is None:
        chosen = list(known)
    else:
        wanted = {str(m).strip() for m in modules if str(m).strip()}
        pinned = sorted(wanted & baseline)
        if pinned:
            raise ValueError(
                "cannot select " + ", ".join(pinned) + ": baseline traffic is always included "
                "and is not selectable (see --list-modules)")
        unknown = sorted(wanted - set(known))
        if unknown:
            raise ValueError("unknown module(s): " + ", ".join(unknown) +
                             ". Known: " + ", ".join(known))
        chosen = [n for n in known if n in wanted]          # registry order, not caller order
    if only:
        keep = {str(p).strip().upper() for p in only}
        chosen = [n for n in chosen if INC.REGISTRY[n].prefix.upper() in keep]
    if exclude:
        drop = {str(m).strip() for m in exclude}
        unknown = sorted(drop - set(known))
        if unknown:
            raise ValueError("unknown module(s) in exclude: " + ", ".join(unknown))
        chosen = [n for n in chosen if n not in drop]
    # Scenario dependencies: an NPM scenario caused by a compromised LOTL host auto-includes the
    # NDR scenario that compromised it, so the capture carries the intrusion context. Honours an
    # explicit exclude of the dependency; re-sorted into registry order so the build stays ordered.
    drop = {str(m).strip() for m in (exclude or [])}
    deps = getattr(INC, "SCENARIO_DEPENDENCIES", {})
    add = {deps[n] for n in chosen if n in deps and deps[n] not in drop}
    if add:
        want = set(chosen) | add
        chosen = [n for n in known if n in want]
    return chosen


# ---------------------------------------------------------------- post-build exporters (v5b)
# Each exporter is run after the capture is written and returns a dict merged into the build
# summary. The three built-ins below cover the historical outputs; a capability module can
# register another (e.g. a new report format) via register_exporter() without editing build().
# Exporters never affect the pcap itself, so they carry no risk to the 466,343 baseline.
class _ExportCtx:
    """The build artifacts an exporter may read: the output path, the PcapWriter, the PKI, the
    flow Ctx, the selected module list, and the certs/iocs destinations."""
    def __init__(self, **kw):
        self.__dict__.update(kw)


EXPORTERS = []                      # list of (name, fn); fn(ectx) -> dict merged into summary


def register_exporter(name, fn):
    """Register a post-build exporter. fn(ectx) returns a dict of summary keys (or {})."""
    EXPORTERS.append((name, fn))


def _export_server_certs(e):
    if not e.certs_dir:
        return {}
    names = e.pki.export_pems(e.certs_dir)
    return {"certs": (e.certs_dir, len(names))}


def _export_threat_collection(e):
    if not e.iocs_prefix:
        return {}
    # only export indicators the selected modules actually put on the wire
    iocs = INC.threat_collection(e.iocs_prefix + ".stix.json", e.iocs_prefix + ".csv",
                                 only_ips=INC.used_indicator_ips(e.ctx))
    return {"iocs": iocs}


def _export_generation_report(e):
    # packets by protocol, counted as the capture was written (no second pass, no dissector)
    protocols = sorted(e.writer.protocols.items(), key=lambda kv: -kv[1])
    report_csv = (e.out[:-5] if e.out.endswith(".pcap") else e.out) + "-generation-report.csv"
    try:
        with open(report_csv, "w") as rf:
            rf.write("protocol,packets,percent\n")
            for name, n in protocols:
                rf.write("%s,%d,%.4f\n" % (name, n, 100.0 * n / max(1, e.writer.n)))
    except OSError:
        report_csv = None
    return {"protocols": protocols, "report_csv": report_csv}


register_exporter("server-certs", _export_server_certs)
register_exporter("threat-collection", _export_threat_collection)
register_exporter("generation-report", _export_generation_report)


def preview_campaign(campaign, scale=1.0, date=None, inventory="inventory.json",
                     user_net=None, server_net=None, ot_nets=None):
    """Run ONE campaign through the engine, campaign-only: no baseline day, no incident modules,
    no file kept. Returns (report, totals): `report` is ctx.campaign_report whose ``entries``
    carry exact ts / from_host / to_host / stage / packets / bytes, and `totals` is
    {"packets", "bytes"} from the writer — the campaign's exact contribution to a capture.

    It reuses the real engine action code via the registered 'campaign' scenario, so the figures
    are the same ones the generator would produce and never drift from the actions. The context
    setup below mirrors build()'s; keep the two in step. build() itself is left untouched so the
    baseline pin cannot be affected by this path. Callers must serialise it with real builds
    (it reseeds the process-global RNG), exactly like build()."""
    import tempfile
    netgen.reseed_all()                                  # same global-RNG reset build() does first
    cap_day = set_capture_day(date)
    hosts, link, sites, resolvers = build_hosts(inventory, user_net=user_net,
                                                server_net=server_net, ot_nets=ot_nets,
                                                with_ot=bool(ot_nets))
    pki = PKI(day=cap_day)
    klpath = tempfile.mktemp(suffix=".log"); kl = open(klpath, "w")
    ctx = F.Ctx(hosts, link, ArpModel(link), pki, kl, scale=scale)
    ctx.sites = sites
    ctx.isp_resolvers = resolvers
    ctx.recipe = None
    ctx.recipes = []
    ctx.campaigns = [campaign]                           # read by the registered 'campaign' scenario
    ctx.dir = Directory(hosts, P.username_for)
    pcappath = tempfile.mktemp(suffix=".pcap")
    writer = PcapWriter(pcappath)
    eng = Engine(writer)
    day = Day(ctx, eng, scale)
    try:
        INC.build("campaign", day, ctx, eng)             # schedules ONLY the campaign
        eng.run()                                        # executes it; _wrap fills packets/bytes
    finally:
        writer.close(); kl.close()
        for _p in (pcappath, klpath):
            try:
                os.remove(_p)
            except OSError:
                pass
    report = ctx.campaign_report or {"campaigns": [], "entries": [], "errors": []}
    return report, {"packets": writer.n, "bytes": writer.bytes}


def build(scale=1.0, out=None, keylog=None, inventory="inventory.json",
          certs_dir="certs", iocs_prefix=_DERIVE, stats=None, progress=True,
          on_progress=None, modules=None, exclude=None, only=None,
          user_net=None, server_net=None, should_cancel=None, date=None,
          ot_net=None, ot_nets=None, recipe=None, recipes=None,
          company=None, industry=None, ot_protocols=None,
          campaigns=None, address_mode=None, confirm_real_addresses=False):
    """Generate the capture. Returns a summary dict.

    campaigns: a list of campaign dicts (see netgen.campaign / dev/docs/campaign-m1-contracts.md).
      Supplying one activates the 'campaign' scenario, exactly as recipes activate custom-import;
      with none the scenario is inert and the capture is unchanged. After the build the campaign
      exports are written beside the pcap (<out>.campaign.json, .campaign-iocs.stix.json,
      .attack-navigator.json, .campaign-report.md).
    address_mode: 'mapped' (default; indicator IPv4 re-addressed into 198.18.0.0/15) or 'real'.
      Real addresses require confirm_real_addresses=True, otherwise ValueError.

    modules/exclude/only: incident selection (see select_modules); the default builds every
    module, which is the historical behaviour.
    user_net/server_net: re-address the two emulated /24s (default: whatever the inventory
    says, i.e. 10.10.10.0/24 and 10.10.20.0/24). Host numbering, counts, MACs, services and
    traffic patterns are unchanged — only the network part moves. External addresses and the
    real threat-intel indicators are never re-addressed.
    on_progress(packets, bytes, last_ts): optional callback for GUIs/embedding (no printing).
    should_cancel(): optional predicate for GUIs; when it returns True the run is abandoned and
      `netgen.core.Cancelled` is raised, after the partial pcap and key log have been deleted.
      It is polled between module builds and every CANCEL_EVERY packets while writing. It must
      not be confused with on_progress, whose exceptions are deliberately swallowed — a UI
      callback failing must never break a build, but a cancel must always stop one.
    """
    selected = select_modules(modules, exclude, only)
    # Recipes (from the pcap importer) activate the custom-import scenario, one CUSTOM run per
    # recipe, read back by its builder to recreate each exemplar's flows. `recipes` is a list of
    # paths; `recipe` is accepted as a single-path fallback. With none, custom is never built.
    recipe_paths = list(recipes or [])
    if recipe:
        recipe_paths.append(recipe)
    recipe_list = []
    if recipe_paths:
        import pcapprofile as _pp
        for _p in recipe_paths:
            _rec, _warn = _pp.load_recipe(_p)       # raises ValueError naming the file
            for _w in _warn:
                print("  recipe warning (%s): %s" % (os.path.basename(_p), _w))
            recipe_list.append(_rec)
        if "custom-import" not in selected:
            selected = list(selected) + ["custom-import"]
    recipe_data = recipe_list[0] if recipe_list else None
    # Campaigns (threat-indicator driven attack chains) activate the 'campaign' scenario the same
    # way. address_mode, when given, overrides each campaign's own option.
    campaign_list = [dict(c) for c in (campaigns or []) if c]
    if address_mode not in (None, "mapped", "real"):
        raise ValueError("address_mode must be 'mapped' or 'real', got %r" % (address_mode,))
    if address_mode:
        for _c in campaign_list:
            _c["options"] = dict(_c.get("options") or {}, address_mode=address_mode)
    if any((_c.get("options") or {}).get("address_mode") == "real" for _c in campaign_list) \
            and not confirm_real_addresses:
        raise ValueError("real address mode puts real indicator addresses in the packets; "
                         "pass confirm_real_addresses=True (CLI: --confirm-real-addresses) to allow it")
    if campaign_list and "campaign" not in selected:
        selected = list(selected) + ["campaign"]
    # ot_net is the switch: absent means no OT subnet at all, and the capture is
    # packet-identical to one built before the feature existed. ot_nets overrides the
    # individual /24s when given.
    if ot_net and not ot_nets:
        ot_nets = dict(OT_DEFAULTS, ot=ot_net)
    user_net, server_net, ot_nets = validate_nets(user_net, server_net, ot_nets)
    os.environ["TZ"] = "America/New_York"
    time.tzset()
    # The emulated company. (company, industry) together derive the whole on-wire identity --
    # domain, host prefix, Root CA, org, SIP realm, namespace (see netgen.identity) -- and the
    # exported filenames. Set it BEFORE reseed_all() (which pushes the identity into every
    # module) and before deriving the output names. Blank/None on both resets to the DEFAULT
    # (Example Logistics) singleton, so a plain build stays byte-for-byte what it always was
    # (and names its files example-*), and still pins at 466,343.
    if company or industry:
        identity.set_current(identity.Identity(company or None, industry or None))
    else:
        identity.set_current(None)
    _id = identity.get_current()
    # Exported filenames follow the company: Example Logistics -> example-all-in-one.pcap /
    # example-threat-collection.*, Acme Manufacturing -> acme-all-in-one.pcap / acme-*. An
    # explicit out=/iocs_prefix= still wins; iocs_prefix=None still skips the collection.
    if out is None:
        out = _id.pcap_basename + ".pcap"
    if iocs_prefix is _DERIVE:
        iocs_prefix = _id.stix_basename
    keylog = keylog or (out[:-5] if out.endswith(".pcap") else out) + "-tls-keys.log"

    # ensure the host inventory exists (auto-build on first run)
    if not os.path.exists(inventory):
        if getattr(sys, "frozen", False):
            # Inside a .app, sys.executable is the app itself — spawning it would relaunch the
            # GUI instead of running inventory.py. The server seeds the bundled inventory.json
            # into the output folder precisely so this branch is never reached; if it is, say
            # so plainly rather than fork-bombing the user's Dock.
            raise RuntimeError(
                f"{inventory} is missing and cannot be rebuilt from inside the packaged app. "
                "Copy inventory.json into the output folder, or run from source.")
        if progress:
            print(f"{inventory} not found — building it...", flush=True)
        subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "inventory.py")],
                       check=True)

    # The calendar day the capture sits on. Default is TODAY, so a capture uploaded to a
    # sensor for offline analysis appears where the operator is already looking instead of
    # days in the past. Must be set before build_hosts/Day, because the window constants in
    # netgen.model are recomputed here. PKI reads the same day, so the certificates cannot
    # disagree with the packets.
    # Return every module RNG to its declared seed. Without this a second build in the same
    # interpreter continues the first one's stream, so the GUI's second capture of a session
    # differed from its first with identical arguments. Must precede set_capture_day() and all
    # scheduling — anything that draws before this point would be reset underneath itself.
    netgen.reseed_all()

    cap_day = set_capture_day(date)

    hosts, link, sites, resolvers = build_hosts(inventory, user_net=user_net,
                                                server_net=server_net, ot_nets=ot_nets,
                                                with_ot=bool(ot_nets))
    pki = PKI(day=cap_day)
    kl = open(keylog, "w")
    ctx = F.Ctx(hosts, link, ArpModel(link), pki, kl, scale=scale)
    ctx.sites = sites
    ctx.isp_resolvers = resolvers
    ctx.recipe = recipe_data              # single-recipe fallback (None = inert)
    ctx.recipes = recipe_list             # one CUSTOM scenario per recipe (read by custom-import)
    ctx.campaigns = campaign_list         # read by the 'campaign' scenario (empty = inert)
    # The account directory. Derived from the inventory, so who is disabled/expired/locked is
    # the same on every run — a demo that tells a different story each build is not a demo.
    ctx.dir = Directory(hosts, P.username_for)

    writer = PcapWriter(out)
    eng = Engine(writer)
    day = Day(ctx, eng, scale, ot_protocols=ot_protocols)

    t0 = time.time()

    def prog(w):
        if on_progress:
            try:
                on_progress(w.n, w.bytes, w.last_ts)
            except Exception:                    # noqa: BLE001 — never let a UI callback break generation
                pass
        if progress:
            print(f"  {w.n:>10,} pkts  {w.bytes/1e6:>8.1f} MB  clock {time.strftime('%H:%M:%S', time.localtime(w.last_ts))}  ({time.time()-t0:.0f}s)", flush=True)

    try:
        # stage 1 (the only stage): schedule the normal day, then the selected incident modules
        day.build()
        for name in selected:
            # Scheduling is quick per module but not instant across 28 of them, and a user who
            # has pressed Stop should not wait for the whole registry before anything happens.
            if should_cancel is not None and should_cancel():
                raise Cancelled(0)
            INC.build(name, day, ctx, eng)
        eng.run(progress=prog,
                should_continue=None if should_cancel is None else (lambda: not should_cancel()))
    except Cancelled:
        # A partial pcap is a valid file full of an incomplete business day — exactly the kind
        # of thing that gets replayed by accident six months later. Discard it.
        writer.close()
        kl.close()
        for path in (out, keylog):
            try:
                os.remove(path)
            except OSError:
                pass
        raise
    writer.close()
    kl.close()
    if os.path.getsize(keylog) == 0:
        os.remove(keylog)
        keylog = None

    if stats:
        import json
        json.dump(eng.stats, open(stats, "w"), indent=1)

    by_cat = {}
    for n in selected:
        by_cat[INC.REGISTRY[n].prefix] = by_cat.get(INC.REGISTRY[n].prefix, 0) + 1
    cats = ", ".join(f"{v} {k}" for k, v in sorted(by_cat.items())) or "none"
    # Named legs, never list position: link.fw_extra is ordered differently by the two inventory
    # layouts (the dual-firewall one carries the IDMZ legs first), so a positional zip mislabels.
    nets = {"user": link.fw_a.ip.rsplit(".", 1)[0] + ".0/24",
            "server": link.fw_b.ip.rsplit(".", 1)[0] + ".0/24"}
    for key, nm in (("ot", "FW-OT"), ("ops", "FW-OPS"), ("idmz", "FW-IDMZ")):
        if nm in hosts:
            nets[key] = hosts[nm].subnet
    # Run the registered post-build exporters (built-in: server certs, threat collection,
    # generation report). Each merges its keys into the summary; an exporter failing never
    # discards a finished capture.
    _ectx = _ExportCtx(out=out, writer=writer, pki=pki, ctx=ctx, selected=selected,
                       certs_dir=certs_dir, iocs_prefix=iocs_prefix)
    _exports = {}
    for _xname, _xfn in EXPORTERS:
        try:
            _exports.update(_xfn(_ectx) or {})
        except Exception as _xe:                         # noqa: BLE001
            if progress:
                print(f"  exporter {_xname!r} failed: {_xe}")
    certs = _exports.get("certs")
    iocs = _exports.get("iocs")
    protocols = _exports.get("protocols") or sorted(writer.protocols.items(), key=lambda kv: -kv[1])
    report_csv = _exports.get("report_csv")

    summary = {"pcap": out, "packets": writer.n, "bytes": writer.bytes, "keylog": keylog,
               "protocols": protocols, "report_csv": report_csv,
               "modules": len(selected), "module_names": selected, "by_category": by_cat,
               "all_modules": len(selected) == len(INC.REGISTRY), "certs": certs, "iocs": iocs,
               "nets": nets, "date": "%04d-%02d-%02d" % cap_day,
               "identity": {"company": identity.get_current().name,
                            "industry": identity.get_current().industry,
                            "org": identity.get_current().org,
                            "domain": identity.get_current().domain}}
    # Surface any extra keys a module exporter returned (e.g. a new report's path) without
    # letting one shadow a summary field the build owns. The built-in exporter keys above are
    # already consumed; this is what makes register_exporter()'s "merged into the summary"
    # contract true for module-provided exporters.
    for _k, _v in _exports.items():
        summary.setdefault(_k, _v)
    # the custom-import reconstruction report: what was rebuilt and what could not be
    cr = getattr(ctx, "custom_report", None)
    if cr:
        import json as _json
        rp = (out[:-5] if out.endswith(".pcap") else out) + "-custom-report.json"
        try:
            with open(rp, "w") as _f:
                _json.dump(cr, _f, indent=2)
            summary["custom_report"] = rp
        except OSError:
            pass
        if progress:
            built = ", ".join("%s(%d)" % (b["protocol"], b["sessions"]) for b in cr.get("built", []))
            skipped = ", ".join(x["protocol"] for x in cr.get("skipped", []))
            print(f"  custom-import built: {built or 'none'}")
            if skipped:
                print(f"  custom-import could not reconstruct: {skipped}")
    # the campaign exports and narration, derived from what the runner recorded as it emitted
    crep = getattr(ctx, "campaign_report", None)
    if crep:
        try:
            import json as _jsonlib
            from netgen.campaign import exports as _cexp, console as _ccon
            base = out[:-5] if out.endswith(".pcap") else out
            written, built = {}, []
            for _camp in campaign_list:
                _label = (_camp.get("meta") or {}).get("id") or (_camp.get("meta") or {}).get("name")
                if not any(c.get("id") == _label for c in crep.get("campaigns", [])):
                    continue                                # invalid or skipped: nothing to export
                built.append(_label)
                _pre = base if len(campaign_list) == 1 else base + "-" + str(_label)
                written[_label] = _cexp.write_all(_camp, crep, _pre)
            summary["campaign"] = {"built": built, "exports": written,
                                   "errors": list(crep.get("errors", [])) +
                                             [e for _c in crep.get("campaigns", []) for e in _c.get("errors", [])],
                                   "actions": len(crep.get("entries", [])),
                                   "emitted": sum(1 for e in crep.get("entries", []) if e.get("status") == "ok"),
                                   # per-action records and the indicator table, for the GUI results view
                                   # (JSON-safe copies, capped so a huge campaign cannot bloat the status reply)
                                   "entries": _jsonlib.loads(_jsonlib.dumps(list(crep.get("entries", []))[:2000], default=str)),
                                   "iocs": _jsonlib.loads(_jsonlib.dumps(
                                       [dict(r, campaign=_c.get("id")) for _c in crep.get("campaigns", [])
                                        for r in _c.get("iocs", [])][:5000], default=str))}
            summary["campaign_console"] = _ccon.narrate(crep)
            if progress:
                for _line in summary["campaign_console"]:
                    print("  " + _line)
                for _lbl, _p in written.items():
                    print(f"  campaign exports ({_lbl}): " + ", ".join(os.path.basename(v) for v in _p.values()))
        except Exception as _ce:                            # noqa: BLE001 -- never lose a finished capture
            summary["campaign"] = {"error": "%s: %s" % (type(_ce).__name__, _ce)}
            if progress:
                print(f"  campaign exports failed: {_ce}")
    # Per-scenario counters (from Engine.stats; no extra pass) and the manifest beside the pcap.
    # Neither may ever discard a finished capture, so failures are recorded, not raised.
    try:
        _bk, _cons = BM.by_scenario(eng.stats, selected, writer.n, writer.bytes)
        summary["by_scenario"] = _bk
        summary.update(_cons)
        _extra = [keylog, summary.get("report_csv"), (summary.get("iocs") or {}).get("stix"),
                  (summary.get("iocs") or {}).get("csv"), summary.get("custom_report")]
        for _w in (summary.get("campaign") or {}).get("exports", {}).values():
            _extra += list(_w.values()) if isinstance(_w, dict) else []
        _first = min((b["first_ts"] for b in _bk.values() if b["first_ts"] is not None), default=None)
        _last = max((b["last_ts"] for b in _bk.values() if b["last_ts"] is not None), default=None)
        _id2 = identity.get_current()
        _params = {"scale": scale, "date": summary["date"], "company": _id2.name, "industry": _id2.industry,
                   "user_net": nets["user"], "server_net": nets["server"], "ot": "ot" in nets,
                   "ot_nets": {k: v for k, v in nets.items() if k not in ("user", "server")},
                   "ot_protocols": sorted(ot_protocols) if ot_protocols else [],
                   "recipes": len(recipe_list), "campaigns": len(campaign_list),
                   "address_mode": address_mode, "scenarios": list(selected)}
        _mp = BM.write(out, _ver(), _params, selected, INC.REGISTRY, INC.resolve_window, local(5), _bk, _cons,
                       {"packets": writer.n, "bytes": writer.bytes, "first_ts": _first, "last_ts": _last,
                        "duration_s": round(_last - _first, 3) if _first is not None else 0.0},
                       _extra, scenario_meta.get)
        summary["manifest"] = os.path.basename(_mp)
    except Exception as _me:                                # noqa: BLE001
        summary["manifest_error"] = "%s: %s" % (type(_me).__name__, _me)
    if progress:
        print(f"\ndone: {writer.n:,} packets, {writer.bytes/1e6:.1f} MB -> {out}")
        print(f"  modules included: {len(selected)} ({cats}), plus the normal day")
        print(f"  networks:         user {nets['user']}, server {nets['server']}")
        print(f"  capture day:      {summary['date']} (05:00-21:00 America/New_York)")
        if keylog:
            print(f"  TLS key log:      {keylog}")
        if certs:
            print(f"  server certs/keys: {certs[1]} pair(s) + CA -> {certs[0]}/")
        if iocs:
            print(f"  threat collection: {iocs['indicators']} indicators -> {iocs['stix']}, {iocs['csv']}")
    return summary


def _ver():
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION"), encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def list_modules():
    """Print the registry grouped by category, for --list-modules."""
    by = {}
    for name, inc in INC.REGISTRY.items():
        by.setdefault(inc.prefix, []).append((name, inc))
    for prefix in ("NDR", "NPM", "CRP", "IR", "CUSTOM", "CAMPAIGN"):
        entries = by.get(prefix, [])
        if not entries:
            continue
        print(f"\n{prefix} ({len(entries)}):")
        for name, inc in entries:
            (h1, m1), (h2, m2) = inc.window
            print(f"  {name:<28} {h1:02d}:{m1:02d}-{h2:02d}:{m2:02d}  {inc.title}")
    print(f"\n{len(INC.REGISTRY)} selectable modules. Default is all of them.")
    base = INC.baseline_modules()
    if base:
        print("\nBaseline, always included (not selectable):")
        for b in base:
            print(f"  {b['name']:<28} {b['window']}  {b['title']}")
            print(f"  {'':<28} {b['why']}")


def list_actions():
    """Print the campaign action registry, for --list-actions."""
    from netgen.campaign import actions as ACT
    specs = ACT.load_all()
    if not specs:
        print("no campaign actions are registered")
        return
    for token, sp in specs.items():
        print(f"  {token:<26} {sp.tactic:<20} {','.join(sp.techniques):<22} {'/'.join(sp.protocols):<22} {sp.title}")
    print(f"\n{len(specs)} campaign actions.")


def list_feeds():
    """Print the threat-intel feeds, for --list-feeds."""
    from intel import sources
    for fid, fd in sorted(sources.FEEDS.items()):
        print(f"  {fid:<20} {getattr(fd, 'group', ''):<14} {'key needed' if getattr(fd, 'needs_key', False) else 'no key':<11} {fd.title}")
    print(f"\n{len(sources.FEEDS)} feeds. Fetch with --intel-feed ID[:N]; --offline reads only the cache.")


def campaigns_from_args(args):
    """Load --campaign files and compile one campaign from --intel-file / --intel-feed input.
    Returns the list of campaign dicts. Prints what it did."""
    out = []
    if args.campaign:
        from netgen.campaign import schema
        for p in args.campaign:
            out.append(schema.load(p))
            print(f"campaign: loaded {p}")
    iocs, names = [], []
    if args.intel_file:
        from intel import parsers
        for p in args.intel_file:
            with open(p, "rb") as f:
                got = parsers.parse_any(f.read(), source=os.path.basename(p))
            print(f"intel: {len(got)} indicator(s) parsed from {p}")
            iocs += got
            names.append(os.path.splitext(os.path.basename(p))[0])
    if args.intel_feed:
        from intel import sources
        for spec in args.intel_feed:
            fid, _, n = spec.partition(":")
            got = sources.fetch(fid, limit=int(n) if n else 50, offline=args.offline)
            print(f"intel: {len(got)} indicator(s) from feed {fid}" + (" (offline cache)" if args.offline else ""))
            iocs += got
            names.append(fid)
    if iocs:
        from intel import filters
        from netgen.campaign import compiler
        kept, dropped = filters.clean(iocs, allow_private=False)
        print(f"intel: {len(kept)} kept, {len(dropped)} dropped")
        for d in dropped[:5]:
            print(f"  dropped: {d}")
        opts = {"address_mode": args.address_mode} if args.address_mode else None
        camp = compiler.compile_campaign(kept, options=opts, name="+".join(names) or None)
        if args.save_campaign:
            import json
            with open(args.save_campaign, "w") as f:
                json.dump(camp, f, indent=2, sort_keys=True)
            print(f"campaign: saved {args.save_campaign}")
        out.append(camp)
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Single-stage generator: one pcap with the normal day + the selected incident modules.")
    ap.add_argument("--scale", type=float, default=1.0, help="traffic-volume multiplier (default 1.0 = full day)")
    ap.add_argument("--out", default=None,
                    help="output pcap path (default: <company>-all-in-one.pcap, e.g. "
                         "example-all-in-one.pcap)")
    ap.add_argument("--keylog", default=None, help="TLS key log path (default derived from --out)")
    ap.add_argument("--inventory", default="inventory.json", help="inventory path (auto-built if missing)")
    ap.add_argument("--certs-dir", default="certs", help="directory for exported server cert/key PEMs (default 'certs')")
    ap.add_argument("--no-certs", action="store_true", help="skip certificate/key export")
    ap.add_argument("--iocs-prefix", default=None,
                    help="prefix for the exported threat collection "
                         "(default: <company>-threat-collection)")
    ap.add_argument("--no-iocs", action="store_true", help="skip the threat-collection export")
    ap.add_argument("--stats", default=None, help="optional per-conversation-type stats JSON")
    ap.add_argument("--recipe", action="append", default=None, metavar="JSON",
                    help="a pcap-import recipe JSON; repeat for several (one CUSTOM scenario per recipe)")
    ap.add_argument("--date", metavar="YYYY-MM-DD", default=None,
                    help="calendar day the capture covers (default: today). Pin it to make "
                         "two runs byte-comparable.")
    org = ap.add_argument_group("emulated company (default: Example Logistics)")
    org.add_argument("--company", metavar="NAME", default=None,
                     help="company name that drives the on-wire identity (domain, host prefix, "
                          "Root CA, org). Default: Example")
    org.add_argument("--industry", metavar="KIND", default=None, choices=identity.INDUSTRIES,
                     help="industry: " + ", ".join(identity.INDUSTRIES) + ". Default: Logistics")
    net = ap.add_argument_group("emulated networks (default: whatever the inventory says)")
    net.add_argument("--user-net", metavar="CIDR", default=None,
                     help="class C (/24) for the user subnet, e.g. 192.168.10.0/24")
    net.add_argument("--server-net", metavar="CIDR", default=None,
                     help="class C (/24) for the server subnet, e.g. 192.168.20.0/24")
    net.add_argument("--ot-net", metavar="CIDR", default=None, nargs="?", const=OT_DEFAULTS["ot"],
                     help="add the optional OT / IoT subnet (Purdue levels 0-2), e.g. 10.10.30.0/24. "
                          "Two further /24s follow it for level 3 and the IDMZ; with this flag "
                          "absent no OT asset is built at all")
    net.add_argument("--ot-ops-net", metavar="CIDR", default=None,
                     help="class C (/24) for Purdue level 3, site operations (default 10.10.40.0/24)")
    net.add_argument("--ot-idmz-net", metavar="CIDR", default=None,
                     help="class C (/24) for Purdue level 3.5, the IDMZ (default 10.10.50.0/24)")
    sel = ap.add_argument_group("incident selection (default: every module)")
    sel.add_argument("--list-modules", action="store_true",
                     help="print the module registry with categories and windows, then exit")
    sel.add_argument("--module", action="append", metavar="NAME", dest="modules",
                     help="include only this module (repeatable)")
    sel.add_argument("--exclude", action="append", metavar="NAME",
                     help="drop this module (repeatable); applies after --module/--only")
    sel.add_argument("--only", action="append", metavar="CATEGORY", choices=["NDR", "NPM", "CRP", "IR", "CUSTOM", "CAMPAIGN"],
                     help="include only this category (repeatable): NDR, NPM, CRP, IR, CUSTOM or CAMPAIGN")
    sel.add_argument("--no-modules", action="store_true",
                     help="baseline business day only, no incidents")
    cg = ap.add_argument_group("campaigns (threat indicators -> attack campaign; off unless a campaign is given)")
    cg.add_argument("--campaign", action="append", metavar="FILE", help="a campaign JSON file; repeatable")
    cg.add_argument("--intel-file", action="append", metavar="FILE",
                    help="threat-indicator file (text, CSV, STIX, MISP, OTX; defanged is fine); "
                         "compiled into a campaign. Repeatable, all files form one campaign")
    cg.add_argument("--intel-feed", action="append", metavar="ID[:N]",
                    help="fetch N indicators (default 50) from a feed (see --list-feeds); repeatable")
    cg.add_argument("--offline", action="store_true", help="feeds read only the local cache, no network")
    cg.add_argument("--save-campaign", metavar="FILE", help="write the compiled campaign JSON here")
    cg.add_argument("--address-mode", choices=["mapped", "real"], default=None,
                    help="mapped (default): indicator IPv4 re-addressed into 198.18.0.0/15; real: the "
                         "indicators' own addresses (needs --confirm-real-addresses)")
    cg.add_argument("--confirm-real-addresses", action="store_true",
                    help="confirm that real indicator addresses may appear in the packets")
    cg.add_argument("--list-actions", action="store_true", help="print the campaign actions, then exit")
    cg.add_argument("--list-feeds", action="store_true", help="print the threat-intel feeds, then exit")
    cg.add_argument("--campaign-explain", action="store_true",
                    help="print why each indicator became each stage/action, then exit (no build)")
    args = ap.parse_args()
    if args.list_modules:
        list_modules()
        return
    if args.list_actions:
        list_actions()
        return
    if args.list_feeds:
        list_feeds()
        return
    campaigns = []
    if args.campaign or args.intel_file or args.intel_feed or args.campaign_explain:
        if args.address_mode == "real" and not args.confirm_real_addresses:
            ap.error("--address-mode real puts the indicators' REAL IPv4 addresses into the packets. "
                     "Replaying that capture on a routed link could send traffic to real hosts. "
                     "Add --confirm-real-addresses if you understand that and the replay is isolated.")
        if args.address_mode == "real":
            print("WARNING: real address mode: real indicator addresses will appear in the packets. "
                  "Replay only on an isolated link.")
        try:
            campaigns = campaigns_from_args(args)
        except (OSError, ValueError, ImportError, KeyError) as e:
            ap.error("campaign input: %s" % e)
        if args.campaign_explain:
            from netgen.campaign import compiler
            if not campaigns:
                ap.error("--campaign-explain needs --campaign, --intel-file or --intel-feed")
            for c in campaigns:
                txt = compiler.explain_campaign(c)
                print(txt if isinstance(txt, str) else "\n".join(txt))
            return
    modules = [] if args.no_modules else args.modules
    try:
        chosen = select_modules(modules, args.exclude, args.only)
        ot_req = {"ot": args.ot_net, "ops": args.ot_ops_net, "idmz": args.ot_idmz_net} \
            if (args.ot_net or args.ot_ops_net or args.ot_idmz_net) else None
        user_net, server_net, ot_nets = validate_nets(args.user_net, args.server_net, ot_req)
    except ValueError as e:
        ap.error(str(e))
    if args.company or args.industry:
        _id = identity.Identity(args.company or None, args.industry or None)
        print(f"company: {_id.org}  (domain {_id.domain}, host prefix {_id.prefix})")
    if user_net or server_net:
        print(f"networks: user {user_net or 'unchanged'}, server {server_net or 'unchanged'}")
    if ot_nets:
        print(f"OT subnet: cell/area {ot_nets['ot']}, operations {ot_nets['ops']}, "
              f"IDMZ {ot_nets['idmz']}")
    print(f"selected {len(chosen)} of {len(INC.REGISTRY)} modules"
          + (": " + ", ".join(chosen) if 0 < len(chosen) < len(INC.REGISTRY) else ""))
    try:
        build(scale=args.scale, out=args.out, keylog=args.keylog, inventory=args.inventory,
              certs_dir=None if args.no_certs else args.certs_dir,
              iocs_prefix=None if args.no_iocs else (args.iocs_prefix or _DERIVE), stats=args.stats,
              modules=modules, exclude=args.exclude, only=args.only,
              user_net=args.user_net, server_net=args.server_net, date=args.date,
              ot_nets=ot_nets, recipes=args.recipe,
              company=args.company, industry=args.industry,
              campaigns=campaigns or None, address_mode=args.address_mode,
              confirm_real_addresses=args.confirm_real_addresses)
    except ValueError as e:                      # a bad recipe: say so plainly, no traceback
        if args.recipe:
            raise SystemExit("error: %s" % e)
        raise


if __name__ == "__main__":
    main()
