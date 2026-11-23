"""Endpoint resolution for campaigns: turn the `from` / `to` references of an action into
netgen.core.Host objects.

Internal references (``ws``, ``ws2``, ``any_ws``, ``server``, ``dc``, ``file``, ``sql``, ``web``,
``fw``, ``host:SUFFIX``) are looked up in the built environment through ``H()``, so the capture
speaks the current company's names. External references (``attacker``, ``c2:N``, ``exfil:N``,
``payload:N``, ``scanner:N``, ``phish:N``, ``tor:N``, ``brute:N``, ``ioc:N``) become internet-side
hosts built from the campaign's indicators. One indicator is one host per build (cached on the
Ctx), so the same C2 always has the same address and MAC.

Address modes: ``mapped`` (default) moves an indicator's IPv4 into the benchmark range
198.18.0.0/15 so nothing real can be reached by a replay; ``real`` uses the indicator's own IPv4
and is only allowed after the caller confirmed it (see addressing.real_mode_check).

Randomness is netgen.flows.rng only (the engine's reseeded generator).
"""
from ..core import Host
from ..flows import rng
from ..identity import H

ROLE_FOR_PREFIX = {"c2": "c2", "exfil": "exfil", "payload": "payload", "scanner": "scanner",
                   "phish": "phishing", "tor": "tor", "brute": "brute"}
ADDRESSABLE = ("ipv4", "domain", "url")
INTERNAL_ROLES = ("ws", "ws2", "any_ws", "server", "dc", "file", "sql", "web", "fw")


class EndpointError(ValueError):
    """A reference that cannot be resolved (missing host, no indicator of that role, ...)."""


# ------------------------------------------------------------------ addressing
def _seed(campaign):
    try:
        return int((campaign.get("meta") or {}).get("seed", 1))
    except (TypeError, ValueError):
        return 1


def _mode(campaign):
    return ((campaign.get("options") or {}).get("address_mode") or "mapped")


def ioc_host_text(ioc):
    """(ipv4 or None, domain or None) for an addressable IOC (a URL contributes its host)."""
    from . import addressing
    kind, host = addressing.ioc_host(ioc)
    if kind == "ip":
        return host, None
    if kind == "domain":
        return None, host
    return None, None


def mapping(campaign):
    """{host: mapped ipv4} for the whole campaign (collision-free, deterministic). Cached on the
    runtime copy of the campaign under "_map" when the runner made one."""
    m = campaign.get("_map")
    if m is None:
        from . import addressing
        m = addressing.mapped_table(campaign.get("iocs") or [], _seed(campaign))
    return m


def real_ok(ip):
    """(ok, reason) for using `ip` as a real address."""
    from . import addressing
    return addressing.real_mode_check(ip)


def address_for(ioc, campaign):
    """The IPv4 an indicator has in the packets. Mapped mode (default): its slot in the campaign's
    mapped table. Real mode: the indicator's own public IPv4 (a domain with no address of its own
    still gets a mapped one, since a domain indicator carries none)."""
    ip, dom = ioc_host_text(ioc)
    if ip is None and dom is None:
        raise EndpointError("indicator %r has no address" % (ioc.get("value"),))
    if ip and _mode(campaign) == "real":
        ok, why = real_ok(ip)
        if not ok:
            raise EndpointError(why)
        return ip
    got = mapping(campaign).get(ip or dom)
    if got is None:                                          # not part of the campaign's table (synthetic attacker)
        from . import addressing
        got = (addressing.map_ioc_ip(ip, _seed(campaign)) if ip
               else addressing.map_domain_ip(dom, _seed(campaign)))
    return got


# ------------------------------------------------------------------ external hosts
def _build_ext(ctx, ip, fqdn, hops=9):
    name = (fqdn.split(".")[0] if fqdn else "EXT-" + ip.replace(".", "-")).upper()[:30]
    h = Host(name, ip, "02:00:5e:%02x:%02x:%02x" % tuple(rng.randrange(256) for _ in range(3)),
             "linux", "external", ip.rsplit(".", 1)[0] + ".0/24", fqdn or "")
    h.hops = hops
    return h


def external_host(ctx, ref, ioc_or_inline, campaign):
    """An internet-side Host for `ioc_or_inline` (an IOC dict, or an inline dict with ``ip`` and/or
    ``domain``). Cached per Ctx so one indicator is one host. `ref` only labels errors."""
    cache = ctx.__dict__.setdefault("_campaign_ext", {})
    spec = dict(ioc_or_inline or {})
    if "type" not in spec:                                  # inline form
        if spec.get("ip"):
            spec = {"type": "ipv4", "value": spec["ip"]}
        elif spec.get("domain"):
            spec = {"type": "domain", "value": spec["domain"]}
    if spec.get("type") not in ADDRESSABLE:
        raise EndpointError("%s: indicator type %r cannot be a network endpoint" % (ref, spec.get("type")))
    key = (spec["type"], str(spec["value"]).lower(), _mode(campaign))
    if key not in cache:
        ip, dom = ioc_host_text(spec)
        addr = address_for(spec, campaign)
        if addr in {h.ip for h in cache.values()}:           # real mode: two indicators, one address
            return next(h for h in cache.values() if h.ip == addr)
        cache[key] = _build_ext(ctx, addr, dom)
    return cache[key]


def _candidates(campaign, role):
    out = []
    for i, ioc in enumerate(campaign.get("iocs") or []):
        if ioc.get("type") in ADDRESSABLE and (role is None or ioc.get("role") == role):
            out.append((i, ioc))
    return out


def find_ioc(campaign, ref):
    """(index, ioc) a reference like ``c2:1`` / ``ioc:3`` points at, or None for ``attacker``
    with no indicator at all. Wraps around within the role's list."""
    iocs = campaign.get("iocs") or []
    if ref.startswith("ioc:"):
        try:
            i = int(ref[4:])
            return i, iocs[i]
        except (ValueError, IndexError):
            raise EndpointError("%s: no such indicator" % ref) from None
    if ref == "attacker":
        for role in ("scanner", "brute", "c2", "phishing", None):
            c = _candidates(campaign, role)
            if c:
                return c[0]
        return None
    prefix, _, n = ref.partition(":")
    role = ROLE_FOR_PREFIX.get(prefix)
    if role is None:
        raise EndpointError("unknown endpoint reference %r" % ref)
    try:
        n = int(n or 0)
    except ValueError:
        raise EndpointError("bad endpoint reference %r" % ref) from None
    c = _candidates(campaign, role)
    if not c:
        c = _candidates(campaign, None)                     # fall back to any addressable indicator
        if not c:
            raise EndpointError("%s: the campaign has no addressable indicator" % ref)
    return c[n % len(c)]


def is_external_ref(ref):
    return ref == "attacker" or ref.split(":", 1)[0] in ROLE_FOR_PREFIX or ref.startswith("ioc:")


# ------------------------------------------------------------------ internal hosts
def workstations(ctx):
    pre = H("WS-")
    return sorted((n for n in ctx.h if n.startswith(pre)))


def _need(ctx, suffix):
    name = H(suffix)
    if name not in ctx.h:
        raise EndpointError("the built environment has no host %s (needed by the campaign)" % name)
    return ctx.h[name]


def resolve_internal(ctx, role, options=None):
    """Resolve an internal role to a Host. ``ws`` is stable for the whole build (the compromised
    workstation), ``ws2`` is a different one, ``any_ws`` is a fresh pick each call."""
    options = options or {}
    state = ctx.__dict__.setdefault("_campaign_int", {})
    if role == "ws":
        if "ws" not in state:
            pick = H("WS-047")
            ws = workstations(ctx)
            if pick not in ctx.h:
                if not ws:
                    raise EndpointError("the built environment has no workstations")
                pick = ws[rng.randrange(len(ws))]
            state["ws"] = ctx.h[pick]
        return state["ws"]
    if role == "ws2":
        if "ws2" not in state:
            ws = [n for n in workstations(ctx) if n != resolve_internal(ctx, "ws").name]
            if not ws:
                raise EndpointError("the built environment has no second workstation")
            state["ws2"] = ctx.h[ws[rng.randrange(len(ws))]]
        return state["ws2"]
    if role == "any_ws":
        ws = workstations(ctx)
        if not ws:
            raise EndpointError("the built environment has no workstations")
        return ctx.h[ws[rng.randrange(len(ws))]]
    if role == "server":
        tgt = options.get("lateral_target") or "server"
        if tgt != "server":
            return resolve_internal(ctx, tgt, options)
        for suffix in ("FILE1", "WEB1", "SQL1", "DC1"):
            if H(suffix) in ctx.h:
                return ctx.h[H(suffix)]
        raise EndpointError("the built environment has no application or file server")
    if role == "fw":                         # the firewall's inside user leg (a build has FW-A, FW-B, FW-OUT, not FW1)
        for cand in ("FW1", "FW-A"):
            if cand in ctx.h or H(cand) in ctx.h:
                return ctx.h[cand] if cand in ctx.h else ctx.h[H(cand)]
        raise EndpointError("the built environment has no firewall host")
    fixed = {"dc": "DC1", "file": "FILE1", "sql": "SQL1", "web": "WEB1"}
    if role in fixed:
        return _need(ctx, fixed[role])
    if role.startswith("host:"):
        return _need(ctx, role[5:])
    if role in ctx.h:                                       # a bare full name or suffix such as FILE1
        return ctx.h[role]
    if H(role) in ctx.h:
        return ctx.h[H(role)]
    raise EndpointError("unknown internal role %r" % role)


def resolve_endpoint(ctx, ref, campaign):
    """(Host, [ioc indexes], is_external) for a `from`/`to` reference."""
    if is_external_ref(ref):
        found = find_ioc(campaign, ref)
        if found is None:                                   # 'attacker' with no indicators at all
            h = external_host(ctx, ref, {"type": "domain", "value": "attacker.invalid-campaign.example"}, campaign)
            return h, [], True
        i, ioc = found
        return external_host(ctx, ref, ioc, campaign), [i], True
    return resolve_internal(ctx, ref, campaign.get("options")), [], False
