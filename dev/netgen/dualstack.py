"""Opt-in dual-stack IPv6 slice of the day (network option ``ipv6``).

The layer is purely additive. It is scheduled after the baseline day and every selected scenario, and
every packet it emits carries one of the five ``v6:`` tags (``TAGS``), so removing those frames leaves the
option-off capture: same packet count, same per-protocol mix, same 5-tuples and timestamps.

How the default day stays untouched:

* No shared random stream is advanced. Each flow runs inside ``Layer.isolated()``: the engine's seeded
  generators (the ones ``netgen.reseed_all()`` reseeds, plus the global ``random``) are saved, reseeded
  from the flow's index, and restored afterwards. Scheduling decisions and the NDP model draw from
  ``random.Random`` instances held on the layer (never in a module dictionary, so ``incidents``'
  generator scan and ``reseed_all()`` do not see them).
* Hosts keep their own ephemeral-port counters: ``Layer.isolated()`` swaps in a private counter per
  host for the duration of a flow and puts the baseline value back. No ``Host`` is ever created.
* The v6 flows are the existing flow functions run on ``Layer.ctx``, a shallow copy of the build's ``Ctx``
  whose ``tcp``/``udp``/``arp_for`` produce IPv6 frames and NDP, with private DNS, Kerberos-ticket and
  client-DNS caches. ``Ctx.tcp()`` switches to ``TcpSession6`` only on that copy (``Ctx.v6`` is None on
  the build's own context).
* Addresses are derived, never drawn (``frames6``): internal hosts get a ULA from the company identity,
  external hosts a 2001:db8::/32 documentation address. Servers and gateways are always dual-stack; a
  workstation is dual-stack when a hash of its name falls under the configured share.

This module declares no ``rng``/``SEED`` pair, so ``reseed_all()`` skips it.
"""
import copy
import random
import struct
import types
import zlib

from . import core, frames6 as F6

TAGS = ("v6:nd", "v6:dhcp", "v6:dns", "v6:https", "v6:smb")     # the only tags this layer emits
DEFAULT_SHARE = 0.25
MLD_QUERY, MLD_QUERY_INTERVAL, RA_INTERVAL = 130, 125.0, 600.0   # ICMPv6 type, seconds, seconds
ALL_DHCP_AGENTS = bytes.fromhex("ff020000000000000000000000010002")
LLMNR_GROUP = bytes.fromhex("ff020000000000000000000000010003")
MDNS_GROUP = bytes.fromhex("ff0200000000000000000000000000fb")


def _h32(*parts):
    return zlib.crc32(":".join(str(p) for p in parts).encode())


def _gens():
    """The shared generators a flow may draw from, in a fixed order: every netgen module that
    ``reseed_all()`` reseeds, plus the global ``random``. A fixed order keeps per-flow seeds stable."""
    from . import _engine_modules
    return [m.rng for m in _engine_modules() if hasattr(m, "rng") and hasattr(m, "SEED")] + [random]


# ------------------------------------------------------------------ addressing
class V6Map:
    """Host -> IPv6 address, memoised; every address is a pure function of the host.

    The memo is keyed by ``id(host)`` and keeps the host itself, so a throwaway host (a scan's absent address,
    an endpoint made inside one action) can never be freed and have its id reused by a different host."""

    def __init__(self, link, ident):
        self.link, self.ident = link, ident
        self._a, self._l = {}, {}

    def addr(self, h):
        e = self._a.get(id(h))
        if e is None:
            inside = h.ipb[:3] in self.link.fw
            e = self._a[id(h)] = (h, F6.ula(self.ident, h.ipb[2], h.mac) if inside else F6.external(h.ip))
        return e[1]

    def lla(self, h):
        e = self._l.get(id(h))
        if e is None:
            e = self._l[id(h)] = (h, F6.link_local(h.mac))
        return e[1]


# ------------------------------------------------------------------ L2/L3 helpers
def _frame(smac, dmac, src, dst, nh, seg, hop):
    return core.eth(dmac, smac, F6.ETH_IPV6, F6.ipv6(src, dst, nh, seg, hop=hop))


class NdpModel:
    """IPv6 twin of ``core.ArpModel``: a neighbour-cache so each flow is preceded by an observable
    NS/NA exchange when the entry is stale. Draws only from its own private generator."""

    def __init__(self, layer):
        self.L = layer
        self.cache = {}
        self.rng = random.Random(_h32("ipv6", "ndp"))

    def _expiry(self, requester):
        low = requester.os.lower()
        if "pan-os" in low:
            return 1800 * self.rng.uniform(0.9, 1.1)
        if requester.ttl == 128:
            return 45 * self.rng.uniform(1.0, 2.2)
        return 60 * self.rng.uniform(1.0, 3.0)

    def resolve(self, req, tgt, ts):
        L = self.L
        gw = id(tgt) in L.gw_ids
        taddr = L.map.lla(tgt) if gw else L.map.addr(tgt)
        key = (req.mac, taddr)
        if self.cache.get(key, 0) > ts:
            return []
        self.cache[key] = ts + self._expiry(req)
        src = L.map.lla(req) if gw else L.map.addr(req)
        flags = F6.NA_SOLICITED | F6.NA_OVERRIDE | (F6.NA_ROUTER if gw else 0)
        return [(ts, F6.ns(req.mac, src, taddr)),
                (ts + self.rng.uniform(0.00008, 0.0006), F6.na(tgt.mac, req.mac, taddr, src, flags=flags))]

    def before_flow(self, a, b, ts, vantage=None):
        """NS/NA exchanges that precede a flow a->b as seen on vantage's segment (mirrors ``ArpModel.before_flow``)."""
        vantage = vantage or a
        out = []
        if core.same_subnet(a, b):
            out += self.resolve(a, b, ts)
            out += self.resolve(b, a, ts + 0.002)
        else:
            local = a if core.same_subnet(a, vantage) else b
            remote = b if local is a else a
            gw = self.L.link.gateway_toward(local, remote)
            if gw is not None:
                out += self.resolve(local, gw, ts)
                out += self.resolve(gw, local, ts + 0.002)
        return out


class TcpSession6(core.TcpSession):
    """``TcpSession`` over IPv6: same timing, sequencing and ACK behaviour, framing replaced.

    The MSS option is 20 bytes smaller than the IPv4 session would offer (1440 on a 1460 path) so no
    segment exceeds a 1500-byte path MTU. IP options do not exist in IPv6 and are ignored."""

    def __init__(self, link, v6map, client, server, dport, t0, **kw):
        super().__init__(link, client, server, dport, t0, **kw)
        self.v6 = v6map
        self.mss -= 20

    def _frame(self, a, b, sport, dport, seq, ack, flags, win, payload=b"", opts=b""):
        dmac, smac, hop = self.link.addr(a, b, self.vantage)
        src, dst = self.v6.addr(a), self.v6.addr(b)
        seg = F6.tcp6(src, dst, sport, dport, seq, ack, flags, win, payload, opts)
        flow = _h32(src.hex(), dst.hex(), min(sport, dport), max(sport, dport)) & 0xFFFFF
        return core.eth(dmac, smac, F6.ETH_IPV6, F6.ipv6(src, dst, F6.NH_TCP, seg, hop=hop, flow=flow))


# ------------------------------------------------------------------ DHCPv6 (RFC 8415)
def _opt(code, data):
    return struct.pack("!HH", code, len(data)) + data


def _duid(mac):
    return struct.pack("!HH", 3, 1) + mac                    # DUID-LL, hardware type Ethernet


def _domain(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"


def dhcp6_msg(mtype, xid, opts):
    return bytes([mtype]) + (xid & 0xFFFFFF).to_bytes(3, "big") + b"".join(opts)


def _udp6_frame(smac, dmac, src, dst, sport, dport, payload, hop=255):
    return _frame(smac, dmac, src, dst, F6.NH_UDP, F6.udp6(src, dst, sport, dport, payload), hop)


# ------------------------------------------------------------------ the layer
class Layer:
    """Everything the option builds: the address map, NDP model, the v6 ``Ctx`` and the isolation wrapper."""

    def __init__(self, ctx, ident, share, chatter, dc_names):
        self.base, self.ident, self.share, self.chatter = ctx, ident, share, chatter
        self.dc_names = dc_names
        self.link = ctx.link
        self.map = V6Map(ctx.link, ident)
        self.gw_ids = {id(h) for h in ctx.link.fw.values()} | {id(ctx.link.fw_out)}
        self.ndp = NdpModel(self)
        self.gens = _gens()
        self.ports = {}
        self.dual = []
        pool = {id(h): h for h in ctx.h.values()}
        for h in ctx.isp_resolvers:
            pool[id(h)] = h
        for v in ctx.sites.values():
            pool[id(v[1])] = v[1]
        self.pool = list(pool.values())
        c6 = self.ctx = copy.copy(ctx)                       # shallow: PKI, key log, hosts, sites are shared
        c6.v6 = self                                         # the Ctx.tcp() switch: only this copy has it
        c6.dns_cache, c6.tgs_cache, c6._client_dns = {}, set(), {}
        c6.txid = 1 + _h32("ipv6", "txid") % 60000
        c6.arp_for = self.ndp.before_flow
        c6.udp = types.MethodType(_ctx_udp, self)            # c6.udp(...) calls from the flow code reach the layer
        c4 = self.ctx4 = copy.copy(ctx)                      # IPv4 legs of a v6 story (a relay): private ARP, DNS and ticket caches
        c4.arp, c4.dns_cache, c4.tgs_cache, c4._client_dns = core.ArpModel(ctx.link), {}, set(), {}
        c4.txid = 1 + _h32("ipv6", "txid4") % 60000

    # -- seams used by flows.Ctx -------------------------------------------------------------
    def session(self, client, server, dport, t, **kw):
        return TcpSession6(self.link, self.map, client, server, dport, t, **kw)

    def udp_frame(self, a, b, sport, dport, payload, vantage, tos=0):
        dmac, smac, hop = self.link.addr(a, b, vantage)
        src, dst = self.map.addr(a), self.map.addr(b)
        flow = _h32(src.hex(), dst.hex(), min(sport, dport), max(sport, dport)) & 0xFFFFF
        return core.eth(dmac, smac, F6.ETH_IPV6,
                        F6.ipv6(src, dst, F6.NH_UDP, F6.udp6(src, dst, sport, dport, payload), hop=hop, tc=tos, flow=flow))

    def echo(self, a, b, vantage, ident, seq, request, payload=b""):
        """One ICMPv6 echo request or reply a->b as seen on vantage's segment (the v6 twin of the IPv4 echo frame)."""
        dmac, smac, hop = self.link.addr(a, b, vantage)
        src, dst = self.map.addr(a), self.map.addr(b)
        return _frame(smac, dmac, src, dst, F6.NH_ICMPV6, F6.echo6(src, dst, ident, seq, payload, reply=not request), hop)

    def ns_probe(self, a, target):
        """A neighbour solicitation from ``a`` for a host that does not exist (the v6 twin of an unanswered ARP request)."""
        return F6.ns(a.mac, self.map.lla(a), self.map.addr(target))

    # -- isolation ---------------------------------------------------------------------------
    def isolated(self, k, fn):
        """Run ``fn`` (which returns a list of frames) on streams of its own, then put every shared
        stream and every host's ephemeral port back where they were."""
        saved = [g.getstate() for g in self.gens]
        ports = [(h, h._port) for h in self.pool]
        for i, g in enumerate(self.gens):
            g.seed(_h32("ipv6", k, i))
        for h in self.pool:
            h._port = self.ports.get(id(h)) or 49152 + _h32("ipv6port", h.name) % 8000
        try:
            return list(fn())
        finally:
            for h, p in ports:
                self.ports[id(h)] = h._port
                h._port = p
            for g, st in zip(self.gens, saved, strict=True):
                g.setstate(st)


def campaign_layer(ctx):
    """A layer for campaign actions (campaign option ``ip_family``): addressing, NDP and the v6 ``Ctx`` only.
    No scheduled chatter, so it adds nothing until an action runs on ``layer.ctx`` inside ``layer.isolated``."""
    from .identity import H, get_current
    return Layer(ctx, get_current(), 0.0, False, (H("DC1"), H("DC2")))


def _ctx_udp(self, a, b, sport, dport, payload, ts, vantage=None, tos=0, df=False, nocsum=False):
    """``Ctx.udp`` for the v6 context: ``df`` does not exist in IPv6 and the UDP checksum is mandatory."""
    return (ts, self.udp_frame(a, b, sport, dport, payload, vantage or a, tos=tos))


# ------------------------------------------------------------------ frame sequences (pure, no draws)
def _mld_query(smac, src):
    body = struct.pack("!HH", 10000, 0) + bytes(16) + bytes([2, 125]) + struct.pack("!H", 0)
    seg = F6.icmpv6(src, F6.ALL_NODES, MLD_QUERY, 0, body)
    return core.eth(F6.mcast_mac6(F6.ALL_NODES), smac, F6.ETH_IPV6,
                    F6.ipv6(src, F6.ALL_NODES, F6.NH_ICMPV6, seg, hop=1, ext=[("hbh", b"\x05\x02\x00\x00")]))


def _groups(L, h):
    g = [F6.solicited_node(L.map.lla(h)), F6.solicited_node(L.map.addr(h))]
    return g + ([LLMNR_GROUP, MDNS_GROUP] if h.ttl == 128 else [MDNS_GROUP])


def _prefix(L, octet):
    return F6.ula(L.ident, octet, bytes(6))[:8] + bytes(8)


def _ra(L, gw, octet, dst=F6.ALL_NODES, dmac=None):
    return F6.ra(gw.mac, L.map.lla(gw), dst, dmac=dmac, prefixes=[(_prefix(L, octet), 64, 2592000, 604800)],
                 mtu=1500, lifetime=1800, flags=0x80)


def boot_frames(L, h, t):
    """What a dual-stack host does when it comes up: DAD for its link-local and ULA address, an MLD join,
    a router solicitation answered by the gateway's RA."""
    gw = L.link.gateway_for(h)
    lla, ula = L.map.lla(h), L.map.addr(h)
    out = [(t, F6.ns(h.mac, F6.UNSPECIFIED, lla, slla=False)),
           (t + 0.3, F6.mld_report(h.mac, lla, _groups(L, h))),
           (t + 1.0, F6.ns(h.mac, F6.UNSPECIFIED, ula, slla=False)),
           (t + 1.3, F6.mld_report(h.mac, lla, _groups(L, h)))]
    ts = t + 2.0 + _h32("ipv6", h.name, "rs") % 1000 / 1000.0
    out.append((ts, F6.rs(h.mac, lla)))
    if gw is not None:
        out.append((ts + 0.012, _ra(L, gw, h.ipb[2], dst=lla, dmac=h.mac)))
    return out


def dhcp_frames(L, h, t):
    """DHCPv6 solicit/advertise/request/reply; the client's gateway is the relay agent that answers."""
    gw = L.link.gateway_for(h)
    srv, srv2 = L.base.h[L.dc_names[0]], L.base.h[L.dc_names[1]]
    xid = _h32("ipv6", h.name, "xid")
    iaid = _h32("iaid", h.name)
    cid, sid = _opt(1, _duid(h.mac)), _opt(2, _duid(srv.mac))
    iana = _opt(3, struct.pack("!III", iaid, 0, 0))
    lease = _opt(3, struct.pack("!III", iaid, 1800, 2880) + _opt(5, L.map.addr(h) + struct.pack("!II", 3600, 7200)))
    oro = _opt(6, struct.pack("!HH", 23, 24))
    elapsed = _opt(8, struct.pack("!H", 0))
    dns = _opt(23, L.map.addr(srv) + L.map.addr(srv2))
    dom = _opt(24, _domain(L.ident.domain))
    lla = L.map.lla(h)
    mc = F6.mcast_mac6(ALL_DHCP_AGENTS)
    relay = L.map.lla(gw) if gw is not None else lla
    rmac = gw.mac if gw is not None else h.mac

    def to_srv(ts, m):
        return (ts, _udp6_frame(h.mac, mc, lla, ALL_DHCP_AGENTS, 546, 547, m, hop=1))

    def to_cli(ts, m):
        return (ts, _udp6_frame(rmac, h.mac, relay, lla, 547, 546, m, hop=64))
    return [to_srv(t, dhcp6_msg(1, xid, [cid, elapsed, iana, oro])),
            to_cli(t + 0.004, dhcp6_msg(2, xid, [cid, sid, lease, dns, dom])),
            to_srv(t + 0.03, dhcp6_msg(3, xid, [cid, sid, elapsed, lease, oro])),
            to_cli(t + 0.036, dhcp6_msg(7, xid, [cid, sid, lease, dns, dom]))]


def mld_round(L, gw, members, t):
    """A general query from the gateway and one report from each member host (``members`` is a list of
    ``(host, delay)``)."""
    out = [(t, _mld_query(gw.mac, L.map.lla(gw)))]
    out += [(t + d, F6.mld_report(h.mac, L.map.lla(h), _groups(L, h))) for h, d in members]
    return sorted(out, key=lambda p: p[0])


# ------------------------------------------------------------------ scheduling
def schedule(ctx, eng, day, scale, opts):
    """Schedule the dual-stack slice on ``eng`` (after the day and all scenarios) and return the layer.

    ``opts``: ``{"share": 0 < share <= 1, "chatter": bool}`` (see ``opengenerator_build.normalize_network_options``)."""
    from . import flows as F, model as M
    from .identity import H, get_current
    L = Layer(ctx, get_current(), opts["share"], opts["chatter"], (H("DC1"), H("DC2")))
    srng = random.Random(_h32("ipv6", "schedule"))
    c6, t_lo, t_hi = L.ctx, M.T_START, M.T_END
    k = [0]

    def at(ts, tag, fn, *a, **kw):
        """A flow built by the existing flow function ``fn`` on the v6 context, on isolated streams."""
        if not t_lo <= ts < t_hi:
            return
        k[0] += 1
        n = k[0]
        eng.schedule(ts, lambda: L.isolated(n, lambda: fn(c6, *a, ts=ts, **kw)), tag)

    def fixed(ts, tag, frames):
        eng.schedule(ts, lambda: frames, tag)

    clients = [w for w in day.workstations if _h32("ipv6", "dual", w.name) % 10000 < opts["share"] * 10000]
    L.dual = [w.name for w in clients]
    file1, dc1 = ctx.h[H("FILE1")], ctx.h[H("DC1")]
    online = {}                                              # host name -> (arrive, leave), for MLD membership
    for ws in clients:
        arrive = srng.uniform(M.local(6, 45), M.local(8, 40))
        leave = srng.uniform(M.local(14, 15), M.local(16))
        online[ws.name] = (arrive, leave)
        if opts["chatter"]:
            fixed(arrive, "v6:nd", boot_frames(L, ws, arrive))
            fixed(arrive + 5.0, "v6:dhcp", dhcp_frames(L, ws, arrive + 5.0))
        t = arrive + srng.uniform(8, 20)
        at(t, "v6:dns", F.resolve_internal, ws, file1)
        at(t + srng.uniform(1, 4), "v6:smb", F.smb_sysvol_gpo, ws)
        at(t + srng.uniform(20, 90), "v6:https", F.https_session, ws, ctx.sites["telemetry.example.org"], requests=1, sizes=[900])
        at(t + srng.uniform(30, 200), "v6:dns", F.dns_lookup, ws, srng.choice(M.BROWSE_SITES), external=True)
        t += srng.uniform(300, 900)
        mean_gap = 1800 / scale                              # half the IPv4 workstation's activity rate
        while t < leave:
            t += srng.expovariate(1 / mean_gap)
            if t >= leave:
                break
            r = srng.random()
            if r < 0.4:
                at(t, "v6:https", F.page_load, ws, ctx.sites[srng.choice(M.BROWSE_SITES)])
            elif r < 0.65:
                at(t, "v6:smb", F.smb_file_activity, ws, file1)
            elif r < 0.85:
                at(t, "v6:dns", F.resolve_internal, ws, dc1)
            else:
                at(t, "v6:dns", F.dns_lookup, ws, srng.choice(M.BROWSE_SITES), external=True)
    if opts["chatter"]:
        legs = {}
        for pfx, gw in ctx.link.fw.items():
            legs.setdefault(id(gw), (gw, []))[1].append(pfx[2])
        for gw, octets in legs.values():                     # one RA per advertised prefix, every ~10 minutes
            for octet in octets:
                t = t_lo + srng.uniform(0, RA_INTERVAL)
                while t < t_hi:
                    fixed(t, "v6:nd", [(t, _ra(L, gw, octet))])
                    t += RA_INTERVAL * srng.uniform(0.5, 1.0)
            members = [h for h in clients if ctx.link.gateway_for(h) is gw] + \
                      [h for h in day.win_servers if ctx.link.gateway_for(h) is gw]
            t = t_lo + srng.uniform(0, MLD_QUERY_INTERVAL)
            while t < t_hi:
                due = [(h, srng.uniform(0.05, 5.0)) for h in members
                       if h.name not in online or online[h.name][0] <= t < online[h.name][1]]
                fixed(t, "v6:nd", mld_round(L, gw, due, t))
                t += MLD_QUERY_INTERVAL
    return L


def report(layer, stats):
    """Manifest block for the option: what was asked for and what it produced, from ``Engine.stats``."""
    tags = {t: {"packets": st[0], "bytes": st[2]} for t, st in sorted(stats.items()) if t.startswith("v6:")}
    return {"share": layer.share, "chatter": layer.chatter, "dual_stack_clients": len(layer.dual),
            "packets": sum(v["packets"] for v in tags.values()), "bytes": sum(v["bytes"] for v in tags.values()),
            "tags": tags}
