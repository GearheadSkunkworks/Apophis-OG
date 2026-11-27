"""Two IPv6 link-local attack scenarios built on the dual-stack layer (``netgen.dualstack``).

* ``rogue_ra``    "mitm6 style": a compromised workstation advertises itself with rogue Router Advertisements,
  answers victims' DHCPv6 requests with itself as the DNS server, serves ``wpad`` over IPv6 and collects NTLM
  authentication from the HTTP proxy-discovery fetch, then reuses the captured identity against a file server
  over IPv4 (the relay leg).
* ``nd_flood``    neighbour-discovery flood: a burst of Router Advertisements from random source addresses, each
  announcing a different /64 prefix, and a storm of Neighbor Solicitations for addresses that do not exist, which
  make the gateway solicit each one three times.

Additive by construction, like the dual-stack option: every flow runs inside ``Layer.isolated()`` (the shared random
streams and the hosts' ephemeral ports are put back afterwards) and all decisions come from ``random.Random``
instances created per flow and kept in locals, never in a module dictionary. The scenario is selected explicitly
(it is a registry entry), so nothing here runs in a default build.
"""
import base64
import random
import struct

from . import core, dualstack as DS, flows as F, frames6 as F6, protocols as P

RA_REPEAT_S = (20.0, 45.0)          # a rogue RA is repeated at about this interval
MAX_VICTIMS = 6
WPAD_UA = "WinHttp-Autoproxy-Service/5.1"


def _rng(*parts):
    return random.Random(DS._h32("ipv6atk", *parts))


def _victims(ctx, atk, n):
    """Workstations on the attacker's segment (same gateway), a stable subset in name order."""
    same = [h for h in sorted(ctx.h.values(), key=lambda h: h.name)
            if h is not atk and "workstation" in getattr(h, "role", "").lower() and core.same_subnet(h, atk)]
    return same[:max(1, min(n, MAX_VICTIMS))]


def _take(eng, L, tag, ts, k, fn):
    eng.schedule(ts, lambda: L.isolated("atk:%s" % k, fn), tag)


# ------------------------------------------------------------------ mitm6 style
def _rogue_ra(L, atk):
    """Router Advertisement from a workstation: M and O set (so hosts ask DHCPv6 for configuration), no default
    router (lifetime 0), an on-link prefix that SLAAC must not use (autonomous flag clear)."""
    return F6.ra(atk.mac, L.map.lla(atk), prefixes=[(DS._prefix(L, atk.ipb[2]), 64, 2592000, 604800, 0x80)],
                 lifetime=0, flags=0xC0)


def _dhcp_takeover(L, victim, atk, ts, rng):
    """Solicit, the attacker's Advertise, Request, Reply: the DNS server on offer is the attacker's own address."""
    xid, iaid = DS._h32("ipv6atk", victim.name, "xid"), DS._h32("iaid", victim.name)
    cid, sid = DS._opt(1, DS._duid(victim.mac)), DS._opt(2, DS._duid(atk.mac))
    iana = DS._opt(3, struct.pack("!III", iaid, 0, 0))
    lease = DS._opt(3, struct.pack("!III", iaid, 300, 480) + DS._opt(5, L.map.addr(victim) + struct.pack("!II", 600, 900)))
    oro, elapsed = DS._opt(6, struct.pack("!HH", 23, 24)), DS._opt(8, struct.pack("!H", 0))
    dns, dom = DS._opt(23, L.map.addr(atk)), DS._opt(24, DS._domain(L.ident.domain))
    vlla, alla = L.map.lla(victim), L.map.lla(atk)
    mc = F6.mcast_mac6(DS.ALL_DHCP_AGENTS)

    def to_srv(t, m):
        return (t, DS._udp6_frame(victim.mac, mc, vlla, DS.ALL_DHCP_AGENTS, 546, 547, m, hop=1))

    def to_cli(t, m):
        return (t, DS._udp6_frame(atk.mac, victim.mac, alla, vlla, 547, 546, m, hop=64))
    d = rng.uniform(0.001, 0.004)
    return [to_srv(ts, DS.dhcp6_msg(1, xid, [cid, elapsed, iana, oro])),
            to_cli(ts + d, DS.dhcp6_msg(2, xid, [cid, sid, lease, dns, dom])),
            to_srv(ts + 0.03, DS.dhcp6_msg(3, xid, [cid, sid, elapsed, lease, oro])),
            to_cli(ts + 0.03 + d, DS.dhcp6_msg(7, xid, [cid, sid, lease, dns, dom]))]


def _wpad(L, victim, atk, ts, rng):
    """The victim resolves ``wpad`` through the attacker's DNS and fetches /wpad.dat, answering the attacker's NTLM challenge."""
    ctx = L.ctx
    name = "wpad." + L.ident.domain
    nb = L.ident.domain.split(".")[0].upper()
    out = list(ctx.arp_for(victim, atk, ts))
    t = ts
    for qtype in (P.DNS_A, P.DNS_AAAA):                      # hosts ask for both; the attacker answers with itself
        txid, sport = ctx.next_txid(), victim.eph()
        ans = [(P.DNS_AAAA, L.map.addr(atk))] if qtype == P.DNS_AAAA else []
        out.append(ctx.udp(victim, atk, sport, 53, P.dns_query(txid, name, qtype), t))
        out.append(ctx.udp(atk, victim, 53, sport, P.dns_response(txid, name, qtype, ans, ttl=300), t + rng.uniform(0.0006, 0.003),
                           vantage=victim))
        t += 0.002
    s = ctx.tcp(victim, atk, 80, t + 0.01).handshake()
    user = P.username_for(victim.name)

    def req(auth=None):
        h = {"Authorization": "NTLM " + base64.b64encode(auth).decode()} if auth else None
        return P.http_request("GET", "/wpad.dat", "wpad", WPAD_UA, headers=h)

    def deny(auth=None):
        v = "NTLM " + base64.b64encode(auth).decode() if auth else "NTLM"
        return P.http_response("401 Unauthorized", b"", "text/html", s.t, server="Microsoft-HTTPAPI/2.0",
                               headers={"WWW-Authenticate": v})
    s.c2s(req(), think=0.001)
    s.s2c(deny(), think=0.002)
    s.c2s(req(P.ntlm_negotiate()), think=0.002)
    s.s2c(deny(P.ntlm_challenge(nb, dns_domain=L.ident.domain)), think=0.002)
    s.c2s(req(P.ntlm_authenticate(user, nb, victim.name)), think=0.003)
    s.s2c(P.http_response("200 OK", b"function FindProxyForURL(u,h){return \"DIRECT\";}", "application/x-ns-proxy-autoconfig", s.t,
                          server="Microsoft-HTTPAPI/2.0"), think=0.002)
    return F.merged(out, s.close(think=0.01)), user


def rogue_ra(ctx, eng, tag, win, atk):
    """Schedule the rogue-RA / DHCPv6 / WPAD / relay story on ``eng`` for the window ``win``."""
    L = DS.campaign_layer(ctx)
    lo, hi = win
    victims = _victims(ctx, atk, int(2 + 6 * min(1.0, max(0.0, ctx.scale * 25))))
    rng = _rng("rogue-ra")
    fileserver = ctx.h[next(n for n in ctx.h if n.endswith("FILE1"))]
    k = 0
    t = lo + 20
    while t < hi - 120:                                      # the RA is repeated, as the tool does
        k += 1
        _take(eng, L, tag, t, k, lambda t=t: [(t, _rogue_ra(L, atk))])
        t += rng.uniform(*RA_REPEAT_S)
    for i, v in enumerate(victims):
        t0 = lo + 40 + i * rng.uniform(45, 110)
        k += 1

        def story(v=v, t0=t0):
            r = _rng("rogue-ra", v.name)
            out = L.ndp.before_flow(v, atk, t0)
            out += _dhcp_takeover(L, v, atk, t0 + 0.2, r)
            wp, user = _wpad(L, v, atk, t0 + r.uniform(3, 8), r)
            out += wp
            out += F.smb_file_activity(L.ctx4, atk, fileserver, t0 + 14, n_files=1, write_ratio=0.0, share="C$", ntlm_user=user)
            return sorted(out, key=lambda p: p[0])
        _take(eng, L, tag, t0, k, story)


# ------------------------------------------------------------------ neighbour-discovery flood
def _random_mac(r):
    return bytes([0x02 | (r.randrange(256) & 0xFC)]) + bytes(r.randrange(256) for _ in range(5))


def nd_flood(ctx, eng, tag, win, atk):
    """Schedule an RA flood and a Neighbor Solicitation storm from ``atk`` on its own segment."""
    L = DS.campaign_layer(ctx)
    lo, hi = win
    gw = L.link.gateway_for(atk)
    n_ra = int(300 + 1200 * min(1.0, ctx.scale * 25))
    n_ns = int(150 + 600 * min(1.0, ctx.scale * 25))
    start = lo + 60
    dur = min(240.0, (hi - lo) * 0.5)

    def burst(first, n, kind):
        def run():
            r = _rng("nd-flood", kind)
            out = L.ndp.before_flow(atk, gw, first) if gw is not None else []
            t = first
            for _ in range(n):
                t += r.uniform(0.2, 1.8) * dur / n
                if kind == "ra":                             # a new random source and a new /64 in every advertisement
                    mac = _random_mac(r)
                    prefix = bytes([0x20, 0x01, 0x0d, 0xb8]) + bytes(r.randrange(256) for _ in range(4)) + bytes(8)
                    out.append((t, F6.ra(mac, F6.link_local(mac), prefixes=[(prefix, 64, 2592000, 604800)], lifetime=1800, flags=0x08)))
                else:                                        # an address nobody holds: the gateway asks three times, a second apart
                    target = DS._prefix(L, atk.ipb[2])[:8] + bytes(r.randrange(256) for _ in range(8))
                    out.append((t, F6.ns(atk.mac, L.map.lla(atk), target)))
                    if gw is not None:
                        out += [(t + 0.001 + j * 1.0, F6.ns(gw.mac, L.map.lla(gw), target)) for j in range(3)]
            return sorted(out, key=lambda p: p[0])
        return run
    _take(eng, L, tag, start, 1, burst(start, n_ra, "ra"))
    _take(eng, L, tag, start + dur + 30, 2, burst(start + dur + 30, n_ns, "ns"))
