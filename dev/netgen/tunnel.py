"""Opt-in tunnel carriers (network_options "tunnels"): GRE, VXLAN and 6in4 around any scenario's frames.

``Tunneler`` is the ``Engine.wrap`` hook: for every frame of a chosen scenario it returns the outer
frame(s) that carry it, so one inner frame becomes one outer frame, or several IPv4 fragments when the
outer packet would exceed the carrier MTU. Frames of every other scenario pass through untouched.
It draws no random numbers, creates no ``Host`` and keeps only counters and IP identification numbers,
so the inner frame stream (and the engine's draws) equal the untunneled build exactly.

Wire model, one site-to-site pair of tunnel endpoints per rule (addresses derived from a hash of the
rule, 172.16.x.1 and 172.17.x.1):

* GRE (protocol 47): IPv4 or IPv6 packets only, inner EtherType in the GRE protocol field; ARP and
  other non-IP frames never enter an L3 tunnel and pass through.
* VXLAN (UDP 4789, source port from a hash of the inner headers, UDP checksum 0, VNI from the rule):
  the whole inner Ethernet frame, ARP included.
* 6in4 (protocol 41): IPv6 packets only; IPv4 frames and ARP pass through.

The outer Ethernet header reuses the inner frame's MACs: the tunnel ends on the devices at this vantage.
Direction follows the inner MACs (sender below receiver = local to remote), so both directions of a flow
use the same pair. The outer IPv4 header never sets DF and carries a per-direction identification, and an
outer packet longer than the rule's ``mtu`` (default 1500) is fragmented as RFC 791 says: a tunnel without
path-MTU discovery, which also keeps every frame replayable on a standard-MTU interface. ``mtu`` above the
largest frame (9000) leaves them whole. The TCP MSS clamps in ``frames6`` (1436 GRE, 1410 VXLAN) are for
sessions built for a tunnel; a wrapper cannot change an existing session's MSS, so it fragments instead.

Unlike ``VlanTagger`` (one frame in, one frame out, applied inside the writer) the wrapper can emit
several frames and must know the scenario, so it hangs off the engine, before the writer and its tagger.
"""
import hashlib

from .capwap import ip_fragment
from .core import eth
from .frames6 import ETH_IPV6, gre, ipv4_raw, udp_nocsum, vxlan, vxlan_sport

CARRIERS = ("gre", "vxlan", "6in4")
ALL = "*"                                   # a scenario name that matches every scenario
DEFAULT_MTU, MIN_MTU, MAX_MTU = 1500, 576, 9000
_ETH_IPV4 = 0x0800


def _entries(v):
    """The raw tunnel option as dicts. A string "carrier:scenario[,scenario...]" is shorthand."""
    if isinstance(v, (str, dict)):
        v = [v]
    if not isinstance(v, (list, tuple)) or not v:
        raise ValueError("tunnels must be a non-empty list of {carrier, scenarios} objects or 'carrier:scenario' strings")
    for e in v:
        if isinstance(e, str):
            carrier, _, names = e.partition(":")
            e = {"carrier": carrier, "scenarios": [n for n in names.split(",") if n]}
        if not isinstance(e, dict):
            raise ValueError("a tunnel must be an object or a 'carrier:scenario' string")
        yield e


def normalize(v):
    """Canonical form: a list of {"carrier", "scenarios" (sorted, unique), "mtu"} sorted by carrier and scenarios.

    Raises ValueError for an unknown carrier or key, no scenario, a bad mtu, or a scenario named by two
    tunnels (one scenario rides one carrier). The canonical list goes into the build parameters."""
    out, seen = [], set()
    for e in _entries(v):
        unknown = set(e) - {"carrier", "scenarios", "mtu"}
        if unknown:
            raise ValueError("unknown tunnel key(s): " + ", ".join(sorted(unknown)))
        carrier, names, mtu = e.get("carrier"), e.get("scenarios"), e.get("mtu", DEFAULT_MTU)
        if carrier not in CARRIERS:
            raise ValueError("tunnel carrier must be one of " + ", ".join(CARRIERS))
        names = [names] if isinstance(names, str) else names
        if not names or not all(isinstance(n, str) and n for n in names):
            raise ValueError("a tunnel needs at least one scenario name (or '%s' for all)" % ALL)
        if isinstance(mtu, bool) or not isinstance(mtu, int) or not MIN_MTU <= mtu <= MAX_MTU:
            raise ValueError("tunnel mtu must be a whole number %d-%d" % (MIN_MTU, MAX_MTU))
        names = sorted(set(names))
        if seen & set(names) or (out and (ALL in names or ALL in seen)):
            raise ValueError("a scenario can ride only one tunnel ('%s' covers every scenario)" % ALL)
        seen |= set(names)
        out.append({"carrier": carrier, "scenarios": names, "mtu": mtu})
    return sorted(out, key=lambda t: (t["carrier"], t["scenarios"]))


def check_scenarios(tunnels, known):
    """Raise ValueError for a scenario name that is neither ``ALL`` nor in ``known``: a typo must not build the default capture."""
    bad = sorted({n for t in tunnels for n in t["scenarios"]} - set(known) - {ALL})
    if bad:
        raise ValueError("unknown tunnel scenario(s): " + ", ".join(bad))


class _Rule:
    def __init__(self, t):
        self.carrier, self.mtu, self.names = t["carrier"], t["mtu"], tuple(t["scenarios"])
        h = hashlib.sha256(("%s\n%s" % (self.carrier, "\n".join(self.names))).encode()).digest()
        self.local, self.remote = bytes([172, 16, h[0], 1]), bytes([172, 17, h[0], 1])
        self.vni = int.from_bytes(h[1:4], "big") or 1
        self.inner = self.outer = self.frags = self.passed = self.added = 0


class Tunneler:
    """``Engine.wrap`` hook: ``tunneler(tag, frame)`` -> the list of frames to write for that frame."""

    def __init__(self, tunnels, scenario_of):
        """tunnels: ``normalize`` output. scenario_of: engine tag -> scenario name (build_manifest.scenario_of)."""
        self.rules = [_Rule(t) for t in tunnels]
        self._by_name = {n: r for r in self.rules for n in r.names}
        self._scenario_of = scenario_of
        self._for_tag = {}                          # engine tag -> rule or None (tags repeat per frame)
        self._ident = {}                            # outer source address -> last IP identification

    def _rule(self, tag):
        if tag not in self._for_tag:
            self._for_tag[tag] = self._by_name.get(self._scenario_of(tag)) or self._by_name.get(ALL)
        return self._for_tag[tag]

    def __call__(self, tag, frame):
        r = self._rule(tag)
        if r is None:
            return [frame]
        et = int.from_bytes(frame[12:14], "big")
        if r.carrier == "vxlan":
            body, proto = udp_nocsum(vxlan_sport(frame), 4789, vxlan(frame, r.vni)), 17
        elif et == ETH_IPV6 and r.carrier == "6in4":
            body, proto = frame[14:], 41
        elif et in (_ETH_IPV4, ETH_IPV6) and r.carrier == "gre":
            body, proto = gre(frame[14:], et), 47
        else:
            r.passed += 1
            return [frame]
        src, dst = (r.local, r.remote) if frame[6:12] <= frame[0:6] else (r.remote, r.local)
        ident = self._ident[src] = (self._ident.get(src, 0) + 1) & 0xFFFF or 1
        out = ip_fragment(eth(frame[0:6], frame[6:12], _ETH_IPV4, ipv4_raw(src, dst, proto, body, ident=ident, df=False)), r.mtu)
        r.inner += 1
        r.outer += len(out)
        r.frags += len(out) > 1
        r.added += sum(len(f) for f in out) - len(frame)
        return out

    def report(self):
        """Per tunnel: frames wrapped, outer frames written, how many wrapped frames were fragmented, bytes added
        to the file (frame bytes before the writer pads, outer less inner), and frames a carrier could not take."""
        return [{"carrier": r.carrier, "scenarios": list(r.names), "mtu": r.mtu, "inner_frames": r.inner,
                 "outer_frames": r.outer, "fragmented": r.frags, "added_bytes": r.added, "passed_through": r.passed}
                for r in self.rules]
