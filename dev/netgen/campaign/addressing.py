"""Address mapping and bogon checks for campaign indicators.

Default mode is *mapped*: indicator IPv4 addresses and the addresses behind indicator domains are re-addressed
into 198.18.0.0/15 (RFC 2544 benchmark range, not globally routable), so a replayed capture can never talk to a
real indicator host. Real addresses are an explicit opt-in and must pass ``real_mode_check``.

Mapping is a pure function of (value, seed): ``sha256`` picks a first-choice slot and linear probing resolves any
clash against the other values of the same campaign, so one campaign never maps two values to one address.
Host parts .0 and .255 are never produced. IPv6 indicators are carried but unsupported by the runner.
"""
import hashlib
import ipaddress
from urllib.parse import urlsplit

MAPPED_POOL = ipaddress.ip_network("198.18.0.0/15")
_BASE = int(MAPPED_POOL.network_address)
_SIZE = MAPPED_POOL.num_addresses

_SPECIAL = [
    ("0.0.0.0/8", "unspecified"), ("10.0.0.0/8", "private"), ("100.64.0.0/10", "cgnat"),
    ("127.0.0.0/8", "loopback"), ("169.254.0.0/16", "link-local"), ("172.16.0.0/12", "private"),
    ("192.0.0.0/24", "reserved"), ("192.0.2.0/24", "documentation"), ("192.88.99.0/24", "reserved"),
    ("192.168.0.0/16", "private"), ("198.18.0.0/15", "benchmark"), ("198.51.100.0/24", "documentation"),
    ("203.0.113.0/24", "documentation"), ("224.0.0.0/4", "multicast"), ("240.0.0.0/4", "reserved"),
]
_SPECIAL = [(ipaddress.ip_network(n), label) for n, label in _SPECIAL]


def _addr(ip):
    try:
        return ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None


def classify(ip):
    """'global' for a routable public IPv4, else a label: private, loopback, link-local, multicast, reserved,
    documentation, benchmark, cgnat, unspecified, broadcast, ipv6, invalid."""
    a = _addr(ip)
    if a is None:
        return "invalid"
    if a.version == 6:
        return "ipv6"
    if int(a) == 0xFFFFFFFF:
        return "broadcast"
    for net, label in _SPECIAL:
        if a in net:
            return label
    return "global"


def is_reserved(ip):
    """True for anything that is not a plain public IPv4 (private, loopback, multicast, documentation, ...)."""
    return classify(ip) != "global"


def is_mapped(ip):
    a = _addr(ip)
    return bool(a and a.version == 4 and a in MAPPED_POOL)


def real_mode_check(ip):
    """(ok, reason). Real mode refuses reserved, private, loopback, link-local, multicast, documentation,
    benchmark and IPv6 values; only routable public IPv4 passes."""
    c = classify(ip)
    if c == "global":
        return True, ""
    return False, "%s is a %s address; real mode only accepts public IPv4 addresses" % (str(ip)[:64], c)


def is_ipv6(value):
    a = _addr(value)
    return bool(a and a.version == 6)


def _slot_ok(off):
    return (off & 0xFF) not in (0, 0xFF)


def _pick(kind, value, seed, taken):
    h = int.from_bytes(hashlib.sha256(("%s|%s|%s" % (seed, kind, value)).encode("utf-8")).digest()[:8], "big")
    off = h % _SIZE
    taken = taken or ()
    for _ in range(_SIZE):
        if _slot_ok(off):
            ip = str(ipaddress.ip_address(_BASE + off))
            if ip not in taken:
                return ip
        off = (off + 1) % _SIZE
    raise RuntimeError("mapped address pool exhausted")


def map_ioc_ip(ip, seed, taken=None):
    """Deterministic mapped address in 198.18.0.0/15 for a real IPv4. ``taken`` (a set of already-assigned
    mapped addresses) makes probing skip them; use ``mapped_table`` for a whole campaign."""
    return _pick("ip", str(ip).strip(), seed, taken)


def map_domain_ip(domain, seed, taken=None):
    """Deterministic mapped address for the host a domain indicator resolves to."""
    return _pick("dom", str(domain).strip().lower().rstrip("."), seed, taken)


def url_host(url):
    """Host part of a URL indicator (lowercase, no port, no brackets) or ''."""
    try:
        h = urlsplit(url if "://" in url else "//" + url).hostname
    except ValueError:
        return ""
    return (h or "").lower()


def ioc_host(ioc):
    """(kind, host) for an IOC that names a network endpoint: ('ip'|'domain'|'ipv6', value) or (None, '')."""
    t, v = ioc.get("type"), str(ioc.get("value", ""))
    if t == "ipv4":
        return "ip", v
    if t == "ipv6":
        return "ipv6", v
    if t == "domain":
        return "domain", v.lower().rstrip(".")
    if t == "url":
        h = url_host(v)
        if not h:
            return None, ""
        a = _addr(h)
        if a is not None:
            return ("ip" if a.version == 4 else "ipv6"), str(a)
        return "domain", h
    return None, ""


def mapped_table(iocs, seed):
    """{value: mapped_ip} for every IPv4 and domain endpoint named by the IOCs (a URL contributes its host).
    Collision-free inside the table, inside 198.18.0.0/15, stable for a given (iocs, seed). IPv6 is skipped."""
    hosts = {}
    for ioc in iocs:
        kind, h = ioc_host(ioc)
        if kind in ("ip", "domain") and h:
            hosts[h] = kind
    taken, table = set(), {}
    for h in sorted(hosts):
        ip = map_ioc_ip(h, seed, taken) if hosts[h] == "ip" else map_domain_ip(h, seed, taken)
        taken.add(ip)
        table[h] = ip
    return table


def unsupported_ipv6(iocs):
    """IPv6 values (indicators or URL hosts) the runner cannot place; record them in the report."""
    out = []
    for ioc in iocs:
        kind, h = ioc_host(ioc)
        if kind == "ipv6" and h not in out:
            out.append(h)
    return out
