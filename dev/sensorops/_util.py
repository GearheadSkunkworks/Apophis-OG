"""Local filesystem helpers shared by the pushes, independent of any sensor provider."""
import ipaddress as _ip
import os
import re as _re
import socket as _socket

# A sensor address must be a BARE host[:port] -- a hostname or IP, with an optional port. It is
# interpolated straight into "https://<sensor>/..." and the API key rides in that request, so if
# it could carry a scheme, path, userinfo ('@') or query it could be crafted into a URL that
# sends the request (and the credential) to a different asset. This pattern permits a hostname,
# an IPv4 address or a bracketed IPv6 address, each with an optional :port, and nothing else.
_SENSOR_RE = _re.compile(
    r"^(?:\[[0-9A-Fa-f:]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)(?::\d{1,5})?$")


def valid_sensor(sensor):
    """Return the sensor address stripped, or raise ValueError if it is not a bare host[:port]."""
    s = (sensor or "").strip()
    if not _SENSOR_RE.match(s):
        raise ValueError(
            "the address must be a hostname or IP with an optional :port — no scheme, "
            "path, '@', '/' or query (got %r)" % sensor)
    m = _re.search(r":(\d{1,5})$", s)
    if m and not (1 <= int(m.group(1)) <= 65535):
        raise ValueError("the port is out of range 1-65535 (got %r)" % sensor)
    return s


def path_hint(expanded):
    """A nudge for the one path mistake that actually happens here.

    macOS home directories live under /Users; /home exists as an empty autofs mount point, so
    a Linux-style path fails silently rather than obviously. Typing the muscle-memory path is
    easy, and the resulting "nothing found" reads as a missing capture. Shared by both pushes'
    preflight checks.
    """
    if not expanded.startswith("/home/"):
        return ""
    guess = "/Users/" + expanded[len("/home/"):]  # release-scan: allow
    if os.path.exists(guess):
        return " Did you mean %s?" % guess
    return " macOS home directories live under /Users, not /home — try %s" % guess


def _bad_sensor_addr(a):
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast


def split_sensor(sensor):
    """(host, port or None) from a validated bare host[:port]; IPv6 brackets removed."""
    s = valid_sensor(sensor)
    port = None
    m = _re.search(r"(?<=[\]\w.-]):(\d{1,5})$", s)
    if m:
        port, s = int(m.group(1)), s[:m.start()]
    if s.startswith("["):
        s = s[1:-1]
    return s, port


def resolve_sensor(sensor, getaddrinfo=None):
    """Resolve a sensor address ONCE and return (host, port, address) with the address to connect to.

    Raises ValueError if the host is, or resolves to, a loopback, link-local (169.254/16, fe80::/10),
    unspecified or multicast address (any one of several answers is enough to refuse). Raises LookupError
    if it does not resolve. RFC 1918 and other private ranges are allowed: labs are private. The caller
    connects to the returned address, so a DNS answer that changes later cannot redirect the request."""
    host, port = split_sensor(sensor)
    low = host.lower().rstrip(".")
    if low == "localhost" or low.endswith(".localhost"):
        raise ValueError("loopback sensor addresses are not allowed")
    lit = None
    try:
        lit = _ip.ip_address(host)
    except ValueError:
        try:                                    # 127.1, 2130706433, 0x7f.1
            lit = _ip.ip_address(_socket.inet_aton(host))
        except (OSError, ValueError):
            lit = None
    if lit is not None:
        if _bad_sensor_addr(lit):
            raise ValueError("loopback, link-local and unspecified sensor addresses are not allowed")
        return host, port, str(lit)
    try:
        infos = (getaddrinfo or _socket.getaddrinfo)(host, port or 443, type=_socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        raise LookupError("cannot resolve %r" % host[:80]) from None
    addrs = []
    for i in infos:
        try:
            a = _ip.ip_address(i[4][0].split("%")[0])
        except ValueError:
            continue
        if _bad_sensor_addr(a):
            raise ValueError("that sensor name resolves to a loopback or link-local address")
        if str(a) not in addrs:
            addrs.append(str(a))
    if not addrs:
        raise LookupError("cannot resolve %r" % host[:80])
    return host, port, addrs[0]
