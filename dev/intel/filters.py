"""Clean an IOC list before it is used in a campaign.

clean(iocs, allow_private=False, drop_documentation=False, allow_list=True) -> (kept, dropped)
dropped is a list of (ioc, reason).

Dropped:
  * ipv4/ipv6 that are loopback, link-local, multicast, unspecified (0.0.0.0), broadcast, RFC 1918 /
    ULA private, reserved (240/4), carrier-grade NAT 100.64/10 -> reason "private/reserved address"
    (kept when allow_private=True).
  * Documentation ranges (RFC 5737 192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32) and the
    RFC 2544 benchmarking range 198.18/15 are KEPT by default because demos and tests use them;
    drop_documentation=True removes them.
  * Duplicates (same intel.model.ioc_key): the highest-confidence one is kept, tags/techniques merged.
Allow-listed (well-known benign): public DNS resolvers (8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1, 9.9.9.9,
149.112.112.112, 208.67.222.222/220.220, 2606:4700:4700::1111...), and apex domains of major sites
(google.com, microsoft.com, cloudflare.com, github.com, amazonaws.com, ...) including subdomains and
URLs/emails on them. Allow-listed IOCs are dropped with reason "allow-listed" unless allow_list=False,
in which case they are kept and tagged "allow-listed". Reserved names (example.com/.org/.net, *.example,
*.test, *.invalid, *.localhost) are never allow-listed.
"""
import ipaddress
from urllib.parse import urlsplit

from . import model

_DOC_NETS = [ipaddress.ip_network(n) for n in
             ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15", "2001:db8::/32")]
ALLOW_IPS = {
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222",
    "208.67.220.220", "2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111",
    "2606:4700:4700::1001", "2620:fe::fe", "9.9.9.10",
}
ALLOW_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "microsoft.com",
    "windows.com", "windowsupdate.com", "office.com", "office365.com", "live.com", "outlook.com",
    "microsoftonline.com", "azure.com", "azureedge.net", "cloudflare.com", "cloudflare-dns.com",
    "github.com", "githubusercontent.com", "amazonaws.com", "amazon.com", "apple.com", "icloud.com",
    "facebook.com", "twitter.com", "linkedin.com", "wikipedia.org", "mozilla.org", "akamai.net",
    "akamaiedge.net", "fastly.net", "digicert.com", "letsencrypt.org", "ubuntu.com", "debian.org",
    "yahoo.com", "youtube.com", "dropbox.com", "adobe.com", "zoom.us", "slack.com", "cisco.com",
    "oracle.com", "ibm.com", "paypal.com", "ntp.org", "pool.ntp.org", "root-servers.net",
    # government, standards and the security press: reference sites that reports cite, never attacker hosts
    "cisa.gov", "dhs.gov", "usa.gov", "fbi.gov", "nist.gov", "mitre.org", "cve.org", "first.org", "stopransomware.gov",
    "fortinet.com", "trendmicro.com", "sophos.com", "crowdstrike.com", "talosintelligence.com", "paloaltonetworks.com",
    "mandiant.com", "virustotal.com", "bleepingcomputer.com", "securityaffairs.com", "techtarget.com", "krebsonsecurity.com",
    "thehackernews.com", "arcticwolf.com", "truesec.com", "itsecurityguru.org", "welivesecurity.com", "securelist.com",
}
_REFERENCE_TLDS = {"gov", "mil", "edu"}          # any host under these is a public institution, not infrastructure to replay
_RESERVED_NAMES = {"example.com", "example.org", "example.net"}
_RESERVED_TLDS = {"example", "test", "invalid", "localhost"}


def _ip(ioc):
    try:
        return ipaddress.ip_address(ioc["value"])
    except (ValueError, KeyError):
        return None


def _is_private(ip):
    if ip.version == 4 and str(ip) == "255.255.255.255":
        return True
    if any(ip in n for n in _DOC_NETS):
        return False
    cgnat = ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10")
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_unspecified or ip.is_reserved or cgnat)


def _host_of(ioc):
    t, v = ioc.get("type"), ioc.get("value", "")
    if t == "domain":
        return v
    if t == "url":
        try:
            return (urlsplit(v).hostname or "").lower()
        except ValueError:
            return ""
    if t == "email":
        return v.rsplit("@", 1)[-1].lower()
    return ""


def _allow_listed(ioc):
    t = ioc.get("type")
    if t in ("ipv4", "ipv6"):
        return ioc["value"] in ALLOW_IPS
    h = _host_of(ioc)
    if not h:
        return False
    if h in _RESERVED_NAMES or h.rsplit(".", 1)[-1] in _RESERVED_TLDS:
        return False
    if t == "url" and h in ALLOW_IPS:
        return True
    return h.rsplit(".", 1)[-1] in _REFERENCE_TLDS or any(h == d or h.endswith("." + d) for d in ALLOW_DOMAINS)


def clean(iocs, allow_private=False, drop_documentation=False, allow_list=True):
    """See module docstring. Returns (kept, dropped_with_reason); input is not modified."""
    kept, dropped = [], []
    for ioc in iocs:
        ioc = dict(ioc, tags=list(ioc.get("tags", [])), techniques=list(ioc.get("techniques", [])))
        t = ioc.get("type")
        if t in ("ipv4", "ipv6"):
            ip = _ip(ioc)
            if ip is None:
                dropped.append((ioc, "invalid address"))
                continue
            if drop_documentation and any(ip in n for n in _DOC_NETS):
                dropped.append((ioc, "documentation/benchmark address"))
                continue
            if not allow_private and _is_private(ip):
                dropped.append((ioc, "private/reserved address"))
                continue
        if _allow_listed(ioc):
            if allow_list:
                dropped.append((ioc, "allow-listed"))
                continue
            ioc["tags"] = model.norm_tags(ioc["tags"] + ["allow-listed"])
        kept.append(ioc)
    uniq, by_key = [], {}
    for ioc in kept:
        k = model.ioc_key(ioc)
        if k in by_key:
            model.merge(by_key[k], ioc)
            dropped.append((ioc, "duplicate (merged into the first copy)"))
        else:
            by_key[k] = ioc
            uniq.append(ioc)
    return uniq, dropped
