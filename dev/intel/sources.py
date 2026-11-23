"""Threat-intel feed registry and fetcher.

FEEDS: feed_id -> Feed. fetch(feed_id, limit=50, key=None, cache=True, offline=False, **params) -> [ioc].

Network rules: https only (also for redirects), 20 s timeout, User-Agent 'OpenGenerator-intel/1',
response size cap (FETCH_MAX = 8 MB). The 'url' feed (user-typed URL) additionally refuses hosts that
resolve to loopback/private/link-local/multicast/reserved addresses, validated at connect time (the
validated address is the one connected to, so DNS rebinding cannot swap it) and on every redirect.
API keys: argument or env var (OTX_API_KEY, ABUSECH_AUTH_KEY); sent only as a request header to
the feed's own host; never cached, logged or put in error text.
Feeds set their own roles (C2IntelFeeds => c2, blocklist.de ssh => brute, Tor exit list => tor, ...).
Verification status of each feed is recorded in the `notes` field (checked 2026-11-19).
"""
import ipaddress
import json
import os
import re
import socket
import ssl
import time
import zipfile
import zlib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional
import http.client

from . import cache as _cache
from . import classify, model, parsers

USER_AGENT = "OpenGenerator-intel/1"
TIMEOUT = 20
FETCH_MAX = 8 * 1024 * 1024
MISP_MAX_EVENTS = 8
MAX_REDIRECTS = 3
TOTAL_DEADLINE = 60          # seconds for one whole fetch, however slowly the body arrives
USER_URL_PORTS = (443,)      # extra ports for the 'url' feed must be added here on purpose


class FeedError(Exception):
    """Fetch/parse problem with a message safe to show to a user (never contains keys)."""


@dataclass
class Feed:
    id: str
    title: str
    group: str
    url: str
    needs_key: bool = False
    key_env: str = ""
    key_header: str = ""
    fmt: str = "text"
    parse: Optional[Callable] = None
    ttl: int = 3600
    method: str = "GET"
    kind: str = "simple"          # simple | misp_feed | user_url | post
    terms: str = ""
    notes: str = ""
    max_bytes: int = 0            # response cap for this feed; 0 means FETCH_MAX
    why: str = ""                 # one line on why the feed is offered
    gives: str = ""               # plain statement: indicator types delivered and which of them send traffic
    params: dict = field(default_factory=dict)

    def public(self):
        return {"id": self.id, "title": self.title, "group": self.group, "url": self.url,
                "needs_key": self.needs_key, "key_env": self.key_env, "format": self.fmt, "terms": self.terms,
                "why": self.why, "gives": self.gives}


# ---------------------------------------------------------------- HTTP with SSRF protection
def _ssl_context():
    ctx = ssl.create_default_context()
    try:
        if ctx.cert_store_stats().get("x509_ca", 0) == 0:
            for f in ("/etc/ssl/cert.pem", "/opt/homebrew/etc/ca-certificates/cert.pem",
                      "/usr/local/etc/openssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"):
                if os.path.exists(f):
                    ctx.load_verify_locations(f)
                    break
            else:
                try:
                    import certifi
                    ctx.load_verify_locations(certifi.where())
                except ImportError:
                    pass
    except (ssl.SSLError, OSError):
        pass
    return ctx


def is_public_ip(ip):
    """True only for globally routable addresses."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 6:
        emb = a.ipv4_mapped or (a.sixtofour if a.sixtofour else None)
        if a.teredo:
            return False
        if a in ipaddress.ip_network("64:ff9b::/96"):         # NAT64 well-known prefix
            emb = ipaddress.IPv4Address(int(a) & 0xFFFFFFFF)
        if emb is not None:
            return is_public_ip(str(emb))
    return bool(a.is_global and not (a.is_multicast or a.is_loopback or a.is_link_local
                                     or a.is_private or a.is_reserved or a.is_unspecified))


def resolve_public(host, port=443):
    """Resolve host; return its addresses if ALL are public, else raise FeedError."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError) as e:
        raise FeedError("cannot resolve host %r" % host[:80]) from e
    addrs = []
    for i in infos:
        a = i[4][0]
        if not is_public_ip(a):
            raise FeedError("refusing host %r: resolves to a non-public address" % host[:80])
        if a not in addrs:
            addrs.append(a)
    if not addrs:
        raise FeedError("host %r did not resolve" % host[:80])
    return addrs


def _numeric_spelling(host):
    """True for IPv4 spellings that ip_address() refuses but the resolver accepts (127.1, 2130706433,
    0x7f.1, 0177.0.0.1)."""
    try:
        socket.inet_aton(host)
        return True
    except (OSError, ValueError, UnicodeError):
        return False


def check_user_url(url, allow_ports=()):
    """Validate a user-typed URL for the 'url' feed; returns the normalised URL or raises FeedError.

    https only, no credentials, port 443 unless listed in allow_ports (or USER_URL_PORTS), no address
    literal that is not public, no numeric IPv4 spelling, and every address the host resolves to public."""
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in url):
        raise FeedError("not a usable URL")
    try:
        u = urllib.parse.urlsplit(url)
        host = u.hostname
        port = u.port or 443
    except ValueError:
        raise FeedError("not a usable URL") from None
    if u.scheme.lower() != "https":
        raise FeedError("only https URLs are allowed")
    if not host or u.username is not None or u.password is not None or "@" in u.netloc:
        raise FeedError("URL must have a host and no embedded credentials")
    if port not in set(USER_URL_PORTS) | set(allow_ports):
        raise FeedError("port %d is not allowed" % port)
    if "%" in host:
        raise FeedError("refusing host %r" % host[:80])
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    if literal:
        if not is_public_ip(host):
            raise FeedError("refusing non-public address %s" % host[:80])
    elif _numeric_spelling(host):
        raise FeedError("refusing numeric host spelling %r" % host[:80])
    else:
        resolve_public(host, port)
    return url


def _make_conn_class(ssrf):
    class _Conn(http.client.HTTPSConnection):
        def connect(self):
            if ssrf:
                addrs = resolve_public(self.host, self.port)
                sock = None
                last = None
                for a in addrs:
                    try:
                        sock = socket.create_connection((a, self.port), self.timeout)
                        break
                    except OSError as e:
                        last = e
                if sock is None:
                    raise last or OSError("connect failed")
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
            else:
                super().connect()
    return _Conn


class _Handler(urllib.request.HTTPSHandler):
    def __init__(self, ctx, ssrf):
        super().__init__(context=ctx)
        self._ssrf, self._ctx = ssrf, ctx

    def https_open(self, req):
        return self.do_open(_make_conn_class(self._ssrf), req, context=self._ctx)


class _Redirect(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS
    max_repeats = MAX_REDIRECTS

    def __init__(self, secret_headers, ssrf=False):
        self._secret = {h.lower() for h in secret_headers}
        self._ssrf = ssrf

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        nu = urllib.parse.urlsplit(newurl)
        if nu.scheme.lower() != "https":
            raise urllib.error.URLError("refusing redirect to non-https URL")
        old = urllib.parse.urlsplit(req.full_url)
        if nu.hostname != old.hostname and (any(h.lower() in self._secret for h in req.headers) or "key=" in old.query):
            raise urllib.error.URLError("refusing cross-host redirect for a keyed request")
        if self._ssrf:
            try:
                check_user_url(newurl, allow_ports=[old.port or 443])
            except FeedError as e:
                raise urllib.error.URLError("refusing redirect: %s" % e) from None
        if fp is not None:                         # never read an unbounded redirect body
            try:
                fp.read = lambda *a, **k: b""
            except AttributeError:
                pass
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _bounded_inflate(data, wbits, cap):
    d = zlib.decompressobj(wbits)
    try:
        out = d.decompress(data, cap + 1)
    except zlib.error:
        raise FeedError("the response could not be decompressed") from None
    if len(out) > cap or d.unconsumed_tail:
        raise FeedError("decompressed response larger than the %d byte cap" % cap)
    return out


def unpack(data, cap=FETCH_MAX, encoding=""):
    """Undo a gzip/deflate Content-Encoding or a gzip/zip payload, never producing more than cap bytes."""
    enc = (encoding or "").strip().lower()
    if enc in ("gzip", "x-gzip"):
        return _bounded_inflate(data, 31, cap)
    if enc == "deflate":
        try:
            return _bounded_inflate(data, 15, cap)
        except FeedError:
            return _bounded_inflate(data, -15, cap)
    if enc not in ("", "identity"):
        raise FeedError("unsupported content encoding")
    if data[:2] == b"\x1f\x8b":
        return _bounded_inflate(data, 31, cap)
    if data[:4] == b"PK\x03\x04":
        try:
            import io
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos = [i for i in z.infolist()[:64] if not i.is_dir()]
                if not infos or sum(i.file_size for i in infos) > cap * 4 or infos[0].file_size > cap:
                    raise FeedError("zip archive larger than the %d byte cap" % cap)
                if infos[0].flag_bits & 0x1:
                    raise FeedError("encrypted zip archives are not supported")
                with z.open(infos[0]) as f:
                    out = f.read(cap + 1)
        except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError, zlib.error):
            raise FeedError("the zip archive could not be read") from None
        if len(out) > cap:
            raise FeedError("decompressed response larger than the %d byte cap" % cap)
        return out
    return data


def http_get(url, *, method="GET", headers=None, data=None, ssrf=False, max_bytes=FETCH_MAX, timeout=TIMEOUT,
             deadline=TOTAL_DEADLINE):
    """Fetch bytes over https. Raises FeedError. Never includes header values in errors.

    Size is capped on the declared Content-Length, on the bytes actually read (so a lie or a chunked body
    cannot exceed it), and after any decompression; the whole fetch also has a time limit."""
    u = urllib.parse.urlsplit(url)
    if u.scheme.lower() != "https":
        raise FeedError("only https is allowed")
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    hdrs.update(headers or {})
    secret = [k for k in hdrs if k.lower() in ("auth-key", "x-otx-api-key")]
    handlers = [_Handler(_ssl_context(), ssrf), _Redirect(secret, ssrf)]
    if ssrf:
        handlers.append(urllib.request.ProxyHandler({}))      # a proxy would sidestep the address checks
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    end = time.monotonic() + deadline
    try:
        with opener.open(req, timeout=timeout) as r:
            declared = r.headers.get("Content-Length")
            if declared is not None and declared.strip().isdigit() and int(declared) > max_bytes:
                raise FeedError("response larger than the %d byte cap" % max_bytes)
            buf = bytearray()
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > max_bytes:
                    raise FeedError("response larger than the %d byte cap" % max_bytes)
                if time.monotonic() > end:
                    raise FeedError("the response took too long")
            return unpack(bytes(buf), max_bytes, r.headers.get("Content-Encoding", ""))
    except FeedError:
        raise
    except urllib.error.HTTPError as e:
        raise FeedError("HTTP %s from %s" % (e.code, u.hostname)) from None
    except (urllib.error.URLError, socket.timeout, TimeoutError, ssl.SSLError, OSError,
            http.client.HTTPException, ValueError) as e:
        raise FeedError("could not fetch %s: %s" % (u.hostname, type(e).__name__)) from None


# ---------------------------------------------------------------- per-feed parsers
def _list_parser(feed_id, role, why, cap=FETCH_MAX):
    def parse(raw, source=None):
        text = parsers._to_text(raw, cap)
        out, seen = [], {}
        for ln in text.splitlines()[:200000]:
            s = ln.strip()
            if not s or s[0] in "#;":
                continue
            tok = s.split()[0].split(",")[0]
            parsers._add(out, seen, parsers._make(tok, source or feed_id, "", role=role, why=why))
        return out
    return parse


def _force_role(fn, role, why, types=("ipv4", "ipv6", "domain", "url")):
    def parse(raw, source=None):
        res = fn(raw)
        for i in res:
            if i["type"] in types:
                i["role"], i["why"] = role, why
        return res
    return parse


def _parse_c2intel(role_why):
    def parse(raw, source="c2intel"):
        res = parsers.parse_csv(raw, source)
        for i in res:
            if i["type"] in ("ipv4", "ipv6", "domain", "url"):
                i["role"], i["why"] = "c2", role_why
            low = i["note"].lower()
            if "cobalt" in low:
                i["tags"] = model.norm_tags(i["tags"] + ["cobalt strike"])
            if "fronting" in low or "fronted" in low:
                i["tags"] = model.norm_tags(i["tags"] + ["domain-fronting"])
                i["confidence"] = 30
        return res
    return parse


def _parse_urlhaus(raw):
    d = parsers._json_load(raw, FETCH_MAX)
    out, seen = [], {}
    items = parsers._lst(d.get("urls")) if isinstance(d, dict) else []
    for it in items:
        if not isinstance(it, dict):
            continue
        tags = [t for t in parsers._lst(it.get("tags")) if isinstance(t, str)]
        ioc = parsers._make(str(it.get("url", "")), "urlhaus", "", role="payload",
                            why="URLhaus lists malware download URLs",
                            confidence=80 if it.get("url_status") == "online" else 50, tags=tags,
                            first_seen=it.get("date_added"), note="%s %s" % (it.get("threat", ""), it.get("url_status", "")))
        parsers._add(out, seen, ioc)
    return out


_KEV_RULES = (
    ("T1133", r"\b(?:vpn|remote access|remote desktop|rdp|ssh|citrix|netscaler|globalprotect|anyconnect|secure access|"
              r"pulse|ivanti|fortigate|fortios|sonicwall|gateway)\b"),
    ("T1203", r"\b(?:browser|chrome|chromium|firefox|safari|edge|office|word|excel|outlook|acrobat|reader|pdf|flash|"
              r"internet explorer|webkit|v8)\b"),
    ("T1068", r"\b(?:privilege escalation|elevation of privilege|escalat\w+ privileges?|local privilege|"
              r"privilege|kernel|use[- ]after[- ]free in the kernel)\b"),
    ("T1190", r"\b(?:remote(?:ly)?|unauthenticated|network|web|http|server|appliance|firewall|router|"
              r"public[- ]facing|authentication bypass|sql injection|command injection|deserialization|"
              r"path traversal|file upload)\b"),
)


def _kev_techniques(v):
    """ATT&CK techniques implied by what a KEV record says (product class and the weakness), first match
    per rule; none when the text says nothing useful. T1190 exploit of a public-facing service, T1133
    external remote services, T1203 client execution, T1068 privilege escalation."""
    text = " ".join(str(v.get(k) or "") for k in ("vendorProject", "product", "vulnerabilityName", "shortDescription")).lower()
    out = [t for t, rx in _KEV_RULES if re.search(rx, text)]
    client = "T1203" in out and not re.search(r"\b(?:server|appliance|gateway|firewall|vpn)\b", text)
    if client:
        out = [t for t in out if t != "T1190"]
    return out[:3]


def _kev_note(v):
    """'Vendor Product: Name | what CISA says | Required action: ...'. The part before the first ' | ' is what
    cve_profiles matches on; the rest is the plain-language description the indicator card shows."""
    head = "%s %s: %s" % (v.get("vendorProject", ""), v.get("product", ""), v.get("vulnerabilityName", ""))
    parts = [head, str(v.get("shortDescription") or "").strip()]
    if str(v.get("requiredAction") or "").strip():
        parts.append("CISA action: " + str(v["requiredAction"]).strip())
    return " | ".join(p for p in parts if p)


def _parse_kev(raw):
    d = parsers._json_load(raw, FETCH_MAX)
    out, seen = [], {}
    vs = [v for v in (parsers._lst(d.get("vulnerabilities")) if isinstance(d, dict) else []) if isinstance(v, dict)]
    vs.sort(key=lambda v: str(v.get("dateAdded", "")), reverse=True)
    for v in vs:
        tags = ["kev"] + (["ransomware"] if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known" else [])
        tags += [str(v.get(k)).strip()[:40] for k in ("vendorProject", "product") if str(v.get(k) or "").strip()]
        ioc = parsers._make(str(v.get("cveID", "")), "cisa-kev", "", confidence=95, tags=tags,
                            techniques=_kev_techniques(v), first_seen=v.get("dateAdded"),
                            note=_kev_note(v))
        if ioc is not None:
            ioc["why"] = "CISA lists this CVE as exploited in the wild; carried as a detection expectation (%s)" % (
                ", ".join(ioc.get("techniques") or []) or "no technique implied")
        parsers._add(out, seen, ioc)
    return out


def _parse_phishtank(raw):
    import csv
    import io
    out, seen = [], {}
    for row in csv.DictReader(io.StringIO(parsers._to_text(raw, 32 * 1024 * 1024))):
        if (row.get("online") or "").lower() != "yes":
            continue
        tgt = (row.get("target") or "").strip()
        parsers._add(out, seen, parsers._make(row.get("url") or "", "phishtank", "", role="phishing",
                                              why="PhishTank lists verified phishing URLs", confidence=85,
                                              tags=[tgt] if tgt and tgt != "Other" else [],
                                              first_seen=row.get("submission_time"), note="PhishTank id %s" % row.get("phish_id", "")))
    return out


def _parse_dshield(raw):
    d = parsers._json_load(raw, FETCH_MAX)
    out, seen = [], {}
    for it in (d if isinstance(d, list) else []):
        if isinstance(it, dict):
            parsers._add(out, seen, parsers._make(str(it.get("ipv4", "")), "dshield", "", role="scanner",
                                                  why="SANS Internet Storm Center lists this address as an attack source",
                                                  confidence=70, first_seen=it.get("date"),
                                                  note="last seen %s" % it.get("lastseen", "")))
    return out


def _parse_spamhaus_drop(raw):
    """DROP lists netblocks, not hosts: one address per block (network + 1) stands in for it, tagged with the block."""
    out, seen = [], {}
    for ln in parsers._to_text(raw, FETCH_MAX).splitlines()[:20000]:
        try:
            d = json.loads(ln)
            net = ipaddress.ip_network(str(d["cidr"]), strict=True)
        except (ValueError, KeyError, TypeError, RecursionError):
            continue
        if net.version != 4 or net.prefixlen > 30:
            continue
        parsers._add(out, seen, parsers._make(str(net.network_address + 1), "spamhaus-drop", "", role="scanner",
                                              why="Spamhaus DROP lists this netblock as hijacked or run by criminals; one address stands in for it",
                                              confidence=60, tags=["sampled-from:%s" % net, "sbl:%s" % d.get("sblid", "")],
                                              note="Spamhaus DROP netblock %s (%s)" % (net, d.get("rir", ""))))
    return out


def _parse_shodan(raw):
    """Hosts a Shodan search matched (no role: they are targets, not attackers) and the CVEs Shodan flagged on them."""
    d = parsers._json_load(raw, FETCH_MAX)
    out, seen = [], {}
    for m in (parsers._lst(d.get("matches")) if isinstance(d, dict) else []):
        if not isinstance(m, dict):
            continue
        prod = str(m.get("product") or "")[:60]
        port = m.get("port")
        host = parsers._make(str(m.get("ip_str", "")), "shodan", "", confidence=60,
                             tags=([prod] if prod else []) + (["port:%s" % port] if port else []),
                             note="Shodan: %s exposed on port %s" % (prod or "a service", port))
        parsers._add(out, seen, host)
        vulns = m.get("vulns")
        for cve in (vulns if isinstance(vulns, list) else list(vulns) if isinstance(vulns, dict) else [])[:20]:
            parsers._add(out, seen, parsers._make(str(cve), "shodan", "", confidence=60, tags=[prod] if prod else [],
                                                  note="%s exposed to the internet (Shodan)" % (prod or "a service")))
    return out



def _parse_via(fn):
    return lambda raw: fn(raw)


# ---------------------------------------------------------------- registry
def _reg(*feeds):
    return {f.id: f for f in feeds}


FEEDS = _reg(
    Feed("circl", "CIRCL OSINT", "MISP feeds", "https://www.circl.lu/doc/misp/feed-osint/manifest.json",
         fmt="misp", kind="misp_feed", parse=lambda raw: parsers.parse_misp(raw, "circl", FETCH_MAX), ttl=6 * 3600,
         params={"base": "https://www.circl.lu/doc/misp/feed-osint/"},
         terms="CIRCL OSINT feed, see circl.lu", notes="verified live 2026-11-19 (manifest)"),
    Feed("otx", "AlienVault OTX pulses", "Community", "https://otx.alienvault.com/api/v1/search/pulses",
         needs_key=True, key_env="OTX_API_KEY", key_header="X-OTX-API-KEY", fmt="otx", kind="otx",
         parse=lambda raw: parsers.parse_otx(raw, "otx", FETCH_MAX), ttl=1800, params={"q": "c2"},
         terms="OTX terms apply; free API key required", notes="verified live 2026-11-20: search lists pulses, indicators fetched per pulse"),
    Feed("url", "From a URL", "Custom", "", fmt="auto", kind="user_url",
         parse=lambda raw: parsers.parse_any(raw, "url", FETCH_MAX), ttl=900, params={"url": ""},
         terms="Whatever the publisher requires", notes="https only, public hosts only (SSRF checked)"),
    Feed("threatfox", "ThreatFox (abuse.ch)", "abuse.ch", "https://threatfox-api.abuse.ch/api/v1/",
         needs_key=True, key_env="ABUSECH_AUTH_KEY", key_header="Auth-Key", fmt="threatfox", kind="post",
         parse=lambda raw: parsers.parse_threatfox(raw, "threatfox", FETCH_MAX), ttl=1800, params={"days": 1},
         terms="CC0; abuse.ch Auth-Key required", notes="needs key; verified live 2026-11-20"),
    Feed("urlhaus", "URLhaus (abuse.ch)", "abuse.ch", "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/",
         needs_key=True, key_env="ABUSECH_AUTH_KEY", key_header="Auth-Key", fmt="json", kind="simple",
         parse=_parse_urlhaus, ttl=1800, terms="CC0; abuse.ch Auth-Key required",
         notes="needs key; verified live 2026-11-20"),
    Feed("c2intel-ip", "C2IntelFeeds addresses (30 day)", "C2", "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv",
         fmt="csv", parse=_parse_c2intel("C2IntelFeeds lists C2 addresses"), ttl=6 * 3600,
         terms="drb-ra/C2IntelFeeds (GitHub) terms", notes="verified live 2026-11-19"),
    Feed("c2intel-domain", "C2IntelFeeds domains (30 day)", "C2", "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day.csv",
         fmt="csv", parse=_parse_c2intel("C2IntelFeeds lists C2 domains"), ttl=6 * 3600,
         terms="drb-ra/C2IntelFeeds (GitHub) terms", notes="verified live 2026-11-19"),
    Feed("blocklist-ssh", "blocklist.de SSH attackers", "Brute force", "https://lists.blocklist.de/lists/ssh.txt",
         fmt="text", parse=_list_parser("blocklist-ssh", "brute", "blocklist.de SSH brute-force sources"),
         ttl=3600, terms="blocklist.de terms", notes="verified live 2026-11-19"),
    Feed("blocklist-login", "blocklist.de login attackers", "Brute force", "https://lists.blocklist.de/lists/bruteforcelogin.txt",
         fmt="text", parse=_list_parser("blocklist-login", "brute", "blocklist.de login brute-force sources"),
         ttl=3600, terms="blocklist.de terms", notes="verified live 2026-11-19"),
    Feed("blocklist-mail", "blocklist.de mail attackers", "Brute force", "https://lists.blocklist.de/lists/mail.txt",
         fmt="text", parse=_list_parser("blocklist-mail", "brute", "blocklist.de mail brute-force sources"),
         ttl=3600, terms="blocklist.de terms", notes="verified live 2026-11-19"),
    Feed("cins-army", "CINS Army bad actors", "Reputation", "https://cinsscore.com/list/ci-badguys.txt",
         fmt="text", parse=_list_parser("cins-army", "scanner", "CINS Army list of addresses attacking other networks"),
         ttl=6 * 3600, terms="CINS Score terms", notes="verified live 2026-11-23"),
    Feed("ipsum", "IPsum (listed on 3 or more blocklists)", "Reputation",
         "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
         fmt="text", parse=_list_parser("ipsum", "scanner", "IPsum: address appears on at least three public blocklists"),
         ttl=6 * 3600, terms="stamparm/ipsum (GitHub) terms", notes="verified live 2026-11-23"),
    Feed("phishing-db-ips", "Phishing.Database addresses", "Phishing",
         "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-IPs-ACTIVE.txt",
         fmt="text", parse=_list_parser("phishing-db-ips", "phishing", "Phishing.Database lists active phishing hosts"),
         ttl=6 * 3600, terms="Phishing.Database (MIT licence)", notes="checked 2026-11-23"),
    Feed("phishing-db-domains", "Phishing.Database domains", "Phishing",
         "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
         fmt="text", parse=_list_parser("phishing-db-domains", "phishing", "Phishing.Database lists active phishing domains", 32 << 20),
         ttl=6 * 3600, max_bytes=32 << 20, terms="Phishing.Database (MIT licence)", notes="checked 2026-11-23; large file"),
    Feed("phishtank", "PhishTank verified online", "Phishing", "https://data.phishtank.com/data/online-valid.csv",
         fmt="csv", parse=_parse_phishtank, ttl=3600, max_bytes=32 << 20,
         terms="PhishTank (Cisco Talos): a few downloads per day without an app key", notes="checked 2026-11-23"),
    Feed("dshield", "SANS ISC attack sources (DShield)", "Reputation", "https://isc.sans.edu/api/threatlist?json",
         fmt="json", parse=_parse_dshield, ttl=6 * 3600, terms="CC BY-NC-SA 4.0 (SANS ISC); fetch only, do not redistribute",
         notes="checked 2026-11-23"),
    Feed("spamhaus-drop", "Spamhaus DROP netblocks", "Reputation", "https://www.spamhaus.org/drop/drop_v4.json",
         fmt="json", parse=_parse_spamhaus_drop, ttl=24 * 3600, terms="Free for any use; credit Spamhaus; fetch at most daily",
         notes="checked 2026-11-23"),
    Feed("shodan", "Shodan search", "Community", "https://api.shodan.io/shodan/host/search",
         needs_key=True, key_env="SHODAN_API_KEY", kind="shodan", fmt="json", parse=_parse_shodan, ttl=3600,
         params={"q": "has_vuln:true"}, terms="Shodan account key required; search may use query credits",
         notes="checked 2026-11-23"),
    Feed("siberkapan", "SiberKapan daily threat feed", "MISP feeds", "https://siberkapan.org/misp-feed/manifest.json",
         fmt="misp", kind="misp_feed", parse=_force_role(lambda raw: parsers.parse_misp(raw, "siberkapan", FETCH_MAX), "scanner",
                          "SiberKapan sensors (honeypot, web server) saw this address attack", types=("ipv4",)), ttl=6 * 3600,
         params={"base": "https://siberkapan.org/misp-feed/"}, terms="SiberKapan (official MISP default feed); see siberkapan.org",
         notes="checked 2026-11-23"),
    Feed("infoblox", "Infoblox threat intelligence", "MISP feeds",
         "https://raw.githubusercontent.com/infobloxopen/threat-intelligence/main/indicators/misp/manifest.json",
         fmt="misp", kind="misp_feed", parse=lambda raw: parsers.parse_misp(raw, "infoblox", FETCH_MAX), ttl=6 * 3600,
         params={"base": "https://raw.githubusercontent.com/infobloxopen/threat-intelligence/main/indicators/misp/"},
         terms="CC BY 4.0 (Infoblox)", notes="checked 2026-11-23"),
    Feed("honeynet-ssh", "APNIC honeynet SSH brute force", "Brute force",
         "https://feeds.honeynet.asia/bruteforce/latest-sshbruteforce-unique.csv", fmt="text",
         parse=_list_parser("honeynet-ssh", "brute", "APNIC Community Honeynet saw this address guess SSH passwords"),
         ttl=6 * 3600, terms="APNIC Community Honeynet Project; see feeds.honeynet.asia", notes="checked 2026-11-23"),
    Feed("honeynet-telnet", "APNIC honeynet Telnet brute force", "Brute force",
         "https://feeds.honeynet.asia/bruteforce/latest-telnetbruteforce-unique.csv", fmt="text",
         parse=_list_parser("honeynet-telnet", "brute", "APNIC Community Honeynet saw this address guess Telnet passwords"),
         ttl=6 * 3600, terms="APNIC Community Honeynet Project; see feeds.honeynet.asia", notes="checked 2026-11-23"),
    Feed("honeynet-urls", "APNIC honeynet malware URLs", "C2", "https://feeds.honeynet.asia/url/latest-url-unique.csv",
         fmt="text", parse=_list_parser("honeynet-urls", "payload", "APNIC Community Honeynet saw malware fetched from this URL"),
         ttl=6 * 3600, terms="APNIC Community Honeynet Project; see feeds.honeynet.asia", notes="checked 2026-11-23"),
    Feed("cert-pl", "CERT Polska malicious domains", "Phishing", "https://hole.cert.pl/domains/domains.txt",
         fmt="text", parse=_list_parser("cert-pl", "phishing", "CERT Polska warning list of malicious domains"),
         ttl=24 * 3600, terms="CERT Polska (hole.cert.pl); see the site for terms", notes="checked 2026-11-23"),
    Feed("tor-exit", "Tor exit nodes", "Anonymisation", "https://check.torproject.org/torbulkexitlist",
         fmt="text", parse=_list_parser("tor-exit", "tor", "Tor Project bulk exit list"), ttl=3600,
         terms="Tor Project", notes="verified live 2026-11-19"),
    Feed("openphish", "OpenPhish community feed", "Phishing", "https://openphish.com/feed.txt",
         fmt="text", parse=_list_parser("openphish", "phishing", "OpenPhish phishing URL feed"), ttl=3600,
         terms="OpenPhish community feed terms", notes="verified live 2026-11-19"),
    Feed("cisa-kev", "CISA Known Exploited Vulnerabilities", "Vulnerabilities",
         "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
         fmt="json", parse=_parse_kev, ttl=12 * 3600, terms="US Government public data", notes="verified live 2026-11-19"),
)


# What each feed delivers and what the campaign sends for it; wording matches the indicator cards
# (describe.py): addresses, domains and URLs send traffic, other types are hidden as "not on the wire".
_GIVES = {
    "circl": "Gives IP addresses, domains and URLs (these send traffic: C2 beacons, payload downloads, phishing visits), plus CVEs, "
             "hashes, file names and e-mail addresses (hidden). An indicator with no role word sends nothing until you give it a role.",
    "otx": "Gives IP addresses, domains and URLs (these send traffic), plus IPv6 addresses, CVEs, hashes, file names and e-mail "
           "addresses (hidden). An indicator with no role word sends nothing until you give it a role.",
    "url": "Gives whatever the list holds. IP addresses, domains and URLs send traffic; hashes, file names, e-mail addresses and "
           "CVEs of non-network products are hidden. An indicator with no role word sends nothing until you give it a role.",
    "threatfox": "Gives IP addresses, domains and URLs (these send traffic: C2 beacons, payload downloads) and file hashes (hidden).",
    "urlhaus": "Gives URLs only; each one sends an HTTP(S) download of an inert file.",
    "c2intel-ip": "Gives IP addresses only; each one is a C2 server and sends repeated TLS/HTTPS beacons.",
    "c2intel-domain": "Gives domains only; each one is a C2 server and sends a DNS lookup then TLS/HTTPS beacons.",
    "blocklist-ssh": "Gives IP addresses only; each one sends repeated failed logins against an internal service, then one that succeeds. IPv6 entries are hidden.",
    "blocklist-login": "Gives IP addresses only; each one sends repeated failed logins against an internal service, then one that succeeds. IPv6 entries are hidden.",
    "blocklist-mail": "Gives IP addresses only; each one sends repeated failed logins against an internal service, then one that succeeds. IPv6 entries are hidden.",
    "cins-army": "Gives IP addresses only; each one sends inbound connection attempts across many internal addresses and ports (a scanner).",
    "ipsum": "Gives IP addresses only; each one sends inbound connection attempts across many internal addresses and ports (a scanner).",
    "phishing-db-ips": "Gives IP addresses only; each one sends a workstation fetching the phishing lure page.",
    "phishing-db-domains": "Gives domains (a few entries are bare IP addresses); each one sends a DNS lookup then a workstation fetching the phishing lure page.",
    "phishtank": "Gives URLs only; each one sends a workstation fetching the phishing lure page.",
    "dshield": "Gives IP addresses only; each one sends inbound connection attempts across many internal addresses and ports (a scanner).",
    "spamhaus-drop": "Gives netblocks, so one IP address stands in for each block (tagged with it); each sends inbound connection attempts across many internal addresses and ports (a scanner).",
    "shodan": "Gives IP addresses of exposed services (no role: they send nothing until you give them one) and CVEs; only a CVE for a network-facing product sends an inert probe, the rest are hidden.",
    "siberkapan": "Gives IP addresses (hosts that hit its honeypot and web-server sensors); each one sends inbound connection attempts across many internal addresses and ports (a scanner). IPv6 entries are hidden.",
    "infoblox": "Gives IP addresses, domains and URLs (these send traffic), plus CVEs, hashes, file names and e-mail addresses (hidden). An indicator with no role word sends nothing until you give it a role.",
    "honeynet-ssh": "Gives IP addresses only; each one sends repeated failed logins against an internal service, then one that succeeds.",
    "honeynet-telnet": "Gives IP addresses only; each one sends repeated failed logins against an internal service, then one that succeeds (the campaign sends SSH or RDP logons, not Telnet).",
    "honeynet-urls": "Gives URLs only (many point at a bare IP address and port); each one sends an HTTP(S) download of an inert file.",
    "cert-pl": "Gives domains (a few entries are file names, hidden); each one sends a DNS lookup then a workstation fetching the lure page.",
    "tor-exit": "Gives IP addresses only; each one sends a Tor-style TLS session from the workstation.",
    "openphish": "Gives URLs only; each one sends a workstation fetching the phishing lure page.",
    "cisa-kev": "Gives CVEs only, and no hosts. Only a CVE for a network-facing product sends traffic (an inert probe of the "
                "product's web path, then the server's refusal); the rest are hidden.",
}
for _f in FEEDS.values():
    _f.gives = _GIVES[_f.id]
assert set(_GIVES) == set(FEEDS), "every feed must state what it gives"

_WHY = {
    "circl": "Analyst-curated MISP OSINT events from a national CERT, current to the day.",
    "otx": "The largest community pulse feed, with campaign context around each indicator.",
    "url": "Your own list: any https page or file you trust.",
    "threatfox": "Community-submitted C2 and payload indicators from abuse.ch, tagged by malware family.",
    "urlhaus": "Live malware-download URLs from abuse.ch.",
    "c2intel-ip": "Fresh C2 server addresses, including Cobalt Strike, updated daily.",
    "c2intel-domain": "The same C2 feed as domains, with fronted domains tagged.",
    "blocklist-ssh": "Real sources of SSH password guessing reported by honeypots and servers.",
    "blocklist-login": "Real sources of web and service login guessing.",
    "blocklist-mail": "Real sources of mail-service login guessing.",
    "cins-army": "Addresses seen attacking other networks, from a long-running sensor network.",
    "ipsum": "Addresses that appear on at least three public blocklists, so few false alarms.",
    "dshield": "Attack sources from the SANS Internet Storm Center honeypot network.",
    "spamhaus-drop": "Netblocks Spamhaus judges hijacked or run by criminals: the most trusted hostile-network list.",
    "openphish": "Current phishing URLs, refreshed through the day.",
    "phishtank": "Community-verified phishing URLs (Cisco Talos).",
    "phishing-db-ips": "Phishing hosts reached by address, from an open, MIT-licensed list.",
    "phishing-db-domains": "Active phishing domains from an open, MIT-licensed list.",
    "siberkapan": "A daily own-source feed built on a real honeypot and sensor network; an official MISP default feed.",
    "infoblox": "Indicators from a major DNS-security vendor's research team, openly licensed.",
    "honeynet-ssh": "SSH password guessers caught by a regional honeypot network, refreshed daily.",
    "honeynet-telnet": "Telnet password guessers caught by the same honeypot network.",
    "honeynet-urls": "Malware download URLs captured by the same honeypots, many served from bare IPs.",
    "cert-pl": "A national CERT's warning list of malicious domains, refreshed daily.",
    "tor-exit": "The Tor Project's own exit list: real anonymised-egress addresses.",
    "cisa-kev": "The US government list of vulnerabilities exploited in the wild.",
    "shodan": "Search internet-exposed services with your own query, to build exploit-probe scenarios against products found exposed.",
}
for _f in FEEDS.values():
    _f.why = _WHY[_f.id]
assert set(_WHY) == set(FEEDS), "every feed must say why it is offered"


# ---------------------------------------------------------------- fetch
def _key_for(feed, key):
    if not feed.needs_key:
        return None
    k = key or os.environ.get(feed.key_env, "")
    k = (k or "").strip()
    if not k:
        raise FeedError("%s needs an API key (pass key= or set %s)" % (feed.title, feed.key_env))
    if len(k) > 200 or any(ord(c) < 33 or ord(c) > 126 for c in k):
        raise FeedError("the API key looks malformed")
    return k


def _fetch_raw(feed, limit, key, params):
    h = {}
    if feed.needs_key and feed.key_header:
        h[feed.key_header] = key
    if feed.kind == "user_url":
        url = check_user_url(params.get("url", ""))
        return http_get(url, ssrf=True).decode("utf-8", errors="replace")
    if feed.kind == "misp_feed":
        return _fetch_misp_feed(feed, limit)
    if feed.kind == "shodan":
        q = str(params.get("q") or feed.params["q"])[:200]
        url = "%s?%s" % (feed.url, urllib.parse.urlencode({"key": key, "query": q}))
        return http_get(url).decode("utf-8", errors="replace")
    if feed.kind == "otx":
        q = str(params.get("q") or feed.params["q"])[:100]
        url = "%s?%s" % (feed.url, urllib.parse.urlencode({"q": q, "limit": max(1, min(int(limit), 20)), "sort": "-modified"}))
        raw = http_get(url, headers=h).decode("utf-8", errors="replace")
        return _otx_with_indicators(raw, limit, h)
    if feed.id == "threatfox":
        body = json.dumps({"query": "get_iocs", "days": max(1, min(int(params.get("days", 1)), 7))}).encode()
        h["Content-Type"] = "application/json"
        return http_get(feed.url, method="POST", headers=h, data=body).decode("utf-8", errors="replace")
    url = feed.url.replace("{limit}", str(max(1, min(int(limit), 1000))))
    return http_get(url, headers=h, max_bytes=feed.max_bytes or FETCH_MAX).decode("utf-8", errors="replace")



def _otx_with_indicators(raw, limit, headers):
    """OTX's search endpoint lists pulses without their indicators. Fetch up to five pulses' indicators
    (one request each, ids checked) and attach them, so the normal OTX parser sees what a pulse export has."""
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return raw
    pulses = [p for p in (parsers._lst(data.get("results")) if isinstance(data, dict) else []) if isinstance(p, dict)][:5]
    per = max(1, min(100, -(-int(limit) // max(1, len(pulses)))))
    for p in pulses:
        pid = str(p.get("id") or "")
        if p.get("indicators") or not re.fullmatch(r"[0-9a-f]{24}", pid):
            continue
        try:
            sub = json.loads(http_get("https://otx.alienvault.com/api/v1/pulses/%s/indicators?limit=%d" % (pid, per),
                                      headers=headers).decode("utf-8", errors="replace"))
        except (FeedError, ValueError, OSError, RecursionError):
            continue
        res = sub.get("results") if isinstance(sub, dict) else None
        p["indicators"] = [i for i in parsers._lst(res) if isinstance(i, dict)][:per]
    return json.dumps({"results": pulses})

def _fetch_misp_feed(feed, limit):
    base = feed.params["base"]
    try:
        man = json.loads(http_get(feed.url).decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        raise FeedError("unexpected manifest format") from None
    if not isinstance(man, dict):
        raise FeedError("unexpected manifest format")

    def _stamp(kv):
        t = str(kv[1].get("timestamp", 0))
        return -int(t) if t.isdigit() and len(t) < 15 else 0
    order = sorted(((k, v) for k, v in man.items() if isinstance(v, dict)), key=_stamp)
    events, count = [], 0
    for uuid, _ in order[:40]:
        if len(events) >= MISP_MAX_EVENTS or count >= limit:
            break
        if not all(c in "0123456789abcdef-" for c in uuid):
            continue
        try:
            ev = json.loads(http_get(base + uuid + ".json").decode("utf-8", errors="replace"))
        except (FeedError, ValueError, RecursionError):
            continue
        n = len(parsers.parse_misp(ev, feed.id, FETCH_MAX))
        if n:
            events.append(ev)
            count += n
    return json.dumps(events)


def _cache_params(feed, limit, params):
    p = {k: v for k, v in params.items() if v not in (None, "")}
    if feed.kind in ("misp_feed", "otx", "shodan") or "{limit}" in feed.url:
        p["limit"] = limit
    return p


def fetch(feed_id, *, limit=50, key=None, cache=True, offline=False, fresh=False, **params):
    """Return up to `limit` IOCs from a feed.

    offline=True serves the cache only (any age) and raises FeedError if nothing is cached.
    cache=True stores the raw response (never the key) and reuses it within the feed's TTL.
    fresh=True skips the cache read for this call (the result is still stored).
    Extra params: q= (otx), url= ('url' feed), days= (threatfox). Raises FeedError, never KeyError.
    """
    feed = FEEDS.get(feed_id)
    if feed is None:
        raise FeedError("unknown feed %r (see FEEDS)" % (feed_id,))
    limit = max(1, min(int(limit), 5000))
    if feed.kind == "user_url" and not params.get("url"):
        raise FeedError("the 'url' feed needs url=https://...")
    cp = _cache_params(feed, limit, params)
    raw = None
    if offline:
        raw = _cache.get(feed.id, cp, ttl=None)
        if raw is None:
            raise FeedError("no cached data for %s (offline mode)" % feed.id)
    else:
        if cache and not fresh:
            raw = _cache.get(feed.id, cp, ttl=feed.ttl)
        if raw is None:
            k = _key_for(feed, key)
            raw = _fetch_raw(feed, limit, k, params)
            if cache:
                try:
                    _cache.put(feed.id, cp, raw)
                except OSError:
                    pass
    iocs = feed.parse(raw)
    for i in iocs:
        i["source"] = feed.id
    return model.dedupe(iocs)[:limit]
