"""Indicator refang + classification.

refang(s)         undo common defanging (hxxp, [.], (.), [dot], {.}, [@], [at], [:], [://] ...).
classify_value(s) -> (type, canonical) or (None, s).

Types: ipv4 (strict dotted quad, no leading-zero octets), ipv6, cidr, domain (IDNA-safe, RFC 1035
label rules, TLD alphabetic; file-like TLDs such as .exe/.dll/.php are reported as filename),
url (scheme://host...), md5/sha1/sha256 (lowercased hex), email, cve (upper case), filename.
A trailing ':port' on an address/domain is accepted and dropped (use split_port to keep it).
"""
import functools
import ipaddress
import re
import unicodedata

_DEFANG = [
    (re.compile(r"\[\s*://\s*\]|\(\s*://\s*\)"), "://"),
    (re.compile(r"\[\s*:\s*\]|\(\s*:\s*\)"), ":"),
    (re.compile(r"[\[\(\{]\s*(?:\.|dot|DOT|Dot)\s*[\]\)\}]"), "."),
    (re.compile(r"[\[\(\{]\s*(?:@|at|AT|At)\s*[\]\)\}]"), "@"),
    (re.compile(r"[\[\(\{]\s*/\s*[\]\)\}]"), "/"),
    (re.compile(r"^(?:h[xX]{2}p)(s?)", re.I), None),  # handled below
    (re.compile(r"^fxp(s?)(?=:|\[)", re.I), None),
]


_HINT = re.compile(r"[\[\(\{]|hxxp|fxp|//", re.I)
_RE_HXXP_COLON = re.compile(r"^h[xX]{2}p(s?)(?=:)", re.I)
_RE_HXXP_BRACKET = re.compile(r"^h[xX]{2}p(s?)(?=\[)", re.I)
_RE_FXP = re.compile(r"^fxp(s?)(?=:)", re.I)
_RE_SCHEME = re.compile(r"^(https?|ftps?)(?:\[:\]|:)?//", re.I)


def refang(s):
    """Return s with defanging undone. Idempotent; never raises on str input."""
    if not isinstance(s, str):
        return ""
    s = s.strip()
    if not _HINT.search(s):          # nothing that could be defanged: skip every substitution
        return s
    for pat, rep in _DEFANG[:5]:
        s = pat.sub(rep, s)
    s = _RE_HXXP_COLON.sub(lambda m: "http" + m.group(1).lower(), s)
    s = _RE_HXXP_BRACKET.sub(lambda m: "http" + m.group(1).lower(), s)
    s = _RE_FXP.sub(lambda m: "ftp" + m.group(1).lower(), s)
    s = _RE_SCHEME.sub(lambda m: m.group(1).lower() + "://", s)
    return s


FILE_EXTS_UNAMBIGUOUS = {
    "exe", "dll", "bat", "cmd", "ps1", "vbs", "vbe", "msi", "jar", "php", "asp", "aspx", "jsp",
    "txt", "log", "tmp", "dat", "bin", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx",
    "pdf", "lnk", "scr", "sys", "iso", "img", "html", "htm", "js", "css", "png", "jpg", "jpeg",
    "gif", "ico", "json", "xml", "csv", "rtf", "hta", "wsf", "cab", "ini", "cfg", "elf", "apk",
    "dmg", "pkg", "tlb", "ocx", "cpl", "drv", "reg", "swf", "chm", "eml", "msg", "pst", "mdb", "pyc", "dot", "wsc", "job", "7z", "rar", "tar", "gz", "tgz", "bak", "db", "sql", "yaml", "yml", "conf",
}
FILE_EXTS_AMBIGUOUS = {"zip", "sh", "py", "pl", "rb", "mov", "md", "ps"}  # also real TLDs
_ALL_EXTS = FILE_EXTS_UNAMBIGUOUS | FILE_EXTS_AMBIGUOUS

# TLDs trusted when scanning free text (any 2-letter ccTLD is also trusted); classify_value itself
# accepts any alphabetic TLD.
COMMON_TLDS = {
    "com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "io", "co", "me", "tv", "cc",
    "xyz", "top", "site", "online", "club", "shop", "app", "dev", "cloud", "tech", "store", "icu",
    "vip", "pro", "example", "test", "invalid", "localhost", "local", "onion", "internal", "lan",
    "corp",
}

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_HEX = {32: "md5", 40: "sha1", 64: "sha256"}
_HEXRE = re.compile(r"^[0-9a-fA-F]+$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
_PORT_SUFFIX = re.compile(r"^(.+?):(\d{1,5})$")
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]{1,15})://(\S+)$")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+'=-]{1,64}@([^@\s]{3,255})$")
_PATHFILE = re.compile(r"^(?:[A-Za-z]:[\\/]|[\\/]|\.{1,2}[\\/]|~[\\/]|%[A-Za-z0-9_]+%[\\/])[^\s<>|*?\"]*$")
_PLAINFILE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_ .+()$~-]{0,200}$")


def is_ipv4(s):
    if not isinstance(s, str):
        return False
    p = s.split(".")
    if len(p) != 4:
        return False
    for o in p:
        if not o.isascii() or not o.isdigit() or len(o) > 3:
            return False
        if len(o) > 1 and o[0] == "0":
            return False
        if int(o) > 255:
            return False
    return True


def _domain(s):
    """Return canonical ascii domain or None."""
    s = s.strip().rstrip(".")
    if not s or len(s) > 253 or " " in s:
        return None
    if not s.isascii():
        try:
            s = s.encode("idna").decode("ascii")
        except (UnicodeError, ValueError):
            return None
    s = s.lower()
    labels = s.split(".")
    if len(labels) < 2:
        return None
    for lab in labels:
        if not _LABEL.match(lab):
            return None
    tld = labels[-1]
    if not (tld.startswith("xn--") or (tld.isalpha() and 2 <= len(tld) <= 63)):
        return None
    if all(c in "0123456789." for c in s):
        return None
    return s


def tld_of(domain):
    return domain.rsplit(".", 1)[-1]


def is_trusted_tld(domain):
    t = tld_of(domain)
    return len(t) == 2 or t in COMMON_TLDS or t.startswith("xn--")


def split_port(s):
    """'1.2.3.4:443' -> ('1.2.3.4', 443); anything else -> (s, None)."""
    s = refang(s)
    m = _PORT_SUFFIX.match(s)
    if m and "]" not in s and s.count(":") == 1:
        port = int(m.group(2))
        if 0 < port < 65536:
            return m.group(1), port
    return s, None


def _is_filename(s):
    if len(s) > 255 or "." not in s:
        return False
    base = re.split(r"[\\/]", s)[-1]
    if "." not in base:
        return False
    ext = base.rsplit(".", 1)[-1].lower()
    if ext not in _ALL_EXTS or len(base) <= len(ext) + 1:
        return False
    if _PATHFILE.match(s):
        return True
    return bool(_PLAINFILE.match(s)) and "/" not in s and "\\" not in s


def _url(s):
    m = _SCHEME.match(s)
    if not m:
        return None
    scheme, rest = m.group(1).lower(), m.group(2)
    if scheme not in ("http", "https", "ftp", "ftps", "sftp", "tcp", "udp", "ws", "wss"):
        return None
    m2 = re.match(r"^(?:[^@/?#]*@)?(\[[0-9a-fA-F:.]+\]|[^/?#:]+)(?::(\d{1,5}))?([/?#].*)?$", rest)
    if not m2:
        return None
    host, port, tail = m2.group(1), m2.group(2), m2.group(3) or ""
    if port and not (0 < int(port) < 65536):
        return None
    if host.startswith("["):
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return None
        host_c = host.lower()
    elif is_ipv4(host):
        host_c = host
    else:
        d = _domain(host)
        if d is None:
            return None
        host_c = d
    if len(s) > 2048 or any(ord(c) < 33 for c in s):
        return None
    userinfo = ""
    if "@" in rest.split("/")[0]:
        userinfo = rest.split("/")[0].rsplit("@", 1)[0] + "@"
    return "%s://%s%s%s%s" % (scheme, userinfo, host_c, (":" + port) if port else "", tail)


_ASCII_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def _scrub(s):
    """Drop invisible format characters (zero-width, bidi, BOM); None when a control character,
    line/paragraph separator or lone surrogate is present, so no canonical value can carry one."""
    if s.isascii():
        return None if _ASCII_CTRL.search(s) else s
    out = []
    for ch in s:
        cat = unicodedata.category(ch)
        if cat == "Cf":
            continue
        if cat in ("Cc", "Zl", "Zp", "Cs"):
            return None
        out.append(ch)
    return "".join(out)


@functools.lru_cache(maxsize=32768)
def _classify_short(s):
    return _classify(s)


def classify_value(s):
    """Classify one token. Returns (type, canonical_value) or (None, original).
    Short tokens are memoised (the parsers classify each token up to three times)."""
    if isinstance(s, str) and len(s) <= 256:
        return _classify_short(s)
    return _classify(s)


def _classify(s):
    orig = s
    if not isinstance(s, str):
        return None, ""
    s = refang(s).strip().strip("\u200b\ufeff")
    s = s.strip("<>\"'`")
    if not s or len(s) > 2100:
        return None, orig
    s = _scrub(s)
    if not s:
        return None, orig
    if _CVE.match(s):
        return "cve", s.upper()
    if _HEXRE.match(s) and len(s) in _HEX:
        return _HEX[len(s)], s.lower()
    if "://" in s:
        u = _url(s)
        return ("url", u) if u else (None, orig)
    if "/" in s and not _PATHFILE.match(s):
        # cidr?
        a, _, p = s.partition("/")
        if p.isascii() and p.isdigit() and len(p) <= 3 and ((is_ipv4(a) and int(p) <= 32) or (":" in a and int(p) <= 128)):
            try:
                return "cidr", str(ipaddress.ip_network(s, strict=False))
            except ValueError:
                return None, orig
        return None, orig
    if "@" in s:
        m = _EMAIL.match(s)
        if m:
            d = _domain(m.group(1))
            if d:
                return "email", s.rsplit("@", 1)[0] + "@" + d
        return None, orig
    if is_ipv4(s):
        return "ipv4", s
    b = s[1:-1] if s.startswith("[") and s.endswith("]") else s
    if ":" in b and re.fullmatch(r"[0-9a-fA-F:.]+", b) and b.count(":") >= 2:
        try:
            return "ipv6", ipaddress.IPv6Address(b).compressed
        except ValueError:
            return None, orig
    host, port = split_port(s)
    if port is not None:
        if is_ipv4(host):
            return "ipv4", host
        d = _domain(host)
        if d and not _is_filename(host):
            return "domain", d
        return None, orig
    if _is_filename(s) or _PATHFILE.match(s) and _is_filename(s):
        return "filename", s
    d = _domain(s)
    if d:
        if tld_of(d) in FILE_EXTS_UNAMBIGUOUS:
            return "filename", s
        return "domain", d
    return None, orig


def ip_of(ioc):
    """Return ipaddress object for ipv4/ipv6 IOC value, else None."""
    try:
        return ipaddress.ip_address(ioc["value"])
    except (ValueError, KeyError, TypeError):
        return None
