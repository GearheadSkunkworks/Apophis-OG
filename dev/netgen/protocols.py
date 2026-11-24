"""
Application-layer payload builders. Each function returns bytes that are
handed to a TcpSession or wrapped in a UDP datagram by flows.py.
"""
import base64
import json
import os
import random
import struct
import time
import zlib

from . import asn1 as A
from .core import csum
from .identity import get_current

SEED = 777                 # reseeded per build by netgen.reseed_all()
rng = random.Random(SEED)
DOMAIN = "corp.example.local"
REALM = DOMAIN.upper()
# The OT forest: Purdue level 3 runs its own directory (EXL-OTDC1), so OT logons authenticate in a
# separate realm and OT accounts are separate from enterprise accounts.
OT_DOMAIN = "ot.example.local"
OT_REALM = OT_DOMAIN.upper()
# The NetBIOS domain name is the leftmost label of the DNS domain, upper-cased and capped at
# 15 characters -- what Windows proposes during domain promotion. It is NOT the organisation
# name: for corp.example.local the short name is CORP, not EXAMPLE.
#
# It was hard-coded to "EXAMPLE" here while NTLM session setup and LDAP simple binds used
# "CORP", so the same environment advertised two different NetBIOS names: CLDAP Netlogon said
# one thing and ntlmssp.auth.domain said another. Deriving it removes the possibility.
NETBIOS = DOMAIN.split(".")[0].upper()[:15]
OT_NETBIOS = OT_DOMAIN.split(".")[0].upper()[:15]    # the OT forest's own short name, same derivation
BASE_DN = ",".join("DC=" + lbl for lbl in DOMAIN.split("."))


def apply_identity(identity):
    """Set the domain identity for the build about to run (called from netgen.reseed_all).

    Updates every module-level value derived from the domain -- DOMAIN, REALM, NETBIOS and
    BASE_DN -- so the whole engine speaks the chosen company's DNS/Kerberos/NetBIOS names.
    Functions read these at call time, so one call here reaches them all. A no-op in effect
    for the default identity (the literals above are written in its tokens)."""
    global DOMAIN, REALM, NETBIOS, BASE_DN, OT_DOMAIN, OT_REALM, OT_NETBIOS
    DOMAIN = identity.domain
    REALM = identity.realm
    NETBIOS = identity.netbios
    BASE_DN = ",".join("DC=" + lbl for lbl in DOMAIN.split("."))
    OT_DOMAIN = "ot." + identity.slug + ".local"        # the OT forest follows the company, like corp.*
    OT_REALM = OT_DOMAIN.upper()
    OT_NETBIOS = OT_DOMAIN.split(".")[0].upper()[:15]

FIRST = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory", "niaj", "olivia",
         "peggy", "rupert", "sybil", "trent", "victor", "walter", "yvonne", "zara", "liam", "noah", "emma", "ava", "mia",
         "lucas", "ethan", "sofia", "amelia", "harper", "elijah", "james", "logan", "mason", "aria", "chloe", "ella"]
LAST = ["mathers", "okafor", "lindqvist", "reyes", "tanaka", "brennan", "kowalski", "haddad", "nguyen", "petrov",
        "sorensen", "delacroix", "mbeki", "costa", "whitfield", "yamamoto", "ibrahim", "fischer", "oduya", "marchetti"]


def username_for(hostname: str) -> str:
    n = int("".join(ch for ch in hostname if ch.isdigit()) or "0")
    return f"{FIRST[n % len(FIRST)][0]}{LAST[(n * 7) % len(LAST)]}"


PASSWORD_WORDS = ["Autumn", "Falcon", "Harbor", "Meadow", "Quartz", "Ripple", "Summit", "Thistle", "Willow", "Zephyr",
                  "Beacon", "Canyon", "Driftwood", "Granite", "Horizon", "Juniper"]


def password_for(user: str) -> str:
    """Deterministic, per-account password — a fixed build never gives two accounts the same
    secret, the way one shared constant does. `abrennan` keeps a fixed, documented password
    (CRP-03 brief fix 2's "one documented account for the page tasks") so a session note or
    answer key can cite it without that being the Extra Challenge's own hidden marker."""
    if user == "abrennan":
        return "Printer!23"
    h = zlib.crc32(user.encode())
    word = PASSWORD_WORDS[h % len(PASSWORD_WORDS)]
    num = (h >> 8) % 90 + 10
    return f"{word}{num}!"


def blob(n: int) -> bytes:
    """Compressed-looking (high entropy) filler, e.g. office documents."""
    return os.urandom(n)


_PE_STRINGS = (b"KERNEL32.dll", b"ADVAPI32.dll", b"USER32.dll", b"WS2_32.dll", b"OpenSCManagerW", b"CreateServiceW",
               b"StartServiceCtrlDispatcherW", b"RegisterServiceCtrlHandlerExW", b"SetServiceStatus", b"CreateProcessW",
               b"CreateNamedPipeW", b"ConnectNamedPipe", b"ReadFile", b"WriteFile", b"GetModuleFileNameW", b"LoadLibraryA",
               b"GetProcAddress", b"VirtualAlloc", b"ExitProcess", b"This program cannot be run in DOS mode.",
               b"C:\\Windows\\System32\\cmd.exe", b"\\\\.\\pipe\\", b"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
               b"Microsoft Visual C++ Runtime Library", b"api-ms-win-crt-runtime-l1-1-0.dll", b"%s\\%s", b"R6034", b"bad allocation")


def pe_blob(n: int, dll=False) -> bytes:
    """A file of n bytes that starts as a valid 64-bit PE image: MZ header with the DOS stub, PE signature,
    COFF header (EXE or DLL), optional header and a four-section table (.text .rdata .data .rsrc) whose raw
    sizes add up to the file; .rdata carries import and message strings, everything else is high-entropy."""
    n = max(n, 4096)
    stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21This program cannot be run in DOS mode.\r\r\n$".ljust(64, b"\x00")
    dos = b"MZ" + b"\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8" + b"\x00" * 7 + b"\x40" + b"\x00" * 35
    dos = dos[:60] + struct.pack("<I", 0x80)
    hdr_size = 0x400
    body = n - hdr_size
    sizes = [int(body * 0.55) // 512 * 512, int(body * 0.25) // 512 * 512, int(body * 0.12) // 512 * 512]
    sizes.append(body - sum(sizes))
    names = (b".text", b".rdata", b".data", b".rsrc")
    chars = (0x60000020, 0x40000040, 0xC0000040, 0x40000040)
    ts = rng.randint(0x5F000000, 0x69000000)
    coff = struct.pack("<HHIIIHH", 0x8664, 4, ts, 0, 0, 240, 0x2022 if dll else 0x0022)
    va, entry = 0x1000, 0x1000 + rng.randint(0x10, 0x400)
    opt = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII", 0x20B, 14, rng.randint(10, 38), sizes[0], sizes[1] + sizes[2], 0,
                      entry, 0x1000, 0x180000000 if not dll else 0x10000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0,
                      0x1000 + sum((x + 0xFFF) // 0x1000 * 0x1000 for x in sizes), hdr_size, 0,
                      3 if not dll else 2, 0x8160, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt = opt + b"\x00" * (240 - len(opt))
    sect = b""
    raw = hdr_size
    for nm, sz, ch in zip(names, sizes, chars, strict=False):
        sect += struct.pack("<8sIIIIIIHHI", nm, sz, va, sz, raw, 0, 0, 0, 0, ch)
        va += (sz + 0xFFF) // 0x1000 * 0x1000
        raw += sz
    head = (dos.ljust(0x40, b"\x00") + stub).ljust(0x80, b"\x00") + b"PE\x00\x00" + coff + opt + sect
    head = head.ljust(hdr_size, b"\x00")
    strings = b"\x00".join(rng.sample(_PE_STRINGS, len(_PE_STRINGS))) + b"\x00"
    rdata = (strings + os.urandom(max(0, sizes[1] - len(strings))))[:sizes[1]]
    return head + os.urandom(sizes[0]) + rdata + os.urandom(sizes[2]) + os.urandom(sizes[3])


def text_blob(n: int) -> bytes:
    words = ("shipment manifest pallet carrier dock lane tracking invoice consignee origin destination weight kg "
             "hazmat customs broker eta etd container seal trailer route driver depot hub scan exception delivered").split()
    out = []
    size = 0
    below, m = rng._randbelow, len(words)        # choice(words) and randint(6, 14) are these draws, minus two call layers each
    while size < n:
        w = " ".join([words[below(m)] for _ in range(6 + below(9))]).capitalize() + ".\n"
        out.append(w)
        size += len(w)
    return "".join(out).encode()[:n]


def file_blob(name: str, n: int) -> bytes:
    """A file of n bytes with a minimal valid header for its extension (PDF, or the OOXML zip
    magic for xlsx/docx/pptx) and a text-extractable body, so a read of a staged file is not
    just opaque random bytes -- an analyst pulling the SMB read packets gets something to find."""
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    n = max(n, 256)
    if ext == "pdf":
        head = b"%PDF-1.7\n1 0 obj<</Type/Catalog>>endobj\n%% "
        body = text_blob(max(0, n - len(head) - 9))
        return (head + body)[:n - 9] + b"\n%%EOF\n"
    if ext in ("xlsx", "docx", "pptx"):
        # a minimal local-file-header-shaped ZIP (PK\x03\x04) -- the OOXML container magic --
        # followed by a plausible text body; not a real parseable archive, just the magic bytes.
        head = b"PK\x03\x04" + b"\x00" * 26
        return (head + text_blob(max(0, n - len(head))))[:n]
    return text_blob(n) if n < 200_000 else blob(n)


# ============================================================================ DNS
def _dns_name(name: str) -> bytes:
    out = b""
    for lab in name.rstrip(".").split("."):
        out += bytes([len(lab)]) + lab.encode()
    return out + b"\x00"


DNS_A, DNS_AAAA, DNS_PTR, DNS_SRV, DNS_SOA, DNS_TXT = 1, 28, 12, 33, 6, 16


def dns_query(txid: int, name: str, qtype=DNS_A, rd=True, edns=False) -> bytes:
    flags = 0x0100 if rd else 0x0000
    q = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 1 if edns else 0) + _dns_name(name) + struct.pack("!HH", qtype, 1)
    if edns:   # EDNS0 OPT pseudo-record (RFC 6891): UDP payload size 1232, no DO bit, no options
        q += b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)
    return q


def dns_referral(txid: int, name: str, qtype: int, zone: str, ns_names, ttl=172800) -> bytes:
    """A non-authoritative referral: no answer, the delegated zone's NS records in the authority section."""
    q = _dns_name(name) + struct.pack("!HH", qtype, 1)
    auth = b"".join(_dns_name(zone) + struct.pack("!HHIH", 2, 1, ttl, len(_dns_name(n))) + _dns_name(n) for n in ns_names)
    return struct.pack("!HHHHHH", txid, 0x8000, 1, 0, len(ns_names), 0) + q + auth


def dns_response(txid: int, name: str, qtype: int, answers, rcode=0, aa=True, ttl=1200, authority=None, auth_ttl=3600) -> bytes:
    """answers: list of (rtype, rdata_bytes) or for SRV/PTR strings handled by caller."""
    flags = 0x8180 | (0x0400 if aa else 0) | rcode
    q = _dns_name(name) + struct.pack("!HH", qtype, 1)
    ans = b""
    for rtype, rdata in answers:
        ans += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata
    auth = b""
    if authority:
        auth = _dns_name(authority[0]) + struct.pack("!HHIH", DNS_SOA, 1, auth_ttl, len(authority[1])) + authority[1]
    return struct.pack("!HHHHHH", txid, flags, 1, len(answers), 1 if authority else 0, 0) + q + ans + auth


def soa_rdata(mname=None, rname=None) -> bytes:
    _id = get_current()
    mname = mname or _id.fqdn("DC1")
    rname = rname or ("hostmaster." + _id.domain)
    return _dns_name(mname) + _dns_name(rname) + struct.pack("!IIIII", 2026091401, 900, 600, 86400, 3600)


def tld_negative(name: str, nxdomain=True):
    """Authority section a public resolver returns for a negative answer. A name that does not exist (NXDOMAIN)
    carries the TLD operator's SOA (a0.nic.<tld>); a name that exists with no record of the type asked (NODATA)
    carries the registered domain's own SOA. Never the internal domain controller's. Returns (zone, soa_rdata, ttl)."""
    labels = name.rstrip(".").split(".")
    tld = labels[-1]
    if not nxdomain and len(labels) >= 2:
        zone = ".".join(labels[-2:])
        soa = (_dns_name(f"ns1.{zone}") + _dns_name(f"hostmaster.{zone}")
               + struct.pack("!IIIII", rng.randint(2026010100, 2026110599), 7200, 3600, 1209600, 300))
        return zone, soa, 300
    soa = (_dns_name(f"a0.nic.{tld}") + _dns_name(f"noc.nic.{tld}")
           + struct.pack("!IIIII", rng.randint(1790000000, 1790999999), 1800, 900, 604800, 900))
    return tld, soa, rng.choice((300, 600, 900))


def srv_rdata(prio, weight, port, target) -> bytes:
    return struct.pack("!HHH", prio, weight, port) + _dns_name(target)


# ========================================================================== DHCP
def dhcp(op: int, xid: int, mac: bytes, msgtype: int, ciaddr=b"\x00" * 4, yiaddr=b"\x00" * 4, siaddr=b"\x00" * 4,
         giaddr=b"\x00" * 4, options=b"", flags=0x8000, hops=0, secs=0) -> bytes:
    hdr = struct.pack("!BBBBIHH", op, 1, 6, hops, xid, secs, flags) + ciaddr + yiaddr + siaddr + giaddr + mac + b"\x00" * 10
    hdr += b"\x00" * 192 + b"\x63\x82\x53\x63"
    return hdr + b"\x35\x01" + bytes([msgtype]) + options + b"\xff"


def opt(code: int, data: bytes) -> bytes:
    return bytes([code, len(data)]) + data


def dhcp_client_opts(hostname: str, mac: bytes, windows=True, req_ip=None, server_id=None) -> bytes:
    o = opt(61, b"\x01" + mac)
    if req_ip:
        o += opt(50, req_ip)
    if server_id:
        o += opt(54, server_id)
    o += opt(12, hostname.encode())
    if windows:
        o += opt(81, b"\x00\x00\x00" + f"{hostname}.{DOMAIN}".encode())
        o += opt(60, b"MSFT 5.0")
        o += opt(55, bytes([1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]))
    else:
        o += opt(55, bytes([1, 121, 3, 6, 15, 108, 114, 119, 252, 95, 44, 46]))
    return o


def dhcp_server_opts(server_ip: bytes, router: bytes, dns: list, lease=28800) -> bytes:
    return (opt(54, server_ip) + opt(51, struct.pack("!I", lease)) + opt(58, struct.pack("!I", lease // 2))
            + opt(59, struct.pack("!I", lease * 7 // 8)) + opt(1, b"\xff\xff\xff\x00") + opt(3, router)
            + opt(6, b"".join(dns)) + opt(15, DOMAIN.encode()))


# =========================================================================== NTP
NTP_EPOCH = 2208988800


def _ntp_ts(t: float) -> bytes:
    sec = int(t) + NTP_EPOCH
    frac = int((t - int(t)) * (1 << 32))
    return struct.pack("!II", sec & 0xFFFFFFFF, frac)


def ntp_request(t: float, windows=True) -> bytes:
    li_vn_mode = (0 << 6) | (3 << 3) | 3
    if windows:
        return struct.pack("!BBBb", li_vn_mode, 0, 10, -6) + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 24 + _ntp_ts(t)
    return struct.pack("!BBBb", (0 << 6) | (4 << 3) | 3, 0, 10, -6) + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 24 + _ntp_ts(t)


def ntp_response(t_req_origin: bytes, t_recv: float, t_tx: float, stratum=2, refid=b"\xc6\x33\x64\x05", vn=4) -> bytes:
    # RFC 5905 9.1: a server answers with the version the client asked in (NPM-11 brief fix 1)
    li_vn_mode = (0 << 6) | (vn << 3) | 4
    return (struct.pack("!BBBb", li_vn_mode, stratum, 10, -23) + struct.pack("!I", 0x00000123) + struct.pack("!I", 0x0000005A)
            + refid + _ntp_ts(t_recv - 300) + t_req_origin + _ntp_ts(t_recv) + _ntp_ts(t_tx))


# ======================================================================== KERBEROS
def _principal(ntype: int, *names: str) -> bytes:
    return A.seq(A.ctx(0, A.integer(ntype)), A.ctx(1, A.seq(*[A.gen_string(n) for n in names])))


def _enc_data(etype: int, cipher: bytes, kvno=None) -> bytes:
    parts = [A.ctx(0, A.integer(etype))]
    if kvno is not None:
        parts.append(A.ctx(1, A.integer(kvno)))
    parts.append(A.ctx(2, A.octets(cipher)))
    return A.seq(*parts)


def _ticket(sname: bytes, size: int, realm: str = None, etype: int = 18) -> bytes:
    return A.app(1, A.seq(A.ctx(0, A.integer(5)), A.ctx(1, A.gen_string(realm or REALM)), A.ctx(2, sname),
                          A.ctx(3, _enc_data(etype, blob(size), 2))))


def krb_as_req(user: str, ts: float, nonce: int, preauth: bool, realm: str = None) -> bytes:
    # realm defaults to the enterprise REALM; the OT forest (OT_REALM) passes its own
    REALM = realm or globals()["REALM"]
    cname = _principal(1, user)
    sname = _principal(2, "krbtgt", REALM)
    etypes = A.seq(A.integer(18), A.integer(17), A.integer(23), A.integer(24), A.integer(-135))
    body = A.seq(A.ctx(0, A.bitstring(b"\x40\x81\x00\x10")), A.ctx(1, cname), A.ctx(2, A.gen_string(REALM)),
                 A.ctx(3, sname), A.ctx(5, A.gen_time(ts + 86400 * 365 * 10)), A.ctx(6, A.gen_time(ts + 86400 * 365 * 10)),
                 A.ctx(7, A.integer(nonce)), A.ctx(8, etypes))
    padata = []
    if preauth:
        padata.append(A.seq(A.ctx(1, A.integer(2)), A.ctx(2, A.octets(_enc_data(18, blob(52))))))
    padata.append(A.seq(A.ctx(1, A.integer(128)), A.ctx(2, A.octets(A.seq(A.ctx(0, A.boolean(True)))))))  # PA-PAC-REQUEST
    msg = A.seq(A.ctx(1, A.integer(5)), A.ctx(2, A.integer(10)), A.ctx(3, A.seq(*padata)), A.ctx(4, body))
    return A.app(10, msg)


def krb_error_preauth(user: str, ts: float, code: int = 25, realm: str = None) -> bytes:
    """KRB-ERROR. code 25 = KDC_ERR_PREAUTH_REQUIRED (normal), 24 = KDC_ERR_PREAUTH_FAILED (spray/bad password)."""
    REALM = realm or globals()["REALM"]
    edata = A.seq(
        A.seq(A.ctx(1, A.integer(19)), A.ctx(2, A.octets(A.seq(A.seq(A.ctx(0, A.integer(18)), A.ctx(1, A.gen_string(REALM + user))))))),
        A.seq(A.ctx(1, A.integer(2)), A.ctx(2, A.octets(b""))),
        A.seq(A.ctx(1, A.integer(16)), A.ctx(2, A.octets(b""))),
        A.seq(A.ctx(1, A.integer(15)), A.ctx(2, A.octets(b""))),
    )
    # crealm [7] and cname [8] are OPTIONAL in KRB-ERROR (RFC 4120 §5.9.1) and Windows always
    # sends them. Without them the error names no account, so nothing downstream can attribute
    # a failed logon to a user — which makes every authentication failure anonymous and, for
    # practical purposes, invisible. They are the whole reason to emit these at all.
    msg = A.seq(A.ctx(0, A.integer(5)), A.ctx(1, A.integer(30)), A.ctx(4, A.gen_time(ts)), A.ctx(5, A.integer(rng.randint(1, 999999))),
                A.ctx(6, A.integer(code)), A.ctx(7, A.gen_string(REALM)), A.ctx(8, _principal(1, user)),
                A.ctx(9, A.gen_string(REALM)), A.ctx(10, _principal(2, "krbtgt", REALM)),
                A.ctx(12, A.octets(edata)))
    return A.app(30, msg)


def krb_as_rep(user: str, pac_size=1400, realm: str = None, etype: int = 18) -> bytes:
    """etype 18 (AES) for a normal logon; AS-REP roasting (no pre-auth) asks for RC4 (23), which
    makes the reply crackable the same way a Kerberoast ticket is."""
    REALM = realm or globals()["REALM"]
    cname = _principal(1, user)
    sname = _principal(2, "krbtgt", REALM)
    padata = A.seq(A.seq(A.ctx(1, A.integer(19)), A.ctx(2, A.octets(A.seq(A.seq(A.ctx(0, A.integer(18)), A.ctx(1, A.gen_string(REALM + user))))))))
    msg = A.seq(A.ctx(0, A.integer(5)), A.ctx(1, A.integer(11)), A.ctx(2, padata), A.ctx(3, A.gen_string(REALM)),
                A.ctx(4, cname), A.ctx(5, _ticket(sname, pac_size, REALM, etype=etype)), A.ctx(6, _enc_data(etype, blob(310), 2)))
    return A.app(11, msg)


def krb_as_req_pkinit(client: str, ts: float, nonce: int, realm: str = None) -> bytes:
    """AS-REQ carrying PA-PK-AS-REQ (padata-type 16) instead of ENC-TIMESTAMP -- the
    certificate-backed logon a PKINIT client (one holding an AD CS-issued cert) presents, as
    opposed to a password. The padata-value stands in for the real CMS-signed AuthPack; a
    sensor keys its PKINIT detection on the padata-type (16) and the principal, both of which
    are on the wire either way."""
    REALM = realm or globals()["REALM"]
    cname = _principal(1, client)
    sname = _principal(2, "krbtgt", REALM)
    etypes = A.seq(A.integer(18), A.integer(17), A.integer(23), A.integer(24), A.integer(-135))
    body = A.seq(A.ctx(0, A.bitstring(b"\x40\x81\x00\x10")), A.ctx(1, cname), A.ctx(2, A.gen_string(REALM)),
                 A.ctx(3, sname), A.ctx(5, A.gen_time(ts + 86400 * 365 * 10)), A.ctx(6, A.gen_time(ts + 86400 * 365 * 10)),
                 A.ctx(7, A.integer(nonce)), A.ctx(8, etypes))
    padata = [A.seq(A.ctx(1, A.integer(16)), A.ctx(2, A.octets(blob(900)))),
              A.seq(A.ctx(1, A.integer(128)), A.ctx(2, A.octets(A.seq(A.ctx(0, A.boolean(True))))))]
    msg = A.seq(A.ctx(1, A.integer(5)), A.ctx(2, A.integer(10)), A.ctx(3, A.seq(*padata)), A.ctx(4, body))
    return A.app(10, msg)


def krb_as_rep_pkinit(client: str, pac_size=1400, realm: str = None, etype: int = 18) -> bytes:
    """AS-REP answering a PKINIT AS-REQ: PA-PK-AS-REP (padata-type 17) replaces the
    ENC-TS-encrypted-with-password reply-key hint a password logon's AS-REP carries."""
    REALM = realm or globals()["REALM"]
    cname = _principal(1, client)
    sname = _principal(2, "krbtgt", REALM)
    padata = A.seq(A.seq(A.ctx(1, A.integer(17)), A.ctx(2, A.octets(blob(300)))))
    msg = A.seq(A.ctx(0, A.integer(5)), A.ctx(1, A.integer(11)), A.ctx(2, padata), A.ctx(3, A.gen_string(REALM)),
                A.ctx(4, cname), A.ctx(5, _ticket(sname, pac_size, REALM, etype=etype)), A.ctx(6, _enc_data(etype, blob(310), 2)))
    return A.app(11, msg)


# Encryption types offered in a TGS-REQ. A normal client offers the AES types first; a
# Kerberoast deliberately asks for RC4 (23) so the reply is encrypted under the service
# account's NTLM hash, which is crackable offline. The etype list is the classic tell.
KRB_ETYPES_NORMAL = (18, 17, 23)
KRB_ETYPES_RC4_ONLY = (23,)


def krb_tgs_req(user: str, service: str, host_fqdn: str, ts: float, nonce: int, etypes=None, realm: str = None) -> bytes:
    REALM = realm or globals()["REALM"]
    sname = _principal(2, service, host_fqdn)
    body = A.seq(A.ctx(0, A.bitstring(b"\x40\x81\x00\x00")), A.ctx(2, A.gen_string(REALM)), A.ctx(3, sname),
                 A.ctx(5, A.gen_time(ts + 86400 * 365 * 10)), A.ctx(7, A.integer(nonce)),
                 A.ctx(8, A.seq(*[A.integer(e) for e in (etypes or KRB_ETYPES_NORMAL)])))
    ap_req = A.app(14, A.seq(A.ctx(0, A.integer(5)), A.ctx(1, A.integer(14)), A.ctx(2, A.bitstring(b"\x00\x00\x00\x00")),
                             A.ctx(3, _ticket(_principal(2, "krbtgt", REALM), 1400, REALM)), A.ctx(4, _enc_data(18, blob(130)))))
    padata = A.seq(A.seq(A.ctx(1, A.integer(1)), A.ctx(2, A.octets(ap_req))),
                   A.seq(A.ctx(1, A.integer(167)), A.ctx(2, A.octets(A.seq(A.ctx(0, A.bitstring(b"\x80\x00\x00\x00")))))))
    return A.app(12, A.seq(A.ctx(1, A.integer(5)), A.ctx(2, A.integer(12)), A.ctx(3, padata), A.ctx(4, body)))


def krb_tgs_rep(user: str, service: str, host_fqdn: str, realm: str = None, etype: int = 18) -> bytes:
    """etype 18 for a normal AES ticket; Kerberoasting asks for RC4 (23), so the ticket AND the
    enc-part the TGS-REP wraps it in must both come back etype 23 -- that is what makes the
    reply crackable offline against the service account's NTLM hash."""
    REALM = realm or globals()["REALM"]
    msg = A.seq(A.ctx(0, A.integer(5)), A.ctx(1, A.integer(13)), A.ctx(3, A.gen_string(REALM)), A.ctx(4, _principal(1, user)),
                A.ctx(5, _ticket(_principal(2, service, host_fqdn), 1500, REALM, etype=etype)), A.ctx(6, _enc_data(etype, blob(220))))
    return A.app(13, msg)


def krb_ap_req_token(user: str, service: str, host_fqdn: str) -> bytes:
    """GSS-API/SPNEGO initial token carrying a Kerberos AP-REQ (for SMB, LDAP, HTTP Negotiate)."""
    ap_req = A.app(14, A.seq(A.ctx(0, A.integer(5)), A.ctx(1, A.integer(14)), A.ctx(2, A.bitstring(b"\x20\x00\x00\x00")),
                             A.ctx(3, _ticket(_principal(2, service, host_fqdn), 1500)), A.ctx(4, _enc_data(18, blob(150)))))
    krb_oid = A.oid("1.2.840.113554.1.2.2")
    inner = krb_oid + b"\x01\x00" + ap_req          # GSS-API InitialContextToken with TOK_ID 01 00
    gss = A.app(0, inner)
    mech_types = A.seq(krb_oid, A.oid("1.2.840.48018.1.2.2"), A.oid("1.3.6.1.4.1.311.2.2.10"))
    neg_init = A.ctx(0, A.seq(A.ctx(0, mech_types), A.ctx(2, A.octets(gss))))
    return A.app(0, A.oid("1.3.6.1.5.5.2") + neg_init)


def spnego_accept_completed() -> bytes:
    ap_rep = A.app(15, A.seq(A.ctx(0, A.integer(5)), A.ctx(1, A.integer(15)), A.ctx(2, _enc_data(18, blob(60)))))
    krb_oid = A.oid("1.2.840.113554.1.2.2")
    gss = A.app(0, krb_oid + b"\x02\x00" + ap_rep)
    return A.ctx(1, A.seq(A.ctx(0, A.enum(0)), A.ctx(1, krb_oid), A.ctx(2, A.octets(gss))))


# ========================================================================== LDAP
def _ldap_msg(msgid: int, protocol_op: bytes, controls=b"") -> bytes:
    return A.seq(A.integer(msgid), protocol_op, controls)


def _filter_eq(attr: str, value: str) -> bytes:
    return A.tlv(0xA3, A.octets(attr.encode()) + A.octets(value.encode()))


def _filter_present(attr: str) -> bytes:
    return A.tlv(0x87, attr.encode())


def _filter_and(*fs) -> bytes:
    return A.tlv(0xA0, b"".join(fs))


def ldap_bind_request(msgid: int, token: bytes) -> bytes:
    sasl = A.tlv(0xA3, A.octets(b"GSS-SPNEGO") + A.octets(token))
    return _ldap_msg(msgid, A.tlv(0x60, A.integer(3) + A.octets(b"") + sasl))


def ldap_bind_response(msgid: int) -> bytes:
    cred = A.tlv(0x87, spnego_accept_completed())
    return _ldap_msg(msgid, A.tlv(0x61, A.enum(0) + A.octets(b"") + A.octets(b"") + cred))


def ldap_bind_request_simple(msgid: int, dn: str, password: bytes = b"") -> bytes:
    """Simple (non-SASL) bind — the kind an appliance or a script does, and the kind that can
    fail with a readable reason."""
    return _ldap_msg(msgid, A.tlv(0x60, A.integer(3) + A.octets(dn.encode()) + A.tlv(0x80, password)))


def ldap_bind_response_fail(msgid: int, rc: int = 49, data: str = "52e", dn: str = "") -> bytes:
    """A refused bind.

    Active Directory answers *every* credential problem with resultCode 49 (invalidCredentials)
    and hides the real reason in the diagnostic message as `AcceptSecurityContext error, data
    <hex>`: 52e wrong password, 525 no such user, 532 password expired, 533 account disabled,
    701 account expired, 773 must reset, 775 locked out. Analysts read that hex, so getting it
    on the wire is the whole point — a bare 49 says almost nothing.
    """
    msg = f"80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data {data}, v4563"
    return _ldap_msg(msgid, A.tlv(0x61, A.enum(rc) + A.octets(dn.encode()) + A.octets(msg.encode())))


def ldap_search_request(msgid: int, base: str, scope: int, filt: bytes, attrs: list, size_limit=0, controls=b"") -> bytes:
    attr_seq = A.seq(*[A.octets(a.encode()) for a in attrs])
    body = (A.octets(base.encode()) + A.enum(scope) + A.enum(0) + A.integer(size_limit) + A.integer(0)
            + A.boolean(False) + filt + attr_seq)
    return _ldap_msg(msgid, A.tlv(0x63, body), controls)


LDAP_PAGED_OID = "1.2.840.113556.1.4.319"        # RFC 2696 simple paged results


def ldap_paged_control(size: int, cookie: bytes = b"") -> bytes:
    """Controls ::= [0] SEQUENCE OF Control; the paged-results value is SEQUENCE { size, cookie }."""
    val = A.seq(A.integer(size), A.octets(cookie))
    return A.ctx(0, A.seq(A.octets(LDAP_PAGED_OID.encode()), A.octets(val)))


def ldap_search_entry(msgid: int, dn: str, attrs: dict) -> bytes:
    parts = []
    for k, vals in attrs.items():
        parts.append(A.seq(A.octets(k.encode()), A.set_(*[A.octets(v if isinstance(v, bytes) else v.encode()) for v in vals])))
    return _ldap_msg(msgid, A.tlv(0x64, A.octets(dn.encode()) + A.seq(*parts)))


def ldap_search_done(msgid: int, rc=0, controls=b"") -> bytes:
    return _ldap_msg(msgid, A.tlv(0x65, A.enum(rc) + A.octets(b"") + A.octets(b"")), controls)


def ldap_unbind(msgid: int) -> bytes:
    return _ldap_msg(msgid, b"\x42\x00")


def cldap_netlogon_query(msgid: int, hostname: str) -> bytes:
    filt = _filter_and(_filter_eq("DnsDomain", DOMAIN), _filter_eq("Host", hostname), _filter_eq("NtVer", "\x16\x00\x00\x00"))
    return ldap_search_request(msgid, "", 0, filt, ["Netlogon"])


def cldap_netlogon_response(msgid: int, dc_fqdn: str) -> bytes:
    n = _dns_name
    nl = (struct.pack("<HHI", 0x17, 0, 0x0003F3FD) + os.urandom(16) + n(DOMAIN) + n(DOMAIN) + n(dc_fqdn) + n(NETBIOS)
          + n(dc_fqdn.split(".")[0].upper()) + b"\x00" + n("Default-First-Site-Name") + n("Default-First-Site-Name")
          + struct.pack("<IHH", 5, 0xFFFF, 0xFFFF))
    entry = ldap_search_entry(msgid, "", {"Netlogon": [nl]})
    return entry + ldap_search_done(msgid)


# =========================================================================== SMB2
SMB2_NEGOTIATE, SMB2_SESSION_SETUP, SMB2_LOGOFF, SMB2_TREE_CONNECT, SMB2_TREE_DISCONNECT = 0, 1, 2, 3, 4
SMB2_CREATE, SMB2_CLOSE, SMB2_FLUSH, SMB2_READ, SMB2_WRITE, SMB2_IOCTL, SMB2_QUERY_DIR, SMB2_QUERY_INFO = 5, 6, 7, 8, 9, 11, 14, 16
SMB2_SET_INFO = 17


class Smb2:
    """Stateful SMB2 message builder (dialect 3.1.1). Signing is on only when require_signing is
    set (Windows domain controllers require it): negotiate says so on both sides and every message
    from the final session-setup response on carries an AES-128-CMAC over the message with a
    per-session key the generator invents, as the real signature would be computed."""

    def __init__(self, require_signing=False):
        self.require_signing = require_signing
        self._sign_key = None
        self._last_create_new = False
        self._last_overwrite = False
        self.msgid = 0
        self.session = 0
        self.tree = 0
        self.credits = 1
        self._resp_mid = None

    def _consume_ids(self, charge: int):
        """A request with CreditCharge N uses N consecutive MessageIds (MS-SMB2 3.2.4.1.3). Its own id is the
        first; the next request starts after the last, and the response echoes the first."""
        self._resp_mid = self.msgid
        self.msgid += charge - 1

    def _hdr(self, cmd: int, flags: int, status=0, tree=None, credit_req=64, credit_charge=1) -> bytes:
        mid = self.msgid
        if flags & 0x01 and cmd in (SMB2_READ, SMB2_WRITE) and self._resp_mid is not None:
            mid, self._resp_mid = self._resp_mid, None
        h = struct.pack("<4sHHIHHIIQ", b"\xfeSMB", 64, credit_charge, status, cmd, credit_req, flags, 0, mid)
        h += struct.pack("<IIQ", 0xFEFF, self.tree if tree is None else tree, self.session) + b"\x00" * 16
        return h

    def wrap(self, msg: bytes) -> bytes:
        if self._sign_key is not None:
            from cryptography.hazmat.primitives import cmac
            from cryptography.hazmat.primitives.ciphers import algorithms
            flags = struct.unpack_from("<I", msg, 16)[0] | 0x8          # SMB2_FLAGS_SIGNED
            msg = msg[:16] + struct.pack("<I", flags) + msg[20:48] + b"\x00" * 16 + msg[64:]
            c = cmac.CMAC(algorithms.AES(self._sign_key))
            c.update(msg)
            msg = msg[:48] + c.finalize()[:16] + msg[64:]
        return b"\x00" + len(msg).to_bytes(3, "big") + msg

    def negotiate_req(self, client_guid: bytes) -> bytes:
        self.msgid = 0
        dialects = struct.pack("<HHHHH", 0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
        hdr = self._hdr(SMB2_NEGOTIATE, 0, credit_req=10)
        raw_off = 64 + 36 + len(dialects)
        pad = (8 - raw_off % 8) % 8
        ctx_off = raw_off + pad
        fixed = struct.pack("<HHHHI16sIHH", 36, 5, 0x0003 if self.require_signing else 0x0001, 0, 0x7F, client_guid, ctx_off, 2, 0)
        ctx1 = struct.pack("<HHI", 1, 38, 0) + struct.pack("<HHH", 1, 32, 1) + os.urandom(32)
        ctx1 += b"\x00" * ((8 - len(ctx1) % 8) % 8)
        ctx2 = struct.pack("<HHI", 2, 6, 0) + struct.pack("<HHH", 2, 0x0002, 0x0001) + b"\x00\x00"
        return self.wrap(hdr + fixed + dialects + b"\x00" * pad + ctx1 + ctx2)

    def negotiate_resp(self, server_guid: bytes, ts: float) -> bytes:
        hdr = self._hdr(SMB2_NEGOTIATE, 0x01, credit_req=1)
        ft = int((ts + 11644473600) * 10_000_000)
        token = A.app(0, A.oid("1.3.6.1.5.5.2") + A.ctx(0, A.seq(A.ctx(0, A.seq(A.oid("1.3.6.1.4.1.311.2.2.30"), A.oid("1.2.840.48018.1.2.2"), A.oid("1.2.840.113554.1.2.2"), A.oid("1.3.6.1.4.1.311.2.2.10"))))))
        sec_off = 64 + 64
        body = struct.pack("<HHHH16sIIIIQQHHI", 65, 0x0003 if self.require_signing else 1, 0x0311, 2, server_guid, 0x2F, 0x800000, 0x800000, 0x800000, ft, ft, sec_off, len(token), 0)
        body += token
        pad = (8 - (64 + len(body)) % 8) % 8
        body += b"\x00" * pad
        ctx_off = 64 + len(body)
        ctx1 = struct.pack("<HHI", 1, 38, 0) + struct.pack("<HHH", 1, 32, 1) + os.urandom(32)
        ctx1 += b"\x00" * ((8 - len(ctx1) % 8) % 8)
        ctx2 = struct.pack("<HHI", 2, 4, 0) + struct.pack("<HH", 1, 0x0002)
        body = body[:60] + struct.pack("<I", ctx_off) + body[64:]
        return self.wrap(hdr + body + ctx1 + ctx2)

    def session_setup_req(self, token: bytes) -> bytes:
        self.msgid += 1
        hdr = self._hdr(SMB2_SESSION_SETUP, 0)
        body = struct.pack("<HBBIIHHQ", 25, 0, 0x02, 0, 0, 64 + 24, len(token), 0) + token
        return self.wrap(hdr + body)

    def session_setup_resp(self) -> bytes:
        self.session = rng.getrandbits(64) | 0x1
        token = spnego_accept_completed()
        hdr = self._hdr(SMB2_SESSION_SETUP, 0x01)
        body = struct.pack("<HHHH", 9, 0, 64 + 8, len(token)) + token
        if self.require_signing:
            self._sign_key = bytes(rng.getrandbits(8) for _ in range(16))
        return self.wrap(hdr + body)

    def session_setup_challenge(self, token: bytes) -> bytes:
        """Interim response carrying the NTLM challenge.

        STATUS_MORE_PROCESSING_REQUIRED (0xC0000016) is what makes this a *continuation* rather
        than a failure — the session id is issued here and echoed by the client's type 3.
        """
        self.session = rng.getrandbits(64) | 0x1
        hdr = self._hdr(SMB2_SESSION_SETUP, 0x01, status=0xC0000016)
        body = struct.pack("<HHHH", 9, 0, 64 + 8, len(token)) + token
        return self.wrap(hdr + body)

    def session_setup_fail(self, status: int) -> bytes:
        """Refused logon. SMB2 error responses carry a 9-byte error body, not a session."""
        self.session = 0
        hdr = self._hdr(SMB2_SESSION_SETUP, 0x01, status=status)
        body = struct.pack("<HHI", 9, 0, 0) + b"\x00"
        return self.wrap(hdr + body)

    def tree_connect_req(self, path: str) -> bytes:
        self.msgid += 1
        hdr = self._hdr(SMB2_TREE_CONNECT, 0, tree=0)
        p = path.encode("utf-16-le")
        body = struct.pack("<HHHH", 9, 0, 64 + 8, len(p)) + p
        return self.wrap(hdr + body)

    def tree_connect_resp(self, share_type=1) -> bytes:
        self.tree = rng.randint(1, 0xFFFF)
        hdr = self._hdr(SMB2_TREE_CONNECT, 0x01)
        body = struct.pack("<HBBIII", 16, share_type, 0, 0x00000800 if share_type == 1 else 0, 0x1F01FF, 0x1F01FF)
        return self.wrap(hdr + body)

    def create_req(self, name: str, disposition=1, access=0x00120089, write=False, pipe=False, overwrite=False,
                   delete_on_close=False) -> bytes:
        """pipe=True: open an existing named pipe the way a Windows client does (FILE_OPEN,
        read+write data access 0x0012019F), because the caller then writes RPC PDUs to it.
        delete_on_close=True: FILE_OPEN on an existing file with DELETE added to the access
        mask and FILE_DELETE_ON_CLOSE (0x1000) in CreateOptions -- how PsExec/RemCom remove
        their dropped binary (no separate SET_INFO needed; the CLOSE deletes it)."""
        self.msgid += 1
        hdr = self._hdr(SMB2_CREATE, 0)
        n = name.encode("utf-16-le")
        self._last_create_new = bool(write) and not pipe and not overwrite and not delete_on_close     # overwrite=True: the file exists (FILE_OVERWRITTEN)
        self._last_overwrite = bool(write) and overwrite
        if pipe:
            body = struct.pack("<HBBIQQIIIIIHHII", 57, 0, 0, 2, 0, 0, 0x0012019F, 0x80, 7, 1, 0x40, 64 + 56, len(n), 0, 0) + n
            return self.wrap(hdr + body)
        if write:
            access = 0x0012019F
        if delete_on_close:
            access = 0x0013019F
        createopts = (0x44 if not write else 0x40)
        if delete_on_close:
            createopts |= 0x1000
        body = struct.pack("<HBBIQQIIIIIHHII", 57, 0, 0, 2, 0, 0, access, 0x80 if not name.endswith("\\") else 0x10,
                           7, disposition if not write else 5, createopts, 64 + 56, len(n), 0, 0) + n
        if len(n) == 0:
            body += b"\x00"
        return self.wrap(hdr + body)

    def open_existing_req(self, name: str) -> bytes:
        """CREATE that opens an existing file for read, write and rename: FILE_OPEN (never truncates),
        DesiredAccess read+write+DELETE (a rename needs DELETE on the handle)."""
        self.msgid += 1
        hdr = self._hdr(SMB2_CREATE, 0)
        n = name.encode("utf-16-le")
        self._last_create_new = False
        body = struct.pack("<HBBIQQIIIIIHHII", 57, 0, 0, 2, 0, 0, 0x0013019F, 0x80, 7, 1, 0x40, 64 + 56, len(n), 0, 0) + n
        return self.wrap(hdr + body)

    def set_info_rename_req(self, fid: bytes, new_name: str) -> bytes:
        """SET_INFO, FileRenameInformation ([MS-FSCC] 2.4.34.2): rename the open handle within its share."""
        self.msgid += 1
        hdr = self._hdr(SMB2_SET_INFO, 0)
        n = new_name.encode("utf-16-le")
        buf = struct.pack("<B7sQI", 0, b"\x00" * 7, 0, len(n)) + n
        body = struct.pack("<HBBIHHI16s", 33, 1, 10, len(buf), 64 + 32, 0, 0, fid) + buf
        return self.wrap(hdr + body)

    def set_info_resp(self) -> bytes:
        return self.wrap(self._hdr(SMB2_SET_INFO, 0x01) + struct.pack("<H", 2))

    def create_resp(self, ts: float, size: int, directory=False, action=None) -> bytes:
        hdr = self._hdr(SMB2_CREATE, 0x01)
        ft = int((ts + 11644473600) * 10_000_000)
        fid = os.urandom(16)
        if action is None:
            # FILE_OPENED (1) for an open; FILE_CREATED (2) for a create-or-overwrite that makes a new file
            action = 1 if directory else (2 if self._last_create_new else (3 if self._last_overwrite else 1))
        body = struct.pack("<HBBIQQQQQQII16sII", 89, 1, 0, action, ft, ft, ft, ft, size, size,
                           0x10 if directory else 0x20, 0, fid, 0, 0)
        return self.wrap(hdr + body), fid

    def read_req(self, fid: bytes, offset: int, length: int) -> bytes:
        self.msgid += 1
        charge = max(1, (length + 65535) // 65536)
        hdr = self._hdr(SMB2_READ, 0, credit_charge=charge)
        self._consume_ids(charge)
        body = struct.pack("<HBBIQ16sIIIHH", 49, 0x50, 0, length, offset, fid, 0, 0, 0, 0, 0) + b"\x00"
        return self.wrap(hdr + body)

    def read_resp(self, data: bytes) -> bytes:
        hdr = self._hdr(SMB2_READ, 0x01, credit_charge=max(1, (len(data) + 65535) // 65536))
        body = struct.pack("<HBBIII", 17, 0x50, 0, len(data), 0, 0) + data
        return self.wrap(hdr + body)

    def write_req(self, fid: bytes, offset: int, data: bytes) -> bytes:
        self.msgid += 1
        charge = max(1, (len(data) + 65535) // 65536)
        hdr = self._hdr(SMB2_WRITE, 0, credit_charge=charge)
        self._consume_ids(charge)
        self._last_cc = charge
        body = struct.pack("<HHIQ16sIIHHI", 49, 0x70, len(data), offset, fid, 0, 0, 0, 0, 0) + data
        return self.wrap(hdr + body)

    def write_resp(self, n: int) -> bytes:
        hdr = self._hdr(SMB2_WRITE, 0x01, credit_charge=max(1, (n + 65535) // 65536))
        return self.wrap(hdr + struct.pack("<HHIIHH", 17, 0, n, 0, 0, 0))

    def close_req(self, fid: bytes) -> bytes:
        self.msgid += 1
        hdr = self._hdr(SMB2_CLOSE, 0)
        return self.wrap(hdr + struct.pack("<HHI16s", 24, 1, 0, fid))

    def close_resp(self, ts: float, size: int) -> bytes:
        hdr = self._hdr(SMB2_CLOSE, 0x01)
        ft = int((ts + 11644473600) * 10_000_000)
        return self.wrap(hdr + struct.pack("<HHIQQQQQQI", 60, 1, 0, ft, ft, ft, ft, size, size, 0x20))

    def query_dir_req(self, fid: bytes, pattern="*") -> bytes:
        self.msgid += 1
        hdr = self._hdr(SMB2_QUERY_DIR, 0)
        p = pattern.encode("utf-16-le")
        body = struct.pack("<HBBI16sHHI", 33, 37, 0, 0, fid, 64 + 32, len(p), 65536) + p
        return self.wrap(hdr + body)

    def query_dir_resp(self, names: list, ts: float) -> bytes:
        hdr = self._hdr(SMB2_QUERY_DIR, 0x01)
        ft = int((ts + 11644473600) * 10_000_000)
        entries = b""
        for i, (name, size, is_dir) in enumerate(names):
            n = name.encode("utf-16-le")
            e = struct.pack("<IIQQQQQQIIIBB24sHQ", 0, i + 1, ft, ft, ft, ft, size, size, 0x10 if is_dir else 0x20, len(n), 0, 0, 0, b"\x00" * 24, 0, rng.getrandbits(62))
            e += n
            pad = (8 - len(e) % 8) % 8
            e += b"\x00" * pad
            if i < len(names) - 1:
                e = struct.pack("<I", len(e)) + e[4:]
            entries += e
        body = struct.pack("<HHI", 9, 64 + 8, len(entries)) + entries
        return self.wrap(hdr + body)

    def tree_disconnect_req(self) -> bytes:
        self.msgid += 1
        return self.wrap(self._hdr(SMB2_TREE_DISCONNECT, 0) + b"\x04\x00\x00\x00")

    def tree_disconnect_resp(self) -> bytes:
        return self.wrap(self._hdr(SMB2_TREE_DISCONNECT, 0x01) + b"\x04\x00\x00\x00")

    def logoff_req(self) -> bytes:
        self.msgid += 1
        return self.wrap(self._hdr(SMB2_LOGOFF, 0, tree=0) + b"\x04\x00\x00\x00")

    def logoff_resp(self) -> bytes:
        return self.wrap(self._hdr(SMB2_LOGOFF, 0x01, tree=0) + b"\x04\x00\x00\x00")


# =========================================================================== HTTP
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Microsoft-CryptoAPI/10.0",                                    # OCSP/CRL fetch
    "Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.71",  # WSUS / Windows Update
    "Microsoft NCSI",                                              # connectivity check
    "com.apple.trustd/2.0",                                        # macOS OCSP
]


def aaaa_rdata(v6: str) -> bytes:
    """16-byte AAAA rdata from an IPv6 string."""
    import socket as _s
    return _s.inet_pton(_s.AF_INET6, v6)


def ptr_rdata(name: str) -> bytes:
    return _dns_name(name)


def cname_rdata(name: str) -> bytes:
    return _dns_name(name)


def ocsp_request(serial=None) -> bytes:
    """Minimal well-formed DER OCSPRequest (RFC 6960) so the OCSP dissector parses cleanly."""
    import os as _os
    from . import asn1 as A
    serial = serial if serial is not None else int.from_bytes(_os.urandom(8), "big")
    certid = A.seq(A.seq(A.oid("1.3.14.3.2.26"), A.null()),   # SHA-1 AlgorithmIdentifier
                   A.octets(_os.urandom(20)), A.octets(_os.urandom(20)), A.integer(serial))
    request = A.seq(certid)
    tbs = A.seq(A.seq(request))                               # TBSRequest { requestList SEQ OF Request }
    return A.seq(tbs)


def ocsp_response(status=0) -> bytes:
    """Minimal DER OCSPResponse carrying only responseStatus (parses cleanly; status 0=successful)."""
    from . import asn1 as A
    return A.seq(A.enum(status))


def http_date(ts: float) -> str:
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(ts))


def http_request(method: str, path: str, host: str, ua: str, headers=None, body=b"") -> bytes:
    h = [f"{method} {path} HTTP/1.1", f"Host: {host}", "Connection: keep-alive", f"User-Agent: {ua}",
         "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
         "Accept-Encoding: gzip, deflate", "Accept-Language: en-US,en;q=0.9"]
    if headers:
        h += headers
    if body:
        h.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(h) + "\r\n\r\n").encode() + body


def http_response(status: str, body: bytes, ctype: str, ts: float, server="Microsoft-IIS/10.0", headers=None, gzip=False) -> bytes:
    if gzip:
        import gzip as _g
        body = _g.compress(body, 6, mtime=0)
    h = [f"HTTP/1.1 {status}", f"Content-Type: {ctype}", f"Content-Length: {len(body)}", f"Server: {server}",
         f"Date: {http_date(ts)}", "Connection: keep-alive"]
    if gzip:
        h.append("Content-Encoding: gzip")
    if headers:
        h += headers
    return ("\r\n".join(h) + "\r\n\r\n").encode() + body


def intranet_page(title: str, rows: int, ts: float) -> bytes:
    _id = get_current()
    trs = "".join(f"<tr><td>{_id.prefix}{rng.randint(100000, 999999)}</td><td>{rng.choice(['Chicago','Dallas','Newark','Memphis','Denver'])}</td>"
                  f"<td>{rng.choice(['In transit','Delivered','At hub','Exception'])}</td><td>{rng.randint(1, 26)} pallets</td></tr>" for _ in range(rows))
    return (f"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{title} - {_id.name} Intranet</title>"
            f"<link rel=\"stylesheet\" href=\"/static/site.css\"><script src=\"/static/app.js\" defer></script></head>"
            f"<body><header><h1>{_id.org}</h1><nav><a href=\"/\">Home</a> <a href=\"/shipments\">Shipments</a> "
            f"<a href=\"/carriers\">Carriers</a> <a href=\"/reports\">Reports</a></nav></header><main><h2>{title}</h2>"
            f"<p>Generated {http_date(ts)}</p><table><thead><tr><th>Shipment</th><th>Hub</th><th>Status</th><th>Load</th></tr></thead>"
            f"<tbody>{trs}</tbody></table></main><footer>{_id.org} internal use only</footer></body></html>").encode()


def shipments_json(n: int) -> bytes:
    items = [{"id": f"{get_current().prefix}{rng.randint(100000, 999999)}", "hub": rng.choice(["ORD", "DFW", "EWR", "MEM", "DEN"]),
              "status": rng.choice(["IN_TRANSIT", "DELIVERED", "AT_HUB", "EXCEPTION"]), "pallets": rng.randint(1, 26),
              "eta": f"2026-09-{rng.randint(14, 30):02d}T{rng.randint(0, 23):02d}:00:00Z"} for _ in range(n)]
    return json.dumps({"count": n, "items": items}, separators=(",", ":")).encode()


SITE_CSS = ("body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f8;color:#1d2a35}header{background:#0b3d6b;color:#fff;padding:12px 24px}"
            "nav a{color:#cfe3f7;margin-right:14px;text-decoration:none}main{padding:24px}table{border-collapse:collapse;width:100%;background:#fff}"
            "th,td{border-bottom:1px solid #d8dee4;padding:6px 10px;text-align:left}footer{padding:12px 24px;color:#6c7a89;font-size:12px}\n" * 12).encode()
APP_JS = ("(function(){'use strict';const api='/api/shipments';async function refresh(){const r=await fetch(api+'?page=1&size=50',{credentials:'include'});"
          "if(!r.ok)return;const j=await r.json();document.querySelector('tbody').innerHTML=j.items.map(i=>`<tr><td>${i.id}</td><td>${i.hub}</td><td>${i.status}</td><td>${i.pallets} pallets</td></tr>`).join('');}"
          "document.addEventListener('DOMContentLoaded',()=>{refresh();setInterval(refresh,60000);});})();\n" * 25).encode()


# ============================================================================ TDS
def tds_packet(ptype: int, payload: bytes, status=1, spid=0, packet_id=1) -> bytes:
    return struct.pack("!BBHHBB", ptype, status, 8 + len(payload), spid, packet_id, 0) + payload


def tds_prelogin(client=True) -> bytes:
    # option tokens: VERSION(0), ENCRYPTION(1), INSTOPT(2), THREADID(3), MARS(4), TERMINATOR(0xff)
    opts = [(0, b"\x10\x00\x0a\xdc\x00\x00"), (1, b"\x02"), (2, b"\x00"), (3, struct.pack("<I", rng.randint(1000, 9000))), (4, b"\x00")]
    hdr_len = 5 * len(opts) + 1
    hdr = b""
    body = b""
    off = hdr_len
    for t, v in opts:
        hdr += struct.pack("!BHH", t, off, len(v))
        body += v
        off += len(v)
    hdr += b"\xff"
    return tds_packet(0x12, hdr + body, spid=0 if client else rng.randint(51, 120))


def tds_login7(user: str, app="IntranetApp", host=None, db="Logistics") -> bytes:
    host = host or get_current().host("WEB1")
    def u(x):
        return x.encode("utf-16-le")
    pwd = bytes(((b >> 4) | ((b & 0xF) << 4)) ^ 0xA5 for b in "P@ssw0rd!".encode("utf-16-le"))
    fields = [u(host), u(user), pwd, u(app), u(get_current().fqdn("SQL1")), b"", u("Microsoft SqlClient Data Provider"), u("us_english"), u(db)]
    fixed = struct.pack("<IIIIIBBBBiI", 0x74000004, 4096, 0x07000000, rng.randint(1000, 9000), 0, 0xE0, 0x03, 0x00, 0x00, -300, 0x00000409)
    data_start = 4 + len(fixed) + 4 * 9 + 6 + 4 + 4 + 4 + 4
    offs = b""
    data = b""
    for f in fields:
        offs += struct.pack("<HH", data_start + len(data), len(f) // 2)
        data += f
    tail = b"\x00\x50\x56\xab\xcd\xef" + struct.pack("<HH", 0, 0) + struct.pack("<HH", 0, 0) + struct.pack("<HH", 0, 0) + struct.pack("<I", 0)
    pkt = fixed + offs + tail + data
    pkt = struct.pack("<I", len(pkt) + 4) + pkt
    return tds_packet(0x10, pkt)


def tds_login_ack(db="Logistics") -> bytes:
    def envchange(t, new, old):
        n, o = new.encode("utf-16-le"), old.encode("utf-16-le")
        body = bytes([t, len(new)]) + n + bytes([len(old)]) + o
        return b"\xe3" + struct.pack("<H", len(body)) + body
    prog = "Microsoft SQL Server".encode("utf-16-le")
    la_body = b"\x01" + b"\x74\x00\x00\x04" + bytes([len(prog) // 2]) + prog + b"\x10\x00\x0a\xdc"
    la = b"\xad" + struct.pack("<H", len(la_body)) + la_body
    msg = f"Changed database context to '{db}'.".encode("utf-16-le")
    info_body = struct.pack("<IBB", 5701, 1, 0) + struct.pack("<H", len(msg) // 2) + msg + b"\x08" + get_current().host("SQL1").encode("utf-16-le") + b"\x00" + struct.pack("<I", 1)
    info = b"\xab" + struct.pack("<H", len(info_body)) + info_body
    done = b"\xfd" + struct.pack("<HHQ", 0, 0, 0)
    return tds_packet(0x04, envchange(1, db, "master") + envchange(2, "us_english", "") + envchange(4, "4096", "4096") + la + info + done, spid=rng.randint(51, 120))


def tds_sql_batch(sql: str) -> bytes:
    all_headers = struct.pack("<IIHQI", 22, 18, 2, rng.randint(1, 2**40), 1)
    return tds_packet(0x01, all_headers + sql.encode("utf-16-le"))


def tds_result(cols: list, rows: list) -> bytes:
    """cols: list of (name, type) with type in {'int','nvarchar','datetime'}; rows: list of tuples."""
    cm = b"\x81" + struct.pack("<H", len(cols))
    for name, t in cols:
        n = name.encode("utf-16-le")
        if t == "int":
            cm += struct.pack("<IH", 0, 0x0009) + b"\x26\x04" + bytes([len(name)]) + n
        elif t == "nvarchar":
            cm += struct.pack("<IH", 0, 0x0009) + b"\xe7" + struct.pack("<H", 200) + b"\x09\x04\xd0\x00\x34" + bytes([len(name)]) + n
        else:
            cm += struct.pack("<IH", 0, 0x0009) + b"\x6f\x08" + bytes([len(name)]) + n
    body = cm
    for r in rows:
        body += b"\xd1"
        for (_name, t), v in zip(cols, r, strict=False):
            if t == "int":
                body += b"\x04" + struct.pack("<i", v)
            elif t == "nvarchar":
                s = v.encode("utf-16-le")
                body += struct.pack("<H", len(s)) + s
            else:
                body += b"\x08" + struct.pack("<ii", 46270 + rng.randint(0, 10), rng.randint(0, 25919999))
    body += b"\xfd" + struct.pack("<HHQ", 0x10, 0xC1, len(rows))
    return body


def tds_error(number: int, msg: str, severity: int = 20, state: int = 1, line: int = 1, spid: int = 60) -> bytes:
    """A TDS ERROR token (0xAA) stream terminated by DONE with error flag set."""
    m = msg.encode("utf-16-le")
    srv = get_current().host("SQL1").encode("utf-16-le")
    proc = b""
    body = struct.pack("<IBB", number, state, severity) + struct.pack("<H", len(m) // 2) + m
    body += bytes([len(srv) // 2]) + srv + bytes([len(proc) // 2]) + proc + struct.pack("<i", line)
    tok = b"\xaa" + struct.pack("<H", len(body)) + body
    done = b"\xfd" + struct.pack("<HHQ", 0x0002, 0x0000, 0)   # DONE, error bit set, 0 rows
    return tok + done


def tds_split(ptype: int, payload: bytes, spid: int) -> bytes:
    """Split a token stream across 4096-byte TDS packets."""
    out = b""
    n = 4096 - 8
    chunks = [payload[i:i + n] for i in range(0, len(payload), n)] or [b""]
    for i, c in enumerate(chunks):
        out += tds_packet(ptype, c, status=1 if i == len(chunks) - 1 else 0, spid=spid, packet_id=(i + 1) & 0xFF)
    return out


SQL_QUERIES = [
    "SELECT TOP (50) s.ShipmentId, s.TrackingNo, h.HubCode, s.Status, s.Pallets, s.ETA FROM dbo.Shipments s JOIN dbo.Hubs h ON h.HubId = s.HubId WHERE s.Status IN ('IN_TRANSIT','AT_HUB') ORDER BY s.ETA",
    "SELECT c.CarrierId, c.Name, COUNT(*) AS OpenLoads FROM dbo.Carriers c JOIN dbo.Loads l ON l.CarrierId = c.CarrierId WHERE l.ClosedAt IS NULL GROUP BY c.CarrierId, c.Name",
    "SELECT ShipmentId, Status, UpdatedAt FROM dbo.Shipments WHERE TrackingNo = N'{prefix}{n}'",
    "UPDATE dbo.Shipments SET Status = N'AT_HUB', UpdatedAt = SYSUTCDATETIME() WHERE ShipmentId = {n}",
    "SELECT TOP (200) * FROM dbo.ScanEvents WHERE ShipmentId = {n} ORDER BY ScannedAt DESC",
    "EXEC dbo.usp_GetDockSchedule @HubCode = N'ORD', @Date = '2026-09-14'",
    "SELECT UserId, DisplayName, Role FROM dbo.Users WHERE sAMAccountName = N'{user}'",
]


# ========================================================================== CAPWAP
CAPWAP_HDR_CTRL = b"\x00\x10\x02\x00\x00\x00\x00\x00"   # preamble, HLEN=2, RID=0, WBID=1, no flags
CAPWAP_HDR_KEEP = b"\x00\x10\x02\x08\x00\x00\x00\x00"   # same with K (keep-alive) bit set


def capwap_echo(seq: int, request=True) -> bytes:
    return CAPWAP_HDR_CTRL + struct.pack("!IBHB", 13 if request else 14, seq & 0xFF, 0, 0)


# CAPWAP control message types: 3/4 Join, 5/6 Config Status, 7/8 Config Update,
# 9 WTP Event, 11/12 Change State Event, 13/14 Echo
def capwap_control(msgtype: int, seq: int, elems: bytes = b"") -> bytes:
    return CAPWAP_HDR_CTRL + struct.pack("!IBHB", msgtype, seq & 0xFF, len(elems), 0) + elems


def capwap_keepalive(session_id: bytes) -> bytes:
    elem = struct.pack("!HH", 35, 16) + session_id
    return CAPWAP_HDR_KEEP + struct.pack("!H", 2 + len(elem)) + elem


def capwap_data_frame(wifi_client_mac: bytes, payload_len: int) -> bytes:
    """802.3 frame tunnelled inside CAPWAP data (T-bit clear = 802.3)."""
    return CAPWAP_HDR_CTRL + wifi_client_mac + os.urandom(6) + b"\x08\x00" + os.urandom(payload_len)


# ============================================================================ SIP
def sip_msg(start: str, headers: list, body=b"") -> bytes:
    h = list(headers)
    if body:
        h.append("Content-Type: application/sdp")
    h.append(f"Content-Length: {len(body)}")
    return (start + "\r\n" + "\r\n".join(h) + "\r\n\r\n").encode() + body


def sdp(ip: str, port: int, sess_id: int) -> bytes:
    return (f"v=0\r\no=- {sess_id} 1 IN IP4 {ip}\r\ns=SIP Call\r\nc=IN IP4 {ip}\r\nt=0 0\r\n"
            f"m=audio {port} RTP/AVP 0 8 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\n"
            f"a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=ptime:20\r\na=sendrecv\r\n").encode()


def rtp_packet(seq: int, ts: int, ssrc: int, pt=0, marker=False) -> bytes:
    return struct.pack("!BBHII", 0x80, pt | (0x80 if marker else 0), seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc) + os.urandom(160)


def rtcp_sr(ssrc: int, ntp: float, rtp_ts: int, pkts: int, octets: int) -> bytes:
    # All three are 32-bit fields that WRAP (RFC 3550 §6.4.1), and callers pass a random
    # initial RTP timestamp plus an offset — so rtp_ts legitimately exceeds 2**32 on a long
    # call that started near the top of the range. rtp_packet() has always masked; this did
    # not, and raised struct.error instead. Deterministic seeding made that a guaranteed crash
    # at scale 1.0 rather than a rare one.
    sr = (struct.pack("!BBHI", 0x80, 200, 6, ssrc) + _ntp_ts(ntp)
          + struct.pack("!III", rtp_ts & 0xFFFFFFFF, pkts & 0xFFFFFFFF, octets & 0xFFFFFFFF))
    cname = f"{ssrc:08x}@{get_current().prefix.lower().rstrip('-')}".encode()
    sdes_item = bytes([1, len(cname)]) + cname
    sdes_body = struct.pack("!I", ssrc) + sdes_item + b"\x00"
    sdes_body += b"\x00" * ((4 - len(sdes_body) % 4) % 4)
    sdes = struct.pack("!BBH", 0x81, 202, len(sdes_body) // 4) + sdes_body
    return sr + sdes


def rtcp_sr_report(ssrc: int, ntp: float, rtp_ts: int, pkts: int, octets: int, source_ssrc: int,
                   fraction_lost: int, cumulative_lost: int, ext_high_seq: int, jitter: int,
                   lsr: int = 0, dlsr: int = 0) -> bytes:
    """RFC 3550 compound packet from an endpoint that is also sending media: Sender Report with one
    reception report block about the peer's stream (6.4.1) followed by SDES with the CNAME (6.1)."""
    block = (struct.pack("!I", source_ssrc & 0xFFFFFFFF)
             + struct.pack("!I", ((fraction_lost & 0xFF) << 24) | (cumulative_lost & 0xFFFFFF))
             + struct.pack("!IIII", ext_high_seq & 0xFFFFFFFF, jitter & 0xFFFFFFFF, lsr & 0xFFFFFFFF, dlsr & 0xFFFFFFFF))
    sr = (struct.pack("!BBHI", 0x81, 200, 12, ssrc) + _ntp_ts(ntp)
          + struct.pack("!III", rtp_ts & 0xFFFFFFFF, pkts & 0xFFFFFFFF, octets & 0xFFFFFFFF) + block)
    cname = f"{ssrc:08x}@{get_current().prefix.lower().rstrip('-')}".encode()
    sdes_body = struct.pack("!I", ssrc) + bytes([1, len(cname)]) + cname + b"\x00"
    sdes_body += b"\x00" * ((4 - len(sdes_body) % 4) % 4)
    return sr + struct.pack("!BBH", 0x81, 202, len(sdes_body) // 4) + sdes_body


def ntp_middle32(t: float) -> int:
    """Middle 32 bits of the NTP timestamp, as carried in a report block's LSR field."""
    return int.from_bytes(_ntp_ts(t)[2:6], "big")


def rtcp_rr(reporter_ssrc: int, source_ssrc: int, fraction_lost: int, cumulative_lost: int,
            jitter: int, ext_high_seq: int = 0, lsr: int = 0, dlsr: int = 0) -> bytes:
    """RTCP Receiver Report (PT=201) carrying loss fraction and interarrival jitter, so a
    monitor can compute call quality / MOS. fraction_lost 0-255 (of 256); jitter in RTP ts units."""
    report_block = (struct.pack("!I", source_ssrc & 0xFFFFFFFF)
                    + struct.pack("!I", ((fraction_lost & 0xFF) << 24) | (cumulative_lost & 0xFFFFFF))
                    + struct.pack("!I", ext_high_seq & 0xFFFFFFFF)
                    + struct.pack("!I", jitter & 0xFFFFFFFF)
                    + struct.pack("!I", lsr & 0xFFFFFFFF)
                    + struct.pack("!I", dlsr & 0xFFFFFFFF))
    body = struct.pack("!I", reporter_ssrc & 0xFFFFFFFF) + report_block
    length_words = (4 + len(body)) // 4 - 1          # total 32-bit words minus one
    return struct.pack("!BBH", 0x81, 201, length_words) + body   # V=2, RC=1, PT=201


def krb_error(code: int, user: str, ts: float, service: str = "krbtgt") -> bytes:
    """Minimal KRB-ERROR. code 37 = KRB_AP_ERR_SKEW (clock skew), 32 = TKT_EXPIRED, etc."""
    msg = A.seq(A.ctx(0, A.integer(5)), A.ctx(1, A.integer(30)), A.ctx(4, A.gen_time(ts)),
                A.ctx(5, A.integer(rng.randint(1, 999999))), A.ctx(6, A.integer(code)),
                A.ctx(7, A.gen_string(REALM)), A.ctx(8, _principal(1, user)),
                A.ctx(9, A.gen_string(REALM)), A.ctx(10, _principal(2, service, REALM)))
    return A.app(30, msg)


# =========================================================================== NTLM
# NTLMSSP, for the authentication that is NOT Kerberos. A real Windows estate always has some:
# a legacy app that never got an SPN, a share reached by IP literal (which skips Kerberos
# entirely), a non-domain-joined device. It is also the path that carries the clearest failure
# signal, because the NT status code says exactly why a logon was refused.
#
# Wire format (MS-NLMP): 8-byte signature, 4-byte message type, then a run of fixed fields in
# which every variable-length item is a descriptor — len(2), maxlen(2), offset(4) — pointing
# into a payload appended after the fixed part. Strings are UTF-16LE when the UNICODE flag is
# negotiated, which it always is here. tshark reads `ntlmssp.auth.username`,
# `ntlmssp.auth.domain`, `ntlmssp.auth.hostname` and `ntlmssp.ntlmserverchallenge` out of this.

NTLMSSP_SIG = b"NTLMSSP\x00"
# UNICODE | OEM | REQUEST_TARGET | NTLM | ALWAYS_SIGN | EXTENDED_SESSIONSECURITY | TARGET_INFO
# | VERSION | 128 | 56 — what a modern Windows client actually offers.
NTLM_FLAGS = 0xE2888235


def _ntlm_field(payload_len: int, offset: int) -> bytes:
    return struct.pack("<HHI", payload_len, payload_len, offset)


def _ntlm_version() -> bytes:
    # Windows 10/Server 2019-ish: major 10, minor 0, build 19041, NTLM revision 15.
    return struct.pack("<BBHxxxB", 10, 0, 19041, 15)


def ntlm_negotiate(domain: str = "", workstation: str = "") -> bytes:
    """NTLMSSP_NEGOTIATE (type 1) — the client's opening offer."""
    d = domain.upper().encode("ascii")
    w = workstation.upper().encode("ascii")
    off = 32 + 8                                  # fixed part + version
    body = NTLMSSP_SIG + struct.pack("<I", 1) + struct.pack("<I", NTLM_FLAGS)
    body += _ntlm_field(len(d), off) + _ntlm_field(len(w), off + len(d))
    body += _ntlm_version()
    return body + d + w


def ntlm_challenge(target: str, challenge: bytes = None, dns_domain: str = "") -> bytes:
    """NTLMSSP_CHALLENGE (type 2) — the server's 8-byte nonce plus its target info."""
    tgt = target.upper().encode("utf-16-le")
    challenge = challenge or os.urandom(8)
    # AV_PAIRs: NetBIOS domain (2), NetBIOS computer (1), DNS domain (4), EOL (0)
    dns = (dns_domain or target).lower().encode("utf-16-le")
    info = (struct.pack("<HH", 2, len(tgt)) + tgt
            + struct.pack("<HH", 1, len(tgt)) + tgt
            + struct.pack("<HH", 4, len(dns)) + dns
            + struct.pack("<HH", 0, 0))
    t_off = 48 + 8
    i_off = t_off + len(tgt)
    body = NTLMSSP_SIG + struct.pack("<I", 2)
    body += _ntlm_field(len(tgt), t_off)
    body += struct.pack("<I", NTLM_FLAGS) + challenge + b"\x00" * 8
    body += _ntlm_field(len(info), i_off)
    body += _ntlm_version()
    return body + tgt + info


def ntlm_authenticate(user: str, domain: str, workstation: str, nt_len: int = 24) -> bytes:
    """NTLMSSP_AUTH (type 3) — the message that actually names the account.

    This is the one that matters for identity attribution: `ntlmssp.auth.username` comes from
    here. An NTLM exchange without it is invisible to anything that reports who logged on.
    """
    u = user.encode("utf-16-le")
    d = domain.upper().encode("utf-16-le")
    w = workstation.upper().encode("utf-16-le")
    lm = b"\x00" * 24
    nt = os.urandom(nt_len)                       # NTLMv2 response: 16-byte proof + blob
    skey = os.urandom(16)
    off = 64 + 8 + 16                             # fixed + version + MIC
    lm_off = off
    nt_off = lm_off + len(lm)
    d_off = nt_off + len(nt)
    u_off = d_off + len(d)
    w_off = u_off + len(u)
    k_off = w_off + len(w)
    body = NTLMSSP_SIG + struct.pack("<I", 3)
    body += _ntlm_field(len(lm), lm_off) + _ntlm_field(len(nt), nt_off)
    body += _ntlm_field(len(d), d_off) + _ntlm_field(len(u), u_off) + _ntlm_field(len(w), w_off)
    body += _ntlm_field(len(skey), k_off)
    body += struct.pack("<I", NTLM_FLAGS) + _ntlm_version() + os.urandom(16)   # MIC
    return body + lm + nt + d + u + w + skey


# --- SPNEGO wrappers carrying NTLM rather than Kerberos ---------------------------------
NTLM_OID = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"      # 1.3.6.1.4.1.311.2.2.10


def spnego_ntlm_init(nego: bytes) -> bytes:
    """negTokenInit offering NTLM only — what a client sends when Kerberos is not on the table."""
    mech_types = A.ctx(0, A.seq(NTLM_OID))
    return A.ctx(0, A.seq(mech_types, A.ctx(2, A.octets(nego))))


def spnego_ntlm_challenge(chal: bytes) -> bytes:
    """negTokenTarg, negResult = accept-incomplete (1), carrying the NTLM challenge."""
    return A.ctx(1, A.seq(A.ctx(0, A.enum(1)), A.ctx(1, NTLM_OID), A.ctx(2, A.octets(chal))))


def spnego_ntlm_auth(auth: bytes) -> bytes:
    """negTokenTarg carrying the NTLM type 3 message."""
    return A.ctx(1, A.seq(A.ctx(2, A.octets(auth))))


# =========================================================================== SNMP
def snmp_get(reqid: int, oids: list, community=b"public", getnext=False) -> bytes:
    vbs = A.seq(*[A.seq(A.oid(o), A.null()) for o in oids])
    pdu = A.tlv(0xA1 if getnext else 0xA0, A.integer(reqid) + A.integer(0) + A.integer(0) + vbs)
    return A.seq(A.integer(1), A.octets(community), pdu)


def snmp_response(reqid: int, varbinds: list, community=b"public") -> bytes:
    vbs = A.seq(*[A.seq(A.oid(o), v) for o, v in varbinds])
    pdu = A.tlv(0xA2, A.integer(reqid) + A.integer(0) + A.integer(0) + vbs)
    return A.seq(A.integer(1), A.octets(community), pdu)


def snmp_getbulk(reqid: int, oids: list, community=b"public", non_repeaters=0, max_repetitions=10) -> bytes:
    """GetBulkRequest-PDU (RFC 3416): same shape as GetRequest, but the error-status/
    error-index slots are reinterpreted as non-repeaters/max-repetitions. What
    snmpbulkwalk/most NMS table walkers send instead of a run of GetNexts."""
    vbs = A.seq(*[A.seq(A.oid(o), A.null()) for o in oids])
    pdu = A.tlv(0xA5, A.integer(reqid) + A.integer(non_repeaters) + A.integer(max_repetitions) + vbs)
    return A.seq(A.integer(1), A.octets(community), pdu)


def snmp_trap_v2(reqid: int, uptime: int, trap_oid: str, varbinds: list, community=b"public") -> bytes:
    vbs = [A.seq(A.oid("1.3.6.1.2.1.1.3.0"), A.snmp_timeticks(uptime)), A.seq(A.oid("1.3.6.1.6.3.1.1.4.1.0"), A.oid(trap_oid))]
    vbs += [A.seq(A.oid(o), v) for o, v in varbinds]
    pdu = A.tlv(0xA7, A.integer(reqid) + A.integer(0) + A.integer(0) + A.seq(*vbs))
    return A.seq(A.integer(1), A.octets(community), pdu)


# ========================================================================= SYSLOG
def syslog(pri: int, ts: float, host: str, msg: str) -> bytes:
    stamp = time.strftime("%b %e %H:%M:%S", time.localtime(ts))
    return f"<{pri}>{stamp} {host} {msg}".encode()


# ===================================================================== NBNS/LLMNR
def _nb_encode(name: str, suffix=0x00) -> bytes:
    name = name.upper().ljust(15)[:15] + chr(suffix)
    enc = "".join(chr(((ord(c) >> 4) & 0xF) + 0x41) + chr((ord(c) & 0xF) + 0x41) for c in name)
    return b"\x20" + enc.encode() + b"\x00"


def nbns_query(txid: int, name: str, suffix=0x20) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0110, 1, 0, 0, 0) + _nb_encode(name, suffix) + struct.pack("!HH", 0x20, 1)


def nbns_registration(txid: int, name: str, ip: bytes, suffix=0x00) -> bytes:
    q = _nb_encode(name, suffix)
    rr = q + struct.pack("!HHIH", 0x20, 1, 300000, 6) + b"\x00\x00" + ip
    return struct.pack("!HHHHHH", txid, 0x2910, 1, 0, 0, 1) + q + struct.pack("!HH", 0x20, 1) + rr


def llmnr_query(txid: int, name: str, qtype=1) -> bytes:
    return struct.pack("!HHHHHH", txid, 0, 1, 0, 0, 0) + _dns_name(name) + struct.pack("!HH", qtype, 1)


def mdns_query(names: list) -> bytes:
    q = b"".join(_dns_name(n) + struct.pack("!HH", DNS_PTR, 1) for n in names)
    return struct.pack("!HHHHHH", 0, 0, len(names), 0, 0, 0) + q


def txt_rdata(items) -> bytes:
    """DNS-SD TXT rdata: each key=value is a length-prefixed string. Always compute the
    lengths — a hand-written prefix that disagrees with its string malforms the record."""
    out = b""
    for it in items:
        b = it.encode() if isinstance(it, str) else it
        if len(b) > 255:
            raise ValueError("TXT string too long")
        out += bytes([len(b)]) + b
    return out


def mdns_response(name: str, instance: str, host: str, port: int, ip: bytes, txt: bytes = None) -> bytes:
    ptr = _dns_name(name) + struct.pack("!HHIH", DNS_PTR, 0x8001, 4500, len(_dns_name(instance + "." + name))) + _dns_name(instance + "." + name)
    srv_rd = struct.pack("!HHH", 0, 0, port) + _dns_name(host)
    srv = _dns_name(instance + "." + name) + struct.pack("!HHIH", DNS_SRV, 0x8001, 120, len(srv_rd)) + srv_rd
    if txt is not None:
        txt_rd = txt
    else:
        _model = b"model=" + get_current().host("SB").encode()
        txt_rd = bytes([len(_model)]) + _model + b"\x09srcvers=1"
    txt = _dns_name(instance + "." + name) + struct.pack("!HHIH", DNS_TXT, 0x8001, 4500, len(txt_rd)) + txt_rd
    a = _dns_name(host) + struct.pack("!HHIH", DNS_A, 0x8001, 120, 4) + ip
    return struct.pack("!HHHHHH", 0, 0x8400, 0, 4, 0, 0) + ptr + srv + txt + a


def ssdp_msearch() -> bytes:
    return (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:dial-multiscreen-org:service:dial:1\r\n"
            b"USER-AGENT: Google Chrome/128.0.0.0 Windows\r\n\r\n")


# ====================================================================== PJL/PRINT
def pjl_job(user: str, docname: str, size: int) -> bytes:
    head = (f"\x1b%-12345X@PJL JOB NAME=\"{docname}\"\r\n@PJL SET USERNAME=\"{user}\"\r\n@PJL SET JOBNAME=\"{docname}\"\r\n"
            f"@PJL SET COPIES=1\r\n@PJL SET DUPLEX=OFF\r\n@PJL SET RESOLUTION=600\r\n@PJL ENTER LANGUAGE=PCLXL\r\n").encode()
    body = b") HP-PCL XL;3;0;Comment Copyright HP\n" + zlib.compress(text_blob(size), 9)
    tail = b"\x1b%-12345X@PJL EOJ NAME=\"" + docname.encode() + b"\"\r\n\x1b%-12345X"
    return head + body + tail


# =========================================================================== SSH
def ssh_kexinit(client=True) -> bytes:
    def nl(s):
        b = s.encode()
        return struct.pack("!I", len(b)) + b
    # "ext-info-c" is a client-only marker (RFC 8308); a server's list never carries it
    kex = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group16-sha512" + (",ext-info-c" if client else "")
    hk = "ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256"
    enc = "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com"
    mac = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com"
    comp = "none,zlib@openssh.com"
    payload = b"\x14" + os.urandom(16) + nl(kex) + nl(hk) + nl(enc) + nl(enc) + nl(mac) + nl(mac) + nl(comp) + nl(comp) + nl("") + nl("") + b"\x00" + b"\x00\x00\x00\x00"
    return ssh_packet(payload)


def ssh_packet(payload: bytes) -> bytes:
    pad = 8 - (len(payload) + 5) % 8
    if pad < 4:
        pad += 8
    return struct.pack("!IB", len(payload) + 1 + pad, pad) + payload + os.urandom(pad)


def ssh_ecdh_init() -> bytes:
    return ssh_packet(b"\x1e" + struct.pack("!I", 32) + os.urandom(32))


def ssh_ecdh_reply() -> bytes:
    hk = struct.pack("!I", 51) + struct.pack("!I", 11) + b"ssh-ed25519" + struct.pack("!I", 32) + os.urandom(32)
    sig = struct.pack("!I", 83) + struct.pack("!I", 11) + b"ssh-ed25519" + struct.pack("!I", 64) + os.urandom(64)
    return ssh_packet(b"\x1f" + hk + struct.pack("!I", 32) + os.urandom(32) + sig)


def ssh_newkeys() -> bytes:
    return ssh_packet(b"\x15")


def ssh_encrypted(n: int) -> bytes:
    return os.urandom(n)


# ============================================================================ RDP
def rdp_x224_connect(user: str) -> bytes:
    cookie = f"Cookie: mstshash={user}\r\n".encode()
    neg = struct.pack("<BBHI", 1, 0, 8, 0x0000000B)   # TYPE_RDP_NEG_REQ, protocols = TLS | CredSSP (HYBRID)
    x224 = struct.pack("!BBHHB", 6 + len(cookie) + len(neg), 0xE0, 0, 0, 0) + cookie + neg
    return struct.pack("!BBH", 3, 0, 4 + len(x224)) + x224


def rdp_x224_confirm() -> bytes:
    neg = struct.pack("<BBHI", 2, 0, 8, 0x00000002)   # TYPE_RDP_NEG_RSP, selected = HYBRID (CredSSP)
    x224 = struct.pack("!BBHHB", 6 + len(neg), 0xD0, 0, 0, 0) + neg
    return struct.pack("!BBH", 3, 0, 4 + len(x224)) + x224


# ========================================================================= DCERPC
NDR_SYNTAX = bytes.fromhex("045d888aeb1cc9119fe808002b104860") + struct.pack("<I", 2)
import uuid as _uuidmod


def _dce_uuid(text: str) -> bytes:
    """Interface UUID as it travels in a DCE/RPC bind: the first three groups little-endian."""
    return _uuidmod.UUID(text).bytes_le


DRSUAPI_UUID = _dce_uuid("e3514235-4b06-11d1-ab04-00c04fc2dcd2")   # drsuapi v4.0
EFSR_UUID = _dce_uuid("c681d488-d850-11d0-8c52-00c04fd90f7e")   # MS-EFSR; PetitPotam coercion


def efs_open_file_raw_req(unc: str) -> bytes:
    """A valid NDR stub for EfsRpcOpenFileRaw (MS-EFSR opnum 0): a conformant+varying wide
    string (the UNC path the victim is coerced to reach) and a Flags long. Valid NDR so tshark
    dissects it cleanly rather than flagging a malformed packet."""
    w = unc.encode("utf-16-le") + b"\x00\x00"
    n = len(w) // 2
    stub = struct.pack("<III", n, 0, n) + w            # max_count, offset, actual_count, chars
    if len(stub) % 4:                                   # NDR 4-byte alignment
        stub += b"\x00" * (4 - len(stub) % 4)
    stub += struct.pack("<I", 0)                        # Flags
    return stub


def efs_open_file_raw_resp() -> bytes:
    """EfsRpcOpenFileRaw response: a 20-byte context handle and a return status."""
    return b"\x00" * 4 + os.urandom(16) + struct.pack("<I", 0)
EPM_UUID = _dce_uuid("e1af8308-5d1f-11c9-91a4-08002b14a0fa")       # epmapper v3.0
SPOOLSS_UUID = _dce_uuid("12345678-1234-abcd-ef00-0123456789ab")   # spoolss
SVCCTL_UUID = _dce_uuid("367abb81-9844-35f1-ad32-98f038001003")    # svcctl
SRVSVC_UUID = _dce_uuid("4b324fc8-1670-01d3-1278-5a47bf6ee188")    # srvsvc
WKSSVC_UUID = _dce_uuid("6bffd098-a112-3610-9833-46c3f87e345a")    # wkssvc
# DCOM / WMI (MS-DCOM, MS-WMI): activation on tcp/135, then the objects on a dynamic port
WMI_ACTIVATOR_UUID = _dce_uuid("000001a0-0000-0000-c000-000000000046")   # ISystemActivator v0.0
IREMUNKNOWN2_UUID = _dce_uuid("00000143-0000-0000-c000-000000000046")    # IRemUnknown2 v0.0
WMI_LOGIN_UUID = _dce_uuid("f309ad18-d86a-11d0-a075-00c04fb68820")       # IWbemLevel1Login v0.0
WMI_SERVICES_UUID = _dce_uuid("9556dc99-828c-11cf-a37e-00aa003240c7")    # IWbemServices v0.0
WMI_UUID = WMI_LOGIN_UUID           # the interface the diagram's WMI filter keys on


def _pad4(b: bytes) -> bytes:
    return b + b"\x00" * ((4 - len(b) % 4) % 4)


def _dce_hdr(ptype: int, flags: int, frag_len: int, auth_len: int, callid: int) -> bytes:
    return struct.pack("<BBBBBBBBHHI", 5, 0, ptype, flags, 0x10, 0, 0, 0, frag_len, auth_len, callid)


def _gss_krb_token(tok_id: bytes, inner: bytes) -> bytes:
    return A.app(0, A.oid("1.2.840.113554.1.2.2") + tok_id + inner)


def _krb_ap_req_raw(user: str, service: str, host_fqdn: str) -> bytes:
    return A.app(14, A.seq(A.ctx(0, A.integer(5)), A.ctx(1, A.integer(14)), A.ctx(2, A.bitstring(b"\x20\x00\x00\x00")),
                           A.ctx(3, _ticket(_principal(2, service, host_fqdn), 1500)), A.ctx(4, _enc_data(18, blob(150)))))


def _krb_ap_rep_raw() -> bytes:
    return A.app(15, A.seq(A.ctx(0, A.integer(5)), A.ctx(1, A.integer(15)), A.ctx(2, _enc_data(18, blob(60)))))


def _auth_trailer(auth_type: int, level: int, pad_len: int, value: bytes) -> bytes:
    return struct.pack("<BBBBI", auth_type, level, pad_len, 0, 0) + value


def _wrap_token() -> bytes:
    """RFC 4121 wrap token header (sealed) + confounder/checksum tail as seen in DCERPC privacy."""
    return b"\x05\x04\x06\xff" + struct.pack("!HHQ", 0, 28, rng.getrandbits(48)) + os.urandom(60)


def dcerpc_bind(callid: int, abstract_uuid: bytes, ver: int, auth=None, extra=()) -> bytes:
    """auth: None (no auth) or (user, service, host_fqdn) for Kerberos packet privacy.
    extra: further (uuid, version) presentation contexts, numbered 1.. after the first."""
    ctx = struct.pack("<HBB", 0, 1, 0) + abstract_uuid + struct.pack("<HH", ver, 0) + NDR_SYNTAX
    for i, (eu, ev) in enumerate(extra, 1):
        ctx += struct.pack("<HBB", i, 1, 0) + eu + struct.pack("<HH", ev, 0) + NDR_SYNTAX
    body = struct.pack("<HHIBBH", 5840, 5840, 0, 1 + len(extra), 0, 0) + ctx
    trailer = b""
    if auth:
        trailer = _auth_trailer(16, 6, 0, _gss_krb_token(b"\x01\x00", _krb_ap_req_raw(*auth)))
    hdr = _dce_hdr(11, 3, 16 + len(body) + len(trailer), len(trailer) - 8 if auth else 0, callid)
    return hdr + body + trailer


def dcerpc_bind_ack(callid: int, sec_addr: str, auth=False, nctx: int = 1) -> bytes:
    sa = sec_addr.encode() + b"\x00"
    body = struct.pack("<HHI", 5840, 5840, 0x12345) + struct.pack("<H", len(sa)) + sa
    body = _pad4(body)
    body += struct.pack("<BBHHH", nctx, 0, 0, 0, 0) + NDR_SYNTAX
    for _ in range(nctx - 1):
        body += struct.pack("<HH", 0, 0) + NDR_SYNTAX
    trailer = b""
    if auth:
        trailer = _auth_trailer(16, 6, 0, _gss_krb_token(b"\x02\x00", _krb_ap_rep_raw()))
    hdr = _dce_hdr(12, 3, 16 + len(body) + len(trailer), len(trailer) - 8 if auth else 0, callid)
    return hdr + body + trailer


def dcerpc_request(callid: int, opnum: int, stub: bytes, sealed=False, ctx_id: int = 0) -> bytes:
    if sealed:
        pad = (16 - len(stub) % 16) % 16
        stub = os.urandom(len(stub) + pad)
        trailer = _auth_trailer(16, 6, pad, _wrap_token())
        hdr = _dce_hdr(0, 3, 24 + len(stub) + len(trailer), len(trailer) - 8, callid)
    else:
        stub = _pad4(stub)
        trailer = b""
        hdr = _dce_hdr(0, 3, 24 + len(stub), 0, callid)
    return hdr + struct.pack("<IHH", len(stub), ctx_id, opnum) + stub + trailer


def dcerpc_response(callid: int, stub: bytes, sealed=False) -> bytes:
    if sealed:
        pad = (16 - len(stub) % 16) % 16
        stub = os.urandom(len(stub) + pad)
        trailer = _auth_trailer(16, 6, pad, _wrap_token())
        hdr = _dce_hdr(2, 3, 24 + len(stub) + len(trailer), len(trailer) - 8, callid)
    else:
        stub = _pad4(stub)
        trailer = b""
        hdr = _dce_hdr(2, 3, 24 + len(stub), 0, callid)
    return hdr + struct.pack("<IHH", len(stub), 0, 0) + stub + trailer


def _tower(if_uuid: bytes, if_ver: int, port: int, ip: bytes) -> bytes:
    def floor(lhs, rhs):
        return struct.pack("<H", len(lhs)) + lhs + struct.pack("<H", len(rhs)) + rhs
    t = struct.pack("<H", 5)
    t += floor(b"\x0d" + if_uuid + struct.pack("<H", if_ver), b"\x00\x00")
    t += floor(b"\x0d" + NDR_SYNTAX[:16] + b"\x02\x00", b"\x00\x00")
    t += floor(b"\x0b", b"\x00\x00")
    t += floor(b"\x07", struct.pack("!H", port))
    t += floor(b"\x09", ip)
    return t


def epm_map_request(if_uuid: bytes, if_ver: int, ip: bytes) -> bytes:
    """ept_map (opnum 3) stub: object uuid ptr, tower ptr, entry handle, max towers."""
    tower = _tower(if_uuid, if_ver, 135, ip)
    obj = struct.pack("<I", 1) + b"\x00" * 16
    tw = struct.pack("<I", 2) + struct.pack("<II", len(tower), len(tower)) + _pad4(tower)
    return obj + tw + b"\x00" * 20 + struct.pack("<I", 4)


def epm_map_response(if_uuid: bytes, if_ver: int, port: int, ip: bytes) -> bytes:
    tower = _tower(if_uuid, if_ver, port, ip)
    towers = struct.pack("<III", 4, 0, 1) + struct.pack("<I", 3) + struct.pack("<II", len(tower), len(tower)) + _pad4(tower)
    return b"\x00" * 20 + struct.pack("<I", 1) + towers + struct.pack("<I", 0)


# =========================================================================== ICMP
def icmp_echo(ident: int, seq: int, request=True, payload=None) -> bytes:
    if payload is None:
        payload = bytes(range(0x61, 0x61 + 23)) + bytes(range(0x61, 0x61 + 9))  # Windows 32-byte abcdef... pattern
    hdr = struct.pack("!BBHHH", 8 if request else 0, 0, 0, ident, seq)
    c = csum(hdr + payload)
    return hdr[:2] + struct.pack("H", c) + hdr[4:] + payload


def icmp_frag_needed(next_mtu: int, quoted: bytes) -> bytes:
    """ICMP type 3 code 4 (Destination Unreachable - Fragmentation Needed and DF Set), carrying the
    next-hop MTU and the first 28 bytes (IP header + 8) of the oversized datagram that triggered it.
    This is the packet a PMTUD blackhole never delivers back to the sender."""
    hdr = struct.pack("!BBHHH", 3, 4, 0, 0, next_mtu & 0xFFFF)
    c = csum(hdr + quoted)
    return hdr[:2] + struct.pack("H", c) + hdr[4:] + quoted


# ==================================================== DNS tunneling / cleartext
_B32 = "abcdefghijklmnopqrstuvwxyz234567"


def b32label(data: bytes) -> str:
    """RFC 4648-ish base32 (lowercase, no padding) for DNS-safe labels."""
    bits = 0
    val = 0
    out = []
    for byte in data:
        val = (val << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(_B32[(val >> bits) & 31])
    if bits:
        out.append(_B32[(val << (5 - bits)) & 31])
    return "".join(out)


def dns_tunnel_query(txid: int, payload: bytes, domain: str, qtype=DNS_TXT, rd=True, edns=False) -> bytes:
    """Encode payload as dot-separated base32 labels under an attacker domain."""
    enc = b32label(payload)
    labels = [enc[i:i + 60] for i in range(0, len(enc), 60)] or ["a"]
    name = ".".join(labels) + "." + domain
    return dns_query(txid, name, qtype, rd=rd, edns=edns)


def dns_tunnel_response(txid: int, name: str, data: bytes, qtype=DNS_TXT, aa=True) -> bytes:
    if qtype == DNS_TXT:
        chunk = base64.b64encode(data)[:255]      # printable, the way a tunnelling tool encodes its downstream
        rd = bytes([len(chunk)]) + chunk
    else:  # NULL / CNAME-style: stuff data into a name
        rd = _dns_name(b32label(data)[:120] + "." + name.split(".", 1)[-1])
    return dns_response(txid, name, qtype, [(qtype, rd)], aa=aa, ttl=0)


def http_basic_request(method: str, path: str, host: str, user: str, pw: str, ua: str = "curl/8.6.0") -> bytes:
    cred = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return http_request(method, path, host, ua, [f"Authorization: Basic {cred}"])


def ftp_line(s: str) -> bytes:
    return (s + "\r\n").encode()


# ======================================================================== MCP
# Model Context Protocol over the Streamable HTTP transport (spec 2025-06-18, which
# replaced the 2024-11-05 HTTP+SSE transport). Wire shape, per the specification:
#   * ONE endpoint path serving both POST and GET (here /mcp).
#   * Client POSTs a single JSON-RPC 2.0 request/notification/response, and MUST send
#     `Accept: application/json, text/event-stream`.
#   * A POSTed *request* gets back either `application/json` (one object) or an SSE stream.
#   * A POSTed *notification* or *response* gets `202 Accepted` with NO body.
#   * The server MAY assign `Mcp-Session-Id` on the InitializeResult; the client MUST then
#     echo it on every subsequent request, along with `MCP-Protocol-Version`.
#   * The client MAY GET the endpoint to hold open an SSE stream for server->client messages.
#   * DELETE with the session id terminates the session.
# Everything below emits exactly those bytes, so the capture dissects as ordinary HTTP with
# readable JSON-RPC bodies.
MCP_PROTOCOL_VERSION = "2025-06-18"
MCP_ENDPOINT = "/mcp"
MCP_PORT = 3000


def _json(obj) -> bytes:
    """Compact JSON, the way a real client serializes it."""
    import json as _j
    return _j.dumps(obj, separators=(",", ":")).encode()


def jsonrpc_request(rid, method, params=None) -> bytes:
    m = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        m["params"] = params
    return _json(m)


def jsonrpc_notification(method, params=None) -> bytes:
    m = {"jsonrpc": "2.0", "method": method}          # a notification carries no id
    if params is not None:
        m["params"] = params
    return _json(m)


def jsonrpc_result(rid, result) -> bytes:
    return _json({"jsonrpc": "2.0", "id": rid, "result": result})


def jsonrpc_error(rid, code, message, data=None) -> bytes:
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return _json({"jsonrpc": "2.0", "id": rid, "error": err})


def mcp_post(host: str, body: bytes, session_id=None, ua="mcp-client/1.2.0",
             proto=True, path=MCP_ENDPOINT) -> bytes:
    """Client -> server POST. `Accept` lists both types, as the spec requires."""
    h = [f"POST {path} HTTP/1.1", f"Host: {host}", "Connection: keep-alive",
         f"User-Agent: {ua}", "Accept: application/json, text/event-stream",
         "Content-Type: application/json"]
    if proto:
        h.append(f"MCP-Protocol-Version: {MCP_PROTOCOL_VERSION}")
    if session_id:
        h.append(f"Mcp-Session-Id: {session_id}")
    h.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(h) + "\r\n\r\n").encode() + body


def mcp_get_stream(host: str, session_id, ua="mcp-client/1.2.0", last_event_id=None,
                   path=MCP_ENDPOINT) -> bytes:
    """Client -> server GET that opens the server-to-client SSE stream."""
    h = [f"GET {path} HTTP/1.1", f"Host: {host}", "Connection: keep-alive",
         f"User-Agent: {ua}", "Accept: text/event-stream", "Cache-Control: no-store",
         f"MCP-Protocol-Version: {MCP_PROTOCOL_VERSION}"]
    if session_id:
        h.append(f"Mcp-Session-Id: {session_id}")
    if last_event_id:
        h.append(f"Last-Event-ID: {last_event_id}")
    return ("\r\n".join(h) + "\r\n\r\n").encode()


def mcp_delete(host: str, session_id, ua="mcp-client/1.2.0", path=MCP_ENDPOINT) -> bytes:
    """Client -> server DELETE: explicit session termination."""
    h = [f"DELETE {path} HTTP/1.1", f"Host: {host}", "Connection: keep-alive",
         f"User-Agent: {ua}", f"MCP-Protocol-Version: {MCP_PROTOCOL_VERSION}",
         f"Mcp-Session-Id: {session_id}", "Content-Length: 0"]
    return ("\r\n".join(h) + "\r\n\r\n").encode()


def mcp_json_response(body: bytes, ts: float, session_id=None, server="luminaboard-mcp/2.4.0") -> bytes:
    """Server -> client single JSON-RPC response (`Content-Type: application/json`)."""
    h = ["HTTP/1.1 200 OK", "Content-Type: application/json",
         f"Content-Length: {len(body)}", f"Server: {server}", f"Date: {http_date(ts)}",
         "Connection: keep-alive"]
    if session_id:
        h.append(f"Mcp-Session-Id: {session_id}")
    return ("\r\n".join(h) + "\r\n\r\n").encode() + body


def mcp_accepted(ts: float, server="luminaboard-mcp/2.4.0") -> bytes:
    """Server -> client `202 Accepted`, no body — the response to a notification/response."""
    h = ["HTTP/1.1 202 Accepted", f"Server: {server}", f"Date: {http_date(ts)}",
         "Content-Length: 0", "Connection: keep-alive"]
    return ("\r\n".join(h) + "\r\n\r\n").encode()


def mcp_sse_headers(ts: float, session_id=None, server="luminaboard-mcp/2.4.0") -> bytes:
    """Server -> client SSE stream headers. No Content-Length: the body is open-ended."""
    h = ["HTTP/1.1 200 OK", "Content-Type: text/event-stream", "Cache-Control: no-cache, no-store",
         f"Server: {server}", f"Date: {http_date(ts)}", "Connection: keep-alive"]
    if session_id:
        h.append(f"Mcp-Session-Id: {session_id}")
    return ("\r\n".join(h) + "\r\n\r\n").encode()


def mcp_sse_event(data: bytes, event_id=None, event="message") -> bytes:
    """One SSE frame. `id:` makes the stream resumable via Last-Event-ID, per the spec."""
    out = b""
    if event_id is not None:
        out += b"id: " + str(event_id).encode() + b"\n"
    if event:
        out += b"event: " + event.encode() + b"\n"
    return out + b"data: " + data + b"\n\n"


def mcp_sse_comment(text="keepalive") -> bytes:
    """An SSE comment line — what real servers send to keep an idle stream warm."""
    return b": " + text.encode() + b"\n\n"


# ---- realistic payloads for a conference-room display that has become an MCP server ----
MCP_SERVER_INFO = {"name": "luminaboard-mcp", "title": "LuminaBoard Room Agent", "version": "2.4.0"}
MCP_TOOLS = [
    {"name": "get_room_status", "title": "Room Status",
     "description": "Current occupancy, display state and input source for this room",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "display_message", "title": "Display Message",
     "description": "Show a message on the room display",
     "inputSchema": {"type": "object",
                     "properties": {"text": {"type": "string", "description": "Message to display"},
                                    "seconds": {"type": "integer", "description": "How long to show it"}},
                     "required": ["text"]}},
    {"name": "capture_whiteboard", "title": "Capture Whiteboard",
     "description": "Capture the current whiteboard surface as a PNG resource",
     "inputSchema": {"type": "object",
                     "properties": {"format": {"type": "string", "enum": ["png", "pdf"]}}}},
    {"name": "list_scheduled_meetings", "title": "Scheduled Meetings",
     "description": "Meetings scheduled on this room's calendar for a given day",
     "inputSchema": {"type": "object",
                     "properties": {"date": {"type": "string", "description": "ISO-8601 date"}},
                     "required": ["date"]}},
]


def mcp_initialize(rid, client_name="mcp-client", client_version="1.2.0") -> bytes:
    return jsonrpc_request(rid, "initialize", {
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {"roots": {"listChanged": True}, "sampling": {}, "elicitation": {}},
        "clientInfo": {"name": client_name, "title": client_name, "version": client_version}})


def mcp_initialize_result(rid) -> bytes:
    return jsonrpc_result(rid, {
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {"logging": {}, "tools": {"listChanged": True},
                         "resources": {"subscribe": True, "listChanged": True},
                         "prompts": {"listChanged": True}},
        "serverInfo": MCP_SERVER_INFO,
        "instructions": "Room display agent. Use get_room_status before display_message."})


def mcp_tools_list_result(rid) -> bytes:
    return jsonrpc_result(rid, {"tools": MCP_TOOLS})


def mcp_tool_call(rid, name, arguments) -> bytes:
    return jsonrpc_request(rid, "tools/call", {"name": name, "arguments": arguments})


def mcp_tool_result(rid, text, is_error=False) -> bytes:
    return jsonrpc_result(rid, {"content": [{"type": "text", "text": text}], "isError": is_error})


# ============================================================================= MODBUS / TCP
# The OT protocols the baseline day emits (Modbus/DNP3/BACnet) are the richly-metriced ones:
#   Modbus  - 20 metrics, with req_type and rsp_error_type as NAMED STRINGS, so function
#             codes and exception codes break out per peer. The richest of the three.
#   BACnet  - 32 metrics, full APDU breakdown (confirmed/unconfirmed, the three ACK kinds,
#             errors, rejects, aborts), peer-oriented rather than client/server.
#   DNP3    - 8 metrics, request/response counts by peer only. No function-code detail.
# As of 2026-10 the platform ALSO parses EtherNet/IP, Siemens S7comm, OPC UA, synchrophasor
# (IEEE C37.118) and ICCP/TASE.2 (MMS). Those are emitted by the SELECTABLE OT scenarios (see the
# ot-* entries in incidents.py), not the always-on baseline, so a default build is unchanged; the
# builders for them live below. PROFINET and IEC 61850 are still unsupported and remain absent.

MODBUS_PORT = 502

# Function codes, with the names the platform reports them under.
MB_READ_COILS, MB_READ_DISCRETE = 0x01, 0x02
MB_READ_HOLDING, MB_READ_INPUT = 0x03, 0x04
MB_WRITE_COIL, MB_WRITE_REG = 0x05, 0x06
MB_WRITE_COILS, MB_WRITE_REGS = 0x0F, 0x10
# Exception codes. 0x02 is the one a mistyped register address produces; 0x06 is a busy slave.
MB_EX_ILLEGAL_FUNC, MB_EX_ILLEGAL_ADDR, MB_EX_ILLEGAL_VALUE = 0x01, 0x02, 0x03
MB_EX_SLAVE_FAIL, MB_EX_ACK, MB_EX_BUSY = 0x04, 0x05, 0x06
MB_EX_GATEWAY_FAILED = 0x0B   # gateway target device failed to respond -- a unit id nobody answers for


def _mbap(tid: int, unit: int, pdu: bytes) -> bytes:
    """MBAP header + PDU. The length field counts the unit id and the PDU, not itself."""
    return struct.pack("!HHHB", tid & 0xFFFF, 0, len(pdu) + 1, unit) + pdu


def modbus_read_req(tid, unit, func, start, count):
    return _mbap(tid, unit, struct.pack("!BHH", func, start, count))


def modbus_read_rsp(tid, unit, func, count, seed=None):
    """Register reads answer with a byte count then the data; coil reads pack 8 per byte."""
    if func in (MB_READ_COILS, MB_READ_DISCRETE):
        nbytes = (count + 7) // 8
        body = bytes(rng.randrange(256) for _ in range(nbytes))
    else:
        nbytes = count * 2
        body = b"".join(struct.pack("!H", rng.randrange(65536)) for _ in range(count))
    return _mbap(tid, unit, struct.pack("!BB", func, nbytes) + body)


def modbus_write_reg_req(tid, unit, addr, value):
    return _mbap(tid, unit, struct.pack("!BHH", MB_WRITE_REG, addr, value & 0xFFFF))


def modbus_write_reg_rsp(tid, unit, addr, value):
    """A successful single write echoes the request exactly -- that is the protocol."""
    return modbus_write_reg_req(tid, unit, addr, value)


def modbus_write_coil_req(tid, unit, addr, on):
    return _mbap(tid, unit, struct.pack("!BHH", MB_WRITE_COIL, addr, 0xFF00 if on else 0x0000))


def modbus_write_coil_rsp(tid, unit, addr, on):
    """A successful single coil write echoes the request exactly -- that is the protocol."""
    return modbus_write_coil_req(tid, unit, addr, on)


def modbus_write_regs_req(tid, unit, start, values):
    body = b"".join(struct.pack("!H", v & 0xFFFF) for v in values)
    return _mbap(tid, unit, struct.pack("!BHHB", MB_WRITE_REGS, start, len(values), len(body)) + body)


def modbus_write_regs_rsp(tid, unit, start, n):
    return _mbap(tid, unit, struct.pack("!BHH", MB_WRITE_REGS, start, n))


def modbus_exception(tid, unit, func, code):
    """Function code with the top bit set, then the exception code. the platform surfaces this as
    Response Errors by Error, which is why the baseline emits a few of them."""
    return _mbap(tid, unit, struct.pack("!BB", func | 0x80, code))


# ============================================================================= BACNET / IP
BACNET_PORT = 47808                 # 0xBAC0

BVLC_UNICAST, BVLC_BROADCAST = 0x0A, 0x0B
# APDU PDU types, in the high nibble of the first byte.
APDU_CONFIRMED, APDU_UNCONFIRMED, APDU_SIMPLE_ACK = 0x00, 0x10, 0x20
APDU_COMPLEX_ACK, APDU_SEGMENT_ACK, APDU_ERROR = 0x30, 0x40, 0x50
APDU_REJECT, APDU_ABORT = 0x60, 0x70
# Service choices.
BAC_READ_PROPERTY, BAC_WRITE_PROPERTY = 12, 15
BAC_COV_NOTIFICATION, BAC_WHO_IS, BAC_I_AM = 2, 8, 0
# Object types (high 10 bits of the object identifier).
BAC_OBJ_ANALOG_INPUT, BAC_OBJ_ANALOG_VALUE, BAC_OBJ_BINARY_INPUT = 0, 2, 3
BAC_OBJ_DEVICE = 8
BAC_PROP_PRESENT_VALUE, BAC_PROP_OBJECT_NAME = 85, 77


def _bvlc(func: int, npdu: bytes) -> bytes:
    """BVLC: type 0x81, function, then the length of the WHOLE BVLC message including itself."""
    return struct.pack("!BBH", 0x81, func, len(npdu) + 4) + npdu


def _npdu(expecting_reply: bool, broadcast: bool = False) -> bytes:
    """NPDU version + control.

    Bit 5 (0x20) of the control byte means "a destination specifier follows" -- DNET, DLEN and
    a hop count -- NOT "this is a broadcast". Setting it without those fields makes a dissector
    eat three bytes of the APDU, which does not produce a malformed packet: it silently
    reinterprets the PDU type, so COV notifications came back as a mixture of Confirmed-Request,
    Unconfirmed-Request and SimpleACK. A local broadcast is expressed by the BVLC function
    (0x0B, original-broadcast-NPDU) and the IP destination, and the control byte stays 0.
    """
    del broadcast                      # kept in the signature: callers read better for it
    return struct.pack("!BB", 0x01, 0x04 if expecting_reply else 0x00)


def _obj_id(obj_type: int, instance: int) -> int:
    return ((obj_type & 0x3FF) << 22) | (instance & 0x3FFFFF)


def bacnet_read_property_req(invoke_id, obj_type, instance, prop=BAC_PROP_PRESENT_VALUE):
    apdu = struct.pack("!BBBB", APDU_CONFIRMED, 0x04, invoke_id & 0xFF, BAC_READ_PROPERTY)
    apdu += b"\x0c" + struct.pack("!I", _obj_id(obj_type, instance))     # context tag 0
    apdu += b"\x19" + struct.pack("!B", prop)                            # context tag 1
    return _bvlc(BVLC_UNICAST, _npdu(True) + apdu)


def bacnet_complex_ack(invoke_id, obj_type, instance, value, prop=BAC_PROP_PRESENT_VALUE):
    apdu = struct.pack("!BBB", APDU_COMPLEX_ACK, invoke_id & 0xFF, BAC_READ_PROPERTY)
    apdu += b"\x0c" + struct.pack("!I", _obj_id(obj_type, instance))
    apdu += b"\x19" + struct.pack("!B", prop)
    apdu += b"\x3e" + b"\x44" + struct.pack("!f", value) + b"\x3f"       # opening tag, REAL, closing
    return _bvlc(BVLC_UNICAST, _npdu(False) + apdu)


def bacnet_simple_ack(invoke_id, service=BAC_WRITE_PROPERTY):
    return _bvlc(BVLC_UNICAST, _npdu(False) +
                 struct.pack("!BBB", APDU_SIMPLE_ACK, invoke_id & 0xFF, service))


def bacnet_write_property_req(invoke_id, obj_type, instance, value):
    apdu = struct.pack("!BBBB", APDU_CONFIRMED, 0x04, invoke_id & 0xFF, BAC_WRITE_PROPERTY)
    apdu += b"\x0c" + struct.pack("!I", _obj_id(obj_type, instance))
    apdu += b"\x19" + struct.pack("!B", BAC_PROP_PRESENT_VALUE)
    apdu += b"\x3e" + b"\x44" + struct.pack("!f", value) + b"\x3f"
    return _bvlc(BVLC_UNICAST, _npdu(True) + apdu)


def bacnet_cov_notification(proc_id, dev_instance, obj_type, instance, value):
    """Unconfirmed change-of-value -- the bulk of a quiet BMS, one datagram, no reply."""
    apdu = struct.pack("!BB", APDU_UNCONFIRMED, BAC_COV_NOTIFICATION)
    apdu += b"\x09" + struct.pack("!B", proc_id & 0xFF)
    apdu += b"\x1c" + struct.pack("!I", _obj_id(BAC_OBJ_DEVICE, dev_instance))
    apdu += b"\x2c" + struct.pack("!I", _obj_id(obj_type, instance))
    apdu += b"\x39\x00"
    apdu += b"\x4e" + b"\x09" + struct.pack("!B", BAC_PROP_PRESENT_VALUE)
    apdu += b"\x2e" + b"\x44" + struct.pack("!f", value) + b"\x2f" + b"\x4f"
    return _bvlc(BVLC_BROADCAST, _npdu(False, broadcast=True) + apdu)


def bacnet_who_is_req() -> bytes:
    """Unconfirmed Who-Is, no instance-range limits -- the shortest, most common form; how a
    BACnet discovery sweep actually starts, broadcast on the subnet."""
    apdu = struct.pack("!BB", APDU_UNCONFIRMED, BAC_WHO_IS)
    return _bvlc(BVLC_BROADCAST, _npdu(False) + apdu)


def bacnet_i_am_rsp(dev_instance, max_apdu=1476, vendor_id=260) -> bytes:
    """A device's I-Am reply to a Who-Is: its own device-object identifier, max APDU length,
    segmentation support (none), vendor id -- application-tagged, per ASHRAE 135, not the
    context tags ReadProperty/ComplexACK use."""
    apdu = struct.pack("!BB", APDU_UNCONFIRMED, BAC_I_AM)
    apdu += b"\xc4" + struct.pack("!I", _obj_id(BAC_OBJ_DEVICE, dev_instance))
    apdu += b"\x22" + struct.pack("!H", max_apdu)
    apdu += b"\x91\x03"                                     # segmentation-supported: no-segmentation
    apdu += b"\x21" + struct.pack("!B", vendor_id & 0xFF)
    return _bvlc(BVLC_UNICAST, _npdu(False) + apdu)


def bacnet_error(invoke_id, service=BAC_READ_PROPERTY, err_class=2, err_code=32):
    """error class 2 = object, code 32 = unknown-object."""
    apdu = struct.pack("!BBB", APDU_ERROR, invoke_id & 0xFF, service)
    apdu += b"\x91" + struct.pack("!B", err_class) + b"\x91" + struct.pack("!B", err_code)
    return _bvlc(BVLC_UNICAST, _npdu(False) + apdu)


def bacnet_reject(invoke_id, reason=9):
    return _bvlc(BVLC_UNICAST, _npdu(False) +
                 struct.pack("!BBB", APDU_REJECT, invoke_id & 0xFF, reason))


def bacnet_abort(invoke_id, reason=4):
    return _bvlc(BVLC_UNICAST, _npdu(False) +
                 struct.pack("!BBB", APDU_ABORT, invoke_id & 0xFF, reason))


# ================================================================================== DNP3
DNP3_PORT = 20000

# DNP3 uses its own CRC (IEC 60870-5-1 / DNP3 spec): polynomial 0x3D65, reflected, final
# XOR 0xFFFF. It is NOT CRC-16/CCITT. Every link-layer block carries one and tshark checks
# them, so getting this wrong shows up as a capture full of "bad CRC" rather than as silence.
_DNP3_CRC = []


def _dnp3_crc_table():
    if _DNP3_CRC:
        return _DNP3_CRC
    for b in range(256):
        crc = b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
        _DNP3_CRC.append(crc & 0xFFFF)
    return _DNP3_CRC


def dnp3_crc(data: bytes) -> bytes:
    tbl = _dnp3_crc_table()
    crc = 0
    for ch in data:
        crc = (crc >> 8) ^ tbl[(crc ^ ch) & 0xFF]
    return struct.pack("<H", (~crc) & 0xFFFF)


def _dnp3_frame(control: int, dest: int, src: int, payload: bytes) -> bytes:
    """Link header (10 bytes incl. CRC) then the payload in 16-byte blocks, each CRC'd."""
    hdr = struct.pack("<BBBBHH", 0x05, 0x64, len(payload) + 5, control, dest, src)
    out = hdr + dnp3_crc(hdr)
    for i in range(0, len(payload), 16):
        blk = payload[i:i + 16]
        out += blk + dnp3_crc(blk)
    return out


def dnp3_read_req(seq, dest, src, group=30, variation=1, count=8):
    """Application function 1 = READ. Group 30 var 1 is 32-bit analog input with flag."""
    transport = struct.pack("!B", 0xC0 | (seq & 0x3F))          # FIR+FIN, sequence
    app = struct.pack("!BB", 0xC0 | (seq & 0x0F), 0x01)         # app control, func READ
    app += struct.pack("<BBBBH", group, variation, 0x00, 0, count - 1)
    return _dnp3_frame(0xC4, dest, src, transport + app)        # 0xC4 = PRM, unconfirmed user data


def dnp3_response(seq, dest, src, count=8, iin=0x0000):
    """Function 129 = RESPONSE. IIN is the two-byte internal indications field."""
    transport = struct.pack("!B", 0xC0 | (seq & 0x3F))
    app = struct.pack("!BB", 0xC0 | (seq & 0x0F), 0x81)
    app += struct.pack("<H", iin)
    app += struct.pack("<BBBBH", 30, 1, 0x00, 0, count - 1)
    for _ in range(count):
        app += struct.pack("<BI", 0x01, rng.randrange(0, 2 ** 31))      # flag + 32-bit value
    return _dnp3_frame(0x44, dest, src, transport + app)        # 0x44 = response direction


def dnp3_link_status_req(dest, src) -> bytes:
    """Link-layer REQUEST_LINK_STATUS (function 9, a primary-station code: PRM set) -- no
    application payload, just the link header; what a master checks is alive before polling,
    part of a real enumeration pass."""
    return _dnp3_frame(0xC9, dest, src, b"")


def dnp3_link_status_rsp(dest, src) -> bytes:
    """Link-layer LINK_STATUS reply (function 11, a secondary-station code: PRM clear -- 9 and
    11 are different tables, and a dissector that reads 11 with PRM set reports it unknown)."""
    return _dnp3_frame(0x0B, dest, src, b"")


def dnp3_unsolicited(seq, dest, src, count=2):
    """Function 130 = UNSOLICITED RESPONSE -- an RTU reporting a change without being asked."""
    transport = struct.pack("!B", 0xC0 | (seq & 0x3F))
    app = struct.pack("!BB", 0xF0 | (seq & 0x0F), 0x82)
    app += struct.pack("<H", 0x0020)                            # IIN: device restart cleared
    app += struct.pack("<BBBBH", 2, 1, 0x00, 0, count - 1)      # group 2 = binary input event
    for _ in range(count):
        app += struct.pack("<B", rng.choice((0x81, 0x01)))
    return _dnp3_frame(0x44, dest, src, transport + app)


# ============================================================ RADIUS (RFC 2865), UDP 1812/1813
# Minimal but valid Access-Request / Access-Accept. User-Password is omitted (NAC/802.1X EAP
# setups authenticate without it on the wire); the platform and tshark key off the code, the
# attributes and the authenticator, all of which are present and correct here.
def radius_attr(t: int, val: bytes) -> bytes:
    return bytes([t & 0xFF, (len(val) + 2) & 0xFF]) + val


def _radius_pkt(code: int, ident: int, authenticator: bytes, attrs: bytes) -> bytes:
    length = 20 + len(attrs)
    return bytes([code & 0xFF, ident & 0xFF]) + length.to_bytes(2, "big") + authenticator + attrs


def radius_access_request(ident: int, user: str, nas_ipb: bytes, calling_id: str = "",
                          nas_port_type: int = 19) -> tuple:
    """Returns (packet, request_authenticator). nas_port_type 19 = Wireless-802.11, 15 = Ethernet."""
    auth = bytes(rng.getrandbits(8) for _ in range(16))     # Request Authenticator: random per RFC
    attrs = radius_attr(1, user.encode("latin-1", "replace"))              # User-Name
    attrs += radius_attr(4, nas_ipb)                                       # NAS-IP-Address
    attrs += radius_attr(5, (0).to_bytes(4, "big"))                        # NAS-Port
    attrs += radius_attr(61, nas_port_type.to_bytes(4, "big"))             # NAS-Port-Type
    if calling_id:
        attrs += radius_attr(31, calling_id.encode("latin-1", "replace"))  # Calling-Station-Id
    return _radius_pkt(1, ident, auth, attrs), auth


def radius_response(code: int, ident: int, req_authenticator: bytes, attrs: bytes = b"",
                    secret: bytes = None) -> bytes:
    """Access-Accept(2)/Reject(3). Response Authenticator = MD5(code+id+len+ReqAuth+attrs+secret)."""
    import hashlib
    if secret is None:
        secret = (get_current().prefix.lower() + "radius-secret").encode()
    length = 20 + len(attrs)
    head = bytes([code & 0xFF, ident & 0xFF]) + length.to_bytes(2, "big")
    resp_auth = hashlib.md5(head + req_authenticator + attrs + secret).digest()
    return head + resp_auth + attrs


# ---- 802.1X over RADIUS: EAP-Message / Message-Authenticator (RFC 3579), EAP-PEAP framing --------
RADIUS_SECRET = None            # None -> derived from the build identity (see _radius_secret)


def _radius_secret(secret=None):
    return secret if secret is not None else (get_current().prefix.lower() + "radius-secret").encode()


def eap_packet(code: int, ident: int, etype: int = None, data: bytes = b"") -> bytes:
    body = (bytes([etype]) + data) if etype is not None else b""
    return bytes([code, ident & 0xFF]) + (4 + len(body)).to_bytes(2, "big") + body


def peap_packet(code: int, ident: int, flags: int, tls: bytes = b"", total: int = None) -> bytes:
    """EAP-Request/Response, type 25 (PEAP): flags L=0x80 (4-byte TLS length follows), M=0x40, S=0x20."""
    head = bytes([flags]) + (total.to_bytes(4, "big") if flags & 0x80 else b"")
    return eap_packet(code, ident, 25, head + tls)


def eap_message_attrs(eap: bytes) -> bytes:
    """EAP-Message (79), split into 253-byte attributes (RFC 3579 3.1)."""
    return b"".join(radius_attr(79, eap[i:i + 253]) for i in range(0, len(eap), 253)) or radius_attr(79, b"")


def _with_message_authenticator(code: int, ident: int, auth_field: bytes, attrs: bytes, secret: bytes) -> bytes:
    """attrs + a valid Message-Authenticator: HMAC-MD5 over the packet with the attribute zeroed;
    auth_field is the Request Authenticator (requests) or the request's authenticator (replies)."""
    import hmac as _hmac
    ma_zero = radius_attr(80, b"\x00" * 16)
    full = attrs + ma_zero
    head = bytes([code & 0xFF, ident & 0xFF]) + (20 + len(full)).to_bytes(2, "big")
    mac = _hmac.new(secret, head + auth_field + full, "md5").digest()
    return attrs + radius_attr(80, mac)


def radius_eap_request(ident: int, user: str, nas_ipb: bytes, nas_id: str, eap: bytes, state: bytes = b"",
                       calling_id: str = "", called_id: str = "", nas_port: int = 0, nas_port_type: int = 19,
                       connect_info: str = "", first: bool = True, secret: bytes = None):
    """Access-Request of an 802.1X conversation: User-Name, NAS identity, Service-Type Framed,
    EAP-Message, State on follow-ups and a valid Message-Authenticator. Returns (packet, request authenticator)."""
    secret = _radius_secret(secret)
    auth = bytes(rng.getrandbits(8) for _ in range(16))
    a = radius_attr(1, user.encode("latin-1", "replace"))
    a += radius_attr(4, nas_ipb) + radius_attr(32, nas_id.encode())
    a += radius_attr(5, nas_port.to_bytes(4, "big")) + radius_attr(61, nas_port_type.to_bytes(4, "big"))
    a += radius_attr(6, (2).to_bytes(4, "big")) + radius_attr(12, (1400).to_bytes(4, "big"))
    if called_id:
        a += radius_attr(30, called_id.encode())
    if calling_id:
        a += radius_attr(31, calling_id.encode())
    if connect_info:
        a += radius_attr(77, connect_info.encode())
    if state:
        a += radius_attr(24, state)
    a += eap_message_attrs(eap)
    a = _with_message_authenticator(1, ident, auth, a, secret)
    return _radius_pkt(1, ident, auth, a), auth


def radius_eap_reply(code: int, ident: int, req_auth: bytes, eap: bytes, state: bytes = b"", extra: bytes = b"",
                     secret: bytes = None) -> bytes:
    """Access-Challenge (11) / Access-Accept (2) / Access-Reject (3) carrying an EAP-Message, with a
    valid Message-Authenticator and Response Authenticator."""
    import hashlib
    secret = _radius_secret(secret)
    a = extra
    if state:
        a += radius_attr(24, state)
    a += eap_message_attrs(eap)
    a = _with_message_authenticator(code, ident, req_auth, a, secret)
    head = bytes([code & 0xFF, ident & 0xFF]) + (20 + len(a)).to_bytes(2, "big")
    return head + hashlib.md5(head + req_auth + a + secret).digest() + a


def ms_mppe_keys() -> bytes:
    """MS-MPPE-Send-Key / Recv-Key (Microsoft vendor 311, types 16 and 17) as two Vendor-Specific attributes."""
    out = b""
    for vtype in (16, 17):
        salt = (0x8000 | rng.getrandbits(15)).to_bytes(2, "big")
        val = salt + bytes(rng.getrandbits(8) for _ in range(48))
        vsa = (311).to_bytes(4, "big") + bytes([vtype, 2 + len(val)]) + val
        out += radius_attr(26, vsa)
    return out


# ============================================================ ONC RPC / NFSv3 (RFC 1813), TCP 2049
# Enough of RPC and NFSv3 to produce a believable, cleanly-dissected read session: NULL, FSINFO,
# GETATTR, LOOKUP, ACCESS, READ. post_op_attr is sent as "attributes_follow = FALSE" everywhere
# except GETATTR (which must carry an fattr3), which keeps every reply structurally valid without
# a full attribute cache. Over TCP each message carries the 4-byte record mark (last fragment).
def xdr_opaque(b: bytes) -> bytes:
    pad = (-len(b)) % 4
    return len(b).to_bytes(4, "big") + b + b"\x00" * pad


def xdr_str(s) -> bytes:
    return xdr_opaque(s.encode("latin-1", "replace") if isinstance(s, str) else s)


def _rpc_record(body: bytes) -> bytes:
    return (0x80000000 | len(body)).to_bytes(4, "big") + body      # last-fragment flag | length


def rpc_auth_unix(machine: str, uid: int = 0, gid: int = 0, gids=()) -> bytes:
    body = (rng.getrandbits(32).to_bytes(4, "big") + xdr_str(machine)
            + uid.to_bytes(4, "big") + gid.to_bytes(4, "big")
            + len(gids).to_bytes(4, "big") + b"".join(g.to_bytes(4, "big") for g in gids))
    return (1).to_bytes(4, "big") + xdr_opaque(body)               # flavor AUTH_UNIX = 1


_RPC_AUTH_NULL = (0).to_bytes(4, "big") + (0).to_bytes(4, "big")   # flavor 0, length 0


def rpc_call(xid: int, prog: int, vers: int, proc: int, cred: bytes = b"", args: bytes = b"") -> bytes:
    cred = cred or _RPC_AUTH_NULL
    body = (xid.to_bytes(4, "big") + (0).to_bytes(4, "big")        # msg_type CALL
            + (2).to_bytes(4, "big")                                # rpcvers 2
            + prog.to_bytes(4, "big") + vers.to_bytes(4, "big") + proc.to_bytes(4, "big")
            + cred + _RPC_AUTH_NULL + args)                         # cred, verf(AUTH_NULL), args
    return _rpc_record(body)


def rpc_reply(xid: int, results: bytes = b"") -> bytes:
    body = (xid.to_bytes(4, "big") + (1).to_bytes(4, "big")        # msg_type REPLY
            + (0).to_bytes(4, "big")                                # reply_stat MSG_ACCEPTED
            + _RPC_AUTH_NULL                                        # verf
            + (0).to_bytes(4, "big")                                # accept_stat SUCCESS
            + results)
    return _rpc_record(body)


def nfs3_fattr3(is_dir: bool = False, size: int = 4096, fileid: int = 0x1a2b3c, uid: int = 10000, gid: int = 10000) -> bytes:
    import struct as _s
    # type, mode, nlink, uid, gid, size(64), used(64), rdev(2x32), fsid(64), fileid(64),
    # atime(sec,nsec), mtime(sec,nsec), ctime(sec,nsec)
    return _s.pack(
        ">IIIII QQ II Q Q II II II",
        2 if is_dir else 1,                  # type: NF3DIR / NF3REG
        0o40755 if is_dir else 0o100644,     # mode
        2 if is_dir else 1,                  # nlink
        uid, gid,                            # uid, gid
        size, (size + 4095) // 4096 * 4096,  # size, used
        0, 0,                                # rdev specdata1/2
        0x0000000100000001,                  # fsid (64-bit)
        fileid,                              # fileid (64-bit)
        1700000000, 0,                       # atime
        1700000000, 0,                       # mtime
        1700000000, 0,                       # ctime
    )


def nfs3_fsinfo() -> bytes:
    import struct as _s
    # status OK, post_op_attr(follows=FALSE), then the FSINFO body
    return (b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00"
            + _s.pack(">IIIIIII", 65536, 65536, 4096, 65536, 65536, 4096, 65536)  # rt/wt/dtpref
            + (0x0000000800000000).to_bytes(8, "big")   # maxfilesize
            + _s.pack(">II", 1, 0)                        # time_delta
            + (0x0000001B).to_bytes(4, "big"))           # properties (LINK|SYMLINK|HOMOGENEOUS|CANSETTIME)


# ============================================================ IKEv2 / ESP-in-UDP (RFC 7296, RFC 3948)
# Remote-access IPsec (NAT-T): IKE_SA_INIT on udp/500, then IKE and ESP on udp/4500 (IKE behind a
# 4-byte zero non-ESP marker; ESP data is SPI + sequence + ciphertext; a NAT keepalive is one 0xFF
# byte). IKE_AUTH and INFORMATIONAL carry an Encrypted (SK) payload, opaque by design.
def _ike_payload(next_type: int, body: bytes) -> bytes:
    return bytes([next_type, 0]) + (4 + len(body)).to_bytes(2, "big") + body


def ike_message(ispi: bytes, rspi: bytes, exch: int, msgid: int, initiator: bool, payloads, first: int) -> bytes:
    """payloads: list of (type, body); `first` is the first payload type (the chain is built here)."""
    chain = b""
    for i, (_t, body) in enumerate(payloads):
        nxt = payloads[i + 1][0] if i + 1 < len(payloads) else 0
        chain += _ike_payload(nxt, body)
    flags = 0x08 if initiator else 0x20
    return (ispi + rspi + bytes([first, 0x20, exch, flags]) + msgid.to_bytes(4, "big")
            + (28 + len(chain)).to_bytes(4, "big") + chain)


def ike_sa_init(ispi: bytes, rspi: bytes, initiator: bool) -> bytes:
    def tr(more, ttype, tid, keylen=None):
        attr = (0x800E).to_bytes(2, "big") + keylen.to_bytes(2, "big") if keylen else b""
        return bytes([3 if more else 0, 0]) + (8 + len(attr)).to_bytes(2, "big") + bytes([ttype, 0]) + tid.to_bytes(2, "big") + attr
    trs = tr(1, 1, 12, 256) + tr(1, 2, 5) + tr(1, 3, 12) + tr(0, 4, 14)       # AES-CBC-256, PRF-HMAC-SHA2-256, SHA2-256-128, MODP-2048
    prop = bytes([0, 0]) + (8 + len(trs)).to_bytes(2, "big") + bytes([1, 1, 0, 4]) + trs
    ke = (14).to_bytes(2, "big") + b"\x00\x00" + _rand_bytes(256)
    nonce = _rand_bytes(32)
    nat = [(41, b"\x00\x00" + (16388).to_bytes(2, "big") + _rand_bytes(20)),
           (41, b"\x00\x00" + (16389).to_bytes(2, "big") + _rand_bytes(20))]
    return ike_message(ispi, rspi, 34, 0, initiator, [(33, prop), (34, ke), (40, nonce)] + nat, 33)


def ike_encrypted(ispi: bytes, rspi: bytes, exch: int, msgid: int, initiator: bool, inner_len: int, inner_first: int = 35) -> bytes:
    """IKE_AUTH / INFORMATIONAL: header + one SK payload (IV + ciphertext + 16-byte ICV; random bytes)."""
    body = _rand_bytes(16 + ((inner_len + 15) // 16) * 16 + 16)
    return _ike_sk(ispi, rspi, exch, msgid, initiator, body, inner_first)


def _ike_sk(ispi, rspi, exch, msgid, initiator, body, inner_first):
    sk = bytes([inner_first, 0]) + (4 + len(body)).to_bytes(2, "big") + body    # SK: next-payload = first inner payload
    flags = 0x08 if initiator else 0x20
    return (ispi + rspi + bytes([46, 0x20, exch, flags]) + msgid.to_bytes(4, "big")
            + (28 + len(sk)).to_bytes(4, "big") + sk)


def esp_in_udp(spi: bytes, seq: int, n: int) -> bytes:
    return spi + seq.to_bytes(4, "big") + _rand_bytes(n)


# ============================================================ OT process protocols (ported 2026-10)
# EtherNet/IP, S7comm, OPC UA, IEEE C37.118 synchrophasor and ICCP/TASE.2, ported from the
# OpenGenerator engine. Emitted only when selected through Day(ot_protocols=...) on the OT subnet,
# so a default build never calls anything below. Random payload bytes come from `rng` (not
# os.urandom) so the OT frames stay reproducible like the Modbus/DNP3/BACnet ones.
def _rand_bytes(n):
    # randrange(256) is getrandbits(9), drawn again while it is 256 or more; spelled out it makes the same draws in the same order
    # (the build stays reproducible) in under half the time, and this fills every ESP payload.
    gb, out = rng.getrandbits, bytearray(n)
    for i in range(n):
        r = gb(9)
        while r > 255:
            r = gb(9)
        out[i] = r
    return bytes(out)


# ------------------------------------------------------------ EtherNet/IP (CIP) — TCP 44818, UDP 2222
# The encapsulation header is little-endian; a sensor keys on TCP 44818 + the command code
# (RegisterSession 0x65, SendRRData 0x6F) and the CIP service inside the Common Packet Format.
ENIP_PORT = 44818
ENIP_IO_PORT = 2222


def _enip_encap(command, session, data, status=0, context=b"\x00" * 8, options=0):
    """ENIP encapsulation header (little-endian) + command-specific data."""
    return struct.pack("<HHII8sI", command, len(data), session, status, context, options) + data


def enip_register_session(session=0):
    return _enip_encap(0x0065, session, struct.pack("<HH", 1, 0))        # protocol version 1, options 0


def enip_register_session_rsp(session):
    return _enip_encap(0x0065, session, struct.pack("<HH", 1, 0))


def _cip_symbol_path(tag):
    """ANSI extended symbol segment (0x91) for a tag name, word-aligned."""
    tb = tag.encode()
    seg = b"\x91" + bytes([len(tb)]) + tb
    if len(seg) % 2:
        seg += b"\x00"
    return seg


def cip_read_tag(tag, elements=1):
    path = _cip_symbol_path(tag)
    return bytes([0x4C, len(path) // 2]) + path + struct.pack("<H", elements)   # service 0x4C Read Tag


def cip_read_tag_rsp(nbytes=4):
    data = struct.pack("<H", 0x00C4) + _rand_bytes(nbytes)                  # DINT type + value
    return bytes([0xCC, 0x00, 0x00, 0x00]) + data                           # reply service 0x4C|0x80, status OK


def _enip_cpf(cip):
    """Common Packet Format: null address item + unconnected data item carrying the CIP message."""
    return (struct.pack("<IH", 0, 0)                                        # interface handle, timeout
            + struct.pack("<H", 2)                                          # item count
            + struct.pack("<HH", 0x0000, 0)                                 # null address item
            + struct.pack("<HH", 0x00B2, len(cip)) + cip)                   # unconnected data item


def enip_send_rr_data(session, cip):
    return _enip_encap(0x006F, session, _enip_cpf(cip))


def enip_list_identity():
    return _enip_encap(0x0063, 0, b"")                                      # UDP 44818 discovery


def enip_io_data(seq, n=8):
    """CIP Class 1 implicit I/O (UDP 2222): 32-bit real-time header seq + opaque I/O data."""
    return struct.pack("<H", 2) + struct.pack("<H", seq & 0xFFFF) + _rand_bytes(n)


# ------------------------------------------------------------ Siemens S7comm — TCP 102 (TPKT/COTP/S7)
# S7comm rides ISO-TSAP (RFC 1006): TPKT -> COTP -> the S7 PDU (protocol id 0x32). TCP 102 also
# carries MMS (ICCP/TASE.2) — same transport, different upper layer, disambiguated by payload.
ISO_TSAP_PORT = 102


def _tpkt(payload):
    return struct.pack("!BBH", 3, 0, len(payload) + 4) + payload


def cotp_cr(dst_ref=0, src_ref=0x0001, src_tsap=0x0100, dst_tsap=0x0102):
    """COTP Connection Request (0xE0) with calling/called TSAPs and class 0."""
    params = (b"\xc1\x02" + struct.pack("!H", src_tsap)                     # calling TSAP
              + b"\xc2\x02" + struct.pack("!H", dst_tsap)                   # called TSAP
              + b"\xc0\x01\x0a")                                           # TPDU size 1024
    body = struct.pack("!BHHB", 0xE0, dst_ref, src_ref, 0x00) + params
    return _tpkt(bytes([len(body)]) + body)


def cotp_cc(dst_ref=0x0001, src_ref=0x0002, src_tsap=0x0102, dst_tsap=0x0100):
    params = (b"\xc1\x02" + struct.pack("!H", src_tsap) + b"\xc2\x02" + struct.pack("!H", dst_tsap)
              + b"\xc0\x01\x0a")
    body = struct.pack("!BHHB", 0xD0, dst_ref, src_ref, 0x00) + params
    return _tpkt(bytes([len(body)]) + body)


def _cotp_dt(payload):
    return _tpkt(b"\x02\xf0\x80" + payload)                                 # COTP DT, EOT


def _s7_hdr(rosctr, pdu_ref, param, data=b"", err=b""):
    hdr = struct.pack("!BBHHHH", 0x32, rosctr, 0, pdu_ref & 0xFFFF, len(param), len(data))
    return hdr + err + param + data


def s7_setup_comm(pdu_ref=1):
    param = b"\xf0\x00" + struct.pack("!HHH", 1, 1, 480)                    # func 0xF0 setup, max AmQ, PDU length
    return _cotp_dt(_s7_hdr(1, pdu_ref, param))                            # ROSCTR 1 = job


def s7_setup_comm_rsp(pdu_ref=1):
    param = b"\xf0\x00" + struct.pack("!HHH", 1, 1, 480)
    return _cotp_dt(_s7_hdr(3, pdu_ref, param, err=b"\x00\x00"))           # ROSCTR 3 = ack_data (+ 2-byte err)


def _s7_item(db, start, length, area=0x84):
    """S7ANY address item: read `length` bytes from DB `db` at byte offset `start`."""
    addr = ((start & 0x1FFFF) << 3)                                        # byte offset -> bit address
    return (b"\x12\x0a\x10\x02" + struct.pack("!H", length) + struct.pack("!H", db)
            + bytes([area]) + addr.to_bytes(3, "big"))


def s7_read_req(pdu_ref, db=1, start=0, length=16):
    param = b"\x04\x01" + _s7_item(db, start, length)                      # func 0x04 Read Var, 1 item
    return _cotp_dt(_s7_hdr(1, pdu_ref, param))


def s7_read_rsp(pdu_ref, length=16):
    param = b"\x04\x01"                                                     # func 0x04, item count 1
    data = b"\xff\x04" + struct.pack("!H", length * 8) + _rand_bytes(length)
    return _cotp_dt(_s7_hdr(3, pdu_ref, param, data=data, err=b"\x00\x00"))


def s7_write_req(pdu_ref, db=1, start=0, values=b"\x00\x01"):
    param = b"\x05\x01" + _s7_item(db, start, len(values))                 # func 0x05 Write Var
    data = b"\x00\x04" + struct.pack("!H", len(values) * 8) + values
    return _cotp_dt(_s7_hdr(1, pdu_ref, param, data=data))


def s7_write_rsp(pdu_ref):
    param = b"\x05\x01"
    return _cotp_dt(_s7_hdr(3, pdu_ref, param, data=b"\xff", err=b"\x00\x00"))   # per-item result 0xFF = OK


# ------------------------------------------------------------ OPC UA — TCP 4840 (opc.tcp binary)
# A sensor keys on TCP 4840 + the 3-byte message type (HEL/ACK/OPN/MSG/CLO) and little-endian
# size. HEL/ACK are byte-exact; OPN/MSG carry a secure-channel/sequence header and a service
# request encoded plausibly (full NodeId/service encoding is approximated).
OPCUA_PORT = 4840


def _opcua_str(s):
    b = s.encode()
    return struct.pack("<I", len(b)) + b


def _opcua_msg(mtype, chunk, body):
    return mtype + chunk + struct.pack("<I", 8 + len(body)) + body


def opcua_hello(url=None):
    url = url or "opc.tcp://%sotopc1:4840" % get_current().prefix.lower()
    body = (struct.pack("<IIIII", 0, 65536, 65536, 16777216, 5000) + _opcua_str(url))
    return _opcua_msg(b"HEL", b"F", body)                                  # version, bufs, maxmsg, maxchunk, url


def opcua_ack():
    return _opcua_msg(b"ACK", b"F", struct.pack("<IIIII", 0, 65536, 65536, 16777216, 5000))


def opcua_open_secure_channel():
    policy = _opcua_str("http://opcfoundation.org/UA/SecurityPolicy#None")
    body = struct.pack("<I", 1) + policy + struct.pack("<ii", -1, -1)      # channel id, policy, no certs
    return _opcua_msg(b"OPN", b"F", body + struct.pack("<II", 1, 1) + _rand_bytes(16))


def opcua_open_secure_channel_rsp():
    policy = _opcua_str("http://opcfoundation.org/UA/SecurityPolicy#None")
    body = struct.pack("<I", 1) + policy + struct.pack("<ii", -1, -1)
    return _opcua_msg(b"OPN", b"F", body + struct.pack("<II", 1, 1) + _rand_bytes(16))


# well-known service request NodeIds (numeric, ns=0)
OPCUA_SVC = {"CreateSession": 459, "ActivateSession": 467, "Browse": 527, "Read": 631,
             "CreateSubscription": 787, "Publish": 826}


def opcua_service(secure_channel, token, seq, req_id, svc_name, stub=24):
    """A MSG chunk: secure-channel id + token, sequence + request id, then a numeric NodeId
    (four-byte form, encoding 0x01) for the service + a plausible service-request stub."""
    node = struct.pack("<BH", 0x01, OPCUA_SVC.get(svc_name, 631))          # numeric NodeId (approximated)
    hdr = struct.pack("<IIII", secure_channel, token, seq, req_id)
    return _opcua_msg(b"MSG", b"F", hdr + node + _rand_bytes(stub))


# ------------------------------------------------------------ IEEE C37.118.2 — TCP 4712 / UDP 4713
# PMU -> PDC phasor streaming. Frame = SYNC(0xAA + type/version), FRAMESIZE, IDCODE, SOC,
# FRACSEC, body, CRC-CCITT. A sensor keys on the 0xAA sync, the frame type and the CRC.
C37118_CMD_PORT = 4712
C37118_DATA_PORT = 4713
_C37_DATA, _C37_HDR, _C37_CFG2, _C37_CMD = 0x01, 0x11, 0x31, 0x41          # SYNC byte2: type<<4 | version(1)


def _c37_crc(data):
    """CRC-CCITT (poly 0x1021, init 0xFFFF, no final xor) over the frame up to the CRC field."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return struct.pack("!H", crc)


def _c37_frame(sync2, idcode, soc, fracsec, body):
    frame = struct.pack("!BBHHII", 0xAA, sync2, 0, idcode, soc, fracsec) + body
    frame = frame[:2] + struct.pack("!H", len(frame) + 2) + frame[4:]      # FRAMESIZE includes the 2-byte CRC
    return frame + _c37_crc(frame)


def c37118_command(idcode, soc, cmd=2):
    """PDC->PMU command: 1=data off, 2=data on, 4=send CFG-2, 5=send header."""
    return _c37_frame(_C37_CMD, idcode, soc, 0, struct.pack("!H", cmd))


def c37118_config2(idcode, soc, station=None):
    station = station or get_current().prefix + "PMU01"
    """A minimal but valid CFG-2: 1 PMU, 1 phasor, 1 analog, 0 digital, 30 fps."""
    stn = station.encode("latin-1", "replace")[:16].ljust(16, b" ")
    pmu = (stn + struct.pack("!H", idcode)
           + struct.pack("!H", 0x0000)                                     # FORMAT: all integer
           + struct.pack("!HHH", 1, 1, 0)                                  # PHNMR, ANNMR, DGNMR
           + b"VA".ljust(16, b" ") + b"ANALOG1".ljust(16, b" ")            # channel names
           + struct.pack("!I", 0)                                          # phasor conv (volt, int)
           + struct.pack("!I", 0)                                          # analog conv
           + struct.pack("!H", 0x0000)                                     # FNOM: bit 0 clear = 60 Hz
           + struct.pack("!H", 1))                                         # CFGCNT
    body = (struct.pack("!I", 1000000)                                     # TIME_BASE
            + struct.pack("!H", 1)                                         # NUM_PMU
            + pmu + struct.pack("!H", 30))                                 # DATA_RATE 30 fps
    return _c37_frame(_C37_CFG2, idcode, soc, 0, body)


def c37118_data(idcode, soc, fracsec):
    """One data frame: STAT, one rectangular integer phasor, FREQ, DFREQ, one analog."""
    body = (struct.pack("!H", 0x0000)                                      # STAT: all good
            + struct.pack("!hh", rng.randint(-2000, 2000), rng.randint(-2000, 2000))  # phasor (real, imag)
            + struct.pack("!hh", rng.randint(-50, 50), 0)                  # FREQ dev (mHz), DFREQ
            + struct.pack("!h", rng.randint(0, 1000)))                     # analog
    return _c37_frame(_C37_DATA, idcode, soc, fracsec, body)


# ------------------------------------------------------------ ICCP / TASE.2 — MMS over TCP 102
# Inter-control-centre data exchange. MMS (ISO 9506) over RFC 1006: TPKT -> COTP -> ISO session
# -> ISO presentation -> MMS. The OSI session/presentation framing is a minimal, structurally
# valid wrapper (full ACSE/COPP negotiation is approximated); the MMS PDUs are correct BER.
def _osi_dt_userdata(mms):
    """Minimal ISO 8327 session (GIVE_TOKENS + DATA_TRANSFER) carrying an ISO 8823 presentation
    user-data wrapping the MMS PDU as presentation context 3 (MMS)."""
    pres = A.tlv(0x61, A.tlv(0x30, A.tlv(0xA0, A.tlv(0x02, bytes([3])) + mms)))   # CP-type user-data, PCI 3
    return b"\x01\x00\x01\x00" + pres                                      # SPDU GT(0x01) + DT(0x01) then PPDU


def _mms_invoke(invoke):
    return A.tlv(0x02, invoke.to_bytes(2, "big").lstrip(b"\x00") or b"\x00")


def mms_initiate_req():
    """MMS Initiate-RequestPDU (tag 0xA8): local detail, max outstanding, nesting level."""
    body = (A.tlv(0x80, (0x7FFF).to_bytes(2, "big"))                       # localDetailCalling
            + A.tlv(0x81, bytes([5])) + A.tlv(0x82, bytes([5]))            # proposedMaxServOutstanding calling/called
            + A.tlv(0x83, bytes([10])))                                    # proposedDataStructureNestingLevel
    return _cotp_dt(_osi_dt_userdata(A.tlv(0xA8, body)))


def mms_initiate_rsp():
    body = A.tlv(0x80, (0x7FFF).to_bytes(2, "big")) + A.tlv(0x81, bytes([5])) + A.tlv(0x82, bytes([5]))
    return _cotp_dt(_osi_dt_userdata(A.tlv(0xA9, body)))                   # Initiate-ResponsePDU


def mms_read_req(invoke, domain="ICC", var="MeasuredValueF_1"):
    """MMS confirmed-request Read (TASE.2 object): named variable in a domain."""
    name = A.tlv(0xA1, A.tlv(0x1A, domain.encode()) + A.tlv(0x1A, var.encode()))   # domain-specific objectName
    varspec = A.tlv(0xA1, A.tlv(0xA0, A.tlv(0x30, A.tlv(0xA0, name))))    # listOfVariable SEQUENCE OF
    read = A.tlv(0xA4, A.tlv(0x80, b"\x00") + varspec)                     # Read-Request, specWithResult=FALSE
    return _cotp_dt(_osi_dt_userdata(A.tlv(0xA0, _mms_invoke(invoke) + read)))   # confirmed-RequestPDU


def mms_read_rsp(invoke, value=12345):
    data = A.tlv(0xA1, A.tlv(0x85, value.to_bytes(4, "big")))             # listOfAccessResult: integer
    read = A.tlv(0xA4, data)
    return _cotp_dt(_osi_dt_userdata(A.tlv(0xA1, _mms_invoke(invoke) + read)))   # confirmed-ResponsePDU


def mms_information_report(domain="ICC", var="Transfer_Set_1", value=240):
    """Unconfirmed InformationReport — the heart of TASE.2 by-exception data transfer."""
    name = A.tlv(0xA1, A.tlv(0x1A, domain.encode()) + A.tlv(0x1A, var.encode()))
    varlist = A.tlv(0xA0, A.tlv(0x30, A.tlv(0xA0, name)))
    data = A.tlv(0xA0, A.tlv(0x85, value.to_bytes(4, "big")))
    report = A.tlv(0xA0, varlist + data)                                   # InformationReport
    return _cotp_dt(_osi_dt_userdata(A.tlv(0xA3, report)))                 # unconfirmed-PDU


# ---------------------------------------------------------------- encoder registry (v5b / 5c)
# Every public encoder defined in this module resolves through a swappable registry, so a
# capability module can OVERRIDE or ADD a protocol encoder at run time
# (register_encoder / reset_encoder) without any call site changing: the engine always calls
# `P.<name>(...)`, and each such name is rebound below to a dispatcher that looks the current
# implementation up in ENCODERS. By default every dispatcher calls the original built-in, so
# output is byte-for-byte unchanged and the no-module baseline still pins at 466,343.
import types as _types

_ENCODER_BUILTINS = {}          # name -> original built-in function (for reset)
ENCODERS = {}                   # name -> current implementation (built-in unless overridden)
_ENCODER_SKIP = {"register_encoder", "reset_encoder", "encoder_names", "apply_identity"}


def _encoder_dispatch(name):
    def _d(*a, **k):
        return ENCODERS[name](*a, **k)
    _d.__name__ = _d.__qualname__ = name
    _d._encoder = name
    return _d


def register_encoder(name, fn):
    """Override (or add) a protocol encoder at run time. Returns the previous implementation
    (or None). Picked up immediately by every `P.<name>(...)` call."""
    prev = ENCODERS.get(name)
    ENCODERS[name] = fn
    g = globals()
    if getattr(g.get(name), "_encoder", None) != name:
        g[name] = _encoder_dispatch(name)       # install a dispatcher for a newly-added encoder
    return prev


def reset_encoder(name):
    """Restore a built-in encoder, or remove a module-added one."""
    if name in _ENCODER_BUILTINS:
        ENCODERS[name] = _ENCODER_BUILTINS[name]
    else:
        ENCODERS.pop(name, None)
        g = globals()
        if getattr(g.get(name), "_encoder", None) == name:
            del g[name]


def encoder_names():
    """Sorted names of every registered encoder (built-in + module-added)."""
    return sorted(ENCODERS)


def _install_encoders():
    """Capture each public, module-level function as a built-in encoder and replace its module
    global with a dispatcher, so all P.<name>(...) calls route through ENCODERS."""
    g = globals()
    for _name, _obj in list(g.items()):
        if _name.startswith("_") or _name in _ENCODER_SKIP:
            continue
        if (isinstance(_obj, _types.FunctionType) and _obj.__module__ == __name__
                and getattr(_obj, "_encoder", None) is None):
            _ENCODER_BUILTINS[_name] = _obj
            ENCODERS[_name] = _obj
            g[_name] = _encoder_dispatch(_name)


_install_encoders()
