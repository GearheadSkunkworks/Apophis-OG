"""
Exemplar profiler for an imported pcap (Phase 1 of the custom-import feature).

Reads a standalone capture and characterises it at the HEADER level only: protocol and byte
mix, hosts and inferred roles, conversations, server ports, the timing envelope, layer-2 facts,
and a light TLS/DNS summary (SNI names, TLS versions, offered/negotiated key-exchange groups,
queried names). It never decrypts anything and never needs an external dissector: packets are
parsed with the standard library and named with the generator's own `netgen.core.classify`, the
same function the writer uses, so the profile cannot disagree with how the engine would label
the same frame.

This is deliberately read-only. It does not rewrite, merge, or synthesise anything; those are
later phases. Supported link types are Ethernet (the common case) and raw IPv4; anything else is
counted and flagged rather than mis-parsed.
"""
import os
import socket
import struct

from netgen.core import classify

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),      # LE, microsecond  (usec * 1000 = nsec)
    b"\xa1\xb2\xc3\xd4": (">", 1_000),      # BE, microsecond
    b"\x4d\x3c\xb2\xa1": ("<", 1),          # LE, nanosecond
    b"\xa1\xb2\x3c\x4d": (">", 1),          # BE, nanosecond
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101          # raw IP, no link layer
LINKTYPE_RAW_ALT = (12, 14)  # some writers use these for raw IP
LINKTYPE_NULL = 0            # BSD loopback: 4-byte address-family header, then IP
LINKTYPE_LOOP = 108          # OpenBSD loopback, same shape
MAX_CAPTURE_BYTES = 1 << 30  # 1 GiB: the largest capture the importer accepts
MAX_CONVOS = 200_000         # table caps: memory grows with flows, not bytes, so bound them and
MAX_HOSTS = 100_000          # count what was left out rather than run out of memory
MAX_PORTS = 50_000
MAX_NAMES = 5_000            # distinct SNI / DNS / file-name style strings kept
_LINK_NAMES = {0: "BSD loopback", 1: "Ethernet", 9: "PPP", 105: "802.11", 113: "Linux cooked (SLL)",
               127: "802.11 + radiotap", 143: "DOCSIS", 147: "user-defined", 228: "raw IPv4",
               229: "raw IPv6", 276: "Linux cooked v2 (SLL2)"}


def link_name(lt):
    return _LINK_NAMES.get(lt, "link type %d" % lt)


READ_TIMEOUT = 8.0


def probe_readable(path, timeout=None):
    """Open the file and read a byte on a helper thread. On macOS a folder such as Downloads can
    hold open() until a privacy prompt is answered; without this the request would hang for good
    and the page would sit on 'Generating…'. Raises ValueError with a fixable message."""
    import threading
    box = {}

    def _go():
        try:
            with open(path, "rb") as fh:
                fh.read(1)
            box["ok"] = True
        except OSError as e:
            box["err"] = e
    t = threading.Thread(target=_go, daemon=True)
    t.start()
    t.join(READ_TIMEOUT if timeout is None else timeout)
    if t.is_alive():
        raise ValueError("%s could not be opened: the operating system did not answer. On macOS this "
                         "usually means a folder-access permission prompt is waiting (for example "
                         "Downloads). Allow it, or copy the file into your output folder and use that "
                         "path." % os.path.basename(path))
    if "err" in box:
        raise ValueError("%s could not be read: %s" % (os.path.basename(path), box["err"].strerror or box["err"]))


def check_size(path):
    """Raise ValueError when the file is over the importer's size limit."""
    n = os.path.getsize(path)
    if n > MAX_CAPTURE_BYTES:
        raise ValueError("capture is %.2f GB; the importer accepts up to 1 GiB (%d bytes)"
                         % (n / 1e9, MAX_CAPTURE_BYTES))
    return n


class _CSet(set):
    """A set that stops growing at `cap` and counts what it refused, so a hostile or huge capture
    cannot make the profile's memory unbounded."""
    def __init__(self, cap=MAX_NAMES):
        super().__init__()
        self.cap, self.dropped = cap, 0

    def add(self, v):
        if v in self or len(self) < self.cap:
            set.add(self, v)
        else:
            self.dropped += 1

# PQC / hybrid key-exchange groups, so the profile can report post-quantum readiness the same
# way the npm-pqc-posture scenario and the platform do.
_PQC_GROUPS = {0x11ec: "X25519MLKEM768", 0x11eb: "SecP256r1MLKEM768", 0x6399: "X25519Kyber768Draft00",
               0x11ed: "SecP384r1MLKEM1024"}

# Protocols the engine can re-synthesise today (classify() names that have a builder). Anything
# observed outside this set is a parser/synthesis candidate, not something a scenario can yet
# reproduce faithfully.
ENGINE_SYNTH = {"HTTP", "HTTPS", "DNS", "mDNS", "LLMNR", "NBNS", "NBDS", "SMB2", "NetBIOS-SSN",
                "LDAP", "Kerberos", "TDS", "SNMP", "RTP", "RTCP", "NTP", "DHCP", "SIP", "DCE/RPC",
                "FTP", "FTP-DATA", "ICMP", "ARP", "Syslog", "SSDP", "CAPWAP", "Modbus", "BACnet",
                "DNP3", "RDP", "SSH", "MCP", "JetDirect", "IPP", "LPD", "SMTP", "NFS", "RADIUS"}

# Server ports the platform dissects that the engine renders only as TCP/UDP-other. Observing these in
# an exemplar names a concrete parser candidate. Taken from the connected sensor's record types
# and metric categories (a reference sensor).
PLATFORM_PORTS = {22: "SSH", 3389: "RDP", 25: "SMTP", 587: "SMTP", 465: "SMTP", 110: "POP3",
                 143: "IMAP", 2049: "NFS", 23: "Telnet", 69: "TFTP", 1080: "SOCKS", 6379: "Redis",
                 27017: "MongoDB", 11211: "Memcache", 104: "DICOM", 2575: "HL7", 5900: "RFB/VNC",
                 1812: "RADIUS", 1813: "RADIUS", 1494: "Citrix-ICA", 2598: "Citrix-ICA",
                 5985: "WSMAN", 5986: "WSMAN", 61616: "ActiveMQ", 1414: "IBM-MQ", 5672: "AMQP",
                 8009: "AJP"}


def kind(path):
    """'pcap', 'pcapng' or None from the magic number."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return None
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    return None


def _normalise(linktype, data):
    """Return an Ethernet II frame for `data`, or None to skip. VLAN tags are stripped and raw
    IP is wrapped in a dummy Ethernet header, so everything downstream uses one frame shape and
    `classify` works unchanged."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        for _ in range(2):                              # 802.1Q / 802.1ad (QinQ): drop up to two tags
            if data[12:14] in (b"\x81\x00", b"\x88\xa8", b"\x91\x00") and len(data) >= 18:
                data = data[:12] + data[16:]
            else:
                break
        return data
    if linktype == LINKTYPE_RAW or linktype in LINKTYPE_RAW_ALT:
        if not data:
            return None
        ver = data[0] >> 4
        et = b"\x08\x00" if ver == 4 else (b"\x86\xdd" if ver == 6 else b"\x00\x00")
        return b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + et + data
    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP) and len(data) > 4:   # BSD loopback (macOS lo0)
        body = data[4:]
        ver = body[0] >> 4
        if ver in (4, 6):
            return b"\x00" * 12 + (b"\x08\x00" if ver == 4 else b"\x86\xdd") + body
        return None
    if linktype == 113 and len(data) >= 16:            # Linux cooked capture (SLL)
        return b"\x00" * 12 + data[14:16] + data[16:]
    if linktype == 276 and len(data) >= 20:            # Linux cooked capture v2 (SLL2)
        return b"\x00" * 12 + data[0:2] + data[20:]
    return None                                        # unsupported link layer


def _iter_pcap(f):
    head = f.read(24)
    if len(head) < 24:
        return
    endian, ts_mult = PCAP_MAGICS[head[:4]]
    linktype = struct.unpack(endian + "I", head[20:24])[0]
    rec = struct.Struct(endian + "IIII")
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        ts_sec, ts_frac, incl, _orig = rec.unpack(h)
        data = f.read(incl)
        if len(data) < incl:
            return
        ts = ts_sec + (ts_frac * ts_mult) / 1e9
        yield ts, linktype, data


def _iter_pcapng(f):
    import mmap
    try:                                   # map the file: a 1 GB capture must not be read into RAM
        data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    except (ValueError, OSError):
        data = f.read()
    off, n = 0, len(data)
    endian = "<"
    tsresol = {}          # interface_id -> seconds per tick
    linktypes = {}        # interface_id -> linktype
    iface = 0
    while off + 8 <= n:
        # block_type(4), block_total_length(4) in the file's endianness
        if data[off:off + 4] == PCAPNG_MAGIC:          # Section Header: read byte-order magic
            bom = data[off + 8:off + 12]
            endian = "<" if bom == b"\x1a\x2b\x3c\x4d"[::-1] or bom == b"\x4d\x3c\x2b\x1a" else ">"
            # the standard BOM is 0x1A2B3C4D; detect endianness by matching it either way
            endian = "<" if struct.unpack("<I", bom)[0] == 0x1A2B3C4D else ">"
            tsresol.clear(); linktypes.clear(); iface = 0      # a new section renumbers its interfaces
        # block layout: type (4 bytes), total length (4 bytes), body, total length again
        btype = struct.unpack(endian + "I", data[off:off + 4])[0] if data[off:off + 4] != PCAPNG_MAGIC else 0x0A0D0D0A
        blen = struct.unpack(endian + "I", data[off + 4:off + 8])[0]
        if blen < 12 or off + blen > n:
            return
        body = data[off + 8:off + blen - 4]
        if btype == 0x00000001 and len(body) >= 8:     # Interface Description Block
            lt = struct.unpack(endian + "H", body[0:2])[0]
            linktypes[iface] = lt
            res = 6                                     # default 1e-6
            # options follow snaplen (body: linktype(2) reserved(2) snaplen(4) options...)
            opt = body[8:]
            p = 0
            while p + 4 <= len(opt):
                code, olen = struct.unpack(endian + "HH", opt[p:p + 4])
                val = opt[p + 4:p + 4 + olen]
                if code == 0:
                    break
                if code == 9 and val:                  # if_tsresol
                    b = val[0]
                    res = (b & 0x7F)
                    tsresol[iface] = (1.0 / (2 ** (b & 0x7F))) if (b & 0x80) else (10.0 ** -(b & 0x7F))
                p += 4 + olen + ((4 - olen % 4) % 4)
            tsresol.setdefault(iface, 1e-6)
            iface += 1
        elif btype == 0x00000006 and len(body) >= 20:  # Enhanced Packet Block
            ifid = struct.unpack(endian + "I", body[0:4])[0]
            tsh, tsl = struct.unpack(endian + "II", body[4:12])
            caplen = struct.unpack(endian + "I", body[12:16])[0]
            pkt = body[20:20 + caplen]       # ifid, ts_hi, ts_lo, caplen, origlen, then the data
            ticks = (tsh << 32) | tsl
            ts = ticks * tsresol.get(ifid, 1e-6)
            yield ts, linktypes.get(ifid, LINKTYPE_ETHERNET), pkt
        elif btype == 0x00000003 and len(body) >= 4:   # Simple Packet Block
            orig = struct.unpack(endian + "I", body[0:4])[0]
            pkt = body[4:4 + orig]
            yield 0.0, linktypes.get(0, LINKTYPE_ETHERNET), pkt
        off += blen


def iter_frames_lt(path, cap=None):
    """Yield (ts, link_type, ethernet_frame) per packet, the frame normalised to Ethernet II.
    Unsupported link layers yield a None frame so the caller can count them by link type."""
    k = kind(path)
    n = 0
    with open(path, "rb") as f:
        it = _iter_pcap(f) if k == "pcap" else (_iter_pcapng(f) if k == "pcapng" else iter(()))
        for ts, lt, data in it:
            yield ts, lt, _normalise(lt, data)
            n += 1
            if cap and n >= cap:
                return


def iter_frames(path, cap=None):
    """Yield (ts, ethernet_frame) for each packet (kept for callers that do not need the link type)."""
    for ts, _lt, eth in iter_frames_lt(path, cap):
        yield ts, eth


def _ip(b):
    return socket.inet_ntoa(b)


def _grease(v):
    return (v & 0x0F0F) == 0x0A0A


def _ja4(proto, ver, sni_present, ciphers, exts, sigalgs, alpn):
    """The JA4 TLS client fingerprint (FoxIO), which is what the platform keys on. Format
    ja4_a_ja4_b_ja4_c; GREASE values are dropped."""
    vmap = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10"}
    cph = [c for c in ciphers if not _grease(c)]
    ex = [e for e in exts if not _grease(e)]
    d = "d" if sni_present else "i"
    a2 = (alpn[0] + alpn[-1]) if alpn else "00"
    a = "%s%s%s%02d%02d%s" % (proto, vmap.get(ver, "00"), d, min(len(cph), 99), min(len(ex), 99), a2)
    cj = ",".join("%04x" % c for c in sorted(cph))
    b = _hashlib.sha256(cj.encode()).hexdigest()[:12] if cph else "000000000000"
    exc = sorted(e for e in ex if e not in (0x0000, 0x0010))      # JA4_c drops SNI and ALPN
    cstr = ",".join("%04x" % e for e in exc) + "_" + ",".join("%04x" % s for s in sigalgs)
    c = _hashlib.sha256(cstr.encode()).hexdigest()[:12] if (exc or sigalgs) else "000000000000"
    return "%s_%s_%s" % (a, b, c)


def _parse_tls_client_hello(payload, proto="t"):
    """Parse a TLS ClientHello. Returns a dict (sni, groups, version, ja4, nciphers) or None.
    Guarded: any irregularity returns None rather than raising."""
    try:
        if len(payload) < 6 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        legacy = struct.unpack("!H", payload[9:11])[0]
        p = 9 + 2 + 32                                       # rec(5)+hs(4): ver(2)+random(32)
        sidlen = payload[p]; p += 1 + sidlen
        cslen = struct.unpack("!H", payload[p:p + 2])[0]; p += 2
        ciphers = [struct.unpack("!H", payload[p + i:p + i + 2])[0] for i in range(0, cslen, 2)]
        p += cslen
        complen = payload[p]; p += 1 + complen
        extslen = struct.unpack("!H", payload[p:p + 2])[0]; p += 2
        end = p + extslen
        sni, groups, ver, exts, sigalgs, alpn, sni_present = None, [], legacy, [], [], None, False
        while p + 4 <= end:
            etype, elen = struct.unpack("!HH", payload[p:p + 4]); p += 4
            ev = payload[p:p + elen]; p += elen
            exts.append(etype)
            if etype == 0 and len(ev) >= 5:                  # server_name
                sni_present = True
                nlen = struct.unpack("!H", ev[3:5])[0]
                if nlen and len(ev) >= 5 + nlen:
                    sni = ev[5:5 + nlen].decode("utf-8", "replace")
            elif etype == 10 and len(ev) >= 2:               # supported_groups
                glen = struct.unpack("!H", ev[0:2])[0]
                for i in range(2, min(2 + glen, len(ev) - 1), 2):
                    groups.append(struct.unpack("!H", ev[i:i + 2])[0])
            elif etype == 13 and len(ev) >= 2:               # signature_algorithms
                slen = struct.unpack("!H", ev[0:2])[0]
                for i in range(2, min(2 + slen, len(ev) - 1), 2):
                    sigalgs.append(struct.unpack("!H", ev[i:i + 2])[0])
            elif etype == 43 and len(ev) >= 1:               # supported_versions
                vs = [struct.unpack("!H", ev[j:j + 2])[0] for j in range(1, min(1 + ev[0], len(ev) - 1), 2)]
                vs = [v for v in vs if not _grease(v)]
                if vs:
                    ver = max(vs)
            elif etype == 16 and len(ev) >= 3:               # ALPN: pick the first protocol
                first = ev[3:3 + ev[2]]
                if first:
                    alpn = first.decode("latin-1", "replace")
        version_str = {0x0304: "TLS 1.3", 0x0303: "TLS 1.2", 0x0302: "TLS 1.1",
                       0x0301: "TLS 1.0"}.get(ver, "TLS (other)")
        return {"sni": sni, "groups": groups, "version": version_str,
                "ja4": _ja4(proto, ver, sni_present, ciphers, exts, sigalgs, alpn)}
    except Exception:
        return None


def _dns_qname(payload):
    """The first queried name in a DNS message, or None."""
    try:
        if len(payload) < 13:
            return None
        qd = struct.unpack("!H", payload[4:6])[0]
        if qd < 1:
            return None
        p = 12
        labels = []
        while True:
            ln = payload[p]
            if ln == 0 or ln & 0xC0:                         # end or compression pointer
                break
            labels.append(payload[p + 1:p + 1 + ln].decode("ascii", "replace"))
            p += 1 + ln
            if len(labels) > 20:
                break
        return ".".join(labels) or None
    except Exception:
        return None


# ---- QUIC (RFC 9001 Initial decryption for the SNI) -----------------------------------------
import hmac as _hmac
import hashlib as _hashlib

QUIC_SALTS = {
    0x00000001: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),   # v1 (RFC 9001)
    0x6b3343cf: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),   # v2 (RFC 9369)
    0xff00001d: bytes.fromhex("afbfec289993d24c9e9786f19c6111e04390a899"),   # draft-29
}
QUIC_VERSION_NAMES = {0x00000001: "v1", 0x6b3343cf: "v2", 0xff00001d: "draft-29"}


def _hkdf_expand_label(secret, label, length):
    full = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = _hmac.new(secret, t + info + bytes([i]), _hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def _quic_varint(b, o):
    first = b[o]
    n = 1 << (first >> 6)
    v = first & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[o + k]
    return v, o + n


def quic_parse_initial(udp):
    """Return (version_name, sni_or_None) for a QUIC long-header Initial packet, else None.
    Decrypts the Initial per RFC 9001 using the published salts to read the ClientHello SNI;
    on any irregularity it degrades to (version_name, None) or None. Needs cryptography, which
    the app already bundles."""
    try:
        if not udp or not (udp[0] & 0x80):              # not a long header
            return None
        ver = struct.unpack("!I", udp[1:5])[0]
        # require a RECOGNISED QUIC version, or random UDP with the high bit set false-positives
        if ver not in QUIC_VERSION_NAMES:
            return None
        vname = QUIC_VERSION_NAMES[ver]
        if (udp[0] & 0x30) != 0x00:                     # long packet type must be Initial (00)
            return (vname, None)
        if ver not in QUIC_SALTS:
            return (vname, None)
        o = 5
        dcil = udp[o]; o += 1
        dcid = udp[o:o + dcil]; o += dcil
        scil = udp[o]; o += 1
        o += scil
        tl, o = _quic_varint(udp, o)
        o += tl
        plen, o = _quic_varint(udp, o)
        pn_off = o
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        init_secret = _hmac.new(QUIC_SALTS[ver], dcid, _hashlib.sha256).digest()
        cis = _hkdf_expand_label(init_secret, b"client in", 32)
        key = _hkdf_expand_label(cis, b"quic key", 16)
        iv = _hkdf_expand_label(cis, b"quic iv", 12)
        hp = _hkdf_expand_label(cis, b"quic hp", 16)
        sample = udp[pn_off + 4:pn_off + 4 + 16]
        enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
        mask = enc.update(sample) + enc.finalize()
        first = udp[0] ^ (mask[0] & 0x0F)
        pnlen = (first & 0x03) + 1
        pn_bytes = bytes(udp[pn_off + i] ^ mask[1 + i] for i in range(pnlen))
        pn = int.from_bytes(pn_bytes, "big")
        header = bytes([first]) + udp[1:pn_off] + pn_bytes
        payload = udp[pn_off + pnlen: pn_off + plen]     # ciphertext incl 16-byte tag
        nonce = bytes(iv[i] ^ (pn.to_bytes(12, "big")[i]) for i in range(12))
        pt = AESGCM(key).decrypt(nonce, payload, header)
        # walk frames for a CRYPTO frame (0x06) carrying the TLS ClientHello
        i = 0
        crypto = b""
        while i < len(pt):
            ft = pt[i]; i += 1
            if ft == 0x00:                               # PADDING
                continue
            if ft == 0x01:                               # PING
                continue
            if ft == 0x06:                               # CRYPTO
                _coff, i = _quic_varint(pt, i)
                clen, i = _quic_varint(pt, i)
                crypto += pt[i:i + clen]; i += clen
                continue
            break                                        # unknown frame: stop walking
        if crypto[:1] == b"\x01":                        # TLS handshake ClientHello
            rec = b"\x16\x03\x03" + struct.pack("!H", len(crypto)) + crypto
            ch = _parse_tls_client_hello(rec)
            return (vname, ch[0] if ch else None)
        return (vname, None)
    except Exception:
        return None


# ---- addresses embedded in payloads (for the Phase-2 re-address consistency problem) --------
import re as _re
_IPV4_RE = _re.compile(rb"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])")


def embedded_addrs(proto, payload):
    """Addresses and hostnames carried INSIDE a payload, which a header-only re-address would
    leave stale. Returns a set of (ip_or_name, where). Best-effort and cheap; only the protocols
    that commonly embed addresses are scanned."""
    found = set()
    try:
        if proto == "HTTP":
            for m in _re.finditer(rb"(?i)\r\n(host|location|referer|x-forwarded-for):[ ]*([^\r\n]+)", payload):
                found.add((m.group(2)[:120].decode("latin-1", "replace"), m.group(1).decode().lower()))
        elif proto == "FTP":
            for m in _re.finditer(rb"PORT (\d+,\d+,\d+,\d+),", payload):
                found.add((m.group(1).replace(b",", b".").decode(), "ftp-port"))
            for m in _re.finditer(rb"227 .*?(\d+,\d+,\d+,\d+)", payload):
                found.add((m.group(1).replace(b",", b".").decode(), "ftp-pasv"))
        elif proto in ("SMB2", "NetBIOS-SSN"):
            for m in _re.finditer(rb"\\\\([A-Za-z0-9_.-]{2,})\\", payload):
                found.add((m.group(1).decode("latin-1", "replace"), "smb-unc"))
        elif proto in ("DNS", "mDNS", "LLMNR"):
            for m in _IPV4_RE.finditer(payload):         # A-record answers (rough)
                found.add((m.group(1).decode(), "dns-answer"))
    except Exception:
        pass
    return found


def _http_facts(payload, http):
    """Tally HTTP request/response facts that drive the HTTP builders: methods, paths, hosts,
    user-agents, status codes, content types. Cleartext only."""
    try:
        le = payload.find(b"\r\n")
        if le < 0:
            return
        parts = payload[:le].decode("latin-1", "replace").split(" ")
        if parts and parts[0].startswith("HTTP/"):
            if len(parts) >= 2 and parts[1].isdigit():
                http["status"][parts[1]] = http["status"].get(parts[1], 0) + 1
        elif len(parts) >= 3 and parts[2].startswith("HTTP/"):
            http["methods"][parts[0]] = http["methods"].get(parts[0], 0) + 1
            path = parts[1].split("?")[0][:80]
            http["paths"][path] = http["paths"].get(path, 0) + 1
        for m in _re.finditer(rb"(?i)\r\n(host|user-agent|content-type):[ ]*([^\r\n]+)", payload):
            k = m.group(1).decode().lower()
            v = m.group(2).decode("latin-1", "replace")[:90]
            if k == "host":
                http["hosts"][v] = http["hosts"].get(v, 0) + 1
            elif k == "user-agent":
                http["uas"][v] = http["uas"].get(v, 0) + 1
            else:
                ct = v.split(";")[0]
                http["ctypes"][ct] = http["ctypes"].get(ct, 0) + 1
    except Exception:
        pass


SMB2_CMD = {0: "Negotiate", 1: "SessionSetup", 2: "Logoff", 3: "TreeConnect", 4: "TreeDisconnect",
            5: "Create", 6: "Close", 8: "Read", 9: "Write", 11: "IOCTL", 14: "QueryDirectory",
            16: "QueryInfo", 17: "SetInfo"}


def _smb2_facts(payload, smb):
    """Tally SMB2 commands, and best-effort tree (share) and file names from request structures."""
    try:
        i = payload.find(b"\xfeSMB")
        while i >= 0 and i + 64 <= len(payload):
            cmd = struct.unpack("<H", payload[i + 12:i + 14])[0]
            is_resp = struct.unpack("<I", payload[i + 16:i + 20])[0] & 0x1
            smb["cmds"][SMB2_CMD.get(cmd, "cmd%d" % cmd)] = smb["cmds"].get(SMB2_CMD.get(cmd, "cmd%d" % cmd), 0) + 1
            body = i + 64
            if cmd == 3 and not is_resp and body + 8 <= len(payload):       # TreeConnect request
                poff = struct.unpack("<H", payload[body + 4:body + 6])[0]
                plen = struct.unpack("<H", payload[body + 6:body + 8])[0]
                if plen and i + poff + plen <= len(payload):
                    t = payload[i + poff:i + poff + plen].decode("utf-16-le", "replace")
                    if t:
                        smb["trees"].add(t)
            elif cmd == 5 and not is_resp and body + 48 <= len(payload):     # Create request
                noff = struct.unpack("<H", payload[body + 44:body + 46])[0]
                nlen = struct.unpack("<H", payload[body + 46:body + 48])[0]
                if nlen and i + noff + nlen <= len(payload):
                    fn = payload[i + noff:i + noff + nlen].decode("utf-16-le", "replace")
                    if fn and len(smb["files"]) < 200:
                        smb["files"].add(fn)
            i = payload.find(b"\xfeSMB", i + 4)
    except Exception:
        pass


def _der_tlv(buf, o):
    """One DER TLV at offset o. Returns (tag, content_bytes, next_offset). Kerberos tags are all
    low-number (single-byte); long-form lengths are handled."""
    tag = buf[o]; o += 1
    ln = buf[o]; o += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[o:o + n], "big"); o += n
    return tag, buf[o:o + ln], o + ln


def _der_children(content):
    """Yield (tag, content) for each TLV inside a constructed value."""
    o = 0
    while o < len(content):
        t, c, o = _der_tlv(content, o)
        yield t, c


def _kerberos_principal(payload):
    """(realm, principal) from a Kerberos AS-REQ/TGS-REQ (KDC-REQ), else None. Walks the DER:
    [APPLICATION 10|12] -> SEQUENCE -> [4] req-body -> SEQUENCE -> [1] cname and [2] realm. A
    minimal decoder, since the bundled netgen.asn1 only encodes."""
    try:
        start = None
        for cand in (0, 4):                         # UDP starts at 0; TCP has a 4-byte length prefix
            if cand < len(payload) and payload[cand] in (0x6A, 0x6C):   # [APPLICATION 10]/[12]
                start = cand
                break
        if start is None:
            return None
        _t, app, _ = _der_tlv(payload, start)       # APPLICATION wraps the KDC-REQ SEQUENCE
        _t, kdcreq, _ = _der_tlv(app, 0)
        reqbody = None
        for t, c in _der_children(kdcreq):
            if t == 0xA4:                            # [4] req-body
                reqbody = c
        if reqbody is None:
            return None
        _t, body, _ = _der_tlv(reqbody, 0)           # [4] wraps a SEQUENCE
        realm = user = None
        for t, c in _der_children(body):
            if t == 0xA2:                            # [2] realm = GeneralString
                _rt, rc, _ = _der_tlv(c, 0)
                realm = rc.decode("latin-1", "replace")
            elif t == 0xA1:                          # [1] cname = PrincipalName
                _pt, princ, _ = _der_tlv(c, 0)       # [1] wraps a SEQUENCE
                for pt, pc in _der_children(princ):
                    if pt == 0xA1:                   # [1] name-string = SEQUENCE OF GeneralString
                        _st, names, _ = _der_tlv(pc, 0)
                        labels = [lc.decode("latin-1", "replace") for lt, lc in _der_children(names) if lt == 0x1B]
                        user = "/".join(labels)
        if user or realm:
            return realm, user
        return None
    except Exception:
        return None


def _ssh_facts(payload, ssh):
    """SSH identification banner and, from KEXINIT, the first KEX and cipher offered."""
    try:
        if payload[:4] == b"SSH-":
            line = payload.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
            ssh["versions"].add(line.decode("latin-1", "replace")[:60])
            return
        # KEXINIT is cleartext (msg code 20). An encrypted SSH packet can also have 20 at this
        # offset by chance, so only accept name-lists that are printable ASCII algorithm names.
        if len(payload) >= 6 and payload[5] == 20:
            p = 6 + 16                                   # packet_len(4)+pad_len(1)+code(1)+cookie(16)

            def nl(q):
                n = int.from_bytes(payload[q:q + 4], "big")
                if n > len(payload):
                    return "", q + 4
                return payload[q + 4:q + 4 + n].decode("latin-1", "replace"), q + 4 + n

            def _alg(s):
                return bool(s) and len(s) < 2000 and "-" in s and all(32 <= ord(c) < 127 for c in s)
            kex, p = nl(p)
            _shk, p = nl(p)
            enc, p = nl(p)
            if _alg(kex):
                ssh["kex"].add(kex.split(",")[0])
            if _alg(enc):
                ssh["cipher"].add(enc.split(",")[0])
    except Exception:
        pass


def _smtp_facts(payload, smtp):
    """SMTP commands, envelope addresses (MAIL FROM / RCPT TO) and response codes."""
    try:
        for raw in payload.split(b"\r\n"):
            if not raw:
                continue
            line = raw.decode("latin-1", "replace")
            up = line.upper()
            if up[:4] in ("EHLO", "HELO"):
                smtp["cmds"]["EHLO"] = smtp["cmds"].get("EHLO", 0) + 1
            elif up.startswith("MAIL FROM") or up.startswith("RCPT TO"):
                cmd = "MAIL" if up[0] == "M" else "RCPT"
                smtp["cmds"][cmd] = smtp["cmds"].get(cmd, 0) + 1
                m = _re.search(r"<([^>]+)>", line)
                if m and len(smtp["addrs"]) < 100:
                    smtp["addrs"].add(m.group(1))
            elif up.split(" ", 1)[0] in ("DATA", "QUIT", "AUTH", "STARTTLS", "NOOP", "RSET", "VRFY"):
                c = up.split(" ", 1)[0]
                smtp["cmds"][c] = smtp["cmds"].get(c, 0) + 1
            elif len(line) >= 3 and line[:3].isdigit():
                smtp["codes"][line[:3]] = smtp["codes"].get(line[:3], 0) + 1
    except Exception:
        pass


NFS3_PROC = {0: "NULL", 1: "GETATTR", 2: "SETATTR", 3: "LOOKUP", 4: "ACCESS", 5: "READLINK",
             6: "READ", 7: "WRITE", 8: "CREATE", 9: "MKDIR", 11: "REMOVE", 13: "RENAME",
             16: "READDIR", 17: "READDIRPLUS", 18: "FSSTAT", 21: "COMMIT"}


def _nfs_facts(payload, nfs, is_tcp):
    """Tally NFS (ONC RPC program 100003) procedures from RPC CALLs."""
    try:
        o = 4 if is_tcp else 0                           # TCP has a record-mark fragment header
        if len(payload) < o + 24:
            return
        mtype = int.from_bytes(payload[o + 4:o + 8], "big")
        rpcvers = int.from_bytes(payload[o + 8:o + 12], "big")
        prog = int.from_bytes(payload[o + 12:o + 16], "big")
        if mtype == 0 and rpcvers == 2 and prog == 100003:
            proc = int.from_bytes(payload[o + 20:o + 24], "big")
            nm = NFS3_PROC.get(proc, "proc%d" % proc)
            nfs["procs"][nm] = nfs["procs"].get(nm, 0) + 1
    except Exception:
        pass


RADIUS_CODE = {1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject", 4: "Accounting-Request",
               5: "Accounting-Response", 11: "Access-Challenge", 12: "Status-Server"}


def _radius_facts(payload, radius):
    """RADIUS message code tally; returns the User-Name attribute (an identity) if present."""
    try:
        if len(payload) < 20:
            return None
        code = payload[0]
        length = int.from_bytes(payload[2:4], "big")
        if code not in RADIUS_CODE or length < 20 or length > len(payload):
            return None
        radius["codes"][RADIUS_CODE[code]] = radius["codes"].get(RADIUS_CODE[code], 0) + 1
        p, user = 20, None
        while p + 2 <= length:
            t, l = payload[p], payload[p + 1]
            if l < 2:
                break
            if t == 1:                                   # User-Name
                user = payload[p + 2:p + l].decode("latin-1", "replace")
            p += l
        return user
    except Exception:
        return None


NTP_MODE = {0: "reserved", 1: "sym-active", 2: "sym-passive", 3: "client", 4: "server",
            5: "broadcast", 6: "control", 7: "private"}


def _ntp_facts(payload, ntp):
    """NTP version, mode and stratum. Modes 6 (control) and 7 (private/monlist) are the abuse and
    amplification vectors, so they are worth surfacing even though NTP is otherwise ordinary."""
    try:
        if not payload:
            return
        b0 = payload[0]
        ntp["versions"].add("v%d" % ((b0 >> 3) & 7))
        m = NTP_MODE.get(b0 & 7, str(b0 & 7))
        ntp["modes"][m] = ntp["modes"].get(m, 0) + 1
        if len(payload) >= 2:
            ntp["stratum"].add(payload[1])
    except Exception:
        pass


def _ntlm_type3(payload):
    """(domain, user, workstation) from an NTLMSSP AUTHENTICATE (type 3) blob, else None. The
    strings are UTF-16LE at offsets relative to the NTLMSSP signature. Guarded."""
    try:
        base = payload.index(b"NTLMSSP\x00")
        if struct.unpack("<I", payload[base + 8:base + 12])[0] != 3:
            return None

        def field(o):
            ln = struct.unpack("<H", payload[base + o:base + o + 2])[0]
            off = struct.unpack("<I", payload[base + o + 4:base + o + 8])[0]
            raw = payload[base + off:base + off + ln]
            return raw.decode("utf-16-le", "replace") if ln else ""
        dom = field(28)
        usr = field(36)
        wks = field(44)
        if not (usr or dom or wks):
            return None
        return dom, usr, wks
    except Exception:
        return None


def _dhcp_hostname(payload):
    """The hostname (DHCP option 12) a client reports, else None."""
    try:
        i = payload.find(b"\x63\x82\x53\x63")           # BOOTP magic cookie
        if i < 0:
            return None
        p = i + 4
        while p + 2 <= len(payload):
            code = payload[p]
            if code == 255:
                break
            if code == 0:
                p += 1
                continue
            ln = payload[p + 1]
            if code == 12:
                return payload[p + 2:p + 2 + ln].decode("ascii", "replace")
            p += 2 + ln
        return None
    except Exception:
        return None


def profile(path, cap=None):
    """Characterise the capture. Returns a dict of facts; raises on an unreadable file."""
    probe_readable(path)
    k = kind(path)
    if not k:
        raise RuntimeError("not a pcap or pcapng file (bad magic number)")
    check_size(path)
    skips = {}                     # reason -> frames left out of the profile (shown in the report)
    unsupported_links = {}          # link type -> frames, for captures the parser cannot read
    overflow = {"hosts": 0, "convos": 0, "ports": 0}   # items refused once a table hit its cap
    protos, bytes_by = {}, {}
    hosts = {}                      # ip -> [pkts, bytes]
    convos = {}                     # (a,b,dport,proto) -> [pkts, bytes]
    server_ports = {}               # (ip, port, l4) -> syn_count
    macs = set()
    vlans = set()
    snis, tls_versions, offered_groups, negotiated = _CSet(), {}, set(), {}
    dns_names = _CSet()
    quic, quic_snis = {}, set()     # version-name -> count
    embedded = set()                # (addr_or_name, where) carried inside payloads
    encap = {}                      # encapsulation seen: IPv6, etc.
    users, domains, host_names = set(), set(), set()
    host_id = {}                    # ip -> {"user","workstation","hostname"}
    minute_pkts = {}                # int(ts//60) -> packets, for the peak minute
    ja4s = {}                       # JA4 client fingerprint -> count
    http = {"methods": {}, "paths": {}, "hosts": {}, "uas": {}, "status": {}, "ctypes": {}}
    smb = {"cmds": {}, "trees": _CSet(), "files": _CSet()}
    ssh = {"versions": set(), "kex": set(), "cipher": set()}
    smtp = {"cmds": {}, "addrs": set(), "codes": {}}
    nfs = {"procs": {}}
    radius = {"codes": {}}
    ntp = {"modes": {}, "versions": set(), "stratum": set()}
    pending = {}                    # flow -> (needed_bytes, buffered) for a segmented ClientHello

    def _rec_ch(ch):                # record a parsed ClientHello; returns 1 if it parsed, else 0
        if not ch:
            return 0
        if ch["sni"]:
            snis.add(ch["sni"])
        tls_versions[ch["version"]] = tls_versions.get(ch["version"], 0) + 1
        ja4s[ch["ja4"]] = ja4s.get(ch["ja4"], 0) + 1
        for grp in ch["groups"]:
            if grp in _PQC_GROUPS:
                offered_groups.add(_PQC_GROUPS[grp])
        return 1
    first_ts = last_ts = None
    total_pkts = total_bytes = 0
    nonip = unsupported = 0
    tls_handshakes = 0

    for ts, _lt, eth in iter_frames_lt(path, cap=cap):
        total_pkts += 1
        if total_pkts % 200_000 == 0:               # keep the free-form text tallies bounded
            for _d in (http["paths"], http["uas"], http["hosts"], ja4s):
                if len(_d) > 4 * MAX_NAMES:
                    for _k, _ in sorted(_d.items(), key=lambda kv: kv[1])[:len(_d) - MAX_NAMES]:
                        del _d[_k]
        if eth is None:
            unsupported += 1
            unsupported_links[_lt] = unsupported_links.get(_lt, 0) + 1
            continue
        total_bytes += len(eth)
        if ts:
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = ts if last_ts is None else max(last_ts, ts)
            minute_pkts[int(ts // 60)] = minute_pkts.get(int(ts // 60), 0) + 1
        try:
            name = classify(eth)
        except (IndexError, struct.error):          # runt frame the classifier cannot read
            skips["truncated frame"] = skips.get("truncated frame", 0) + 1
            continue
        if len(eth) >= 14 and eth[0:6] != b"\x00\x00\x00\x00\x00\x00":
            macs.add(eth[6:12].hex())

        # ---- layer 3: IPv4 and IPv6 (no v6 extension headers), else count and skip ----
        et = eth[12:14]
        if et == b"\x08\x00":
            ihl = (eth[14] & 0x0F) * 4 if len(eth) > 14 else 0
            if len(eth) < 34 or ihl < 20 or len(eth) < 14 + ihl:   # runt or bad header length
                skips["truncated IPv4 header"] = skips.get("truncated IPv4 header", 0) + 1
                continue
            l4 = eth[23]
            src, dst = _ip(eth[26:30]), _ip(eth[30:34])
            off = 14 + ihl
            if ((eth[20] & 0x1F) << 8) | eth[21]:      # non-first fragment: no transport header here
                skips["IPv4 non-first fragment (counted, not parsed)"] = \
                    skips.get("IPv4 non-first fragment (counted, not parsed)", 0) + 1
                l4 = 0
        elif et == b"\x86\xdd" and len(eth) >= 54:
            encap["IPv6"] = encap.get("IPv6", 0) + 1
            l4 = eth[20]
            src = socket.inet_ntop(socket.AF_INET6, eth[22:38])
            dst = socket.inet_ntop(socket.AF_INET6, eth[38:54])
            off = 54
            for _ in range(8):                          # walk extension headers to the transport
                if l4 in (0, 43, 60) and len(eth) >= off + 8:
                    l4, off = eth[off], off + (eth[off + 1] + 1) * 8
                elif l4 == 44 and len(eth) >= off + 8:  # fragment header
                    l4 = eth[off] if (((eth[off + 2] << 8) | eth[off + 3]) >> 3) == 0 else 0
                    off += 8
                else:
                    break
        else:
            if et in (b"\x08\x00", b"\x86\xdd"):
                skips["truncated IPv6 header"] = skips.get("truncated IPv6 header", 0) + 1
                continue
            protos[name] = protos.get(name, 0) + 1
            bytes_by[name] = bytes_by.get(name, 0) + len(eth)
            nonip += 1
            continue

        # ---- QUIC overrides the port-based name before anything is counted ----
        if l4 == 17 and len(eth) >= off + 8:
            up = eth[off + 8:]
            if up[:1] and (up[0] & 0x80):
                qr = quic_parse_initial(up)
                if qr:
                    name = "QUIC"
                    quic[qr[0]] = quic.get(qr[0], 0) + 1
                    if qr[1]:
                        quic_snis.add(qr[1])

        protos[name] = protos.get(name, 0) + 1
        bytes_by[name] = bytes_by.get(name, 0) + len(eth)
        for h in (src, dst):
            r = hosts.get(h)
            if r is None:
                if len(hosts) >= MAX_HOSTS:
                    overflow["hosts"] += 1
                    continue
                r = hosts[h] = [0, 0]
            r[0] += 1; r[1] += len(eth)

        if l4 in (6, 17) and len(eth) >= off + 4:
            sp = (eth[off] << 8) | eth[off + 1]
            dp = (eth[off + 2] << 8) | eth[off + 3]
            se = f"{src}:{sp}"
            lo, hi = sorted((se, f"{dst}:{dp}"))
            ck = (lo, hi, l4)
            cc = convos.get(ck)
            if cc is None:
                if len(convos) >= MAX_CONVOS:
                    overflow["convos"] += 1
                    continue
                cc = convos[ck] = [0, 0, ts or 0, ts or 0, 0, 0]
            cc[0] += 1; cc[1] += len(eth)
            if ts:
                cc[3] = ts
            cc[4 if se == lo else 5] += len(eth)          # directional bytes
            if l4 == 6:
                flags = eth[off + 13] if len(eth) > off + 13 else 0
                if flags & 0x02 and not flags & 0x10:        # SYN without ACK: dst is the server
                    sk = (dst, dp, "tcp")
                    if sk in server_ports or len(server_ports) < MAX_PORTS:
                        server_ports[sk] = server_ports.get(sk, 0) + 1
                    else:
                        overflow["ports"] += 1
                payload = eth[off + ((eth[off + 12] >> 4) * 4):]
                fk = (src, sp, dst, dp)
                consumed_tls = False
                # TLS ClientHello, reassembling across TCP segments so a large (e.g. PQC) hello
                # split over two packets is still counted. Only ClientHellos are buffered.
                if fk in pending:
                    need, buf = pending.pop(fk)
                    buf += payload
                    if len(buf) >= need:
                        tls_handshakes += _rec_ch(_parse_tls_client_hello(buf))
                    elif len(buf) < 70000:
                        pending[fk] = (need, buf)
                    consumed_tls = True
                elif payload[:1] == b"\x16" and len(payload) >= 6 and payload[5:6] == b"\x01":
                    rec_len = int.from_bytes(payload[3:5], "big")
                    if len(payload) < 5 + rec_len and len(pending) < 256:
                        pending[fk] = (5 + rec_len, payload)   # incomplete: wait for the rest
                    else:
                        tls_handshakes += _rec_ch(_parse_tls_client_hello(payload))
                    consumed_tls = True
                if consumed_tls:
                    pass
                elif payload[:4] in (b"GET ", b"POST", b"HEAD", b"PUT ", b"HTTP") or payload[:7] in (b"OPTIONS", b"DELETE ", b"CONNECT"):
                    _http_facts(payload, http)
                if not consumed_tls and b"\xfeSMB" in payload:   # SMB2 commands, shares, filenames
                    _smb2_facts(payload, smb)
                if not consumed_tls and b"NTLMSSP\x00" in payload:  # NTLM auth from the client (src)
                    t3 = _ntlm_type3(payload)
                    if t3:
                        dom, usr, wks = t3
                        if usr:
                            users.add("%s\\%s" % (dom, usr) if dom else usr)
                            host_id.setdefault(src, {})["user"] = usr
                        if dom:
                            domains.add(dom)
                        if wks:
                            host_names.add(wks)
                            host_id.setdefault(src, {})["workstation"] = wks
                if not consumed_tls and (sp == 22 or dp == 22):   # SSH banner / KEXINIT
                    _ssh_facts(payload, ssh)
                if not consumed_tls and (sp in (25, 587, 465) or dp in (25, 587, 465)):
                    _smtp_facts(payload, smtp)
                if not consumed_tls and (sp == 2049 or dp == 2049):
                    _nfs_facts(payload, nfs, True)
                if not consumed_tls and (sp == 88 or dp == 88):   # Kerberos AS-REQ / TGS-REQ
                    kp = _kerberos_principal(payload)
                    if kp:
                        realm, usr = kp
                        if usr:
                            users.add("%s\\%s" % (realm.split(".")[0], usr) if realm else usr)
                            host_id.setdefault(src, {}).setdefault("user", usr)
                        if realm:
                            domains.add(realm)
                if not consumed_tls and len(embedded) < 400:
                    embedded |= embedded_addrs(name, payload)
            elif l4 == 17:
                if sp == 53 or dp == 53:
                    nm = _dns_qname(eth[off + 8:])
                    if nm:
                        dns_names.add(nm)
                if sp in (1812, 1813, 1645, 1646) or dp in (1812, 1813, 1645, 1646):   # RADIUS
                    ru = _radius_facts(eth[off + 8:], radius)
                    if ru:
                        users.add(ru)
                        if src != "0.0.0.0":
                            host_id.setdefault(src, {}).setdefault("user", ru)
                if sp == 2049 or dp == 2049:                 # NFS over UDP
                    _nfs_facts(eth[off + 8:], nfs, False)
                if sp == 123 or dp == 123:                   # NTP
                    _ntp_facts(eth[off + 8:], ntp)
                if sp == 88 or dp == 88:                     # Kerberos over UDP
                    kp = _kerberos_principal(eth[off + 8:])
                    if kp:
                        realm, usr = kp
                        if usr:
                            users.add("%s\\%s" % (realm.split(".")[0], usr) if realm else usr)
                            host_id.setdefault(src, {}).setdefault("user", usr)
                        if realm:
                            domains.add(realm)
                if sp in (67, 68) or dp in (67, 68):
                    hn = _dhcp_hostname(eth[off + 8:])
                    if hn:
                        host_names.add(hn)
                        if src != "0.0.0.0":
                            host_id.setdefault(src, {})["hostname"] = hn
                if len(embedded) < 400:
                    embedded |= embedded_addrs(name, eth[off + 8:])

    dur = (last_ts - first_ts) if (first_ts is not None and last_ts is not None) else 0.0
    return {
        "path": path, "format": k, "pkts": total_pkts, "bytes": total_bytes,
        "first_ts": first_ts, "last_ts": last_ts, "duration": dur,
        "nonip": nonip, "unsupported": unsupported,
        "skips": skips, "unsupported_links": unsupported_links, "overflow": overflow,
        "name_overflow": snis.dropped + dns_names.dropped + smb["trees"].dropped + smb["files"].dropped,
        "protocols": protos, "bytes_by": bytes_by,
        "hosts": hosts, "convos": convos, "server_ports": server_ports,
        "macs": macs, "vlans": vlans,
        "tls_handshakes": tls_handshakes, "snis": snis, "tls_versions": tls_versions,
        "pqc_offered": offered_groups, "dns_names": dns_names,
        "quic": quic, "quic_snis": quic_snis, "embedded": embedded, "encap": encap,
        "users": users, "domains": domains, "host_names": host_names, "host_id": host_id,
        "minute_pkts": minute_pkts, "ja4s": ja4s, "http": http, "smb": smb,
        "ssh": ssh, "smtp": smtp, "nfs": nfs, "radius": radius, "ntp": ntp,
    }


# -------------------------------------------------------------------- rendering
def _fmt_bytes(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return "%.0f %s" % (n, u) if u == "B" else "%.1f %s" % (n, u)
        n /= 1024.0


def _fmt_dur(s):
    s = int(s)
    if s < 60:
        return "%ds" % s
    if s < 3600:
        return "%dm %ds" % (s // 60, s % 60)
    return "%dh %dm" % (s // 3600, (s % 3600) // 60)


def _esc(x):
    import html
    return html.escape(str(x))


TABLES = ("protocols", "hosts", "conversations", "ports", "names")
FULL_ROWS_IN_PAGE = 2000        # the page shows this many rows per full table; downloads have them all


def tables(prof):
    """Every table of the profile as (columns, rows): the full data behind the report, used by the
    page's 'show all' lists and by the JSON/CSV export. Rows are plain values, nothing is truncated."""
    p = prof
    total = max(1, p["pkts"] - p["unsupported"])
    serving = {}
    for (ip, port, _l4), cnt in p["server_ports"].items():
        serving.setdefault(ip, []).append((port, cnt))
    out = {}
    out["protocols"] = (["protocol", "packets", "share_pct", "bytes"],
                        [[n, c, round(100.0 * c / total, 2), p["bytes_by"].get(n, 0)]
                         for n, c in sorted(p["protocols"].items(), key=lambda kv: -kv[1])])
    out["hosts"] = (["host", "role", "serves_ports", "packets", "bytes"],
                    [[ip, "server" if ip in serving else "client/peer",
                      " ".join(str(pt) for pt, _ in sorted(serving.get(ip, []), key=lambda x: -x[1])),
                      pk, by] for ip, (pk, by) in sorted(p["hosts"].items(), key=lambda kv: -kv[1][1])])
    out["conversations"] = (["endpoint_a", "endpoint_b", "l4", "packets", "bytes", "duration_s",
                             "bytes_a_to_b", "bytes_b_to_a"],
                            [[a, b, "TCP" if l4 == 6 else "UDP", v[0], v[1], round(max(0.0, v[3] - v[2]), 3), v[4], v[5]]
                             for (a, b, l4), v in sorted(p["convos"].items(), key=lambda kv: -kv[1][1])])
    tally = {}
    for (ip, port, l4), cnt in p["server_ports"].items():
        r = tally.setdefault((port, l4), [0, 0]); r[0] += cnt; r[1] += 1
    out["ports"] = (["port", "l4", "syns", "server_hosts"],
                    [[pt, l4, r[0], r[1]] for (pt, l4), r in sorted(tally.items(), key=lambda kv: -kv[1][0])])
    names = [["tls_sni", v] for v in sorted(p["snis"])] + [["dns_query", v] for v in sorted(p["dns_names"])] \
        + [["quic_sni", v] for v in sorted(p["quic_snis"])]
    out["names"] = (["kind", "value"], names)
    return out


def tables_json(prof):
    """The whole profile as one JSON-able dict: summary, coverage and every full table."""
    t = tables(prof)
    return {"summary": profile_summary(prof), "duration_s": round(prof["duration"], 3),
            "tables": {k: {"columns": c, "rows": r} for k, (c, r) in t.items()}}


def table_csv(prof, name):
    """One table as CSV text. Cells that start with = + - @ are prefixed so a spreadsheet opened on
    an export cannot be made to run a formula by a hostile capture (SNI / DNS / host strings)."""
    import csv
    import io
    if name not in TABLES:
        raise ValueError("unknown table %r (choose from %s)" % (name, ", ".join(TABLES)))
    cols, rows = tables(prof)[name]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([("'" + c) if isinstance(c, str) and c[:1] in ("=", "+", "-", "@", "\t", "\r") else c for c in r])
    return buf.getvalue()


def _full_table(prof, name, label):
    """A collapsed 'show all' list for one table, plus its download links."""
    from urllib.parse import quote
    cols, rows = tables(prof)[name]
    shown = rows[:FULL_ROWS_IN_PAGE]
    head = "".join("<th>%s</th>" % _esc(c) for c in cols)
    body = "".join("<tr>%s</tr>" % "".join("<td class='m'>%s</td>" % _esc(c) for c in r) for r in shown)
    more = ("<p>Showing the first %d of %d rows; the download has all of them.</p>" % (len(shown), len(rows))
            if len(rows) > len(shown) else "")
    q = quote(prof["path"], safe="")
    dl = ("<p><a href='/profile/export?path=%s&amp;table=%s&amp;format=csv'>Download CSV</a> &middot; "
          "<a href='/profile/export?path=%s&amp;format=json'>Download full profile JSON</a></p>" % (q, name, q))
    return ("<details><summary>All %d %s</summary>%s<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>%s</details>"
            % (len(rows), label, dl, head, body, more))


def coverage_html(prof):
    """What the profiler could and could not read: the honest accounting that makes an empty or
    partial profile explainable."""
    p = prof
    usable = p["pkts"] - p["unsupported"] - sum(p["skips"].values())
    rows = [("Packets in the file", p["pkts"]), ("Profiled as IP traffic or named non-IP", max(0, usable))]
    for k, v in sorted(p["unsupported_links"].items(), key=lambda kv: -kv[1]):
        rows.append(("Unreadable link type: %s" % link_name(k), v))
    for k, v in sorted(p["skips"].items(), key=lambda kv: -kv[1]):
        rows.append((k, v))
    notes = []
    ov = p["overflow"]
    if ov["hosts"] or ov["convos"] or ov["ports"]:
        notes.append("Table limits were reached (%d hosts, %d conversations, %d server-port entries left out of the "
                     "tables). Totals and protocol counts are still complete." % (ov["hosts"], ov["convos"], ov["ports"]))
    if p.get("name_overflow"):
        notes.append("%d distinct names (SNI, DNS, SMB) were not kept after the per-list limit of %d."
                     % (p["name_overflow"], MAX_NAMES))
    if p["encap"].get("IPv6"):
        notes.append("%d IPv6 packets were profiled; the engine builds IPv4 scenarios only." % p["encap"]["IPv6"])
    body = "".join("<tr><td>%s</td><td class='m'>%d</td></tr>" % (_esc(a), b) for a, b in rows)
    return ("<table><thead><tr><th>What</th><th>Frames</th></tr></thead><tbody>%s</tbody></table>%s"
            % (body, "".join("<p>%s</p>" % _esc(n) for n in notes)))


def content(prof):
    """A render_page content dict (kpis / sections / notes), wrapped by the server or CLI with
    the same chrome as the About page and the diagrams."""
    p = prof
    total = max(1, p["pkts"] - p["unsupported"])
    # protocol mix table, by packets, with byte share
    rows = sorted(p["protocols"].items(), key=lambda kv: -kv[1])
    tb = p["bytes"] or 1
    proto_rows = "".join(
        "<tr><td>%s</td><td class='m'>%d</td><td class='m'>%.1f%%</td><td class='m'>%s</td></tr>"
        % (_esc(n), c, 100.0 * c / total, _fmt_bytes(p["bytes_by"].get(n, 0)))
        for n, c in rows[:20])

    # top hosts by bytes, with an inferred role
    serving = {}
    for (ip, port, _l4), cnt in p["server_ports"].items():
        serving.setdefault(ip, []).append((port, cnt))
    host_rows = ""
    for ip, (pk, by) in sorted(p["hosts"].items(), key=lambda kv: -kv[1][1])[:15]:
        role = "server" if ip in serving else "client / peer"
        ports = ", ".join(str(pt) for pt, _ in sorted(serving.get(ip, []), key=lambda x: -x[1])[:5])
        host_rows += ("<tr><td class='m'>%s</td><td>%s</td><td class='m'>%s</td><td class='m'>%d</td>"
                      "<td class='m'>%s</td></tr>" % (_esc(ip), role, _esc(ports) or "&mdash;", pk, _fmt_bytes(by)))

    # top conversations by bytes, with duration and direction (client-heavy vs server-heavy)
    conv_rows = ""
    durs = []
    for (a, b, l4), v in sorted(p["convos"].items(), key=lambda kv: -kv[1][1])[:15]:
        pk, by, f0, f1, a2b, b2a = v
        d = max(0.0, f1 - f0)
        dirn = "&harr;" if not (a2b or b2a) else ("%d%% &rarr;" % round(100.0 * a2b / (a2b + b2a)))
        conv_rows += ("<tr><td class='m'>%s</td><td class='m'>%s</td><td class='m'>%s</td>"
                      "<td class='m'>%d</td><td class='m'>%s</td><td class='m'>%s</td><td class='m'>%s</td></tr>"
                      % (_esc(a), _esc(b), "TCP" if l4 == 6 else "UDP", pk, _fmt_bytes(by),
                         _fmt_dur(d) if d >= 1 else "<1s", dirn))
    for v in p["convos"].values():
        durs.append(max(0.0, v[3] - v[2]))
    durs.sort()
    median_dur = durs[len(durs) // 2] if durs else 0.0
    peak = max(p["minute_pkts"].values()) if p["minute_pkts"] else 0

    # top server ports
    port_tally = {}
    for (_ip, port, l4), cnt in p["server_ports"].items():
        port_tally[(port, l4)] = port_tally.get((port, l4), 0) + cnt
    port_rows = "".join(
        "<tr><td class='m'>%d/%s</td><td class='m'>%d</td></tr>" % (port, l4, cnt)
        for (port, l4), cnt in sorted(port_tally.items(), key=lambda kv: -kv[1])[:12])

    snis = ", ".join(sorted(p["snis"])[:30]) or "&mdash;"
    dns = ", ".join(sorted(p["dns_names"])[:40]) or "&mdash;"
    tlsv = ", ".join("%s (%d)" % (k, v) for k, v in sorted(p["tls_versions"].items())) or "&mdash;"
    pqc = ", ".join(sorted(p["pqc_offered"])) or "none offered"
    quicv = ", ".join("%s (%d)" % (k, v) for k, v in sorted(p["quic"].items())) or "&mdash;"
    quicsni = ", ".join(sorted(p["quic_snis"])[:30]) or "&mdash;"
    ja4top = ", ".join("%s (%d)" % (k, v) for k, v in sorted(p["ja4s"].items(), key=lambda kv: -kv[1])[:8]) or "&mdash;"

    # HTTP detail
    def _tl(d, n=8):
        return ", ".join("%s (%d)" % (k, v) for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:n]) or "&mdash;"
    h = p["http"]
    http_html = ("<table><tbody>"
                 "<tr><td><b>Methods</b></td><td class='m'>%s</td></tr>"
                 "<tr><td><b>Status codes</b></td><td class='m'>%s</td></tr>"
                 "<tr><td><b>User agents</b></td><td>%s</td></tr>"
                 "<tr><td><b>Content types</b></td><td class='m'>%s</td></tr>"
                 "<tr><td><b>Top paths</b></td><td class='m'>%s</td></tr>"
                 "<tr><td><b>Top hosts</b></td><td>%s</td></tr>"
                 "</tbody></table>"
                 % (_esc(_tl(h["methods"])), _esc(_tl(h["status"])), _esc(_tl(h["uas"], 6)),
                    _esc(_tl(h["ctypes"])), _esc(_tl(h["paths"], 10)), _esc(_tl(h["hosts"], 8))))

    # SMB detail
    sm = p["smb"]
    smb_html = ("<table><tbody>"
                "<tr><td><b>Commands</b></td><td class='m'>%s</td></tr>"
                "<tr><td><b>Shares (tree connects)</b></td><td class='m'>%s</td></tr>"
                "<tr><td><b>Files created</b></td><td class='m'>%s</td></tr>"
                "</tbody></table>"
                % (_esc(_tl(sm["cmds"], 12)),
                   _esc(", ".join(sorted(sm["trees"])[:20]) or "&mdash;"),
                   _esc(", ".join(sorted(sm["files"])[:20]) or "&mdash;")))

    # candidate-protocol detail (platform-visible, not engine-synthesised): SSH, SMTP, NFS, RADIUS
    sh, mt, nf, ra = p["ssh"], p["smtp"], p["nfs"], p["radius"]
    cd_rows = ""
    if sh["versions"] or sh["kex"] or sh["cipher"]:
        cd_rows += ("<tr><td><b>SSH</b></td><td>versions: %s<br>kex: %s &middot; cipher: %s</td></tr>"
                    % (_esc(", ".join(sorted(sh["versions"])[:8]) or "&mdash;"),
                       _esc(", ".join(sorted(sh["kex"])) or "&mdash;"),
                       _esc(", ".join(sorted(sh["cipher"])) or "&mdash;")))
    if mt["cmds"] or mt["addrs"] or mt["codes"]:
        cd_rows += ("<tr><td><b>SMTP</b></td><td>commands: %s &middot; codes: %s<br>addresses: %s</td></tr>"
                    % (_esc(_tl(mt["cmds"])), _esc(_tl(mt["codes"])),
                       _esc(", ".join(sorted(mt["addrs"])[:15]) or "&mdash;")))
    if nf["procs"]:
        cd_rows += "<tr><td><b>NFS</b></td><td>procedures: %s</td></tr>" % _esc(_tl(nf["procs"], 12))
    if ra["codes"]:
        cd_rows += "<tr><td><b>RADIUS</b></td><td>messages: %s</td></tr>" % _esc(_tl(ra["codes"]))
    cand_detail_html = ("<p>Detail for protocols the platform dissects but the engine does not yet "
                        "synthesise. Parsed read-only, to characterise what a scenario would need "
                        "and to feed identities (RADIUS user names, SMTP envelope addresses).</p>"
                        "<table><tbody>%s</tbody></table>"
                        % (cd_rows or "<tr><td colspan='2'>none of SSH / SMTP / NFS / RADIUS seen</td></tr>"))

    # NTP detail (the engine already synthesises NTP; this characterises it, and flags abuse modes)
    nt = p["ntp"]
    abuse = [m for m in ("control", "private") if m in nt["modes"]]
    strat = sorted(nt["stratum"])
    ntp_html = ("<table><tbody>"
                "<tr><td><b>Modes</b></td><td class='m'>%s</td></tr>"
                "<tr><td><b>Versions</b></td><td class='m'>%s</td></tr>"
                "<tr><td><b>Stratum values</b></td><td class='m'>%s</td></tr>"
                "<tr><td><b>Abuse modes present</b></td><td class='m'>%s</td></tr>"
                "</tbody></table>"
                % (_esc(_tl(nt["modes"])), _esc(", ".join(sorted(nt["versions"])) or "&mdash;"),
                   _esc(", ".join(str(s) for s in strat[:16]) or "&mdash;"),
                   _esc(", ".join(abuse) + " (control/monlist amplification)" if abuse else "none")))

    # embedded addresses, the Phase-2 re-address consistency finding
    emb_rows = "".join("<tr><td class='m'>%s</td><td>%s</td></tr>" % (_esc(a), _esc(w))
                       for a, w in sorted(p["embedded"])[:40])
    emb_html = ("<p>Addresses and names found INSIDE payloads. A header-level re-address leaves "
                "these stale, so they are what a transform step has to rewrite or flag.</p>"
                "<table><thead><tr><th>Value</th><th>Where</th></tr></thead><tbody>%s</tbody></table>"
                % (emb_rows or "<tr><td colspan='2'>none found in the parsed protocols</td></tr>"))

    # reproducibility coverage, against the engine's builders and the platform's dissectors
    synth = {n: c for n, c in p["protocols"].items() if n in ENGINE_SYNTH}
    cand = {n: c for n, c in p["protocols"].items()
            if n not in ENGINE_SYNTH and n not in ("Ethernet-other", "TCP-other", "UDP-other")
            and not n.startswith("IP-proto-")}
    rx_named = {}
    for (ip, port, _l4), cnt in p["server_ports"].items():
        nm = PLATFORM_PORTS.get(port)
        if nm and nm not in ENGINE_SYNTH:              # only the platform protocols the engine lacks
            rx_named[nm] = rx_named.get(nm, 0) + cnt
    synth_pkts = sum(synth.values())
    cls_total = max(1, sum(p["protocols"].values()) - p["protocols"].get("Ethernet-other", 0))
    cand_list = ", ".join("%s (%d)" % (n, c) for n, c in sorted(cand.items(), key=lambda kv: -kv[1])) or "none"
    rx_list = ", ".join("%s (%d SYNs)" % (n, c) for n, c in sorted(rx_named.items(), key=lambda kv: -kv[1])) or "none observed"
    cov_html = ("<p>How much of this capture a scenario could reproduce today. The engine can "
                "synthesise the protocols it already builds; everything else is a parser/synthesis "
                "candidate, named where the platform would dissect it.</p>"
                "<table><tbody>"
                "<tr><td><b>Synthesisable now</b></td><td class='m'>%.1f%% of classified packets</td></tr>"
                "<tr><td><b>Candidate protocols</b></td><td>%s</td></tr>"
                "<tr><td><b>platform-visible on server ports</b></td><td class='m'>%s</td></tr>"
                "</tbody></table>" % (100.0 * synth_pkts / cls_total, _esc(cand_list), _esc(rx_list)))

    # identities: users / domains / hostnames, and which host presented which
    id_rows = ""
    for ip, d in sorted(p["host_id"].items()):
        id_rows += ("<tr><td class='m'>%s</td><td class='m'>%s</td><td class='m'>%s</td>"
                    "<td class='m'>%s</td></tr>"
                    % (_esc(ip), _esc(d.get("user", "&mdash;")), _esc(d.get("workstation", "&mdash;")),
                       _esc(d.get("hostname", "&mdash;"))))
    id_html = ("<p>Identities seen in the clear: NTLM authentication (user, domain, workstation) and "
               "the hostname DHCP clients report. These are what map an exemplar host onto a specific "
               "Example host and account.</p>"
               "<table><tbody>"
               "<tr><td><b>Users</b></td><td>%s</td></tr>"
               "<tr><td><b>Domains</b></td><td class='m'>%s</td></tr>"
               "<tr><td><b>Hostnames</b></td><td>%s</td></tr></tbody></table>"
               % (_esc(", ".join(sorted(p["users"])[:40]) or "&mdash;"),
                  _esc(", ".join(sorted(p["domains"])) or "&mdash;"),
                  _esc(", ".join(sorted(p["host_names"])[:40]) or "&mdash;")))
    if id_rows:
        id_html += ("<table><thead><tr><th>Host</th><th>User</th><th>Workstation</th><th>DHCP name</th>"
                    "</tr></thead><tbody>%s</tbody></table>" % id_rows)

    # topology: group IPv4 hosts by /24, internal vs external, and a suggested Example mapping
    def _is_priv(ip):
        return ip.startswith(("10.", "192.168.")) or any(ip.startswith("172.%d." % n) for n in range(16, 32))
    subnets = {}
    for ip in p["hosts"]:
        if ":" in ip:                                  # IPv6, grouped separately
            subnets.setdefault("IPv6", [0])[0] += 1
            continue
        pref = ip.rsplit(".", 1)[0] + ".0/24"
        s = subnets.setdefault(pref, [0, _is_priv(ip)])
        s[0] += 1
    internal = sorted(((k, v) for k, v in subnets.items() if k != "IPv6" and v[1]), key=lambda kv: -kv[1][0])
    external = sorted(((k, v) for k, v in subnets.items() if k != "IPv6" and not v[1]), key=lambda kv: -kv[1][0])
    sub_rows = "".join("<tr><td class='m'>%s</td><td>%s</td><td class='m'>%d</td></tr>"
                       % (k, "internal" if v[1] else "external", v[0])
                       for k, v in sorted(((k, v) for k, v in subnets.items() if k != "IPv6"),
                                          key=lambda kv: (-kv[1][0]))[:12])
    sugg = ""
    if internal:
        sugg += "<li>%s &rarr; <b>user</b> network (10.10.10.0/24), %d hosts</li>" % (internal[0][0], internal[0][1][0])
    if len(internal) > 1:
        sugg += "<li>%s &rarr; <b>server</b> network (10.10.20.0/24), %d hosts</li>" % (internal[1][0], internal[1][1][0])
    if external:
        sugg += "<li>%d external subnet(s) &rarr; the simulated internet side, kept out of the re-address</li>" % len(external)
    topo_html = ("<p>Hosts grouped by /24, internal versus external, with a first-cut mapping onto the "
                 "Example networks for a later re-address. The two busiest internal subnets map to the "
                 "user and server networks; externals stay on the internet side.</p>"
                 "<table><thead><tr><th>Subnet</th><th>Side</th><th>Hosts</th></tr></thead><tbody>%s</tbody></table>"
                 "<ul>%s</ul>" % (sub_rows or "<tr><td colspan='3'>none</td></tr>",
                                  sugg or "<li>not enough internal structure to suggest a mapping</li>"))

    sections = [
        ("What the profiler read", coverage_html(p)),
        ("Protocol mix",
         "<table><thead><tr><th>Protocol</th><th>Packets</th><th>Share</th><th>Bytes</th></tr></thead>"
         "<tbody>%s</tbody></table>%s" % (proto_rows, _full_table(p, "protocols", "protocols"))),
        ("Hosts and inferred roles",
         "<p>Role is inferred from who receives the TCP SYN: a host that is the destination of "
         "connection openings is marked a server, and the ports it serves are listed.</p>"
         "<table><thead><tr><th>Host</th><th>Role</th><th>Serves ports</th><th>Packets</th>"
         "<th>Bytes</th></tr></thead><tbody>%s</tbody></table>%s" % (host_rows, _full_table(p, "hosts", "hosts"))),
        ("Flows and timing",
         "<p>Top conversations by bytes, with duration and direction (share of bytes from endpoint "
         "A). Busiest minute: %d packets. Median flow duration: %s.</p>"
         "<table><thead><tr><th>Endpoint A</th><th>Endpoint B</th><th>L4</th><th>Packets</th>"
         "<th>Bytes</th><th>Duration</th><th>Dir</th></tr></thead><tbody>%s</tbody></table>%s"
         % (peak, _fmt_dur(median_dur) if median_dur >= 1 else "<1s", conv_rows,
            _full_table(p, "conversations", "conversations"))),
        ("Server ports",
         "<table><thead><tr><th>Port</th><th>SYNs seen</th></tr></thead><tbody>%s</tbody></table>%s"
         % (port_rows or "<tr><td colspan='2'>none observed</td></tr>", _full_table(p, "ports", "server ports"))),
        ("TLS, QUIC and DNS",
         "<table><tbody>"
         "<tr><td><b>TLS handshakes</b></td><td class='m'>%d</td></tr>"
         "<tr><td><b>TLS versions</b></td><td>%s</td></tr>"
         "<tr><td><b>Post-quantum groups offered</b></td><td class='m'>%s</td></tr>"
         "<tr><td><b>TLS SNI names</b></td><td>%s</td></tr>"
         "<tr><td><b>JA4 client fingerprints</b></td><td class='m'>%s</td></tr>"
         "<tr><td><b>QUIC Initials (by version)</b></td><td class='m'>%s</td></tr>"
         "<tr><td><b>QUIC SNI names</b></td><td>%s</td></tr>"
         "<tr><td><b>DNS names queried</b></td><td>%s</td></tr>"
         "</tbody></table>"
         % (p["tls_handshakes"], tlsv, _esc(pqc), _esc(snis), _esc(ja4top), quicv, _esc(quicsni), _esc(dns))),
        ("HTTP detail", http_html),
        ("SMB detail", smb_html),
        ("NTP detail", ntp_html),
        ("Candidate protocol detail (SSH / SMTP / NFS / RADIUS)", cand_detail_html),
        ("Identities", id_html),
        ("Topology and suggested mapping", topo_html),
        ("Addresses embedded in payloads", emb_html),
        ("Reproducibility coverage", cov_html),
    ]
    notes = [
        ("", "Header-level, read-only",
         "This profile is built from packet headers and the cleartext parts of the handshake. "
         "Nothing is decrypted, and no external dissector is used. It describes the imported "
         "capture; it does not change it. TLS ClientHellos that span TCP segments are reassembled, "
         "so their count and fingerprints are exact; other multi-segment payloads are read one "
         "segment at a time, so a few such values can run low."),
        ("warn", "An imported capture is not a Example capture",
         "The hosts, addresses and protocols here are whatever the file contained. Re-addressing "
         "it into the baseline networks and building a scenario from it are later phases, each "
         "with their own limits."),
    ]
    if p["unsupported"]:
        notes.append(("warn", "Some packets were skipped",
                      "%d packet(s) used a link layer this profiler does not parse (see 'What the "
                      "profiler read'). They are counted but not classified." % p["unsupported"]))
    # a compact protocol-mix bar for the page header (render_page expects an svg)
    SAP, PLUM, CY = "#C2410C", "#DC2626", "#15803D"
    top = rows[:8]
    mx = max((c for _n, c in top), default=1)
    W, Hs = 1180, 70 + 26 * len(top)
    svg = ['<svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg" '
           'font-family="Source Sans 3,Arial,sans-serif">' % (W, Hs)]
    svg.append('<defs><linearGradient id="pmg" x1="0" y1="0" x2="1" y2="0">'
               '<stop offset="0" stop-color="%s"/><stop offset="1" stop-color="%s"/></linearGradient></defs>' % (SAP, PLUM))
    svg.append('<text x="14" y="26" font-size="13" font-weight="900" fill="%s">PROTOCOL MIX</text>' % SAP)
    svg.append('<text x="14" y="43" font-size="10" fill="#4B5563">top %d of %d protocols, by packets</text>'
               % (len(top), len(p["protocols"])))
    bx, bw = 180, W - 320
    for i, (nm, cnt) in enumerate(top):
        y = 60 + i * 26
        w = bw * cnt / mx
        svg.append('<text x="170" y="%d" text-anchor="end" font-size="10.5" fill="%s" '
                   'font-family="ui-monospace,Menlo,monospace">%s</text>' % (y + 4, SAP, _esc(nm)))
        svg.append('<rect x="%d" y="%d" width="%.1f" height="14" rx="3" fill="url(#pmg)"/>' % (bx, y - 7, max(2, w)))
        svg.append('<text x="%.1f" y="%d" font-size="10" fill="#4a4760">%d (%.1f%%)</text>'
                   % (bx + max(2, w) + 6, y + 4, cnt, 100.0 * cnt / total))
    svg.append('</svg>')

    return {
        "svg": "".join(svg),
        "doc_tag": "Imported capture<br>Exemplar profile",
        "h1": "Capture profile",
        "subtitle": "Header-level characterisation of %s" % os.path.basename(p["path"]),
        "kpis": [
            ("{:,}".format(p["pkts"]), "Packets"),
            (_fmt_bytes(p["bytes"]), "Captured bytes"),
            (_fmt_dur(p["duration"]), "Duration"),
            ("{:,}".format(len(p["hosts"])), "Hosts"),
            (str(len(p["protocols"])), "Protocols"),
            (p["format"], "Format", "mono"),
        ],
        "sections": sections,
        "notes": notes,
    }


def compare_content(src, built, report_path=None):
    """A render_page content dict comparing the source capture's profile with the profile of a
    capture rebuilt from its recipe. Honest about what the comparison means: the rebuild is the
    custom scenario laid over a normal day, so the useful reading is which protocols the recipe
    added and which it could not, not a packet-for-packet match."""
    import json
    sp, bp = src["protocols"], built["protocols"]
    names = sorted(set(sp) | set(bp), key=lambda n: -(max(sp.get(n, 0), bp.get(n, 0))))
    rows = ""
    for n in names:
        a, b = sp.get(n, 0), bp.get(n, 0)
        tag = "only in source" if b == 0 else ("only in rebuild" if a == 0 else "")
        rows += ("<tr><td>%s</td><td class='m'>%d</td><td class='m'>%d</td><td class='m'>%+d</td><td>%s</td></tr>"
                 % (_esc(n), a, b, b - a, tag))
    covered = [n for n in sp if n in bp]
    missing = sorted(n for n in sp if n not in bp)
    sections = [
        ("How to read this",
         "<p>The rebuilt capture is the recipe's custom scenario laid over a normal generated day, so its "
         "totals are not expected to match the source. Read it for coverage: which of the source's protocols "
         "now appear, and which the engine could not build. Volumes are scaled and capped per protocol.</p>"),
        ("Protocol coverage",
         "<p>%d of %d source protocols appear in the rebuild%s.</p>"
         "<table><thead><tr><th>Protocol</th><th>Source packets</th><th>Rebuilt packets</th><th>Delta</th>"
         "<th></th></tr></thead><tbody>%s</tbody></table>"
         % (len(covered), len(sp), ("; absent: " + _esc(", ".join(missing[:12]))) if missing else "", rows)),
        ("Hosts",
         "<table><tbody><tr><td><b>Source hosts</b></td><td class='m'>%d</td></tr>"
         "<tr><td><b>Rebuilt hosts</b></td><td class='m'>%d</td></tr>"
         "<tr><td><b>Source addresses reused in the rebuild</b></td><td class='m'>%d</td></tr></tbody></table>"
         "<p>A rebuild maps the source onto the simulated environment, so reused addresses should be few.</p>"
         % (len(src["hosts"]), len(built["hosts"]), len(set(src["hosts"]) & set(built["hosts"])))),
    ]
    if report_path and os.path.isfile(report_path):
        try:
            with open(report_path) as fh:
                rep = json.load(fh)
            built_rows = "".join(
                "<tr><td>%s</td><td>%s</td><td>%s</td><td class='m'>%s</td></tr>"
                % (_esc(b.get("protocol")), _esc(b.get("builder")), _esc(b.get("server")), _esc(b.get("sessions")))
                for b in rep.get("built", []))
            skip_rows = "".join("<tr><td>%s</td><td>%s</td></tr>" % (_esc(k.get("protocol")), _esc(k.get("reason")))
                                for k in rep.get("skipped", []))
            sections.append(("Reconstruction report (from the build)",
                             "<table><thead><tr><th>Protocol</th><th>Builder</th><th>Server</th><th>Sessions built</th>"
                             "</tr></thead><tbody>%s</tbody></table>"
                             "<table><thead><tr><th>Skipped</th><th>Reason</th></tr></thead><tbody>%s</tbody></table>"
                             % (built_rows or "<tr><td colspan='4'>none</td></tr>",
                                skip_rows or "<tr><td colspan='2'>none</td></tr>")))
        except (OSError, ValueError):
            pass
    return {
        "svg": "<svg viewBox='0 0 1180 10' xmlns='http://www.w3.org/2000/svg'></svg>",
        "doc_tag": "Imported capture<br>Source vs rebuild",
        "h1": "Capture comparison",
        "subtitle": "%s  versus  %s" % (os.path.basename(src["path"]), os.path.basename(built["path"])),
        "kpis": [("{:,}".format(src["pkts"]), "Source packets"), ("{:,}".format(built["pkts"]), "Rebuilt packets"),
                 ("%d / %d" % (len(covered), len(sp)), "Protocols covered"),
                 (str(len(missing)), "Not rebuilt")],
        "sections": sections,
        "notes": [],
    }


# ------------------------------------------------------------ synthesis spec (Phase 2, Half A)
# Where an exemplar's L7 cannot simply be re-addressed, it is RECREATED in the simulated
# environment. This turns a profile into a deterministic recipe the generator can later execute:
# exemplar hosts/roles/identities/flows mapped onto real Example hosts, the corp domain, the
# engine's users and PKI. It is data only; it changes nothing and runs nothing.
# The recipe vocabulary: one token per engine builder the custom-import scenario can drive.
# Token -> (engine builder it calls, the canonical Example server the recipe records for it).
# Must stay in step with incidents.CI_SUPPORTED.
_CI_BUILDER = {
    "HTTPS": ("https_session", "EXL-WEB2"),   "HTTP": ("page_load", "EXL-WEB1"),
    "SMB2": ("smb_file_activity", "EXL-FILE1"), "Kerberos": ("kerberos_as", "EXL-DC1"),
    "LDAP": ("ldap_session", "EXL-DC1"),      "TDS": ("tds_session", "EXL-SQL1"),
    "DNS": ("dns_lookup", "EXL-DC1"),         "RDP": ("rdp_session", "EXL-MGMT1"),
    "SNMP": ("snmp_poll", "EXL-SWB1"),        "SSH": ("ssh_session", "EXL-MGMT1"),
    "FTP": ("anon_ftp_session", "EXL-BACKUP1"), "NTP": ("ntp_exchange", "EXL-NTP1"),
    "DHCP": ("dhcp_acquire", "EXL-DC1"),      "Syslog": ("syslog_msg", "EXL-LOG1"),
    "SIP": ("sip_call", "EXL-PBX1"),          "Print": ("print_job", "EXL-PRINT1"),
    "MCP": ("mcp_session", "EXL-SB-02"),      "NameRes": ("name_noise", "EXL-DC1"),
    "ICMP": ("icmp_ping", "EXL-WEB1"),        "Modbus": ("modbus_poll_block", "EXL-PLC-01"),
    "BACnet": ("bacnet_read_exchange", "EXL-PLC-01"), "DNP3": ("dnp3_poll_block", "EXL-RTU-01"),
    "SMTP": ("smtp_session", "EXL-BACKUP1"),  "NFS": ("nfs_session", "EXL-BACKUP1"),
    "RADIUS": ("radius_auth", "EXL-DC1"),
}
# A CI protocol named from the TCP server port the exemplar's SYNs landed on.
_CI_TCP_PORT = {443: "HTTPS", 80: "HTTP", 8080: "HTTP", 445: "SMB2", 139: "SMB2", 1433: "TDS",
                88: "Kerberos", 389: "LDAP", 636: "LDAP", 53: "DNS", 3389: "RDP", 161: "SNMP",
                22: "SSH", 21: "FTP", 631: "Print", 515: "Print", 9100: "Print", 3000: "MCP",
                502: "Modbus", 20000: "DNP3", 25: "SMTP", 587: "SMTP", 2049: "NFS"}
# CI protocols with no TCP server port (UDP or flow-less): named from the protocol tally instead.
# Token -> the classify names that imply it.
_CI_PRESENCE = {
    "NTP": ("NTP",), "DHCP": ("DHCP",), "Syslog": ("Syslog",), "SIP": ("SIP", "RTP", "RTCP"),
    "SNMP": ("SNMP",), "DNS": ("DNS",), "BACnet": ("BACnet",), "ICMP": ("ICMP",),
    "NameRes": ("mDNS", "LLMNR", "NBNS", "NBDS", "SSDP"), "RADIUS": ("RADIUS",),
}


def _load_inventory(path):
    import json
    ws, servers = [], {}
    try:
        with open(path) as f:
            inv = json.load(f)

        def walk(o):
            if isinstance(o, dict):
                if "hostname" in o and "ip" in o:
                    h = o["hostname"]
                    if h.startswith(("EXL-WS", "EXL-MAC")):
                        ws.append((h, o["ip"]))
                    else:
                        servers[h] = o["ip"]
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(inv)
    except Exception:
        pass
    return sorted(ws), servers


RECIPE_SCHEMA = 1


def unusable_reason(prof):
    """None when the profile saw usable IP traffic, else a plain-language reason it did not. The
    server turns this into an error instead of presenting an empty report as a success."""
    if prof["pkts"] == 0:
        return "the file has a valid capture header but contains no packets"
    if prof["unsupported"] >= prof["pkts"]:
        names = ", ".join("%s (%d frames)" % (link_name(k), v)
                          for k, v in sorted(prof["unsupported_links"].items(), key=lambda kv: -kv[1]))
        return ("every frame uses a link type the importer cannot read: %s. Supported: Ethernet "
                "(with VLAN/QinQ), raw IP, BSD loopback, Linux cooked (SLL/SLL2)" % names)
    if not prof["hosts"] and not prof["nonip"]:
        return "no IPv4 or IPv6 traffic could be read from this capture"
    return None


def profile_summary(prof):
    """The coverage facts that travel inside the recipe, so a recipe says what its source did and
    did not contain."""
    return {
        "packets": prof["pkts"], "bytes": prof["bytes"], "hosts": len(prof["hosts"]),
        "conversations": len(prof["convos"]),
        "protocols": dict(sorted(prof["protocols"].items(), key=lambda kv: -kv[1])),
        "skipped": dict(prof["skips"]),
        "unsupported_link_frames": {link_name(k): v for k, v in prof["unsupported_links"].items()},
        "table_overflow": dict(prof["overflow"]),
    }


def validate_recipe(obj):
    """Check a loaded recipe's structure and return (clean_recipe, warnings). Raises ValueError with
    a message naming the problem. Lenient about unknown keys and about recipes made before the
    schema field existed; strict about shape, so the builder never sees a wrong type."""
    warnings = []
    if not isinstance(obj, dict):
        raise ValueError("a recipe must be a JSON object, not %s" % type(obj).__name__)
    ver = obj.get("schema", 0)
    if not isinstance(ver, int) or ver > RECIPE_SCHEMA:
        raise ValueError("recipe schema %r is newer than this build understands (max %d)" % (ver, RECIPE_SCHEMA))
    if not isinstance(obj.get("flows"), list) or not obj["flows"]:
        raise ValueError("recipe has no 'flows' list; was it exported by Import pcap > Export recipe?")
    hm = obj.get("host_map", [])
    if not isinstance(hm, list) or any(not isinstance(h, dict) for h in hm):
        raise ValueError("'host_map' must be a list of objects")
    clean_flows = []
    for i, f in enumerate(obj["flows"]):
        if not isinstance(f, dict) or not isinstance(f.get("protocol"), str):
            warnings.append("flow %d dropped: not an object with a 'protocol' string" % i)
            continue
        f = dict(f)
        try:
            n = float(f.get("sessions", 10))
            if n != n or n in (float("inf"), float("-inf")):
                raise ValueError
        except (TypeError, ValueError):
            warnings.append("flow %d (%s) dropped: 'sessions' is not a number" % (i, f["protocol"]))
            continue
        f["sessions"] = int(max(0, min(n, 10_000_000)))
        for key in ("paths", "user_agents", "shares"):
            v = f.get(key)
            if v is not None:
                f[key] = [x for x in v if isinstance(x, str)] if isinstance(v, list) else []
        clean_flows.append(f)
    if not clean_flows:
        raise ValueError("no usable flows in the recipe (%s)" % "; ".join(warnings[:3]))
    out = dict(obj)
    out["flows"] = clean_flows
    out["host_map"] = hm
    return out, warnings


def load_recipe(path):
    """Read and validate a recipe file. Errors name the file."""
    import json
    probe_readable(path)
    try:
        with open(path) as fh:
            raw = json.load(fh)
    except (OSError, ValueError) as e:
        raise ValueError("%s: %s" % (os.path.basename(path), e))
    try:
        return validate_recipe(raw)
    except ValueError as e:
        raise ValueError("%s: %s" % (os.path.basename(path), e))


def build_spec(prof, inventory_path):
    """A scenario recipe (dict) that recreates the exemplar inside the Example environment."""
    from netgen.protocols import DOMAIN, REALM
    ws, servers = _load_inventory(inventory_path)
    p = prof

    # map exemplar internal clients (busiest first) onto Example workstations, round-robin
    internal_clients = [ip for ip, (pk, by) in sorted(p["hosts"].items(), key=lambda kv: -kv[1][1])
                        if ":" not in ip and ip.startswith(("10.", "192.168.", "172."))
                        and (ip, None) not in [(s, None) for s in ()]]
    client_ips = [ip for ip in internal_clients if (ip, [0, 0])]  # keep order
    host_map = []
    wsn = [w for w in ws if w[0].startswith("EXL-WS")] or ws
    for i, ip in enumerate([c for c in client_ips if c not in [s for s in servers.values()]][:30]):
        nw, nwip = wsn[i % len(wsn)] if wsn else ("EXL-WS-001", "")
        host_map.append({"exemplar": ip, "role": "client", "example": nw, "ip": nwip})

    # flows: one per CI protocol the engine can build. One flow per protocol token; the consumer
    # fans it out across the window and the mapped workstation pool.
    flows = []
    seen = set()

    def _emit(proto, sessions, port=None, origin="server port"):
        if proto in seen:
            return
        seen.add(proto)
        builder, srv = _CI_BUILDER[proto]
        flow = {"protocol": proto, "builder": builder, "server": srv,
                "server_ip": servers.get(srv, ""), "port": port,
                "sessions": int(max(1, sessions)), "client_pool": "mapped workstations",
                "named_from": origin}
        if proto in ("HTTPS", "HTTP"):
            h = p["http"]
            flow["paths"] = [k for k, _ in sorted(h["paths"].items(), key=lambda kv: -kv[1])[:6]]
            flow["user_agents"] = [k for k, _ in sorted(h["uas"].items(), key=lambda kv: -kv[1])[:3]]
            flow["methods"] = h["methods"]
        if proto == "SMB2":
            flow["shares"] = sorted(p["smb"]["trees"])[:8]
            flow["operations"] = p["smb"]["cmds"]
        flows.append(flow)

    # 1. TCP protocols named from the observed server ports — real SYN counts drive the sessions.
    for (ip, port, l4), syns in sorted(p["server_ports"].items(), key=lambda kv: -kv[1]):
        if l4 != "tcp":
            continue
        proto = _CI_TCP_PORT.get(port)
        if proto:
            _emit(proto, int(syns), port=port)

    # 2. UDP / flow-less protocols named from the protocol tally — no server port is recorded for
    #    these, so the session count is estimated from how many packets of that kind were seen.
    for proto, names in _CI_PRESENCE.items():
        hits = sum(p["protocols"].get(n, 0) for n in names)
        if hits > 0:
            _emit(proto, min(60, max(1, hits // 8)), origin="protocol tally")

    span = int(p["duration"]) or 3600
    syn_users = sorted(p["users"])
    return {
        "schema": RECIPE_SCHEMA,
        "_comment": "Scenario recipe generated from an imported pcap. Recreates the exemplar's "
                    "pattern in the simulated environment: hosts, identities, domains and "
                    "certificates are simulated, not copied. The exemplar's own addresses, paths "
                    "and user agents are recorded here for traceability and drive the mapping. "
                    "Reproducible only for the protocols the engine builds.",
        "profile_summary": profile_summary(p),
        "source": {"file": os.path.basename(p["path"]), "format": p["format"], "packets": p["pkts"],
                   "duration_sec": span, "peak_minute_pkts": max(p["minute_pkts"].values()) if p["minute_pkts"] else 0},
        "window": {"suggested_minutes": max(5, min(span // 60, 120))},
        "environment": {"domain": DOMAIN, "realm": REALM,
                        "users": "simulated via username_for on the mapped workstations",
                        "tls": "engine PKI (decryptable RSA, or TLS 1.3 posture); exemplar certs not copied"},
        "host_map": host_map,
        "identities_seen": {"domains": sorted(p["domains"]), "user_count": len(syn_users),
                            "note": "mapped to Example accounts, not reused"},
        "flows": flows,
        "reproducible": {
            "rebuilt_as_flows": sorted(seen),
            "synthesisable": sorted(n for n in p["protocols"] if n in ENGINE_SYNTH),
            "approximate_only": sorted(n for n in p["protocols"]
                                       if n not in ENGINE_SYNTH and n not in ("Ethernet-other", "TCP-other", "UDP-other")
                                       and not n.startswith("IP-proto-")),
            "not_reproduced": [n for n in ("TCP-other", "UDP-other") if n in p["protocols"]],
        },
        "notes": [
            "Timing: each flow's sessions are spread evenly across the custom scenario's window; the "
            "exemplar's busiest-minute shape is recorded in 'source' but not replayed.",
            "Volume: 'sessions' is what the exemplar showed. The builder scales it by the generation "
            "scale and caps it at 400 sessions per protocol, so a recipe is a pattern, not a replay.",
            "Each flow is a call to the named engine builder with the mapped server and workstation pool.",
            "Anything under approximate_only / not_reproduced cannot be recreated faithfully; the engine "
            "has no builder for it.",
        ],
    }


def main():
    import argparse
    import json
    ap = argparse.ArgumentParser(description="Profile an imported pcap (header-level, read-only).")
    ap.add_argument("pcap")
    ap.add_argument("-o", "--out", default=None, help="write HTML here (default: stdout facts)")
    ap.add_argument("--spec", default=None, help="write a scenario-recipe JSON here")
    ap.add_argument("--cap", type=int, default=None, help="stop after N packets")
    args = ap.parse_args()
    if args.spec:
        prof = profile(args.pcap, cap=args.cap)
        spec = build_spec(prof, os.path.join(os.path.dirname(os.path.abspath(__file__)), "inventory.json"))
        with open(args.spec, "w") as f:
            json.dump(spec, f, indent=2)
        print("wrote", args.spec, "(%d flows)" % len(spec["flows"]))
        return
    prof = profile(args.pcap, cap=args.cap)
    if args.out:
        import make_diagram as M
        data = M.gather(os.path.join(M.APP_DIR, "inventory.json"), None, None)
        mods, sel = M.load_modules(None)
        c = M.DiagramContext(data, mods, sel)
        out = content(prof)
        d = M.Diagram("profile", "Capture profile", "Imported pcap", lambda _c: out, 0, None)
        with open(args.out, "w") as f:
            f.write(M.render_page(d, c, M.load_logo()))
        print("wrote", args.out)
    else:
        for key in ("format", "pkts", "bytes", "duration", "tls_handshakes"):
            print(key, "=", prof[key])
        print("protocols:", dict(sorted(prof["protocols"].items(), key=lambda kv: -kv[1])))
        print("pqc_offered:", prof["pqc_offered"])


if __name__ == "__main__":
    main()
