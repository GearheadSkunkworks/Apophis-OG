"""Crafted on-the-wire bytes for fingerprint fidelity (TLS 1.3 ClientHello/ServerHello/cert and
the exact OpenSSH 9.6 KEXINIT), built on the engine's own low-level TLS record helpers so the
module never touches core.

Two honest design points (see ja4.py for the full reproducibility matrix):

  * HTTPS phases emit a real crafted TLS 1.3 **ClientHello/ServerHello/Certificate** so a sensor
    recomputes JA4 / JA4S / JA4X509 from genuine handshake bytes -- then carry the HTTP as
    *cleartext inside TLS application-data record frames* (``_rec(23, ...)``). That is the spec's
    sanctioned §4 option (b) ("emit the cleartext HTTP on 443 and mark it decrypted"): the engine
    has no TLS 1.3 key schedule, so this is how both the fingerprint AND the readable HTTP record
    land on the wire.
  * SSH KEXINIT carries the exact OpenSSH 9.6 client/server algorithm name-lists, so HASSH /
    HASSH-server are byte-for-byte correct (verified in ja4/self_test).
"""
import os
import struct

from netgen.tls import _ext, _hs, _rec, VER  # type: ignore

# ------------------------------------------------------------------ TLS 1.3 ClientHello (JA4)
_GROUP_KS = {0x001d: 32, 0x0017: 65, 0x0018: 97}      # x25519 / secp256r1 / secp384r1 key-share sizes


def _ext_payload(code, sni, groups, sigalgs, alpn):
    """Build a standard payload for a known extension codepoint (well-formed, JA4-neutral)."""
    if code == 0x0000:                                 # server_name
        host = (sni or "").encode()
        return struct.pack("!H", len(host) + 3) + b"\x00" + struct.pack("!H", len(host)) + host
    if code == 0x0005:                                 # status_request: OCSP, no responder IDs/extensions
        return b"\x01" + struct.pack("!H", 0) + struct.pack("!H", 0)
    if code == 0x000a:                                 # supported_groups
        g = b"".join(struct.pack("!H", x) for x in groups)
        return struct.pack("!H", len(g)) + g
    if code == 0x000b:                                 # ec_point_formats
        return b"\x01\x00"
    if code == 0x000d:                                 # signature_algorithms
        s = b"".join(struct.pack("!H", x) for x in sigalgs)
        return struct.pack("!H", len(s)) + s
    if code == 0x0010:                                 # ALPN
        lst = b"".join(bytes([len(p)]) + p.encode() for p in (alpn or []))
        return struct.pack("!H", len(lst)) + lst
    if code == 0x0017:                                 # extended_master_secret
        return b""
    if code == 0x001b:                                 # compress_certificate (brotli)
        return b"\x02\x00\x02"
    if code == 0x0023:                                 # session_ticket
        return b""
    if code == 0x002b:                                 # supported_versions: TLS 1.3
        return b"\x02\x03\x04"
    if code == 0x002d:                                 # psk_key_exchange_modes: psk_dhe_ke
        return b"\x01\x01"
    if code == 0x0033:                                 # key_share: one x25519 entry
        ks = struct.pack("!HH", 0x001d, 32) + os.urandom(32)
        return struct.pack("!H", len(ks)) + ks
    if code == 0xff01:                                 # renegotiation_info
        return b"\x00"
    return b""                                         # any other declared ext: empty (count still right)


# The module builds one ClientHello immediately followed by its own ServerHello (every call site
# below is `s.c2s(client_hello_for(...))` then `s.s2c(server_hello_flight(...))` for the same
# session, synchronously, before the next session's flight starts), so a module-level "last
# client session id" is safe and lets server_hello_flight echo it (RFC 8446 4.1.3) without
# threading a new parameter through every one of this module's call sites.
_last_client_sid = [None]


def client_hello(ciphers, ext_order, groups, sigalgs, alpn=None, sni=None, client_random=None):
    """A TLS 1.3 ClientHello whose cipher list, extension list/order, groups, sig-algs, ALPN and
    SNI are exactly the arguments -- so JA4 recomputes from the same inputs ja4.ja4() is given."""
    crand = client_random or os.urandom(32)
    sid = os.urandom(32)
    _last_client_sid[0] = sid
    order = [c for c in ext_order if not (c == 0x0000 and not sni)]   # never an empty server_name
    exts = b"".join(_ext(c, _ext_payload(c, sni, groups, sigalgs, alpn)) for c in order)
    suites = b"".join(struct.pack("!H", c) for c in ciphers)
    ch = (VER + crand + bytes([32]) + sid + struct.pack("!H", len(suites)) + suites
          + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    return _rec(22, _hs(1, ch))


def server_hello_flight(cert_der, ca_der=None, server_random=None, client_session_id=None):
    """ServerHello (TLS 1.3, cipher 0x1302, extensions supported_versions then key_share -> JA4S
    t130200_1302_a56c5b993250) followed by a cleartext Certificate handshake record (so a sensor
    reads the leaf and computes JA4X509). Then an opaque EncryptedExtensions/Finished blob.

    `client_session_id` defaults to the id the matching client_hello() call just generated, so
    legacy_session_id echoes the ClientHello's as RFC 8446 4.1.3 requires."""
    srand = server_random or os.urandom(32)
    sid = client_session_id if client_session_id is not None else (_last_client_sid[0] or os.urandom(32))
    s_ks = struct.pack("!HH", 0x001d, 32) + os.urandom(32)
    s_exts = _ext(0x002b, b"\x03\x04") + _ext(0x0033, s_ks)           # order fixed -> JA4S hash
    sh = (VER + srand + bytes([32]) + sid + struct.pack("!H", 0x1302) + b"\x00"
          + struct.pack("!H", len(s_exts)) + s_exts)
    ders = [cert_der] + ([ca_der] if ca_der else [])
    # cert_entry: <cert_data length:3><DER><extensions length:2 = 0> (RFC 8446 4.4.2)
    certs = b"".join(len(c).to_bytes(3, "big") + c + b"\x00\x00" for c in ders)
    cert_msg = b"\x00" + len(certs).to_bytes(3, "big") + certs         # certificate_request_context(0) + list
    flight = _rec(22, _hs(2, sh)) + _rec(22, _hs(11, cert_msg)) + _rec(23, os.urandom(1400))
    return flight


def tls_cleartext(http_bytes):
    """Wrap cleartext HTTP in a TLS application-data record frame (the '...marked decrypted' path)."""
    out = []
    for i in range(0, len(http_bytes), 16384):
        out.append(_rec(23, http_bytes[i:i + 16384]))
    return b"".join(out)


# ------------------------------------------------------------------ TLS fingerprint profiles (spec 11)
# Implant (Wshot): JA4 t13i911000 -> no SNI, 91 ciphers, 10 extensions, no ALPN. The 91-cipher and
# extension VALUES are not in the spec (only the JA4 prefix + unrecoverable hash), so the list is a
# plausible 91-long enumeration; the PREFIX (counts/flags) is what reproduces.
_IMPLANT_CIPHERS = tuple(range(0x1301, 0x1301 + 3)) + (0x00ff,) + tuple(
    c for c in (
        0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028, 0xc027, 0xc00a, 0xc009,
        0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f, 0x00a3, 0x009f,
        0x00a2, 0x009e, 0x00a7, 0x006b, 0x0067, 0x0039, 0x0033, 0x00ab, 0x00aa, 0x00a9,
        0x00a8, 0x00ae, 0x00ad, 0x00b2, 0x00b1, 0x00b6, 0x00b5, 0xc032, 0xc031, 0xc030,
        0xc02e, 0xc02d, 0xc026, 0xc025, 0xc02a, 0xc029, 0xc005, 0xc004, 0xc003, 0xc002,
        0xc00f, 0xc00e, 0xc00d, 0xc00c, 0xc008, 0xc007, 0xc012, 0xc011, 0xc010, 0x000a,
        0x0005, 0x0004, 0x008b, 0x008c, 0x008d, 0x008a, 0x0041, 0x0084, 0x0007, 0x0016,
        0x0013, 0x0066, 0x00bc, 0x00bd, 0x00be, 0x00bf, 0x00c0, 0x00c1, 0x00c2, 0x00c3,
        0x0045, 0x0044, 0x0088, 0x0087, 0x0096, 0x00c4, 0x00c5))[:87]
# pad/truncate to exactly 91 distinct values
_IMPLANT_CIPHERS = tuple(dict.fromkeys(_IMPLANT_CIPHERS))
while len(_IMPLANT_CIPHERS) < 91:
    _IMPLANT_CIPHERS += (0xcca8 + len(_IMPLANT_CIPHERS),)
_IMPLANT_CIPHERS = _IMPLANT_CIPHERS[:91]
_IMPLANT_EXTS = (0x000a, 0x000b, 0x000d, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033, 0xff01)  # 10, no SNI/ALPN
_IMPLANT_GROUPS = (0x001d, 0x0017, 0x0018)
_IMPLANT_SIGALGS = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)

# Workforce 76.31.96.12: JA4 t13i2011h1_2b729b4bf6f3_... -> exact 20-cipher list (JA4_b exact),
# no SNI, 11 extensions incl ALPN http/1.1, groups 001d 0017 0018.
WORKFORCE_CIPHERS = (0x1302, 0x1301, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xc024, 0xc023, 0xc028,
                     0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c,
                     0x0035, 0x002f)
_WORKFORCE_EXTS = (0x000a, 0x000b, 0x000d, 0x0010, 0x0017, 0x001b, 0x0023, 0x002b, 0x002d, 0x0033, 0xff01)  # 11 incl ALPN(0x10)
_WORKFORCE_GROUPS = (0x001d, 0x0017, 0x0018)
_WORKFORCE_SIGALGS = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)

# Attacker replay client (Chrome/125-like); its TLS JA4 is "browser-like" (not pinned in the spec),
# the decisive signal is its JA4H stolen cookie, handled in phases.py.
_CHROME_CIPHERS = (0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                   0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035)
_CHROME_EXTS = (0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0010, 0x0005, 0x000d, 0x0012,
                0x0033, 0x002d, 0x002b, 0x001b, 0x0023)
_CHROME_GROUPS = (0x001d, 0x0017, 0x0018)
_CHROME_SIGALGS = (0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)

# OpenSSL-library client (python-httpx / curl's default stack): TLS 1.3 + 1.2 suites in OpenSSL's
# own order, HTTP/1.1 only (no h2 ALPN) -- distinct from the browser profiles above/below.
_OPENSSL_CIPHERS = (0x1302, 0x1303, 0x1301, 0xc02c, 0xc030, 0xc02b, 0xc02f, 0x009f, 0x009e,
                    0xc024, 0xc028, 0xc023, 0xc027, 0x006b, 0x0067, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f)
_OPENSSL_EXTS = (0x002b, 0x000d, 0x000a, 0x0033, 0x0017, 0x0023)   # 6, no SNI/ALPN/GREASE
_OPENSSL_GROUPS = (0x001d, 0x0017, 0x0018)
_OPENSSL_SIGALGS = (0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b, 0x0804, 0x0805,
                    0x0806, 0x0401, 0x0501, 0x0601, 0x0303, 0x0301, 0x0302, 0x0402, 0x0502, 0x0602)

PROFILES = {
    "implant":   dict(ciphers=_IMPLANT_CIPHERS, ext_order=_IMPLANT_EXTS, groups=_IMPLANT_GROUPS,
                      sigalgs=_IMPLANT_SIGALGS, alpn=None, sni=None),
    "workforce": dict(ciphers=WORKFORCE_CIPHERS, ext_order=_WORKFORCE_EXTS, groups=_WORKFORCE_GROUPS,
                      sigalgs=_WORKFORCE_SIGALGS, alpn=["http/1.1"], sni=None),
    "openssl":   dict(ciphers=_OPENSSL_CIPHERS, ext_order=_OPENSSL_EXTS, groups=_OPENSSL_GROUPS,
                      sigalgs=_OPENSSL_SIGALGS, alpn=["http/1.1"], sni=None),
    "chrome":    dict(ciphers=_CHROME_CIPHERS, ext_order=_CHROME_EXTS, groups=_CHROME_GROUPS,
                      sigalgs=_CHROME_SIGALGS, alpn=["h2", "http/1.1"], sni=None),
}


def client_hello_for(profile, sni=None):
    p = dict(PROFILES[profile])
    if sni is not None:
        p = dict(p, sni=sni)
    return client_hello(p["ciphers"], p["ext_order"], p["groups"], p["sigalgs"], p["alpn"], p["sni"])


# ------------------------------------------------------------------ SSH KEXINIT (HASSH, spec 10.3)
# Exact OpenSSH 9.6p1 default name-lists -- verified: client md5 = aae6b9604f6f3356543709a376d7f657,
# server md5 = e42184b06d45385a906f0803d04c83da.
_KEX_BASE = ("sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,"
             "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
             "diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,"
             "diffie-hellman-group18-sha512,diffie-hellman-group14-sha256")
KEX_CLIENT = _KEX_BASE + ",ext-info-c,kex-strict-c-v00@openssh.com"
KEX_SERVER = _KEX_BASE + ",ext-info-s,kex-strict-s-v00@openssh.com"
HK_CLIENT = ("ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,"
             "sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,"
             "sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256")
HK_SERVER = "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256"
ENC = ("chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,"
       "aes128-gcm@openssh.com,aes256-gcm@openssh.com")
MAC = ("umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,"
       "hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,"
       "umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1")
COMP_CLIENT = "none,zlib@openssh.com,zlib"
COMP_SERVER = "none,zlib@openssh.com"


def _nl(s):
    b = s.encode()
    return struct.pack("!I", len(b)) + b


from netgen.protocols import ssh_packet as _ssh_packet  # noqa: E402  (identical framing)


def ssh_kexinit(client=True) -> bytes:
    kex, hk, comp = (KEX_CLIENT, HK_CLIENT, COMP_CLIENT) if client else (KEX_SERVER, HK_SERVER, COMP_SERVER)
    payload = (b"\x14" + os.urandom(16) + _nl(kex) + _nl(hk) + _nl(ENC) + _nl(ENC)
               + _nl(MAC) + _nl(MAC) + _nl(comp) + _nl(comp) + _nl("") + _nl("")
               + b"\x00" + b"\x00\x00\x00\x00")
    return _ssh_packet(payload)


# SSH key exchange values that fit the negotiated sntrup761x25519-sha512@openssh.com: the client
# sends sntrup761 public key (1,158 B) + X25519 (32 B) = 1,190 B; the server answers with the
# sntrup761 ciphertext (1,039 B) + X25519 (32 B) = 1,071 B, its ed25519 host key and signature.
def ssh_kex_init_sntrup() -> bytes:
    return _ssh_packet(b"\x1e" + struct.pack("!I", 1190) + os.urandom(1190))


def ssh_kex_reply_sntrup() -> bytes:
    hk = struct.pack("!I", 51) + struct.pack("!I", 11) + b"ssh-ed25519" + struct.pack("!I", 32) + os.urandom(32)
    sig = struct.pack("!I", 83) + struct.pack("!I", 11) + b"ssh-ed25519" + struct.pack("!I", 64) + os.urandom(64)
    return _ssh_packet(b"\x1f" + hk + struct.pack("!I", 1071) + os.urandom(1071) + sig)


# DTLS 1.2 record layer (RFC 6347 4.1): type, version 0xFEFD, epoch, 48-bit sequence, length.
def dtls_record(seq, payload_len, epoch=1, ctype=23):
    return (struct.pack("!BHH", ctype, 0xFEFD, epoch) + seq.to_bytes(6, "big")
            + struct.pack("!H", payload_len) + os.urandom(payload_len))
