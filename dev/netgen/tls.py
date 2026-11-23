"""
Real TLS 1.2 (TLS_RSA_WITH_AES_128_GCM_SHA256) session builder.

Produces genuine handshake records with an RSA-encrypted premaster secret,
derives keys with the TLS 1.2 PRF, encrypts application data with AES-GCM
and writes CLIENT_RANDOM lines to a key-log file so that Wireshark and
similar tools decrypt the traffic.
"""
import datetime
from .identity import get_current
import hashlib
import hmac
import os
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

CIPHER = 0x009C  # TLS_RSA_WITH_AES_128_GCM_SHA256
VER = b"\x03\x03"


def prf(secret: bytes, label: bytes, seed: bytes, n: int) -> bytes:
    seed = label + seed
    out = b""
    a = seed
    while len(out) < n:
        a = hmac.new(secret, a, hashlib.sha256).digest()
        out += hmac.new(secret, a + seed, hashlib.sha256).digest()
    return out[:n]


class PKI:
    """One fabricated CA and a per-hostname leaf certificate cache."""

    # Certificate validity is anchored to the CAPTURE DAY, not to fixed literals. With a
    # fixed anchor, a capture day that moves forward eventually sits past the leaf notAfter
    # and every server certificate silently reads as expired -- which changes the TLS posture
    # findings and would break the decryption demo about ten months out. The offsets below
    # reproduce exactly the relationships the fixed dates had when the day was 2026-09-14,
    # so a capture generated on that day is unchanged.
    CA_BEFORE_DAYS   = 256      # CA issued ~8 months before the capture
    CA_LIFE_DAYS     = 3650
    LEAF_BEFORE_DAYS = 105      # leaf issued ~3.5 months before, one-year-ish life
    LEAF_LIFE_DAYS   = 397
    EXPIRED_BEFORE   = 1717     # the CRP 'expired certificate' posture: long dead either way
    EXPIRED_LIFE     = 365
    OLD_CA_BEFORE_DAYS = 2200   # CRP-02 defect 2: must predate EXPIRED_BEFORE, so the expired
                                # leaf is issued after its own CA exists, not before it

    def __init__(self, ca_name=None, day=None):
        ca_name = ca_name or get_current().ca
        self.anchor = self._anchor(day)
        self.ca_key = rsa.generate_private_key(65537, 2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                             "%s Certificate Services" % get_current().name)])
        now = self.anchor - datetime.timedelta(days=self.CA_BEFORE_DAYS)
        self.ca_cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                        .public_key(self.ca_key.public_key()).serial_number(x509.random_serial_number())
                        .not_valid_before(now)
                        .not_valid_after(now + datetime.timedelta(days=self.CA_LIFE_DAYS))
                        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                        .sign(self.ca_key, hashes.SHA256()))
        self.leaf = {}
        self._pub = None
        self._old = None

    @staticmethod
    def is_internal(hostname: str) -> bool:
        h = hostname.lower()
        return "." not in h or h.endswith((".local", ".internal", ".lan", ".corp", ".test"))

    def _public_ca(self):
        """A second issuer for names outside the corporate domain, so a CDN / SaaS / C2 front is not
        signed by the lab's own internal CA (a public site's certificate chains to a public CA)."""
        if self._pub is None:
            key = rsa.generate_private_key(65537, 2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Demo Public TLS CA R1"),
                              x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Demo Trust Services")])
            now = self.anchor - datetime.timedelta(days=self.CA_BEFORE_DAYS)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=self.CA_LIFE_DAYS))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                    .sign(key, hashes.SHA256()))
            self._pub = (key, cert)
        return self._pub

    def _old_ca(self):
        """A CA old enough to have genuinely issued the CRP 'expired certificate' leaf
        (EXPIRED_BEFORE days ago): self.ca_cert is only CA_BEFORE_DAYS old, which is less
        than EXPIRED_BEFORE, so that leaf would predate its own issuer's existence."""
        if self._old is None:
            key = rsa.generate_private_key(65537, 2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, get_current().ca),
                              x509.NameAttribute(NameOID.ORGANIZATION_NAME, "%s Certificate Services" % get_current().name)])
            now = self.anchor - datetime.timedelta(days=self.OLD_CA_BEFORE_DAYS)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=self.CA_LIFE_DAYS))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                    .sign(key, hashes.SHA256()))
            self._old = (key, cert)
        return self._old

    @staticmethod
    def _anchor(day):
        """Midnight UTC on the capture day. `day` may be (y,m,d), a date, or None for the
        day netgen.model is currently using -- so the certificates and the packets always
        agree about what day it is."""
        if day is None:
            from .model import capture_day
            day = capture_day()
        if hasattr(day, "year"):
            day = (day.year, day.month, day.day)
        return datetime.datetime(day[0], day[1], day[2], tzinfo=datetime.timezone.utc)

    def cert_for(self, hostname: str):
        if hostname in self.leaf:
            return self.leaf[hostname]
        key = rsa.generate_private_key(65537, 2048)
        now = self.anchor - datetime.timedelta(days=self.LEAF_BEFORE_DAYS)
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        if self.is_internal(hostname):
            ca_key, ca_cert = self.ca_key, self.ca_cert
        else:
            ca_key, ca_cert = self._public_ca()
        cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(ca_cert.subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + datetime.timedelta(days=self.LEAF_LIFE_DAYS))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
                .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(ca_key, hashes.SHA256()))
        der = cert.public_bytes(serialization.Encoding.DER)
        ca_der = ca_cert.public_bytes(serialization.Encoding.DER)
        self.leaf[hostname] = (key, der, ca_der)
        return self.leaf[hostname]

    def bad_cert_for(self, hostname: str, mode: str):
        """mode: 'expired' (past notAfter) or 'selfsigned' (issuer==subject, untrusted)."""
        cache = self.__dict__.setdefault("_bad", {})
        ck = (hostname, mode)
        if ck in cache:
            return cache[ck]
        key = rsa.generate_private_key(65537, 2048)
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        b = (x509.CertificateBuilder().subject_name(subj)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False))
        if mode == "expired":
            old_key, old_ca_cert = self._old_ca()
            n0 = self.anchor - datetime.timedelta(days=self.EXPIRED_BEFORE)
            cert = (b.issuer_name(old_ca_cert.subject).not_valid_before(n0)
                    .not_valid_after(n0 + datetime.timedelta(days=self.EXPIRED_LIFE))
                    .sign(old_key, hashes.SHA256()))
            chain = (key, cert.public_bytes(serialization.Encoding.DER), old_ca_cert.public_bytes(serialization.Encoding.DER))
        else:  # selfsigned
            now = self.anchor - datetime.timedelta(days=self.CA_BEFORE_DAYS)
            cert = (b.issuer_name(subj).not_valid_before(now)
                    .not_valid_after(now + datetime.timedelta(days=self.CA_LIFE_DAYS))
                    .sign(key, hashes.SHA256()))
            chain = (key, cert.public_bytes(serialization.Encoding.DER))
        cache[ck] = chain
        return chain

    def export_pems(self, out_dir):
        """Write each issued leaf certificate + its RSA private key, plus the CA
        cert, as PEM files into out_dir. These are what the platform loads for
        certificate/private-key TLS decryption on replay. Returns the hostnames written."""
        os.makedirs(out_dir, exist_ok=True)
        # Name the CA file after its own subject so it follows the emulated company, exactly as
        # the leaf files follow their host: "Example Demo Root CA" -> example-demo-root-ca.crt,
        # "Acme Demo Root CA" -> acme-demo-root-ca.crt.
        ca_cn = self.ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        ca_safe = "-".join(ca_cn.lower().split()) or "demo-root-ca"
        with open(os.path.join(out_dir, ca_safe + ".crt"), "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
        if self._pub is not None:
            with open(os.path.join(out_dir, "demo-public-tls-ca-r1.crt"), "wb") as f:
                f.write(self._pub[1].public_bytes(serialization.Encoding.PEM))
        written = []
        for host, (key, der, ca_der) in self.leaf.items():
            safe = host.replace("*", "_").replace("/", "_")
            cert = x509.load_der_x509_certificate(der)
            with open(os.path.join(out_dir, safe + ".crt"), "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            with open(os.path.join(out_dir, safe + ".key"), "wb") as f:
                f.write(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.TraditionalOpenSSL,
                                          serialization.NoEncryption()))
            written.append(host)
        return written


# Legacy weak handshake (TLS 1.0 / weak ciphers) — emitted as opaque records so a
# dissector reports the negotiated version and cipher. Not key-logged (the point
# is the weak posture, not the plaintext).
WEAK_VER = b"\x03\x01"  # TLS 1.0
# RC4_SHA, 3DES_SHA, AES128_SHA, RC4_MD5, then the empty-renegotiation-info SCSV (RFC 5746) a
# legacy Windows client sends in lieu of (not alongside) the extension on some stacks. No ECC
# suites: an ECDHE offer with no supported_groups/ec_point_formats extensions is not a real
# client's ClientHello (CRP-01 brief fix 4).
WEAK_SUITES = [0x0005, 0x000A, 0x002F, 0x0004, 0x00FF]
# Encrypted Finished record length by cipher suite (CRP-01 brief fix 2): plaintext Finished is
# always 16 B (4 B handshake header + 12 B verify_data); MAC-then-encrypt adds the suite's MAC,
# CBC suites then pad to the block size. RC4_SHA/ECDHE_RC4_SHA: HMAC-SHA1 (20 B), no padding ->
# 36. RC4_MD5: HMAC-MD5 (16 B), no padding -> 32 (this is the brief's "32", for the MD5 suite,
# not SHA1 -- its own other two numbers, 40 for 3DES-CBC and 48 for AES128-CBC, are exact and
# unchanged). 3DES_EDE_CBC_SHA: 36 padded to an 8-byte block -> 40. AES_128_CBC_SHA: 36 padded to
# a 16-byte block -> 48.
WEAK_FINISHED_LEN = {0x0005: 36, 0x0004: 32, 0xC011: 36, 0x000A: 40, 0x002F: 48, 0xC013: 48}


def _rec_v(ver: bytes, ctype: int, body: bytes) -> bytes:
    return bytes([ctype]) + ver + struct.pack("!H", len(body)) + body


def weak_handshake(pki: "PKI", sni: str, cipher=0x0005, cert_mode=None):
    """
    Return [(from_client, bytes), ...] for a TLS 1.0 handshake negotiating a weak
    cipher (default RC4_SHA), optionally with an expired/self-signed cert.
    App data after this is opaque random bytes.
    """
    crand, srand = os.urandom(32), os.urandom(32)
    if cert_mode:
        chain = pki.bad_cert_for(sni, cert_mode)
        leaf_der = chain[1]
        cert_ders = chain[1:]
    else:
        key, leaf_der, ca_der = pki.cert_for(sni)
        cert_ders = (leaf_der, ca_der)
    sni_ext = struct.pack("!HH", 0, len(sni) + 5) + struct.pack("!HBH", len(sni) + 3, 0, len(sni)) + sni.encode()
    reneg_ext = struct.pack("!HH", 0xff01, 1) + b"\x00"   # renegotiation_info, empty renegotiated_connection
    exts = sni_ext + reneg_ext
    suites = b"".join(struct.pack("!H", c) for c in WEAK_SUITES)
    ssid = os.urandom(32)
    ch = WEAK_VER + crand + bytes([0]) + struct.pack("!H", len(suites)) + suites + b"\x01\x00" + struct.pack("!H", len(exts)) + exts
    ch_hs = _hs(1, ch)
    sh = WEAK_VER + srand + bytes([32]) + ssid + struct.pack("!H", cipher) + b"\x00\x00\x00"
    sh_hs = _hs(2, sh)
    certs = b"".join(len(c).to_bytes(3, "big") + c for c in cert_ders)
    cert_hs = _hs(11, len(certs).to_bytes(3, "big") + certs)
    shd_hs = _hs(14, b"")
    flight1 = _rec_v(WEAK_VER, 22, ch_hs)
    flight2 = _rec_v(WEAK_VER, 22, sh_hs) + _rec_v(WEAK_VER, 22, cert_hs) + _rec_v(WEAK_VER, 22, shd_hs)
    cke = _hs(16, struct.pack("!H", 256) + os.urandom(256))
    finished_len = WEAK_FINISHED_LEN.get(cipher, 48)
    flight3 = _rec_v(WEAK_VER, 22, cke) + _rec_v(WEAK_VER, 20, b"\x01") + _rec_v(WEAK_VER, 22, os.urandom(finished_len))
    flight4 = _rec_v(WEAK_VER, 20, b"\x01") + _rec_v(WEAK_VER, 22, os.urandom(finished_len))
    return [(True, flight1), (False, flight2), (True, flight3), (False, flight4)]


def peap_handshake(pki: "PKI", sni: str):
    """The TLS 1.2 handshake an EAP-PEAP supplicant runs with the NPS server inside EAP-Message
    attributes: [(from_client, bytes), ...] in four flights (ClientHello; ServerHello, the
    certificate chain, ServerHelloDone; key exchange, ChangeCipherSpec, Finished; ChangeCipherSpec,
    Finished). The Finished messages are opaque (AES-GCM sized); nobody decrypts the tunnel."""
    crand, srand = os.urandom(32), os.urandom(32)
    key, leaf_der, ca_der = pki.cert_for(sni)
    sigalgs = _ext(13, struct.pack("!H", 12) + b"".join(struct.pack("!H", a) for a in (0x0401, 0x0501, 0x0601, 0x0403, 0x0503, 0x0603)))
    reneg = _ext(0xff01, b"\x00")
    exts = sigalgs + reneg
    suites = b"".join(struct.pack("!H", c) for c in (0xC02F, 0x009C, 0x002F))
    ch = VER + crand + b"\x00" + struct.pack("!H", len(suites)) + suites + b"\x01\x00" + struct.pack("!H", len(exts)) + exts
    sh = VER + srand + bytes([32]) + os.urandom(32) + struct.pack("!H", 0x009C) + b"\x00" + struct.pack("!H", len(reneg)) + reneg
    certs = b"".join(len(c).to_bytes(3, "big") + c for c in (leaf_der, ca_der))
    cert_hs = _hs(11, len(certs).to_bytes(3, "big") + certs)
    flight1 = _rec(22, _hs(1, ch))
    flight2 = _rec(22, _hs(2, sh)) + _rec(22, cert_hs) + _rec(22, _hs(14, b""))
    cke = _hs(16, struct.pack("!H", 256) + os.urandom(256))
    flight3 = _rec(22, cke) + _rec(20, b"\x01") + _rec(22, os.urandom(40))
    flight4 = _rec(20, b"\x01") + _rec(22, os.urandom(40))
    return [(True, flight1), (False, flight2), (True, flight3), (False, flight4)]


def tunnel_record(n: int) -> bytes:
    """One encrypted application-data record inside the PEAP tunnel (AES-GCM sized: 8-byte
    explicit nonce + n bytes + 16-byte tag)."""
    return _rec(23, os.urandom(8 + n + 16))


def weak_app_data(from_client: bool, n: int) -> bytes:
    return _rec_v(WEAK_VER, 23, os.urandom(n))


def weak_alert(desc: int, fatal: bool = True) -> bytes:
    """A TLS 1.0 Alert record (RFC 2246 7.2): one byte level (2=fatal, 1=warning), one byte
    description -- 42 bad_certificate, 46 certificate_unknown, 48 unknown_ca, 45
    certificate_expired. CRP-02 brief fix 3: the client's cert-warning dialog closes the
    connection this way (or with a bare close, no alert at all) before key exchange."""
    return _rec_v(WEAK_VER, 21, bytes([2 if fatal else 1, desc]))


def _rec(ctype: int, body: bytes) -> bytes:
    return bytes([ctype]) + VER + struct.pack("!H", len(body)) + body


# ---- TLS 1.3 post-quantum posture handshake ------------------------------------------------
# A metadata-only TLS 1.3 handshake whose ONLY purpose is to carry, in cleartext, the key-exchange
# posture the platform reads: the client's supported_groups (the "capable" signal) and the
# server's selected key_share group (the "using" signal). Like weak_handshake(), there is no
# key schedule -- everything after ServerHello is
# opaque bytes. We never decrypt these, so nothing here touches the TLS 1.2 RSA decryption path.
TLS13_GROUPS = {
    "x25519": 0x001d, "secp256r1": 0x0017, "secp384r1": 0x0018,
    "X25519MLKEM768": 0x11ec, "SecP256r1MLKEM768": 0x11eb, "X25519Kyber768Draft00": 0x6399,
}
# client/server key_share byte sizes per group (hybrid = ML-KEM part + 32-byte X25519)
_KS_CLIENT = {0x001d: 32, 0x0017: 65, 0x0018: 97, 0x11ec: 1216, 0x11eb: 1249, 0x6399: 1216}
_KS_SERVER = {0x001d: 32, 0x0017: 65, 0x0018: 97, 0x11ec: 1120, 0x11eb: 1153, 0x6399: 1120}
TLS13_SUITES = [0x1301, 0x1302, 0x1303]   # AES128-GCM, AES256-GCM, CHACHA20
_SIGALGS_13 = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


def _ext(etype: int, data: bytes) -> bytes:
    return struct.pack("!HH", etype, len(data)) + data


# Pure TLS 1.3 ClientHello profiles for the posture scenario: each client type sends its own
# cipher order, extension set and order, GREASE use, ALPN and ticket/psk extensions, so JA3/JA4
# differ across populations. No renegotiation_info or ec_point_formats (a pure 1.3 client sends neither).
_TLS13_PROFILES = {
    "chrome": dict(suites=(0x1301, 0x1302, 0x1303), grease=True, shuffle=True, versions=(0x0304, 0x0303),
                   exts=(0, 5, 10, 13, 16, 18, 23, 27, 35, 43, 45, 50, 51), alpn=b"\x02h2\x08http/1.1",
                   sigalgs=(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)),
    "safari": dict(suites=(0x1301, 0x1302, 0x1303), grease=True, shuffle=False, versions=(0x0304, 0x0303),
                   exts=(0, 23, 5, 10, 13, 16, 18, 50, 51, 45, 43, 27), alpn=b"\x02h2\x08http/1.1",
                   sigalgs=(0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0501, 0x0806, 0x0601)),
    "firefox": dict(suites=(0x1301, 0x1303, 0x1302), grease=False, shuffle=False, versions=(0x0304, 0x0303),
                    exts=(0, 23, 10, 35, 16, 5, 34, 51, 43, 13, 45, 28), alpn=b"\x02h2\x08http/1.1",
                    sigalgs=(0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601)),
    "appliance": dict(suites=(0x1302, 0x1301), grease=False, shuffle=False, versions=(0x0304,),
                      exts=(0, 10, 13, 43, 51), alpn=None, sigalgs=(0x0804, 0x0805, 0x0403, 0x0503)),
    "agent": dict(suites=(0x1301, 0x1302, 0x1303), grease=False, shuffle=False, versions=(0x0304, 0x0303),
                  exts=(0, 10, 13, 16, 43, 45, 51), alpn=b"\x08http/1.1",
                  sigalgs=(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)),
}


def tls13_posture(sni: str, offer_groups, select_group, client_random=None, profile=None):
    """Return [(from_client, bytes), ...] for a TLS 1.3 handshake.

    offer_groups: list of group codepoints the client advertises in supported_groups (order kept).
    select_group: the codepoint the server echoes in its key_share (must be one the client
                  sent a key_share for). the platform flags the session post-quantum iff this is a
                  hybrid/PQC group. App data after this is opaque.
    profile: a key of _TLS13_PROFILES; None keeps the single generic hello of the first version.
    """
    from .core import rng as _random
    crand = client_random or os.urandom(32)
    srand = os.urandom(32)
    sid = os.urandom(32)
    prof = _TLS13_PROFILES.get(profile)
    g_pick = (lambda: _random.choice(GREASE)) if prof and prof["grease"] else (lambda: None)
    # the client sends real-sized key_shares for its PQC offer (if any) and for x25519
    share_groups = [g for g in offer_groups if g in (0x11ec, 0x11eb, 0x6399)][:1] + [0x001d]
    ks_list = b""
    if prof and prof["grease"]:
        ks_list += struct.pack("!HH", g_pick(), 1) + b"\x00"
    ks_list += b"".join(struct.pack("!HH", g, _KS_CLIENT[g]) + os.urandom(_KS_CLIENT[g]) for g in share_groups)
    groups_all = ([g_pick()] if prof and prof["grease"] else []) + list(offer_groups)
    groups_bytes = b"".join(struct.pack("!H", g) for g in groups_all)
    sni_data = struct.pack("!H", len(sni) + 3) + b"\x00" + struct.pack("!H", len(sni)) + sni.encode()
    if not prof:
        alpn_list = b"\x02h2\x08http/1.1"
        exts = (
            _ext(0, sni_data) +
            _ext(10, struct.pack("!H", len(groups_bytes)) + groups_bytes) +
            _ext(13, struct.pack("!H", len(_SIGALGS_13) * 2) + b"".join(struct.pack("!H", a) for a in _SIGALGS_13)) +
            _ext(43, b"\x02\x03\x04") +                       # supported_versions: TLS 1.3
            _ext(51, struct.pack("!H", len(ks_list)) + ks_list) +   # key_share
            _ext(16, struct.pack("!H", len(alpn_list)) + alpn_list) +
            _ext(0x000b, b"\x01\x00") +                        # ec_point_formats: uncompressed
            _ext(0xff01, b"\x00")                               # renegotiation_info
        )
        suites = b"".join(struct.pack("!H", c) for c in TLS13_SUITES)
    else:
        sig = lambda al: struct.pack("!H", len(al) * 2) + b"".join(struct.pack("!H", a) for a in al)
        vers = list(prof["versions"])
        if prof["grease"]:
            vers.insert(0, g_pick())
        build = {
            0: lambda: _ext(0, sni_data),
            5: lambda: _ext(5, b"\x01\x00\x00\x00\x00"),
            10: lambda: _ext(10, struct.pack("!H", len(groups_bytes)) + groups_bytes),
            13: lambda: _ext(13, sig(prof["sigalgs"])),
            16: lambda: _ext(16, struct.pack("!H", len(prof["alpn"])) + prof["alpn"]),
            18: lambda: _ext(18, b""),
            23: lambda: _ext(23, b""),
            27: lambda: _ext(27, b"\x02\x00\x02"),
            28: lambda: _ext(28, struct.pack("!H", 0x4001)),
            34: lambda: _ext(34, sig((0x0403, 0x0503, 0x0603, 0x0203))),
            35: lambda: _ext(35, b""),
            43: lambda: _ext(43, bytes([len(vers) * 2]) + b"".join(struct.pack("!H", v) for v in vers)),
            45: lambda: _ext(45, b"\x01\x01"),
            50: lambda: _ext(50, sig(prof["sigalgs"][:6])),
            51: lambda: _ext(51, struct.pack("!H", len(ks_list)) + ks_list),
        }
        order = [e for e in prof["exts"] if e != 16 or prof["alpn"]]
        if prof["shuffle"]:
            _random.shuffle(order)
        parts = [build[e]() for e in order]
        if prof["grease"]:
            parts.insert(0, _ext(g_pick(), b""))
            parts.append(_ext(g_pick(), b"\x00"))
        exts = b"".join(parts)
        cs = ([g_pick()] if prof["grease"] else []) + list(prof["suites"])
        suites = b"".join(struct.pack("!H", c) for c in cs)
    ch = VER + crand + bytes([32]) + sid + struct.pack("!H", len(suites)) + suites + b"\x01\x00" + struct.pack("!H", len(exts)) + exts
    flight1 = _rec(22, _hs(1, ch))
    # ServerHello: selected cipher 0x1301, extensions = supported_versions + key_share(selected)
    s_ks = struct.pack("!HH", select_group, _KS_SERVER[select_group]) + os.urandom(_KS_SERVER[select_group])
    s_exts = _ext(43, b"\x03\x04") + _ext(51, s_ks)
    sh = VER + srand + bytes([32]) + sid + struct.pack("!H", 0x1301) + b"\x00" + struct.pack("!H", len(s_exts)) + s_exts
    # ServerHello, then CCS, then opaque encrypted {EncryptedExtensions, Certificate, Finished}
    flight2 = _rec(22, _hs(2, sh)) + _rec(20, b"\x01") + _rec(23, os.urandom(2800))
    # client CCS + opaque encrypted Finished
    flight3 = _rec(20, b"\x01") + _rec(23, os.urandom(52))
    return [(True, flight1), (False, flight2), (True, flight3)]


def tls13_app_data(from_client: bool, n: int) -> bytes:
    return _rec(23, os.urandom(n))


def _hs(htype: int, body: bytes) -> bytes:
    return bytes([htype]) + len(body).to_bytes(3, "big") + body


# Client fingerprint profiles. The values are the JA3 inputs: offered cipher suites, the
# extension list in the order the client sends it, supported groups, and signature algorithms.
# They are shaped after what the real clients send, not copied byte-for-byte — the point is
# that the capture contains several distinct fingerprints rather than one, so a JA3-based view
# separates a browser from an agent from an appliance.
#
# CIPHER must appear in every list: the server picks it, and the key schedule depends on it.
# Suite codepoints used below (RFC 5246/5289/7905): 0xC02F ECDHE-RSA-AES128-GCM, 0xC030 ECDHE-RSA-AES256-GCM,
# 0xC02B/0xC02C ECDHE-ECDSA-GCM, 0xCCA8/0xCCA9 ChaCha20, 0x009C RSA-AES128-GCM (CIPHER), 0x009D RSA-AES256-GCM,
# 0xC013/0xC014 ECDHE-RSA-CBC-SHA, 0x002F/0x0035 RSA-CBC-SHA. TLS 1.3 suites (0x1301..) appear in browser hellos.
# Every list offers each codepoint once and offers CIPHER and 0xC02F, because the server picks one of them and the
# key schedule depends on the pick. "grease" profiles put RFC 8701 GREASE values in suites, extensions, groups and
# versions (random per session, ignored by JA3), the way Chromium does.
GREASE = (0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA)
CLIENT_PROFILES = {
    "chrome": dict(
        suites=(0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, CIPHER, 0x009D, 0x002F, 0x0035),
        exts=(0, 0xFF01, 23, 5, 10, 11, 35, 16, 18, 13, 51, 45, 43),
        groups=(0x001D, 0x0017, 0x0018), versions=(0x0304, 0x0303), grease=True,
        sigalgs=(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)),
    "firefox": dict(
        suites=(0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C, 0xC030, 0xC013, 0xC014, CIPHER, 0x009D, 0x002F, 0x0035),
        exts=(0, 23, 0xFF01, 10, 11, 35, 16, 5, 51, 43, 13, 45),
        groups=(0x001D, 0x0017, 0x0018, 0x0019), versions=(0x0304, 0x0303),
        sigalgs=(0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501)),
    "edge": dict(
        suites=(0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xC030, 0xC02F, 0xCCA9, 0xCCA8, CIPHER, 0x009D, 0xC014, 0xC013),
        exts=(0, 0xFF01, 23, 5, 10, 11, 35, 16, 18, 13, 51, 45, 43),
        groups=(0x001D, 0x0017, 0x0018), versions=(0x0304, 0x0303), grease=True,
        sigalgs=(0x0403, 0x0503, 0x0603, 0x0401, 0x0501, 0x0601)),
    "safari": dict(
        suites=(0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xC030, 0xC02F, 0xCCA9, 0xCCA8, CIPHER, 0x009D, 0xC014, 0xC013),
        exts=(0, 0xFF01, 23, 10, 11, 16, 5, 13, 18, 51, 45, 43),
        groups=(0x001D, 0x0017, 0x0018, 0x0019), versions=(0x0304, 0x0303),
        sigalgs=(0x0403, 0x0804, 0x0401, 0x0503, 0x0203)),
    # Windows system components: WinHTTP/schannel, a much shorter hello than any browser
    "winhttp": dict(
        suites=(0xC030, 0xC02F, 0xC02C, 0xC02B, CIPHER, 0x009D),
        exts=(0, 10, 11, 13, 23, 0xFF01),
        groups=(0x001D, 0x0017, 0x0018),
        sigalgs=(0x0403, 0x0503, 0x0603, 0x0401, 0x0501)),
    # Appliances, phones, boards: short list, no ALPN games
    "embedded": dict(
        suites=(0xC02F, 0xC030, CIPHER),
        exts=(0, 10, 11, 13, 16),
        groups=(0x0017, 0x0018),
        sigalgs=(0x0401, 0x0403, 0x0601)),
    # scripts and agents linked against OpenSSL
    "openssl": dict(
        suites=(0xC02F, 0xC02B, 0xC030, 0xC02C, CIPHER, 0x009D),
        exts=(0, 11, 10, 23, 13, 16, 0xFF01),
        groups=(0x001D, 0x0017, 0x001E, 0x0019, 0x0018),
        sigalgs=(0x0403, 0x0503, 0x0603, 0x0804, 0x0401)),
    # a Go net/http client (the language many implants and agents are written in): TLS 1.3 offer, ChaCha, no browser extras
    "go": dict(
        suites=(0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC009, 0xC013, 0xC00A, 0xC014, CIPHER, 0x009D, 0x002F, 0x0035),
        exts=(0, 5, 10, 11, 13, 23, 0xFF01, 43, 51),
        groups=(0x001D, 0x0017, 0x0018, 0x0019), versions=(0x0304, 0x0303),
        sigalgs=(0x0804, 0x0805, 0x0806, 0x0403, 0x0503, 0x0603, 0x0401, 0x0501, 0x0601)),
}

# Key exchange for the TLS 1.2 sessions. Real servers prefer ECDHE (forward secrecy), and TlsSession(kex="ecdhe") builds a
# genuine ECDHE-RSA handshake (still decryptable in Wireshark with the key log). The default stays static RSA for every
# host because the documented replay route (REPLAY-tcpreplay.md section 4) decrypts the HTTPS with the exported server
# certificates and private keys, which cannot read an ECDHE session. Flipping EXTERNAL_KEX to "ecdhe" makes the
# internet side forward-secret; that trades away sensor-side decryption, so it is a deployment choice.
EXTERNAL_KEX = "rsa"
INTERNAL_KEX = "rsa"


class TlsSession:
    """
    Build the byte streams for one TLS 1.2 connection. After handshake(),
    use client_data()/server_data() to get encrypted records for application
    payloads; feed the returned bytes into a TcpSession.
    """

    def __init__(self, pki: PKI, sni: str, keylog, client_random=None, alpn=b"http/1.1",
                 profile="chrome", kex=None, selfsigned=False):
        self.pki = pki
        self.sni = sni
        self.keylog = keylog
        self.alpn = alpn
        # Which client is speaking. JA3 is computed over the offered cipher list, extension
        # list, groups and EC point formats — so varying those per device class is what gives
        # the capture more than one fingerprint. Every profile still offers CIPHER, because the
        # server selects it and the rest of the handshake (and the key log) depends on it.
        self.profile = profile if profile in CLIENT_PROFILES else "chrome"
        self.crand = client_random or os.urandom(32)
        self.srand = os.urandom(32)
        # server key exchange: ECDHE-RSA for external names (and any host the caller says), static RSA inside
        if kex is None:
            kex = INTERNAL_KEX if PKI.is_internal(sni) else EXTERNAL_KEX
        prof = CLIENT_PROFILES[self.profile]
        self.kex = "ecdhe" if kex == "ecdhe" and 0xC02F in prof["suites"] else "rsa"
        self.selfsigned = selfsigned     # RDP and many appliances present a self-signed certificate
        self.hs_msgs = b""
        self.cseq = 0
        self.sseq = 0

    def handshake(self):
        """Returns list of (from_client: bool, bytes) flights."""
        if self.selfsigned:
            key, leaf_der = self.pki.bad_cert_for(self.sni, "selfsigned")
            chain_ders = (leaf_der,)
        else:
            key, leaf_der, ca_der = self.pki.cert_for(self.sni)
            chain_ders = (leaf_der, ca_der)
        prof = CLIENT_PROFILES[self.profile]
        # ---- ClientHello
        sni_ext = struct.pack("!HH", 0, len(self.sni) + 5) + struct.pack("!HBH", len(self.sni) + 3, 0, len(self.sni)) + self.sni.encode()
        groups = struct.pack("!" + "H" * len(prof["groups"]), *prof["groups"])
        groups_ext = struct.pack("!HHH", 10, len(groups) + 2, len(groups)) + groups
        sigalgs = struct.pack("!" + "H" * len(prof["sigalgs"]), *prof["sigalgs"])
        sigalgs_ext = struct.pack("!HHH", 13, len(sigalgs) + 2, len(sigalgs)) + sigalgs
        alpn_list = bytes([len(self.alpn)]) + self.alpn
        alpn_ext = struct.pack("!HHH", 16, len(alpn_list) + 2, len(alpn_list)) + alpn_list if self.alpn else b""
        ecpf_ext = struct.pack("!HHBB", 11, 2, 1, 0)
        ems_ext = struct.pack("!HH", 23, 0)
        renego_ext = struct.pack("!HHB", 0xFF01, 1, 0)
        sct_ext = struct.pack("!HH", 18, 0)
        status_ext = struct.pack("!HHBHH", 5, 5, 1, 0, 0)
        grease = prof.get("grease")
        g = [GREASE[int.from_bytes(os.urandom(1), "big") % 16] for _ in range(4)] if grease else []
        if grease:
            groups = struct.pack("!H", g[0]) + groups
            groups_ext = struct.pack("!HHH", 10, len(groups) + 2, len(groups)) + groups
        vers = ((g[1],) if grease else ()) + tuple(prof.get("versions", ()))
        ver_ext = struct.pack("!HHB", 43, 1 + 2 * len(vers), 2 * len(vers)) + b"".join(struct.pack("!H", v) for v in vers) if vers else b""
        ks = (struct.pack("!HH", g[0], 1) + b"\x00" if grease else b"") + struct.pack("!HH", 0x001D, 32) + os.urandom(32)
        ks_ext = struct.pack("!HHH", 51, len(ks) + 2, len(ks)) + ks
        psk_ext = struct.pack("!HHBB", 45, 2, 1, 1)
        ticket_ext = struct.pack("!HH", 35, 0)
        avail = {0: sni_ext, 11: ecpf_ext, 10: groups_ext, 13: sigalgs_ext, 16: alpn_ext,
                 23: ems_ext, 0xFF01: renego_ext, 18: sct_ext, 5: status_ext, 43: ver_ext, 51: ks_ext,
                 45: psk_ext, 35: ticket_ext}
        exts = b"".join(avail[e] for e in prof["exts"] if avail.get(e))
        if grease:
            exts = struct.pack("!HH", g[2], 0) + exts + struct.pack("!HHB", g[3], 1, 0)
        suite_list = ((g[1],) if grease else ()) + tuple(prof["suites"])
        suites = struct.pack("!" + "H" * len(suite_list), *suite_list)
        sid = os.urandom(32)
        ch = VER + self.crand + bytes([32]) + sid + struct.pack("!H", len(suites)) + suites + b"\x01\x00" + struct.pack("!H", len(exts)) + exts
        ch_hs = _hs(1, ch)
        self.hs_msgs += ch_hs
        flight1 = _rec(22, ch_hs)
        # ---- ServerHello + Certificate + ServerHelloDone
        alpn_sel = struct.pack("!HHH", 16, len(alpn_list) + 2, len(alpn_list)) + alpn_list if self.alpn else b""
        s_exts = alpn_sel + struct.pack("!HHB", 0xFF01, 1, 0) + struct.pack("!HH", 23, 0)
        cipher = 0xC02F if self.kex == "ecdhe" else CIPHER
        sh = VER + self.srand + bytes([32]) + sid + struct.pack("!H", cipher) + b"\x00" + struct.pack("!H", len(s_exts)) + s_exts
        sh_hs = _hs(2, sh)
        certs = b"".join(len(c).to_bytes(3, "big") + c for c in chain_ders)
        cert_hs = _hs(11, len(certs).to_bytes(3, "big") + certs)
        shd_hs = _hs(14, b"")
        if self.kex == "ecdhe":
            from cryptography.hazmat.primitives.asymmetric import ec, x25519
            if 0x001D in prof["groups"]:
                curve, sk = 0x001D, x25519.X25519PrivateKey.generate()
                spub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                ck = x25519.X25519PrivateKey.generate()
                cpub = ck.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                premaster = sk.exchange(ck.public_key())
            else:
                curve, sk = 0x0017, ec.generate_private_key(ec.SECP256R1())
                ck = ec.generate_private_key(ec.SECP256R1())
                fmt = (serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                spub, cpub = sk.public_key().public_bytes(*fmt), ck.public_key().public_bytes(*fmt)
                premaster = sk.exchange(ec.ECDH(), ck.public_key())
            params = b"\x03" + struct.pack("!H", curve) + bytes([len(spub)]) + spub
            sig = key.sign(self.crand + self.srand + params, padding.PKCS1v15(), hashes.SHA256())
            ske_hs = _hs(12, params + struct.pack("!HH", 0x0401, len(sig)) + sig)
            self.hs_msgs += sh_hs + cert_hs + ske_hs + shd_hs
            flight2 = _rec(22, sh_hs) + _rec(22, cert_hs) + _rec(22, ske_hs) + _rec(22, shd_hs)
            cke_hs = _hs(16, bytes([len(cpub)]) + cpub)
        else:
            self.hs_msgs += sh_hs + cert_hs + shd_hs
            flight2 = _rec(22, sh_hs) + _rec(22, cert_hs) + _rec(22, shd_hs)
            premaster = VER + os.urandom(46)
            enc_pm = key.public_key().encrypt(premaster, padding.PKCS1v15())
            cke_hs = _hs(16, struct.pack("!H", len(enc_pm)) + enc_pm)
        self.hs_msgs += cke_hs
        # extended master secret (RFC 7627) since both sides offered it
        session_hash = hashlib.sha256(self.hs_msgs).digest()
        self.master = prf(premaster, b"extended master secret", session_hash, 48)
        kb = prf(self.master, b"key expansion", self.srand + self.crand, 40)
        self.ckey, self.skey = AESGCM(kb[0:16]), AESGCM(kb[16:32])
        self.civ, self.siv = kb[32:36], kb[36:40]
        self.keylog.write(f"CLIENT_RANDOM {self.crand.hex()} {self.master.hex()}\n")
        c_verify = prf(self.master, b"client finished", hashlib.sha256(self.hs_msgs).digest(), 12)
        c_fin_hs = _hs(20, c_verify)
        self.hs_msgs += c_fin_hs
        flight3 = _rec(22, cke_hs) + _rec(20, b"\x01") + self._enc(True, 22, c_fin_hs)
        # ---- server CCS + Finished
        s_verify = prf(self.master, b"server finished", hashlib.sha256(self.hs_msgs).digest(), 12)
        s_fin_hs = _hs(20, s_verify)
        flight4 = _rec(20, b"\x01") + self._enc(False, 22, s_fin_hs)
        return [(True, flight1), (False, flight2), (True, flight3), (False, flight4)]

    def _enc(self, from_client: bool, ctype: int, plaintext: bytes) -> bytes:
        if from_client:
            seqn, key, iv = self.cseq, self.ckey, self.civ
            self.cseq += 1
        else:
            seqn, key, iv = self.sseq, self.skey, self.siv
            self.sseq += 1
        explicit = struct.pack("!Q", seqn)
        nonce = iv + explicit
        aad = explicit + bytes([ctype]) + VER + struct.pack("!H", len(plaintext))
        ct = key.encrypt(nonce, plaintext, aad)
        body = explicit + ct
        return bytes([ctype]) + VER + struct.pack("!H", len(body)) + body

    def app_data(self, from_client: bool, data: bytes) -> bytes:
        out = []
        for i in range(0, len(data), 16384):
            out.append(self._enc(from_client, 23, data[i:i + 16384]))
        return b"".join(out)

    def close_notify(self, from_client=True) -> bytes:
        return self._enc(from_client, 21, b"\x01\x00")
