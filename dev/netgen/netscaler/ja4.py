"""JA4 / JA4S / JA4H / JA4X509 / HASSH computation (FoxIO JA4 spec).

Self-contained, stdlib-only. Used by this module in two ways:

  * to *verify* in ``self_test()`` that the bytes we actually put on the wire recompute to the
    fingerprints the incident spec (§11) calls for -- but ONLY the components that are
    mathematically reproducible from the spec (see the honesty notes below);
  * as the single source of truth for the fingerprint prefixes the crafted ClientHello / KEXINIT
    are built to satisfy.

What is and is not reproducible from the spec (the spec gives several fingerprints only as their
output hash, and SHA-256 / MD5 cannot be inverted):

  * JA4_a / JA4H_a / JA4S_a prefixes (protocol, TLS version, SNI flag, cipher & extension counts,
    ALPN): fully reproducible -- we build the ClientHello to carry exactly those counts/flags.
  * JA4_b (sorted cipher-suite hash): reproducible ONLY where the spec gives the raw cipher list
    (the workforce client). The implant's 91-cipher list is not given, so its JA4_b is not.
  * JA4_c (sorted extensions + signature_algorithms hash): NOT reproducible for anyone -- the spec
    never lists the extensions or sig-algs, only the hash.
  * HASSH / HASSH-server: a property of the SSH *software version*. We rebuild the real OpenSSH
    9.6 default KEXINIT name-lists; the MD5 of those lists is the proof (asserted in self_test).
  * JA4S_b (server extension hash): reproducible iff a standard TLS 1.3 ServerHello (2 extensions)
    hashes to the spec value -- verified empirically, see self_test.
  * Cert SHA1/SHA256 and literal JA4H cookie hashes: NOT reproducible (no original key bytes / no
    cookie preimage). The *relational* cookie signal (same cookie, two clients) IS reproduced.
"""
import hashlib


def _is_grease(v: int) -> bool:
    """TLS GREASE values (RFC 8701): 0x0a0a, 0x1a1a, ... 0xfafa. Excluded from JA4."""
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def _h12(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def _hx(vals):
    return ["%04x" % v for v in vals if not _is_grease(v)]


def ja4(tls_version="13", sni=True, ciphers=(), extensions=(), sigalgs=(), alpn=None):
    """Compute a JA4 TLS client fingerprint.

    ciphers / extensions / sigalgs: lists of integer codepoints as sent in the ClientHello.
    alpn: the first ALPN protocol string (e.g. "http/1.1", "h2") or None.
    """
    c = _hx(ciphers)
    # extension COUNT includes SNI and ALPN; the JA4_c HASH excludes them.
    e_all = _hx(extensions)
    sni_c = "d" if sni else "i"
    if alpn:
        a = (alpn[0] + alpn[-1]) if len(alpn) >= 2 else (alpn + alpn)
    else:
        a = "00"
    a_part = "t" + tls_version + sni_c + "%02d" % min(99, len(c)) + "%02d" % min(99, len(e_all)) + a
    b_part = _h12(",".join(sorted(c)))
    e_no = sorted(x for x in e_all if x not in ("0000", "0010"))
    sa = _hx(sigalgs)
    c_in = ",".join(e_no) + ("_" + ",".join(sa) if sa else "")
    c_part = _h12(c_in)
    return "%s_%s_%s" % (a_part, b_part, c_part)


def ja4_b(ciphers):
    """Just the sorted-cipher-suite hash component (the piece the workforce vector pins down)."""
    return _h12(",".join(sorted(_hx(ciphers))))


def ja4s(tls_version="13", ext_codepoints=(), cipher=0x1302, alpn=None):
    """Server fingerprint from the ServerHello: version, extension count, chosen cipher, ALPN,
    then the hash of the server extensions (in order, GREASE removed)."""
    e = _hx(ext_codepoints)
    a = (alpn[0] + alpn[-1]) if alpn and len(alpn) >= 2 else ("00" if not alpn else alpn + alpn)
    a_part = "t" + tls_version + "%02d" % min(99, len(e)) + a
    return "%s_%04x_%s" % (a_part, cipher, _h12(",".join(e)))


def hassh(kex, enc_c2s, mac_c2s, comp_c2s):
    """HASSH (client) = md5(kex;enc;mac;comp), each a comma-joined KEXINIT name-list."""
    # lint-ok: the HASSH fingerprint is defined as an MD5, an identifier and not a security control
    return hashlib.md5((";".join([kex, enc_c2s, mac_c2s, comp_c2s])).encode(), usedforsecurity=False).hexdigest()


def ja4h_a(method="ge", version="11", cookie=True, referer=True, nhdr=0, lang="en-US"):
    """JA4H_a: method(2) + version(2) + cookie?(c/n) + referer?(r/n) + header count(2) +
    first 4 chars of the primary Accept-Language (lowercased, '-' stripped, 0-padded)."""
    lv = (lang.lower().replace("-", "")[:4]).ljust(4, "0") if lang else "0000"
    return "%s%s%s%s%02d%s" % (method[:2].lower(), version, "c" if cookie else "n",
                               "r" if referer else "n", min(99, nhdr), lv)
