"""Minimal DER/BER encoders for Kerberos, LDAP and SNMP payloads."""
import time


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def tlv_tag(tagbytes: bytes, content: bytes) -> bytes:
    return tagbytes + _len(len(content)) + content


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def set_(*items: bytes) -> bytes:
    return tlv(0x31, b"".join(items))


def integer(v: int) -> bytes:
    if v == 0:
        return b"\x02\x01\x00"
    n = (v.bit_length() + 8) // 8
    return tlv(0x02, v.to_bytes(n, "big", signed=True))


def octets(b: bytes) -> bytes:
    return tlv(0x04, b)


def gen_string(s: str) -> bytes:
    return tlv(0x1B, s.encode())


def bitstring(b: bytes, unused=0) -> bytes:
    return tlv(0x03, bytes([unused]) + b)


def gen_time(ts: float) -> bytes:
    return tlv(0x18, time.strftime("%Y%m%d%H%M%SZ", time.gmtime(ts)).encode())


def ctx(n: int, content: bytes) -> bytes:
    """[n] EXPLICIT constructed context tag."""
    return tlv(0xA0 | n, content)


def app(n: int, content: bytes) -> bytes:
    """[APPLICATION n] constructed."""
    return tlv(0x60 | n, content)


def boolean(v: bool) -> bytes:
    return b"\x01\x01\xff" if v else b"\x01\x01\x00"


def enum(v: int) -> bytes:
    return tlv(0x0A, bytes([v]))


def null() -> bytes:
    return b"\x05\x00"


def oid(s: str) -> bytes:
    parts = [int(p) for p in s.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p < 0x80:
            out += bytes([p])
        else:
            chunks = []
            while p:
                chunks.append(p & 0x7F)
                p >>= 7
            chunks.reverse()
            out += bytes([c | 0x80 for c in chunks[:-1]] + [chunks[-1]])
    return tlv(0x06, out)


# SNMP-specific application tags
def snmp_counter32(v): return tlv(0x41, v.to_bytes(4, "big"))
def snmp_gauge32(v): return tlv(0x42, v.to_bytes(4, "big"))
def snmp_timeticks(v): return tlv(0x43, v.to_bytes(4, "big"))
def snmp_counter64(v): return tlv(0x46, v.to_bytes(8, "big"))
def snmp_ipaddr(b): return tlv(0x40, b)
# context-specific primitive exception values (RFC 3416 2.4.2): [0] noSuchObject, [1]
# noSuchInstance, [2] endOfMibView -- all zero-length. A real walk ends in one of these,
# most commonly endOfMibView once it steps off the end of the requested subtree.
def snmp_no_such_object(): return b"\x80\x00"
def snmp_no_such_instance(): return b"\x81\x00"
def snmp_end_of_mib_view(): return b"\x82\x00"
