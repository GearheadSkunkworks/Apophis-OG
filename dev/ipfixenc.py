"""IPFIX (RFC 7011) and NetFlow v9 (RFC 3954) message encoder, stdlib only.

Pure functions over plain records; no capture or build knowledge. A record is a dict:
  src, dst (IPv4 or IPv6 text, same family), sport, dport, proto, pkts, octets,
  start_ms, end_ms (epoch milliseconds), flags (TCP flag bits), in_if, out_if,
  vlan (int or None: a vlanId field is sent only when set), tag (str or None).

messages(records, version, ...) yields (export_time_seconds, message_bytes). Records are sent in the
order given (callers sort by end time so the export time never goes backwards). Templates are sent in
the first message, whenever a template is first needed, and again every `refresh_msgs` messages or
`refresh_s` seconds of export time. A message never exceeds mtu - 28 bytes (IPv4 + UDP headers).

IPFIX: the sequence number is the count of data records sent before the message (template records do
not count); sets are not padded; the scenario tag is the enterprise-specific element 1 of PEN 32473
(the RFC 5612 documentation number: not a registered element), a variable-length string. NetFlow v9:
the sequence number counts export packets, flowsets are padded to 4 bytes, times are 32-bit
milliseconds since a synthetic boot time (`boot_ms`), and the tag is not exported (CSV only).
"""
import socket
import struct

IPFIX, NF9 = 10, 9
TAG_PEN, TAG_ELEMENT, TAG_MAX = 32473, 1, 512        # PEN 32473 = documentation use (RFC 5612)
_VARLEN = 0xFFFF
_BASE_ID = 256                                       # data set ids: 256 + (family6 * 2 + has_vlan)
_KEYS = ((False, False), (False, True), (True, False), (True, True))


def _fields(v6, vlan, version):
    """Template field list: (element id, length, enterprise number or None)."""
    f = [(27, 16, None), (28, 16, None)] if v6 else [(8, 4, None), (12, 4, None)]
    f += [(7, 2, None), (11, 2, None), (4, 1, None), (6, 2 if version == IPFIX else 1, None),
          (2, 8, None), (1, 8, None)]
    f += [(152, 8, None), (153, 8, None)] if version == IPFIX else [(22, 4, None), (21, 4, None)]
    f += [(10, 4, None), (14, 4, None)]
    if vlan:
        f.append((58, 2, None))
    if version == IPFIX:
        f.append((TAG_ELEMENT, _VARLEN, TAG_PEN))
    return f


def template_id(v6, vlan):
    return _BASE_ID + (2 if v6 else 0) + (1 if vlan else 0)


def _template_record(v6, vlan, version):
    fs = _fields(v6, vlan, version)
    out = [struct.pack("!HH", template_id(v6, vlan), len(fs))]
    for eid, ln, pen in fs:
        out.append(struct.pack("!HHI", eid | 0x8000, ln, pen) if pen is not None else struct.pack("!HH", eid, ln))
    return b"".join(out)


def _tag_bytes(tag):
    b = (tag or "").encode("utf-8")[:TAG_MAX].decode("utf-8", "ignore").encode("utf-8")   # never cut a character in half
    return (bytes([len(b)]) if len(b) < 255 else b"\xff" + struct.pack("!H", len(b))) + b


def _data_record(r, v6, version, boot_ms):
    af = socket.AF_INET6 if v6 else socket.AF_INET
    p = [socket.inet_pton(af, r["src"]), socket.inet_pton(af, r["dst"]),
         struct.pack("!HHB", r["sport"], r["dport"], r["proto"]),
         struct.pack("!H", r["flags"] & 0xFFFF) if version == IPFIX else struct.pack("!B", r["flags"] & 0xFF),
         struct.pack("!QQ", r["pkts"], r["octets"])]
    if version == IPFIX:
        p.append(struct.pack("!QQ", r["start_ms"], r["end_ms"]))
    else:
        p.append(struct.pack("!II", (r["start_ms"] - boot_ms) & 0xFFFFFFFF, (r["end_ms"] - boot_ms) & 0xFFFFFFFF))
    p.append(struct.pack("!II", r["in_if"], r["out_if"]))
    if r.get("vlan") is not None:
        p.append(struct.pack("!H", r["vlan"]))
    if version == IPFIX:
        p.append(_tag_bytes(r.get("tag")))
    return b"".join(p)


def messages(records, version=IPFIX, mtu=1500, refresh_msgs=20, refresh_s=600.0, domain=1, boot_ms=0):
    """Yield (export_time_s, bytes) for the records. See the module docstring."""
    if version not in (IPFIX, NF9):
        raise ValueError("version must be 10 (IPFIX) or 9 (NetFlow v9)")
    maxlen = mtu - 28
    hdr = 16 if version == IPFIX else 20
    tmpl = {k: _template_record(k[0], k[1], version) for k in _KEYS}
    announced = []                                     # template keys already sent, in first-use order
    st = {"seq": 0, "since": None, "t0": 0.0}          # since = messages sent since the last template refresh

    def pad(n):
        return (-n) % 4 if version == NF9 else 0

    def size(tk, data):
        t = sum(len(tmpl[k]) for k in tk)
        n = hdr + (4 + t if t else 0)
        for bs in data.values():
            raw = sum(len(b) for b in bs)
            n += 4 + raw + pad(raw)
        return n

    def flush(tk, data, nrec, t_s):
        sets, count = [], len(tk)
        if tk:
            body = b"".join(tmpl[k] for k in tk)
            sets.append(struct.pack("!HH", 2 if version == IPFIX else 0, 4 + len(body)) + body)
        for k, bs in data.items():
            raw = b"".join(bs)
            raw += b"\0" * pad(len(raw))
            sets.append(struct.pack("!HH", template_id(*k), 4 + len(raw)) + raw)
            count += len(bs)
        body = b"".join(sets)
        if version == IPFIX:
            head = struct.pack("!HHIII", IPFIX, hdr + len(body), int(t_s) & 0xFFFFFFFF, st["seq"] & 0xFFFFFFFF, domain)
            st["seq"] += nrec
        else:
            head = struct.pack("!HHIIII", NF9, count, (int(t_s * 1000) - boot_ms) & 0xFFFFFFFF, int(t_s) & 0xFFFFFFFF,
                               st["seq"] & 0xFFFFFFFF, domain)
            st["seq"] += 1
        st["since"] += 1
        return t_s, head + body

    cur = None                                         # [template keys, {key: [bodies]}, record count, last end time]
    for r in records:
        k = (":" in r["src"], r.get("vlan") is not None)
        body = _data_record(r, k[0], version, boot_ms)
        t = r["end_ms"] / 1000.0
        for attempt in (0, 1):                         # attempt 1 = the same record in a fresh, empty message
            if cur is None:
                refresh = st["since"] is None or st["since"] >= refresh_msgs or t - st["t0"] >= refresh_s
                cur = [list(announced) if refresh else [], {}, 0, t]
                if refresh:
                    st["since"], st["t0"] = 0, t
            tk = cur[0] if k in announced else cur[0] + [k]
            data = {**cur[1], k: cur[1].get(k, []) + [body]}
            if size(tk, data) <= maxlen:
                if k not in announced:
                    announced.append(k)
                cur[0], cur[1] = tk, data
                cur[2] += 1
                cur[3] = max(cur[3], t)
                break
            if attempt or cur[2] == 0:
                raise ValueError("one record does not fit in mtu %d" % mtu)
            yield flush(*cur)
            cur = None
    if cur is not None and cur[2]:
        yield flush(*cur)
