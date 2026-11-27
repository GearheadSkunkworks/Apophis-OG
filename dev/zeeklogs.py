"""Zeek-style conn.log and dns.log writers (stdlib only, no netgen import).

"Zeek-style" means: the standard Zeek column names, types and TSV header block (or JSON lines),
filled by this module's own rules. It is NOT claimed to match a real Zeek run; that claim waits
for a reference run. Every derived field below is approximate and says so.

conn.log (write_conn_log) consumes flow records (plain dicts; see CONN_KEYS). Derivations:
  uid        "C" + 17 base62 chars of sha1(proto, endpoints, start): stable for the same flow.
  service    by the responder port only (SERVICES, overridable via rules["service_ports"]); set only
             when the responder answered (resp_pkts > 0). Not payload-confirmed.
  conn_state from the OR of TCP flags per direction (flags_orig / flags_resp: int bitmask or a
             letter string such as "SA"), not the flag sequence, which the flow record does not keep:
      SYN from orig, no responder packets      S0 (SH if orig also FIN, RSTOS0 if orig also RST)
      SYN from orig, responder RST without SYN REJ
      SYN + responder SYN-ACK (established)    SF if both sides FIN; else RSTO / RSTR (orig / resp
                                               RST); else S2 (only orig FIN) / S3 (only resp FIN)
                                               / S1 (open)
      no orig SYN, responder SYN-ACK           SHR (RSTRH if responder also RST)
      anything else (mid-stream, one-way)      OTH
      UDP / ICMP: SF when the responder sent anything, else S0.
  history    letters in a fixed order, upper case = originator, lower case = responder:
             S/h (SYN, SYN-ACK), A (ACK), D/d (payload), F/f (FIN), R/r (RST). Real Zeek records
             the order of events and repeats; this string records presence only.
  orig_bytes / resp_bytes are L4 payload bytes, orig_ip_bytes / resp_ip_bytes are IP-level;
  a side with no packets logs "-" (unset) for its payload bytes.
  local_orig / local_resp are unset unless rules["local_nets"] (CIDR strings) is given.

dns.log (write_dns_log) reads only the pcap (pcapprofile.iter_frames) and parses UDP/53 over
IPv4 and IPv6 (no fragments, no IPv6 extension headers; TCP/53 is not parsed). One line per
transaction:
  - a transaction is keyed by (client addr, client port, server addr, server port, DNS id);
  - the first query of a key opens it; a repeated query while it is open is a retransmission and
    is ignored; the first response closes it (rtt = response time - query time); a later response
    to a closed key is ignored;
  - an unanswered query is logged at the end with rtt, rcode, answers unset;
  - a response with no open query is logged with its question section, rtt unset;
  - ts is the query time (response time for an orphan response); lines are sorted by ts;
  - rejected is true when the response rcode is not NOERROR.
  uid is sha1 of the 5-tuple, DNS id and ts; it is NOT the conn.log uid (join on 5-tuple + time).
"""
import hashlib
import ipaddress
import json
import struct
import time

import pcapprofile

CONN_KEYS = ("proto", "src", "sport", "dst", "dport", "start", "end", "orig_pkts", "resp_pkts",
             "orig_ip_bytes", "resp_ip_bytes", "orig_bytes", "resp_bytes", "flags_orig",
             "flags_resp", "tag", "tags", "first_pkt", "last_pkt")

SERVICES = {53: "dns", 80: "http", 8080: "http", 443: "ssl", 8443: "ssl", 445: "smb", 139: "netbios-ssn",
            22: "ssh", 123: "ntp", 389: "ldap", 636: "ldap", 88: "kerberos", 464: "kerberos",
            3389: "rdp", 21: "ftp", 25: "smtp", 587: "smtp", 110: "pop3", 143: "imap", 161: "snmp",
            67: "dhcp", 68: "dhcp", 514: "syslog", 3306: "mysql", 1812: "radius", 137: "netbios-ns", 5060: "sip", 1433: "mssql", 135: "dce_rpc"}

CONN_FIELDS = [
    ("ts", "time"), ("uid", "string"), ("id.orig_h", "addr"), ("id.orig_p", "port"),
    ("id.resp_h", "addr"), ("id.resp_p", "port"), ("proto", "enum"), ("service", "string"),
    ("duration", "interval"), ("orig_bytes", "count"), ("resp_bytes", "count"),
    ("conn_state", "string"), ("local_orig", "bool"), ("local_resp", "bool"),
    ("missed_bytes", "count"), ("history", "string"), ("orig_pkts", "count"),
    ("orig_ip_bytes", "count"), ("resp_pkts", "count"), ("resp_ip_bytes", "count"),
    ("tunnel_parents", "set[string]")]

DNS_FIELDS = [
    ("ts", "time"), ("uid", "string"), ("id.orig_h", "addr"), ("id.orig_p", "port"),
    ("id.resp_h", "addr"), ("id.resp_p", "port"), ("proto", "enum"), ("trans_id", "count"),
    ("rtt", "interval"), ("query", "string"), ("qclass", "count"), ("qclass_name", "string"),
    ("qtype", "count"), ("qtype_name", "string"), ("rcode", "count"), ("rcode_name", "string"),
    ("AA", "bool"), ("TC", "bool"), ("RD", "bool"), ("RA", "bool"), ("Z", "count"),
    ("answers", "vector[string]"), ("TTLs", "vector[interval]"), ("rejected", "bool")]

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
          33: "SRV", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS",
          255: "*", 252: "AXFR", 251: "IXFR", 99: "SPF", 257: "CAA"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
QCLASSES = {1: "C_INTERNET", 3: "C_CHAOS", 4: "C_HESIOD", 254: "C_NONE", 255: "C_ANY"}

_B62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
_FLAGBITS = ((1, "F"), (2, "S"), (4, "R"), (8, "P"), (16, "A"), (32, "U"))
_PROTO_NUM = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmp"}


def _uid(*parts):
    n = int.from_bytes(hashlib.sha1("|".join(map(str, parts)).encode(), usedforsecurity=False).digest(), "big")
    out = ""
    for _ in range(17):
        n, r = divmod(n, 62)
        out += _B62[r]
    return "C" + out


def _flags(v):
    """TCP flags (int bitmask or letter string, None = none) -> set of letters."""
    if not v:
        return set()
    if isinstance(v, str):
        return set(v.upper())
    return {c for bit, c in _FLAGBITS if v & bit}


def _proto(p):
    if isinstance(p, int):
        return _PROTO_NUM.get(p, "unknown_transport")
    p = str(p).lower()
    return p if p in ("tcp", "udp", "icmp") else ("icmp" if p.startswith("icmp") else "unknown_transport")


def conn_state(proto, resp_pkts, flags_orig, flags_resp):
    """Zeek-style conn_state from OR'd flags (see the module docstring); approximate."""
    if proto != "tcp":
        return "SF" if resp_pkts else "S0"
    o, r = _flags(flags_orig), _flags(flags_resp)
    if "S" in o:
        if not resp_pkts:
            return "RSTOS0" if "R" in o else ("SH" if "F" in o else "S0")
        if "S" in r and "A" in r:
            if "F" in o and "F" in r:
                return "SF"
            if "R" in o:
                return "RSTO"
            if "R" in r:
                return "RSTR"
            return "S2" if "F" in o else ("S3" if "F" in r else "S1")
        return "REJ" if "R" in r and "S" not in r else "OTH"
    if "S" in r and "A" in r:
        return "RSTRH" if "R" in r else "SHR"
    return "OTH"


def history(proto, flags_orig, flags_resp, orig_bytes, resp_bytes):
    """Presence-only history string (module docstring). Empty for non-TCP."""
    if proto != "tcp":
        return ""
    o, r = _flags(flags_orig), _flags(flags_resp)
    return ("S" * ("S" in o) + "h" * ("S" in r) + "A" * ("A" in o and ("S" in o or "S" in r))
            + "D" * bool(orig_bytes) + "d" * bool(resp_bytes) + "F" * ("F" in o) + "f" * ("F" in r)
            + "R" * ("R" in o) + "r" * ("R" in r))


def _stamp(t):
    return time.strftime("%Y-%m-%d-%H-%M-%S", time.gmtime(t))


def _esc(s, extra=""):
    """Escape control bytes, backslash and (for set/vector elements) the ',' separator as \\xNN, so
    attacker-controlled DNS names or flow strings cannot add tabs, newlines or columns to a TSV row."""
    return "".join("\\x%02x" % ord(c) if (c < " " or c in "\x7f\\" + extra) else c for c in s)


def _cell(v, typ, elem=False):
    """TSV cell: None -> '-', list -> ',' joined ('(empty)' when empty)."""
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "T" if v else "F"
    if isinstance(v, (list, tuple)):
        inner = typ.split("[")[1][:-1] if "[" in typ else typ
        return ",".join(_cell(x, inner, True) for x in v) or "(empty)"
    return "%.6f" % v if typ in ("time", "interval") else _esc(str(v), "," if elem else "")


def _write(path, log, fields, rows, fmt, t0, t1):
    """rows: dicts keyed by field name (None = unset)."""
    if fmt not in ("tsv", "json"):
        raise ValueError("fmt must be 'tsv' or 'json'")
    with open(path, "w", newline="\n") as f:
        if fmt == "tsv":
            f.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n")
            f.write("#path\t%s\n#open\t%s\n" % (log, _stamp(t0)))
            f.write("#fields\t" + "\t".join(n for n, _ in fields) + "\n")
            f.write("#types\t" + "\t".join(t for _, t in fields) + "\n")
            for r in rows:
                f.write("\t".join(_cell(r[n], t) for n, t in fields) + "\n")
            f.write("#close\t%s\n" % _stamp(t1))
        else:
            for r in rows:
                o = {}
                for n, t in fields:
                    v = r[n]
                    if v is None:
                        continue
                    o[n] = round(v, 6) if t in ("time", "interval") else (
                        [round(x, 6) for x in v] if t == "vector[interval]" else v)
                f.write(json.dumps(o, separators=(",", ":")) + "\n")
    return len(rows)


write_rows = _write                                   # public name for the sibling writers (zeekapp)


def write_conn_log(flows, path, fmt="tsv", rules=None):
    """Write flow records (dicts with CONN_KEYS) as a Zeek-style conn.log; returns the row count.
    rules (optional dict): "service_ports" {port: name} overrides SERVICES, "local_nets" [CIDR]."""
    rules = rules or {}
    svc = dict(SERVICES)
    svc.update({int(k): v for k, v in (rules.get("service_ports") or {}).items()})
    nets = [ipaddress.ip_network(n, strict=False) for n in rules.get("local_nets") or []]
    loc = (lambda a: any(ipaddress.ip_address(a) in n for n in nets)) if nets else (lambda a: None)
    rows = []
    for fl in sorted(flows, key=lambda x: (x["start"], str(x["src"]), x["sport"], str(x["dst"]), x["dport"])):
        p = _proto(fl["proto"])
        op, rp = fl["orig_pkts"], fl["resp_pkts"]
        ob, rb = fl["orig_bytes"], fl["resp_bytes"]
        rows.append({
            "ts": fl["start"], "uid": _uid(p, fl["src"], fl["sport"], fl["dst"], fl["dport"], "%.6f" % fl["start"]),
            "id.orig_h": fl["src"], "id.orig_p": fl["sport"], "id.resp_h": fl["dst"], "id.resp_p": fl["dport"],
            "proto": p, "service": svc.get(fl["dport"]) if rp and p in ("tcp", "udp") else None,
            "duration": max(0.0, fl["end"] - fl["start"]),
            "orig_bytes": ob if op else None, "resp_bytes": rb if rp else None,
            "conn_state": conn_state(p, rp, fl["flags_orig"], fl["flags_resp"]),
            "local_orig": loc(fl["src"]), "local_resp": loc(fl["dst"]), "missed_bytes": 0,
            "history": history(p, fl["flags_orig"], fl["flags_resp"], ob, rb) or None,
            "orig_pkts": op, "orig_ip_bytes": fl["orig_ip_bytes"], "resp_pkts": rp,
            "resp_ip_bytes": fl["resp_ip_bytes"], "tunnel_parents": [],
        })
    return _write(path, "conn", CONN_FIELDS, rows, fmt, rows[0]["ts"] if rows else 0,
                  max((r["ts"] + r["duration"] for r in rows), default=0))


# ---------------------------------------------------------------- dns.log

def _name(b, o):
    """Decode a DNS name at offset o (compression followed); returns (name, offset after it)."""
    labels, end, hops = [], None, 0
    while True:
        ln = b[o]
        if ln == 0:
            o += 1
            break
        if ln & 0xC0 == 0xC0:
            hops += 1
            if hops > 10:
                raise ValueError("pointer loop")
            if end is None:
                end = o + 2
            o = ((ln & 0x3F) << 8) | b[o + 1]
            continue
        labels.append(b[o + 1:o + 1 + ln].decode("ascii", "replace"))
        o += 1 + ln
    return ".".join(labels), (end if end is not None else o)


def _rdata(b, o, rtype, n):
    if rtype == 1 and n == 4:
        return str(ipaddress.IPv4Address(b[o:o + 4]))
    if rtype == 28 and n == 16:
        return str(ipaddress.IPv6Address(b[o:o + 16]))
    if rtype in (2, 5, 12):
        return _name(b, o)[0]
    if rtype == 15:
        return _name(b, o + 2)[0]
    if rtype == 16:
        out, p = [], o
        while p < o + n:
            ln = b[p]
            out.append(b[p + 1:p + 1 + ln].decode("ascii", "replace"))
            p += 1 + ln
        return "".join(out)
    return b[o:o + n].hex()


def parse_dns(b):
    """DNS message -> dict (id, qr, aa, tc, rd, ra, z, rcode, q, qtype, qclass, answers, ttls) or None."""
    try:
        if len(b) < 12:
            return None
        tid, fl, qd, an = struct.unpack("!HHHH", b[:8])
        m = {"id": tid, "qr": fl >> 15, "aa": bool(fl & 0x400), "tc": bool(fl & 0x200),
             "rd": bool(fl & 0x100), "ra": bool(fl & 0x80), "z": (fl >> 4) & 7, "rcode": fl & 15,
             "q": None, "qtype": None, "qclass": None, "answers": [], "ttls": []}
        o = 12
        for i in range(qd):
            nm, o = _name(b, o)
            qt, qc = struct.unpack("!HH", b[o:o + 4])
            o += 4
            if i == 0:
                m["q"], m["qtype"], m["qclass"] = nm, qt, qc
        for _ in range(an):
            _, o = _name(b, o)
            rt, _rc, ttl, n = struct.unpack("!HHIH", b[o:o + 10])
            o += 10
            m["answers"].append(_rdata(b, o, rt, n))
            m["ttls"].append(float(ttl))
            o += n
        return m
    except (IndexError, ValueError, struct.error):
        return None


def _udp53(eth):
    """(src, sport, dst, dport, payload) for UDP with port 53 on either side, else None.
    Ports are checked before any address is decoded: this runs once per frame of a large capture."""
    if len(eth) < 14:
        return None
    t, o = struct.unpack("!H", eth[12:14])[0], 14
    while t in (0x8100, 0x88A8) and len(eth) >= o + 4:
        t, o = struct.unpack("!H", eth[o + 2:o + 4])[0], o + 4
    if t == 0x0800 and len(eth) >= o + 20:
        if eth[o + 9] != 17 or struct.unpack("!H", eth[o + 6:o + 8])[0] & 0x3FFF:
            return None            # not UDP, or a fragment
        a, w, u = o + 12, 4, o + (eth[o] & 15) * 4
    elif t == 0x86DD and len(eth) >= o + 40:
        if eth[o + 6] != 17:
            return None            # extension headers are not walked
        a, w, u = o + 8, 16, o + 40
    else:
        return None
    if len(eth) < u + 8:
        return None
    sp, dp, ln = struct.unpack("!HHH", eth[u:u + 6])
    if 53 not in (sp, dp):
        return None
    cls = ipaddress.IPv4Address if w == 4 else ipaddress.IPv6Address
    return str(cls(eth[a:a + w])), sp, str(cls(eth[a + w:a + 2 * w])), dp, eth[u + 8:u + ln]


def _dns_row(ts, k, q, r, rtt):
    m = r if q is None else q
    rc = r["rcode"] if r else None
    return {
        "ts": ts, "uid": _uid("dns", *k, "%.6f" % ts), "id.orig_h": k[0], "id.orig_p": k[1],
        "id.resp_h": k[2], "id.resp_p": k[3], "proto": "udp", "trans_id": k[4], "rtt": rtt,
        "query": m["q"], "qclass": m["qclass"], "qclass_name": QCLASSES.get(m["qclass"]),
        "qtype": m["qtype"], "qtype_name": QTYPES.get(m["qtype"]),
        "rcode": rc, "rcode_name": RCODES.get(rc, str(rc)) if r else None,
        "AA": r["aa"] if r else None, "TC": r["tc"] if r else None, "RD": m["rd"],
        "RA": r["ra"] if r else None, "Z": r["z"] if r else None,
        "answers": (r["answers"] or None) if r else None, "TTLs": (r["ttls"] or None) if r else None,
        "rejected": (rc != 0) if r else None}


def write_dns_log(pcap_path, path, fmt="tsv"):
    """Parse DNS transactions from a pcap and write a Zeek-style dns.log; returns the row count."""
    pending, closed, rows, first, last = {}, set(), [], None, 0
    for ts, eth in pcapprofile.iter_frames(pcap_path):
        u = _udp53(eth)
        m = parse_dns(u[4]) if u else None
        if not m:
            continue
        first = ts if first is None else first
        last = ts
        if m["qr"] == 0:
            k = (u[0], u[1], u[2], u[3], m["id"])           # client -> server
            if k not in pending:                            # a repeat while open is a retransmission
                pending[k] = (ts, m)
        else:
            k = (u[2], u[3], u[0], u[1], m["id"])           # response: client's view of the key
            if k in pending:
                qts, q = pending.pop(k)
                rows.append(_dns_row(qts, k, q, m, ts - qts))
                closed.add(k)
            elif k not in closed:                           # orphan; later duplicates are dropped
                rows.append(_dns_row(ts, k, None, m, None))
                closed.add(k)
    rows += [_dns_row(qts, k, q, None, None) for k, (qts, q) in pending.items()]
    rows.sort(key=lambda r: (r["ts"], r["uid"]))
    return _write(path, "dns", DNS_FIELDS, rows, fmt, first or 0, last)
