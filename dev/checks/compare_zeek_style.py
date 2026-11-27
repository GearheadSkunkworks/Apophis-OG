"""Dev-only: compare Zeek-style conn.log / dns.log / ssl.log / x509.log / http.log and a pcapng
converter output against tshark's view of the same pcap. Never imported by the app. Skips (exit 0,
clear message) when tshark is absent.

  python3 checks/compare_zeek_style.py capture.pcap [--conn conn.log] [--dns dns.log]
      [--ssl ssl.log] [--x509 x509.log] [--http http.log] [--pcapng capture.pcapng]

Conversations: tshark's conv,tcp / conv,udp tables have no idle splitting (and split TCP by SYN
reuse), so both sides are merged by the unordered 5-tuple first and compared on that key: the key
set and the total frame count per key. Bytes are not compared (tshark prints frame bytes with
varying units; the logs carry IP and payload bytes).
DNS: tshark -T fields over UDP/53 messages. Compared: the set of (query, qtype) pairs, and the set
of (query, qtype, rcode) over responses. Message counts are printed, not asserted (the log
collapses retransmissions and duplicate responses by design). Answers, TTLs and RTT are NOT
compared here. Exit 0 = agree (or skipped), 1 = differences found.

ssl.log: the set of TCP ClientHello 5-tuples (tshark; DTLS/QUIC over UDP is not followed) against the log rows, and per 5-tuple the SNI and the
ServerHello cipher suite id. TLS carried inside RDP (responder port 3389; tshark decodes it, the log
does not follow it) is counted and listed as "not compared", never silently dropped. x509.log: the
multiset of SHA-256 fingerprints of every certificate tshark sees in a Certificate message against the
log's fingerprints. http.log: the multiset of (5-tuple, method, uri) over TCP requests and of
(5-tuple, status code) over TCP responses; UDP HTTP-like traffic (SSDP) is out of scope. NOT compared:
versions beyond the ServerHello suite id, curve, resumption, alerts, dates, subjects, sizes, hosts and
user agents. JA3/JA4 are not logged. pcapng: capinfos packet count and first/last time equal to the pcap's.
"""
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import zeekapp  # noqa: E402 - sys.path is set up first
_MAC_APP = "/Applications/Wireshark.app/Contents/MacOS/tshark"


def tshark_path():
    return shutil.which("tshark") or (_MAC_APP if os.path.exists(_MAC_APP) else None)


def _run(args):
    return subprocess.run([tshark_path()] + args, capture_output=True, text=True, check=True).stdout


def _norm(a):
    return str(ipaddress.ip_address(a))


def _key(proto, a, ap, b, bp):
    return (proto,) + tuple(sorted([(_norm(a), int(ap)), (_norm(b), int(bp))]))


def tshark_conv(pcap, proto):
    """{unordered 5-tuple: total frames} merged over tshark's conversations."""
    out, row = {}, re.compile(r"^(\S+)\s+<->\s+(\S+)\s+(.*)$")
    for line in _run(["-r", pcap, "-q", "-z", "conv,%s" % proto]).splitlines():
        m = row.match(line)
        if not m:
            continue
        t = m.group(3).split()                  # f1 b1 u1 f2 b2 u2 ft bt ut start dur
        (a, ap), (b, bp) = m.group(1).rsplit(":", 1), m.group(2).rsplit(":", 1)
        k = _key(proto, a, ap, b, bp)
        out[k] = out.get(k, 0) + int(t[6])
    return out


def read_log(path):
    """Zeek-style log (TSV with #fields, or JSON lines) -> list of dicts; '-' / missing = None."""
    rows, fields = [], None
    with open(path) as f:
        for line in f:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#") or not line:
                continue
            elif line[0] == "{":
                rows.append(json.loads(line))
            else:
                rows.append({n: (None if v == "-" else v) for n, v in zip(fields, line.split("\t"))})
    return rows


def log_conv(rows):
    out = {}
    for r in rows:
        if r["proto"] not in ("tcp", "udp"):
            continue
        k = _key(r["proto"], r["id.orig_h"], r["id.orig_p"], r["id.resp_h"], r["id.resp_p"])
        out[k] = out.get(k, 0) + int(r["orig_pkts"]) + int(r["resp_pkts"])
    return out


def compare_conn(pcap, conn_log):
    """Returns (diff lines, summary dict)."""
    all_log = log_conv(read_log(conn_log))
    diffs, summary = [], {}
    for proto in ("tcp", "udp"):
        ts = tshark_conv(pcap, proto)
        lg = {k: v for k, v in all_log.items() if k[0] == proto}
        summary[proto] = {"tshark_5tuples": len(ts), "log_5tuples": len(lg),
                          "tshark_frames": sum(ts.values()), "log_frames": sum(lg.values())}
        for k in sorted(set(ts) - set(lg)):
            diffs.append("%s only in tshark: %s (%d frames)" % (proto, k[1:], ts[k]))
        for k in sorted(set(lg) - set(ts)):
            diffs.append("%s only in log: %s (%d frames)" % (proto, k[1:], lg[k]))
        for k in sorted(set(ts) & set(lg)):
            if ts[k] != lg[k]:
                diffs.append("%s frame count %s: tshark %d, log %d" % (proto, k[1:], ts[k], lg[k]))
    return diffs, summary


def tshark_dns(pcap):
    """[(is_response, query, qtype, rcode)] per UDP/53 DNS message, as tshark parses it."""
    out = _run(["-r", pcap, "-Y", "dns && udp.port == 53", "-T", "fields", "-e", "dns.flags.response",
                "-e", "dns.qry.name", "-e", "dns.qry.type", "-e", "dns.flags.rcode"])
    msgs = []
    for line in out.splitlines():
        p = (line.split("\t") + ["", "", "", ""])[:4]
        msgs.append((p[0] in ("1", "True", "true"), p[1].split(",")[0] or None,
                     int(p[2].split(",")[0]) if p[2] else None, int(p[3]) if p[3] else None))
    return msgs


def compare_dns(pcap, dns_log):
    rows = read_log(dns_log)
    msgs = tshark_dns(pcap)
    diffs = []
    t_q = {(q, t) for _, q, t, _ in msgs if q}
    l_q = {(r["query"], int(r["qtype"])) for r in rows if r.get("query")}
    t_r = {(q, t, rc) for resp, q, t, rc in msgs if resp and q}
    l_r = {(r["query"], int(r["qtype"]), int(r["rcode"])) for r in rows
           if r.get("rcode") is not None and r.get("query")}
    for name, a, b in (("(query, qtype)", t_q, l_q), ("(query, qtype, rcode)", t_r, l_r)):
        for x in sorted(a - b, key=str):
            diffs.append("%s only in tshark: %s" % (name, x))
        for x in sorted(b - a, key=str):
            diffs.append("%s only in log: %s" % (name, x))
    summary = {"tshark_messages": len(msgs), "tshark_responses": sum(1 for m in msgs if m[0]),
               "log_transactions": len(rows), "log_answered": sum(1 for r in rows if r.get("rcode") is not None)}
    return diffs, summary


def _fields(pcap, flt, fields, opts=()):
    """tshark -Y flt -T fields: one list of column strings per matching frame."""
    out = _run(["-r", pcap, "-Y", flt, "-T", "fields"] + list(opts) + [x for f in fields for x in ("-e", f)])
    return [(line.split("\t") + [""] * len(fields))[:len(fields)] for line in out.splitlines()]


_TUPLE = ["ip.src", "tcp.srcport", "ip.dst", "tcp.dstport"]
_RDP_PORT = "3389"


def _diff(name, a, b, diffs, cap=8):
    """Multiset difference a vs b (Counters) -> readable lines in diffs."""
    from collections import Counter
    for lbl, x, y in (("tshark", Counter(a), Counter(b)), ("log", Counter(b), Counter(a))):
        for k, v in list((x - y).items())[:cap]:
            diffs.append("%s only in %s: %s (x%d)" % (name, lbl, k, v))


def compare_ssl(pcap, ssl_log):
    rows = read_log(ssl_log)
    ch = _fields(pcap, "tls.handshake.type == 1 && tcp", _TUPLE + ["tls.handshake.extensions_server_name"])
    sh = _fields(pcap, "tls.handshake.type == 2 && tcp", _TUPLE + ["tls.handshake.ciphersuite"])
    skipped = [r for r in ch if r[3] == _RDP_PORT]
    ch = [r for r in ch if r[3] != _RDP_PORT]
    t_hello = [(r[0], r[1], r[2], r[3]) for r in ch]
    t_sni = {(r[0], r[1], r[2], r[3]): r[4] or None for r in ch}
    t_ciph = {(r[2], r[3], r[0], r[1]): int(r[4], 16) for r in sh if r[1] != _RDP_PORT and r[4]}
    l_hello = [(r["id.orig_h"], r["id.orig_p"], r["id.resp_h"], r["id.resp_p"]) for r in rows]
    diffs = []
    _diff("ClientHello 5-tuple", t_hello, l_hello, diffs)
    inv = {v: k for k, v in zeekapp.CIPHERS.items()}
    for r in rows:
        k = (r["id.orig_h"], r["id.orig_p"], r["id.resp_h"], r["id.resp_p"])
        if k in t_sni and (t_sni[k] or None) != r.get("server_name"):
            diffs.append("server_name for %s: tshark %r, log %r" % (k, t_sni[k], r.get("server_name")))
        if k in t_ciph and r.get("cipher") and inv.get(r["cipher"]) != t_ciph[k]:
            diffs.append("cipher for %s: tshark 0x%04x, log %s" % (k, t_ciph[k], r["cipher"]))
    summary = {"tshark_client_hellos": len(ch), "tshark_server_hellos": len(t_ciph), "log_rows": len(rows),
               "not_compared_tls_inside_rdp": len(skipped)}
    return diffs, summary


def compare_x509(pcap, x509_log):
    rows = read_log(x509_log)
    t, skipped = [], 0
    for r in _fields(pcap, "tls.handshake.type == 11 && tcp", _TUPLE + ["tls.handshake.certificate"]):
        fps = [hashlib.sha256(bytes.fromhex(c.replace(":", ""))).hexdigest() for c in r[4].split(",") if c]
        if _RDP_PORT in (r[1], r[3]):                  # TLS inside RDP: not followed by the log
            skipped += len(fps)
        else:
            t += fps
    lg = [r["fingerprint"] for r in rows]
    diffs = []
    _diff("certificate fingerprint", t, lg, diffs)
    return diffs, {"tshark_certificates": len(t), "log_rows": len(rows), "not_compared_tls_inside_rdp": skipped}


def compare_http(pcap, http_log):
    rows = read_log(http_log)
    # without TCP desegmentation tshark reports a request from its headers, as the log does; with it a
    # request whose body never completes (a stalled upload) is not reported at all
    nodeseg = ("-o", "tcp.desegment_tcp_streams:FALSE")
    rq = _fields(pcap, "http.request && tcp", _TUPLE + ["http.request.method", "http.request.uri"], nodeseg)
    rs = _fields(pcap, "http.response && tcp", _TUPLE + ["http.response.code"], nodeseg)
    t_rq = [(r[0], r[1], r[2], r[3], r[4], r[5]) for r in rq]
    t_rs = [(r[2], r[3], r[0], r[1], r[4]) for r in rs]
    l_rq = [(r["id.orig_h"], r["id.orig_p"], r["id.resp_h"], r["id.resp_p"], r["method"], r["uri"]) for r in rows]
    l_rs = [(r["id.orig_h"], r["id.orig_p"], r["id.resp_h"], r["id.resp_p"], r["status_code"])
            for r in rows if r.get("status_code") is not None]
    diffs = []
    _diff("http request", t_rq, l_rq, diffs)
    _diff("http status", [x for x in t_rs if not x[4].startswith("1")], [x for x in l_rs if not x[4].startswith("1")], diffs)
    return diffs, {"tshark_requests": len(t_rq), "tshark_responses": len(t_rs), "log_rows": len(rows)}


def capinfos_path():
    p = shutil.which("capinfos")
    sib = os.path.join(os.path.dirname(tshark_path() or ""), "capinfos")
    return p or (sib if os.path.exists(sib) else None)


def _capinfos(path):
    out = subprocess.run([capinfos_path(), "-M", "-c", "-a", "-e", "-S", path], capture_output=True, text=True,
                         check=True).stdout
    d = {}
    for line in out.splitlines():
        k, _, v = line.partition(":")
        d[k.strip()] = v.strip()
    return {"packets": int(d["Number of packets"]), "first": float(d["Earliest packet time"]),
            "last": float(d["Latest packet time"])}


def compare_pcapng(pcap, pcapng):
    if not capinfos_path():
        return [], {"skipped": "capinfos not found"}
    a, b = _capinfos(pcap), _capinfos(pcapng)
    diffs = ["%s: pcap %s, pcapng %s" % (k, a[k], b[k]) for k in a if a[k] != b[k]]
    return diffs, {"pcap": a, "pcapng": b}


def main(argv):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("pcap")
    ap.add_argument("--conn")
    ap.add_argument("--dns")
    ap.add_argument("--ssl")
    ap.add_argument("--x509")
    ap.add_argument("--http")
    ap.add_argument("--pcapng")
    a = ap.parse_args(argv)
    if not tshark_path():
        print("SKIP: tshark not found; comparison not run")
        return 0
    bad = 0
    for name, fn, log in (("conn", compare_conn, a.conn), ("dns", compare_dns, a.dns), ("ssl", compare_ssl, a.ssl),
                          ("x509", compare_x509, a.x509), ("http", compare_http, a.http),
                          ("pcapng", compare_pcapng, a.pcapng)):
        if not log:
            continue
        diffs, summary = fn(a.pcap, log)
        print("%s: %s" % (name, json.dumps(summary)))
        for d in diffs[:50]:
            print("  DIFF", d)
        if len(diffs) > 50:
            print("  ... %d more" % (len(diffs) - 50))
        print("%s: %s" % (name, "AGREE" if not diffs else "%d differences" % len(diffs)))
        bad += bool(diffs)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
