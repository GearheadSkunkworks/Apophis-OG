"""Post-build exporters "ipfix" and "netflow9": an exporter pcap plus a CSV, both derived from the flow table.

For each requested format the files are <stem>-ipfix.pcap / <stem>-ipfix.csv (IPFIX, RFC 7011) or
<stem>-netflow9.pcap / <stem>-netflow9.csv (NetFlow v9, RFC 3954). The pcap holds UDP datagrams from a
synthetic exporter to a synthetic collector (documentation addresses, TEST-NET-1) carrying template and
data records, stamped with the flow end times so it replays in capture order. The CSV holds the same
records. One record per direction that carried packets (unidirectional records); the flow table has one
start and one end per flow, so both directions of a flow share them. Flows are exported once, after
they end: there is no active-timeout splitting.

Everything is a pure function of (pcap, tag sidecar): same inputs, same records. Exporter and collector
addresses, the exporter MACs, the interface numbers (1 = the originator side, 2 = the responder side), the
observation domain id and the scenario-tag element are SYNTHETIC values, not facts about any device.
Runs only when the build option exports contains the format; never raises: a failure is recorded in the
returned block and the capture is kept. VLAN ids and IPv6 are exported when the flow table carries them
(r["vlan"], IPv6 addresses); today's flow table yields neither.
"""
import csv
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_manifest as BM  # noqa: E402 - sys.path is set up first
import flowtable             # noqa: E402 - sys.path is set up first
import ipfixenc              # noqa: E402 - sys.path is set up first
import safeio                # noqa: E402 - sys.path is set up first

KIND = "flow-export"
FORMATS = {"ipfix": (ipfixenc.IPFIX, 4739), "netflow9": (ipfixenc.NF9, 2055)}   # name -> (version, UDP port)
EXPORTER, COLLECTOR = "192.0.2.1", "192.0.2.2"       # RFC 5737 TEST-NET-1: documentation addresses
EXPORTER_MAC, COLLECTOR_MAC = b"\x02\x00\x5e\x00\x00\x01", b"\x02\x00\x5e\x00\x00\x02"
SRC_PORT, MTU = 49152, 1500
REFRESH_MSGS, REFRESH_S = 20, 600.0
CSV_COLUMNS = ["direction", "src", "dst", "sport", "dport", "proto", "packets", "octets", "start_ms", "end_ms",
               "tcp_flags", "ingress_if_synthetic", "egress_if_synthetic", "vlan", "scenario_tag"]
_PROTO = {"tcp": 6, "udp": 17, "icmp": 1}


def paths(out, name):
    stem = (out[:-5] if out.endswith(".pcap") else out) + "-" + name
    return stem + ".pcap", stem + ".csv"


def _ms(t):
    return int(round(t * 1000))


def records(flow_iter):
    """Flow dicts -> unidirectional export records, sorted by (end, start, first packet, direction)."""
    out = []
    for f in flow_iter:
        start, end = _ms(f["start"]), _ms(f["end"])
        icmp = f["proto"] == "icmp"
        common = {"proto": _PROTO[f["proto"]], "start_ms": start, "end_ms": end, "vlan": f.get("vlan"), "tag": f["tag"]}
        if f["orig_pkts"]:
            # ICMP has no ports: the flow table carries type/code in sport/dport; send them as dport = type << 8 | code
            sp, dp = (0, f["sport"] << 8 | f["dport"]) if icmp else (f["sport"], f["dport"])
            out.append((end, start, f["first_pkt"], 0, {**common, "direction": "orig", "src": f["src"], "dst": f["dst"],
                        "sport": sp, "dport": dp, "pkts": f["orig_pkts"], "octets": f["orig_ip_bytes"],
                        "flags": f["flags_orig"], "in_if": 1, "out_if": 2}))
        if f["resp_pkts"]:
            out.append((end, start, f["first_pkt"], 1, {**common, "direction": "resp", "src": f["dst"], "dst": f["src"],
                        "sport": 0 if icmp else f["dport"], "dport": 0 if icmp else f["sport"],
                        "pkts": f["resp_pkts"], "octets": f["resp_ip_bytes"], "flags": f["flags_resp"],
                        "in_if": 2, "out_if": 1}))
    out.sort(key=lambda x: x[:4])
    return [x[4] for x in out]


def _csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def frame(payload, port, ident):
    """Ethernet + IPv4 + UDP frame, exporter -> collector, with correct IP and UDP checksums."""
    src, dst = socket.inet_aton(EXPORTER), socket.inet_aton(COLLECTOR)
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", SRC_PORT, port, udp_len, 0) + payload
    ck = _csum(src + dst + struct.pack("!BBH", 0, 17, udp_len) + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", ck) + udp[8:]
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + udp_len, ident & 0xFFFF, 0x4000, 64, 17, 0) + src + dst
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    return COLLECTOR_MAC + EXPORTER_MAC + b"\x08\x00" + ip + udp


def _pcap_header():
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def write_export(recs, version, port, pcap_path, csv_path):
    """Write the exporter pcap and the CSV for `recs`; returns {"messages": n, "records": n}."""
    boot = (min(r["start_ms"] for r in recs) - 60000) if recs else 0
    n = 0
    with safeio.create_new(pcap_path, "wb") as pf, safeio.create_new(csv_path, "w", newline="", encoding="utf-8") as cf:
        pf.write(_pcap_header())
        w = csv.writer(cf, lineterminator="\n")
        w.writerow(CSV_COLUMNS)
        for r in recs:
            w.writerow([r["direction"], r["src"], r["dst"], r["sport"], r["dport"], r["proto"], r["pkts"], r["octets"],
                        r["start_ms"], r["end_ms"], r["flags"], r["in_if"], r["out_if"],
                        "" if r["vlan"] is None else r["vlan"], r["tag"] or ""])
        for t, msg in ipfixenc.messages(recs, version, MTU, REFRESH_MSGS, REFRESH_S, 1, boot):
            fr = frame(msg, port, n)
            sec, us = int(t), int(round((t - int(t)) * 1e6))
            pf.write(struct.pack("<IIII", sec + us // 1000000, us % 1000000, len(fr), len(fr)) + fr)
            n += 1
    return {"messages": n, "records": len(recs)}


def export(e):
    """_ExportCtx -> {"ipfix": block, "netflow9": block} for the requested formats ({} when none)."""
    want = [k for k in FORMATS if k in (getattr(e, "exports", None) or ())]
    res = {}
    recs = stats = err = None
    for name in want:
        version, port = FORMATS[name]
        pcap, csvp = paths(e.out, name)
        block = {"kind": KIND, "format": name, "files": [os.path.basename(pcap), os.path.basename(csvp)],
                 "rules": {**{k: v for k, v in flowtable.RULES.items() if k.endswith("_idle")}, "mtu": MTU,
                           "template_refresh_messages": REFRESH_MSGS, "template_refresh_seconds": REFRESH_S,
                           "udp_port": port, "records": "unidirectional, one per direction with packets"},
                 "synthetic": ["exporter and collector addresses and MACs", "ingress and egress interface numbers",
                               "observation domain id"] + (["scenario-tag element (PEN 32473)"] if version == ipfixenc.IPFIX else [])}
        try:
            if recs is None and err is None:
                try:
                    if not getattr(e, "tags_path", None):
                        raise ValueError("the tag sidecar is missing")
                    stats = {}
                    recs = records(flowtable.export_flows(e, stats))
                except Exception as ex:                      # noqa: BLE001 - recorded in each block below
                    err = ex
            if err is not None:
                raise err
            r = write_export(recs, version, port, pcap, csvp)
            flow_pkts = sum(x["pkts"] for x in recs)
            block.update(r, flow_packets=flow_pkts, unflowed_frames=stats["unflowed"], packets=e.writer.n,
                         tags_sha256=BM.sha256_file(e.tags_path),
                         exports_consistent=flow_pkts + stats["unflowed"] == e.writer.n)
        except Exception as ex:                              # noqa: BLE001 - never discard a finished capture
            block.pop("files")
            block["error"] = BM.export_error(ex)
            for p in (pcap, csvp):
                try:
                    os.remove(p)
                except OSError:
                    pass
        res[name] = block
    return res
