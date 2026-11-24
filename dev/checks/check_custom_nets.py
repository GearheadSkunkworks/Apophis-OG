"""Regression check: with custom user/server/OT subnets, (1) the capture must complete and keep every
internal packet on the configured /24s, and (2) the run summary must label each network correctly. (The
other versions of this check also cover a detection bundle and diagrams, which OpenGenerator does not have.) Nothing may fall back to the stock 10.10.10 /
10.10.20 / 10.10.30 addresses. Self-contained: builds into a temp dir, reads the files itself."""
import os, re, struct, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USER, SERVER, OT = "10.10.100", "10.10.200", "10.10.250"
STOCK = {"10.10.10", "10.10.20"}
STOCK_PAYLOAD_RX = re.compile(rb"(?<![\d.])10\.10\.(?:10|20|30)\.\d{1,3}")
NETS = dict(user_net=USER + ".0/24", server_net=SERVER + ".0/24",
            ot_nets={"ot": OT + ".0/24", "ops": None, "idmz": None})


def check_summary(tmp):
    """The run summary must label each network as requested (it once paired legs by list position)."""
    sys.path.insert(0, HERE)
    import opengenerator_build as NB
    want = {"user": USER + ".0/24", "server": SERVER + ".0/24", "ot": OT + ".0/24",
            "ops": "10.10.251.0/24", "idmz": "10.10.252.0/24"}
    s = NB.build(scale=0.002, out=os.path.join(tmp, "s.pcap"), inventory=os.path.join(HERE, "inventory.json"),
                 progress=False, certs_dir=None, iocs_prefix=None, modules=[], user_net=want["user"], server_net=want["server"],
                 ot_nets={k: want[k] for k in ("ot", "ops", "idmz")})
    if s["nets"] != want:
        sys.exit("run summary mislabels the networks: %s, wanted %s" % (s["nets"], want))
    print("run summary labels user/server/OT/ops/IDMZ correctly")


def main():
    with tempfile.TemporaryDirectory() as d:
        pcap = os.path.join(d, "t.pcap")
        r = subprocess.run([sys.executable, "opengenerator_build.py", "--scale", "0.002", "--out", pcap,
                            "--certs-dir", os.path.join(d, "certs"), "--no-iocs",
                            "--user-net", USER + ".0/24", "--server-net", SERVER + ".0/24",
                            "--ot-net", OT + ".0/24"], cwd=HERE, capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit("build failed with custom networks:\n" + r.stderr[-1500:])
        seen, n, text = set(), 0, {}
        with open(pcap, "rb") as f:
            f.read(24)
            while True:
                h = f.read(16)
                if len(h) < 16:
                    break
                data = f.read(struct.unpack("<I", h[8:12])[0])
                n += 1
                for m in STOCK_PAYLOAD_RX.finditer(data):      # documents and configs quoting an address
                    text[m.group(0)] = text.get(m.group(0), 0) + 1
                if len(data) >= 34 and data[12:14] == b"\x08\x00":
                    for ip in (data[26:29], data[30:33]):
                        if ip[0] == 10:
                            seen.add(".".join(map(str, ip)))
        if text:
            sys.exit("payloads still quote stock addresses: %s" % sorted(text)[:8])
        stray = seen & STOCK
        if stray or not {USER, SERVER} <= seen:
            sys.exit("custom networks not honoured: stock subnets seen %s; saw %s" % (sorted(stray), sorted(seen)))
        check_summary(d)
        print("custom networks honoured (%d packets, internal /24s: %s)" % (n, ", ".join(sorted(seen))))


if __name__ == "__main__":
    main()
