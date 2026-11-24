"""The scenarios added in the engine update honour the emulated company.

Builds each scenario with a non-default company and custom networks, then checks that (1) the build completes, (2) nothing in the
capture, TLS key log or exported certificates carries a default-company name (EXL-<host>, corp.example.local),
and (3) the scenario's own traffic is present (frames to or from a host only that scenario creates, or on a port only it uses).

Run: python3 checks/check_company_identity.py [SCENARIO ...]      (default: all of them; builds run 4 at a time, about 2 minutes)
"""
import concurrent.futures
import os
import re
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPANY, INDUSTRY, USER_NET, SERVER_NET, OT_NET = "Acme", "Manufacturing", "192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24"

# scenario -> (a host IP or "port:N" only it produces, minimum frames)
SCENARIOS = {
    "ndr-php2shell":                  ("192.168.20.42", 500),     # the portal server it creates
    "ndr-ot-sanctioned-writes":       ("port:502", 100),
    "ndr-ot-new-pair":                ("port:502", 100),
    "ndr-ot-field-egress":            ("203.0.113.70", 50),
    "ndr-ot-protocol-sweep":          ("port:502", 500),
    "npm-nightly-backup":             ("port:445", 5000),
    "ir-netscaler-cve88771":          ("203.0.113.88", 50),
    "ir-beyondtrust-cve102764":       ("203.0.113.102", 50),
    "ir-metabase-cve72898":           ("203.0.113.72", 50),
    "ir-sharepoint-cve58644":         ("203.0.113.58", 50),
    "ir-panos-globalprotect-cve0257": ("203.0.113.57", 20),     # the forged-cookie legs are few at scale 0.01
    "ir-vcenter-cve59310":            ("203.0.113.59", 50),
    "ir-wordpress-upgrade-race":      ("203.0.113.119", 50),
    "ir-ipopt-tcp-uaf":               ("203.0.113.140", 50),
    "ir-armorycastle-vcenter-cve123890": ("203.0.113.123", 20),
    "ir-outlook-ntlm-leak-cve124194": ("203.0.113.124", 20),
    "ir-freeswitch-sip-message-cve116779": ("203.0.113.126", 20),
    "ir-puppet-report-rce-cve115731": ("203.0.113.127", 20),
    "ir-openssh-sshole-cve123158":    ("203.0.113.151", 20),
    "ir-optimjack-supplychain":       ("192.0.2.144", 20),
    "ir-turla-cereal-exchange":       ("203.0.113.170", 20),
    "ndr-gentlemen":                  ("203.0.113.160", 20),
}
LEAK = re.compile(rb"(?i)corp\.example\.local|north(?:)wind|(?<![a-z0-9])exl-(?:dc|file|sql|web|ws|fw|mgmt|backup|sb|ot|hmi|plc|rtu|scada|eng|cag|sp\d|vc|esxi|bi\d|gpgw|vpn|lnx|db|print|log|sw|wlc|ap|ntp|sensor|idmz|pdc|btrs)")


def frames(path, want):
    """Frames whose IPv4 src/dst is `want` (an address) or whose TCP/UDP port is N ('port:N')."""
    ip = None if want.startswith("port:") else bytes(int(x) for x in want.split("."))
    port = int(want[5:]) if want.startswith("port:") else None
    n = 0
    with open(path, "rb") as f:
        f.read(24)
        while True:
            h = f.read(16)
            if len(h) < 16:
                break
            d = f.read(struct.unpack("<I", h[8:12])[0])
            if len(d) < 38 or d[12:14] != b"\x08\x00":
                continue
            if ip is not None:
                n += d[26:30] == ip or d[30:34] == ip
            elif d[23] in (6, 17):
                ihl = (d[14] & 0xF) * 4
                sp, dp = struct.unpack("!HH", d[14 + ihl:18 + ihl])
                n += port in (sp, dp)
    return n


def one(name):
    want, minimum = SCENARIOS[name]
    with tempfile.TemporaryDirectory() as d:
        pcap = os.path.join(d, "t.pcap")
        r = subprocess.run([sys.executable, "opengenerator_build.py", "--scale", "0.01", "--module", name, "--company", COMPANY,
                            "--industry", INDUSTRY, "--user-net", USER_NET, "--server-net", SERVER_NET, "--ot-net", OT_NET,
                            "--out", pcap, "--certs-dir", os.path.join(d, "certs"), "--iocs-prefix", os.path.join(d, "ioc"),
                            "--date", "2026-03-02"], cwd=HERE, capture_output=True, text=True)
        if r.returncode != 0:
            return name, ["build failed: " + r.stderr[-400:]]
        errs = []
        blobs = [pcap, os.path.join(d, "t-tls-keys.log")]
        for root, _, fs in os.walk(os.path.join(d, "certs")):
            blobs += [os.path.join(root, x) for x in fs]
        blobs += [os.path.join(d, x) for x in os.listdir(d) if x.startswith("ioc")]
        for p in blobs:
            if os.path.isfile(p):
                for m in LEAK.finditer(open(p, "rb").read()):
                    errs.append("%s carries %r" % (os.path.basename(p), m.group(0)))
                    break
        got = frames(pcap, want)
        if got < minimum:
            errs.append("expected at least %d frames for %s, found %d" % (minimum, want, got))
        return name, errs


def main():
    names = sys.argv[1:] or list(SCENARIOS)
    bad = 0
    with concurrent.futures.ThreadPoolExecutor(4) as ex:
        for name, errs in ex.map(one, names):
            print(("FAIL " if errs else "ok   ") + name)
            for e in errs:
                print("     " + e)
            bad += bool(errs)
    if bad:
        sys.exit("%d scenario(s) failed the company-identity check" % bad)
    print("all %d scenarios honour the emulated company" % len(names))


if __name__ == "__main__":
    main()
