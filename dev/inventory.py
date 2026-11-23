#!/usr/bin/env python3
"""
Example Logistics demo network - deterministic host inventory.

Produces inventory.json and inventory.csv. Every host has a hostname, role,
OS, IP, MAC (vendor-plausible OUI + fabricated host bytes), subnet and the
services it listens on. This file is the single source of truth for the
architecture diagram (task 1) and the pcap generators (tasks 2 and 3).
"""
import csv
import json
import random

DOMAIN = "corp.example.local"
ORG = "Example Logistics"

USER_NET = "10.10.10.0/24"
SRV_NET = "10.10.20.0/24"

# Vendor-plausible OUIs (first three octets). Host bytes are fabricated.
OUI = {
    "dell":     "F4:8E:38",   # Dell workstations / servers
    "apple":    "A4:83:E7",   # Apple
    "hp_print": "3C:D9:2B",   # HP printers
    "cisco_ap": "00:40:96",   # Cisco Aironet access points
    "cisco":    "00:1B:D4",   # Cisco handsets
    "smart":    "00:24:8C",   # Smart board / display
    "vmware":   "00:50:56",   # Virtual servers
    "paloalto": "00:1B:17",   # Firewall
    "cisco_sw": "00:1E:14",   # Switches
    "sensor":   "00:0D:B9",   # Passive sensor mgmt NIC
}

rng = random.Random(20260914)  # fixed seed -> stable MACs


def mac(vendor):
    return OUI[vendor] + ":" + ":".join(f"{rng.randrange(256):02X}" for _ in range(3))


hosts = []


def add(hostname, role, os_, ip, vendor, subnet, services="", notes="", mac_addr=None):
    hosts.append({
        "hostname": hostname,
        "fqdn": f"{hostname.lower()}.{DOMAIN}",
        "role": role,
        "os": os_,
        "ip": ip,
        "mac": mac_addr or mac(vendor),
        "subnet": subnet,
        "services": services,
        "notes": notes,
    })


# ---------------------------------------------------------------- core / edge
add("EXL-FW1", "Firewall / inter-subnet router / NAT / DHCP relay", "PAN-OS",
    "10.10.10.1", "paloalto", USER_NET, "gateway", "inside-A (ethernet1/1)")
fw_mac_b = mac("paloalto")
add("EXL-FW1", "Firewall / inter-subnet router / NAT / DHCP relay", "PAN-OS",
    "10.10.20.1", "paloalto", SRV_NET, "gateway", "inside-B (ethernet1/2)", mac_addr=fw_mac_b)
add("EXL-FW1", "Firewall outside interface", "PAN-OS",
    "203.0.113.2", "paloalto", "203.0.113.0/30", "NAT source", "outside (ethernet1/3); ISP gw 203.0.113.1")
add("EXL-SWA1", "User access switch stack (mgmt SVI)", "IOS-XE",
    "10.10.10.2", "cisco_sw", USER_NET, "ssh/22 snmp/161", "48-port PoE x3, uplink to FW inside-A")
add("EXL-SWB1", "Server distribution switch (mgmt SVI)", "IOS-XE",
    "10.10.20.2", "cisco_sw", SRV_NET, "ssh/22 snmp/161", "uplink to FW inside-B, SPAN source")
add("EXL-SENSOR1", "Passive network sensor (mgmt NIC)", "Sensor appliance",
    "10.10.20.250", "sensor", SRV_NET, "https/443 mgmt", "Receives SPAN of FW inside-A and inside-B; capture NICs unaddressed")

# ------------------------------------------------------------------- servers
servers = [
    ("EXL-DC1",     "10.10.20.10",  "Domain controller (DNS, DHCP, Kerberos, LDAP)", "Windows Server 2022", "dns/53 kerberos/88 ldap/389 ldaps/636 smb/445 dhcp/67 rpc/135", "Primary DNS / DHCP for both subnets"),
    ("EXL-DC2",     "10.10.20.11",  "Domain controller (DNS, Kerberos, LDAP)",       "Windows Server 2022", "dns/53 kerberos/88 ldap/389 ldaps/636 smb/445 rpc/135", "Secondary DNS; AD replication with DC1"),
    ("EXL-FILE1",   "10.10.20.20",  "File server (SMB shares)",                       "Windows Server 2022", "smb/445", "\\\\exl-file1\\Dept, \\\\exl-file1\\Users"),
    ("EXL-SQL1",    "10.10.20.30",  "Database server (Microsoft SQL Server)",         "Windows Server 2022 / SQL Server 2022", "tds/1433", "Backend for WEB1 and WEB2"),
    ("EXL-WEB1",    "10.10.20.40",  "Intranet web application (IIS)",                 "Windows Server 2022 / IIS 10", "http/80 https/443", "intranet.corp.example.local; talks TDS to SQL1"),
    ("EXL-WEB2",    "10.10.20.41",  "Line-of-business web application (IIS)",          "Windows Server 2022 / IIS 10", "http/80 https/443", "shipping.corp.example.local; TDS to SQL1"),
    ("EXL-WLC1",    "10.10.20.50",  "Wireless LAN controller",                        "Cisco AireOS 8.10", "capwap/5246 capwap/5247 https/443", "12 APs on user subnet tunnel here"),
    ("EXL-PBX1",    "10.10.20.60",  "VoIP PBX / SIP call manager",                    "Linux (Asterisk)", "sip/5060 rtp/10000-20000", "10 handsets register here"),
    ("EXL-PRINT1",  "10.10.20.70",  "Print server",                                   "Windows Server 2022", "smb/445 rpc/135", "Spools to the 4 user-subnet printers (ipp/631, raw/9100)"),
    ("EXL-NTP1",    "10.10.20.80",  "NTP time source",                                "Linux (chrony)", "ntp/123", "Stratum 2; all hosts sync here"),
    ("EXL-LOG1",    "10.10.20.90",  "Syslog / SNMP monitoring",                       "Linux", "syslog/514 snmptrap/162 https/443", "Polls switches, APs, printers via SNMP"),
    ("EXL-BACKUP1", "10.10.20.100", "Backup server",                                  "Linux", "ssh/22 smb/445 https/443", "Nightly pulls from FILE1 and SQL1"),
    ("EXL-MGMT1",   "10.10.20.110", "Admin jump host",                                "Windows Server 2022", "rdp/3389", "Admins RDP here, then SSH/RDP to servers"),
]
for name, ip, role, os_, svc, notes in servers:
    add(name, role, os_, ip, "vmware", SRV_NET, svc, notes)

# ---------------------------------------------------------------- user subnet
# Static infrastructure endpoints
for i in range(1, 13):
    add(f"EXL-AP-{i:02d}", "Wireless access point", "Cisco Aironet AP", f"10.10.10.{10+i}", "cisco_ap", USER_NET,
        "capwap client", "Static IP; tunnels to WLC1")
for i in range(1, 5):
    add(f"EXL-PRN-{i:02d}", "Network printer (MFP)", "HP FutureSmart", f"10.10.10.{30+i}", "hp_print", USER_NET,
        "ipp/631 raw/9100 snmp/161 http/80", "Static IP; jobs from PRINT1")
for i in range(1, 5):
    add(f"EXL-SB-{i:02d}", "Smart board / conference display", "Android (embedded)", f"10.10.10.{35+i}", "smart", USER_NET,
        "http/80 mdns/5353", "Static IP; conference rooms")
for i in range(1, 11):
    add(f"EXL-PH-{i:02d}", "VoIP desk phone (Cisco)", "Cisco IP Phone firmware (SIP)", f"10.10.10.{40+i}", "cisco", USER_NET,
        "sip/5060 rtp", "DHCP reservation; registers to PBX1")

# DHCP pool 10.10.10.100 - 10.10.10.199 (workstations)
for i in range(1, 76):
    add(f"EXL-WS-{i:03d}", "Windows workstation", "Windows 11 Enterprise", f"10.10.10.{100+i}", "dell", USER_NET,
        "dhcp client", "Domain-joined; DHCP lease from DC1")
for i in range(1, 21):
    add(f"EXL-MAC-{i:03d}", "macOS workstation", "macOS 15", f"10.10.10.{175+i}", "apple", USER_NET,
        "dhcp client", "Domain-joined; DHCP lease from DC1")

# --------------------------------------------------------------- validations
user_hosts = [h for h in hosts if h["subnet"] == USER_NET and not h["hostname"].startswith(("EXL-FW", "EXL-SW"))]
srv_hosts = [h for h in hosts if h["hostname"] in {s[0] for s in servers}]
assert len(user_hosts) == 125, len(user_hosts)
assert len(srv_hosts) == 13, len(srv_hosts)
ips = [h["ip"] for h in hosts]
assert len(ips) == len(set(ips)), "duplicate IP"
macs = [h["mac"] for h in hosts]
assert len(set(macs)) == len(macs), "duplicate MAC"  # FW1 has three interfaces, three MACs

if __name__ == "__main__":
    with open("inventory.json", "w") as f:
        json.dump({"org": ORG, "domain": DOMAIN, "hosts": hosts}, f, indent=2)
    with open("inventory.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(hosts[0].keys()))
        w.writeheader()
        w.writerows(hosts)
    print(f"{len(hosts)} entries, {len(user_hosts)} user hosts, {len(srv_hosts)} servers")
