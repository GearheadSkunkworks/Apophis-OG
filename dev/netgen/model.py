"""
Business-day model for Example Logistics: builds hosts from inventory.json
and schedules every conversation of the 05:00-21:00 capture window.

Usage: python -m netgen.model --scale 0.02 --out pilot.pcap
"""
import argparse
import json
import os
import random
import time
import zoneinfo
from datetime import datetime

from . import flows as F
from . import protocols as P
from .identity import DEFAULT as _TEMPLATE_IDENTITY, get_current as _current_identity, H
from .core import Host, Link, ArpModel, PcapWriter, Engine
from .tls import PKI, open_private

SEED = 20260914                 # reseeded per build by netgen.reseed_all()
rng = random.Random(SEED)
TZ = zoneinfo.ZoneInfo("America/New_York")


# ---------------------------------------------------------------------------------------
# The capture day
# ---------------------------------------------------------------------------------------
# Every scheduled event in the capture resolves through local(), so this is the ONE place
# that decides which calendar day the business day sits on. It used to be the literal
# datetime(2026, 9, 14), which meant a capture generated months later still claimed to be
# from that Monday -- and an offline upload to a sensor therefore landed days in the past,
# where nobody was looking.
#
# The default is **today**. set_capture_day() pins an explicit day instead, which matters for
# A/B validation: two runs are only byte-comparable if the date is the same, so the override
# is what keeps the "generate twice and diff" discipline possible once the default floats.
#
# The window constants below are module globals because model.py reads them 30 times; they
# are RECOMPUTED by set_capture_day() rather than being lazy, so nothing else has to change.
CAPTURE_DAY = None                      # (y, m, d) when pinned; None means "today"


def capture_day():
    """The (y, m, d) the capture sits on: whatever was pinned, else today."""
    if CAPTURE_DAY:
        return CAPTURE_DAY
    now = datetime.now(TZ)
    return (now.year, now.month, now.day)


def set_capture_day(day=None):
    """Pin the capture day. `day` may be 'YYYY-MM-DD', a date/datetime, or None for today.

    Returns the resolved (y, m, d). Raises ValueError on an unparseable string, because a
    typo that silently produced today's date would be discovered only after a 2.5-minute
    build -- or worse, not at all.
    """
    global CAPTURE_DAY, T_START, T_END, BIZ_START, BIZ_END, ADMIN_END
    if day is None or day == "":
        CAPTURE_DAY = None
    elif isinstance(day, str):
        try:
            d = datetime.strptime(day.strip(), "%Y-%m-%d")
        except ValueError:
            raise ValueError("capture date must be YYYY-MM-DD, got %r" % day) from None
        CAPTURE_DAY = (d.year, d.month, d.day)
    elif hasattr(day, "year"):
        CAPTURE_DAY = (day.year, day.month, day.day)
    else:
        raise ValueError("capture date must be YYYY-MM-DD or a date, got %r" % (day,))
    T_START, T_END = local(5), local(21)
    BIZ_START, BIZ_END = local(7), local(15)
    ADMIN_END = local(19)
    return capture_day()


def local(h, m=0, s=0):
    y, mo, d = capture_day()
    return datetime(y, mo, d, h, m, s, tzinfo=TZ).timestamp()


T_START, T_END = local(5), local(21)
BIZ_START, BIZ_END = local(7), local(15)
ADMIN_END = local(19)

INTERNET = [  # hostname, ip (RFC 5737 TEST-NET-2)
    ("www.example.com", "198.51.100.10"), ("cdn.example.net", "198.51.100.20"), ("updates.example.org", "198.51.100.30"),
    ("api.example.net", "198.51.100.40"), ("news.example.org", "198.51.100.50"), ("mail.example.com", "198.51.100.60"),
    ("maps.example.com", "198.51.100.70"), ("video.example.net", "198.51.100.80"), ("docs.example.org", "198.51.100.90"),
    ("shop.example.com", "198.51.100.100"), ("weather.example.net", "198.51.100.110"), ("social.example.org", "198.51.100.120"),
    ("swcdn.example.net", "198.51.100.130"), ("telemetry.example.org", "198.51.100.140"), ("login.example.com", "198.51.100.150"),
    # smart-board vendor (fictional, like every other host here) — firmware checks + the
    # post-update agent cloud link. Kept out of BROWSE_SITES so only the boards talk to it.
    ("updates.luminaboard-cloud.net", "198.51.100.160"), ("sync.luminaboard-cloud.net", "198.51.100.161"),
]
BROWSE_SITES = [n for n, _ in INTERNET
                if n not in ("updates.example.org", "swcdn.example.net",
                             "updates.luminaboard-cloud.net", "sync.luminaboard-cloud.net")]

# Real, legitimate SaaS / CDN / update / OCSP / connectivity destinations a real
# enterprise contacts constantly. Using real hostnames+IPs enriches the baseline so
# that malicious egress (RMM cloud, cloud-storage exfil) reads as a deviation, and so
# the platform device/role modeling and hardening detections have realistic material.
SAAS = [
    ("outlook.office365.com", "52.96.157.146"), ("teams.microsoft.com", "52.123.128.14"),
    ("login.microsoftonline.com", "20.190.155.1"), ("www.google.com", "142.251.150.119"),
    ("drive.google.com", "173.194.194.100"), ("slack.com", "18.216.36.190"),
    ("wss-primary.slack.com", "18.190.38.130"), ("zoom.us", "170.114.52.2"),
    ("github.com", "140.82.114.3"), ("api.github.com", "140.82.114.6"),
    ("objects.githubusercontent.com", "185.199.108.133"), ("www.dropbox.com", "162.125.3.18"),
    ("cdn.jsdelivr.net", "104.17.207.5"), ("fonts.gstatic.com", "192.178.212.94"),
    ("www.bing.com", "23.195.81.145"), ("aax.amazon-adsystem.com", "18.238.120.20"),
    ("www.cloudflare.com", "104.16.123.96"),
]
UPDATE_HOSTS = [
    ("update.googleapis.com", "64.233.181.100"), ("swscan.apple.com", "23.60.175.11"),
]
OCSP_HOSTS = [
    ("ocsp.digicert.com", "23.11.32.159"), ("ocsp.sectigo.com", "104.18.38.233"),
    ("ocsp.pki.goog", "173.194.193.94"), ("crl.microsoft.com", "23.1.254.211"),
]
CONNCHECK = [
    ("www.msftconnecttest.com", "23.51.25.143"), ("connectivitycheck.gstatic.com", "209.85.145.94"),
]
# Consumer cloud. Staff use these from their desks all day and a corporate capture that
# contains none of it is not a corporate capture. **Workstations only** — a domain controller
# streaming music is not realism, it is a bug, so nothing here is ever scheduled for a server.
CONSUMER = [
    ("www.youtube.com", "142.250.190.14"), ("rr3---sn-8xgp1vo-p5qe.googlevideo.com", "173.194.55.72"),
    ("i.ytimg.com", "142.250.191.182"),
    ("open.spotify.com", "35.186.224.25"), ("audio-fa.scdn.co", "35.186.224.47"),
    ("apresolve.spotify.com", "35.186.224.53"),
    ("music.apple.com", "17.253.55.203"), ("audio-ssl.itunes.apple.com", "17.253.19.201"),
    ("www.instagram.com", "157.240.229.174"), ("scontent.cdninstagram.com", "157.240.22.63"),
    ("www.facebook.com", "157.240.229.35"), ("static.xx.fbcdn.net", "157.240.229.23"),
    ("www.google.com", "142.251.150.100"), ("mail.google.com", "142.251.163.18"),
    ("www.reddit.com", "151.101.65.140"), ("www.linkedin.com", "13.107.42.14"),
    ("www.netflix.com", "54.155.178.5"), ("api.x.com", "104.244.42.65"),
    ("www.amazon.com", "52.94.236.248"), ("www.tiktok.com", "23.203.121.32"),
]

# Cloud generative-AI platforms. Increasingly the single most interesting egress category in a
# corporate capture: it is where data actually leaves, it is usually unsanctioned, and it looks
# exactly like ordinary HTTPS. **Workstations only**, for the same reason as CONSUMER.
GENAI = [
    ("claude.ai", "160.79.104.10"), ("api.anthropic.com", "160.79.104.11"),
    ("chatgpt.com", "104.18.32.47"), ("api.openai.com", "162.159.140.245"),
    ("cdn.oaistatic.com", "104.18.33.47"),
    ("gemini.google.com", "142.250.190.78"), ("generativelanguage.googleapis.com", "142.250.191.74"),
    ("grok.x.ai", "162.159.140.238"), ("api.x.ai", "104.18.34.47"),
    ("copilot.microsoft.com", "20.231.239.246"), ("api.githubcopilot.com", "140.82.113.22"),
    ("www.perplexity.ai", "104.18.36.47"), ("api.mistral.ai", "34.36.104.101"),
    ("huggingface.co", "3.171.153.58"),
]

# Operating-system update services the SERVERS reach, outside the internal network. There is no
# internal WSUS in this environment, so every server patches directly from its vendor — which
# is what makes this traffic externally destined and worth modelling separately from the
# workstation update path.
WIN_SERVER_UPDATE = [
    ("windowsupdate.microsoft.com", "23.46.229.30"),
    ("fe2cr.update.microsoft.com", "20.43.166.128"),
    ("download.windowsupdate.com", "23.46.226.114"),
    ("tlu.dl.delivery.mp.microsoft.com", "152.199.19.161"),
    ("ctldl.windowsupdate.com", "23.46.227.31"),
]
LINUX_SERVER_UPDATE = [
    ("archive.ubuntu.com", "185.125.190.83"), ("security.ubuntu.com", "185.125.190.81"),
    ("deb.debian.org", "151.101.66.132"), ("mirrors.rockylinux.org", "199.232.18.49"),
]

INTERNET += (SAAS + UPDATE_HOSTS + OCSP_HOSTS + CONNCHECK
             + CONSUMER + GENAI + WIN_SERVER_UPDATE + LINUX_SERVER_UPDATE)

CONSUMER_SITES = [n for n, _ in CONSUMER]
GENAI_SITES = [n for n, _ in GENAI]
WIN_UPDATE_SITES = [n for n, _ in WIN_SERVER_UPDATE]
LINUX_UPDATE_SITES = [n for n, _ in LINUX_SERVER_UPDATE]

SAAS_SITES = [n for n, _ in SAAS]
OCSP_SITES = [n for n, _ in OCSP_HOSTS]
CONNCHECK_SITES = [n for n, _ in CONNCHECK]

# A few CDN answer IPs that the large "long tail" of DNS names resolve to.
CDN_ANSWER_IPS = ["104.17.207.5", "151.101.1.69", "185.199.108.133", "142.251.150.119",
                  "13.107.42.14", "104.16.123.96", "23.11.32.159"]
# The long tail of distinct FQDNs a browser touches in a day (ads, analytics, CDNs,
# subresources). Names only — they resolve to CDN_ANSWER_IPS. Drives DNS breadth.
NOISE_DNS = [
    "www.googletagmanager.com", "www.google-analytics.com", "analytics.tiktok.com",
    "px.ads.linkedin.com", "connect.facebook.net", "static.hotjar.com", "cdn.segment.com",
    "js.stripe.com", "cdnjs.cloudflare.com", "ajax.googleapis.com", "unpkg.com",
    "fonts.googleapis.com", "s3.amazonaws.com", "cloudfront.net", "d1.awsstatic.com",
    "telemetry.mozilla.org", "incoming.telemetry.mozilla.org", "settings-win.data.microsoft.com",
    "v10.events.data.microsoft.com", "self.events.data.microsoft.com", "watson.telemetry.microsoft.com",
    "clientservices.googleapis.com", "safebrowsing.googleapis.com", "optimizationguide-pa.googleapis.com",
    "push.services.mozilla.com", "content-autofill.googleapis.com", "edge.microsoft.com",
    "assets.adobedtm.com", "cdn.cookielaw.org", "sc-static.net", "b-graph.facebook.com",
    "graph.microsoft.com", "substrate.office.com", "roaming.officeapps.live.com",
    "config.edge.skype.com", "nexusrules.officeapps.live.com", "www.office.com",
    "outlook.office.com", "res.cdn.office.net", "shed.dual-low.s-part-0017.t-0009.t-msedge.net",
]
# Plausible typos / stale domains that come back NXDOMAIN in every real network.
NX_CANDIDATES = [
    "intranet.corp.example.locall", "shraepoint.corp.example.local", "maiil.google.com",
    "www.gooogle.com", "outlok.office365.com", "githubb.com", "slak.com",
    "wpad.corp.example.local", "isatap.corp.example.local", "teredo.ipv6.microsoft.com",
    "old-fileserver.corp.example.local", "printserver2.corp.example.local",
]


def _prefix_of(cidr):
    """'10.10.20.0/24' -> '10.10.20' (the /24 network part)."""
    return cidr.split("/", 1)[0].rsplit(".", 1)[0]


# OT cadences. These are the numbers the packet budget is built on and the numbers the
# baseline-ot diagram draws its lanes from, so they live here rather than inline: 12 PLCs on a
# 2 s poll is ~1.04M packets across the window, 78% of everything the OT subnet emits. At 1 s
# it is 2.07M -- a fifth of the whole capture from 12 of 238 assets -- which is why the default
# is 2 and why the UI warns below 1.5.
OT_POLL_S = 2.0                  # level 1 supervisory poll
OT_DNP3_POLL_S = 10.0            # historian / RTU integrity poll
OT_BACNET_COV_S = 45.0           # building-management change-of-value

OT_SIDES = ("ot", "ops", "idmz")          # cell/area (L0-2), site operations (L3), IDMZ (L3.5)

#: OT process protocols the OT subnet can emit, in display order. Modbus/DNP3/BACnet are the
#: long-standing baseline (what a build emits when no selection is given); the rest were ported
#: from OpenGenerator (2026-10) and are emitted only when explicitly selected. Synchrophasor and
#: ICCP/TASE.2 are electric-utility protocols (OT_ENERGY_PROTOCOLS). Example has no industry
#: setting, so they carry no extra gate here: selecting them is enough.
OT_PROCESS_PROTOCOLS = ("modbus", "dnp3", "bacnet", "ethernetip", "s7comm", "opcua",
                        "synchrophasor", "iccp")
OT_BASELINE_PROTOCOLS = ("modbus", "dnp3", "bacnet")
OT_ENERGY_PROTOCOLS = ("synchrophasor", "iccp")
#: id -> (label, primary port), for front-ends and CLI help
OT_PROTOCOL_INFO = {
    "modbus": ("Modbus/TCP", 502),
    "dnp3": ("DNP3", 20000),
    "bacnet": ("BACnet/IP", 47808),
    "ethernetip": ("EtherNet/IP (CIP)", 44818),
    "s7comm": ("S7comm", 102),
    "opcua": ("OPC UA", 4840),
    "synchrophasor": ("Synchrophasor (C37.118)", 4712),
    "iccp": ("ICCP / TASE.2", 102),
}


def normalize_ot_protocols(protocols):
    """None -> None (the baseline). Otherwise a tuple of known ids in OT_PROCESS_PROTOCOLS order,
    duplicates dropped. Accepts a list/tuple/set or a comma-separated string. Unknown ids raise
    ValueError naming them and the valid choices."""
    if protocols is None:
        return None
    if isinstance(protocols, str):
        protocols = [p for p in protocols.split(",")]
    wanted = [str(p).strip().lower() for p in protocols if str(p).strip()]
    unknown = sorted(set(p for p in wanted if p not in OT_PROCESS_PROTOCOLS))
    if unknown:
        raise ValueError("unknown OT protocol(s): %s (choose from: %s)"
                         % (", ".join(unknown), ", ".join(OT_PROCESS_PROTOCOLS)))
    return tuple(p for p in OT_PROCESS_PROTOCOLS if p in wanted)


def remap_inventory(inv, user_net=None, server_net=None, ot_nets=None):
    """Re-address the two internal /24s in a loaded inventory, in place.

    Each host keeps its own last octet, so the topology is bit-for-bit the same shape:
    same 144 hosts, same MACs, same roles, same services, same host numbering (the
    compromised foothold EXL-WS-047 stays at <user-net>.147). Only the network part moves.

    The firewall's three interfaces are listed inside-A (user), inside-B (server), outside
    (WAN) — the same ordering build_hosts already relies on — so they identify the two
    internal subnets without hard-coding an address. The WAN interface and every external
    address, including the real malicious indicators, are deliberately left alone.
    """
    ot_nets = ot_nets or {}
    sided = {h["gw_side"]: h for h in inv["hosts"] if h.get("gw_side")}
    if sided:
        # gw_side-tagged inventory: gateway legs may belong to EXL-FW1 or EXL-OTFW1, so the OT
        # subnets are discovered by tag, not by position. "ot"/"ops" sit on EXL-OTFW1, "idmz"
        # on EXL-FW1; the EXL-OTFW1 IDMZ leg (idmz_ot) shares the idmz /24 and is re-addressed
        # by the subnet-match loop below, so it needs no side of its own here.
        if "user" not in sided or "server" not in sided:
            raise ValueError("gw_side-tagged inventory must tag both 'user' and 'server' legs")
        old = {"user": sided["user"]["subnet"], "server": sided["server"]["subnet"]}
        new = {"user": user_net or old["user"], "server": server_net or old["server"]}
        sides = ["user", "server"]
        for side in OT_SIDES:                 # cell/area, site operations, IDMZ
            leg = sided.get(side)
            if leg:
                old[side] = leg["subnet"]
                new[side] = ot_nets.get(side) or old[side]
                sides.append(side)
    else:
        fw = [h for h in inv["hosts"] if h["hostname"] == H("FW1")]
        if len(fw) < 3:
            raise ValueError(f"expected at least 3 {H('FW1')} interface entries in the inventory, found {len(fw)}")
        # inside-A (user), inside-B (server), outside (WAN), then the optional OT legs in order:
        # inside-C cell/area, inside-D site operations, inside-E IDMZ.
        old = {"user": fw[0]["subnet"], "server": fw[1]["subnet"]}
        new = {"user": user_net or old["user"], "server": server_net or old["server"]}
        sides = ["user", "server"]
        for i, side in enumerate(OT_SIDES):
            if len(fw) > 3 + i:
                old[side] = fw[3 + i]["subnet"]
                new[side] = ot_nets.get(side) or old[side]
                sides.append(side)
    pfx = [_prefix_of(new[k]) for k in sides]
    if len(set(pfx)) != len(pfx):
        raise ValueError("every emulated network must be a distinct /24")

    moved = {k: 0 for k in sides}
    for h in inv["hosts"]:
        for side in sides:
            if h["subnet"] == old[side]:
                h["ip"] = _prefix_of(new[side]) + "." + h["ip"].rsplit(".", 1)[1]
                h["subnet"] = new[side]
                moved[side] += 1
                break
    # keep free-text notes that name a subnet coherent with the new addressing
    for h in inv["hosts"]:
        for side in sides:
            if old[side] != new[side] and h.get("notes"):
                h["notes"] = h["notes"].replace(old[side], new[side]).replace(
                    _prefix_of(old[side]) + ".", _prefix_of(new[side]) + ".")
    out = {"user": new["user"], "server": new["server"], "moved": moved}
    for side in OT_SIDES:
        if side in new:
            out[side] = new[side]
    return out



_NX_TEMPLATE = None


def apply_identity(identity):
    """Rewrite module-level content that embeds the company domain -- the DNS NX-candidate list
    -- for the build's identity (called from netgen.reseed_all). No-op for the default."""
    global NX_CANDIDATES, _NX_TEMPLATE
    if _NX_TEMPLATE is None:
        _NX_TEMPLATE = list(NX_CANDIDATES)          # capture the template (default domain) once
    sd = _TEMPLATE_IDENTITY.domain
    NX_CANDIDATES = [c.replace(sd, identity.domain) for c in _NX_TEMPLATE]


def rename_inventory(inv, identity, source=None):
    """Re-brand the loaded host model from the template identity to `identity`: the hostname
    prefix, FQDNs, org and domain, and any embedded prefix/domain in services/notes. A no-op
    when `identity` matches the template (the committed inventory.json is written in the
    template's tokens), so a default build is byte-for-byte unchanged."""
    source = source or _TEMPLATE_IDENTITY
    sp, sd = source.prefix, source.domain
    tp, td = identity.prefix, identity.domain
    inv["org"] = identity.org
    inv["domain"] = identity.domain
    if (tp, td, identity.org) == (sp, sd, source.org):
        return inv
    for h in inv.get("hosts", []):
        hn = h.get("hostname", "")
        if hn.startswith(sp):
            hn = tp + hn[len(sp):]
            h["hostname"] = hn
        h["fqdn"] = "%s.%s" % (hn.lower(), td)
        for k in ("services", "notes", "role"):
            v = h.get(k)
            if isinstance(v, str) and v:
                h[k] = v.replace(sp, tp).replace(sp.lower(), tp.lower()).replace(sd, td)
    return inv


def build_hosts(inv_path, user_net=None, server_net=None, ot_nets=None, with_ot=False,
                identity=None):
    """Build the host table. `with_ot` False drops every OT asset before anything is
    constructed, so a capture without the OT subnet contains no trace of it -- not in the
    host table, not in the diagrams, and not in the asset count deps.py reports."""
    with open(inv_path) as _invf:
        inv = json.load(_invf)
    if not with_ot:
        # Every OT asset carries a "purdue" key, including the three extra firewall legs, so one
        # filter removes the whole feature. An inventory entry with no traffic behind it would
        # still be counted by deps.py and drawn by the topology, which is worse than absent.
        inv["hosts"] = [h for h in inv["hosts"] if not h.get("purdue")]
    if user_net or server_net or ot_nets:
        remap_inventory(inv, user_net, server_net, ot_nets)
    rename_inventory(inv, identity or _current_identity())
    hosts = {}
    sided = any(h.get("gw_side") for h in inv["hosts"])
    routing = None
    if not sided:
        # Legacy / single-firewall inventory: EXL-FW1 lists every inside interface in order.
        # Unchanged behaviour, byte for byte.
        fw = []
        for h in inv["hosts"]:
            obj = Host(h["hostname"], h["ip"], h["mac"], h["os"], h["role"], h["subnet"], h["fqdn"])
            if h["hostname"] == H("FW1"):
                fw.append(obj)
            else:
                hosts[h["hostname"]] = obj
        fw_a, fw_b, fw_out = fw[0], fw[1], fw[2]
        fw_extra = fw[3:]                  # inside-C / -D / -E when the OT subnet is enabled
        hosts["FW-A"], hosts["FW-B"], hosts["FW-OUT"] = fw_a, fw_b, fw_out
        for nm, obj in zip(("FW-OT", "FW-OPS", "FW-IDMZ"), fw_extra, strict=False):
            hosts[nm] = obj
    else:
        # gw_side-tagged inventory: gateway legs may belong to either firewall. Construct every
        # host in inventory order (so the RNG stream is untouched), bucketing the tagged legs.
        gw = {}
        for h in inv["hosts"]:
            obj = Host(h["hostname"], h["ip"], h["mac"], h["os"], h["role"], h["subnet"], h["fqdn"])
            side = h.get("gw_side")
            if side:
                gw[side] = obj
            else:
                hosts[h["hostname"]] = obj
        fw_a, fw_b, fw_out = gw["user"], gw["server"], gw["outside"]
        hosts["FW-A"], hosts["FW-B"], hosts["FW-OUT"] = fw_a, fw_b, fw_out
        idmz, idmz_ot = gw.get("idmz"), gw.get("idmz_ot")   # IDMZ north (EXL-FW1) / south (EXL-OTFW1)
        cell, ops = gw.get("ot"), gw.get("ops")             # cell/area & site-ops behind EXL-OTFW1
        fw_extra = [x for x in (idmz, idmz_ot, cell, ops) if x is not None]
        for nm, obj in (("FW-IDMZ", idmz), ("FW-OT", cell), ("FW-OPS", ops), (H("OTFW1"), idmz_ot)):
            if obj is not None:
                hosts[nm] = obj
        if idmz_ot is not None:            # the dual-firewall IDMZ sandwich is present
            zone = {fw_a.ipb[:3]: 0, fw_b.ipb[:3]: 0, idmz.ipb[:3]: 1}
            default_gw = {fw_a.ipb[:3]: fw_a, fw_b.ipb[:3]: fw_b, idmz.ipb[:3]: idmz}
            for leg in (cell, ops):        # cell/area and site-ops default-route via EXL-OTFW1
                if leg is not None:
                    zone[leg.ipb[:3]] = 2
                    default_gw[leg.ipb[:3]] = leg
            routing = {"zone": zone, "default_gw": default_gw, "idmz_pfx": idmz.ipb[:3],
                       "idmz_north": idmz, "idmz_south": idmz_ot}
    sites = {}
    for name, ip in INTERNET:
        # internet servers: Linux-like TTL 64, several router hops away, MAC never seen (firewall's MAC is)
        s = Host(name.upper(), ip, "02:00:00:%02x:%02x:%02x" % tuple(rng.randrange(256) for _ in range(3)), "linux", "internet host", "198.51.100.0/24", name)
        s.hops = rng.randint(9, 17)
        sites[name] = (name, s)
    resolvers = []
    for ip in ("198.51.100.2", "198.51.100.3"):
        r = Host("ISP-RESOLVER", ip, "02:00:00:%02x:%02x:%02x" % tuple(rng.randrange(256) for _ in range(3)), "linux", "isp resolver", "198.51.100.0/24", "resolver.isp.example")
        r.hops = rng.randint(6, 10)
        resolvers.append(r)
    return hosts, Link(fw_a, fw_b, fw_out, *fw_extra, routing=routing), sites, resolvers


def gaussian_time(mean, sd, lo, hi):
    return min(hi, max(lo, rng.gauss(mean, sd)))


# ---------------------------------------------------------------- baseline contributors (v5b)
# The business day is assembled from ordered "contributors" rather than a hardcoded method
# list, so a capability module can add a baseline sub-generator (e.g. a new always-on service)
# at a chosen point in the sequence without editing Day.build(). Each is fn(day); `order` fixes
# the position. The built-ins below reproduce the historical sequence exactly, so the no-module
# baseline is byte-for-byte unchanged and still pins at 466,343.
BASELINE_CONTRIBUTORS = []           # list of (order, name, fn(day))


def register_baseline(name, order):
    """Register a baseline-day contributor fn(day). Lower `order` runs earlier."""
    def deco(fn):
        BASELINE_CONTRIBUTORS.append((order, name, fn))
        return fn
    return deco


#: OT process protocols that the OT-subnet options can toggle. Modbus/DNP3/BACnet are the long-
#: standing baseline; the rest were added when the platform began parsing them (2026-10). Synchrophasor
#: and ICCP/TASE.2 are electric-utility only and additionally gated to the Energy industry.
OT_PROCESS_PROTOCOLS = ("modbus", "dnp3", "bacnet", "ethernetip", "s7comm", "opcua",
                        "synchrophasor", "iccp")
OT_ENERGY_PROTOCOLS = ("synchrophasor", "iccp")

# ---- OT identity. The OT forest (P.OT_REALM, EXL-OTDC1) has its own accounts, separate from the
# enterprise: one named person per station, and three operators per HMI who rotate with the shift
# (night until 06:00, day 06:00-14:00, swing from 14:00). The SCADA servers run under a service
# account. Engineers coming in from IT use a separate OT account ("ot-" + their enterprise name).
OT_STATION_ACCOUNTS = {
    "HMI1": ("hgarcia", "jmorales", "tnguyen"),     # (night, day, swing) operators
    "HMI2": ("efischer", "rpatel", "lchen"),
    "HMI3": ("sali", "dwilliams", "asantos"),
    "HMI4": ("pmurphy", "mokafor", "bkowalski"),
    "OTENG1": "kbrandt",                            # cell controls engineer
    "ENGWS1": "mrossi",                             # level 3 engineers
    "ENGWS2": "sjohansson",
    "OTTERM1": "cdupont",                           # operations supervisor
}
OT_SCADA_SERVICE_ACCOUNT = "svc-scada"
OT_REMOTE_ACCOUNT_PREFIX = "ot-"


def ot_account_at(station, t):
    """The OT account signed in at `station` at time t: the shift operator on an HMI, otherwise the
    station's named owner (falls back to the enterprise naming for an unlisted station)."""
    pre = _current_identity().prefix
    acct = OT_STATION_ACCOUNTS.get(station[len(pre):] if station.startswith(pre) else station)
    if acct is None:
        return P.username_for(station)
    if isinstance(acct, str):
        return acct
    night, day, swing = acct
    return night if t < local(6) else day if t < local(14) else swing


class Day:
    def __init__(self, ctx: F.Ctx, engine: Engine, scale: float, ot_protocols=None):
        self.ctx, self.eng, self.scale = ctx, engine, scale
        # Which OT process protocols to emit. None = all of them (the default; a plain build and the
        # CLI keep every protocol). A set restricts emission to the chosen subset -- the GUI's OT
        # protocol checkboxes drive this. Only affects the OT subnet, which is off in the pin build.
        self.ot_protocols = None if ot_protocols is None else set(ot_protocols)
        h = ctx.h
        self.workstations = [x for x in h.values() if x.name.startswith((H("WS"), H("MAC")))]
        self.phones = [x for x in h.values() if x.name.startswith(H("PH"))]
        self.aps = [x for x in h.values() if x.name.startswith(H("AP"))]
        self.printers = [x for x in h.values() if x.name.startswith(H("PRN"))]
        self.boards = [x for x in h.values() if x.name.startswith(H("SB"))]
        srv_pfx = ctx.link.server_prefix          # configurable subnets: never hard-code this
        self.servers = [x for x in h.values()
                        if x.ipb[:3] == srv_pfx and x.name not in (H("SENSOR1"), H("SWB1"), "FW-B")]
        self.win_servers = [x for x in self.servers if x.ttl == 128]
        self.lin_servers = [x for x in self.servers if x.ttl == 64]
        # ---- OT groups. Empty lists when the subnet is off, so every ot_* method below is a
        # ---- no-op loop and the capture is packet-identical to one built without the feature.
        g = lambda pre: [x for x in h.values() if x.name.startswith(pre)]
        self.plcs = g(H("PLC-"))
        self.rtus = g(H("RTU-"))
        self.sis = g(H("SIS-"))
        self.hmis = g(H("HMI"))
        self.scada = g(H("SCADA"))
        self.bacnet = g(H("BAC-")) + g(H("ENV-"))
        self.ot_switches = g(H("OTSW-")) + g(H("OTUPS-"))
        self.l3_servers = [x for x in h.values()
                           if x.name.startswith((H("MES"), H("HIST"), H("BATCH"), H("LIMS"),
                                                 H("OTDC"), H("OTFS"), H("OTWSUS"), H("OTAV"),
                                                 H("OTMON"), H("OTBKP"), H("OTLOG")))]
        self.eng_ws = g(H("ENGWS")) + g(H("OTENG"))
        self.ot_terms = g(H("OTTERM"))
        self.idmz = g(H("IDMZ-"))
        self.ot_on = bool(self.plcs)
        if self.ot_on:
            # tickets an OT host requests from EXL-OTDC1 on its own behalf: the station's OT account,
            # or a server's computer account (NAME$) -- see F.kerberos_tgs
            ctx.ot_account = lambda name, t: (ot_account_at(name, t) if name in OT_STATION_ACCOUNTS
                                              else name + "$")

    def add(self, ts, fn, tag, *a, **kw):
        if T_START <= ts < T_END:
            self.eng.schedule(ts, lambda: fn(self.ctx, *a, ts=ts, **kw), tag)

    # ------------------------------------------------------------ infrastructure
    def infrastructure(self):
        ctx, h = self.ctx, self.ctx.h
        for ap in self.aps:
            self.eng.schedule(T_START + rng.uniform(0, 5), lambda ap=ap: F.capwap_ap(ctx, ap, T_START, T_END), "capwap")
        # SNMP polling every 5 minutes from LOG1
        devices = [h[H("SWA1")], h[H("SWB1")], h["FW-B"]] + self.aps + self.printers
        t = T_START + rng.uniform(0, 300)
        while t < T_END:
            for i, d in enumerate(devices):
                self.add(t + i * rng.uniform(0.2, 1.5), F.snmp_poll, "snmp", h[H("LOG1")], d)
            t += 300
        # NTP: Linux/embedded every ~1024 s, Windows hourly
        for x in list(h.values()):
            if x.name in (H("NTP1"), H("SENSOR1")) or x is h["FW-A"] or x is h["FW-OUT"] or x.name.startswith((H("WS"), H("MAC"))):
                continue
            interval = 3600 if x.ttl == 128 else 1024
            t = T_START + rng.uniform(0, interval)
            while t < T_END:
                self.add(t, F.ntp_exchange, "ntp", x)
                t += interval * rng.uniform(0.98, 1.02)
        # syslog: firewall traffic logs (rate follows the day), switches, servers
        t = T_START
        while t < T_END:
            rate = 1.0 if t < BIZ_START else (5.0 if t < BIZ_END else (2.0 if t < ADMIN_END else 0.7))
            t += rng.expovariate(rate * self.scale / 60 * 12)
            self.add(t, F.syslog_msg, "syslog", h["FW-B"])
        for sw in (h[H("SWA1")], h[H("SWB1")]):
            t = T_START + rng.uniform(0, 600)
            while t < T_END:
                self.add(t, F.syslog_msg, "syslog", sw)
                t += rng.expovariate(1 / 900)
        for srv in self.servers:
            t = T_START + rng.uniform(0, 600)
            while t < T_END:
                self.add(t, F.syslog_msg, "syslog", srv)
                t += rng.expovariate(1 / 420)
        # AD replication every 15 min
        t = T_START + rng.uniform(0, 900)
        while t < T_END:
            self.add(t, F.ad_replication, "ad-repl")
            t += 900 + rng.uniform(-20, 20)
        # smart-board mDNS is scheduled in smartboards(), alongside the vendor/MCP traffic
        # phones: registered at start, re-register every hour
        for ph in self.phones:
            t = T_START + rng.uniform(0, 60)
            while t < T_END:
                self.add(t, F.sip_register, "sip", ph)
                t += 3600 * rng.uniform(0.97, 0.995)
        # SQL connection pools for the two web apps (WEB1 intranet, WEB2 LOB)
        self.eng.schedule(local(5, 30), lambda: F.sql_pool_open(ctx, local(5, 30)), "tds")
        self.eng.schedule(local(20, 55), lambda: F.sql_pool_close(ctx, local(20, 55)), "tds")
        self.eng.schedule(local(5, 32), lambda: F.sql_pool_open(ctx, local(5, 32), web=H("WEB2"), svc="svc_shipping", pool=ctx.sql_pool2), "tds")
        self.eng.schedule(local(20, 56), lambda: F.sql_pool_close(ctx, local(20, 56), pool=ctx.sql_pool2), "tds")
        # periodic internal DNS from servers (health checks, replication partners)
        for srv in self.servers:
            t = T_START + rng.uniform(0, 300)
            while t < T_END:
                target = rng.choice(self.servers)
                self.add(t, F.resolve_internal, "dns", srv, target)
                t += rng.expovariate(1 / 240)
        # printers do their own SNMP-free chatter: nothing; print server pings printers hourly
        t = T_START + rng.uniform(0, 3600)
        while t < T_END:
            for p in self.printers:
                self.add(t + rng.uniform(0, 30), F.icmp_ping, "icmp", h[H("PRINT1")], p, count=2)
            t += 3600

    # ------------------------------------------------------------- workstations
    def workstation_day(self, ws):
        ctx = self.ctx
        early = rng.random() < 0.05
        arrive = rng.uniform(local(6), local(6, 45)) if early else gaussian_time(local(7, 30), 25 * 60, local(6, 45), local(8, 40))
        r = rng.random()
        if r < 0.80:
            leave = gaussian_time(local(15, 5), 25 * 60, local(14, 15), local(16, 0))
        elif r < 0.95:
            leave = rng.uniform(local(15, 30), local(17, 0))
        else:
            leave = rng.uniform(local(17), local(19))
        t = arrive
        # boot / logon sequence
        if rng.random() < 0.75:
            self.add(t, F.dhcp_acquire, "dhcp", ws)
            self.add(t + 4 * 3600 * rng.uniform(0.98, 1.02), F.dhcp_renew, "dhcp", ws)
            t += rng.uniform(2, 4)
        else:
            self.add(t, lambda c, w, ts: c.arp.gratuitous(w, ts), "arp", ws)
        if ctx.is_windows(ws):
            self.add(t + 0.5, F.nbns_register, "nbns", ws)
        self.add(t + 1.0, F.dns_lookup, "dns", ws, f"_ldap._tcp.dc._msdcs.{_current_identity().domain}", qtype=33,
                 answers=[(33, F.P.srv_rdata(0, 100, 389, _current_identity().fqdn("DC1"))), (33, F.P.srv_rdata(0, 100, 389, _current_identity().fqdn("DC2")))])
        self.add(t + 1.2, F.resolve_internal, "dns", ws, ctx.h[H("DC1")])
        self.add(t + 1.4, F.cldap_ping, "cldap", ws)
        self.add(t + 1.8, F.kerberos_as, "kerberos", ws, user=ws.name + "$")
        self.add(t + 2.5, F.ldap_session, "ldap", ws, queries=2)
        self.add(t + 4.0, F.smb_sysvol_gpo, "smb", ws)
        self.add(t + 7.0, F.ntp_exchange, "ntp", ws)
        # user logon. ~4% of the time it is fat-fingered once and succeeds on the retry, which
        # is what an ordinary day actually looks like — a directory whose every logon succeeds
        # is the implausible case, not this one.
        d = self.ctx.dir
        acct = d.for_host(ws) if d else None
        uname = acct.name if acct else None
        logon_at = t + rng.uniform(15, 90)
        if d and acct and acct.state == "ok" and rng.random() < d.fumble_rate:
            self.add(logon_at, F.kerberos_as_outcome, "kerberos-fail", ws,
                     user=uname, outcome="bad_password")
            logon_at += rng.uniform(4, 25)
        self.add(logon_at, F.kerberos_as, "kerberos", ws)     # user logon
        self.add(t + rng.uniform(20, 95), F.ldap_session, "ldap", ws, queries=4)
        self.add(t + rng.uniform(40, 200), F.intranet_session, "http", ws)
        self.add(t + rng.uniform(60, 400), F.name_noise, "name-noise", ws)
        t += rng.uniform(120, 600)
        # daytime activity loop
        mean_gap = 900 / self.scale
        while t < leave:
            lunch = local(11, 30) <= t < local(12, 30)
            gap = rng.expovariate(1 / (mean_gap * (2.5 if lunch else 1.0)))
            t += gap
            if t >= leave:
                break
            r = rng.random()
            if r < 0.17:
                self.add(t, F.intranet_session, "http", ws)
            elif r < 0.24:
                self.add(t, F.intranet_session, "http", ws, web=H("WEB2"), host=f"shipping.{_current_identity().domain}", pool=ctx.sql_pool2)
            elif r < 0.52:
                site = ctx.sites[rng.choice(BROWSE_SITES)]
                # a page, not a single connection: origin plus the CDN/font/analytics hosts it
                # pulls in. Most navigations fan out; a few are bare API or asset fetches.
                if rng.random() < 0.75:
                    self.add(t, F.page_load, "https", ws, site)
                else:
                    self.add(t, F.https_session, "https", ws, site)
            elif r < 0.70:
                self.add(t, F.smb_file_activity, "smb", ws, ctx.h[H("FILE1")])
            elif r < 0.78:
                self.add(t, F.dns_lookup, "dns", ws, rng.choice(BROWSE_SITES), external=True, answers=[(1, ctx.sites[rng.choice(BROWSE_SITES)][1].ipb)])
            elif r < 0.84:
                self.add(t, F.print_job, "print", ws)
            elif r < 0.92:
                self.add(t, F.name_noise, "name-noise", ws)
            elif r < 0.96:
                self.add(t, F.ldap_session, "ldap", ws, queries=rng.randint(1, 3))
            else:
                self.add(t, F.smb_sysvol_gpo, "smb", ws)   # 90-minute GPO refresh
            # hourly things independent of the loop
        for tt in range(int(arrive) + 3600, int(leave), 3600):
            self.add(tt + rng.uniform(-60, 60), F.ntp_exchange, "ntp", ws)
            self.add(tt + rng.uniform(0, 300), F.dns_lookup, "dns", ws, "telemetry.example.org", external=True, answers=[(1, ctx.sites["telemetry.example.org"][1].ipb)])
        # OS updates: morning delta for most, larger download in the admin window if still on
        if leave > local(15, 20) and rng.random() < 0.85:
            self.add(rng.uniform(local(15, 5), min(leave - 300, local(17))), F.patch_download, "patch", ws, total=int(rng.uniform(4e6, 20e6) * self.scale))
        elif rng.random() < 0.5:
            self.add(rng.uniform(local(9), local(11)), F.patch_download, "patch", ws, total=int(rng.uniform(1e6, 4e6) * self.scale))
        # Re-authentication through the day: screen unlocks, a scheduled task, a mail client
        # renewing. Before this, every workstation authenticated exactly twice and then never
        # again, which is why an identity view of the capture looked empty.
        if uname:
            for _ in range(rng.randint(4, 10)):
                rt = rng.uniform(logon_at + 600, max(logon_at + 601, leave))
                if rt >= leave:
                    continue
                # an unlock gets mistyped at the same rate a logon does
                if acct.state == "ok" and rng.random() < d.fumble_rate:
                    self.add(rt, F.kerberos_as_outcome, "kerberos-fail", ws,
                             user=uname, outcome="bad_password")
                    rt += rng.uniform(3, 20)
                self.add(rt, F.kerberos_as_outcome, "kerberos", ws, user=uname, outcome="ok")
                # coming back to a locked screen usually means going back to whatever you were
                # using, which means a fresh service ticket
                if rng.random() < 0.4:
                    tgt, svc = rng.choice([(ctx.h[H("FILE1")], "cifs"), (ctx.h[H("WEB1")], "HTTP"),
                                           (ctx.h[H("DC1")], "ldap")])
                    self.add(rt + rng.uniform(0.5, 30), F.kerberos_tgs_refresh, "kerberos",
                             ws, svc, tgt)
        # telemetry beacon
        self.add(arrive + rng.uniform(600, 1800), F.https_session, "https", ws, ctx.sites["telemetry.example.org"], requests=1, sizes=[900])
        # rich real-world background noise while the user is logged on
        self.background_noise(ws, arrive, leave)

    # ------------------------------------------------------- background grey-noise
    def background_noise(self, ws, arrive, leave):
        """Realistic long-tail traffic a real endpoint emits: SaaS egress, broad DNS
        (A/AAAA/PTR/TXT + NXDOMAIN), OS connectivity probes, OCSP/CRL, update checks."""
        import socket as _sock
        ctx = self.ctx
        sc = self.scale
        span = max(1.0, leave - arrive)

        def pk(ip):
            return _sock.inet_aton(ip)

        # 1) SaaS / cloud app usage — a handful of real cloud destinations per user
        for _ in range(max(2, int(rng.uniform(6, 14) * sc))):
            t = arrive + rng.uniform(60, span)
            site = ctx.sites[rng.choice(SAAS_SITES)]
            self.add(t, F.https_session, "saas", ws, site, requests=rng.randint(2, 8))

        # 2) DNS long tail — the many distinct names a browser touches (A, with paired AAAA)
        for _ in range(max(6, int(rng.uniform(30, 70) * sc))):
            t = arrive + rng.uniform(30, span)
            name = rng.choice(NOISE_DNS)
            self.add(t, F.dns_query_ext, "dns-noise", ws, name, qtype=F.P.DNS_A,
                     answers=[(F.P.DNS_A, pk(rng.choice(CDN_ANSWER_IPS)))])
            if rng.random() < 0.4:
                self.add(t + 0.001, F.dns_query_ext, "dns-noise", ws, name, qtype=F.P.DNS_AAAA, answers=None)

        # 3) NXDOMAIN — typos, stale internal names, WPAD/ISATAP probes
        for _ in range(max(1, int(rng.uniform(2, 6) * sc))):
            t = arrive + rng.uniform(30, span)
            name = rng.choice(NX_CANDIDATES)
            internal = name.endswith(_current_identity().domain)
            self.add(t, (F.dns_lookup if internal else F.dns_query_ext), "dns-nx", ws, name, rcode=3, answers=None)

        # 4) TXT (SPF-style) and internal PTR lookups
        if rng.random() < 0.5:
            self.add(arrive + rng.uniform(60, span), F.dns_query_ext, "dns-noise", ws, rng.choice(["google.com", "microsoft.com", "github.com"]),
                     qtype=F.P.DNS_TXT, answers=[(F.P.DNS_TXT, F.P.txt_rdata(["v=spf1 include:_spf.google.com ~all"]))])
        for _ in range(max(1, int(2 * sc))):
            tgt = rng.choice(self.servers)
            rev = ".".join(reversed(tgt.ip.split("."))) + ".in-addr.arpa"
            self.add(arrive + rng.uniform(60, span), F.dns_lookup, "dns", ws, rev,
                     qtype=F.P.DNS_PTR, answers=[(F.P.DNS_PTR, F.P.ptr_rdata(tgt.fqdn))])

        # 5) OS connectivity probes every ~10-20 min
        t = arrive + rng.uniform(30, 120)
        while t < leave:
            self.add(t, F.connectivity_check, "conncheck", ws)
            t += rng.uniform(600, 1200)

        # 6) OCSP / CRL revocation checks (piggyback on TLS browsing)
        for _ in range(max(2, int(rng.uniform(4, 10) * sc))):
            self.add(arrive + rng.uniform(60, span), F.ocsp_check, "ocsp", ws)

        # 7) update-agent check-ins (a couple of hosts per day)
        if rng.random() < 0.4:
            self.add(arrive + rng.uniform(300, span), F.https_session, "update", ws,
                     ctx.sites[rng.choice([n for n, _ in UPDATE_HOSTS])], requests=rng.randint(1, 3))

    # ------------------------------------------------------------------- voice
    def smartboards(self):
        """Baseline smart-board behaviour — part of the normal day, not an incident module.

        Every board polls its vendor's firmware service over HTTPS through the day. One board
        (F.MCP_BOARD) is offered an update mid-morning, downloads it, and from that point on
        runs an MCP server: it advertises _mcp._tcp.local, is driven over plaintext HTTP by
        workstations and the admin jump host, and keeps a link to the vendor cloud.
        """
        h = self.ctx.h
        upd_at = local(*F.MCP_UPDATE_HM)
        board = h.get(H(F.MCP_BOARD))

        for sb in self.boards:
            # mDNS presence all day; the updated board also advertises its MCP endpoint
            t = T_START + rng.uniform(0, 240)
            while t < T_END:
                is_mcp = board is not None and sb is board and t >= upd_at
                self.add(t, F.smartboard_beacon, "mdns", sb, mcp=is_mcp)
                t += rng.uniform(280, 520)

            # firmware poll every ~2 h with jitter. The one board gets an offer at its slot.
            t = T_START + rng.uniform(300, 2400)
            while t < T_END:
                offer = (board is not None and sb is board
                         and upd_at - 1500 <= t < upd_at)     # the poll that returns the update
                self.add(t, F.smartboard_update_check, "sb-update", sb, offer=offer)
                t += rng.uniform(5400, 9000)

        if board is None:
            return

        # the update itself, then the agent comes up
        self.add(upd_at - 1500 + 6, F.smartboard_update_download, "sb-update", board)
        self.add(upd_at, F.smartboard_beacon, "mdns", board, mcp=True)

        # vendor cloud heartbeat from the agent, every ~10 min after the update
        t = upd_at + rng.uniform(20, 90)
        while t < T_END:
            self.add(t, F.smartboard_cloud_link, "mcp-cloud", board)
            t += rng.uniform(480, 780)

        # workstations that discovered the agent drive it through the rest of the day
        clients = rng.sample(self.workstations, min(len(self.workstations),
                                                    max(2, int(6 * self.scale) or 2)))
        for ws in clients:
            t = upd_at + rng.uniform(120, 2400)
            while t < T_END:
                self.add(t, F.mcp_session, "mcp", ws, board)
                t += rng.uniform(900, 3000)
            if rng.random() < 0.5:                            # some hold the SSE stream open
                self.add(upd_at + rng.uniform(300, 5400), F.mcp_sse_listen, "mcp", ws, board)

        # the admin jump host pokes at it during the admin window
        mgmt = h.get(H("MGMT1"))
        if mgmt is not None:
            for k in range(rng.randint(2, 4)):
                self.add(local(15, 20) + k * rng.uniform(900, 2400), F.mcp_session, "mcp",
                         mgmt, board, ua="mcp-inspector/0.9.1")
            self.add(local(15, 40), F.mcp_sse_listen, "mcp", mgmt, board,
                     ua="mcp-inspector/0.9.1")

    def _scaled(self, lo, hi):
        """A per-user event count that follows the capture scale, the way the daytime activity
        loop does (its gap is 900/scale). Without this, cloud egress is a fixed number of
        sessions per person regardless of scale, so it barely registers in a full-size day and
        completely swamps a small validation capture."""
        n = rng.uniform(lo, hi) * self.scale
        whole = int(n)
        return whole + (1 if rng.random() < (n - whole) else 0)

    def cloud_and_peers(self):
        """Consumer cloud, generative-AI egress, workstation-to-workstation traffic, and the
        connections that fail.

        Everything here is **workstation-originated**. Servers do not stream music and do not
        talk to AI platforms — that traffic is scheduled only for desks and laptops, because a
        domain controller reaching chatgpt.com is not added realism, it is a defect that would
        teach a viewer the wrong thing.
        """
        ctx, h = self.ctx, self.ctx.h
        ws_all = [w for w in self.workstations]
        if not ws_all:
            return

        for ws in ws_all:
            day_lo = local(7, 30) + rng.uniform(0, 3600)
            day_hi = local(16, 30)

            # --- consumer cloud: the long tail of a working day -------------------------
            for _ in range(self._scaled(6, 18)):
                t = rng.uniform(day_lo, day_hi)
                site = ctx.sites[rng.choice(CONSUMER_SITES)]
                if rng.random() < 0.5:
                    self.add(t, F.page_load, "cloud", ws, site)
                else:
                    self.add(t, F.https_session, "cloud", ws, site,
                             requests=rng.randint(3, 14))
            # music and video run long; not everyone, but plenty of people
            # Streaming is the single heaviest thing a desk does, so the share of people doing
            # it at any given time governs the whole capture's balance. Measured at 55% of
            # staff with up to 4 long streams each, media alone was 52% of all bytes and the
            # baseline read as a music service with an office attached.
            if rng.random() < 0.28:
                for _ in range(self._scaled(1, 2)):
                    name = rng.choice(["audio-fa.scdn.co", "audio-ssl.itunes.apple.com",
                                       "rr3---sn-8xgp1vo-p5qe.googlevideo.com"])
                    self.add(rng.uniform(day_lo, day_hi), F.media_stream, "cloud-media",
                             ws, ctx.sites[name], minutes=rng.uniform(5, 22))

            # --- generative AI ----------------------------------------------------------
            # Adoption is uneven, which is itself the interesting part: a minority of desks
            # account for most of it, and a few use it constantly.
            roll = rng.random()
            n_ai = 0 if roll < 0.35 else (self._scaled(2, 7) if roll < 0.8 else self._scaled(8, 22))
            for _ in range(n_ai):
                self.add(rng.uniform(day_lo, day_hi), F.genai_session, "genai",
                         ws, ctx.sites[rng.choice(GENAI_SITES)], turns=rng.randint(2, 8))

            # --- peer to peer ------------------------------------------------------------
            if rng.random() < 0.45:
                peer = rng.choice([p for p in ws_all if p is not ws])
                self.add(rng.uniform(day_lo, day_hi), F.peer_smb, "peer-smb", ws, peer,
                         files=rng.randint(1, 3))
            if rng.random() < 0.18:
                peer = rng.choice([p for p in ws_all if p is not ws])
                self.add(rng.uniform(local(9), local(16)), F.peer_media, "peer-media", ws, peer,
                         seconds=rng.uniform(25, 120))

            # --- connections that do not succeed -----------------------------------------
            for _ in range(self._scaled(1, 7)):
                target = rng.choice(ws_all + self.servers)
                if target is ws:
                    continue
                self.add(rng.uniform(day_lo, day_hi), F.connection_refused, "refused", ws, target)
            if rng.random() < 0.12:
                self.add(rng.uniform(day_lo, day_hi), F.connection_aborted, "aborted",
                         ws, h[H("WEB1")])

    def server_patching(self):
        """Servers reaching their vendors' OS update services, outside the internal network.

        There is no internal WSUS here, so each server patches directly: Windows boxes against
        Microsoft, Linux boxes against their distribution mirror. This is deliberately the ONLY
        internet egress the servers generate — no consumer cloud, no AI platforms.
        """
        ctx = self.ctx
        win = [x for x in self.servers if "windows" in (x.os or "").lower()]
        lin = [x for x in self.servers if "linux" in (x.os or "").lower()]

        for srv in win:
            # the daily scan, and a real patch download for a subset of the fleet
            self.add(rng.uniform(local(6, 10), local(8, 30)), F.win_server_update, "os-update",
                     srv, ctx.sites[rng.choice(["fe2cr.update.microsoft.com",
                                                "windowsupdate.microsoft.com"])],
                     ctx.sites[rng.choice(["download.windowsupdate.com",
                                           "tlu.dl.delivery.mp.microsoft.com"])],
                     # most days a server scans and finds a little; a minority pull a real
                     # cumulative update. Patching the whole fleet daily is not what happens.
                     mb=rng.uniform(120, 700) if rng.random() < 0.18 else rng.uniform(4, 40))
            # certificate trust list refresh — small, frequent, cleartext
            for _ in range(rng.randint(1, 2)):
                self.add(rng.uniform(local(7), local(18)), F.https_session, "os-update",
                         srv, ctx.sites["ctldl.windowsupdate.com"], requests=rng.randint(1, 2),
                         sizes=[rng.randint(1500, 40000)])

        for srv in lin:
            self.add(rng.uniform(local(6), local(7, 40)), F.linux_server_update, "os-update",
                     srv, ctx.sites[rng.choice(LINUX_UPDATE_SITES)],
                     mb=rng.uniform(30, 220) if rng.random() < 0.25 else rng.uniform(3, 18))

    def identity(self):
        """Authentication that is not just "everyone logs in once and it works".

        Added because the generated day was implausible on the identity side: 95 logons for 95
        seats, no account ever failed, no account was ever disabled, expired or locked, no
        service account existed, and the only KRB-ERROR on the wire was code 25 — which is not
        a failure at all but the normal first leg of Windows pre-authentication.

        Volumes here are **scale-invariant**, like the existing logon sequence: how many people
        sign in is a property of the business day, not of how much traffic you asked for. That
        also means the behaviour is visible in a small demo capture.

        The proportions are deliberately restrained. `ndr-password-spray` is detectable
        *because* it is the only thing producing a burst of KDC_ERR_PREAUTH_FAILED; baseline
        failures have to stay scattered across accounts and hours, and mostly end in success,
        or the scenario stops being distinguishable.
        """
        h, d = self.ctx.h, self.ctx.dir
        if d is None:
            return
        _dc1, _dc2 = h[H("DC1")], h[H("DC2")]
        file1 = h[H("FILE1")]
        jump = h.get(H("MGMT1"))

        # --- accounts in a bad state, retried by whatever still holds their credentials ------
        for a in d.disabled:
            ws = a.host
            for _ in range(rng.randint(2, 4)):
                t = rng.uniform(local(7, 30), local(18))
                self.add(t, F.kerberos_as_outcome, "kerberos-fail", ws, user=a.name, outcome="revoked")
            # a phone or a mapped drive still trying the old password over NTLM
            self.add(rng.uniform(local(8), local(17)), F.ntlm_smb_logon, "ntlm-fail",
                     ws, file1, user=a.name, outcome="disabled")
            self.add(rng.uniform(local(8), local(17)), F.ldap_bind_failure, "ldap-fail",
                     ws, user=a.name, data="533")

        for a in d.expired:
            ws = a.host
            self.add(rng.uniform(local(7, 45), local(9, 30)), F.kerberos_as_outcome, "kerberos-fail",
                     ws, user=a.name, outcome="expired")
            self.add(rng.uniform(local(7, 50), local(9, 40)), F.kerberos_as_outcome, "kerberos-fail",
                     ws, user=a.name, outcome="expired")
            self.add(rng.uniform(local(9, 30), local(10, 30)), F.ldap_bind_failure, "ldap-fail",
                     ws, user=a.name, data="532")
            # they change it and get on with their day
            self.add(rng.uniform(local(10, 30), local(11, 30)), F.kerberos_as_outcome, "kerberos",
                     ws, user=a.name, outcome="ok")

        for a in d.lockouts:
            ws = a.host
            self.add(rng.uniform(local(7, 40), local(15, 30)), F.kerberos_lockout, "kerberos-lockout",
                     ws, user=a.name)
            # helpdesk unlocks them, and they are fine afterwards
            self.add(rng.uniform(local(15, 45), local(16, 45)), F.kerberos_as_outcome, "kerberos",
                     ws, user=a.name, outcome="ok")

        # --- principals that do not exist: typos, decommissioned accounts in saved creds -----
        for name in d.unknown_names:
            ws = rng.choice(self.workstations)
            self.add(rng.uniform(local(7, 30), local(18)), F.kerberos_as_outcome, "kerberos-fail",
                     ws, user=name, outcome="unknown")

        # --- service accounts on their schedules ---------------------------------------------
        for a in d.services:
            if a.name == "svc_backup":
                for hh in (12, 19):
                    self.add(local(hh, rng.randint(0, 20)), F.service_account_job, "svc",
                             a.host, file1, user=a.name, share="Dept", files=3)
            elif a.name == "svc_sql":
                for hh in range(7, 19, 4):
                    self.add(local(hh, rng.randint(0, 50)), F.kerberos_as_outcome, "svc",
                             a.host, user=a.name, outcome="ok")
            elif a.name == "svc_scan":
                for hh in range(7, 19, 2):
                    self.add(local(hh, rng.randint(0, 55)), F.kerberos_as_outcome, "svc",
                             a.host, user=a.name, outcome="ok")
            elif a.name == "svc_print":
                for hh in (8, 13, 17):
                    self.add(local(hh, rng.randint(0, 40)), F.service_account_job, "svc",
                             a.host, file1, user=a.name, share="Dept", files=1, size=120_000)
            elif a.name == "svc_legacy":
                # no SPN registered, so it can only ever use NTLM — and its password is stale
                for hh in (9, 14):
                    self.add(local(hh, rng.randint(0, 45)), F.ntlm_smb_logon, "svc",
                             a.host, file1, user=a.name, outcome="ok")
                self.add(local(11, rng.randint(0, 50)), F.ntlm_smb_logon, "ntlm-fail",
                         a.host, file1, user=a.name, outcome="bad_password")

        # --- ordinary, successful NTLM ------------------------------------------------------
        # Not every SMB session can use Kerberos. A share reached by IP literal has no SPN to
        # ask for, so Windows falls straight back to NTLM — which is why a real estate always
        # shows some, and why a capture with none looks synthetic.
        for ws in rng.sample(self.workstations, min(14, len(self.workstations))):
            a = d.for_host(ws)
            if not a or a.state != "ok":
                continue
            for _ in range(rng.randint(1, 2)):
                self.add(rng.uniform(local(8), local(17, 30)), F.ntlm_smb_logon, "ntlm",
                         ws, file1, user=a.name, outcome="ok")

        # --- privileged accounts, from the jump host where they belong -----------------------
        if jump is not None:
            for a in d.privileged:
                for _ in range(rng.randint(2, 4)):
                    self.add(rng.uniform(local(8), local(18, 30)), F.privileged_session, "admin-auth",
                             jump, acct=a.name)
            # one mistyped privileged logon — rare, and worth a lot to a detector
            self.add(rng.uniform(local(9), local(17)), F.kerberos_as_outcome, "admin-auth",
                     jump, user=rng.choice(d.privileged).name, outcome="bad_password")

    def voice(self):
        n_calls = max(3, int(45 * self.scale))
        for _ in range(n_calls):
            a, b = rng.sample(self.phones, 2)
            t = gaussian_time(local(10, 30), 2.5 * 3600, local(7), local(17))
            dur = min(720, max(20, rng.lognormvariate(4.9, 0.7)))
            self.add(t, F.sip_call, "voip", a, b, duration=dur)

    # --------------------------------------------------------------- admin work
    def admin(self):
        h = self.ctx.h
        mgmt = h[H("MGMT1")]
        n = max(4, int(14 * self.scale))
        for _ in range(n):
            t = rng.uniform(local(15), local(18, 40))
            if rng.random() < 0.6:
                srv = rng.choice([s for s in self.win_servers if s.name != H("MGMT1")])
                self.add(t, F.icmp_ping, "icmp", mgmt, srv)
                self.add(t + 5, F.rdp_session, "rdp", mgmt, srv, duration=rng.uniform(60, 400))
            else:
                srv = rng.choice(self.lin_servers)
                self.add(t, F.ssh_session, "ssh", mgmt, srv, duration=rng.uniform(60, 600))
        # server patching
        for srv in self.servers:
            if srv.name == H("MGMT1"):
                continue
            self.add(rng.uniform(local(15, 30), local(18)), F.patch_download, "patch", srv, total=int(rng.uniform(12e6, 32e6) * self.scale))
        # backups
        self.add(local(17, 0) + rng.uniform(0, 120), F.smb_bulk_transfer, "backup", h[H("BACKUP1")], h[H("FILE1")], "Dept", int(350e6 * self.scale), direction="read")
        self.add(local(18, 5) + rng.uniform(0, 120), F.smb_bulk_transfer, "backup", h[H("SQL1")], h[H("BACKUP1")], "sqlbackup", int(150e6 * self.scale), direction="write", chunk=1048576, files=3)

    # ------------------------------------------------------------------ OT / ICS
    # Purdue levels 0-3.5. Every method here returns immediately when the OT subnet is off.
    #
    # The process does not keep office hours: unlike every other part of the business day,
    # these run the whole capture window rather than clustering in business hours. That is
    # what makes the OT rows span the full timeline.

    def _ot_enabled(self, proto):
        """Whether an OT process protocol should be emitted. The energy pair is ALWAYS gated to the
        Energy industry (even in the default 'all protocols' build); otherwise None = every
        protocol, and a set restricts emission to the chosen subset."""
        if proto in OT_ENERGY_PROTOCOLS and _current_identity().industry != "Energy":
            return False          # electric-utility protocols: Energy industry only
        if self.ot_protocols is None:
            return True
        return proto in self.ot_protocols

    def _inject_ot(self, suffix, ip, mac_tail, role, hops=None):
        """Add one OT host to ctx.h for a selectable protocol that needs a peer not in the base
        inventory (a PDC, a remote control centre). OT is off in the pin build, so this never
        touches the 466,343 baseline; it runs only when the subnet and the protocol are on."""
        ident = _current_identity()
        name = ident.host(suffix)
        if name in self.ctx.h:
            return self.ctx.h[name]
        if isinstance(ip, int):
            base = (self.plcs[0].subnet if self.plcs else "10.10.30.0/24").rsplit(".", 1)[0]
            ip, subnet = "%s.%d" % (base, ip), (self.plcs[0].subnet if self.plcs else "10.10.30.0/24")
        else:
            subnet = ip.rsplit(".", 1)[0] + ".0/24"
        host = Host(name, ip, "02:00:5e:a0:%02x:%02x" % ((mac_tail >> 8) & 0xFF, mac_tail & 0xFF),
                    "linux", role, subnet, ident.fqdn(suffix))
        if hops:
            host.hops = hops
        self.ctx.h[name] = host
        return host

    def ot_control(self):
        """Levels 1-2. Modbus polling is the bulk of the whole subnet: 12 PLCs on a 2 s poll
        is over a million packets across the window, roughly 78% of everything OT emits."""
        if not self.ot_on or not self._ot_enabled("modbus"):
            return
        period = OT_POLL_S
        span = T_END - T_START
        # One long-lived connection per supervisory/PLC pair, rebuilt in blocks so the engine
        # is not asked to hold 28,800 polls of state in a single session object.
        BLOCK = 900.0                                    # 15 minutes of polling per session
        n_blocks = max(1, int(span / BLOCK))
        per_block = max(1, int(BLOCK / period * min(1.0, max(0.05, self.scale))))
        for i, plc in enumerate(self.plcs):
            master = self.scada[i % len(self.scada)] if self.scada else self.hmis[i % len(self.hmis)]
            for b in range(n_blocks):
                t0 = T_START + b * BLOCK + rng.uniform(0, 1.5)
                self.add(t0, F.modbus_poll_block, "modbus", master, plc,
                         n_polls=per_block, period=period, unit=(i % 4) + 1)
        # HMI panels poll their own line's PLC directly as well -- the panel is a client too.
        for j, hmi in enumerate(self.hmis):
            if not self.plcs:
                break
            plc = self.plcs[(j * 3) % len(self.plcs)]
            for b in range(n_blocks):
                t0 = T_START + b * BLOCK + rng.uniform(0, 2.0)
                self.add(t0, F.modbus_poll_block, "modbus", hmi, plc,
                         n_polls=max(1, per_block // 3), period=period * 3, unit=1)
        # Safety controllers are polled far less often and never written to.
        for k, sis in enumerate(self.sis):
            for b in range(n_blocks):
                t0 = T_START + b * BLOCK + rng.uniform(0, 5.0)
                self.add(t0, F.modbus_poll_block, "modbus", self.scada[k % len(self.scada)], sis,
                         n_polls=max(1, per_block // 10), period=period * 10, unit=1)
        # Operator setpoint changes: a few dozen across the shift, in business hours only.
        for _ in range(self._scaled(18, 40)):
            t = gaussian_time((BIZ_START + BIZ_END) / 2, (BIZ_END - BIZ_START) / 5, BIZ_START, BIZ_END)
            self.add(t, F.modbus_setpoint_write, "modbus",
                     rng.choice(self.hmis or self.scada), rng.choice(self.plcs))

    def ot_telemetry(self):
        """DNP3 from the SCADA masters to the remote RTUs -- slower, and the protocol that
        carries unsolicited change reports rather than being purely polled."""
        if not self.ot_on or not self._ot_enabled("dnp3") or not self.rtus:
            return
        span = T_END - T_START
        BLOCK = 1800.0
        n_blocks = max(1, int(span / BLOCK))
        per_block = max(1, int(BLOCK / OT_DNP3_POLL_S * min(1.0, max(0.05, self.scale))))
        for i, rtu in enumerate(self.rtus):
            master = self.scada[i % len(self.scada)] if self.scada else self.hmis[0]
            for b in range(n_blocks):
                t0 = T_START + b * BLOCK + rng.uniform(0, 4.0)
                self.add(t0, F.dnp3_poll_block, "dnp3", master, rtu,
                         n_polls=per_block, period=OT_DNP3_POLL_S, dest=i + 4, src=3)

    def ot_building(self):
        """BACnet. Mostly unconfirmed change-of-value, which is one datagram with no reply --
        the reason a BMS is cheap in packets and almost free in bytes."""
        if not self.ot_on or not self._ot_enabled("bacnet") or not self.bacnet:
            return
        ctrl = self.ctx.h.get(H("BMS1"))
        if ctrl is None:
            return
        span = T_END - T_START
        n_cov = max(1, int(span / OT_BACNET_COV_S * min(1.0, max(0.05, self.scale))))
        for i, dev in enumerate(self.bacnet):
            for k in range(n_cov):
                t = T_START + k * OT_BACNET_COV_S + rng.uniform(0, OT_BACNET_COV_S * 0.4)
                self.add(t, F.bacnet_cov_burst, "bacnet", dev, ctrl, dev_instance=100 + i)
            n_read = max(1, int(span / 300.0 * min(1.0, max(0.05, self.scale))))
            for k in range(n_read):
                t = T_START + k * 300.0 + rng.uniform(0, 120)
                self.add(t, F.bacnet_read_exchange, "bacnet", ctrl, dev, dev_instance=100 + i)
        # Setpoint writes down to the plant: a handful per day, business hours.
        for _ in range(self._scaled(10, 24)):
            t = gaussian_time((BIZ_START + BIZ_END) / 2, (BIZ_END - BIZ_START) / 5, BIZ_START, BIZ_END)
            self.add(t, F.bacnet_write_exchange, "bacnet", ctrl, rng.choice(self.bacnet),
                     dev_instance=100 + rng.randrange(len(self.bacnet)))

    # ---- OT process protocols the platform began parsing in 2026-10 (selectable OT-subnet options) ----
    def ot_ethernetip(self):
        """EtherNet/IP (CIP): SCADA/HMI scanners poll a Rockwell-style subset of PLCs on TCP 44818,
        plus cyclic Class-1 I/O on UDP 2222."""
        if not self.ot_on or not self._ot_enabled("ethernetip") or not self.plcs:
            return
        scanners = self.scada or self.hmis or self.eng_ws
        if not scanners:
            return
        BLOCK = 900.0
        n_blocks = max(1, int((T_END - T_START) / BLOCK))
        per = max(2, int(BLOCK / 1.0 * min(1.0, max(0.05, self.scale))))
        for i, plc in enumerate(self.plcs[0::3] or self.plcs[:1]):
            scanner = scanners[i % len(scanners)]
            for b in range(n_blocks):
                self.add(T_START + b * BLOCK + rng.uniform(0, 1.5), F.enip_session, "ethernetip",
                         scanner, plc, n_reads=per, period=1.0)
                self.add(T_START + b * BLOCK + rng.uniform(0, 2.0), F.enip_io, "ethernetip",
                         plc, scanner, n=max(2, per // 2), period=0.5)

    def ot_s7comm(self):
        """Siemens S7comm (TCP 102): HMI/engineering stations read S7 PLCs; an engineer occasionally
        writes a setpoint."""
        if not self.ot_on or not self._ot_enabled("s7comm") or not self.plcs:
            return
        clients = self.hmis or self.scada or self.eng_ws
        if not clients:
            return
        BLOCK = 900.0
        n_blocks = max(1, int((T_END - T_START) / BLOCK))
        per = max(2, int(BLOCK / 2.0 * min(1.0, max(0.05, self.scale))))
        for i, plc in enumerate(self.plcs[1::3] or self.plcs[:1]):
            client = clients[i % len(clients)]
            for b in range(n_blocks):
                self.add(T_START + b * BLOCK + rng.uniform(0, 1.5), F.s7comm_session, "s7comm",
                         client, plc, n_reads=per, period=2.0,
                         writes=(1 if (b == 0 and rng.random() < 0.3) else 0))

    def ot_opcua(self):
        """OPC UA (TCP 4840): a SCADA/historian client reads OPC UA servers on the PLCs and the
        MES/historian tier -- the IT/OT convergence layer."""
        if not self.ot_on or not self._ot_enabled("opcua") or not self.plcs:
            return
        clients = self.scada or self.l3_servers or self.hmis
        if not clients:
            return
        servers = (self.plcs[2::3] or self.plcs[:1]) + self.l3_servers
        BLOCK = 1200.0
        n_blocks = max(1, int((T_END - T_START) / BLOCK))
        per = max(2, int(BLOCK / 5.0 * min(1.0, max(0.05, self.scale))))
        for i, srv in enumerate(servers):
            client = clients[i % len(clients)]
            for b in range(n_blocks):
                self.add(T_START + b * BLOCK + rng.uniform(0, 3.0), F.opcua_session, "opcua",
                         client, srv, n_reads=per, period=5.0)

    def ot_synchrophasor(self):
        """IEEE C37.118: substation PMUs (the RTUs) stream phasor data to a PDC. Energy only
        (``_ot_enabled`` returns False outside the Energy industry)."""
        if not self.ot_on or not self._ot_enabled("synchrophasor"):
            return
        pmus = self.rtus or self.plcs
        if not pmus:
            return
        pdc = self._inject_ot("PDC1", 61, 0x0101, "Phasor Data Concentrator (C37.118)")
        BLOCK = 300.0
        n_blocks = max(1, int((T_END - T_START) / BLOCK))
        for pmu in pmus:
            for b in range(n_blocks):
                self.add(T_START + b * BLOCK + rng.uniform(0, 3.0), F.c37118_stream, "synchrophasor",
                         pmu, pdc, seconds=8.0, fps=30)

    def ot_iccp(self):
        """ICCP / TASE.2 (MMS over TCP 102): the local control centre exchanges real-time points with
        a remote control centre over a WAN. Energy only."""
        if not self.ot_on or not self._ot_enabled("iccp"):
            return
        local_cc = self.scada or self.l3_servers or self.hmis
        if not local_cc:
            return
        remote = self._inject_ot("ICC-REMOTE", "198.51.100.90", 0x0202,
                                 "Remote control centre (ICCP/TASE.2 peer)", hops=9)
        BLOCK = 600.0
        n_blocks = max(1, int((T_END - T_START) / BLOCK))
        per = max(2, int(150.0 * min(1.0, max(0.05, self.scale))))
        for b in range(n_blocks):
            self.add(T_START + b * BLOCK + rng.uniform(0, 5.0), F.iccp_session, "iccp",
                     local_cc[b % len(local_cc)], remote, n=per, period=4.0)

    def ot_operations(self):
        """Level 3. This zone speaks IT, not process: SQL, SMB, RDP, HTTPS, Kerberos, backup.
        751 bytes per packet against 77 down in the cell/area zone -- that inversion is the
        single most useful thing about including level 3 at all."""
        if not self.ot_on or not self.l3_servers:
            return
        h = self.ctx.h
        mes, mesdb = h.get(H("MES1")), h.get(H("MESDB1"))
        pool = []
        if mes is not None and mesdb is not None:
            self.eng.schedule(T_START + 60, lambda: F.sql_pool_open(
                self.ctx, T_START + 60, n=4, web=H("MES1"), svc="svc_mes", pool=pool,
                sql=H("MESDB1"), db="MES"), "ot-mes")
            for _ in range(self._scaled(220, 520)):
                t = rng.uniform(T_START + 120, T_END)
                self.eng.schedule(t, (lambda tt: lambda: F.sql_query(self.ctx, tt, "svc_mes", pool=pool))(t),
                                  "ot-mes")
        # Historian collectors writing batches in, and reports reading them back out.
        for c in (h.get(H("HISTC1")), h.get(H("HISTC2"))):
            if c is None or h.get(H("HIST1")) is None:
                continue
            for _ in range(self._scaled(60, 150)):
                t = rng.uniform(T_START, T_END)
                self.add(t, F.smb_file_activity, "ot-hist", c, h[H("HIST1")], n_files=1,
                         write_ratio=0.9, share="Historian", size_range=(40_000, 260_000))
        # Operator terminals and engineering workstations on the MES web UI.
        for ws in self.ot_terms + self.eng_ws:
            for _ in range(self._scaled(10, 26)):
                t = rng.uniform(BIZ_START, ADMIN_END)
                self.add(t, F.intranet_session, "ot-mesweb", ws, pages=rng.randint(2, 5), web=H("MES1"))
        # Recipes, shift handover and reports on the OT file server.
        for ws in self.eng_ws + self.ot_terms:
            if h.get(H("OTFS1")) is None:
                break
            for _ in range(self._scaled(8, 20)):
                t = rng.uniform(T_START, T_END)
                self.add(t, F.smb_file_activity, "ot-files", ws, h[H("OTFS1")], write_ratio=0.35,
                         share="Recipes")
        # Engineering RDP into the level 3 servers, from level 3 workstations.
        for _ in range(self._scaled(3, 7)):
            t = rng.uniform(BIZ_START, ADMIN_END)
            self.add(t, F.rdp_session, "ot-rdp", rng.choice(self.eng_ws),
                     rng.choice([x for x in self.l3_servers if x.ttl == 128] or self.l3_servers),
                     duration=rng.uniform(900, 2400))
        # OT domain authentication. Scale-invariant, like the enterprise identity model:
        # how many people sign in is a property of the day, not of requested traffic volume.
        # The same draws as before (the rest of this method's RNG stream is unchanged); the accounts
        # are now the OT forest's own (OT_STATION_ACCOUNTS) and the shift / re-auth / service /
        # remote-engineering logons are added in ot_identity().
        if h.get(H("OTDC1")) is not None:
            for ws in self.eng_ws + self.ot_terms + self.hmis:
                t = gaussian_time(BIZ_START + 600, 900, T_START, BIZ_END)
                self.add(t, F.kerberos_as_outcome, "ot-auth", ws, user=ot_account_at(ws.name, t),
                         outcome="ok", dc=h[H("OTDC1")], realm=P.OT_REALM)
        # Backup, syslog and SNMP -- the housekeeping every OT zone actually emits.
        if h.get(H("OTBKP1")) is not None:
            for srv in self.l3_servers[:8]:
                t = rng.uniform(T_START, T_START + 5400)
                self.add(t, F.smb_bulk_transfer, "ot-backup", srv, h[H("OTBKP1")], "Backup",
                         int(self._scaled(24_000_000, 60_000_000)), direction="write")
        for dev in self.ot_switches:
            for _ in range(self._scaled(14, 34)):
                t = rng.uniform(T_START, T_END)
                self.add(t, F.snmp_poll, "ot-mgmt", h.get(H("OTMON1")) or dev, dev)
        for src in self.l3_servers[:6] + self.idmz[:3]:
            for _ in range(self._scaled(12, 30)):
                t = rng.uniform(T_START, T_END)
                self.add(t, F.syslog_msg, "ot-mgmt", src)
        # EXL-OTFW1, the industrial firewall, is itself a managed device: SNMP-polled by the OT
        # monitor, shipping syslog, syncing time to the enterprise NTP server, and reached for
        # admin over SSH. This management plane is what makes the platform classify it as network
        # infrastructure rather than a silent inline box, on top of its gateway/ARP presence.
        otfw = h.get(H("OTFW1"))
        if otfw is not None:
            poller = h.get(H("OTMON1")) or otfw
            for _ in range(self._scaled(16, 38)):
                t = rng.uniform(T_START, T_END)
                self.add(t, F.snmp_poll, "ot-mgmt", poller, otfw)
            for _ in range(self._scaled(18, 42)):
                t = rng.uniform(T_START, T_END)
                self.add(t, F.syslog_msg, "ot-mgmt", otfw)
            for _ in range(self._scaled(6, 14)):
                t = rng.uniform(T_START, T_END)
                self.add(t, F.ntp_exchange, "ot-mgmt", otfw)
            for _ in range(self._scaled(2, 5)):
                t = rng.uniform(BIZ_START, ADMIN_END)
                self.add(t, F.ssh_session, "ot-mgmt", poller, otfw, duration=rng.uniform(120, 900))

    def ot_identity(self):
        """Who is signed in where, through the day, in the OT forest -- so every station that drives
        a controller has an identity on the wire (Kerberos AS in P.OT_REALM against EXL-OTDC1, RDP
        mstshash cookies), not one logon per station per day.

        - Shift change: the incoming operator signs on to each HMI at 06:00 and 14:00 (+/- 5 min);
          the night operator re-authenticates once early, before the day shift arrives.
        - Re-auth: screen-lock unlocks through the shift (a fresh AS exchange each time).
        - Engineers and the operations terminal unlock a few times in business hours.
        - SCADA servers sign their service account in at service start and renew the TGT at 10 h.
        - Remote engineering: an IT user RDPs to the jump host; with a separate OT account the jump
          host goes to the IDMZ broker (the single inbound path, see ot_bridge), then a level 3
          engineering workstation, then the cell engineering workstation, which reads and writes
          the controllers while that session is open.
        Scale-invariant, like the enterprise identity model."""
        if not self.ot_on:
            return
        h = self.ctx.h
        otdc = h.get(H("OTDC1"))
        if otdc is None:
            return
        realm = P.OT_REALM

        def auth(t, host, user, tag="ot-auth"):
            self.add(t, F.kerberos_as_outcome, tag, host, user=user, outcome="ok", dc=otdc, realm=realm)

        shift_day, shift_swing = local(6), local(14)
        for hmi in self.hmis:
            auth(T_START + rng.uniform(600, 1800), hmi, ot_account_at(hmi.name, T_START))
            for start in (shift_day, shift_swing):
                auth(start + rng.uniform(-300, 300), hmi, ot_account_at(hmi.name, start + 1))
            for _ in range(rng.randint(3, 5)):
                t = rng.uniform(shift_day + 900, T_END - 60)
                auth(t, hmi, ot_account_at(hmi.name, t))
        for ws in self.eng_ws + self.ot_terms:
            for _ in range(rng.randint(2, 4)):
                t = rng.uniform(BIZ_START + 1800, ADMIN_END)
                auth(t, ws, ot_account_at(ws.name, t))
        for srv in self.scada:
            t0 = T_START + rng.uniform(30, 180)
            auth(t0, srv, OT_SCADA_SERVICE_ACCOUNT)
            auth(t0 + 36000 + rng.uniform(0, 120), srv, OT_SCADA_SERVICE_ACCOUNT)

        jump, broker = h.get(H("OTJUMP1")), h.get(H("IDMZ-BROKER"))
        l3_eng = [w for w in self.eng_ws if not w.name.startswith(H("OTENG"))]
        cell_eng = [w for w in self.eng_ws if w.name.startswith(H("OTENG"))]
        if not (jump and broker and l3_eng and cell_eng and self.workstations and self.plcs):
            return
        for _ in range(rng.randint(2, 3)):
            ws = rng.choice(self.workstations)
            it_user = P.username_for(ws.name)
            ot_user = OT_REMOTE_ACCOUNT_PREFIX + it_user
            t = rng.uniform(BIZ_START + 1800, BIZ_END - 3600)
            dur = rng.uniform(2400, 4200)
            eng3, eng2 = rng.choice(l3_eng), cell_eng[0]
            self.add(t, F.rdp_session, "ot-remote-eng", ws, jump, duration=dur, user=it_user)
            auth(t + 25, jump, ot_user, "ot-remote-eng")
            self.add(t + 30, F.rdp_session, "ot-remote-eng", jump, broker, duration=dur - 60,
                     user=ot_user, realm=realm, dc=otdc)
            self.add(t + 50, F.rdp_session, "ot-remote-eng", broker, eng3, duration=dur - 120,
                     user=ot_user, realm=realm, dc=otdc)
            self.add(t + 75, F.rdp_session, "ot-remote-eng", eng3, eng2, duration=dur - 180,
                     user=ot_user, realm=realm, dc=otdc)
            for plc in rng.sample(self.plcs, min(3, len(self.plcs))):
                tt = t + rng.uniform(300, dur - 400)
                self.add(tt, F.s7comm_session, "ot-remote-eng", eng2, plc, n_reads=rng.randint(20, 60),
                         period=1.0, writes=rng.randint(0, 2))
                self.add(tt + rng.uniform(30, 120), F.modbus_poll_block, "ot-remote-eng", eng2, plc,
                         n_polls=rng.randint(10, 30), period=2.0, unit=1)

    def ot_bridge(self):
        """Level 3.5 and the IT/OT boundary.

        THE INVARIANT: in the baseline, exactly one host in the whole enterprise opens a
        session into the industrial zone -- EXL-OTJUMP1, the privileged-access jump host in
        the server subnet. Everything else crossing the boundary is OT-initiated and outbound.
        Do not add a second inbound source here: a single-source baseline is what makes any
        future scenario that reaches into OT from somewhere else anomalous by construction,
        with no tuning and no threshold.
        """
        if not self.ot_on or not self.idmz:
            return
        h = self.ctx.h
        jump, broker = h.get(H("OTJUMP1")), h.get(H("IDMZ-BROKER"))
        # ---- the single inbound path
        if jump is not None and broker is not None:
            for _ in range(self._scaled(4, 9)):
                t = rng.uniform(BIZ_START, ADMIN_END)
                self.add(t, F.rdp_session, "ot-ingress", jump, broker, duration=rng.uniform(900, 1800))
                # the broker terminates that session and opens its OWN, one level down --
                # nothing passes through the DMZ end to end, which is the point of a DMZ
                tgt = rng.choice(self.l3_servers) if self.l3_servers else None
                if tgt is not None:
                    self.add(t + 20, F.rdp_session, "ot-brokered", broker, tgt,
                             duration=rng.uniform(600, 1500))
            for _ in range(self._scaled(30, 70)):
                t = rng.uniform(T_START, T_END)
                self.add(t, F.intranet_session, "ot-ingress", jump, pages=1, web=H("IDMZ-PROXY"))
        # ---- OT-initiated egress. Sessions opened from inside, never answered into.
        rep, sql = h.get(H("IDMZ-HIST")), h.get(H("SQL1"))
        if rep is not None and sql is not None:
            for _ in range(self._scaled(20, 46)):
                t = rng.uniform(T_START, T_END)
                self.add(t, F.smb_file_activity, "ot-egress", rep, sql, n_files=1, write_ratio=0.95,
                         share="Reporting", size_range=(300_000, 900_000))
        ft, fs = h.get(H("IDMZ-FT")), h.get(H("FS1"))
        if ft is not None and fs is not None:
            for _ in range(self._scaled(8, 20)):
                t = rng.uniform(BIZ_START, ADMIN_END)
                self.add(t, F.smb_bulk_transfer, "ot-egress", ft, fs, "Reports",
                         int(self._scaled(1_400_000, 3_200_000)), direction="write")
        patch = h.get(H("IDMZ-PATCH"))
        if patch is not None:
            for _ in range(self._scaled(6, 16)):
                t = rng.uniform(T_START, T_END)
                self.add(t, F.https_session, "ot-egress", patch,
                         self.ctx.sites["swcdn.example.net"], requests=rng.randint(2, 5))
        for src in self.idmz[:4]:
            for _ in range(self._scaled(8, 18)):
                t = rng.uniform(T_START, T_END)
                self.add(t, F.syslog_msg, "ot-egress", src)

    def classification_enrichment(self):
        """Extra role-signature traffic so each server is seen by the platform as the device TYPE it is
        meant to be, not a generic PC. The classifier keys on the dominant protocol a device SERVES
        to many distinct clients, so this drives: the file server SERVING SMB to a broad set of
        workstations, the LOB web server SERVING HTTP (which also keeps the database server's TDS
        the busy thing it answers), and the printers RECEIVING print jobs plus a printer-MIB SNMP
        walk from the monitoring station. VoIP registration density is raised so the call manager
        reads as telephony, not a gateway. All of it scales with --scale, so it is a modest delta at
        the pinned regression scale and a dominant signal at replay scale. See the platform
        device-classification notes: final roles are confirmed by replaying to the sensor.
        """
        ctx, h = self.ctx, self.ctx.h
        ws = self.workstations
        if not ws:
            return
        file1, web1, web2 = h.get(H("FILE1")), h.get(H("WEB1")), h.get(H("WEB2"))

        def stream(rate_s, fn, tag, *a, **kw):
            """Schedule fn across the business day at mean gap rate_s/scale seconds. Any positional
            arg or kwarg value that is callable is evaluated per-call (so each event gets a fresh
            random workstation / file count)."""
            t = BIZ_START + rng.uniform(0, 120)
            step = max(1.0, rate_s / max(self.scale, 1e-6))
            while t < BIZ_END:
                args = [x() if callable(x) else x for x in a]
                kwa = {k: (v() if callable(v) else v) for k, v in kw.items()}
                self.add(t, fn, tag, *args, **kwa)
                t += rng.expovariate(1.0 / step)

        pick = lambda: rng.choice(ws)
        # File server: SMB reads/writes from many distinct workstations -> file_server
        if file1:
            stream(28, F.smb_file_activity, "fs-smb", pick, file1, n_files=lambda: rng.randint(2, 5))
        # LOB web server: HTTP from many clients (also drives TDS to SQL1 via the app pool) -> web_server
        if web2:
            stream(22, F.intranet_session, "lob-http", pick,
                   web=H("WEB2"), host=f"shipping.{_current_identity().domain}", pool=ctx.sql_pool2)
        # Intranet web server: reinforce its already-correct http_server signal
        if web1:
            stream(30, F.intranet_session, "intra-http", pick)
        # Printers: more print jobs + a printer-MIB SNMP walk from the monitoring host -> printer
        PRN_MIB = ["1.3.6.1.2.1.25.3.5.1.1.1", "1.3.6.1.2.1.43.16.5.1.2.1.1",
                   "1.3.6.1.2.1.43.11.1.1.9.1.1", "1.3.6.1.2.1.43.10.2.1.4.1.1"]
        log1 = h.get(H("LOG1"))
        for p in self.printers:
            t = BIZ_START + rng.uniform(0, 300)
            while t < BIZ_END:
                if log1:
                    self.add(t, F.snmp_poll, "prn-snmp", log1, p, oids=PRN_MIB, community=b"public")
                t += rng.expovariate(1 / 300.0)
            stream(240, F.print_job, "prn-job", pick)
        # VoIP: denser SIP registration so the call manager reads as telephony, not a gateway
        for ph in self.phones:
            t = BIZ_START + rng.uniform(0, 600)
            while t < BIZ_END:
                self.add(t, F.sip_register, "voip-reg", ph)
                t += 1800 * rng.uniform(0.9, 1.1)
        # a few extra calls through PBX1 for RTP/RTCP body (sip_call has ts mid-signature -> lambda)
        if len(self.phones) >= 2:
            t = BIZ_START + rng.uniform(0, 300)
            while t < BIZ_END:
                a, b = rng.sample(self.phones, 2)
                dur = min(300, max(20, rng.lognormvariate(4.3, 0.5)))
                self.eng.schedule(t, (lambda a=a, b=b, t=t, dur=dur: F.sip_call(ctx, a, b, t, dur)), "voip-call")
                t += rng.expovariate(self.scale / 90.0)

    def build(self):
        # Run the registered baseline contributors in order. The built-ins (seeded below the
        # class) are the historical sequence; any module-registered contributor slots in by its
        # `order`. Identical calls in identical order => identical packets.
        for _order, _name, _fn in sorted(BASELINE_CONTRIBUTORS, key=lambda c: c[0]):
            _fn(self)


# Built-in baseline contributors -- the historical Day.build() sequence, now data-driven. Order
# numbers leave gaps so a module can insert between any two. OT contributors are no-ops when the
# OT subnet is off; classification enrichment runs last so every device is already present.
for _o, _n, _f in [
    (10,  "infrastructure",     lambda d: d.infrastructure()),
    (20,  "workstation-day",    lambda d: [d.workstation_day(ws) for ws in d.workstations]),
    (30,  "smartboards",        lambda d: d.smartboards()),
    (40,  "voice",              lambda d: d.voice()),
    (50,  "admin",              lambda d: d.admin()),
    (60,  "identity",           lambda d: d.identity()),
    (70,  "cloud-and-peers",    lambda d: d.cloud_and_peers()),
    (80,  "server-patching",    lambda d: d.server_patching()),
    (90,  "ot-control",         lambda d: d.ot_control()),
    (100, "ot-telemetry",       lambda d: d.ot_telemetry()),
    (110, "ot-building",        lambda d: d.ot_building()),
    (120, "ot-operations",      lambda d: d.ot_operations()),
    (130, "ot-bridge",          lambda d: d.ot_bridge()),
    # OT process protocols parsed since 2026-10. Appended AFTER the historical OT contributors so
    # the Modbus/DNP3/BACnet RNG streams are byte-identical to before; each is a no-op unless its
    # protocol is selected (and, for the energy pair, the Energy industry is set). Before
    # classification, so any injected PDC / remote control-centre host is classified.
    (131, "ot-ethernetip",      lambda d: d.ot_ethernetip()),
    (132, "ot-s7comm",          lambda d: d.ot_s7comm()),
    (133, "ot-opcua",           lambda d: d.ot_opcua()),
    (134, "ot-synchrophasor",   lambda d: d.ot_synchrophasor()),
    (135, "ot-iccp",            lambda d: d.ot_iccp()),
    # OT identity (shift logons, re-auth, service account, remote-engineering chain), appended
    # after everything above so those keep their RNG streams.
    (136, "ot-identity",        lambda d: d.ot_identity()),
    (140, "classification",     lambda d: d.classification_enrichment()),
]:
    register_baseline(_n, _o)(_f)
del _o, _n, _f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--out", default="example-normal-day.pcap")
    ap.add_argument("--keylog", default="example-tls-keys.log")
    ap.add_argument("--inventory", default="inventory.json")
    ap.add_argument("--stats", default=None)
    ap.add_argument("--incident", default=None,
                    help="comma-separated incident name(s) from the registry, e.g. ndr-recon,ndr-data-exfil (also accepts legacy 'sql1')")
    ap.add_argument("--fault-out", default=None, help="fault-only pcap path (with --incident); default derives from the name")
    ap.add_argument("--incident-only", action="store_true", help="write ONLY the fault pcap, not the full day")
    ap.add_argument("--list-incidents", action="store_true", help="print the incident registry and exit")
    ap.add_argument("--export-certs", nargs="?", const="certs", default=None, metavar="DIR",
                    help="after generating, write each TLS server's certificate + RSA private key "
                         "(and the CA cert) as PEM files into DIR (default 'certs') for the platform "
                         "certificate/private-key decryption on replay")
    ap.add_argument("--export-iocs", nargs="?", const="example-threat-collection", default=None, metavar="PREFIX",
                    help="write the embedded external indicators as an importable threat collection "
                         "(PREFIX.stix.json + PREFIX.csv) for the platform / any TIP")
    args = ap.parse_args()
    os.environ["TZ"] = "America/New_York"
    time.tzset()

    from . import incidents as INC
    if args.export_iocs and not (args.incident or args.list_incidents):
        r = INC.threat_collection(args.export_iocs + ".stix.json", args.export_iocs + ".csv")
        print(f"wrote threat collection: {r['indicators']} indicators -> {r['stix']}, {r['csv']}")
    if args.list_incidents:
        w = max(len(n) for n in INC.REGISTRY)
        for name, inc in INC.REGISTRY.items():
            print(f"  {name:<{w}}  [{inc.prefix}]  {inc.title}")
        return

    incident_names = []
    if args.incident:
        incident_names = ["npm-sql1-service-failure" if x.strip() == "sql1" else x.strip()
                          for x in args.incident.split(",") if x.strip()]
        for n in incident_names:
            if n not in INC.REGISTRY:
                raise SystemExit(f"unknown incident '{n}'. Try --list-incidents")

    hosts, link, sites, resolvers = build_hosts(args.inventory)
    arp = ArpModel(link)
    pki = PKI()
    keylog = open_private(args.keylog, "w")
    ctx = F.Ctx(hosts, link, arp, pki, keylog, scale=args.scale)
    ctx.sites = sites
    ctx.isp_resolvers = resolvers

    def fault_path():
        if args.fault_out:
            return args.fault_out
        if len(incident_names) == 1:
            return INC.REGISTRY[incident_names[0]].fault_name()
        return "example-incidents.pcap"

    if incident_names and args.incident_only:
        writer = PcapWriter(fault_path())
        eng = Engine(writer)
        day = Day(ctx, eng, args.scale)
        for n in incident_names:
            INC.build(n, day, ctx, eng)
        t0 = time.time()
        eng.run()
        writer.close()
        keylog.close()
        print(f"done (incident only): {writer.n:,} packets, {writer.bytes/1e6:.1f} MB -> {fault_path()}")
        if args.export_certs:
            names = pki.export_pems(args.export_certs)
            print(f"exported {len(names)} server cert/key pair(s) + CA -> {args.export_certs}/")
        if args.export_iocs:
            r = INC.threat_collection(args.export_iocs + ".stix.json", args.export_iocs + ".csv")
            print(f"wrote threat collection: {r['indicators']} indicators -> {r['stix']}")
        if args.stats:
            with open(args.stats, "w") as sf:
                json.dump(eng.stats, sf, indent=1)
        for k, (n, b, *_) in sorted(eng.stats.items(), key=lambda kv: -kv[1][1]):
            print(f"  {k:26s} {n:>9,} pkts {b/1e6:>9.2f} MB")
        return

    writer = PcapWriter(args.out)
    if incident_names:
        fault = PcapWriter(fault_path())
        eng = Engine(writer, side_writer=fault, side_tag_prefix="incident:", side_copy=True)
    else:
        eng = Engine(writer)
    day = Day(ctx, eng, args.scale)
    day.build()
    for n in incident_names:
        INC.build(n, day, ctx, eng)
    t0 = time.time()

    def prog(w):
        print(f"  {w.n:>9,} pkts  {w.bytes/1e6:>8.1f} MB  clock {time.strftime('%H:%M:%S', time.localtime(w.last_ts))}  ({time.time()-t0:.0f}s)", flush=True)
    eng.run(progress=prog)
    writer.close()
    keylog.close()
    if incident_names:
        fault.close()
        print(f"fault-only pcap: {fault.n:,} packets, {fault.bytes/1e6:.1f} MB -> {fault_path()}")
    print(f"done: {writer.n:,} packets, {writer.bytes/1e6:.1f} MB -> {args.out}")
    if args.export_certs:
        names = pki.export_pems(args.export_certs)
        print(f"exported {len(names)} server cert/key pair(s) + CA -> {args.export_certs}/")
    if args.export_iocs:
        r = INC.threat_collection(args.export_iocs + ".stix.json", args.export_iocs + ".csv")
        print(f"wrote threat collection: {r['indicators']} indicators -> {r['stix']}")
    if args.stats:
        with open(args.stats, "w") as sf:
            json.dump(eng.stats, sf, indent=1)
    for k, (n, b, *_) in sorted(eng.stats.items(), key=lambda kv: -kv[1][1]):
        print(f"  {k:12s} {n:>9,} pkts {b/1e6:>9.2f} MB")


if __name__ == "__main__":
    main()
