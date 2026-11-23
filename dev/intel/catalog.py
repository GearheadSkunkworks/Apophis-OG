"""Offline catalog of malware families and tools named in public feeds (no network, no engine imports).

``family_for(ioc)`` finds the entry a feed record names in its tags, note or source; ``text(entry)`` is the plain
sentence the indicator card shows. Entries say what the thing is and how it is usually used, in general terms from
public reporting. They describe; they carry no tooling.
"""
import re

# id: (display name, kind, description, aliases)
FAMILIES = {
    "cobalt-strike": ("Cobalt Strike", "C2 framework", "a commercial adversary-simulation framework that criminals and state actors also run; its beacons check in to a team server over HTTP(S) or DNS", ("cobaltstrike",)),
    "sliver": ("Sliver", "C2 framework", "an open-source command-and-control framework used for red teaming and by intruders, talking over HTTP(S), DNS, mTLS or WireGuard", ()),
    "brute-ratel": ("Brute Ratel", "C2 framework", "a commercial red-team command-and-control tool built to evade endpoint detection, now seen in intrusions", ("bruteratel",)),
    "havoc": ("Havoc", "C2 framework", "an open-source post-exploitation command-and-control framework", ()),
    "metasploit": ("Metasploit / Meterpreter", "C2 framework", "an exploitation framework whose Meterpreter payload gives an operator a remote session", ("meterpreter",)),
    "qakbot": ("QakBot", "banking trojan and loader", "a trojan that steals credentials and loads further malware, often a first step before ransomware", ("qbot", "pinkslipbot")),
    "emotet": ("Emotet", "botnet and loader", "a long-running botnet spread by phishing email that delivers other malware families", ()),
    "icedid": ("IcedID", "banking trojan and loader", "a trojan that harvests banking credentials and loads follow-on tools such as ransomware", ("bokbot",)),
    "trickbot": ("TrickBot", "botnet and loader", "a modular botnet used to steal credentials, move sideways and deploy ransomware", ()),
    "dridex": ("Dridex", "banking trojan", "a banking trojan distributed by phishing, also used to load ransomware", ()),
    "bumblebee": ("BumbleBee", "loader", "a loader that delivers post-exploitation tools ahead of ransomware", ()),
    "pikabot": ("PikaBot", "loader", "a loader spread by phishing that opens the way for further payloads", ()),
    "asyncrat": ("AsyncRAT", "remote access trojan", "an open-source remote access trojan that gives full control of a workstation", ()),
    "remcos": ("Remcos", "remote access trojan", "a commercial remote-control product widely abused as a trojan", ()),
    "njrat": ("njRAT", "remote access trojan", "a widely shared remote access trojan used for spying and control", ("bladabindi",)),
    "agent-tesla": ("Agent Tesla", "information stealer", "a keylogger and credential stealer sold as a service, usually spread by phishing", ("agenttesla",)),
    "formbook": ("Formbook / XLoader", "information stealer", "a stealer that captures keystrokes and browser data and sends them to a server", ("xloader",)),
    "lumma-stealer": ("Lumma Stealer", "information stealer", "a stealer sold as a service that takes browser credentials, wallets and files", ("lumma", "lummac2")),
    "redline": ("RedLine Stealer", "information stealer", "a stealer that takes saved passwords, cookies and wallet data", ("redlinestealer",)),
    "raccoon": ("Raccoon Stealer", "information stealer", "a stealer sold as a service that takes browser data and credentials", ("raccoonstealer",)),
    "vidar": ("Vidar", "information stealer", "a stealer that takes browser data, wallets and files and reports to a server", ()),
    "mirai": ("Mirai", "IoT botnet", "malware that takes over internet-connected devices to launch denial-of-service floods and scans", ()),
    "gafgyt": ("Gafgyt / Bashlite", "IoT botnet", "a botnet of compromised routers and cameras used for floods and scanning", ("bashlite",)),
    "mozi": ("Mozi", "IoT botnet", "a peer-to-peer botnet spread across routers and other embedded devices", ()),
    "smokeloader": ("SmokeLoader", "loader", "a small loader that downloads other malware for paying customers", ()),
    "guloader": ("GuLoader", "loader", "a downloader that delivers stealers and trojans while hiding from analysis", ("cloudeye",)),
    "socgholish": ("SocGholish", "loader", "fake browser-update lures on compromised websites that lead to a remote access foothold", ("fakeupdates",)),
    "gootloader": ("GootLoader", "loader", "a loader delivered through poisoned search results that leads to ransomware or hands-on intrusion", ()),
    "lockbit": ("LockBit", "ransomware", "a ransomware-as-a-service operation that encrypts files and threatens to publish stolen data", ()),
    "blackcat": ("BlackCat / ALPHV", "ransomware", "a ransomware-as-a-service operation using double extortion", ("alphv",)),
    "akira": ("Akira", "ransomware", "a ransomware group that gets in through exposed remote access, steals data and encrypts file servers", ()),
    "royal": ("Royal", "ransomware", "a ransomware group that steals data and then encrypts systems; later rebranded", ()),
    "blackbasta": ("Black Basta", "ransomware", "a ransomware group using double extortion, often after phishing or exposed services", ()),
    "play": ("Play", "ransomware", "a ransomware group that encrypts files after intrusion through exposed services", ("playcrypt",)),
    "conti": ("Conti", "ransomware", "a ransomware operation that spread through networks with stolen credentials before encrypting", ()),
    "revil": ("REvil / Sodinokibi", "ransomware", "a ransomware-as-a-service operation using double extortion", ("sodinokibi",)),
    "clop": ("Clop", "ransomware", "a ransomware group known for mass theft of data from file-transfer products", ("cl0p",)),
    "medusa": ("Medusa", "ransomware", "a ransomware group using double extortion through a leak site", ()),
    "gh0st": ("Gh0st RAT", "remote access trojan", "a long-lived open-source remote access trojan reused by many actors", ("gh0strat",)),
    "plugx": ("PlugX", "remote access trojan", "a modular backdoor used by espionage actors", ("korplug",)),
    "shadowpad": ("ShadowPad", "backdoor", "a modular backdoor used by espionage actors, sold among related groups", ()),
    "tor": ("Tor", "anonymity network", "an anonymity network; relays and exit nodes appear when malware hides its traffic", ("torexit", "torrelay")),
}
_NON = re.compile(r"[^a-z0-9]+")


def _words(s):
    return " " + _NON.sub(" ", str(s or "").lower()).strip() + " "


def _forms(name):
    w = _words(name).strip()
    return {" " + w + " ", " " + w.replace(" ", "") + " "}


# whole-word match only: "play" must not fire inside "display" or "replay"
_INDEX = sorted(((f, fid) for fid, e in FAMILIES.items() for a in (e[0], fid.replace("-", " ")) + tuple(e[3])
                 for f in _forms(a) if len(f.strip()) >= 3), key=lambda p: -len(p[0]))


def family_for(ioc):
    """Catalog id named in the indicator's tags, note or source, else None (longest name wins)."""
    hay = _words(" ".join([str(t) for t in ioc.get("tags") or []] + [str(ioc.get("note") or ""), str(ioc.get("source") or "")]))
    for form, fid in _INDEX:
        if form in hay:
            return fid
    return None


def text(fid):
    name, kind, desc, _ = FAMILIES[fid]
    return "Linked to %s (%s): %s." % (name, kind, desc)
