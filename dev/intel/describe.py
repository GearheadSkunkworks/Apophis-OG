"""Offline explanation and wire filter for indicators (no network, no engine imports).

playable(ioc) -> (bool, reason): will this indicator reasonably put packets on the wire? The campaign
engine only turns IPv4 addresses, domains and URLs into traffic, so everything else is hidden from the
builder with a plain reason. card(ioc) -> {"what", "traffic"}: what the indicator is and what the
campaign will send for it, built only from the record's own fields and the role table below.
"""

from . import cve_profiles

WIRE_TYPES = ("ipv4", "domain", "url")

_WHY_HIDDEN = {
    "cve": "nothing in its record points to a network-facing product, so an attempt would not be seen on the wire",
    "ipv6": "IPv6 indicators are carried but not simulated",
    "cidr": "an address range is not a single host to talk to",
    "email": "an email address is not seen on the wire by itself",
    "filename": "a file name is not seen on the wire by itself",
    "md5": "a file hash is not seen on the wire by itself",
    "sha1": "a file hash is not seen on the wire by itself",
    "sha256": "a file hash is not seen on the wire by itself",
}

# role -> (what it is, what the campaign sends)
_ROLE = {
    "c2": ("a command-and-control server the malware reports to",
           "repeated TLS/HTTPS beacons from the infected workstation, with a DNS lookup first for a domain"),
    "payload": ("a host that serves the malware payload",
                "an HTTP(S) download of an inert file to the infected workstation"),
    "exfil": ("a destination that stolen data is sent to",
              "a large outbound upload from an internal host"),
    "scanner": ("an outside host that probes networks for targets",
                "inbound connection attempts across many internal addresses and ports"),
    "brute": ("an outside host that guesses passwords",
              "repeated failed logins against an internal service, then one that succeeds"),
    "phishing": ("a host used in phishing delivery",
                 "a workstation fetching the lure page or file"),
    "tor": ("a Tor relay or exit node", "a Tor-style TLS session from the workstation"),
    "compromised": ("a legitimate site known to be compromised",
                    "a workstation fetching content from it"),
    "unknown": ("an indicator whose role is not known", None),
}


def playable(ioc):
    """(True, "") for wire-capable indicators, else (False, plain reason)."""
    t = ioc.get("type")
    if t == "cve":
        return (True, "") if cve_profiles.match(ioc) else (False, _WHY_HIDDEN["cve"])
    return (True, "") if t in WIRE_TYPES else (False, _WHY_HIDDEN.get(t, "it is not seen on the wire"))


def card(ioc):
    if ioc.get("type") == "cve":
        pr = cve_profiles.match(ioc)
        head, _, rest = (ioc.get("note") or "exploited in the wild").partition(" | ")
        return {"what": "%s: %s. Affects %s. %s %s" % (ioc["value"], head, pr["what"], rest.replace(" | ", " "), ioc.get("why") or ""),
                "traffic": "Sends: an inert probe of %s on the web server, then the server's refusal. No exploit "
                           "content: whether a sensor flags it depends on the sensor." % pr["paths"][0]}
    role = "payload" if ioc.get("type") == "url" and ioc.get("role") == "unknown" else ioc.get("role")  # the compiler treats an unlabelled URL as a payload source
    what, traffic = _ROLE.get(role, _ROLE["unknown"])
    kind = {"ipv4": "IP address", "domain": "domain name", "url": "URL"}.get(ioc.get("type"), ioc.get("type"))
    bits = [("%s %s: %s" % (ioc.get("value"), kind, what))]
    for k, label in (("source", "from"), ("first_seen", "first seen")):
        if ioc.get(k):
            bits.append("%s %s" % (label, ioc[k]))
    if ioc.get("tags"):
        bits.append("tags: " + ", ".join(ioc["tags"][:5]))
    if ioc.get("note"):
        bits.append(ioc["note"])
    return {"what": ". ".join(bits), "traffic": ("Sends: " + traffic + ".") if traffic else
            "Sends nothing until you give it a role (c2, payload, exfil, scanner, brute...)."}


def annotate(kept, dropped):
    """Split `kept` into playable (each gets a `card`) and hidden; hidden join `dropped` as (ioc, reason)."""
    out, extra = [], []
    for i in kept:
        ok, why = playable(i)
        if ok:
            out.append(dict(i, card=card(i)))
        else:
            extra.append((i, "hidden, not on the wire: " + why))
    return out, list(dropped) + extra
