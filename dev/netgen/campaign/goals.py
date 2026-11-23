"""Goal modes and starter templates for the campaign builder.

A goal is a named bundle of compiler options (which stages to build, how many beacons), nothing more:
the campaign file stays the same schema, so a goal never changes what an existing campaign produces.
A template is a goal plus a small hand-written indicator set that uses only documentation addresses
and reserved example domains, so it builds with no feed and no network.
"""
import copy

GOALS = {
    "balanced": {"title": "Balanced intrusion",
                 "plain": "The default chain: discovery, credential access, lateral movement and exfiltration.",
                 "options": {}},
    "lateral-movement": {"title": "Lateral movement",
                         "plain": "Aims at detections for moving between hosts: discovery, stolen credentials, remote execution, persistence and privilege escalation.",
                         "options": {"include": ["discovery", "credential_access", "lateral_movement", "persistence", "privilege_escalation"],
                                     "beacons_per_c2": 3}},
    "credential-theft": {"title": "Credential theft",
                         "plain": "Aims at credential-abuse detections: discovery, Kerberos and password attacks, privilege escalation and log tampering.",
                         "options": {"include": ["discovery", "credential_access", "privilege_escalation", "stealth"]}},
    "data-theft": {"title": "Data theft",
                   "plain": "Aims at exfiltration detections: discovery, collection, a covered-up upload to the exfiltration host.",
                   "options": {"include": ["discovery", "collection", "exfiltration", "stealth"]}},
    "ransomware": {"title": "Ransomware",
                   "plain": "Aims at pre-encryption and encryption detections: spread, security tools stopped, data staged out, then impact.",
                   "options": {"include": ["discovery", "credential_access", "lateral_movement", "defense_impairment",
                                           "exfiltration", "impact"]}},
    "c2-beaconing": {"title": "Command-and-control beaconing",
                     "plain": "Only the command channel: many beacons per server and nothing else, for testing beacon and C2-reputation detections.",
                     "options": {"include": [], "beacons_per_c2": 12}},
    "recon-access": {"title": "Reconnaissance and initial access",
                     "plain": "The front of the chain: scanning, infrastructure set-up and the first foothold, with no activity inside the network.",
                     "options": {"include": ["reconnaissance", "resource_development", "initial_access", "execution"]}},
}


def _i(typ, value, role, why, note="", conf=80):
    return {"type": typ, "value": value, "role": role, "confidence": conf, "source": "template", "why": why, "note": note}


TEMPLATES = {
    "ransomware-precursor": {
        "title": "Ransomware precursor", "goal": "ransomware",
        "plain": "A beacon to a command server, stolen credentials, spread to a server, then a staged upload before encryption.",
        "iocs": [_i("ipv4", "203.0.113.10", "c2", "template command server"),
                 _i("domain", "update-check.example.net", "c2", "template command domain"),
                 _i("ipv4", "198.51.100.20", "exfil", "template upload host"),
                 _i("url", "http://payload.example.org/stage/setup.bin", "payload", "template payload download")]},
    "credential-theft-chain": {
        "title": "Credential theft chain", "goal": "credential-theft",
        "plain": "One beacon plus password attacks from a scanner, so a sensor sees credential abuse inside the network.",
        "iocs": [_i("ipv4", "203.0.113.11", "c2", "template command server"),
                 _i("ipv4", "198.51.100.21", "brute", "template password-guessing source")]},
    "slow-data-theft": {
        "title": "Slow data theft", "goal": "data-theft",
        "plain": "A quiet beacon and one large upload to an outside host.",
        "iocs": [_i("domain", "sync-service.example.com", "c2", "template command domain"),
                 _i("ipv4", "198.51.100.22", "exfil", "template upload host")]},
    "web-server-compromise": {
        "title": "Web-facing product compromise", "goal": "recon-access",
        "plain": "A scanner finds a remote-access gateway, an inert exploit-attempt probe follows, then a download.",
        "iocs": [_i("ipv4", "203.0.113.12", "scanner", "template scanner"),
                 _i("cve", "CVE-2023-4966", "vulnerability", "template product flaw",
                    note="Citrix NetScaler ADC: Buffer Overflow | affects NetScaler ADC and Gateway"),
                 _i("url", "http://payload.example.org/drop/tool.exe", "payload", "template payload download")]},
    "beacon-only": {
        "title": "Beacon-only test", "goal": "c2-beaconing",
        "plain": "Two command servers and a dozen beacons each, for testing beacon detections alone.",
        "iocs": [_i("ipv4", "203.0.113.13", "c2", "template command server"),
                 _i("domain", "cdn-assets.example.net", "c2", "template command domain")]},
}


def goal_options(goal):
    """Option overrides for a goal id; ValueError for an unknown id."""
    if goal not in GOALS:
        raise ValueError("unknown goal %r" % str(goal)[:40])
    return copy.deepcopy(GOALS[goal]["options"])


def catalog():
    """JSON-ready lists for the UI: goals (with their options) and templates (with their indicators)."""
    return {"goals": [dict(id=k, **copy.deepcopy(v)) for k, v in GOALS.items()],
            "templates": [dict(id=k, **copy.deepcopy(v)) for k, v in TEMPLATES.items()]}
