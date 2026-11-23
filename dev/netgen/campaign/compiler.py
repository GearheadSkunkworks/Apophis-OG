"""Compile an indicator list into a campaign (v1) with a rule engine that is deterministic and explainable.

``compile_campaign(iocs, options=None, name=None)`` groups the IOCs by role and lays them over the kill chain:

    Initial Access (phishing IOCs) -> Execution (payload) -> Command And Control (c2, tor) -> Discovery ->
    Credential Access -> Lateral Movement -> Exfiltration -> Impact

Discovery .. Impact are included only when named in ``options["include"]``. Every action carries the indexes of
the IOCs that caused it and a one-sentence ``explain``; stage ``techniques`` come from the action specs (and from
IOC-supplied technique ids that belong to the stage's tactic). The compiler uses only actions that are
registered: a missing action is skipped and the reason is recorded in the campaign's ``explain`` list. Same IOCs
and options always give an identical ``schema.dump``; ``meta.seed`` is a hash of the sorted IOC values, and
``meta.created`` is left empty (stamp it outside, a clock would break determinism).

PREFERRED lists the action tokens per tactic the compiler reaches for (the contract with the action modules).
"""
import hashlib
import math
import re
from urllib.parse import urlsplit

from . import actions as _actions
from intel import cve_profiles as _cve_profiles
from . import addressing, attack, families, schema
from .actions import spec_actions as _spec_actions

PREFERRED = {
    "reconnaissance": ["web_dir_scan", "subdomain_enum"],
    "resource-development": ["new_domain_contact", "selfsigned_tls_contact"],
    "initial-access": ["phishing_visit", "web_login_spray", "exposed_service_login"],
    "execution": ["payload_download", "winrm_exec", "ssh_remote_exec"],
    "persistence": ["remote_schtask", "svcctl_persist"],
    "privilege-escalation": ["gpo_modify", "privileged_group_add"],
    "stealth": ["eventlog_clear", "lolbin_fetch"],
    "defense-impairment": ["security_service_stop", "security_update_block"],
    "command-and-control": ["https_beacon", "http_beacon", "dns_beacon", "tor_connect"],
    "discovery": ["ldap_recon", "smb_share_enum", "port_probe", "syn_scan"],
    "credential-access": ["kerberoast", "kerberos_spray", "ssh_brute", "rdp_brute"],
    "lateral-movement": ["smb_admin_exec", "rdp_session"],
    "collection": ["sql_collect", "archive_stage"],
    "exfiltration": ["https_upload", "dns_exfil", "ftp_upload"],
    "impact": ["ransomware_smb"],
}
MAX_C2, MAX_PAYLOAD_REFS, MAX_TOR, MAX_PHISH, MAX_BRUTE, MAX_PAYLOAD_HOSTS = 8, 30, 3, 3, 3, 3
_NARRATIVE = {
    "initial-access": "a user on the compromised workstation is lured to a credential-harvesting page",
    "execution": "the payload is fetched and runs on the workstation",
    "command-and-control": "the implant checks in with its command-and-control infrastructure",
    "discovery": "the operator maps the directory, shares and services around the workstation",
    "credential-access": "the operator requests service tickets and tries passwords against exposed services",
    "lateral-movement": "the operator moves from the workstation to a server",
    "exfiltration": "collected data leaves the network to an attacker-controlled host",
    "impact": "files on a share are mass-renamed, the pattern ransomware leaves on the wire",
    "reconnaissance": "an outside host probes the company's web server and domain names",
    "resource-development": "the workstation contacts attacker-prepared infrastructure: a fresh domain and a self-signed server",
    "persistence": "the operator sets up a scheduled task and a service so the access survives a reboot",
    "privilege-escalation": "the operator edits a group policy and adds an account to a privileged group",
    "stealth": "the operator clears the event log and fetches a file with a signed system component",
    "defense-impairment": "security services are stopped and the vendor update host is blocked",
    "collection": "the operator reads large result sets from a database and stages an archive on a server",
}
_ROLE_LABEL = {"c2": "C2", "payload": "Payload", "exfil": "Exfiltration", "scanner": "Scanner", "brute": "Brute-force",
               "phishing": "Phishing", "tor": "Tor", "compromised": "Compromised-host", "unknown": "Unclassified"}
_VERB = {
    "phishing_visit": "visited the sign-in page of", "payload_download": "was downloaded from",
    "https_beacon": "received HTTPS beacons from the compromised workstation", "http_beacon": "received HTTP beacons from the compromised workstation",
    "dns_beacon": "was queried by DNS beacons from the compromised workstation", "tor_connect": "was connected to as a Tor relay",
    "ldap_recon": "", "smb_share_enum": "", "port_probe": "", "syn_scan": "scanned the target",
    "ssh_brute": "attempted SSH logons against the target", "rdp_brute": "attempted RDP logons against the target",
    "https_upload": "received an HTTPS upload of staged data", "dns_exfil": "received data in DNS query names",
    "ftp_upload": "received an FTP upload of staged data",
}
_FILETYPES = {"exe": "exe", "dll": "dll", "elf": "elf", "zip": "zip", "pdf": "pdf", "doc": "doc", "docx": "doc", "docm": "doc",
              "xls": "doc", "xlsx": "doc"}


def _title(slug):
    return " ".join(w.capitalize() for w in slug.split("-"))


def _short(v, n=60):
    return v if len(v) <= n else v[:n - 3] + "..."


def _is_endpoint(ioc):
    return ioc["type"] in ("ipv4", "domain")


def _url_parts(url):
    try:
        u = urlsplit(url)
        return (u.scheme or "").lower(), u.path or ""
    except ValueError:
        return "", ""


class _Builder:
    def __init__(self, iocs, opts, reg, notes):
        self.iocs, self.o, self.reg, self.notes = iocs, opts, reg, notes
        self.by_role = {}
        for i, ioc in enumerate(iocs):
            self.by_role.setdefault(ioc["role"], []).append(i)
        # position of an ipv4/domain IOC inside its role list (the N in "c2:N")
        self.pos = {}
        for role, idxs in self.by_role.items():
            n = 0
            for i in idxs:
                if _is_endpoint(iocs[i]):
                    self.pos[i] = n
                    n += 1
        self.comp = opts["compromised"]
        lt = opts["lateral_target"]
        self.lat = lt if lt in schema.INTERNAL_ROLES or lt.startswith("host:") else "host:" + lt
        self.profiles = None
        try:
            from .actions import c2 as _c2
            self.profiles = set(getattr(_c2, "PROFILES", {}))
        except Exception:
            pass

    # ---- IOC helpers
    def hosts(self, role, types=("ipv4", "domain", "url")):
        return [i for i in self.by_role.get(role, []) if self.iocs[i]["type"] in types]

    def ref(self, i):
        """Endpoint reference for IOC i: 'role:N' for ipv4/domain, 'ioc:i' for a URL."""
        ioc = self.iocs[i]
        if ioc["type"] in ("ipv4", "domain"):
            pre = {"phishing": "phish"}.get(ioc["role"], ioc["role"])
            return "%s:%d" % (pre, self.pos[i])
        return "ioc:%d" % i

    def label(self, i):
        ioc = self.iocs[i]
        return "%s indicator %d (%s)" % (_ROLE_LABEL.get(ioc["role"], "Indicator"), i + 1, _short(ioc["value"]))

    # ---- action placement
    def add(self, acts, tokens, pairs, params, ioc_idx, why, at=0.0, extra_techniques=()):
        tokens = [tokens] if isinstance(tokens, str) else list(tokens)
        for tok in tokens:
            spec = self.reg.get(tok)
            if spec is None:
                continue
            for f, t in pairs:
                kf, kt = schema.endpoint_kind(f), schema.endpoint_kind(t)
                if spec.src in ("internal", "external") and kf != spec.src:
                    continue
                if spec.dst in ("internal", "external") and kt != spec.dst:
                    continue
                if spec.ot:
                    continue
                p = {k: v for k, v in (params or {}).items() if k in spec.params and v is not None}
                acts.append({"action": tok, "from": f, "to": t, "params": p, "at": round(float(at), 1),
                             "ioc": list(ioc_idx), "explain": why.replace("{v}", _VERB.get(tok, "was used by")), "_spec": spec})
                return spec
        self.notes.append("skipped %s: %s" % (tokens[0], "action not available in this build"
                                              if not any(t in self.reg for t in tokens) else "no endpoint pair fits it"))
        return None

    def dur(self, act):
        spec = act["_spec"]
        p = act["params"]
        if "count" in p and "interval_s" in spec.params or ("count" in p and spec.token.endswith("beacon")):
            iv = float(p.get("interval_s") or spec.params.get("interval_s", {}).get("default") or 60.0)
            return max(spec.min_duration_s, p["count"] * iv)
        if "duration_s" in p:
            return float(p["duration_s"])
        return float(spec.min_duration_s)

    def stage(self, sid, tactic, acts, parallel=False):
        if not acts:
            return None
        techs = []
        t = 0.0
        end = 0.0
        for k, a in enumerate(acts):
            spec = a.pop("_spec")
            a["_dur"] = self.dur({"_spec": spec, "params": a["params"]})
            if not parallel:
                a["at"] = round(t, 1)
            else:
                a["at"] = round(k * 7.0, 1)
            end = max(end, a["at"] + a["_dur"])
            t = a["at"] + min(a["_dur"], 60.0) + 2.0
            for tid in list(spec.techniques) + [x for i in a["ioc"] for x in self.iocs[i]["techniques"]
                                                 if tactic in (attack.technique(x) or {}).get("tactics", [])]:
                if tid not in techs and not attack.validate_ids([tid]):
                    techs.append(tid)
            del a["_dur"]
        dur = int(math.ceil(end + 10))
        return {"id": sid, "name": _title(tactic), "tactic": tactic, "techniques": techs,
                "narrative": _NARRATIVE[tactic], "duration_s": dur, "fast_s": max(10, int(math.ceil(dur / 4.0))),
                "actions": acts}


# ---------------------------------------------------------------- stage rules
def _initial_access(b):
    acts = []
    for k, i in enumerate(b.hosts("phishing")[:MAX_PHISH]):
        ioc = b.iocs[i]
        params = {}
        if ioc["type"] == "url":
            scheme, path = _url_parts(ioc["value"])
            if scheme in ("http", "https"):
                params["scheme"] = scheme
            if path.startswith("/") and len(path) < 200 and re.fullmatch(r"[A-Za-z0-9_./~%-]+", path):
                params["path"] = path
        b.add(acts, "phishing_visit", [(b.comp, b.ref(i))], params, [i],
              "%s: a user visited this phishing page and submitted dummy credentials" % b.label(i), at=0)
    vsrc = _outside_source(b)
    for i in b.by_role.get("vulnerability", [])[:MAX_PHISH]:
        ioc = b.iocs[i]
        pr = _cve_profiles.match(ioc) if ioc["type"] == "cve" else None
        if pr:
            b.add(acts, "exploit_probe", [(b.ref(vsrc) if vsrc is not None else "attacker", "web")],
                  {"profile": pr["id"], "cve": ioc["value"]}, [i],
                  "%s: an internet host probed the %s with the shape of an attempt (no exploit content)" % (ioc["value"], pr["what"]), at=0)
    if "initial_access" in b.o["include"]:
        src = _outside_source(b)
        if src is not None:
            b.add(acts, "web_login_spray", [(b.ref(src), "web")], {}, [src],
                  b.label(src) + " sprayed dummy credentials at the company's web login (initial-access rule)")
            b.add(acts, "exposed_service_login", [(b.ref(src), b.lat)], {}, [src],
                  b.label(src) + " tried to sign in to an exposed remote-access service (initial-access rule)")
        else:
            b.notes.append("skipped web_login_spray: no outside indicator to act as the source")
    return acts


def _outside_source(b):
    """Index of an outside host indicator that can play an inbound actor: scanner, then brute, then C2."""
    for role in ("scanner", "brute", "c2"):
        h = b.hosts(role, ("ipv4", "domain"))
        if h:
            return h[0]
    return None


def _execution(b):
    acts = _execution_payload(b)
    if "execution" in b.o["include"]:
        b.add(acts, "winrm_exec", [(b.comp, b.lat)], {}, [], "Remote shell run over WS-Management on the target (execution rule)")
        b.add(acts, "ssh_remote_exec", [(b.comp, b.lat)], {}, [], "Remote command run over SSH on the target (execution rule)")
    return acts


def _execution_payload(b):
    acts = []
    cands = b.hosts("payload")
    if not cands:
        cands = [i for i in b.by_role.get("unknown", []) if b.iocs[i]["type"] == "url"]
    hashes = [i for i in b.by_role.get("payload", []) if b.iocs[i]["type"] in ("md5", "sha1", "sha256", "filename")]
    for k, i in enumerate(cands[:MAX_PAYLOAD_HOSTS]):
        ioc = b.iocs[i]
        params = {}
        if ioc["type"] == "url":
            scheme, path = _url_parts(ioc["value"])
            if scheme in ("http", "https"):
                params["scheme"] = scheme
            if re.fullmatch(r"/[A-Za-z0-9_./~%-]{0,198}", path or ""):
                params["path"] = path
                name = path.rsplit("/", 1)[-1]
                if "." in name:
                    params["filename"] = name
                    ft = _FILETYPES.get(name.rsplit(".", 1)[-1].lower())
                    if ft:
                        params["filetype"] = ft
        refs = [i] + (hashes[:MAX_PAYLOAD_REFS - 1] if k == 0 else [])
        extra = " (%d payload hash/file indicators attached)" % (len(refs) - 1) if len(refs) > 1 else ""
        b.add(acts, "payload_download", [(b.comp, b.ref(i))], params, refs,
              "%s was downloaded onto the compromised workstation%s" % (b.label(i), extra))
    return acts


def _profile(b, ioc):
    if families.for_ioc(ioc):
        return None                                   # a family tag wins; _c2 handles it
    tags = " ".join(ioc["tags"]).lower().replace(" ", "")
    for key, prof in (("cobaltstrike", "cobaltstrike-like"), ("empire", "empire-like")):
        if key in tags and (b.profiles is None or prof in b.profiles):
            return prof
    return None


def _reconnaissance(b):
    acts = []
    src = _outside_source(b)
    if src is None:
        b.notes.append("skipped reconnaissance: no outside indicator to act as the source")
        return acts
    b.add(acts, "web_dir_scan", [(b.ref(src), "web")], {}, [src],
          b.label(src) + " scanned the company's web server for common paths (reconnaissance rule)")
    b.add(acts, "subdomain_enum", [(b.ref(src), "dc")], {}, [src],
          b.label(src) + " looked up common sub-names of the company domain (reconnaissance rule)")
    return acts


MAX_DATA_PER_ROLE = 3


def _data_actions(b, tactic):
    """Data-defined actions (specs with a "for_role") placed once per indicator of their role, in their tactic's stage."""
    acts = []
    for tok, role in sorted(_spec_actions.placements().items()):
        spec = b.reg.get(tok)
        if spec is None or spec.tactic != tactic:
            continue
        for i in b.hosts(role)[:MAX_DATA_PER_ROLE]:
            pair = (b.ref(i), "web") if spec.src == "external" else (b.comp, b.ref(i))
            b.add(acts, tok, [pair], {}, [i], "%s: %s (data-defined action)" % (b.label(i), spec.summary.rstrip(".").lower()))
    return acts


def _resource_development(b):
    acts = []
    doms = [i for i in b.hosts("c2", ("domain",)) + b.hosts("payload", ("domain",))]
    hosts = b.hosts("c2", ("ipv4", "domain"))
    if doms:
        b.add(acts, "new_domain_contact", [(b.comp, b.ref(doms[0]))], {}, [doms[0]],
              b.label(doms[0]) + " is a recently registered domain the workstation contacted (resource-development rule)")
    if hosts:
        b.add(acts, "selfsigned_tls_contact", [(b.comp, b.ref(hosts[-1]))], {}, [hosts[-1]],
              b.label(hosts[-1]) + " answered with a self-signed certificate on a non-standard port (resource-development rule)")
    if not acts:
        b.notes.append("skipped resource development: no C2 or payload host to contact")
    return acts


def _persistence(b):
    acts = []
    b.add(acts, "remote_schtask", [(b.comp, b.lat)], {}, [], "Scheduled task registered remotely on the target (persistence rule)")
    b.add(acts, "svcctl_persist", [(b.comp, b.lat)], {}, [], "Auto-start service created on the target (persistence rule)")
    return acts


def _privilege_escalation(b):
    acts = []
    b.add(acts, "gpo_modify", [(b.comp, "dc")], {}, [], "Group policy object changed on the directory (privilege-escalation rule)")
    b.add(acts, "privileged_group_add", [(b.comp, "dc")], {}, [], "Account added to a privileged group (privilege-escalation rule)")
    return acts


def _stealth(b):
    acts = []
    b.add(acts, "eventlog_clear", [(b.comp, b.lat)], {}, [], "Event log cleared on the target (stealth rule)")
    pay = b.hosts("payload", ("ipv4", "domain")) or b.hosts("c2", ("ipv4", "domain"))
    if pay:
        b.add(acts, "lolbin_fetch", [(b.comp, b.ref(pay[0]))], {}, [pay[0]],
              b.label(pay[0]) + " served a file to a signed system component (stealth rule)")
    else:
        b.notes.append("skipped lolbin_fetch: no payload or C2 host to fetch from")
    return acts


def _defense_impairment(b):
    acts = []
    b.add(acts, "security_service_stop", [(b.comp, b.lat)], {}, [], "Security services stopped on the target (defense-impairment rule)")
    ext = b.hosts("c2", ("ipv4", "domain")) or b.hosts("payload", ("ipv4", "domain"))
    if ext:
        b.add(acts, "security_update_block", [(b.comp, b.ref(ext[0]))], {}, [ext[0]],
              b.label(ext[0]) + " stands in for the security vendor's update host that the workstation can no longer reach (defense-impairment rule)")
    else:
        b.notes.append("skipped security_update_block: no outside host to stand in for the update server")
    return acts


def _collection(b):
    acts = []
    b.add(acts, "sql_collect", [(b.comp, "sql")], {}, [], "Large result sets read from the database server (collection rule)")
    b.add(acts, "archive_stage", [(b.comp, b.lat)], {}, [], "Archive written into a staging directory on the target (collection rule)")
    return acts


def _c2(b):
    acts = []
    c2 = b.hosts("c2")
    if len(c2) > MAX_C2:
        b.notes.append("%d C2 indicators found; the first %d are beaconed to" % (len(c2), MAX_C2))
    for i in c2[:MAX_C2]:
        ioc = b.iocs[i]
        scheme = _url_parts(ioc["value"])[0] if ioc["type"] == "url" else ""
        tags = " ".join(ioc["tags"]).lower()
        if scheme == "http":
            toks = ["http_beacon", "https_beacon", "dns_beacon"]
        elif ioc["type"] == "domain" and "dns" in tags and "tunnel" not in tags:
            toks = ["dns_beacon", "https_beacon", "http_beacon"]
        else:
            toks = ["https_beacon", "http_beacon", "dns_beacon"]
        params = {"count": b.o["beacons_per_c2"]}
        pick = b.o.get("family", "auto")
        fid = None if pick == "none" else (pick if pick in families.FAMILIES else families.for_ioc(ioc))
        fam = families.FAMILIES.get(fid) if fid else None
        why = b.label(i) + " {v}"
        if fam:
            if not scheme:
                toks = {"http": ["http_beacon", "https_beacon", "dns_beacon"],
                        "dns": ["dns_beacon", "https_beacon", "http_beacon"]}.get(fam["kind"], toks)
            params.update(profile=fid, interval_s=fam["interval_s"], jitter=fam["jitter"],
                          size_min=fam["size_min"], size_max=fam["size_max"])
            why += " (%s look-alike beacon profile, %s)" % (fam["name"], "chosen for the campaign" if pick == fid else "family tag on the indicator")
            b.notes.append(("indicator %d: the campaign picks the family %s: beacons use the %s profile" if pick == fid else
                            "indicator %d carries the family tag %s: beacons use the %s profile") % (i + 1, fam["name"], fid))
        else:
            prof = _profile(b, ioc)
            if prof:
                params["profile"] = prof
        b.add(acts, toks, [(b.comp, b.ref(i))], params, [i], why, at=0)
    for i in b.hosts("tor", ("ipv4", "domain"))[:MAX_TOR]:
        b.add(acts, "tor_connect", [(b.comp, b.ref(i))], {}, [i], b.label(i) + " {v}")
    return acts


def _discovery(b):
    acts = []
    b.add(acts, "ldap_recon", [(b.comp, "dc")], {}, [], "Directory enumeration from the compromised workstation (discovery rule)")
    b.add(acts, "smb_share_enum", [(b.comp, b.lat)], {}, [], "Share enumeration on the lateral-movement target (discovery rule)")
    b.add(acts, "port_probe", [(b.comp, b.lat)], {}, [], "Service port probe of the lateral-movement target (discovery rule)")
    sc = b.hosts("scanner", ("ipv4", "domain"))
    if sc:
        i = sc[0]
        b.add(acts, "syn_scan", [(b.ref(i), b.lat), (b.comp, b.lat)], {}, [i], b.label(i) + " {v}")
    return acts


def _credential_access(b):
    acts = []
    b.add(acts, "kerberoast", [(b.comp, "dc")], {}, [], "Service tickets requested for offline cracking (credential-access rule)")
    b.add(acts, "kerberos_spray", [(b.comp, "dc")], {}, [], "Passwords sprayed against the directory over Kerberos (credential-access rule)")
    for i in b.hosts("brute", ("ipv4", "domain"))[:MAX_BRUTE]:
        tags = " ".join(b.iocs[i]["tags"]).lower()
        toks = ["rdp_brute", "ssh_brute"] if "rdp" in tags else ["ssh_brute", "rdp_brute"]
        b.add(acts, toks, [(b.ref(i), b.lat), (b.comp, b.lat)], {}, [i],
              b.label(i) + " {v}")
    return acts


def _lateral(b):
    acts = []
    b.add(acts, "smb_admin_exec", [(b.comp, b.lat)], {}, [], "Remote service created over the admin share of the target (lateral-movement rule)")
    b.add(acts, "rdp_session", [(b.comp, b.lat)], {}, [], "Interactive session opened on the target (lateral-movement rule)")
    return acts


def _exfil(b):
    acts = []
    cands = b.hosts("exfil")
    target, why_role = (cands[0], "exfiltration") if cands else (None, "")
    if target is None:
        c2 = b.hosts("c2")
        target = c2[0] if c2 else None
    if target is None:
        b.notes.append("skipped exfiltration: no exfil or C2 indicator to send data to")
        return acts
    ioc = b.iocs[target]
    scheme = _url_parts(ioc["value"])[0] if ioc["type"] == "url" else ""
    tags = " ".join(ioc["tags"]).lower()
    if scheme == "ftp" or "ftp" in tags:
        toks = ["ftp_upload", "https_upload"]
    elif ioc["type"] == "domain" and "dns" in tags:
        toks = ["dns_exfil", "https_upload"]
    else:
        toks = ["https_upload", "dns_exfil", "ftp_upload"]
    fallback = "" if why_role else " (no exfil indicator, so the first C2 host is used)"
    why = "%s {v}%s" % (b.label(target), fallback)
    b.add(acts, toks, [(b.comp, b.ref(target))], {}, [target], why)
    return acts


def _impact(b):
    acts = []
    b.add(acts, "ransomware_smb", [(b.comp, b.lat)], {}, [], "Mass file rename on a share, the on-wire pattern of ransomware (impact rule)")
    return acts


_RULES = [("reconnaissance", _reconnaissance, "reconnaissance", False),
          ("resource-development", _resource_development, "resource_development", False),
          ("initial-access", _initial_access, None, False), ("execution", _execution, None, False),
          ("persistence", _persistence, "persistence", False),
          ("command-and-control", _c2, None, True),
          ("privilege-escalation", _privilege_escalation, "privilege_escalation", False),
          ("defense-impairment", _defense_impairment, "defense_impairment", False),
          ("stealth", _stealth, "stealth", False),
          ("discovery", _discovery, "discovery", False),
          ("credential-access", _credential_access, "credential_access", False),
          ("lateral-movement", _lateral, "lateral_movement", False),
          ("collection", _collection, "collection", False),
          ("exfiltration", _exfil, "exfiltration", False),
          ("impact", _impact, "impact", False)]


# ---------------------------------------------------------------- public API
def _seed(iocs):
    h = hashlib.sha256("\n".join(sorted(i["value"] for i in iocs)).encode("utf-8")).hexdigest()
    return (int(h[:8], 16) & 0x7FFFFFFF) or 1, h[:6]


def compile_campaign(iocs, options=None, name=None):
    """IOC dicts (contract section 1) + options (section 2 defaults) -> campaign dict, normalised and valid."""
    opts, errs = schema.normalise_options(options)
    if errs:
        raise schema.CampaignError(errs)
    notes, clean, seen = [], [], set()
    for raw in iocs or []:
        ioc = schema.clean_ioc(raw)
        if ioc is None or ioc["type"] not in schema.IOC_TYPES or not ioc["value"] or len(ioc["value"]) > 2048 \
                or not schema._check_value(ioc["type"], ioc["value"]) or schema._CTRL.search(ioc["value"]):
            notes.append("dropped an invalid indicator: %r" % (str(raw.get("value", "") if isinstance(raw, dict) else raw)[:60],))
            continue
        if ioc["type"] in ("domain", "md5", "sha1", "sha256", "cve"):
            ioc["value"] = ioc["value"].lower() if ioc["type"] != "cve" else ioc["value"].upper()
        key = (ioc["type"], ioc["value"])
        if key in seen:
            continue
        seen.add(key)
        if opts["address_mode"] == "real" and ioc["type"] == "ipv4" and ioc["role"] not in ("unknown", "compromised"):
            ok, why = addressing.real_mode_check(ioc["value"])
            if not ok:
                notes.append("indicator %s left unused in real mode: %s" % (ioc["value"], why))
                ioc["role"] = "unknown"
        clean.append(ioc)
        if len(clean) >= schema.MAX_IOCS:
            notes.append("indicator list truncated to %d" % schema.MAX_IOCS)
            break
    v6 = addressing.unsupported_ipv6(clean)
    if v6:
        notes.append("IPv6 indicators are carried but not simulated: " + ", ".join(v6[:10]))

    seed, tag = _seed(clean)
    reg = _actions.load_all()
    b = _Builder(clean, opts, reg, notes)
    stages = []
    for tactic, fn, gate, parallel in _RULES:
        if gate and gate not in opts["include"]:
            continue
        acts = fn(b)
        acts += _data_actions(b, tactic)
        st = b.stage("s%d" % (len(stages) + 1), tactic, acts, parallel)
        if st:
            stages.append(st)
        elif gate or tactic in ("execution", "command-and-control"):
            notes.append("no %s stage: nothing to build it from" % _title(tactic))
    expect = [{"technique": t, "stage": s["id"]} for s in stages for t in s["techniques"]]
    probed = {i for s in stages for a in s["actions"] if a["action"] == "exploit_probe" for i in a["ioc"]}
    vulns = [i for k, i in enumerate(clean) if i["type"] == "cve" and i["role"] == "vulnerability" and k not in probed]
    pairs = []
    for i in vulns:
        for t in i.get("techniques") or []:
            if attack.validate_ids([t]) == [] and len(pairs) < 500:
                pairs.append({"technique": t, "cve": i["value"]})
    expect += pairs
    if vulns:
        notes.append("%d vulnerability indicator(s) carried as detection expectations (%d technique pairs); no network-facing product matched, so no traffic"
                     % (len(vulns), len(pairs)))
    used = {i for s in stages for a in s["actions"] for i in a["ioc"]}
    nm = re.sub(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]", "", str(name or "")).strip() or "Campaign %s" % tag
    sources = sorted({i["source"] for i in clean if i["source"]})[:50]
    roles = {}
    for i in clean:
        roles[i["role"]] = roles.get(i["role"], 0) + 1
    desc = "Compiled from %d indicators (%s); %d used by actions." % (
        len(clean), ", ".join("%d %s" % (n, r) for r, n in sorted(roles.items())) or "none", len(used))
    camp = {"schema": schema.SCHEMA_ID,
            "meta": {"name": nm[:200], "id": re.sub(r"[^a-z0-9]+", "-", nm.lower()).strip("-")[:64] or "campaign",
                     "description": desc, "actor": "Unattributed", "origin_country": "", "created": "", "seed": seed,
                     "source": {"kind": "iocs", "feeds": sources, "ioc_count": len(clean)}},
            "options": opts, "iocs": clean, "stages": stages, "expect": expect, "explain": notes[:1000]}
    return schema.normalise(camp)


def explain_campaign(campaign):
    """Human-readable lines: stage -> action -> IOC mapping, then indicators nothing used, then compiler notes."""
    iocs = campaign.get("iocs", [])
    lines = ["Campaign %s (seed %s): %d indicators, %d stages" % (
        campaign.get("meta", {}).get("name", "?"), campaign.get("meta", {}).get("seed", "?"), len(iocs),
        len(campaign.get("stages", [])))]
    used = set()
    for st in campaign.get("stages", []):
        lines.append("%s  %s [%s]  %s" % (st["id"], st["name"], ", ".join(st.get("techniques", [])), st.get("narrative", "")))
        for a in st["actions"]:
            lines.append("    %s: %s -> %s  %s" % (a["action"], a["from"], a["to"], a.get("explain", "")))
            for i in a.get("ioc", []):
                used.add(i)
                if i < len(iocs):
                    lines.append("        from IOC #%d %s %s (role %s)" % (i + 1, iocs[i]["type"], _short(iocs[i]["value"], 80), iocs[i]["role"]))
    vuln = [i for i in range(len(iocs)) if iocs[i]["type"] == "cve" and iocs[i]["role"] == "vulnerability" and i not in used]
    used |= set(vuln)
    if vuln:
        lines.append("%d vulnerability indicators are carried as detection expectations, not traffic" % len(vuln))
    idle = [i for i in range(len(iocs)) if i not in used]
    if idle:
        lines.append("Indicators not used by any action: %d (%s)" % (len(idle), ", ".join(
            "#%d %s" % (i + 1, iocs[i]["type"]) for i in idle[:12]) + (", ..." if len(idle) > 12 else "")))
    for n in campaign.get("explain", []):
        lines.append("Note: " + n)
    return lines


# ---------------------------------------------------------------- observability evaluator
# Which indicators actually put packets on the wire. Single source of truth for the UI's
# per-indicator "will this produce traffic?" badge. Observability is EXACT and options-aware:
# an indicator is observable iff some placed action referenced its index (the same `used`
# relation compile_campaign reports). The reasons restate facts the compiler already acted on.
_WIRE_TYPES = ("ipv4", "domain", "url")     # cf. exports.OBSERVABLE; ipv6 is carried but not simulated
_TYPE_NOUN = {"md5": "file hash", "sha1": "file hash", "sha256": "file hash", "cve": "CVE",
              "filename": "filename", "email": "email address", "ipv6": "IPv6 address"}
_ROLE_STAGE_HINT = {"brute": ("credential_access", "Credential access"),
                    "exfil": ("exfiltration", "Exfiltration"),
                    "scanner": ("reconnaissance", "Reconnaissance")}


def observability(campaign):
    """Per-indicator verdict for a compiled campaign: will each indicator produce observable traffic?

    Returns a list aligned to ``campaign['iocs']``: ``{index, type, value, role, observable, reason}``.
    ``observable`` is exact (the indicator's index appears in some placed action) and reflects the
    options actually selected; ``reason`` explains a False so the builder can act on it -- a CVE is a
    detection expectation, a non-wire type is carried for traceability, a gated stage is switched off.
    This is the engine-side source of truth the indicator selector's badge reads; it derives nothing
    the compiler did not already decide, so it can never drift from what actually gets generated.
    """
    iocs = campaign.get("iocs", [])
    include = set(campaign.get("options", {}).get("include", []))
    used = {i for s in campaign.get("stages", []) for a in s.get("actions", []) for i in a.get("ioc", [])}
    out = []
    for i, ioc in enumerate(iocs):
        typ, role = ioc.get("type"), ioc.get("role")
        if i in used:
            if typ in _WIRE_TYPES:
                obs, reason = True, "an action in this campaign puts it on the wire"
            elif typ == "cve":
                obs, reason = True, "an inert exploit-attempt probe of the affected product is on the wire"
            else:
                obs, reason = True, ("carried by an observable action (the download that delivers it): "
                                     "the file transfer is on the wire, this indicator identifies it")
        elif typ == "cve" or role == "vulnerability":
            obs, reason = False, "a vulnerability is a detection expectation, not traffic: only its exploitation would be observable"
        elif typ not in _WIRE_TYPES:
            obs = False
            reason = ("IPv6 indicators are carried but not simulated" if typ == "ipv6"
                      else "a %s is carried for traceability only: only an action that uses it is observable" % _TYPE_NOUN.get(typ, typ))
        else:
            hint = _ROLE_STAGE_HINT.get(role)
            if hint and hint[0] not in include:
                obs, reason = False, "no traffic yet: enable the %s stage to generate it" % hint[1]
            else:
                obs, reason = False, "no action in this campaign exercises it"
        out.append({"index": i, "type": typ, "value": ioc.get("value"), "role": role,
                    "observable": obs, "reason": reason})
    return out
