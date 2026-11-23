"""Parsers: text, CSV, STIX 2.x, MISP, OTX, ThreatFox, plus parse_any (format sniffing).

Every parser returns a list of clean IOC dicts (see intel.model) and never raises on hostile or
malformed content; the only exception is ValueError when the input exceeds the size cap
(MAX_BYTES, default 5 MB, or the max_bytes argument). Nothing is evaluated: input is only
decoded, JSON-parsed, regex-matched or csv-parsed. Deep JSON nesting (RecursionError) yields [].
Parsers dedupe their own output and cap it at MAX_IOCS.
"""
import csv
import io
import json
import re

from . import classify, model, roles, tlds

MAX_BYTES = 5 * 1024 * 1024
MAX_IOCS = 50000
_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


# ---------------------------------------------------------------- helpers
def _to_text(data, max_bytes=MAX_BYTES):
    """bytes/str -> str, enforcing the size cap. Invalid UTF-8 is replaced, BOMs removed."""
    if data is None:
        return ""
    if isinstance(data, (bytes, bytearray)):
        if len(data) > max_bytes:
            raise ValueError("input too large (%d bytes, cap %d)" % (len(data), max_bytes))
        b = bytes(data)
        if (b.startswith(b"\xff\xfe") and len(b) > 3 and b[3] == 0) or \
                (b.startswith(b"\xfe\xff") and len(b) > 2 and b[2] == 0):
            text = b.decode("utf-16", errors="replace")
        else:
            text = b.decode("utf-8", errors="replace")
    elif isinstance(data, str):
        if len(data) > max_bytes or len(data.encode("utf-8", errors="replace")) > max_bytes:
            raise ValueError("input too large (cap %d bytes)" % max_bytes)
        text = data
    else:
        raise ValueError("input must be str or bytes")
    text = text.lstrip("﻿").replace("\x00", "")
    return text


def _json_load(data, max_bytes=MAX_BYTES):
    """Return parsed JSON or None. Accepts str/bytes/already-parsed object."""
    if isinstance(data, (dict, list)):
        return data
    text = _to_text(data, max_bytes)
    try:
        return json.loads(text)
    except (ValueError, RecursionError, MemoryError):
        return None


def _add(out, seen, ioc):
    if ioc is None:
        return
    k = model.ioc_key(ioc)
    if k in seen:
        model.merge(seen[k], ioc)
        return
    if len(out) >= MAX_IOCS:
        return
    seen[k] = ioc
    out.append(ioc)


def _make(value, source, context="", *, hint_type=None, confidence=50, tags=None, techniques=None,
          first_seen=None, note="", role=None, why=""):
    """classify + infer role + build; returns an IOC or None. Never raises."""
    if not isinstance(value, str):
        return None
    t, canon = classify.classify_value(value)
    if t is None:
        return None
    try:
        ioc = model.new_ioc(t, canon, source=source, confidence=confidence, tags=tags,
                            techniques=techniques, first_seen=first_seen, note=note)
    except ValueError:
        return None
    if role and role in model.ROLES and (role != "unknown"):
        ok = roles._ALLOWED.get(t)
        if ok is None or role in ok:
            ioc["role"], ioc["why"] = role, why or "the source labelled it %s" % role
            return ioc
    r, w = roles.infer_role(ioc, context)
    ioc["role"], ioc["why"] = r, w
    return ioc


def _lst(x):
    """x when it is a list, else [] (untrusted JSON may put any type where a list is expected)."""
    return x if isinstance(x, list) else []


def _str_or(x):
    return x if isinstance(x, str) else ""


def _words(s):
    return re.sub(r"[_]+", " ", str(s or ""))


def _techs_from(*texts):
    out = []
    for t in texts:
        for m in _TECH.findall(str(t or "")):
            if m not in out:
                out.append(m)
    return out


def _walk_strings(obj, limit=20000):
    """Iterative walk collecting (key, str) leaves; bounded, no recursion."""
    stack, n = [("", obj, 0)], 0
    while stack and n < limit:
        k, v, d = stack.pop()
        if d > 60:
            continue
        if isinstance(v, str):
            n += 1
            yield k, v
        elif isinstance(v, dict):
            for kk, vv in v.items():
                stack.append((str(kk), vv, d + 1))
        elif isinstance(v, list):
            for vv in v:
                stack.append((k, vv, d + 1))


# ---------------------------------------------------------------- text
_SPLIT = re.compile(r"[\s,;|]+")
_STRIP = "()<>\"'`[]{}|;,"


def looks_like_report(text):
    """True for prose (an advisory or article) rather than a list: at least 30 non-blank lines and 15% of
    them have six or more words (a list of indicators has almost none). Real indicators in a report are defanged; live links are citations."""
    lines = [l for l in str(text).splitlines()[:50000] if l.strip()]
    return len(lines) >= 30 and sum(1 for l in lines if len(l.split()) >= 6) * 100 >= 15 * len(lines)


def _scan_line(line, source, out, seen, heading="", first_only_files=True, extra_ctx="", report=False):
    if len(line) > 20000:
        line = line[:20000]
    toks = [t for t in _SPLIT.split(line) if t]
    tried = set()
    ctx = (line + " " + extra_ctx)
    line_has_role = roles.infer_role({"type": "ipv4"}, line)[0] != "unknown"
    if not line_has_role and heading:
        ctx = heading + " " + ctx
    for idx, raw in enumerate(toks):
        if raw in tried:                 # the same token twice on a line adds nothing
            continue
        tried.add(raw)
        tok = raw
        for _ in range(4):
            new = tok.strip(_STRIP).rstrip(".:!?")
            if new == tok:
                break
            tok = new
        if not tok or len(tok) > 2100:
            continue
        t, canon = classify.classify_value(tok)
        if t is None:
            continue
        defanged = classify.refang(tok) != tok
        if t == "filename" and not (idx == 0 or "/" in canon or "\\" in canon):
            continue
        if t in ("domain", "url") and report and not defanged:
            continue                     # a live link in a report is a citation, not an indicator
        if t == "domain" and not defanged and classify.tld_of(canon) not in tlds.TLDS | classify.COMMON_TLDS:
            continue                     # ntds.dit, webclient.downloadstring: not a real top-level domain
        if t == "domain" and not (defanged or idx == 0 or classify.is_trusted_tld(canon)):
            continue
        if t == "domain" and not (defanged or classify.is_trusted_tld(canon) or len(toks) <= 3):
            continue
        ioc = _make(tok, source, ctx, note=line if len(toks) > 1 else "")
        _add(out, seen, ioc)


def parse_text(text, source="paste", max_bytes=MAX_BYTES):
    """Plain IOC lists or free text. One indicator per line, or many per line.

    Lines starting with # or ; are comments, but a comment that contains a role word ("# C2 servers")
    acts as the role context for the indicators below it until a blank line. Role words on the same
    line set the role (all indicators on a line share it). Defanged values are refanged.
    Filenames and bare words are only taken when they are the first item on a line (or are paths).
    """
    text = _to_text(text, max_bytes)
    report = looks_like_report(text)
    out, seen, heading, done = [], {}, "", set()
    for line in text.splitlines()[:200000]:
        if len(out) >= MAX_IOCS:
            break
        s = line.strip()
        if not s:
            heading = ""
            continue
        if s[0] in "#;":
            c = s.lstrip("#; ").strip()
            heading = c if roles.infer_role({"type": "ipv4"}, c)[0] != "unknown" else ""
            continue
        if (s, heading) in done:         # an identical line under the same heading changes nothing
            continue
        done.add((s, heading))
        if len(s) > 20000:
            s = s[:20000]
        # inline comment after " #" / " ;" becomes context only
        _scan_line(s, source, out, seen, heading, report=report)
    return out


# ---------------------------------------------------------------- CSV
_VALUE_COLS = {"indicator", "ioc", "value", "ip", "ip_address", "ipaddress", "ip address", "domain",
               "url", "hash", "md5", "sha1", "sha256", "sha-256", "host", "hostname", "observable",
               "address", "ioc_value", "dst_ip", "src_ip", "destination", "uri", "file_hash",
               "sha256_hash", "md5_hash", "indicator_value", "artifact", "dns", "ipv4", "ipv6", "email"}
_TYPE_COLS = {"type", "ioc_type", "indicator_type", "kind"}
_CTX_COLS = {"malware", "malware_printable", "malware_family", "family", "threat", "threat_type",
             "description", "comment", "tags", "role", "category", "name", "title", "label",
             "malware_alias", "signature", "status", "note", "notes", "ioc", "source"}
_TIME_COLS = {"first_seen", "first_seen_utc", "date_added", "dateadded", "created", "timestamp",
              "date", "firstseen", "added"}
_CONF_COLS = {"confidence", "confidence_level", "score", "confidence_score"}
_TECH_COLS = {"technique", "techniques", "attack", "attack_id", "attack_ids", "mitre"}


def _delims(sample):
    best, bc = ",", 0
    for d in (",", "\t", ";", "|"):
        c = sample.count(d)
        if c > bc:
            best, bc = d, c
    return best


def parse_csv(text, source="csv", max_bytes=MAX_BYTES):
    """CSV/TSV with header sniffing; headerless files fall back to per-row text scanning.

    Recognised header names: indicator/ioc/value/ip/domain/url/hash/md5/sha1/sha256/type/malware/
    threat_type/first_seen/confidence/tags/description... ThreatFox's commented header line
    ('# "first_seen_utc","ioc_id","ioc_value",...') is understood.
    """
    text = _to_text(text, max_bytes)
    lines = text.splitlines()[:200000]
    header, rows = None, []
    sample = "\n".join(lines[:50])
    delim = _delims(sample)
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if s[0] == "#":
            body = s.lstrip("# ").strip()
            low = body.lower()
            if header is None and ("ioc_value" in low or "first_seen" in low or low.startswith("indicator")
                                   or low.startswith("ip") or low.startswith("domain")) and delim in body:
                header = _row(body, delim)
            continue
        rows.append(ln)
    out, seen = [], {}
    rr = [_row(r, delim) for r in rows[:200000]]
    if header is None and rr:
        first = [c.strip().lower().strip('"') for c in rr[0]]
        if any(c in _VALUE_COLS or c in _TYPE_COLS or c in _TIME_COLS for c in first) and \
                not any(classify.classify_value(c)[0] for c in rr[0]):
            header = rr.pop(0)
    if header is None:
        for r in rr:
            _scan_line(" ".join(c for c in r), source, out, seen)
        return out
    h = [c.strip().lower().strip('"') for c in header]
    idx = {name: i for i, name in enumerate(h)}
    vcols = [i for i, n in enumerate(h) if n in _VALUE_COLS]
    if not vcols:
        for r in rr:
            _scan_line(" ".join(r), source, out, seen)
        return out
    for r in rr:
        def g(names):
            return [r[idx[n]].strip() for n in names if n in idx and idx[n] < len(r) and r[idx[n]].strip()]
        ctx_bits = [c for n in h if n in _CTX_COLS and n not in {"ioc", "indicator", "value"}
                    for c in g([n])]
        ioc_col_ctx = [r[i].strip() for i in vcols if i < len(r) and r[i].strip()
                       and classify.classify_value(r[i])[0] is None]
        ctx_bits = ctx_bits + ioc_col_ctx
        ctx = _words(" ".join(ctx_bits))
        conf = (g([n for n in h if n in _CONF_COLS]) or [None])[0]
        first = (g([n for n in h if n in _TIME_COLS]) or [None])[0]
        tags = [t for t in re.split(r"[;,|]", " ".join(g(["tags"]))) if t.strip()] if "tags" in idx else []
        mal = (g(["malware_printable", "malware", "malware_family", "family"]) or [""])[0]
        if mal and mal.lower() not in ("n/a", "none", "unknown", ""):
            tags.append(mal)
        techs = _techs_from(" ".join(g([n for n in h if n in _TECH_COLS])))
        note = " ".join(ctx_bits)[:200]
        for i in vcols:
            if i >= len(r):
                continue
            v = r[i].strip()
            if not v:
                continue
            _, port = classify.split_port(v)
            ioc = _make(v, source, ctx, confidence=_conf(conf), tags=tags, techniques=techs,
                        first_seen=first, note=note)
            if ioc is not None and port:
                ioc["tags"] = model.norm_tags(ioc["tags"] + ["port:%d" % port])
            _add(out, seen, ioc)
    return out


def _conf(c):
    if c is None:
        return 50
    return model._confidence(c, 50)


def _row(line, delim):
    if '"' not in line and "\r" not in line and "\x00" not in line:      # no quoting: a plain split is what csv would do
        return [c.lstrip(" ") for c in line.split(delim)]
    try:
        return next(csv.reader([line], delimiter=delim, skipinitialspace=True))
    except (csv.Error, StopIteration):
        return [line]


# ---------------------------------------------------------------- STIX
_STIX_CMP = re.compile(
    r"(?P<type>[a-z][a-z0-9-]*):(?P<path>[^\s=!<>]+?)\s*(?P<op>!=|=|ISSUBSET|ISSUPERSET|LIKE|MATCHES|IN)\s*"
    r"(?:'(?P<val>(?:[^'\\]|\\.)*)'|\((?P<lst>[^)]*)\))", re.I)
_STIX_STR = re.compile(r"'((?:[^'\\]|\\.)*)'")
_HASHNAMES = {"MD5": "md5", "SHA-1": "sha1", "SHA1": "sha1", "SHA-256": "sha256", "SHA256": "sha256"}


def _stix_atoms(pattern):
    """Yield (stix_type, path, value) from a STIX pattern string (strict regex, no evaluation)."""
    for m in _STIX_CMP.finditer(pattern[:20000]):
        if m.group("op").upper() == "!=":
            continue
        typ, path = m.group("type").lower(), m.group("path")
        vals = [m.group("val")] if m.group("val") is not None else _STIX_STR.findall(m.group("lst") or "")
        for v in vals:
            yield typ, path, v.replace("\\'", "'").replace("\\\\", "\\")


def _stix_value(typ, path, v):
    p = path.replace("'", "").replace('"', "")
    if typ in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr") and p.startswith("value"):
        return v
    if typ == "email-message" and "from_ref" in p:
        return v
    if typ == "file":
        if p.startswith("hashes."):
            return v if _HASHNAMES.get(p.split(".", 1)[1].upper()) else None
        if p == "name":
            return v
    return None


def _ext_refs(o):
    ids = []
    for r in _lst(o.get("external_references")):
        if isinstance(r, dict) and str(r.get("source_name", "")).lower().startswith("mitre"):
            e = str(r.get("external_id", ""))
            if re.match(r"^T\d{4}(\.\d{3})?$", e):
                ids.append(e)
    return ids


def parse_stix(obj_or_text, source="stix", max_bytes=MAX_BYTES):
    """STIX 2.0/2.1 bundle (or a list/single object). Reads:
      * indicator.pattern comparisons: ipv4-addr/ipv6-addr/domain-name/url/email-addr :value,
        file:hashes.'SHA-256'|MD5|SHA-1, file:name; ISSUBSET and IN (...) too.
      * observed-data (2.0 `objects`, 2.1 `object_refs`) and bare SCOs.
      * Role words from labels, indicator_types, name, description, kill_chain_phases (so
        'command-and-control' => c2); techniques from MITRE external_references and from
        indicator --indicates--> attack-pattern relationships; malware names from indicates --> malware.
    """
    data = _json_load(obj_or_text, max_bytes)
    if data is None:
        return []
    if isinstance(data, dict) and isinstance(data.get("objects"), list):
        objs = data["objects"]
    elif isinstance(data, list):
        objs = data
    elif isinstance(data, dict):
        objs = [data]
    else:
        return []
    objs = [o for o in objs[:200000] if isinstance(o, dict)]
    byid = {o.get("id"): o for o in objs if isinstance(o.get("id"), str)}
    rel_tech, rel_mal = {}, {}
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") in ("indicates", "uses"):
            s, t = o.get("source_ref"), o.get("target_ref")
            if not (isinstance(s, str) and isinstance(t, str)):
                continue
            tgt = byid.get(t) or {}
            if tgt.get("type") == "attack-pattern":
                rel_tech.setdefault(s, []).extend(_ext_refs(tgt))
            elif tgt.get("type") in ("malware", "tool", "intrusion-set", "campaign"):
                if tgt.get("name"):
                    rel_mal.setdefault(s, []).append(tgt["name"])
    out, seen = [], {}

    def ctx_of(o):
        bits = [o.get("name"), o.get("description")]
        bits += [_words(x) for x in _lst(o.get("labels")) if isinstance(x, str)]
        bits += [_words(x) for x in _lst(o.get("indicator_types")) if isinstance(x, str)]
        for ph in _lst(o.get("kill_chain_phases")):
            if isinstance(ph, dict) and ph.get("phase_name"):
                bits.append(_words(ph["phase_name"]).replace("-", " "))
        return " ".join(str(b) for b in bits if b)

    def tags_of(o):
        tg = [x for x in _lst(o.get("labels")) if isinstance(x, str)
              and x.lower() not in ("malicious-activity", "anomalous-activity", "benign", "attribution")]
        return tg

    for o in objs:
        typ = o.get("type")
        if typ == "indicator":
            pat = o.get("pattern")
            if not isinstance(pat, str):
                continue
            oid = o.get("id") if isinstance(o.get("id"), str) else ""
            techs = _ext_refs(o) + rel_tech.get(oid, [])
            tags = tags_of(o) + rel_mal.get(oid, [])
            ctx = ctx_of(o)
            conf = o.get("confidence", 50)
            for st, path, v in _stix_atoms(pat):
                val = _stix_value(st, path, v)
                if val is None:
                    continue
                ioc = _make(val, source, ctx, confidence=_conf(conf), tags=tags, techniques=techs,
                            first_seen=o.get("valid_from") or o.get("created"),
                            note=o.get("name") or o.get("description") or "")
                _add(out, seen, ioc)
        elif typ == "observed-data":
            scos = []
            if isinstance(o.get("objects"), dict):
                scos += [x for x in o["objects"].values() if isinstance(x, dict)]
            for ref in _lst(o.get("object_refs")):
                if isinstance(ref, str) and ref in byid:
                    scos.append(byid[ref])
            for sco in scos:
                for v in _sco_values(sco):
                    ioc = _make(v, source, ctx_of(o), tags=tags_of(o), techniques=_ext_refs(o),
                                first_seen=o.get("first_observed") or o.get("created"),
                                note=o.get("name") or "")
                    _add(out, seen, ioc)
        elif typ in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "email-addr"):
            for v in _sco_values(o):
                _add(out, seen, _make(v, source, ""))
    return out


def _sco_values(sco):
    t = sco.get("type")
    if t in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr") and isinstance(sco.get("value"), str):
        return [sco["value"]]
    if t == "file":
        vals = []
        h = sco.get("hashes")
        if isinstance(h, dict):
            for k, v in h.items():
                if _HASHNAMES.get(str(k).upper()) and isinstance(v, str):
                    vals.append(v)
        if isinstance(sco.get("name"), str):
            vals.append(sco["name"])
        return vals
    return []


# ---------------------------------------------------------------- MISP
_MISP_TYPES = {
    "ip-dst": "ip", "ip-src": "ip", "domain": "dom", "hostname": "dom", "url": "url", "uri": "url",
    "link": "url", "md5": "h", "sha1": "h", "sha256": "h", "filename": "f", "email-src": "mail",
    "email-dst": "mail", "email": "mail", "vulnerability": "cve", "ip-dst|port": "ipport",
    "ip-src|port": "ipport", "domain|ip": "domip", "hostname|port": "hostport",
    "filename|md5": "fh", "filename|sha1": "fh", "filename|sha256": "fh", "cidr": "ip",
    "x509-fingerprint-sha1": None,
}
_MISP_ROLE_CAT = {"Payload delivery": "payload", "Payload installation": "payload",
                  "Artifacts dropped": "payload"}
_GAL = re.compile(r'^misp-galaxy:([\w-]+)="(.+)"$')


def _tag_info(names):
    tags, techs = [], []
    for n in names:
        if not isinstance(n, str):
            continue
        m = _GAL.match(n)
        if m:
            kind, val = m.group(1), m.group(2)
            techs += _techs_from(val) if "mitre" in kind else []
            if "attack-pattern" not in kind:
                tags.append(re.sub(r"\s*-\s*T\d{4}(?:\.\d{3})?$", "", val))
        elif n.lower().startswith(("tlp:", "type:osint", "osint:", "workflow:", "misp:")) or \
                re.match(r"^[\w.-]+:[\w.-]+=", n):
            continue  # TLP/workflow and other machine tags (namespace:predicate="value") are noise
        else:
            tags.append(n)
    return tags, techs


def _misp_events(data):
    """Event dicts found in a MISP export. Iterative with a depth limit (hostile nesting cannot recurse)."""
    ev, stack = [], [(data, 0)]
    while stack:
        d, depth = stack.pop()
        if depth > 8:
            continue
        if isinstance(d, dict):
            if isinstance(d.get("Event"), dict):
                ev.append(d["Event"])
            elif isinstance(d.get("response"), (list, dict)):
                r = d["response"]
                for x in reversed(r if isinstance(r, list) else [r]):
                    if isinstance(x, dict):
                        if "Event" in x:
                            stack.append((x, depth + 1))
                        elif "Attribute" in x or "Object" in x:
                            ev.append(x)
            elif "Attribute" in d or "Object" in d:
                ev.append(d)
        elif isinstance(d, list):
            for x in reversed(d[:5000]):
                stack.append((x, depth + 1))
        if len(ev) >= 5000:
            break
    return ev


def parse_misp(obj_or_text, source="misp", max_bytes=MAX_BYTES):
    """MISP event JSON, {"Event":..}, {"response":[{"Event":..}]} or a list of events.

    Reads Event.Attribute and Event.Object[].Attribute (deleted ones skipped). Supports types
    ip-dst/ip-src (+|port), domain, hostname, domain|ip, url, md5, sha1, sha256, filename(|hash),
    email-*, vulnerability. Category 'Payload delivery'/'Payload installation'/'Artifacts dropped'
    => payload; 'Network activity' destinations (ip-dst/domain/hostname/url) => c2 unless a role
    word in comment/event info/tags says otherwise. to_ids true => confidence 80, else 50.
    ATT&CK techniques come from `misp-galaxy:mitre-attack-pattern="Name - T1059"` tags and Galaxy
    clusters; malware/actor galaxy values become tags.
    """
    data = _json_load(obj_or_text, max_bytes)
    if data is None:
        return []
    out, seen = [], {}
    for ev in _misp_events(data)[:5000]:
        names = [t.get("name") for t in _lst(ev.get("Tag")) if isinstance(t, dict)]
        for g in _lst(ev.get("Galaxy")):
            if isinstance(g, dict):
                for c in _lst(g.get("GalaxyCluster")):
                    if isinstance(c, dict) and c.get("value"):
                        names.append('misp-galaxy:%s="%s"' % (g.get("type", "galaxy"), c["value"]))
        ev_tags, ev_techs = _tag_info(names)
        info = str(ev.get("info") or "")
        attrs = list(_lst(ev.get("Attribute")))
        for ob in _lst(ev.get("Object")):
            if isinstance(ob, dict):
                attrs += [dict(a, _obj=ob.get("name", "")) for a in _lst(ob.get("Attribute"))
                          if isinstance(a, dict)]
        for a in attrs[:MAX_IOCS]:
            if not isinstance(a, dict) or a.get("deleted"):
                continue
            kind = _MISP_TYPES.get(str(a.get("type")))
            val = a.get("value")
            if not kind or not isinstance(val, str):
                continue
            a_tags, a_techs = _tag_info([t.get("name") for t in _lst(a.get("Tag")) if isinstance(t, dict)])
            cat = _str_or(a.get("category"))
            comment = str(a.get("comment") or "")
            ctx = " ".join([comment, info, " ".join(ev_tags + a_tags)])
            base = dict(confidence=80 if a.get("to_ids") else 50, tags=ev_tags + a_tags,
                        techniques=ev_techs + a_techs,
                        first_seen=a.get("first_seen") or a.get("timestamp") or ev.get("date"),
                        note=comment or info)
            vals = []
            if kind in ("ip", "dom", "url", "h", "f", "mail", "cve"):
                vals = [val]
            elif kind in ("ipport", "hostport"):
                vals = [val.split("|")[0]]
            elif kind == "domip":
                vals = val.split("|")[:2]
            elif kind == "fh":
                vals = val.split("|")[-1:]
            for v in vals:
                ioc = _make(v, source, ctx, **base)
                if ioc is None:
                    continue
                if ioc["role"] == "unknown":
                    if cat in _MISP_ROLE_CAT and ioc["type"] in ("md5", "sha1", "sha256", "url", "domain",
                                                                  "ipv4", "ipv6", "filename"):
                        ioc["role"], ioc["why"] = "payload", "MISP category '%s'" % cat
                    elif cat == "Network activity" and ioc["type"] in ("ipv4", "ipv6", "domain", "url") \
                            and str(a.get("type")) not in ("ip-src",):
                        ioc["role"], ioc["why"] = "c2", "MISP 'Network activity' destination"
                _add(out, seen, ioc)
    return out


# ---------------------------------------------------------------- OTX
_OTX_TYPES = {"ipv4", "ipv6", "domain", "hostname", "url", "uri", "email", "cve", "cidr", "filepath",
              "filehash-md5", "filehash-sha1", "filehash-sha256"}


def _otx_pulses(data):
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            return [p for p in data["results"] if isinstance(p, dict)]
        if isinstance(data.get("indicators"), list):
            return [data]
    if isinstance(data, list):
        return [p for p in data if isinstance(p, dict) and isinstance(p.get("indicators"), list)]
    return []


def parse_otx(obj_or_text, source="otx", max_bytes=MAX_BYTES):
    """AlienVault OTX pulse JSON: a pulse, {"results":[pulses]} (search/subscribed) or a list.

    indicators[].type IPv4/IPv6/domain/hostname/URL/FileHash-MD5|SHA1|SHA256/email/CVE; role words
    come from the indicator's role/title/description, the pulse name and tags;
    attack_ids[].id => techniques; malware_families and tags => tags.
    """
    data = _json_load(obj_or_text, max_bytes)
    if data is None:
        return []
    out, seen = [], {}
    for p in _otx_pulses(data)[:5000]:
        tags = [t for t in _lst(p.get("tags")) if isinstance(t, str)]
        for m in _lst(p.get("malware_families")):
            tags.append(m.get("display_name") or m.get("id") if isinstance(m, dict) else m)
        tags = [t for t in tags if isinstance(t, str)]
        techs = []
        for a in _lst(p.get("attack_ids")):
            techs.append(a.get("id") if isinstance(a, dict) else a)
        techs = [t for t in techs if isinstance(t, str)]
        pctx = " ".join([str(p.get("name") or ""), " ".join(tags)])
        for ind in _lst(p.get("indicators"))[:MAX_IOCS]:
            if not isinstance(ind, dict):
                continue
            ty = str(ind.get("type", "")).lower()
            val = ind.get("indicator")
            if ty not in _OTX_TYPES or not isinstance(val, str):
                continue
            if ty == "filepath":
                continue
            ctx = " ".join([_words(ind.get("role")), str(ind.get("title") or ""),
                            str(ind.get("description") or "")])
            ioc = _make(val, source, ctx, confidence=70, tags=tags, techniques=techs,
                        first_seen=ind.get("created") or p.get("created"),
                        note=ind.get("title") or ind.get("description") or p.get("name") or "")
            if ioc is not None and ioc["role"] == "unknown" and ioc["type"] in ("ipv4", "ipv6", "domain", "url"):
                r, w = roles.infer_role(ioc, pctx)
                if r != "unknown":
                    ioc["role"], ioc["why"] = r, "pulse name/tags: " + w
            _add(out, seen, ioc)
    return out


# ---------------------------------------------------------------- ThreatFox
_TF_ROLE = {"botnet_cc": "c2", "payload_delivery": "payload", "payload": "payload",
            "cc_skimming": "exfil"}
_TF_TYPES = {"ip:port", "domain", "url", "sha256_hash", "md5_hash", "sha1_hash"}


def _tf_item(it, source, out, seen):
    if not isinstance(it, dict):
        return
    val = it.get("ioc") or it.get("ioc_value")
    ty = str(it.get("ioc_type", "")).lower()
    if not isinstance(val, str) or (ty and ty not in _TF_TYPES):
        return
    tt = str(it.get("threat_type", "")).lower()
    mal = it.get("malware_printable") or it.get("malware") or ""
    tags = [mal] if mal and str(mal).lower() not in ("unknown malware", "n/a") else []
    raw_tags = it.get("tags")
    if isinstance(raw_tags, list):
        tags += [t for t in raw_tags if isinstance(t, str)]
    elif isinstance(raw_tags, str):
        tags += [t for t in re.split(r"[,;]", raw_tags) if t.strip() and t.strip().lower() != "none"]
    host, port = classify.split_port(val) if ty == "ip:port" else (val, None)
    ioc = _make(host, source, _words(tt) + " " + str(mal), role=_TF_ROLE.get(tt),
                why="ThreatFox threat_type %s" % tt,
                confidence=it.get("confidence_level", 50), tags=tags,
                first_seen=it.get("first_seen_utc") or it.get("first_seen"),
                note=("%s %s" % (mal, tt.replace("_", " "))).strip())
    if ioc is not None and port:
        ioc["tags"] = model.norm_tags(ioc["tags"] + ["port:%d" % port])
        ioc["note"] = model.clean_text(ioc["note"] + " port %d" % port)
    _add(out, seen, ioc)


def parse_threatfox(obj_or_text, source="threatfox", max_bytes=MAX_BYTES):
    """ThreatFox JSON ({"query_status","data":[..]}, {"id":[{..}]} export, or list) or its CSV export.

    ioc_type ip:port/domain/url/sha256_hash/md5_hash; threat_type botnet_cc => c2,
    payload_delivery => payload; malware_printable => tag; confidence_level => confidence; the
    port is kept as tag 'port:N' and in the note.
    """
    if not isinstance(obj_or_text, (dict, list)):
        text = _to_text(obj_or_text, max_bytes)
        data = None
        if text.lstrip()[:1] in "{[":
            data = _json_load(text, max_bytes)
        if data is None:
            return _tf_csv(text, source)
    else:
        data = obj_or_text
    items = []
    if isinstance(data, dict):
        if isinstance(data.get("data"), list):
            items = data["data"]
        else:
            for v in data.values():
                if isinstance(v, list):
                    items += v
                elif isinstance(v, dict):
                    items.append(v)
    elif isinstance(data, list):
        items = data
    out, seen = [], {}
    for it in items[:MAX_IOCS]:
        _tf_item(it, source, out, seen)
    return out


def _tf_csv(text, source):
    header, out, seen = None, [], {}
    for ln in text.splitlines()[:200000]:
        s = ln.strip()
        if not s:
            continue
        if s.startswith("#"):
            if "ioc_value" in s:
                header = [c.strip().strip('"').lower() for c in _row(s.lstrip("# "), ",")]
            continue
        r = _row(s, ",")
        if header is None:
            header = [c.strip().lower() for c in r]
            continue
        _tf_item(dict(zip(header, [c.strip() for c in r])), source, out, seen)
    return out


# ---------------------------------------------------------------- sniffing
def _sniff_json(d):
    """Return a parser name for a parsed JSON value."""
    if isinstance(d, dict):
        if d.get("type") == "bundle" or (isinstance(d.get("objects"), list) and "spec_version" in str(d)[:400]):
            return "stix"
        if "Event" in d or (isinstance(d.get("response"), (list, dict)) and "Event" in json.dumps(d.get("response"))[:2000]):
            return "misp"
        if "Attribute" in d or "Object" in d:
            return "misp"
        if isinstance(d.get("results"), list) and d["results"] and isinstance(d["results"][0], dict) \
                and "indicators" in d["results"][0]:
            return "otx"
        if isinstance(d.get("indicators"), list):
            return "otx"
        if "query_status" in d or (isinstance(d.get("data"), list) and d["data"]
                                   and isinstance(d["data"][0], dict) and "ioc_type" in d["data"][0]):
            return "threatfox"
        if isinstance(d.get("objects"), list):
            return "stix"
        for v in list(d.values())[:3]:
            if isinstance(v, list) and v and isinstance(v[0], dict) and "ioc_type" in v[0]:
                return "threatfox"
        if d.get("type") in ("indicator", "observed-data", "ipv4-addr", "domain-name", "url", "file"):
            return "stix"
    if isinstance(d, list) and d and isinstance(d[0], dict):
        if "ioc_type" in d[0]:
            return "threatfox"
        if "pattern" in d[0] and "type" in d[0]:
            return "stix"
        if "Event" in d[0]:
            return "misp"
    return "generic"


def _generic_json(d, source):
    lines = []
    for k, v in _walk_strings(d):
        lines.append(("%s %s" % (_words(k), v))[:400] if k else v[:400])
    return parse_text("\n".join(lines), source)


def parse_any(text_or_bytes, source="paste", max_bytes=MAX_BYTES):
    """Sniff and parse: STIX/MISP/OTX/ThreatFox JSON, generic JSON, JSON lines, CSV/TSV, plain text.

    Raises ValueError only when over the size cap; hostile or malformed input yields [] / best effort.
    """
    if isinstance(text_or_bytes, (dict, list)):
        d = text_or_bytes
        return _dispatch(_sniff_json(d), d, source, max_bytes)
    text = _to_text(text_or_bytes, max_bytes)
    s = text.lstrip()
    if s[:1] in "{[":
        d = _json_load(text, max_bytes)
        if d is not None:
            return _dispatch(_sniff_json(d), d, source, max_bytes)
        # JSON lines
        recs = []
        for ln in text.splitlines()[:100000]:
            ln = ln.strip()
            if ln[:1] == "{":
                try:
                    recs.append(json.loads(ln))
                except (ValueError, RecursionError):
                    pass
        if recs:
            return _dispatch(_sniff_json(recs), recs, source, max_bytes)
    first = ""
    for ln in text.splitlines()[:30]:
        if ln.strip() and not ln.strip().startswith(";"):
            first = ln.strip()
            if not first.startswith("#") or "ioc_value" in first:
                break
    low = first.lower()
    if "ioc_value" in low and "threat_type" in low:
        return _tf_csv(text, source)
    if any(d in first for d in (",", "\t", "|")) and (
            low.lstrip("# ").split(",")[0].strip('" ') in _VALUE_COLS | _TYPE_COLS | _TIME_COLS
            or any(c.strip('" ') in _VALUE_COLS for c in re.split(r"[,\t|;]", low.lstrip("# ")))
            and not classify.classify_value(first.split(",")[0].strip('" '))[0]):
        return parse_csv(text, source, max_bytes)
    return parse_text(text, source, max_bytes)


def _dispatch(kind, d, source, max_bytes):
    if kind == "stix":
        return parse_stix(d, source, max_bytes)
    if kind == "misp":
        return parse_misp(d, source, max_bytes)
    if kind == "otx":
        return parse_otx(d, source, max_bytes)
    if kind == "threatfox":
        return parse_threatfox(d, source, max_bytes)
    return _generic_json(d, source)
