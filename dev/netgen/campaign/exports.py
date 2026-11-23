"""Campaign outputs written beside the pcap.

* ``<prefix>.campaign.json``            the campaign, canonical dump (sorted keys), replayable
* ``<prefix>.campaign-iocs.stix.json``  STIX 2.1 bundle of the indicators AS THEY APPEAR IN THE PACKETS
                                        (mapped IPv4 in mapped mode, so a sensor threat collection
                                        matches the capture; domains, URLs, hashes unchanged). Only
                                        indicators an action actually emitted are included, the same
                                        rule as netgen.incidents.threat_collection(only_ips=...).
* ``<prefix>.attack-navigator.json``    ATT&CK Navigator layer of the techniques that ran
* ``<prefix>.campaign-report.md``       indicator -> stage -> action -> packets, technique coverage,
                                        and anything skipped or failed
* ``<prefix>.report.html``              the same as one self-contained HTML page (tables only, no
                                        scripts, no external resources, everything escaped)
* ``<prefix>.indicators.csv``           every indicator with the address it has in the capture and whether
                                        an action put it on the wire (spreadsheet-safe cells)
* ``<prefix>.misp-event.json``          MISP event of the indicators that were on the wire, importable into
                                        a MISP instance or back into this builder

When a malware-family beacon profile was used (see ``families``), the STIX bundle also carries a ``malware``
object for the family and ``indicates`` relationships from the indicators its beacons went to.

Everything is derived from the runner's record of what was emitted. Deterministic: ids are uuid5.
"""
import csv
import html
import io
import json
import os
import uuid
from datetime import datetime, timezone

from .. import model
from . import families

_NS = uuid.UUID("6f0e2c1e-8d0b-5d3a-9f0e-0a1c7e5b2d11")
_PATTERNS = {
    "ipv4": lambda v, a: ("ipv4-addr", "[ipv4-addr:value = '%s']" % a),
    "ipv6": lambda v, a: ("ipv6-addr", "[ipv6-addr:value = '%s']" % v),
    "cidr": lambda v, a: ("ipv4-addr", "[ipv4-addr:value = '%s']" % v),
    "domain": lambda v, a: ("domain-name", "[domain-name:value = '%s']" % v),
    "url": lambda v, a: ("url", "[url:value = '%s']" % v.replace("'", "\\'")),
    "md5": lambda v, a: ("file", "[file:hashes.MD5 = '%s']" % v),
    "sha1": lambda v, a: ("file", "[file:hashes.'SHA-1' = '%s']" % v),
    "sha256": lambda v, a: ("file", "[file:hashes.'SHA-256' = '%s']" % v),
    "email": lambda v, a: ("email-addr", "[email-addr:value = '%s']" % v),
    "filename": lambda v, a: ("file", "[file:name = '%s']" % v.replace("'", "\\'")),
}


def _camp_report(report, camp_id):
    if report is None:
        return {"id": camp_id, "entries": [], "stages": [], "iocs": [], "errors": []}
    if "campaigns" in report:
        for c in report["campaigns"]:
            if c.get("id") == camp_id:
                return c
        return report["campaigns"][0] if report["campaigns"] else {"id": camp_id, "entries": [], "stages": [], "iocs": [], "errors": []}
    return report


def _day_iso():
    y, m, d = model.capture_day()
    return datetime(y, m, d, tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# Indicator types that can be seen in the packets: an address, a name (DNS query, TLS SNI, Host
# header) or a URL. Hashes, e-mail addresses, CVE ids and file names are carried for traceability
# only: the payloads are inert filler, so nothing on the wire carries them and exporting them would
# add indicators that match nothing.
OBSERVABLE = ("ipv4", "ipv6", "domain", "url")


def used_indexes(crep, campaign=None):
    """Indexes of observable indicators that at least one action emitted successfully."""
    iocs = (campaign or {}).get("iocs")
    table = {r["index"]: r for r in crep.get("iocs") or []}
    out = set()
    for e in crep.get("entries") or []:
        if e.get("status") == "ok":
            for i in e.get("ioc") or []:
                t = (iocs[i].get("type") if iocs and i < len(iocs) else (table.get(i) or {}).get("type"))
                if t in OBSERVABLE:
                    out.add(i)
    return out


def families_used(campaign, crep):
    """Family ids (definition order of first use) whose beacon profile an action emitted successfully."""
    seen = []
    for e in crep.get("entries") or []:
        if e.get("status") != "ok":
            continue
        f = families.lookup((e.get("params") or {}).get("profile")) if (e.get("params") or {}).get("profile") else None
        if f and f["id"] not in seen:
            seen.append(f["id"])
    return seen


def _family_iocs(crep, fid):
    out = set()
    for e in crep.get("entries") or []:
        if e.get("status") == "ok":
            f = families.lookup((e.get("params") or {}).get("profile")) if (e.get("params") or {}).get("profile") else None
            if f and f["id"] == fid:
                out.update(e.get("ioc") or [])
    return out


def stix_bundle(campaign, crep):
    now = _day_iso()
    table = {r["index"]: r for r in crep.get("iocs") or []}
    used = used_indexes(crep, campaign)
    objs = []
    ind_ids = {}
    for i, ioc in enumerate(campaign.get("iocs") or []):
        if i not in used or ioc.get("type") not in _PATTERNS:
            continue
        row = table.get(i, {})
        addr = row.get("address") or ioc.get("value")
        kind, patt = _PATTERNS[ioc["type"]](str(ioc["value"]), addr)
        name = "%s %s %s" % ((campaign.get("meta") or {}).get("name", "campaign"), kind, ioc["value"])
        o = {"type": "indicator", "spec_version": "2.1",
             "id": "indicator--" + str(uuid.uuid5(_NS, "%s|%s|%s" % (crep.get("id"), ioc["type"], patt))),
             "created": now, "modified": now, "name": name,
             "description": "Campaign indicator (%s, role %s). In the capture as %s." % (
                 ioc.get("source", "campaign"), ioc.get("role", "unknown"), addr),
             "indicator_types": ["malicious-activity"],
             "pattern": patt, "pattern_type": "stix", "valid_from": now,
             "labels": [str(t) for t in (ioc.get("tags") or [])][:6] + [str(ioc.get("role", "unknown"))]}
        objs.append(o)
        ind_ids[i] = o["id"]
    for fid in families_used(campaign, crep):
        fam = families.FAMILIES[fid]
        mid = "malware--" + str(uuid.uuid5(_NS, "malware|%s|%s" % (crep.get("id"), fid)))
        objs.append({"type": "malware", "spec_version": "2.1", "id": mid, "created": now, "modified": now,
                     "name": fam["name"], "is_family": True, "aliases": [fam["name"]] + list(fam["aliases"]),
                     "description": "Beacon traffic in this capture is a benign look-alike of this family's "
                                    "documented network behaviour. No malware is present."})
        for i in sorted(_family_iocs(crep, fid)):
            if i in ind_ids:
                objs.append({"type": "relationship", "spec_version": "2.1",
                             "id": "relationship--" + str(uuid.uuid5(_NS, "rel|%s|%s|%s" % (crep.get("id"), ind_ids[i], mid))),
                             "created": now, "modified": now, "relationship_type": "indicates",
                             "source_ref": ind_ids[i], "target_ref": mid})
    return {"type": "bundle", "id": "bundle--" + str(uuid.uuid5(_NS, "bundle|%s" % crep.get("id"))),
            "objects": objs}


def navigator_layer(campaign, crep):
    """Navigator layer of the techniques that actually ran (actions that emitted traffic) plus the
    stages' declared techniques; the comment says which action and stage."""
    from . import attack
    tech = {}
    for e in crep.get("entries") or []:
        if e.get("status") == "ok":
            for t in e.get("techniques") or []:
                d = tech.setdefault(t, {"id": t, "score": 0, "comment": []})
                d["score"] += 1
                d["comment"].append("%s in %s" % (e.get("action"), e.get("stage")))
    for st in crep.get("stages") or []:
        for t in st.get("techniques") or []:
            tech.setdefault(t, {"id": t, "score": 1, "comment": ["declared by stage %s" % st.get("id")]})
    for x in campaign.get("expect") or []:
        if x.get("cve"):
            d = tech.setdefault(x["technique"], {"id": x["technique"], "score": 1, "comment": []})
            d["comment"].append("expected for %s" % x["cve"])
    items = [dict(v, comment="; ".join(v["comment"][:6])) for _, v in sorted(tech.items())]
    meta = campaign.get("meta") or {}
    return attack.navigator_layer(items, name=meta.get("name") or "OpenGenerator campaign",
                                  comment=meta.get("description") or "")


def report_md(campaign, crep):
    meta = campaign.get("meta") or {}
    L = ["# Campaign report: %s" % (meta.get("name") or crep.get("id")), ""]
    opt = campaign.get("options") or {}
    L += ["Address mode: **%s**. Speed: %s. Seed: %s." % (opt.get("address_mode", "mapped"),
                                                          opt.get("speed", "realistic"), meta.get("seed", "-")), ""]
    entries = crep.get("entries") or []
    ok = [e for e in entries if e.get("status") == "ok"]
    L += ["%d of %d actions emitted traffic: %d packets, %d bytes." % (
        len(ok), len(entries), sum(e["packets"] for e in ok), sum(e["bytes"] for e in ok)), ""]
    L += ["## Indicators to stage to action to packets", "",
          "| Indicator | In the capture as | Stage | Action | Packets |", "|---|---|---|---|---|"]
    table = {r["index"]: r for r in crep.get("iocs") or []}
    rows = 0
    traced = set()
    for e in ok:
        for i in e.get("ioc") or []:
            r = table.get(i, {})
            if r.get("type") not in OBSERVABLE:
                traced.add(i)
                continue
            L.append("| %s (%s) | %s | %s | %s | %d |" % (r.get("value", "?"), r.get("role", "?"),
                                                          r.get("address") or r.get("value", "?"),
                                                          e.get("stage"), e.get("action"), e["packets"]))
            rows += 1
    if not rows:
        L.append("| (none) | | | | |")
    if traced:
        L.append("| %d other indicator(s) (hashes, files, ...) | carried for traceability, not on the wire | | | |" % len(traced))
    used = used_indexes(crep, campaign)
    unused = [r for r in table.values() if r["index"] not in used and r.get("type") in OBSERVABLE]
    L += ["", "## Technique coverage", "", "| Technique | Actions that ran | Stages |", "|---|---|---|"]
    cov = {}
    for e in ok:
        for t in e.get("techniques") or []:
            c = cov.setdefault(t, [0, set()])
            c[0] += 1
            c[1].add(str(e.get("stage")))
    for t, (n, st) in sorted(cov.items()):
        L.append("| %s | %d | %s |" % (t, n, ", ".join(sorted(st))))
    if not cov:
        L.append("| (none) | | |")
    L += ["", "## Not in the capture", ""]
    bad = [e for e in entries if e.get("status") != "ok"]
    for e in bad:
        L.append("- stage %s, action %s: %s (%s)" % (e.get("stage"), e.get("action"), e.get("status"), e.get("error")))
    for err in crep.get("errors") or []:
        if "stage" not in err:
            L.append("- %s" % err.get("error", err))
    if unused:
        L.append("- %d indicator(s) were not emitted by any action (not in the packets, not exported): %s" % (
            len(unused), ", ".join(str(r["value"]) for r in unused[:12]) + (" ..." if len(unused) > 12 else "")))
    if not bad and not unused:
        L.append("- nothing")
    return "\n".join(L) + "\n"


_MISP_TYPES = {"ipv4": ("ip-dst", "Network activity"), "ipv6": ("ip-dst", "Network activity"),
               "domain": ("domain", "Network activity"), "url": ("url", "Network activity")}


def _cell(v):
    """A CSV cell that a spreadsheet will not run as a formula."""
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


def indicators_csv(campaign, crep):
    table = {r["index"]: r for r in crep.get("iocs") or []}
    used = used_indexes(crep, campaign)
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(["type", "value", "role", "confidence", "source", "in_capture_as", "on_the_wire"])
    for i, ioc in enumerate(campaign.get("iocs") or []):
        w.writerow([_cell(x) for x in (ioc.get("type"), ioc.get("value"), ioc.get("role"), ioc.get("confidence"),
                                       ioc.get("source"), (table.get(i) or {}).get("address") or ioc.get("value"),
                                       "yes" if i in used else "no")])
    return out.getvalue()


def misp_event(campaign, crep):
    meta = campaign.get("meta") or {}
    table = {r["index"]: r for r in crep.get("iocs") or []}
    used = used_indexes(crep, campaign)
    attrs = []
    for i, ioc in enumerate(campaign.get("iocs") or []):
        if i not in used or ioc.get("type") not in _MISP_TYPES:
            continue
        typ, cat = _MISP_TYPES[ioc["type"]]
        value = (table.get(i) or {}).get("address") or ioc["value"]
        attrs.append({"uuid": str(uuid.uuid5(_NS, "misp|%s|%s|%s" % (crep.get("id"), typ, value))), "type": typ,
                      "category": cat, "value": str(value), "to_ids": True,
                      "comment": "campaign indicator, role %s" % ioc.get("role", "unknown")})
    return {"Event": {"uuid": str(uuid.uuid5(_NS, "misp-event|%s" % crep.get("id"))),
                      "info": "%s (benign lab simulation, no malware present)" % (meta.get("name") or "OpenGenerator campaign"),
                      "date": _day_iso()[:10], "threat_level_id": "4", "analysis": "2", "distribution": "0",
                      "Tag": [{"name": "tlp:clear"}, {"name": "opengenerator:simulation"}], "Attribute": attrs}}


_CSS = ("body{font:14px/1.45 sans-serif;margin:24px;color:#1b1f24;background:#fff}"
        "h1{font-size:22px}h2{font-size:16px;margin-top:28px;border-bottom:1px solid #ccd}"
        "table{border-collapse:collapse;margin:8px 0;width:100%}th,td{border:1px solid #c9ced6;padding:4px 8px;"
        "text-align:left;vertical-align:top;font-size:13px}th{background:#eef1f5}"
        "td.n{text-align:right}.note{background:#fff7e0;border:1px solid #e6c85a;padding:8px 12px}")


def _e(v):
    return html.escape("" if v is None else str(v), quote=True)


def _table(head, rows, empty=None):
    out = ["<table>", "<thead><tr>" + "".join("<th>%s</th>" % _e(h) for h in head) + "</tr></thead>", "<tbody>"]
    for r in rows:
        out.append("<tr>" + "".join('<td%s>%s</td>' % (' class="n"' if isinstance(c, int) else "", _e(c)) for c in r) + "</tr>")
    if not rows:
        out.append('<tr><td colspan="%d">%s</td></tr>' % (len(head), _e(empty or "none")))
    out += ["</tbody>", "</table>"]
    return "\n".join(out)


def _clock(ts):
    from .console import _clock as c
    return c(ts)


def report_html(campaign, crep):
    """One self-contained HTML page: summary, stage timeline, indicator -> flow table, technique coverage
    (expected / observed / emitted), the malware family used and an address-mode notice. Tables only; no script,
    no external resource. Every value (they come from feeds) is escaped."""
    meta = campaign.get("meta") or {}
    opt = campaign.get("options") or crep.get("options") or {}
    entries = crep.get("entries") or []
    ok = [e for e in entries if e.get("status") == "ok"]
    mode = opt.get("address_mode", "mapped")
    table = {r["index"]: r for r in crep.get("iocs") or []}
    P = ["<!DOCTYPE html>", '<html lang="en"><head><meta charset="utf-8">',
         "<title>Campaign report: %s</title>" % _e(meta.get("name") or crep.get("id")),
         '<meta name="viewport" content="width=device-width, initial-scale=1">',
         "<style>%s</style></head><body>" % _CSS,
         "<h1>Campaign report: %s</h1>" % _e(meta.get("name") or crep.get("id"))]
    if mode == "real":
        P.append('<p class="note"><b>Real address mode.</b> Indicator addresses appear in the capture exactly as '
                 "supplied. Do not replay this capture onto a network where those addresses are reachable.</p>")
    else:
        P.append('<p class="note"><b>Mapped address mode.</b> Indicator IPv4 addresses were re-addressed into the '
                 "198.18.0.0/15 benchmark range, so the addresses in the capture differ from the indicators; the "
                 "table below shows both. Names, URLs and hashes are unchanged.</p>")
    P += ["<h2>Summary</h2>", _table(["Field", "Value"], [
        ["Description", meta.get("description", "")], ["Actor", meta.get("actor", "")],
        ["Address mode", mode], ["Speed", opt.get("speed", "realistic")], ["Seed", meta.get("seed", "-")],
        ["Actions that emitted traffic", "%d of %d" % (len(ok), len(entries))],
        ["Packets", sum(e["packets"] for e in ok)], ["Bytes", sum(e["bytes"] for e in ok)]])]
    P += ["<h2>Stage timeline</h2>", _table(["Start", "Stage", "Tactic", "Techniques", "Length (s)", "Actions run"], [
        [_clock(st.get("start")), st.get("name") or st.get("id"), st.get("tactic") or "", ", ".join(st.get("techniques") or []),
         int(round(st.get("length_s") or 0)),
         "%d of %d" % (len([e for e in ok if e.get("stage") == st.get("id")]), len([e for e in entries if e.get("stage") == st.get("id")]))]
        for st in crep.get("stages") or []], "no stages")]
    rows, traced = [], set()
    for e in ok:
        for i in e.get("ioc") or []:
            r = table.get(i, {})
            if r.get("type") not in OBSERVABLE:
                traced.add(i)
                continue
            rows.append([r.get("value", "?"), r.get("role", "?"), r.get("address") or r.get("value", "?"),
                         e.get("stage"), e.get("action"), e["packets"]])
    P += ["<h2>Indicators to flows</h2>",
          _table(["Indicator", "Role", "In the capture as", "Stage", "Action", "Packets"], rows, "no indicator reached the wire")]
    if traced:
        P.append("<p>%d other indicator(s) (hashes, file names, ...) are carried for traceability; nothing on the wire "
                 "carries them.</p>" % len(traced))
    expected = {}
    cves = {}
    for x in campaign.get("expect") or []:
        if x.get("cve"):
            cves.setdefault(x.get("technique"), set()).add(x["cve"])
        else:
            expected.setdefault(x.get("technique"), set()).add(str(x.get("stage")))
    for t, cs in cves.items():
        expected.setdefault(t, set()).add("%d known-exploited CVE(s): %s%s" % (
            len(cs), ", ".join(sorted(cs)[:3]), ", ..." if len(cs) > 3 else ""))
    for st in crep.get("stages") or []:
        for t in st.get("techniques") or []:
            expected.setdefault(t, set()).add(str(st.get("id")))
    for e in entries:                                   # planned by an action, whether or not it ran
        for t in e.get("techniques") or []:
            expected.setdefault(t, set()).add(str(e.get("stage")))
    emitted = {}
    for e in ok:
        for t in e.get("techniques") or []:
            emitted[t] = emitted.get(t, 0) + 1
    P += ["<h2>Technique coverage</h2>", "<p>Expected: declared by the campaign's stages and actions. Emitted: actions that put "
          "traffic in the capture. Observed: to be filled in from what the sensor reports.</p>",
          _table(["Technique", "Expected in stages", "Emitted by (actions)", "Observed"], [
              [t, ", ".join(sorted(expected.get(t, []))), emitted.get(t, 0), ""] for t in sorted(set(expected) | set(emitted))],
              "no techniques")]
    used = families_used(campaign, crep)
    fam_rows = []
    for fid in used:
        f = families.FAMILIES[fid]
        fam_rows.append([f["name"], fid, f["kind"], "%s s, jitter %s" % (f["interval_s"], f["jitter"]),
                         "%s to %s bytes" % (f["size_min"], f["size_max"]), f["notes"]])
    P += ["<h2>Malware family</h2>"]
    P.append(_table(["Family", "Id", "Kind", "Cadence", "Reply size", "What is imitated"], fam_rows, "no family look-alike profile was used")
             if fam_rows else "<p>No family look-alike profile was used.</p>")
    bad = [e for e in entries if e.get("status") != "ok"]
    notes = [str(err.get("error", err)) for err in crep.get("errors") or [] if "stage" not in err]
    P += ["<h2>Not in the capture</h2>", _table(["Stage", "Action", "Status", "Reason"],
          [[e.get("stage"), e.get("action"), e.get("status"), e.get("error")] for e in bad], "nothing")]
    if notes:
        P.append("<ul>" + "".join("<li>%s</li>" % _e(n) for n in notes) + "</ul>")
    P.append("</body></html>")
    return "\n".join(P) + "\n"


def write_all(campaign, report, prefix):
    """Write the outputs and return {"campaign","stix","navigator","report","html","csv","misp"} paths."""
    d = os.path.dirname(prefix)
    if d:
        os.makedirs(d, exist_ok=True)
    crep = _camp_report(report, (campaign.get("meta") or {}).get("id"))
    paths = {"campaign": prefix + ".campaign.json", "stix": prefix + ".campaign-iocs.stix.json",
             "navigator": prefix + ".attack-navigator.json", "report": prefix + ".campaign-report.md",
             "html": prefix + ".report.html", "csv": prefix + ".indicators.csv", "misp": prefix + ".misp-event.json"}
    with open(paths["campaign"], "w") as f:
        json.dump(campaign, f, indent=2, sort_keys=True)
        f.write("\n")
    with open(paths["stix"], "w") as f:
        json.dump(stix_bundle(campaign, crep), f, indent=1)
    with open(paths["navigator"], "w") as f:
        json.dump(navigator_layer(campaign, crep), f, indent=1)
    with open(paths["report"], "w") as f:
        f.write(report_md(campaign, crep))
    with open(paths["html"], "w") as f:
        f.write(report_html(campaign, crep))
    with open(paths["csv"], "w", newline="") as f:
        f.write(indicators_csv(campaign, crep))
    with open(paths["misp"], "w") as f:
        json.dump(misp_event(campaign, crep), f, indent=1)
    return paths
