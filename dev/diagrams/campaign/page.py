"""Assemble a campaign page from panels and hand it to make_diagram.render_page (contract section 4).

`render(campaign, summary=None, score=None, company=None, inventory=None) -> str` returns a complete static HTML
page (no scripts, no external resources beyond the shared page chrome). `campaign` may be a list for the overview
page. `build(view, ctx) -> dict` returns the builder dict (`svg`, `kpis`, `sections`, `notes`) used by tests.
"""
import importlib

import make_diagram as MD

from . import view as V
from .panels import CSS, alt_table, esc

ORDER = ("header", "plain", "timeline", "flowmap", "stages", "trace", "coverage", "filters", "notes")
_RANK = {"plan": 0, "run": 1, "scored": 2}


def _panel(name):
    try:
        return importlib.import_module("%s.panels.%s" % (__package__, name))
    except ImportError:
        if name == "flowmap":                                    # written by another worker; the page copes without it
            return None
        raise


def panels(view, ctx):
    """Every panel that applies, in page order. A panel that fails or is missing is left out, never fatal,
    except the ones this package owns, which must not fail silently."""
    out = []
    for name in ORDER:
        mod = _panel(name)
        if mod is None:
            continue
        if name == "flowmap":
            if not view["actions"]:
                continue
            try:
                p = mod.render(view, ctx)
            except Exception:                                    # noqa: BLE001  another worker's panel
                p = None
        else:
            p = mod.render(view, ctx)
        if p:
            p.setdefault("id", name)
            out.append(p)
    return out


def _section(p):
    head = esc(p["title"]) + ('<span class="cd-sub">%s</span>' % esc(p["sub"]) if p.get("sub") else "")
    body = ""
    if p.get("svg"):
        body += '<div class="cd-svg">%s</div>' % p["svg"]
        body += alt_table(p.get("alt"), p.get("alt_head"))
    if p.get("html"):
        body += p["html"]
    return head, body


def build(view, ctx):
    ps = panels(view, ctx)
    header = next(p for p in ps if p["id"] == "header")
    sections = [_section(p) for p in ps if p["id"] not in ("header", "notes")]
    if header.get("html"):
        sections.insert(0, ("Overview", header["html"]))
    sections[0] = (sections[0][0], CSS + sections[0][1])          # the stylesheet rides in the first section
    notes = next((p["notes"] for p in ps if p["id"] == "notes"), [])
    return {"svg": "", "kpis": header["kpis"], "sections": sections, "notes": notes,
            "h1": view["meta"]["name"], "subtitle": header["sub"],
            "doc_tag": "Campaign view<br>%s" % esc(header["badge"]), "badge": header["badge"], "panels": ps}


def _wrap(out, title, ctx, company):
    d = MD.Diagram("campaign", title, "Campaign view", lambda c: out, 0, None)
    return MD._relabel_identity(MD.render_page(d, ctx, MD.load_logo()), company)


def render(campaign, summary=None, score=None, company=None, inventory=None):
    ctx = V.make_ctx(inventory)
    if ctx is None:
        raise RuntimeError("the environment inventory could not be loaded")
    if isinstance(campaign, list):
        return _overview(campaign, ctx, company)
    view = V.build(campaign, summary, score, ctx, company)
    out = build(view, ctx)
    return _wrap(out, "Campaign · %s" % out["badge"], ctx, company)


# ------------------------------------------------------------------ several campaigns
def _item(x):
    if isinstance(x, dict) and "campaign" in x and "stages" not in x:
        return x["campaign"], x.get("summary"), x.get("score")
    return x, None, None


def overview_view(items, ctx):
    views = [V.build(c, s, sc, ctx) for c, s, sc in (_item(i) for i in items)]
    merged, vulns = {}, {}
    best = {"detected": 3, "related": 2, "missed": 1, None: 0}
    for v in views:
        for t in v["techniques"]:
            m = merged.setdefault(t["id"], dict(t, stages=[], actions=[], cves=[]))
            for k in ("expected", "emitted", "planned"):
                m[k] = m[k] or t[k]
            if best.get(t["score"], 0) > best.get(m["score"], 0):
                m["score"] = t["score"]
            m["cves"] = sorted(set(m["cves"]) | set(t["cves"]))
        for vu in v["vulns"]:
            vulns.setdefault(vu["cve"], set()).update(vu["techniques"])
    mode = min((v["mode"] for v in views), key=lambda m: _RANK[m]) if views else "plan"
    return {"mode": mode, "views": views, "techniques": [merged[k] for k in sorted(merged)],
            "vulns": [{"cve": k, "techniques": sorted(v)} for k, v in sorted(vulns.items())], "score": None,
            "options": {}, "stages": [], "actions": [], "nodes": [], "edges": [], "iocs": [], "errors": [],
            "notes": [], "meta": {"name": "Campaign overview", "description": ""},
            "totals": {}}


def _overview(items, ctx, company):
    ov = overview_view(items, ctx)
    views = ov["views"]
    rows = ""
    for v in views:
        t = v["totals"]
        rows += ('<tr><td><b>%s</b></td><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td></tr>'
                 % (esc(v["meta"]["name"]), esc(v["mode"].capitalize()), t["stages"], t["actions"], t["techniques"],
                    esc(v["options"].get("address_mode", "mapped"))))
    table = ('<table><thead><tr><th>Campaign</th><th>Mode</th><th>Stages</th><th>Actions</th><th>Techniques</th>'
             '<th>Addressing</th></tr></thead><tbody>%s</tbody></table>' % rows) if rows else \
        '<p class="cd-more">No campaigns were supplied.</p>'
    from .panels import coverage
    sections = [("Campaigns", CSS + table)]
    cov = coverage.render(ov, ctx)
    if cov:
        cov["title"], cov["sub"] = "Merged ATT&CK coverage", "All campaigns together"
        sections.append(_section(cov))
    kpis = [(str(len(views)), "Campaigns"), (str(sum(v["totals"]["stages"] for v in views)), "Stages"),
            (str(sum(v["totals"]["actions"] for v in views)), "Actions"), (str(len(ov["techniques"])), "Techniques")]
    notes = [(n["kind"], n["title"], n["body"]) for n in (views[0]["notes"] if views else [])
             if n["title"].startswith("Device role")]
    out = {"svg": "", "kpis": kpis, "sections": sections, "notes": notes, "h1": "Campaign overview",
           "subtitle": "%d campaigns; each has its own page" % len(views), "doc_tag": "Campaign view<br>Overview"}
    return _wrap(out, "Campaign · Overview", ctx, company)
