"""Campaign page panels. Each module defines ``render(view, ctx) -> dict | None`` (contract section 4).

This package file holds the helpers the panels share: escaping, text fitting, tactic colours and the one
small stylesheet the page embeds. Nothing here runs a script or loads an external resource.
"""
import html
import zlib

import make_diagram as MD

esc = MD.esc
SAPPHIRE, PLUM, CYAN, TANGERINE, GRAY, MAGENTA = MD.SAPPHIRE, MD.PLUM, MD.CYAN, MD.TANGERINE, MD.GRAY, MD.MAGENTA

TACTIC_COLOUR = {
    "reconnaissance": "#64748b", "resource-development": "#7c6f64", "initial-access": TANGERINE,
    "execution": MAGENTA, "persistence": "#8a5cf0", "privilege-escalation": "#a21caf",
    "stealth": "#475569", "defense-impairment": "#0f766e", "credential-access": CYAN,
    "discovery": SAPPHIRE, "lateral-movement": "#1a8a4a", "collection": "#0E7490",
    "command-and-control": PLUM, "exfiltration": "#b45309", "impact": "#7f1d1d",
}
_CYCLE = [PLUM, TANGERINE, CYAN, SAPPHIRE, "#8a5cf0", "#1a8a4a"]


def tactic_colour(slug):
    if slug in TACTIC_COLOUR:
        return TACTIC_COLOUR[slug]
    return _CYCLE[zlib.crc32(str(slug).encode()) % len(_CYCLE)]


def trunc(text, px, size=9.0):
    """Cut `text` to roughly `px` pixels at `size` px font (0.56 em per character)."""
    text = "" if text is None else str(text)
    n = max(1, int(px / (0.56 * size)))
    return text if len(text) <= n else text[:max(1, n - 1)] + "…"


def fmt_int(n):
    return "n/a" if n is None else format(int(n), ",")


def fmt_bytes(n):
    if n is None:
        return "n/a"
    n = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return ("%d %s" % (n, u)) if u == "B" else ("%.1f %s" % (n, u))
        n /= 1024.0


def fmt_dur(sec):
    if sec is None:
        return "n/a"
    sec = int(round(sec))
    if sec < 60:
        return "%ds" % sec
    if sec < 3600:
        return "%dm %02ds" % (sec // 60, sec % 60)
    return "%dh %02dm" % (sec // 3600, (sec % 3600) // 60)


def fmt_off(sec):
    """A planned offset such as +0:00, +12:30 or +1:05:00."""
    sec = int(round(sec or 0))
    h, r = divmod(sec, 3600)
    m, s = divmod(r, 60)
    return "+%d:%02d:%02d" % (h, m, s) if h else "+%d:%02d" % (m, s)


def clock(start, sec):
    """Wall-clock HH:MM:SS from an option start 'HH:MM' plus an offset."""
    try:
        hh, mm = str(start).split(":")[:2]
        total = int(hh) * 3600 + int(mm) * 60 + int(round(sec or 0))
    except (TypeError, ValueError):
        total = int(round(sec or 0))
    total %= 86400
    return "%02d:%02d:%02d" % (total // 3600, (total % 3600) // 60, total % 60)


def when(view, sec):
    """Clock time for a run, an offset for a plan: the timeline and the cards share this rule."""
    return clock(view["options"].get("start"), sec) if view["mode"] != "plan" else fmt_off(sec)


def node_label(view, nid):
    n = next((x for x in view["nodes"] if x["id"] == nid), None)
    return n["label"] if n else str(nid)


def node_of(view, nid):
    return next((x for x in view["nodes"] if x["id"] == nid), None)


def action_name(view, i):
    a = view["actions"][i]
    return "%s (%s)" % (a["title"], a["stage"])


def alt_table(rows, head=None):
    """The text alternative for an SVG: a closed details element holding a table."""
    if not rows:
        return ""
    th = "".join("<th>%s</th>" % esc(h) for h in head) if head else ""
    body = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % esc("" if c is None else c) for c in r) for r in rows)
    return ('<details class="cd-alt"><summary>Text alternative</summary><table>%s<tbody>%s</tbody></table></details>'
            % ("<thead><tr>%s</tr></thead>" % th if th else "", body))


CSS = """<style>
.cd-banner{margin:14px 0 2px;padding:8px 12px;border-left:3px solid var(--cyan);background:#f7f7f9;font-size:11.5px;color:#4a4760}
.cd-banner b{color:var(--sapphire)}
.cd-banner.plan{border-left-color:var(--gray)}.cd-banner.scored{border-left-color:var(--tangerine)}
.cd-plain{margin:2px 0 4px;padding-left:0;list-style:none}
.cd-plain li{font-size:13px;line-height:1.5;margin:0 0 5px}
.cd-plain .refs{font-size:9.5px;color:var(--gray);margin-left:6px;white-space:nowrap}
.cd-sub{display:block;font-size:10.5px;font-weight:400;letter-spacing:0;text-transform:none;color:var(--gray);margin-top:2px}
.cd-card{border:1px solid var(--line);border-radius:8px;margin:0 0 10px;overflow:hidden;break-inside:avoid}
.cd-card>header{display:flex;gap:10px;align-items:center;padding:7px 10px;background:#fafafc;border-bottom:1px solid var(--line)}
.cd-card h3{font-size:12.5px;font-weight:900;color:var(--sapphire)}
.cd-card .nar{padding:6px 10px 2px;font-size:11px;color:#4a4760}
.cd-card table{margin:4px 0 6px}
.cd-badge{display:inline-block;font-size:8.5px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;
  padding:2px 8px;border-radius:999px;white-space:nowrap}
.cd-state{font-size:9.5px;font-weight:700;margin-left:auto;color:var(--gray);white-space:nowrap}
.cd-state.ok{color:var(--cyan)}.cd-state.partial,.cd-state.skipped{color:var(--tangerine)}
td.cd-w{max-width:260px;word-break:break-word}
.cd-muted{color:var(--gray)}
.cd-alt{margin-top:4px;font-size:10px;color:var(--gray)}.cd-alt summary{cursor:default}
.cd-alt table{margin-top:4px;font-size:10px}
.cd-more{font-size:10.5px;color:var(--gray);margin:6px 0 0}
.cd-svg{margin:4px 0}.cd-svg svg{width:100%;height:auto;display:block}
.cd-flag{font-size:9px;font-weight:700;color:var(--tangerine);margin-left:4px}
</style>"""
