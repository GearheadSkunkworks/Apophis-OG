"""Finding it in a capture: per-action display filters, deduplicated. Omitted when no action has a filter."""
from . import esc, fmt_int

GROUP_ABOVE = 40


def collect(view):
    seen, out = {}, []
    for a in view["actions"]:
        for f in a["filters"]:
            key = f["filter"]
            if key in seen:
                row = seen[key]
                row["actions"].append(a)
                continue
            row = {"what": f["what"], "filter": key, "expect": f["expect"], "actions": [a]}
            seen[key] = row
            out.append(row)
    return out


def render(view, ctx):
    rows = collect(view)
    if not rows:
        return None
    grouped = len(rows) > GROUP_ABOVE
    if grouped:                                   # keep the first two filters of each action type
        per, keep = {}, []
        for r in rows:
            tok = r["actions"][0]["action"]
            per[tok] = per.get(tok, 0) + 1
            if per[tok] <= 2:
                keep.append(r)
        rows_shown = keep
    else:
        rows_shown = rows
    run = view["mode"] != "plan"
    body = ""
    for r in rows_shown:
        acts = r["actions"]
        who = "%s%s" % (acts[0]["title"], " +%d more" % (len(acts) - 1) if len(acts) > 1 else "")
        exp = r["expect"]
        if run:
            ok = [a for a in acts if a["status"] == "ok"]
            exp += " (%s packets from this capture)" % fmt_int(sum(a["packets"] or 0 for a in ok)) if ok else \
                " (this action did not run)"
        body += ('<tr><td>%s</td><td class="m cd-w">%s</td><td class="svc">%s</td><td class="svc">%s</td></tr>'
                 % (esc(r["what"]), esc(r["filter"]), esc(exp), esc(who)))
    table = ('<table><thead><tr><th>What</th><th>Display filter</th><th>Expect</th><th>Action</th></tr></thead>'
             '<tbody>%s</tbody></table>' % body)
    if grouped:
        table += '<p class="cd-more">Grouped by action type: %d of %d filters shown.</p>' % (len(rows_shown), len(rows))
    sub = ("Filters carry this capture's addresses and ports." if run else
           "Filters use the addresses the build will place; they are planned values.")
    return {"id": "filters", "title": "Finding it in a capture", "sub": sub, "svg": None, "html": table, "height": 0,
            "alt": [[r["what"], r["filter"], r["expect"]] for r in rows_shown]}
