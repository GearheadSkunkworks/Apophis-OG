"""Indicator trace: which indicator rides which action, at what address, with the address mode stated.

Observable indicators (addresses, names, URLs) get a row each. Hashes, file names, e-mail addresses, CVE
identifiers and network ranges are listed apart as carried, not on the wire. Omitted when the campaign has
neither indicators nor vulnerability expectations."""
from . import action_name, esc

MAX_ROWS = 60
_KIND = {"mapped": "mapped into a test range", "real": "real", "internal": "inventory", "none": "none"}


def render(view, ctx):
    iocs, vulns = view["iocs"], view["vulns"]
    if not iocs and not vulns:
        return None
    mode = view["options"].get("address_mode", "mapped")
    run = view["mode"] != "plan"
    obs = [r for r in iocs if r["type"] in ("ipv4", "ipv6", "domain", "url")]
    carried = [r for r in iocs if r["type"] not in ("ipv4", "ipv6", "domain", "url")]
    html = ""
    if obs:
        rows = ""
        for r in obs[:MAX_ROWS]:
            by = "; ".join(action_name(view, i) for i in r["used_by"][:3]) + (
                " +%d more" % (len(r["used_by"]) - 3) if len(r["used_by"]) > 3 else "")
            if r["type"] == "ipv6":
                addr, state = "not placed", "carried, not placed in the capture"
            else:
                addr = r["address"] or "n/a"
                state = ("on the wire" if r["on_wire"] else
                         ("used by an action that did not run" if r["used_by"] and run else "not used by any action"))
            rows += ('<tr><td class="m cd-w">%s</td><td class="svc">%s</td><td class="svc">%s</td><td class="m ip">%s</td>'
                     '<td class="cd-w">%s</td><td class="svc">%s</td></tr>'
                     % (esc(r["value"]), esc(r["type"]), esc(r["role"]), esc(addr), esc(by or "-"), esc(state)))
        html += ('<table><thead><tr><th>Indicator</th><th>Type</th><th>Role</th><th>Address in the capture</th>'
                 '<th>Carried by</th><th>State</th></tr></thead><tbody>%s</tbody></table>' % rows)
        if len(obs) > MAX_ROWS:
            html += '<p class="cd-more">First %d of %d indicators shown.</p>' % (MAX_ROWS, len(obs))
    if carried or vulns:
        rows = ""
        for r in carried[:MAX_ROWS]:
            by = "; ".join(action_name(view, i) for i in r["used_by"][:3])
            rows += ('<tr><td class="m cd-w">%s</td><td class="svc">%s</td><td class="svc">%s</td><td class="cd-w">%s</td></tr>'
                     % (esc(r["value"]), esc(r["type"]), esc(r["role"]), esc(by or "-")))
        listed = {str(r["value"]).upper() for r in carried if r["type"] == "cve"}
        for v in vulns:
            if v["cve"] in listed:
                continue
            rows += ('<tr><td class="m">%s</td><td class="svc">cve</td><td class="svc">vulnerability</td>'
                     '<td class="cd-w">%s</td></tr>' % (esc(v["cve"]), esc(", ".join(v["techniques"]) or "-")))
        if rows:
            html += ('<h3 style="font-size:11px;margin:12px 0 4px;color:var(--gray)">Carried, not on the wire</h3>'
                     '<table><thead><tr><th>Indicator</th><th>Type</th><th>Role</th><th>Carried by or technique</th></tr>'
                     '</thead><tbody>%s</tbody></table>' % rows)
            if len(carried) > MAX_ROWS:
                html += '<p class="cd-more">First %d of %d shown.</p>' % (MAX_ROWS, len(carried))
    if mode == "real":
        sub = "Real addressing: placed indicators appear in the capture with their own public addresses."
    else:
        sub = ("Mapped addressing: placed indicators appear in the capture at remapped test addresses; the "
               "indicator's own value is shown in the first column.")
    return {"id": "trace", "title": "Indicator trace", "sub": sub, "svg": None, "html": html, "height": 0,
            "alt": [[r["value"], r["type"], r["address"]] for r in iocs[:MAX_ROWS]]}
