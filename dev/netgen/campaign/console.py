"""Console narration of a campaign, built ONLY from what was emitted.

``narrate(report)`` takes ``ctx.campaign_report`` (or one campaign's record from it) and returns
text lines. Every command line, count and byte figure comes from the per-action records the runner
filled in while the packets were generated, so the console cannot disagree with the capture. An
action that failed or was skipped is shown as such, with its reason.
"""
from datetime import datetime

from .. import model

# Optional per-action command renderers: fn(entry) -> str. Anything not listed gets the generic
# "$ <action> <params> <from> -> <to>" form, which is always true to the record.
COMMANDS = {}


def _beacon(entry):
    p = entry.get("params") or {}
    ip = (entry.get("to_host") or {}).get("ip") or entry.get("to")
    jit = p.get("jitter")
    bits = ["beacon", "sleep", str(int(p["interval_s"]) if float(p.get("interval_s", 0)).is_integer() else p.get("interval_s"))]
    if jit is not None:
        bits.append(str(int(round(float(jit) * 100))))
    bits.append("-> %s (%s x%s)" % (ip, entry.get("action"), p.get("count", "?")))
    return " ".join(bits)


for _tok in ("https_beacon", "http_beacon", "dns_beacon"):
    COMMANDS[_tok] = _beacon


def _ip(entry, side):
    h = entry.get(side + "_host") or {}
    return h.get("ip") or entry.get(side) or "?"


def _name(entry, side):
    h = entry.get(side + "_host") or {}
    ref = str(entry.get(side) or "")
    if ":" in ref and not ref.startswith("host:") and h.get("ip"):
        return h["ip"]                                    # an outside indicator host: its address is the useful name
    return h.get("name") or h.get("ip") or ref or "?"


def _opt(p, key, fmt="%s=%s"):
    v = (p or {}).get(key)
    return fmt % (key, v) if v not in (None, "", [], {}) else ""


def _cmd(template, *opts):
    """Build a renderer from a template with {src} {dst} {srcname} {dstname} and optional param keys appended."""
    def fn(entry):
        p = entry.get("params") or {}
        text = template.format(src=_ip(entry, "from"), dst=_ip(entry, "to"),
                               srcname=_name(entry, "from"), dstname=_name(entry, "to"))
        extra = " ".join(x for x in (_opt(p, k) for k in opts) if x)
        return text + (" [" + extra + "]" if extra else "")
    return fn


# One line per new action, in the style of the beacon lines: what the operator would be running, then who to whom.
COMMANDS.update({
    "web_dir_scan": _cmd("dir-scan http://{dstname}/ from {src} wordlist common-paths", "requests", "paths", "count"),
    "subdomain_enum": _cmd("subdomain-enum against {dstname} from {src} wordlist common-names", "names", "count", "domain"),
    "new_domain_contact": _cmd("fetch https://{dstname}/ from {src} (new domain, certificate issued minutes ago)"),
    "selfsigned_tls_contact": _cmd("tls-connect {dstname} from {src} (self-signed certificate, non-standard port)", "port"),
    "web_login_spray": _cmd("login-spray https://{dstname}/ from {src} (dummy credential pairs)", "attempts", "count", "path"),
    "exposed_service_login": _cmd("remote-login {dst} from {src} (exposed remote-access service)", "service", "port", "attempts"),
    "winrm_exec": _cmd("remote-shell {dstname} hostname (WS-Management, {src} -> {dst})", "command"),
    "ssh_remote_exec": _cmd("ssh {dstname} whoami (exec bursts, {src} -> {dst})", "command", "commands"),
    "remote_schtask": _cmd("task-register on {dstname} (task-scheduler RPC over IPC$, {src} -> {dst})", "task_name", "name"),
    "svcctl_persist": _cmd("service-create on {dstname} (auto-start, service-control RPC over IPC$, {src} -> {dst})", "service_name", "name"),
    "gpo_modify": _cmd("policy-edit on {dstname} (policy container change plus SYSVOL write, {src} -> {dst})", "gpo", "policy"),
    "privileged_group_add": _cmd("group-add on {dstname} (member added to a privileged group over LDAP, {src} -> {dst})", "group", "member"),
    "eventlog_clear": _cmd("log-clear on {dstname} (event-log RPC over IPC$, {src} -> {dst})", "log", "logs"),
    "lolbin_fetch": _cmd("system-binary fetch of {dstname} from {src} (look-alike request)", "user_agent", "scheme", "path"),
    "security_service_stop": _cmd("service-stop on {dstname} (security services, service-control RPC, {src} -> {dst})", "services", "service"),
    "security_update_block": _cmd("update-check {dstname} from {src} (lookups and refused connections)", "count", "interval_s"),
    "sql_collect": _cmd("db-query {dstname} (login then large result sets, {src} -> {dst})", "database", "rows", "queries"),
    "archive_stage": _cmd("copy archive to staging share on {dstname} (SMB write, {src} -> {dst})", "size_mb", "total_mb", "directory"),
    "icmp_tunnel": _cmd("icmp-channel {dst} from {src} (echo with variable payload sizes)", "count", "interval_s"),
    "cloud_service_c2": _cmd("poll https://{dstname}/ from {src} (cloud-service API check-ins)", "count", "interval_s", "service"),
    "cloud_storage_upload": _cmd("put chunks to https://{dstname}/ from {src} (object-storage upload)", "total_mb", "total_bytes", "chunks"),
    "smtp_exfil": _cmd("mail-send via {dstname} from {src} (large attachment)", "size_mb", "attachment_bytes", "recipient"),
    "smb_delete_burst": _cmd("delete-files on {dstname} share (SMB delete burst, {src} -> {dst})", "files", "count", "share"),
})


def _clock(ts):
    if ts is None:
        return "--:--:--"
    return datetime.fromtimestamp(ts, model.TZ).strftime("%H:%M:%S")


def _size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%d %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def _endpoint(entry, side):
    ref = entry.get(side)
    h = entry.get(side + "_host") or {}
    return "%s (%s)" % (ref, h["ip"]) if h.get("ip") and h.get("name") else str(ref)


def _params(p):
    return " ".join("%s=%s" % (k, v if not isinstance(v, (list, dict)) else "[...]")
                    for k, v in sorted((p or {}).items()))


def command_line(entry):
    fn = COMMANDS.get(entry.get("action"))
    if fn:
        try:
            return "$ " + fn(entry)
        except Exception:                                         # noqa: BLE001
            pass
    bits = [entry.get("action") or "?"]
    if entry.get("params"):
        bits.append(_params(entry["params"]))
    bits.append("%s -> %s" % (_endpoint(entry, "from"), _endpoint(entry, "to")))
    return "$ " + " ".join(b for b in bits if b)


def _campaigns(report):
    if not report:
        return []
    if "campaigns" in report:
        return report["campaigns"]
    return [report]


def narrate(report):
    lines = []
    if isinstance(report, dict):
        for e in report.get("errors") or []:
            if isinstance(e, dict) and "stage" not in e:
                lines.append("! campaign %s not built: %s" % (e.get("campaign", "?"), e.get("error")))
    for camp in _campaigns(report):
        mode = (camp.get("options") or {}).get("address_mode", "mapped")
        lines.append("=== Campaign: %s (%s addresses) ===" % (camp.get("name") or camp.get("id"), mode))
        total_pk = total_by = ran = 0
        stages = camp.get("stages") or []
        entries = camp.get("entries") or []
        for n, st in enumerate(stages, 1):
            techs = ", ".join(st.get("techniques") or [])
            lines.append("")
            lines.append("[%s] Stage %d/%d: %s%s%s" % (
                _clock(st.get("start")), n, len(stages), st.get("name") or st.get("id"),
                " (%s)" % techs if techs else "", " [%s]" % st["tactic"] if st.get("tactic") else ""))
            if st.get("narrative"):
                lines.append("    " + st["narrative"])
            for e in sorted((x for x in entries if x.get("stage") == st.get("id")),
                            key=lambda x: (x.get("ts") is None, x.get("ts") or 0)):
                lines.append("  [%s] %s" % (_clock(e.get("ts")), command_line(e)))
                if e.get("status") == "ok":
                    ran += 1
                    total_pk += e["packets"]
                    total_by += e["bytes"]
                    lines.append("      %d packets, %s, %s" % (
                        e["packets"], _size(e["bytes"]), "/".join(e.get("protocols") or []) or "-"))
                else:
                    lines.append("      %s: %s" % (e.get("status"), e.get("error") or "did not run"))
        lines.append("")
        lines.append("=== %d of %d actions emitted %d packets (%s) ===" % (
            ran, len(entries), total_pk, _size(total_by)))
    return lines
