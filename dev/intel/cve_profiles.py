"""Which vulnerabilities can be shown on the wire, and how (pure data, no network, no engine imports).

A CVE record (from CISA KEV) names a vendor, product and weakness. ``match(ioc)`` returns the profile of
the network-facing product class it belongs to, or None when nothing about it is reasonably seen on the
wire (a browser, an office file, a local privilege flaw). A profile describes the *shape* of an
exploit attempt only: a request to the product's characteristic endpoint and the server's refusal. No
exploit string, payload or bypass appears anywhere in this table; whether a given sensor flags the
shape depends on that sensor.
"""
import re

# id, regex on "vendor product name" text, title, what it is, endpoints, port, tls
PROFILES = (
    ("vpn_gateway", r"citrix|netscaler|fortinet|fortigate|fortios|pulse|ivanti|globalprotect|palo alto|sonicwall|"
                    r"anyconnect|cisco asa|secure access|vpn",
     "VPN / remote-access gateway", "an internet-facing VPN or remote-access gateway",
     ("/remote/login", "/vpn/index.html", "/global-protect/login.esp"), 443, True),
    ("mail_server", r"exchange|zimbra|roundcube|mail|owa",
     "Mail server", "a web-facing mail server",
     ("/owa/auth/logon.aspx", "/autodiscover/autodiscover.json"), 443, True),
    ("file_transfer", r"moveit|goanywhere|cleo|accellion|file transfer|sharepoint",
     "File-transfer / collaboration server", "a web-facing file-transfer or collaboration server",
     ("/human.aspx", "/_layouts/15/start.aspx"), 443, True),
    ("remote_mgmt", r"screenconnect|connectwise|teamviewer|solarwinds|manageengine|kaseya|remote (?:management|monitoring)",
     "Remote-management server", "a remote-management or monitoring server",
     ("/SetupWizard.aspx", "/webclient/"), 443, True),
    ("web_app", r"confluence|jenkins|weblogic|tomcat|struts|jboss|wordpress|joomla|drupal|gitlab|atlassian|apache|"
               r"nginx|php|jira|spring|log4j|web server|web application|http",
     "Web application / server", "a web application or application server",
     ("/login", "/admin/", "/api/"), 443, True),
    ("network_device", r"router|firewall|switch|appliance|gateway|camera|dvr|nas|d-link|tp-link|zyxel|netgear|qnap",
     "Network appliance", "a network appliance with a web management interface",
     ("/login.cgi", "/cgi-bin/luci/"), 80, False),
)
_COMPILED = tuple((p[0], re.compile(p[1], re.I)) + p[2:] for p in PROFILES)
_CLIENT = re.compile(r"\b(?:browser|chrome|chromium|firefox|safari|edge|office|word|excel|outlook|acrobat|reader|pdf|"
                     r"flash|internet explorer|kernel|windows (?:win32k|common log)|local privilege)\b", re.I)


def _text(ioc):
    return " ".join([str(ioc.get("note") or "").split(" | ")[0]] + [str(t) for t in ioc.get("tags") or []])


def match(ioc):
    """Profile dict for a cve indicator, or None. Client-side and local-privilege products never match."""
    if ioc.get("type") != "cve":
        return None
    text = _text(ioc)
    if _CLIENT.search(text):
        return None
    for pid, rx, title, what, paths, port, tls in _COMPILED:
        if rx.search(text):
            return {"id": pid, "title": title, "what": what, "paths": list(paths), "port": port, "tls": tls}
    return None


def get(pid):
    for p in PROFILES:
        if p[0] == pid:
            return {"id": p[0], "title": p[2], "what": p[3], "paths": list(p[4]), "port": p[5], "tls": p[6]}
    return None
