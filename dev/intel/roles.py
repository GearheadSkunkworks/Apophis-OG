"""Role inference for an IOC from the words around it.

infer_role(ioc, context_text="") -> (role, why)

Rules (first match in this priority order wins; text is the context line plus the IOC's note and tags):
  1. tor          "tor exit", "exit node", "tor relay"
  2. phishing     phish, phishing, credential harvest, fake login
  3. brute        brute force, password spray, credential stuffing, ssh attack, login attack
  4. scanner      scanner, scanning, port scan, mass scan, recon
  5. exfil        exfil, exfiltration, data theft, staging server (data upload)
  6. c2           c2, c&c, cnc, command and control, beacon, team server, botnet_cc, rat server
  7. payload      payload, download, delivery, dropper, loader, malware hosting, stager
  8. compromised  compromised, hacked, infected, hijacked
Type limits: hashes and file names can only be "payload" (that is the role their words are about:
the sample), cve only "vulnerability", cidr/email a few roles; domains, addresses and URLs
take any role. A role word applies to every indicator on the same line. Hashes with no role word
default to payload. A CVE is always role "vulnerability". Anything else is ("unknown", why): the module never guesses a role.
"""
import functools
import re

_RULES = [
    ("tor", r"\btor[\s_-]*(?:exit|relay)\b|\bexit[\s_-]*node\b|\btor\b[\s_-]*exit"),
    ("phishing", r"\bphish\w*|credential[\s_-]*harvest\w*|\bfake[\s_-]*login\b|\bspoof\w*[\s_-]*(?:page|site)"),
    ("brute", r"\bbrute[\s_-]*forc\w*|\bpassword[\s_-]*spray\w*|\bcredential[\s_-]*stuffing\b|\bssh[\s_-]*attack\w*|\blogin[\s_-]*attack\w*|\bbruteforce\w*"),
    ("scanner", r"\bscanner\w*|\bscanning\b|\bport[\s_-]*scan\w*|\bmass[\s_-]*scan\w*|\bscan\b|\brecon\b|\bprobing\b"),
    ("exfil", r"\bexfil\w*|\bdata[\s_-]*theft\b|\bdata[\s_-]*upload\b|\bstaging[\s_-]*server\b"),
    ("c2", r"\bc2s?\b|\bc&c\b|\bc[\s_-]*and[\s_-]*c\b|\bcnc\b|\bcommand[\s_-]*(?:and|&)[\s_-]*control\b|\bbeacon\w*|\bteam[\s_-]*server\b|\bbotnet[\s_-]*c\w*|\brat[\s_-]*server\b|\bc2intel"),
    ("payload", r"\bpayload\w*|\bdownload\w*|\bdelivery\b|\bdeliver\w*|\bdropper\w*|\bloader\b|\bmalware[\s_-]*(?:host\w*|distribution)\b|\bstager\b|\bdropped\b|\binstallation\b"),
    ("compromised", r"\bcompromised\b|\bhacked\b|\binfected\b|\bhijacked\b"),
]
_COMPILED = [(r, re.compile(p, re.I)) for r, p in _RULES]

_ALLOWED = {
    "ipv4": None, "ipv6": None, "domain": None, "url": None,
    "md5": {"payload"}, "sha1": {"payload"}, "sha256": {"payload"}, "filename": {"payload"},
    "email": {"phishing"}, "cve": {"vulnerability"}, "cidr": {"scanner", "brute", "c2", "compromised", "tor"},
}


@functools.lru_cache(maxsize=8192)
def _infer(t, text):
    allowed = _ALLOWED.get(t, None)
    for role, rx in _COMPILED:
        m = rx.search(text)
        if not m:
            continue
        if allowed is not None and role not in allowed:
            continue
        return role, "the text says '%s'" % m.group(0).strip()[:40]
    if t == "cve":
        return "vulnerability", "a CVE names a weakness, not a host: it is carried as a detection expectation, no traffic exploits it"
    if t in ("md5", "sha1", "sha256"):
        return "payload", "file hashes default to payload"
    if t == "filename":
        return "payload", "file names default to payload"
    return "unknown", "no role word in the text"


def infer_role(ioc, context_text=""):
    """Return (role, why). See the module docstring for the rule table. Results are cached per (type, text),
    so many indicators on one long line cost one scan."""
    t = ioc.get("type")
    tags = ioc.get("tags")
    bits = [str(context_text or ""), str(ioc.get("note") or "")] + [str(x) for x in (tags if isinstance(tags, (list, tuple)) else [])]
    text = " | ".join(b for b in bits if b)[:2000]
    return _infer(t if isinstance(t, str) else None, text)
