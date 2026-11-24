"""Readable bodies for the Incident Replay scenarios (shared defect 31: random bytes typed as
text/html, text/css, application/json or XML). Every helper returns bytes of EXACTLY the length
asked for, because the exercise pages quote the sizes; the words come from a private seeded
generator keyed on the request, so nothing here draws from the engine's shared random stream."""
from netgen import protocols as _P
import json
import random
import zlib

_WORDS = ("account overview report status policy session gateway portal update review archive "
          "request service profile settings summary access queue schedule release notice team "
          "inventory support ticket dashboard export import audit backup network device").split()


def _rnd(*key):
    return random.Random(zlib.crc32("|".join(str(k) for k in key).encode()))


def _words(r, n_chars):
    out = []
    while sum(len(w) + 1 for w in out) < n_chars:
        out.append(r.choice(_WORDS))
    return " ".join(out)[:n_chars]


def fit(data, n, pad=b" "):
    """Exactly n bytes: cut at a line end when too long, pad with `pad` before a final newline."""
    if isinstance(data, str):
        data = data.encode()
    if len(data) > n:
        cut = data[:n].rfind(b"\n")
        data = data[:cut + 1] if cut > n // 2 else data[:n]
    if len(data) < n:
        gap = n - len(data)
        data = (data[:-1] + pad * gap + b"\n") if data.endswith(b"\n") else data + pad * gap
    return data[:n]


def html_page(title, n, key="", links=()):
    head = ("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>%s</title>"
            "<link rel=\"stylesheet\" href=\"/style.css\"></head>\n<body><div class=\"header\">%s</div>\n"
            % (title, title))
    nav = "".join("<a href=\"%s\">%s</a> " % (h, t) for h, t in links)
    if nav:
        head += "<div class=\"nav\">%s</div>\n" % nav
    tail = "</body></html>\n"
    r = _rnd("html", title, n, key)
    body = ""
    while n - len(head) - len(body) - len(tail) > 160:
        room = n - len(head) - len(body) - len(tail)
        body += "<p>%s.</p>\n" % _words(r, min(room - 60, r.randint(90, 240)))
    page = head + body + tail
    gap = n - len(page)
    if gap >= 9:
        filler = "<!-- " + _words(r, gap - 9) + " -->"
        page = head + body + filler + tail
    return fit(page, n)


def css_page(title, n, key=""):
    r = _rnd("css", title, n, key)
    s = "/* %s */\nbody { font-family: Arial, sans-serif; margin: 0; color: #222; }\n" % title
    props = ["margin: %dpx;", "padding: %dpx;", "font-size: %dpx;", "border-radius: %dpx;", "line-height: %dpx;"]
    i = 0
    while len(s) < n - 120:
        s += ".c%d { %s }\n" % (i, " ".join(r.choice(props) % r.randint(1, 24) for _ in range(3)))
        i += 1
    return fit(s, n)


def json_doc(n, key="", obj=None):
    """A JSON document of exactly n bytes: `obj` (or a list of generated records) padded with a
    trailing notes string."""
    r = _rnd("json", n, key)
    if obj is None:
        obj = {"data": []}
        i = 1
        while len(json.dumps(obj, separators=(",", ":"))) < n - 80:
            obj["data"].append({"id": i, "name": _words(r, r.randint(8, 24)), "state": r.choice(["ok", "open", "done"])})
            i += 1
    s = json.dumps(obj, separators=(",", ":"))
    if len(s) > n:
        while obj.get("data") and len(json.dumps(obj, separators=(",", ":"))) > n:
            obj["data"].pop()
        s = json.dumps(obj, separators=(",", ":"))
    gap = n - len(s)
    if gap > 0:
        s = s[:-1] + " " * gap + s[-1]          # whitespace before the closing brace keeps it valid
    return s.encode()[:n] if len(s) >= n else s.encode()


def xml_doc(root, n, key=""):
    r = _rnd("xml", root, n, key)
    head = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<%s>\n" % root
    tail = "</%s>\n" % root
    body = ""
    i = 1
    while n - len(head) - len(body) - len(tail) > 100:
        room = n - len(head) - len(body) - len(tail)
        body += "  <entry id=\"%d\">%s</entry>\n" % (i, _words(r, min(room - 40, r.randint(40, 120))))
        i += 1
    s = head + body + tail
    gap = n - len(s)
    if gap > 0:
        s = head + body + " " * (gap - 1) + "\n" + tail if gap > 1 else head + body + tail.replace(">\n", ">") + " "
    return fit(s, n)


# ---- command output for the NetScaler webshell (FreeBSD-based appliance) ----------------------
def netscaler_cmd_output(cmd, n, ns_conf=b"", vip="", snip="", user_pfx="10.10.10"):
    r = _rnd("cmd", cmd, n)
    if cmd.startswith("ls"):
        names = ["rc.conf.local", "ns_gui_check.sh", "sslvpn_cleanup.sh", "vpn_stats.pl", "cron_sync.sh",
                 "ldap_auth_helper", "nsrecover.sh", "portal_theme.tgz"]
        out = "\n".join(names[:r.randint(5, 8)]) + "\n"
    elif cmd == "whoami":
        out = "root\n"
    elif cmd == "id":
        out = "uid=0(root) gid=0(wheel) groups=0(wheel),5(operator)\n"
    elif cmd.startswith("uname"):
        out = ("FreeBSD ns1.%s 12.2-NS13.1-49.15 FreeBSD 12.2-NS13.1-49.15 #0: "
               "Tue Jun 18 03:21:07 UTC 2024 root@sdx-build:/usr/obj/ns_build amd64\n") % _P.DOMAIN
    elif ".htpasswd" in cmd:
        out = "nsroot:$1$%s$%s\n" % ("".join(r.choice("abcdefgh12345678") for _ in range(8)),
                                     "".join(r.choice("abcdefghijklmnop./0123456789") for _ in range(22)))
    elif "grep EST" in cmd:
        out = ""
        for _i in range(12):
            out += "tcp4  0  0  %s.443  %s.%d  ESTABLISHED\n" % (vip or "0.0.0.0", "%s.%d" % (user_pfx, r.randint(20, 90)), r.randint(40000, 60000))
            if len(out) >= n:
                break
    elif cmd.startswith("netstat"):
        rows = [("tcp4", "0.0.0.0.22", "LISTEN"), ("tcp4", "%s.443" % (vip or "0.0.0.0"), "LISTEN"),
                ("tcp4", "127.0.0.1.8080", "LISTEN"), ("tcp4", "%s.80" % (snip or "0.0.0.0"), "LISTEN"),
                ("tcp4", "127.0.0.1.3010", "LISTEN"), ("tcp4", "0.0.0.0.3008", "LISTEN"),
                ("tcp4", "127.0.0.1.5555", "LISTEN"), ("tcp4", "0.0.0.0.3009", "LISTEN")]
        out = ("Active Internet connections (including servers)\nProto Recv-Q Send-Q  "
               "Local Address          Foreign Address        (state)\n")
        rows += [("tcp4", "127.0.0.1.%d" % p, "LISTEN") for p in (3011, 3012, 7000, 7001, 9090, 9091, 5666)]
        for proto, local, st in rows:
            out += "%-5s %6d %6d  %-22s %-22s %s\n" % (proto, 0, 0, local, "*.*", st)
            if len(out) >= n:
                break
    elif cmd.startswith("cat"):
        out = ns_conf.decode(errors="replace") if ns_conf else "# ns.conf\n"
    else:
        out = "\n"
    return fit(out, n)


def linux_cmd_output(cmd, n, host="appliance", user_pfx="10.10.10", local="", extra=""):
    """Readable output of a command run through a webshell on a Linux appliance, exactly n bytes.
    Only listing-style commands are modelled; anything else returns `extra` or a blank line."""
    r = _rnd("lcmd", cmd, n, host)
    if cmd == "whoami":
        out = "root\n"
    elif cmd == "id":
        out = "uid=0(root) gid=0(root) groups=0(root)\n"
    elif cmd.startswith("uname"):
        out = "Linux %s 5.15.0-97-generic #107-Ubuntu SMP Wed Feb 7 13:26:48 UTC 2024 x86_64 GNU/Linux\n" % host
    elif cmd.startswith("ss "):
        out = "Recv-Q Send-Q Local Address:Port    Peer Address:Port Process\n"
        for _ in range(14):
            out += "0      0      %s:443     %s.%d:%d\n" % (local or "0.0.0.0", user_pfx, r.randint(20, 90), r.randint(40000, 60000))
            if len(out) >= n:
                break
    else:
        out = extra or "\n"
    return fit(out, n)


def pem_blob(label, n, key=""):
    """A PEM-shaped block of exactly n bytes (base64 body, 64-column lines). The payload is bytes
    from the private generator, so it carries no real key/secret material."""
    import base64
    r = _rnd("pem", label, n, key)
    head = "-----BEGIN %s-----\n" % label
    tail = "-----END %s-----\n" % label
    room = max(0, n - len(head) - len(tail))
    raw = bytes(r.randrange(256) for _ in range(room))
    b64 = base64.b64encode(raw).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    body = "\n".join(lines) + ("\n" if lines else "")
    s = head + body + tail
    return fit(s, n)
