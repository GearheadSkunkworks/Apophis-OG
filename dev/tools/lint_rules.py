#!/usr/bin/env python3
"""Project lint gate: stdlib-only checks for the mistakes this repo has actually shipped or nearly shipped.

    python3 tools/lint_rules.py                 # check the tree against tools/lint_baseline.json (exit 1 on a problem)
    python3 tools/lint_rules.py --list          # every rule: id, why, fix
    python3 tools/lint_rules.py --summary       # baseline totals per rule
    python3 tools/lint_rules.py --rebaseline    # shrink the baseline after fixing violations (never grows it)
    python3 tools/lint_rules.py --rebaseline --new-rule L023   # first recording of a newly added rule only

The baseline is a ratchet. A file may never have more violations of a rule than the baseline records, a new file may
have none, and a fixed violation must be removed from the baseline (the entry would otherwise hide a future one).
Rules and the reasoning behind each are in docs/code-standards.md. Runs on any Python 3.11+ with no installs.
"""
import argparse
import ast
import json
import os
import re
import sys
import tokenize
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
DEV = os.path.dirname(HERE)
BASELINE = os.path.join(HERE, "lint_baseline.json")

# rule id -> (name, why, fix)
RULES = {
    "L000": ("syntax-error", "A file that does not parse cannot be checked and will not run.", "Fix the syntax error."),
    "L001": ("bare-except", "A bare except also catches KeyboardInterrupt and SystemExit and hides every bug.",
             "Catch the specific exceptions you expect."),
    "L002": ("swallowed-exception", "Catching Exception and doing nothing turns a bug into silent wrong output.",
             "Catch narrower exceptions, or log, re-raise, or add a comment stating why ignoring is correct."),
    "L003": ("shell-exec", "A shell string is an injection path and breaks on paths with spaces.",
             "Pass an argument list and leave shell off; use subprocess instead of os.system/os.popen."),
    "L004": ("subprocess-no-timeout", "A child that never exits hangs the server thread or the build forever.",
             "Pass timeout=, or add the call site to SUBPROCESS_TIMEOUT_ALLOW with a reason."),
    "L005": ("dynamic-code", "eval, exec, pickle, marshal and unsafe yaml run attacker-supplied code.",
             "Parse with json/ast.literal_eval, or yaml.safe_load."),
    "L006": ("mutable-default", "A mutable default argument is shared by every call.",
             "Default to None and create the object inside the function."),
    "L007": ("assert-validation", "assert is stripped under python -O, so input checked with it is not checked.",
             "Raise ValueError (or return an error) for input; keep assert for tests only."),
    "L008": ("random-for-secret", "random is predictable; tokens, keys, nonces and ids must not come from it.",
             "Use secrets or os.urandom. (netgen seeds its streams on purpose and is exempt.)"),
    "L009": ("weak-hash", "md5 and sha1 are broken for any security use.",
             "Use sha256 or better; for a non-security checksum add usedforsecurity=False or # lint-ok: <reason>."),
    "L010": ("insecure-tls-or-temp", "Disabled certificate checks and tempfile.mktemp are classic exploitable shortcuts.",
             "Verify certificates; use tempfile.mkstemp or NamedTemporaryFile."),
    "L011": ("local-path-literal", "An absolute home path leaks the author's machine and breaks everywhere else; /tmp is shared and guessable.",
             "Derive paths from the app data dir, Path.home(), or tempfile."),
    "L012": ("uncapped-request-body", "Reading a request body without a size cap lets one client exhaust memory.",
             "Check Content-Length against a *_CAP constant before reading."),
    "L013": ("unbounded-read", "A bare .read() on a network response or request stream has no size limit.",
             "Read with a byte cap: resp.read(MAX_BYTES + 1) and reject if it overflows."),
    "L014": ("reasonless-suppression", "A suppression with no reason cannot be reviewed or ever removed.",
             "Write the reason after it: '# noqa: S101 - <why>' or '# lint-ok: <why>'. Blanket noqa is never allowed."),
    "L015": ("todo-marker", "Unfinished-work markers in shipped code mean the work is not done.",
             "Finish it or remove it; track real follow-ups outside the code."),
    "L016": ("sleep", "A sleep hides a race or polls badly; it also slows every test and request that crosses it.",
             "Wait on an event or condition, or add the site to SLEEP_ALLOW with a reason."),
    "L017": ("monkeypatch", "Patching a module attribute changes behaviour for every importer.",
             "Pass the dependency in, or wrap it locally; add # lint-ok: <reason> for a deliberate patch."),
    "L018": ("fstring-py311", "Python 3.11 (CI's oldest) rejects a backslash or the same quote inside an f-string expression.",
             "Compute the value into a variable first."),
    "L019": ("network-no-timeout", "A network call without a timeout can hang a request thread forever.",
             "Pass timeout=."),
    "L020": ("html-injection", "Writing non-constant text through innerHTML, outerHTML, insertAdjacentHTML or document.write is XSS.",
             "Use textContent or el(); if markup is needed, wrap every dynamic part in esc()."),
    "L021": ("js-eval", "eval, new Function and string timers run text as code.",
             "Pass a function, or parse data with JSON.parse."),
    "L022": ("blank-target", "target=_blank without rel=noopener gives the opened page a handle on this one.",
             "Add rel=\"noopener noreferrer\" (or 'noopener' in window.open features)."),
    "L023": ("shared-temp-fixed-name", "A constant file name in the shared temp folder is guessable: another user can plant a file or link there first.",
             "Keep state in a per-user 0700 folder (the settings folder), or use tempfile.mkdtemp / mkstemp."),
    "L024": ("write-without-exclusive-open", "open(.., 'w') on a state, log, stop or predictable .tmp path follows a planted link and truncates whatever it points at.",
             "Create it with os.open(path, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, 0o600), or tempfile.mkstemp in the same folder and os.replace."),
    "L025": ("folder-mode", "A settings or run-state folder made with the default mode lets other users on the machine read what is kept in it.",
             "Pass mode=0o700, or call settings_store.ensure_private_dir()."),
    "L026": ("path-lookup-of-privileged-helper", "sudo, pkexec, getcap, secret-tool and security receive passwords or keyring secrets; found through PATH, a user-writable directory can stand in for them.",
             "Look them up in fixed system directories (replay.system_tool, keystore.system_tool) or use an absolute path."),
    "L028": ("secret-file-mode", "A private key, key log or token written through a plain open() takes the default mode, so other users of the machine can read it.",
             "Write it with netgen.tls.open_private(path) or os.open(path, flags, 0o600)."),
    "L029": ("origin-regex-with-any-port", "A Host or Origin guard for a loopback name that matches any port lets a page served from another local port pass; the cookie is not scoped to a port.",
             "Capture the port with (\\d{1,5}) and compare it to the port the server is bound to."),
    "L030": ("privileged-shell-redirect", "Shell text run with elevated rights that redirects into a variable path lets whoever controls the folder point it at another file.",
             "Create the file from the unprivileged side, or have the elevated shell make its own folder first (mkdir fails if the name exists)."),
    "L031": ("cert-check-off-needs-pin", "Turning certificate checks off lets anyone on the path read the credentials sent next.",
             "Pin the certificate (sensorops.pins.check) and list the file in CERT_NONE_PINNED; there is no other allowed use."),
    "L032": ("http-in-production", "A URL allow-list that accepts plain http without an environment switch lets a hostile feed make the app call local services.",
             "Accept http only when an explicit environment variable (for example OG_UPDATE_URL) is set."),
    "L033": ("untrusted-name-into-path", "A name or id read from JSON or a manifest, joined into a path unchecked, writes outside the folder when it holds '..' or a slash.",
             "Check it with re.fullmatch(r'[a-z0-9_.-]{1,64}', value) first, or take os.path.basename."),
    "L034": ("exception-text-in-reply", "Returning the text of a caught Exception to an HTTP client leaks paths, internals and secrets in the message.",
             "Print the traceback to the terminal and reply with a fixed sentence."),
    "L035": ("unpinned-automation", "A pip install without hashes, a workflow without permissions, an action pinned by tag or an unpinned base image lets a changed upstream run in our build.",
             "pip install --require-hashes -r <lock>; permissions: contents: read; uses: owner/repo@<40-hex sha> # tag; FROM image@sha256:..."),
    "L036": ("secret-compared-with-equals", "== on a secret returns sooner the earlier two values differ, which leaks it a byte at a time.",
             "Use hmac.compare_digest(a.encode(), b.encode())."),
    "L037": ("subprocess-in-auth-check", "A subprocess started by an authentication check runs once per request, so any caller can make the server fork helpers.",
             "Cache the secret in memory and refresh it on a timer."),
    "L038": ("post-without-session-cookie", "The app refuses every POST without the page cookie, which is only issued for the printed ?launch= URL; a harness that POSTs with no cookie jar gets 403 on a correct build.",
             "Open the printed URL first through an opener with http.cookiejar.CookieJar (urllib.request.HTTPCookieProcessor) and POST through it."),
    "L039": ("isdigit-without-isascii", "str.isdigit() is true for superscripts and other-script digits that int() rejects, so a guarded int() still raises on hostile text.",
             "Use x.isascii() and x.isdigit() (or re.fullmatch('[0-9]+', x)), and catch ValueError around the conversion."),
    "L040": ("walk-checks-files-not-dirs", "os.walk lists a symlinked directory in dirs, not files; a loop that refuses symlinks among files but ignores dirs lets 'json -> ../evil' through.",
             "Check os.path.islink on each name in dirs as well, or prune and refuse them."),
    "L027": ("audit-logs-values", "An audit or access log that writes request values keeps URLs with keys, folders and host names in a file others may read.",
             "Log the argument names and the status only."),
}

# Files allowed to switch certificate checks off, because they pin the peer's certificate instead (sensorops.pins.check).
CERT_NONE_PINNED = {"sensorops/providers/network_sensor.py": "lab appliances present self-signed certificates; the SHA-256 is pinned on first use"}

# Long-running or deliberately blocking calls. Key: "path" (whole file) or "path::function". Value: why it is allowed.
SUBPROCESS_TIMEOUT_ALLOW = {
    "replay.py::_launch_privileged": "osascript waits for the user to type an administrator password; no fixed bound exists",
}
SLEEP_ALLOW = {
    "replay.py::_watch": "polls a replay's log file for progress; the loop exits when the child process does",
    "replay.py::_self_test": "paces a short self-test replay and checks the elapsed time between steps",
}

NON_SHIPPED = ("tests", "checks", "tools", "docs", "labs", "..")      # first path component
SKIP_DIRS = {"__pycache__", ".git", "node_modules", "fixtures", "assets", "geo", "public"}
UNSUPPRESSIBLE = {"L000", "L014", "L015", "L031"}                        # these ids cannot be silenced with lint-ok
TABLE_ONLY = {"L004", "L016"}                                    # only the allow-list tables can permit these

SUPPRESS_RE = re.compile(r"(noqa|type:\s*ignore|pyright:\s*ignore|pylint:\s*disable|lint-ok)\b(.*)", re.I | re.S)
CODES_RE = re.compile(r"^\s*(?:\[[^\]]*\]|:\s*[A-Za-z]+\d+(?:\s*,\s*[A-Za-z]+\d+)*|=[\w,-]+)")
MARKER_RE = re.compile(r"\b(?:TODO|FIXME|XXX|HACK)\b|(?i:\bworkaround\b|\btemporar(?:y|ily)\s+(?:fix|hack|workaround|solution|patch|code|stub|shim|measure|kludge)\b)")
HOME_RE = re.compile(r"/(?:Users|home)/[A-Za-z0-9._-]+|[A-Za-z]:\\Users\\")
TMP_RE = re.compile(r"(?<![\w.:/~-])/tmp\b")
SECRET_NAME_RE = re.compile(r"token|secret|nonce|salt|passw|api_?key|csrf|uuid|session_?id|_id\b|^id$|boundary", re.I)
ESC_NAMES = ("esc", "escapeHtml", "escHtml", "escapeHTML")
# call -> number of positional arguments that already includes the timeout
NETWORK_CALLS = {"urllib.request.urlopen": 3, "socket.create_connection": 2, "requests.get": 99, "requests.post": 99,
                 "requests.put": 99, "requests.delete": 99, "requests.head": 99, "requests.request": 99,
                 "http.client.HTTPConnection": 99, "http.client.HTTPSConnection": 99}
PRIVILEGED_HELPERS = {"sudo", "pkexec", "getcap", "secret-tool", "security"}
STATE_PATH_RE = re.compile(r"(?i)(?:^|_)(?:run|stop|log|state|pid|lock|current)_?file$|^runfile$|^_?runfile$")
PRIVATE_DIR_RE = re.compile(r"settings_dir|settings_store|_state_dir|state_dir|run_?dir|XDG_RUNTIME_DIR")
AUDIT_FUNC_RE = re.compile(r"audit", re.I)
SECRET_FILE_RE = re.compile(r"(?i)\.key\b|\.pem\b|key_?log|tls-keys|\btoken|secret|passw|private")
COOKIE_OR_BEARER_RE = re.compile(r"HTTPCookieProcessor|['\"]Cookie['\"]|['\"]Authorization['\"]")
ANY_PORT_RE = re.compile(r"\(\?::\\d\{1,5\}\)")
PRIV_SHELL_RE = re.compile(r"osascript|pkexec|\bsudo\b")
REDIRECT_TAIL_RE = re.compile(r"(?:^|\s)\d?>{1,2}\s*$")
URL_FUNC_RE = re.compile(r"(?i)(?:allowed|valid|safe|ok)_?url|url_?(?:allowed|ok|valid)")
NAME_KEYS = {"id", "name", "slug", "scenario", "scenario_id", "filename", "file", "title"}
NAME_CHECKS_RE = re.compile(r"fullmatch\(|\.match\(|basename\(|realpath\(|SLUG")
REPLY_CALL_RE = re.compile(r"(?:^|\.)(?:dumps|_send|send_error|reply)$")
SECRET_CMP_RE = re.compile(r"(?i)secret|token|nonce|api_?key|passw|cookie")
AUTH_FUNC_RE = re.compile(r"(?i)^_?(?:check|verify|authori[sz]e|authenticate)\w*(?:bearer|token|cookie|session|auth)")
SUBPROCESS_RUNNERS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output"}
DYNAMIC_CALLS = {"eval", "exec", "pickle.load", "pickle.loads", "pickle.Unpickler", "marshal.load", "marshal.loads",
                 "yaml.unsafe_load", "dill.load", "dill.loads", "shelve.open"}


class Violation:
    def __init__(self, rule, path, line, detail, end=None):
        self.rule, self.path, self.line, self.detail = rule, path, line, detail
        self.end = end or line

    def __str__(self):
        name, why, fix = RULES[self.rule]
        return "%s:%d: %s %s: %s\n    why: %s\n    fix: %s" % (self.path, self.line, self.rule, name, self.detail, why, fix)


def is_shipped(path):
    return path.split("/")[0] not in NON_SHIPPED


def good_reason(text):
    text = re.sub(r"^[\s:;,.\-—–#/*]+", "", text or "").strip()
    return len(text) >= 6 and len(text.split()) >= 2


# ---------------------------------------------------------------------------------------------- python

def py_comments(src):
    out = {}
    try:
        for tok in tokenize.generate_tokens(iter(src.splitlines(True)).__next__):
            if tok.type == tokenize.COMMENT:
                out[tok.start[0]] = tok.string
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass            # the parse step reports unreadable files as L000; comment checks just see fewer lines
    return out


def check_comment(path, line, text, found):
    """L014 (reasonless suppression) and L015 (markers) for one comment, Python, JS or HTML."""
    for hash_pos in [m.end() for m in re.finditer(r"#|//|/\*|<!--", text)] or [0]:
        m = SUPPRESS_RE.match(text[hash_pos:].lstrip())
        if not m:
            continue
        kind, tail = m.group(1).lower(), m.group(2)
        if kind == "lint-ok":
            if not tail.startswith(":") or not good_reason(tail[1:]):
                found.append(Violation("L014", path, line, "'lint-ok' needs ': <reason>' (at least two words)"))
            continue
        codes = CODES_RE.match(tail)
        if kind == "noqa" and not (codes and tail.lstrip().startswith(":")):
            found.append(Violation("L014", path, line, "blanket 'noqa' without rule codes"))
        elif not good_reason(tail[codes.end():] if codes else tail):
            found.append(Violation("L014", path, line, "'%s' has no reason after it" % m.group(1)))
    if is_shipped(path) and MARKER_RE.search(text):
        found.append(Violation("L015", path, line, "unfinished-work marker in a comment: %r" % MARKER_RE.search(text).group(0)))


_STR_OPEN = re.compile(r"([rRbBuUfF]{0,2})('''|\"\"\"|'|\")")


def fstring_clash(text):
    """True when an f-string literal in `text` holds, inside a {...} expression, a backslash or its own delimiter quote.

    Scans the source text, not the AST: before Python 3.12 the nodes inside an f-string carry unreliable positions, so a
    segment-based check gave different answers on different interpreters. `text` may be several adjacent literals."""
    i, n = 0, len(text)
    while i < n:
        m = _STR_OPEN.match(text, i)
        if not m:
            i += 1
            continue
        is_f, quote = "f" in m.group(1).lower(), m.group(2)
        i = m.end()
        depth, inner = 0, None            # {...} nesting; delimiter of a string nested inside an expression
        while i < n:
            c = text[i]
            if inner:
                if text.startswith(inner, i):
                    i += len(inner)
                    inner = None
                    continue
                if c == "\\":
                    return True
            elif depth:
                if c == "\\" or text.startswith(quote, i):
                    return True           # 3.11 rejects both inside an expression
                if c in "'\"":
                    inner = text[i:i + 3] if text.startswith(c * 3, i) else c
                    i += len(inner)
                    continue
                depth += (c == "{") - (c == "}")
            else:
                if c == "\\":
                    i += 2
                    continue
                if text.startswith(quote, i):
                    i += len(quote)
                    break
                if is_f and c in "{}" and text.startswith(c * 2, i):
                    i += 2
                    continue
                if is_f and c == "{":
                    depth = 1
            i += 1
    return False


class PyChecker(ast.NodeVisitor):
    def __init__(self, path, src, tree, comments):
        self.path, self.src, self.tree, self.comments, self.found = path, src, tree, comments, []
        self.shipped = is_shipped(path)
        self.alias = {}                   # local name -> dotted canonical name
        self.modules = set()
        self.parents = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                self.parents[child] = node
            if isinstance(node, ast.Import):
                for a in node.names:
                    local = a.asname or a.name.split(".")[0]
                    self.alias[local] = a.name if a.asname else local
                    self.modules.add(local)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for a in node.names:
                    self.alias[a.asname or a.name] = node.module + "." + a.name

    def add(self, rule, node, detail):
        self.found.append(Violation(rule, self.path, node.lineno, detail, getattr(node, "end_lineno", None)))

    def name(self, node):
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return None
        parts.append(self.alias.get(node.id, node.id))
        return ".".join(reversed(parts))

    def enclosing_func(self, node):
        while node is not None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return node
            node = self.parents.get(node)
        return None

    def func_name(self, node):
        f = self.enclosing_func(node)
        return f.name if f else ""

    @staticmethod
    def kw(call, name):
        return next((k for k in call.keywords if k.arg == name), None)

    def allowed(self, table, node):
        return self.path in table or "%s::%s" % (self.path, self.func_name(node)) in table

    def visit_ExceptHandler(self, node):
        def broad(t):
            return (isinstance(t, ast.Name) and t.id in ("Exception", "BaseException")) or \
                   (isinstance(t, ast.Tuple) and any(broad(e) for e in t.elts))
        if node.type is None:
            self.add("L001", node, "bare 'except:'")
        elif broad(node.type):
            if self.shipped and node.name:
                for x in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                    if isinstance(x, ast.Call) and REPLY_CALL_RE.search(self.name(x.func) or (x.func.attr if isinstance(x.func, ast.Attribute) else "")) \
                            and any(isinstance(y, ast.Name) and y.id == node.name for a in x.args for y in ast.walk(a)):
                        self.add("L034", x, "the text of the caught exception %r goes into a reply" % node.name)
                        break
            quiet = all(isinstance(s, (ast.Pass, ast.Continue)) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
                        for s in node.body)
            stated = any(good_reason(self.comments[ln]) for ln in range(node.lineno, (node.end_lineno or node.lineno) + 1)
                         if ln in self.comments)
            if quiet and not stated:
                self.add("L002", node, "'except Exception' that only passes or continues, with no logging, re-raise or reason comment")
        self.generic_visit(node)

    def visit_Assert(self, node):
        if self.shipped and not self.func_name(node).startswith(("self_test", "_self_test")):
            self.add("L007", node, "assert in shipped code")
        self.generic_visit(node)

    def _defaults(self, node):
        for d in list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]:
            if isinstance(d, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)) or \
               (isinstance(d, ast.Call) and self.name(d.func) in ("list", "dict", "set", "bytearray", "collections.defaultdict", "collections.deque")):
                self.add("L006", d, "mutable default argument")
        self.generic_visit(node)

    def check_function(self, func):
        """L032 (http accepted without an environment switch) and L037 (a subprocess inside an authentication check)."""
        body = list(ast.walk(func))
        if URL_FUNC_RE.search(func.name) and any(isinstance(x, ast.Constant) and x.value == "http" for x in body) \
                and not any((isinstance(x, ast.Attribute) and x.attr in ("environ", "getenv")) or (isinstance(x, ast.Name) and x.id == "getenv")
                            for x in body):
            self.add("L032", func, "%s accepts plain http with no environment switch" % func.name)
        if AUTH_FUNC_RE.search(func.name):
            for x in body:
                n = self.name(x.func) if isinstance(x, ast.Call) else None
                if n and (n.startswith("subprocess.") or n in ("os.system", "keystore.load", "keystore.available")):
                    self.add("L037", x, "%s runs %s on every call" % (func.name, n))

    def visit_FunctionDef(self, node):
        if self.shipped:
            self.check_function(node)
        if not self.path.startswith("tests/") and AUDIT_FUNC_RE.search(node.name):
            self.check_audit(node)
        self._defaults(node)

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = _defaults

    def check_audit(self, func):
        """L027: an audit function that copies request values (a loop over .items() using the value, or dumping a parameter)."""
        params = {a.arg for a in func.args.args + func.args.kwonlyargs} - {"self", "verb", "status", "path", "method"}
        for node in ast.walk(func):
            if isinstance(node, (ast.For, ast.comprehension)) and isinstance(node.iter, ast.Call) \
                    and isinstance(node.iter.func, ast.Attribute) and node.iter.func.attr == "items" \
                    and isinstance(node.target, ast.Tuple) and len(node.target.elts) == 2 and isinstance(node.target.elts[1], ast.Name):
                val = node.target.elts[1].id
                scope = node if isinstance(node, ast.For) else self.parents.get(node)
                for use in ast.walk(scope):
                    par = self.parents.get(use)
                    if isinstance(use, ast.Name) and use.id == val and isinstance(use.ctx, ast.Load) and \
                            isinstance(par, (ast.Assign, ast.Dict, ast.DictComp, ast.List, ast.Tuple, ast.Subscript, ast.FormattedValue, ast.keyword)):
                        self.add("L027", use, "audit function stores the value %r of a request field" % val)
                        break
            elif isinstance(node, ast.Call) and (self.name(node.func) or "") in ("json.dumps", "str", "repr") \
                    and any(isinstance(a, ast.Name) and a.id in params for a in node.args):
                self.add("L027", node, "audit function serialises a whole request argument")

    def visit_Assign(self, node):
        for t in node.targets:
            if self.shipped and isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id in self.modules:
                self.add("L017", node, "assigns to attribute %s.%s of an imported module" % (t.value.id, t.attr))
            if self.shipped and isinstance(t, ast.Subscript) and self.name(t.value) == "sys.modules":
                self.add("L017", node, "assigns into sys.modules")
            if isinstance(t, ast.Attribute) and t.attr == "check_hostname" and isinstance(node.value, ast.Constant) and node.value.value is False:
                self.cert_off(node, "check_hostname = False")
        self.generic_visit(node)

    def cert_off(self, node, detail):
        """L031: certificate checks may be off only in a file that pins the peer's certificate instead."""
        if not (self.path in CERT_NONE_PINNED and "pins.check(" in self.src):
            self.add("L031", node, detail)

    def visit_Attribute(self, node):
        if self.name(node) == "ssl.CERT_NONE":
            self.cert_off(node, "ssl.CERT_NONE disables certificate verification")
        self.generic_visit(node)

    def visit_Constant(self, node):
        if self.shipped and isinstance(node.value, str) and ANY_PORT_RE.search(node.value) and re.search(r"localhost|127", node.value):
            self.add("L029", node, "a regex that accepts any port and does not capture it")

    def visit_For(self, node):
        if self.name(node.iter.func) == "os.walk" if isinstance(node.iter, ast.Call) else False:
            t = node.target
            body = "\n".join(ast.get_source_segment(self.src, b) or "" for b in node.body)
            if isinstance(t, ast.Tuple) and len(t.elts) == 3 and isinstance(t.elts[1], ast.Name) and "islink" in body:
                dirs_used = any(isinstance(n, ast.Name) and n.id == t.elts[1].id for b in node.body for n in ast.walk(b))
                if not dirs_used:
                    self.add("L040", node, "os.walk loop refuses symlinks among files but never looks at %s" % t.elts[1].id)
        self.generic_visit(node)

    def visit_Compare(self, node):
        if self.shipped and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            sides = [node.left, node.comparators[0]]
            if all(not isinstance(x, ast.Constant) for x in sides):
                def ident(x):
                    return x.id if isinstance(x, ast.Name) else x.attr if isinstance(x, ast.Attribute) else ""
                if any(SECRET_CMP_RE.search(ident(x)) for x in sides):
                    self.add("L036", node, "%s compared with ==" % ast.unparse(node)[:50])
        self.generic_visit(node)

    def visit_JoinedStr(self, node):
        if fstring_clash(ast.get_source_segment(self.src, node) or ""):
            self.add("L018", node, "f-string expression contains a backslash or its own quote character")
        if self.shipped and PRIV_SHELL_RE.search(self.src):
            for a, b in zip(node.values, node.values[1:]):
                if isinstance(a, ast.Constant) and isinstance(a.value, str) and isinstance(b, ast.FormattedValue) \
                        and REDIRECT_TAIL_RE.search(a.value):
                    self.add("L030", node, "shell text redirects into the variable path %s" % ast.unparse(b.value)[:30])
                    break
        self.generic_visit(node)

    def context_names(self, node):
        names = [self.func_name(node)]
        cur = node
        while cur is not None and not isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            if isinstance(cur, ast.Assign):
                names += [t.id if isinstance(t, ast.Name) else getattr(t, "attr", "") for t in cur.targets]
            elif isinstance(cur, (ast.AnnAssign, ast.AugAssign)):
                names.append(cur.target.id if isinstance(cur.target, ast.Name) else getattr(cur.target, "attr", ""))
            elif isinstance(cur, ast.keyword):
                names.append(cur.arg or "")
            if isinstance(cur, ast.stmt):
                break
            cur = self.parents.get(cur)
        return [x for x in names if x]

    def visit_Call(self, node):
        n = self.name(node.func) or ""
        if n in DYNAMIC_CALLS:
            self.add("L005", node, "call to %s" % n)
        if n == "yaml.load":
            loader = self.kw(node, "Loader")
            lv = loader.value if loader else (node.args[1] if len(node.args) > 1 else None)
            if not (lv is not None and (self.name(lv) or "").endswith(("SafeLoader", "CSafeLoader"))):
                self.add("L005", node, "yaml.load without a SafeLoader")
        if n in ("os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"):
            self.add("L003", node, "call to %s" % n)
        if n.startswith("subprocess."):
            sh = self.kw(node, "shell")
            if sh is not None and not (isinstance(sh.value, ast.Constant) and sh.value.value is False):
                self.add("L003", node, "subprocess call with shell=%s" % ast.unparse(sh.value))
        if self.shipped and n in SUBPROCESS_RUNNERS and not self.kw(node, "timeout") and not self.allowed(SUBPROCESS_TIMEOUT_ALLOW, node):
            self.add("L004", node, "%s without timeout=" % n)
        if self.shipped and n == "time.sleep" and not self.allowed(SLEEP_ALLOW, node):
            self.add("L016", node, "time.sleep")
        if self.shipped and n == "setattr" and node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in self.modules:
            self.add("L017", node, "setattr on an imported module")
        if self.shipped and not self.path.startswith("netgen/") and n.startswith("random.") and n != "random.SystemRandom":
            if n in ("random.randbytes", "random.getrandbits"):
                self.add("L008", node, "%s produces raw random bits" % n)
            elif any(SECRET_NAME_RE.search(x) for x in self.context_names(node)):
                self.add("L008", node, "%s used for something named like a secret or id" % n)
        weak = n in ("hashlib.md5", "hashlib.sha1") or (
            n == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant) and str(node.args[0].value).lower() in ("md5", "sha1"))
        if self.shipped and weak:
            ufs = self.kw(node, "usedforsecurity")
            if not (ufs is not None and isinstance(ufs.value, ast.Constant) and ufs.value.value is False):
                self.add("L009", node, "weak hash %s" % n)
        if not self.path.startswith("tests/"):           # the security rules cover tools/ too: they ship files and run as the person
            self.check_state_paths(node, n)
        if n == "tempfile.mktemp":
            self.add("L010", node, "call to %s" % n)
        if n == "ssl._create_unverified_context":
            self.cert_off(node, "call to %s" % n)
        v = self.kw(node, "verify")
        if v is not None and isinstance(v.value, ast.Constant) and v.value.value is False:
            self.cert_off(node, "verify=False")
        if not self.path.startswith("tests/"):
            self.check_secret_and_name_paths(node, n)
        if self.shipped and n in NETWORK_CALLS and not self.kw(node, "timeout") and len(node.args) < NETWORK_CALLS[n]:
            self.add("L019", node, "%s without timeout=" % n)
        if n in ("urllib.request.Request", "urllib.request.urlopen") and not COOKIE_OR_BEARER_RE.search(self.src) and re.search(r"127\.0\.0\.1|localhost", self.src) \
                and (self.kw(node, "data") or len(node.args) > 1 and not (isinstance(node.args[1], ast.Constant) and node.args[1].value is None)) \
                and not (n.endswith("urlopen") and len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and node.args[1].value is None):
            self.add("L038", node, "%s with a body in a file that never handles the session cookie" % n)
        if self.shipped and isinstance(node.func, ast.Attribute) and node.func.attr == "isdigit" and not node.args \
                and not self.path.startswith("netgen/"):          # netgen reads its own generated names, not untrusted text
            scope = self.enclosing_func(node)
            if ".isascii()" not in (ast.get_source_segment(self.src, scope) if scope else self.src):
                self.add("L039", node, "%s.isdigit() with no isascii() in the same function" % ast.unparse(node.func.value)[:30])
        if isinstance(node.func, ast.Attribute) and node.func.attr == "read":
            self.check_read(node)
        self.generic_visit(node)

    def check_secret_and_name_paths(self, node, n):
        """L028: key, key-log and token files opened with a plain open(). L033: a JSON name joined into a path unchecked."""
        args = node.args
        if n == "open" and len(args) >= 2 and isinstance(args[1], ast.Constant) and isinstance(args[1].value, str) \
                and any(c in args[1].value for c in "wax") and SECRET_FILE_RE.search(ast.unparse(args[0])):
            self.add("L028", node, "open(%s, %r) writes a key, key log or token with the default mode" % (ast.unparse(args[0])[:40], args[1].value))
        if (n.endswith(".private_bytes")):
            cur = self.parents.get(node)
            while cur is not None and not isinstance(cur, (ast.With, ast.FunctionDef, ast.Module)):
                cur = self.parents.get(cur)
            if isinstance(cur, ast.With) and any(isinstance(i.context_expr, ast.Call) and self.name(i.context_expr.func) == "open"
                                                 for i in cur.items):
                self.add("L028", node, "a private key is written through a plain open()")
        if n == "os.path.join":
            func = self.enclosing_func(node)
            checked = NAME_CHECKS_RE.search(ast.get_source_segment(self.src, func) or "") if func is not None else False
            for a in args[1:]:
                for x in ast.walk(a):
                    key = None
                    if isinstance(x, ast.Subscript) and isinstance(x.slice, ast.Constant):
                        key = x.slice.value
                    elif isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute) and x.func.attr == "get" and x.args \
                            and isinstance(x.args[0], ast.Constant):
                        key = x.args[0].value
                    if key in NAME_KEYS and not checked:
                        self.add("L033", node, "%s is joined into a path with no fullmatch check" % ast.unparse(x)[:40])
                        return

    def check_state_paths(self, node, n):
        """L023-L026: shared temp names, non-exclusive writes of state paths, folder modes, privileged helper lookups."""
        args = node.args
        if n in ("os.path.join", "pathlib.Path") and args and isinstance(args[0], ast.Call) \
                and self.name(args[0].func) == "tempfile.gettempdir" and len(args) > 1 \
                and all(isinstance(a, ast.Constant) and isinstance(a.value, str) for a in args[1:]):
            self.add("L023", node, "constant file name in the shared temp folder")
        if n == "open" and len(args) >= 2 and isinstance(args[1], ast.Constant) and isinstance(args[1].value, str) \
                and any(c in args[1].value for c in "wa") and "x" not in args[1].value and self.is_state_path(args[0]):
            self.add("L024", node, "open(%s, %r) on a state, log or predictable temp path" % (ast.unparse(args[0])[:40], args[1].value))
        if n in ("os.makedirs", "os.mkdir") and args and PRIVATE_DIR_RE.search(ast.unparse(args[0])):
            mode = self.kw(node, "mode")
            given = mode.value if mode else (args[1] if len(args) > 1 and n == "os.mkdir" else (args[1] if len(args) > 1 else None))
            if not (isinstance(given, ast.Constant) and given.value == 0o700):
                self.add("L025", node, "%s of a settings or run-state folder without mode=0o700" % n)
        helper = args[0].value if args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str) else None
        if args and isinstance(args[0], ast.Name) and args[0].id in ("SECRET_TOOL", "SECURITY"):    # the module constants
            helper = args[0].id.lower().replace("_", "-")
        if helper in PRIVILEGED_HELPERS and (n == "shutil.which" or n.split(".")[-1] == "find_tool"):
            self.add("L026", node, "%s(%r) searches PATH" % (n, helper))
        if n.startswith("subprocess.") and args and isinstance(args[0], (ast.List, ast.Tuple)) and args[0].elts \
                and isinstance(args[0].elts[0], ast.Constant) and args[0].elts[0].value in PRIVILEGED_HELPERS:
            self.add("L026", node, "%s runs %r by bare name, so PATH decides which program it is" % (n, args[0].elts[0].value))

    def is_state_path(self, arg, hops=1):
        """A path that persists or is shared: a *file name like runfile/stopfile/logfile, a '+ \".tmp\"' name, a JSON field.
        A plain name is followed one assignment back (tmp = path + '.tmp')."""
        if isinstance(arg, ast.Name):
            if STATE_PATH_RE.search(arg.id):
                return True
            return hops > 0 and any(isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == arg.id for t in n.targets)
                                    and self.is_state_path(n.value, hops - 1) for n in ast.walk(self.tree))
        if isinstance(arg, ast.Attribute):
            return bool(STATE_PATH_RE.search(arg.attr))
        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
            return isinstance(arg.right, ast.Constant) and isinstance(arg.right.value, str) and arg.right.value.endswith(".tmp")
        if isinstance(arg, ast.JoinedStr):
            last = arg.values[-1] if arg.values else None
            return isinstance(last, ast.Constant) and isinstance(last.value, str) and last.value.endswith(".tmp")
        if isinstance(arg, ast.Subscript):
            return isinstance(arg.slice, ast.Constant) and isinstance(arg.slice.value, str) and bool(STATE_PATH_RE.search(arg.slice.value))
        if isinstance(arg, ast.Call):
            return isinstance(arg.func, ast.Attribute) and arg.func.attr == "get" and bool(arg.args) \
                and isinstance(arg.args[0], ast.Constant) and isinstance(arg.args[0].value, str) and bool(STATE_PATH_RE.search(arg.args[0].value))
        return False

    def check_read(self, node):
        recv = node.func.value
        rname = self.name(recv) or ""
        sized = bool(node.args) and not isinstance(node.args[0], ast.UnaryOp)        # read(-1) is unbounded
        if self.path == "server.py" and rname.endswith("rfile"):
            func = self.enclosing_func(node)
            text = ast.dump(func) if func is not None else ""
            capped = sized and ((isinstance(node.args[0], ast.Call) and self.name(node.args[0].func) == "min") or re.search(r"CAP|MAX|LIMIT", text))
            if not capped:
                self.add("L012", node, "request body read without a size cap")
            return
        if sized or not self.shipped:
            return
        net = isinstance(recv, ast.Call) and (self.name(recv.func) or "").endswith(("urlopen", "requests.get", "requests.post")) \
            or (isinstance(recv, ast.Name) and recv.id in self.urlopen_names())
        if net or rname.endswith("rfile"):
            self.add("L013", node, "unbounded .read() on a network or request stream")

    def urlopen_names(self):
        if not hasattr(self, "_uo"):
            self._uo = set()
            for node in ast.walk(self.tree):
                pairs = []
                if isinstance(node, ast.With):
                    pairs = [(i.optional_vars, i.context_expr) for i in node.items]
                elif isinstance(node, ast.Assign):
                    pairs = [(t, node.value) for t in node.targets]
                for target, val in pairs:
                    if isinstance(target, ast.Name) and isinstance(val, ast.Call) and (self.name(val.func) or "").endswith("urlopen"):
                        self._uo.add(target.id)
        return self._uo


def docstrings(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            b = node.body
            if b and isinstance(b[0], ast.Expr) and isinstance(b[0].value, ast.Constant) and isinstance(b[0].value.value, str):
                yield b[0].value


def lint_python(src, path):
    try:
        tree = ast.parse(src, path)
    except (SyntaxError, ValueError) as e:
        return [Violation("L000", path, getattr(e, "lineno", 1) or 1, str(e))]
    comments = py_comments(src)
    chk = PyChecker(path, src, tree, comments)
    chk.visit(tree)
    found = chk.found
    shipped = is_shipped(path)
    for ln, text in comments.items():
        check_comment(path, ln, text, found)
        if shipped and HOME_RE.search(text):
            found.append(Violation("L011", path, ln, "absolute home path in a comment"))
    if shipped:
        for d in docstrings(tree):
            if MARKER_RE.search(d.value):
                found.append(Violation("L015", path, d.lineno, "unfinished-work marker in a docstring: %r" % MARKER_RE.search(d.value).group(0)))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if HOME_RE.search(node.value):
                    found.append(Violation("L011", path, node.lineno, "absolute home path in a string"))
                elif TMP_RE.search(node.value):
                    found.append(Violation("L011", path, node.lineno, "hard-coded /tmp path"))
    return suppress(found, {ln: t for ln, t in comments.items()}, src.split("\n"), "#")


def suppress(found, comments, lines, lead):
    """Drop violations covered by '<lead> lint-ok: <reason>' on their lines or alone on the line above."""
    ok = {ln for ln, t in comments.items() if re.search(r"lint-ok\s*:", t) and good_reason(t.split("lint-ok", 1)[1].lstrip(": ").rstrip("*/ >-"))}
    kept = []
    for v in found:
        if v.rule not in UNSUPPRESSIBLE and v.rule not in TABLE_ONLY:
            above = v.line - 1
            alone = above in ok and 0 < above <= len(lines) and lines[above - 1].lstrip().startswith(lead)
            if alone or any(ln in ok for ln in range(v.line, v.end + 1)):
                continue
        kept.append(v)
    return kept


# ---------------------------------------------------------------------------------------------- javascript / html

REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%<>~^") | {""}
REGEX_WORDS = {"return", "typeof", "case", "in", "of", "delete", "void", "throw"}


def js_scan(src):
    """Return (masked, comments). masked is src with comments blanked (same offsets); comments is {line: text}."""
    out, comments = [], {}
    i, n, line, last, word = 0, len(src), 1, "", ""
    while i < n:
        c, two = src[i], src[i:i + 2]
        if two == "//":
            j = src.find("\n", i)
            j = n if j < 0 else j
            comments[line] = comments.get(line, "") + src[i:j]
            out.append(" " * (j - i))
            i = j
        elif two == "/*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            seg = src[i:j]
            comments[line] = comments.get(line, "") + seg
            out.append(re.sub(r"[^\n]", " ", seg))
            line += seg.count("\n")
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:min(j + 1, n)])
            i, last, word = min(j + 1, n), c, ""
        elif c == "`":
            j = _skip_string(src, i)
            seg = src[i:j]
            out.append(seg)
            line += seg.count("\n")
            i, last, word = j, "`", ""
        elif c == "/" and (last in REGEX_PRECEDERS or word in REGEX_WORDS):
            j, incls = i + 1, False
            while j < n and src[j] != "\n":
                ch = src[j]
                if ch == "\\":
                    j += 2
                    continue
                incls = True if ch == "[" else False if ch == "]" else incls
                if ch == "/" and not incls:
                    break
                j += 1
            out.append(src[i:min(j + 1, n)])
            i, last, word = min(j + 1, n), ")", ""
        elif c.isalnum() or c in "_$":
            j = i
            while j < n and (src[j].isalnum() or src[j] in "_$"):
                j += 1
            out.append(src[i:j])
            word, last, i = src[i:j], "a", j
        else:
            out.append(c)
            if c == "\n":
                line += 1
            elif not c.isspace():
                last, word = c, ""
            i += 1
    return "".join(out), comments


def _skip_string(s, i):
    """Index just past the string literal starting at s[i] (handles escapes and template ${...})."""
    q = s[i]
    i += 1
    while i < len(s) and s[i] != q:
        if s[i] == "\\":
            i += 1
        elif q == "`" and s[i:i + 2] == "${":
            d, i = 1, i + 2
            while i < len(s) and d:
                d += (s[i] == "{") - (s[i] == "}")
                i += 1
            continue
        i += 1
    return min(i + 1, len(s))


def _split_top(expr, seps):
    """Split expr at top-level separator characters, ignoring brackets and strings."""
    parts, depth, cur, i = [], 0, [], 0
    while i < len(expr):
        c = expr[i]
        if c in "\"'`":
            j = _skip_string(expr, i)
            cur.append(expr[i:j])
            i = j
            continue
        depth += c in "([{"
        depth -= c in ")]}"
        if depth == 0 and c in seps:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def _closes_at_end(s):
    """True if the '(' implied before s is closed only by the final ')' of s."""
    d = 1
    for i, c in enumerate(re.sub(r"(['\"`])(?:\\.|(?!\1).)*\1", lambda m: "x" * len(m.group(0)), s)):
        d += (c == "(") - (c == ")")
        if d == 0:
            return i == len(s) - 1
    return False


def _safe_operand(op):
    """A JS operand is safe for innerHTML when it is a literal or a direct esc(...) call."""
    op = op.strip()
    while op.startswith("(") and op.endswith(")") and _closes_at_end(op[1:]):
        op = op[1:-1].strip()
    if not op or re.fullmatch(r"-?\d+(\.\d+)?", op):
        return True
    if op[0] in "\"'" and _skip_string(op, 0) == len(op):
        return True
    if op[0] == "`" and _skip_string(op, 0) == len(op):
        return all(_safe_operand(m) for m in re.findall(r"\$\{(.*?)\}", op[1:-1]))
    m = re.match(r"(?:[\w$]+\.)*(?:%s)\s*\(" % "|".join(ESC_NAMES), op)
    return bool(m and op.endswith(")") and _closes_at_end(op[m.end():]))


def _expression(masked, start):
    """Text of the JS expression beginning at start, ending at ';' or an unnested line end."""
    depth, i, n = 0, start, len(masked)
    while i < n:
        c = masked[i]
        if c in "\"'`":
            i = _skip_string(masked, i)
            continue
        depth += c in "([{"
        depth -= c in ")]}"
        if depth < 0 or (depth == 0 and c == ";"):
            break
        if depth == 0 and c == "\n":
            prev = masked[start:i].rstrip()[-1:]
            if prev not in "+(,?:" and not masked[i:].lstrip().startswith(("+", "?", ":", ".")):
                break
        i += 1
    return masked[start:i]


def _call_args(masked, open_paren):
    depth, i = 0, open_paren
    while i < len(masked):
        c = masked[i]
        if c in "\"'`":
            i = _skip_string(masked, i)
            continue
        depth += c == "("
        depth -= c == ")"
        if depth == 0:
            return _split_top(masked[open_paren + 1:i], ",")
        i += 1
    return []


def lint_js_text(masked, comments, path, found, line_offset=0):
    def line_of(pos):
        return masked.count("\n", 0, pos) + 1 + line_offset

    for m in re.finditer(r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)", masked):
        if not all(_safe_operand(p) for p in _split_top(_expression(masked, m.end()), "+")):
            found.append(Violation("L020", path, line_of(m.start()), "non-constant text assigned to %s" % m.group(0).strip("=+ .")))
    for m in re.finditer(r"\b(?:insertAdjacentHTML|document\.write(?:ln)?)\s*\(", masked):
        args = _call_args(masked, m.end() - 1)
        text = args[-1] if "insertAdjacentHTML" in m.group(0) else "+".join(args)
        if args and not all(_safe_operand(p) for p in _split_top(text, "+")):
            found.append(Violation("L020", path, line_of(m.start()), "non-constant text passed to %s" % m.group(0).rstrip("( ")))
    for m in re.finditer(r"\beval\s*\(|\bnew\s+Function\b|\bset(?:Timeout|Interval)\s*\(\s*['\"`]", masked):
        found.append(Violation("L021", path, line_of(m.start()), "text executed as code: %s" % m.group(0).strip()))
    rows = masked.split("\n")
    for m in re.finditer(r"_blank", masked):
        ln = masked.count("\n", 0, m.start())
        if "noopener" not in "\n".join(rows[max(0, ln - 3):ln + 4]):
            found.append(Violation("L022", path, ln + 1 + line_offset, "_blank without noopener"))
    for ln, text in comments.items():
        check_comment(path, ln + line_offset, text, found)


def _home_paths(src, path, found):
    if is_shipped(path):
        for i, row in enumerate(src.split("\n"), 1):
            if HOME_RE.search(row):
                found.append(Violation("L011", path, i, "absolute home path"))


def lint_js(src, path):
    masked, comments = js_scan(src)
    found = []
    lint_js_text(masked, comments, path, found)
    _home_paths(src, path, found)
    return suppress(found, comments, src.split("\n"), "//")


def lint_html(src, path):
    found, comments = [], {}
    for m in re.finditer(r"<script\b[^>]*>(.*?)</script>", src, re.S | re.I):
        off = src.count("\n", 0, m.start(1))
        masked, cm = js_scan(m.group(1))
        lint_js_text(masked, cm, path, found, off)
        comments.update({k + off: v for k, v in cm.items()})
    for m in re.finditer(r"<a\b[^>]*>", src, re.I):
        if re.search(r"target\s*=\s*[\"']?_blank", m.group(0)) and "noopener" not in m.group(0):
            found.append(Violation("L022", path, src.count("\n", 0, m.start()) + 1, "<a target=_blank> without rel=noopener"))
    for m in re.finditer(r"<!--(.*?)-->", src, re.S):
        ln = src.count("\n", 0, m.start()) + 1
        check_comment(path, ln, m.group(0), found)
        comments[ln] = comments.get(ln, "") + m.group(0)
    _home_paths(src, path, found)
    return suppress(found, comments, src.split("\n"), ("<!--", "//"))


PIP_RE = re.compile(r"\bpip3?\s+install\b|-m\s+pip\s+install\b")
USES_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")
FROM_RE = re.compile(r"^\s*FROM\s+(?:--\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I)
AUTOMATION_EXT = (".sh", ".command", ".yml", ".yaml")


def is_automation(path):
    base = os.path.basename(path)
    return path.endswith(AUTOMATION_EXT) or base.startswith("Dockerfile")


def lint_automation(src, path):
    """L035 in workflows, Dockerfiles and shell scripts: installs with hashes, token permissions, pinned actions and images."""
    found, lines = [], src.split("\n")
    comments = {i + 1: ln[ln.index("#"):] for i, ln in enumerate(lines) if "#" in ln}
    logical, buf, start = [], "", 0                   # a backslash continues the command on the next line
    for i, ln in enumerate(lines, 1):
        buf, start = (buf + " " + ln.strip().rstrip("\\"), start) if buf else (ln.rstrip("\\"), i)
        if not ln.rstrip().endswith("\\"):
            logical.append((start, i, buf))
            buf = ""
    for a, b, text in logical:
        code = text.split(" #")[0]
        if PIP_RE.search(code) and not code.lstrip().startswith("#") and "--require-hashes" not in code:
            found.append(Violation("L035", path, a, "pip install without --require-hashes", b))
    stages = set()
    for i, ln in enumerate(lines, 1):
        m = USES_RE.match(ln)
        if m and not m.group(1).startswith(("./", "docker://")) and not re.fullmatch(r"[^@]+@[0-9a-f]{40}", m.group(1)):
            found.append(Violation("L035", path, i, "action %s is not pinned to a commit sha" % m.group(1)))
        m = FROM_RE.match(ln) if os.path.basename(path).startswith("Dockerfile") else None
        if m:
            if m.group(1) not in stages and m.group(1).lower() != "scratch" and "@sha256:" not in m.group(1):
                found.append(Violation("L035", path, i, "base image %s is not pinned by digest" % m.group(1)))
            if m.group(2):
                stages.add(m.group(2))
    if "/workflows/" in "/" + path and not re.search(r"(?m)^\s*permissions:", src):
        found.append(Violation("L035", path, 1, "workflow without a permissions: block (the token defaults to broad access)"))
    return suppress(found, comments, lines, "#")


def lint_source(src, path):
    if is_automation(path):
        return lint_automation(src, path)
    return {".py": lint_python, ".js": lint_js, ".html": lint_html}[os.path.splitext(path)[1]](src, path)


# ---------------------------------------------------------------------------------------------- tree and ratchet

# beside the sources: the workflows and packaging recipes (and the public repository's workflow) are build inputs too
EXTRA_DIRS = ("../.github/workflows", "../packaging", "public/.github/workflows")


def iter_files(root):
    for base, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for f in sorted(files):
            if f.endswith((".py", ".js", ".html")) or is_automation(f):
                yield os.path.relpath(os.path.join(base, f), root).replace(os.sep, "/")
    for extra in EXTRA_DIRS:
        for base, dirs, files in os.walk(os.path.join(root, extra)):
            dirs[:] = sorted(dirs)
            for f in sorted(files):
                if is_automation(f) or f.endswith(".py"):
                    yield os.path.relpath(os.path.join(base, f), root).replace(os.sep, "/")


def scan(root):
    found = []
    for rel in iter_files(root):
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as fh:
            found += lint_source(fh.read(), rel)
    return found


def count(found):
    return dict(Counter((v.rule, v.path) for v in found))


def load_baseline(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)["violations"]
    return {(rule, p): n for rule, files in raw.items() for p, n in files.items()}


def save_baseline(path, counts):
    out = {}
    for (rule, p), n in sorted(counts.items()):
        out.setdefault(rule, {})[p] = n
    note = "Ratchet for tools/lint_rules.py: counts may only go down. Regenerate with --rebaseline after fixing violations."
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"note": note, "violations": out}, fh, indent=1, sort_keys=True)
        fh.write("\n")


def compare(counts, base):
    """Return (grown, shrunk): {(rule, path): (now, baseline)} for every key whose count differs."""
    grown, shrunk = {}, {}
    for key in set(counts) | set(base):
        now, was = counts.get(key, 0), base.get(key, 0)
        if now > was:
            grown[key] = (now, was)
        elif now < was:
            shrunk[key] = (now, was)
    return grown, shrunk


def rebaseline(counts, base, path, new_rules=()):
    """Write the baseline. Refuses (returns False) if any count would rise; creating a missing baseline is allowed.
    new_rules onboards a rule that has no baseline entries yet (its first recording); it can never touch an existing rule."""
    if base is not None:
        known = {rule for rule, _ in base}
        grown = {k for k in compare(counts, base)[0] if not (k[0] in new_rules and k[0] not in known)}
        if grown:
            return False
    save_baseline(path, counts)
    return True


def totals(base):
    t = Counter()
    for (rule, _), n in base.items():
        t[rule] += n
    return t


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=DEV)
    ap.add_argument("--baseline", default=BASELINE)
    ap.add_argument("--rebaseline", action="store_true", help="write current counts; refuses if any count would increase")
    ap.add_argument("--new-rule", action="append", default=[], metavar="ID",
                    help="with --rebaseline: record the first violations of a newly added rule (it must have no entries yet)")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--all", action="store_true", help="print every violation, baselined or not")
    args = ap.parse_args(argv)
    if args.list:
        for rid, (name, why, fix) in RULES.items():
            print("%s %s\n    why: %s\n    fix: %s" % (rid, name, why, fix))
        return 0
    base = load_baseline(args.baseline)
    if args.summary:
        for rule, n in sorted(totals(base or {}).items()):
            print("%s %-24s %d" % (rule, RULES[rule][0], n))
        print("total %d" % sum((base or {}).values()))
        return 0
    found = scan(args.root)
    counts = count(found)
    if args.all:
        for v in found:
            print(v)
        return 0
    if args.rebaseline:
        if not rebaseline(counts, base, args.baseline, args.new_rule):
            print("refusing to rebaseline: the baseline may never grow. These exceed it (fix them):")
            for (rule, p), (now, was) in sorted(compare(counts, base)[0].items()):
                if rule in args.new_rule and rule not in {r for r, _ in base}:
                    continue
                print("  %s %s: %d now, baseline %d" % (rule, p, now, was))
            return 1
        print("baseline written: %d violations in %d entries" % (sum(counts.values()), len(counts)))
        return 0
    if base is None:
        print("no baseline at %s: run --rebaseline once to create it" % args.baseline)
        return 1
    grown, shrunk = compare(counts, base)
    for (rule, p), (now, was) in sorted(grown.items()):
        print("FAIL %s %s: %d violations, baseline allows %d%s" % (rule, p, now, was, " (new file or rule: must be clean)" if was == 0 else ""))
        for v in found:
            if v.rule == rule and v.path == p:
                print(v)
    for (rule, p), (now, was) in sorted(shrunk.items()):
        print("FAIL %s %s: fixed down to %d but the baseline still says %d. Reduce the baseline: run tools/lint_rules.py --rebaseline" % (rule, p, now, was))
    if grown or shrunk:
        return 1
    print("lint_rules: OK (%d baselined violations)" % sum(base.values()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
