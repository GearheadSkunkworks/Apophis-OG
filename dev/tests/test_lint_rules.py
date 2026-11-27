"""Tests for tools/lint_rules.py: every rule fails on a violating snippet and passes a clean one, suppressions need a
reason, allow-list tables work, and the baseline ratchet only moves down."""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))
import lint_rules as L  # noqa: E402 - the tools directory is added to the path on the line above


def ids(src, path="mod.py"):
    return sorted({v.rule for v in L.lint_source(src, path)})


# rule -> (violating snippet, clean snippet, path). The L011 sample path is split so the neutrality scan ignores it.
CASES = {
    "L001": ("try:\n    f()\nexcept:\n    raise\n", "try:\n    f()\nexcept ValueError:\n    raise\n", "mod.py"),
    "L002": ("try:\n    f()\nexcept Exception:\n    pass\n", "try:\n    f()\nexcept Exception:\n    log(1)\n", "mod.py"),
    "L003": ("import subprocess\nsubprocess.run('ls', shell=True, timeout=5)\n",
             "import subprocess\nsubprocess.run(['ls'], timeout=5)\n", "mod.py"),
    "L004": ("import subprocess\nsubprocess.run(['ls'])\n", "import subprocess\nsubprocess.run(['ls'], timeout=5)\n", "mod.py"),
    "L005": ("x = eval(s)\n", "import ast\nx = ast.literal_eval(s)\n", "mod.py"),
    "L006": ("def f(a=[]):\n    return a\n", "def f(a=None):\n    return a or []\n", "mod.py"),
    "L007": ("def f(x):\n    assert x > 0\n", "def f(x):\n    if x <= 0:\n        raise ValueError(x)\n", "mod.py"),
    "L008": ("import random\ntoken = random.choice('abc')\n", "import secrets\ntoken = secrets.token_hex(8)\n", "mod.py"),
    "L009": ("import hashlib\nhashlib.md5(b'x')\n", "import hashlib\nhashlib.sha256(b'x')\n", "mod.py"),
    "L010": ("import tempfile\np = tempfile.mktemp()\n", "import tempfile\np = tempfile.mkstemp()\n", "mod.py"),
    "L011": ("P = '/Us' 'ers/someone/data'\n", "import os\nP = os.path.expanduser('~/data')\n", "mod.py"),
    "L012": ("class H:\n    def post(self):\n        return self.rfile.read(int(self.headers['Content-Length']))\n",
             "MAX_BODY = 10\nclass H:\n    def post(self, n):\n        if n > MAX_BODY:\n            return None\n        return self.rfile.read(n)\n",
             "server.py"),
    "L013": ("import urllib.request\nwith urllib.request.urlopen(u, timeout=5) as r:\n    d = r.read()\n",
             "import urllib.request\nwith urllib.request.urlopen(u, timeout=5) as r:\n    d = r.read(1000)\n", "mod.py"),
    "L014": ("x = 1  # noqa\n", "x = 1  # noqa: E501 - long URL kept on one line\n", "mod.py"),
    "L015": ("x = 1  # TODO later\n", "x = 1  # tracked elsewhere\n", "mod.py"),
    "L016": ("import time\ntime.sleep(1)\n", "import threading\nthreading.Event().wait(1)\n", "mod.py"),
    "L017": ("import socket\nsocket.socket = Fake\n", "import socket\nlocal = Fake\n", "mod.py"),
    "L018": ("x = f'{\"a\\n\".join([])}'\n", "j = '\\n'.join([])\nx = f'{j}'\n", "mod.py"),
    "L019": ("import urllib.request\nurllib.request.urlopen(u)\n",
             "import urllib.request\nurllib.request.urlopen(u, timeout=5)\n", "mod.py"),
    "L020": ("el.innerHTML = '<b>' + name + '</b>';\n", "el.innerHTML = '<b>' + esc(name) + '</b>';\n", "ui/a.js"),
    "L021": ("eval(code);\n", "JSON.parse(code);\n", "ui/a.js"),
    "L022": ("window.open(u, '_blank');\n", "window.open(u, '_blank', 'noopener');\n", "ui/a.js"),
    "L023": ("import os, tempfile\nP = os.path.join(tempfile.gettempdir(), 'app-run.json')\n",
             "import os, tempfile\nP = os.path.join(tempfile.mkdtemp(), 'app-run.json')\n", "mod.py"),
    "L024": ("def f(runfile):\n    open(runfile, 'w').close()\n",
             "import os\ndef f(runfile):\n    os.close(os.open(runfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600))\n", "mod.py"),
    "L025": ("import os\nos.makedirs(settings_dir(), exist_ok=True)\n",
             "import os\nos.makedirs(settings_dir(), mode=0o700, exist_ok=True)\n", "mod.py"),
    "L026": ("import shutil\nsudo = shutil.which('sudo')\n",
             "import shutil\nsudo = system_tool('sudo')\nbrew = shutil.which('brew')\n", "mod.py"),
    "L027": ("def audit(verb, status, body):\n    args = {}\n    for k, v in body.items():\n        args[k] = v\n    return args\n",
             "def audit(verb, status, body):\n    return sorted(body)\n", "mod.py"),
    "L028": ("def f(p):\n    open(p + '.key', 'wb')\n", "def f(p):\n    open_private(p + '.key')\n", "mod.py"),
    "L029": ("import re\nR = re.compile(r'^(?:localhost)(?::\\d{1,5})?$')\n",
             "import re\nR = re.compile(r'^(?:localhost)(?::(\\d{1,5}))?$')\n", "mod.py"),
    "L030": ("def f(log):\n    s = f'run > {log}'\n    return 'osascript' + s\n",
             "def f(log):\n    s = f'run {log}'\n    return 'osascript' + s\n", "mod.py"),
    "L031": ("import ssl\nc = ssl.create_default_context()\nc.check_hostname = False\n",
             "import ssl\nc = ssl.create_default_context()\nc.check_hostname = False\npins.check(s, h)\n",
             "sensorops/providers/network_sensor.py"),
    "L032": ("def allowed_url(p):\n    return p.scheme == 'http'\n",
             "import os\ndef allowed_url(p):\n    return p.scheme == 'http' and bool(os.environ.get('OG_UPDATE_URL'))\n", "mod.py"),
    "L033": ("import os\ndef f(base, m):\n    return os.path.join(base, m['id'] + '.json')\n",
             "import os, re\ndef f(base, m):\n    if not re.fullmatch(r'[a-z]+', m['id']):\n        raise ValueError\n    return os.path.join(base, m['id'])\n",
             "mod.py"),
    "L034": ("import json\ntry:\n    f()\nexcept Exception as e:\n    reply = json.dumps({'error': str(e)})\n",
             "import json\ntry:\n    f()\nexcept Exception as e:\n    log(e)\n    reply = json.dumps({'error': 'failed'})\n", "mod.py"),
    "L035": ("steps:\n  - run: pip install cryptography\n",
             "permissions:\n  contents: read\nsteps:\n  - uses: actions/checkout@" + "a" * 40 + "  # v4\n"
             "  - run: pip install --require-hashes -r requirements.lock\n", ".github/workflows/ci.yml"),
    "L036": ("def f(supplied, UI_SECRET):\n    return supplied == UI_SECRET\n",
             "import hmac\ndef f(supplied, UI_SECRET):\n    return hmac.compare_digest(supplied.encode(), UI_SECRET.encode())\n", "mod.py"),
    "L038": ("import urllib.request\nr = urllib.request.Request('http://127.0.0.1:1/api', data=b'{}')\n",
             "import urllib.request, http.cookiejar\nop = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))\nr = urllib.request.Request('http://127.0.0.1:1/api', data=b'{}')\n", "pin.py"),
    "L039": ("def f(s):\n    return int(s) if s.isdigit() else 0\n",
             "def f(s):\n    return int(s) if s.isascii() and s.isdigit() else 0\n", "mod.py"),
    "L040": ("import os\ndef f(t):\n    for d, _dirs, files in os.walk(t):\n        for n in files:\n            if os.path.islink(os.path.join(d, n)):\n                raise ValueError(n)\n",
             "import os\ndef f(t):\n    for d, dirs, files in os.walk(t):\n        for n in files + dirs:\n            if os.path.islink(os.path.join(d, n)):\n                raise ValueError(n)\n", "mod.py"),
    "L037": ("import subprocess\ndef check_bearer(h):\n    return subprocess.run(['security'], timeout=3)\n",
             "def check_bearer(h):\n    return h == CACHED\n", "mod.py"),
}


class RuleTests(unittest.TestCase):
    def test_every_rule_has_a_case(self):
        self.assertEqual(set(CASES) | {"L000"}, set(L.RULES))

    def test_violating_fails_and_clean_passes(self):
        for rule, (bad, good, path) in CASES.items():
            with self.subTest(rule=rule):
                if rule == "L018" and sys.version_info < (3, 12):
                    continue    # this interpreter cannot parse the violating snippet; test_fstring_clash_scanner covers it
                self.assertIn(rule, ids(bad, path))
                self.assertNotIn(rule, ids(good, path))

    def test_new_security_rules_are_precise(self):
        self.assertNotIn("L023", ids("import os, tempfile\nP = os.path.join(tempfile.gettempdir(), name)\n"))
        self.assertNotIn("L023", ids("import os, tempfile\nP = os.path.join(tempfile.gettempdir(), 'a')\n", "tests/t.py"))
        self.assertIn("L024", ids("open(path + '.tmp', 'w')\n"))
        self.assertIn("L024", ids("def f(info):\n    open(info.get('stopfile'), 'w').close()\n"))
        self.assertIn("L024", ids("tmp = out + '.tmp'\nwith open(tmp, 'wb') as f:\n    pass\n"))
        self.assertNotIn("L024", ids("tmp = out + '.json'\nwith open(tmp, 'wb') as f:\n    pass\n"))
        self.assertNotIn("L024", ids("open(path, 'w')\nopen(runfile, 'r')\nopen(logfile, 'x')\n"))
        self.assertNotIn("L025", ids("import os\nos.makedirs(out_dir, exist_ok=True)\n"))
        self.assertIn("L025", ids("import os\nos.makedirs(os.path.join(settings_dir(), 'run'), mode=0o755)\n"))
        self.assertIn("L026", ids("import subprocess\nsubprocess.run(['pkexec', 'x'], timeout=5)\n"))
        self.assertNotIn("L026", ids("import subprocess\nsubprocess.run(['/usr/bin/pkexec', 'x'], timeout=5)\n"))
        self.assertIn("L026", ids("import shutil\nshutil.which(SECRET_TOOL)\n"))
        self.assertNotIn("L027", ids("def audit(verb, status, body):\n    return {k: type(v).__name__ for k, v in body.items()}\n"))
        self.assertIn("L027", ids("import json\ndef audit(verb, status, body):\n    return json.dumps(body)\n"))

    def test_review_rules_are_precise(self):
        self.assertIn("L028", ids("def f(d):\n    with open(d + '/k.pem', 'w') as fh:\n        fh.write(x)\n"))
        self.assertIn("L028", ids("def f(key, path):\n    with open(path, 'wb') as fh:\n        fh.write(key.private_bytes(1, 2, 3))\n"))
        self.assertNotIn("L028", ids("open(path + '.key', 'rb')\nopen('notes.txt', 'w')\n"))
        self.assertNotIn("L028", ids("open(path + '.key', 'wb')\n", "tests/t.py"))
        self.assertNotIn("L029", ids("import re\nR = re.compile(r'^[a-z]+(?::\\d{1,5})?$')\n"))      # a sensor address, not a loopback guard
        self.assertNotIn("L030", ids("def f(a, b):\n    return f'{a} > {b}'\n"))                      # no privileged launcher in the file
        self.assertNotIn("L030", ids("def f(x):\n    return ('osascript', f'<b>{x}</b>', f'a -> {x}')\n"))
        self.assertIn("L031", ids("import ssl\nc = ssl.SSLContext()\nc.verify_mode = ssl.CERT_NONE\n", "sensorops/providers/network_sensor.py"))
        self.assertIn("L031", ids("import ssl\nc = ssl.SSLContext()\nc.verify_mode = ssl.CERT_NONE\npins.check(s, h)\n", "other.py"))
        self.assertIn("L031", ids("x = 1  # lint-ok: because\nimport ssl\nc = ssl.SSLContext()\nc.verify_mode = ssl.CERT_NONE  # lint-ok: needed here\n"))
        self.assertNotIn("L032", ids("def allowed_url(p):\n    return p.scheme == 'https'\n"))
        self.assertNotIn("L032", ids("def other(p):\n    return p.scheme == 'http'\n"))
        self.assertNotIn("L033", ids("import os\ndef f(base, m):\n    return os.path.join(base, os.path.basename(m['name']))\n"))
        self.assertNotIn("L033", ids("import os\ndef f(base, m):\n    return os.path.join(base, m['count'])\n"))
        self.assertNotIn("L034", ids("import json\ntry:\n    f()\nexcept OSError as e:\n    r = json.dumps({'e': str(e)})\n"))
        self.assertIn("L034", ids("def h(self):\n    try:\n        f()\n    except Exception as e:\n        return self._send(500, str(e))\n"))
        sha = "a" * 40
        self.assertIn("L035", ids("jobs:\n  - uses: actions/checkout@v4\n", ".github/workflows/c.yml"))
        self.assertIn("L035", ids("permissions: {}\n  - uses: a/b@" + sha + "\n  - run: python -m pip install --upgrade pip\n", ".github/workflows/c.yml"))
        self.assertIn("L035", ids("FROM python:3.12\nRUN pip install --require-hashes -r r.lock\n", "Dockerfile"))
        self.assertIn("L035", ids("RUN pip install \\\n    -r r.txt\n", "Dockerfile"))
        self.assertNotIn("L035", ids("FROM python@sha256:" + "b" * 64 + " AS base\nFROM base\nRUN pip install --require-hashes \\\n  -r r.lock\n", "Dockerfile"))
        self.assertNotIn("L035", ids("pip install x  # lint-ok: the person's own machine, after a prompt\n", "run.sh"))
        self.assertNotIn("L035", ids("echo 'pip is nice'\n", "run.sh"))
        self.assertIn("L036", ids("def f(self, v):\n    return v != self.api_key\n"))
        self.assertNotIn("L036", ids("def f(token):\n    return token == ''\n"))
        self.assertNotIn("L036", ids("def f(a, b):\n    return a == b\n"))
        self.assertIn("L037", ids("import keystore\ndef verify_session_cookie(c):\n    return keystore.load('x') == c\n"))
        self.assertNotIn("L037", ids("import subprocess\ndef build(c):\n    return subprocess.run(['x'], timeout=3)\n"))

    def test_the_certificate_rule_cannot_be_silenced(self):
        self.assertIn("L031", L.UNSUPPRESSIBLE)

    def test_syntax_error(self):
        self.assertEqual(ids("def (:\n"), ["L000"])

    def test_messages_carry_why_and_fix(self):
        for rid, (name, why, fix) in L.RULES.items():
            self.assertTrue(name and why and fix, rid)
        text = str(L.lint_source("def f(a=[]):\n    pass\n", "mod.py")[0])
        self.assertIn("why:", text)
        self.assertIn("fix:", text)

    def test_variants(self):
        self.assertIn("L003", ids("import os\nos.system('ls')\n"))
        self.assertIn("L003", ids("import os\nos.popen('ls')\n"))
        self.assertIn("L005", ids("import pickle\npickle.loads(b)\n"))
        self.assertIn("L005", ids("import yaml\nyaml.load(s)\n"))
        self.assertNotIn("L005", ids("import yaml\nyaml.load(s, Loader=yaml.SafeLoader)\n"))
        self.assertIn("L002", ids("for i in x:\n    try:\n        f()\n    except Exception:\n        continue\n"))
        self.assertNotIn("L002", ids("try:\n    f()\nexcept OSError:\n    pass\n"))
        self.assertNotIn("L002", ids("try:\n    f()\nexcept Exception:\n    raise\n"))
        self.assertIn("L031", ids("import requests\nrequests.get(u, verify=False, timeout=3)\n"))
        self.assertIn("L031", ids("import ssl\nc = ssl._create_unverified_context()\n"))
        self.assertIn("L011", ids("p = '/tmp/x'\n"))
        self.assertIn("L012", ids("class H:\n    def p(self):\n        return self.rfile.read()\n", "server.py"))
        self.assertNotIn("L012", ids("class H:\n    def p(self):\n        return self.rfile.read()\n", "other.py"))
        self.assertIn("L008", ids("import random\nb = random.getrandbits(64)\n"))
        self.assertNotIn("L008", ids("import random\nx = random.choice([1, 2])\n"))
        self.assertIn("L009", ids("import hashlib\nhashlib.new('sha1')\n"))
        self.assertIn("L020", ids("el.insertAdjacentHTML('beforeend', html);\n", "ui/a.js"))
        self.assertIn("L020", ids("document.write(x);\n", "ui/a.js"))
        self.assertIn("L021", ids("new Function('return 1');\n", "ui/a.js"))
        self.assertIn("L021", ids("setTimeout('go()', 5);\n", "ui/a.js"))
        self.assertIn("L022", ids('<a href="u" target="_blank">x</a>\n', "ui/a.html"))
        self.assertNotIn("L022", ids('<a href="u" target="_blank" rel="noopener">x</a>\n', "ui/a.html"))
        self.assertIn("L020", ids("<script>\nel.innerHTML = a + b;\n</script>\n", "ui/a.html"))

    def test_js_constant_and_escaped_are_clean(self):
        for ok in ("el.innerHTML = '';", "el.innerHTML = `<i>${esc(x)}</i>`;", "el.innerHTML = '<b>' + OGC.esc(a) + '</b>' + 'x';",
                   "el.textContent = name + other;"):
            self.assertEqual(ids(ok + "\n", "ui/a.js"), [], ok)
        self.assertIn("L020", ids("el.innerHTML = `<i>${name}</i>`;\n", "ui/a.js"))
        # a // inside a string is not a comment; a regex literal holding a quote does not derail the scanner
        self.assertEqual(ids("var u = 'http://x/y'; var r = /[\"']/g;\nel.innerHTML = esc(u);\n", "ui/a.js"), [])

    def test_triple_quoted_fstring_may_hold_single_quotes(self):
        self.assertNotIn("L018", ids("x = f'''{d['k']}'''\n"))

    def test_fstring_clash_scanner_is_text_based(self):
        # same answers on every interpreter: these cases drove false positives when positions came from the AST
        clean = ['f"{x!r}"', 'f"{d[\'k\']}"', "f'{d[\"k\"]}'", 'f"{{a}} {x}"', 'f"{d[\'}\']}"', '"a" f"{x}"', 'f"{t.get(\'id\')!r} x"',
                 '"a\\\\n" f"{x}"']
        for s in clean:
            self.assertFalse(L.fstring_clash(s), s)
        for s in ['f"{d["k"]}"', 'f"{\'a\\n\'.join(x)}"', "f'{x}' f'{d['k']}'"]:
            self.assertTrue(L.fstring_clash(s), s)


class ScopeTests(unittest.TestCase):
    def test_tests_and_tools_are_exempt_from_shipped_only_rules(self):
        for path in ("tests/test_x.py", "tools/x.py", "checks/x.py"):
            self.assertEqual(ids("import time\nx = 1  # TODO\nassert x\ntime.sleep(1)\nP = '/tmp/x'\n", path), [], path)

    def test_everywhere_rules_apply_to_tests(self):
        self.assertIn("L001", ids("try:\n    f()\nexcept:\n    pass\n", "tests/test_x.py"))
        self.assertIn("L003", ids("import os\nos.system('x')\n", "tests/test_x.py"))

    def test_netgen_may_use_seeded_random(self):
        self.assertEqual(ids("import random\nsession_id = random.random()\n", "netgen/x.py"), [])
        self.assertIn("L008", ids("import random\nsession_id = random.random()\n", "other.py"))

    def test_self_test_functions_may_assert(self):
        self.assertEqual(ids("def self_test():\n    assert 1\n"), [])


class AllowListTests(unittest.TestCase):
    def test_subprocess_and_sleep_allow_tables(self):
        src = "import subprocess, time\ndef run():\n    subprocess.run(['x'])\n    time.sleep(1)\n"
        self.assertEqual(ids(src, "allowed.py"), ["L004", "L016"])
        L.SUBPROCESS_TIMEOUT_ALLOW["allowed.py::run"] = "test entry: the child is long-running"
        L.SLEEP_ALLOW["allowed.py"] = "test entry: polling loop"
        try:
            self.assertEqual(ids(src, "allowed.py"), [])
        finally:
            del L.SUBPROCESS_TIMEOUT_ALLOW["allowed.py::run"]
            del L.SLEEP_ALLOW["allowed.py"]

    def test_every_allow_entry_has_a_reason_and_names_real_code(self):
        for table in (L.SUBPROCESS_TIMEOUT_ALLOW, L.SLEEP_ALLOW):
            for key, why in table.items():
                self.assertTrue(L.good_reason(why), key)
                path, _, func = key.partition("::")
                with open(os.path.join(L.DEV, path), encoding="utf-8") as fh:
                    self.assertTrue(not func or ("def %s(" % func) in fh.read(), "stale allow-list entry: " + key)

    def test_usedforsecurity_false_allows_md5(self):
        self.assertEqual(ids("import hashlib\nhashlib.md5(b'x', usedforsecurity=False)\n"), [])


class SuppressionTests(unittest.TestCase):
    def test_lint_ok_with_reason_silences(self):
        self.assertEqual(ids("import hashlib\nhashlib.md5(b'x')  # lint-ok: legacy cache key, not security\n"), [])
        self.assertEqual(ids("import hashlib\n# lint-ok: legacy cache key, not security\nhashlib.md5(b'x')\n"), [])
        self.assertEqual(ids("el.innerHTML = a + b;  // lint-ok: markup built from a trusted constant\n", "ui/a.js"), [])
        # inline page scripts use slash-slash comments, so a suppression on the line above covers them too
        self.assertEqual(ids("<script>\n// lint-ok: markup built from a trusted constant\nel.innerHTML = a + b;\n</script>\n", "ui/a.html"), [])
        self.assertIn("L020", ids("<script>\nel.innerHTML = a + b;\n</script>\n", "ui/a.html"))

    def test_lint_ok_without_reason_fails_and_does_not_silence(self):
        for src in ("import hashlib\nhashlib.md5(b'x')  # lint-ok\n", "import hashlib\nhashlib.md5(b'x')  # lint-ok: ok\n"):
            self.assertEqual(ids(src), ["L009", "L014"], src)
        self.assertIn("L014", ids("el.innerHTML = '';  // lint-ok\n", "ui/a.js"))

    def test_lint_ok_on_previous_code_line_does_not_leak(self):
        src = "import hashlib\nx = 1  # lint-ok: reason for the first line only\nhashlib.md5(b'x')\n"
        self.assertIn("L009", ids(src))

    def test_noqa_and_type_ignore_need_codes_and_reasons(self):
        for bad in ("x = 1  # noqa\n", "x = 1  # noqa: E501\n", "x = 1  # type: ignore\n", "x = 1  # type: ignore[attr-defined]\n"):
            self.assertIn("L014", ids(bad), bad)
        self.assertEqual(ids("x = 1  # type: ignore[attr-defined] - stub lacks the attribute\n"), [])
        self.assertEqual(ids("x = 1  # noqa: E501 - long URL\n"), [])

    def test_unsuppressible_rules(self):
        self.assertIn("L015", ids("x = 1  # TODO: finish  lint-ok: because I said so\n"))
        self.assertIn("L004", ids("import subprocess\nsubprocess.run(['x'])  # lint-ok: long running child process\n"))

    def test_swallowed_exception_with_reason_comment_passes(self):
        self.assertEqual(ids("try:\n    f()\nexcept Exception:\n    pass   # best effort: the cache is optional\n"), [])
        self.assertEqual(ids("try:\n    f()\nexcept Exception:\n    # best effort: the cache is optional\n    pass\n"), [])
        self.assertIn("L002", ids("try:\n    f()\nexcept Exception:\n    pass  # ok\n"))

    def test_markers(self):
        for word in ("FIXME", "XXX", "HACK", "workaround", "temporary fix"):
            self.assertIn("L015", ids("x = 1  # %s here\n" % word), word)
        self.assertIn("L015", ids('def f():\n    """TODO: write"""\n'))
        self.assertNotIn("L015", ids("x = 1  # temporary directory for builds\n"))


class RatchetTests(unittest.TestCase):
    BAD = "def f(a=[]):\n    return a\n"
    BAD2 = "def f(a=[], b={}):\n    return a\n"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.src = os.path.join(tmp.name, "src")
        os.makedirs(self.src)
        self.base = os.path.join(tmp.name, "baseline.json")

    def write(self, rel, text):
        with open(os.path.join(self.src, rel), "w", encoding="utf-8") as fh:
            fh.write(text)

    def run_main(self, *extra):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = L.main(["--root", self.src, "--baseline", self.base, *extra])
        return code, buf.getvalue()

    def test_missing_baseline_fails_then_bootstrap_creates_it(self):
        self.write("a.py", self.BAD)
        self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(self.run_main("--rebaseline")[0], 0)
        self.assertEqual(self.run_main()[0], 0)

    def test_growth_fails(self):
        self.write("a.py", self.BAD)
        self.run_main("--rebaseline")
        self.write("a.py", self.BAD2)
        code, out = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("baseline allows 1", out)

    def test_new_file_must_be_clean(self):
        self.write("a.py", self.BAD)
        self.run_main("--rebaseline")
        self.write("b.py", self.BAD)
        code, out = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("new file", out)

    def test_fixed_violation_requires_baseline_reduction(self):
        self.write("a.py", self.BAD2)
        self.run_main("--rebaseline")
        self.write("a.py", self.BAD)
        code, out = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("Reduce the baseline", out)
        self.assertEqual(self.run_main("--rebaseline")[0], 0)
        self.assertEqual(self.run_main()[0], 0)

    def test_fully_fixed_file_entry_must_go(self):
        self.write("a.py", self.BAD)
        self.run_main("--rebaseline")
        self.write("a.py", "x = 1\n")
        self.assertEqual(self.run_main()[0], 1)
        self.run_main("--rebaseline")
        with open(self.base, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["violations"], {})

    def test_rebaseline_cannot_increase(self):
        self.write("a.py", self.BAD)
        self.run_main("--rebaseline")
        with open(self.base, encoding="utf-8") as fh:
            before = fh.read()
        self.write("a.py", self.BAD2)
        self.write("b.py", self.BAD)
        code, out = self.run_main("--rebaseline")
        self.assertEqual(code, 1)
        self.assertIn("never grow", out)
        with open(self.base, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), before)

    def test_new_rule_can_be_onboarded_but_existing_rule_cannot_grow(self):
        self.write("a.py", "def f():\n    try:\n        g()\n    except:\n        pass\n")      # L001 only
        self.run_main("--rebaseline")
        self.write("b.py", self.BAD)                                                          # L006, a rule with no entries
        self.assertEqual(self.run_main("--rebaseline")[0], 1)
        self.assertEqual(self.run_main("--rebaseline", "--new-rule", "L006")[0], 0)
        self.write("c.py", self.BAD)                                                          # L006 now has entries: no growth
        self.assertEqual(self.run_main("--rebaseline", "--new-rule", "L006")[0], 1)

    def test_committed_baseline_matches_tree(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(L.main([]), 0)


if __name__ == "__main__":
    unittest.main()
