#!/usr/bin/env python3
"""Render registered diagrams to PNG files for review (developer tool).

    python3 tools/render_diagram.py NAME [NAME ...] --out DIR [--width 1400] [--company NAME] [--list]

Each diagram is rendered with make_diagram.render(), written as DIR/NAME.html, then screenshotted with a
headless Chromium-family browser at its full page height (found by a first pass that reads the document
height). Set CHROME to the browser binary if it is not one of the usual macOS locations. Prints one line per
diagram: name, pixel height, png path.
"""
import argparse
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
]
PROBE = "<script>document.title='H='+Math.ceil(document.documentElement.scrollHeight)</script>"


def browser():
    for c in [os.environ.get("CHROME")] + CANDIDATES:
        if c and os.path.exists(c):
            return c
    raise SystemExit("no Chromium-family browser found; set CHROME to its binary")


def _run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=120)


def render_png(name, out_dir, width=1400, company=None):
    import make_diagram
    html = make_diagram.render(name, company=company) if company else make_diagram.render(name)
    return _shot(html, name, out_dir, width)


def _shot(html, name, out_dir, width=1400):
    path = os.path.join(out_dir, name + ".html")
    probe = os.path.join(out_dir, name + ".probe.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    with open(probe, "w", encoding="utf-8") as f:
        f.write(html.replace("</body>", PROBE + "</body>") if "</body>" in html else html + PROBE)
    b = browser()
    base = [b, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1"]
    dom = _run(base + ["--window-size=%d,800" % width, "--dump-dom", "file://" + probe]).stdout
    m = re.search(r"<title>H=(\d+)</title>", dom)
    height = int(m.group(1)) + 20 if m else 3000
    os.remove(probe)
    png = os.path.join(out_dir, name + ".png")
    _run(base + ["--window-size=%d,%d" % (width, height), "--screenshot=" + png, "file://" + path])
    return height, png


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("names", nargs="*")
    ap.add_argument("--out", default=".")
    ap.add_argument("--width", type=int, default=1400)
    ap.add_argument("--company")
    ap.add_argument("--list", action="store_true", help="list every registered diagram name and exit")
    ap.add_argument("--html", nargs="*", default=[], help="screenshot existing HTML page files instead of registered diagrams")
    a = ap.parse_args()
    import make_diagram
    if a.list:
        for d in make_diagram.catalog(include_scenarios=True):
            print(d["name"])
        return 0
    os.makedirs(a.out, exist_ok=True)
    for path in a.html:
        name = os.path.splitext(os.path.basename(path))[0]
        with open(path, encoding="utf-8") as f:
            html = f.read()
        h, png = _shot(html, name, a.out, a.width)
        print("%-34s %5d px  %s" % (name, h, png))
    for n in a.names:
        h, png = render_png(n, a.out, a.width, a.company)
        print("%-34s %5d px  %s" % (n, h, png))
    return 0


if __name__ == "__main__":
    sys.exit(main())
