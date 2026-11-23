#!/usr/bin/env python3
"""WCAG contrast check for the colour pairs the UI actually uses.

Reads dev/ui/theme.css (the single token source), resolves every token for each theme x palette by
applying the same cascade the browser would (specificity, then file order) and following var() aliases,
then measures the real text/background pairs. Where the UI composes a colour with CSS
color-mix(in srgb, ...), the same arithmetic is done here, so the ratio is computed, not assumed.

Only pairs listed in PAIRS, NONTEXT and CSS_PAIRS are claimed (3:1 for non-text, 4.5:1 for text). Exit status is 1 when any computed pair is below its minimum
(4.5:1 for normal text, 3:1 for large text), 0 otherwise.

    python3 dev/tools/contrast_check.py            # full table
    python3 dev/tools/contrast_check.py --quiet    # only failures and the summary
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
THEME_CSS = os.path.join(os.path.dirname(HERE), "ui", "theme.css")
THEMES = ("dark", "light")
PALETTES = ("slate", "forge", "teal", "sage", "clay")


# ------------------------------------------------------------------ token resolution
def parse_rules(css):
    """[(selector, {prop: value}, order)] for every rule that sets custom properties."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    css = re.sub(r"@font-face\s*\{[^}]*\}", "", css)
    rules = []
    for i, m in enumerate(re.finditer(r"([^{}]+)\{([^{}]*)\}", css)):
        sel = " ".join(m.group(1).split())
        decls = {}
        for part in m.group(2).split(";"):
            if ":" in part:
                k, v = part.split(":", 1)
                k = k.strip()
                if k.startswith("--"):
                    decls[k] = " ".join(v.split())
        rules.append((sel, decls, i))
    return rules


def _applies(sel, theme, palette):
    if not sel.startswith(":root"):
        return None
    attrs = re.findall(r'\[data-(theme|palette)="([^"]+)"\]', sel)
    for name, val in attrs:
        if name == "theme" and val != theme:
            return None
        if name == "palette" and (palette == "slate" or val != palette):
            return None            # no attribute / slate = base rules only
    return len(attrs)


def resolve_tokens(css, theme, palette):
    """Final {--token: value} with var() chains followed (values may still hold color-mix etc.)."""
    hits = []
    for sel, decls, order in parse_rules(css):
        spec = _applies(sel, theme, palette)
        if spec is not None:
            hits.append((spec, order, decls))
    hits.sort(key=lambda h: (h[0], h[1]))
    raw = {}
    for _, _, decls in hits:
        raw.update(decls)

    def expand(val, depth=0):
        if depth > 12:
            raise ValueError("var() cycle in " + val)
        def rep(m):
            name, fallback = m.group(1), m.group(2)
            if name in raw:
                return expand(raw[name], depth + 1)
            if fallback is not None:
                return fallback.strip()
            raise KeyError(name)
        return re.sub(r"var\((--[\w-]+)(?:\s*,\s*([^)]*))?\)", rep, val)

    return {k: expand(v) for k, v in raw.items()}


# ------------------------------------------------------------------ colour maths
def hex_rgb(h):
    h = h.strip().lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def parse_color(s, over=None):
    """'#rrggbb' or 'color-mix(in srgb, A x%, B)' (opaque, sRGB, as the browser computes it)."""
    s = s.strip()
    if s.startswith("#"):
        return hex_rgb(s)
    m = re.fullmatch(r"color-mix\(in srgb,\s*(.+?)\s+([\d.]+)%\s*,\s*(.+)\)", s)
    if m:
        a, pct, b = parse_color(m.group(1)), float(m.group(2)) / 100.0, parse_color(m.group(3))
        return tuple(pct * x + (1 - pct) * y for x, y in zip(a, b))
    m = re.fullmatch(r"color-mix\(in srgb,\s*(.+?)\s*,\s*(.+)\)", s)
    if m:
        a, b = parse_color(m.group(1)), parse_color(m.group(2))
        return tuple(0.5 * x + 0.5 * y for x, y in zip(a, b))
    raise ValueError("cannot compute colour: " + s)


def _lin(c):
    c = c / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def luminance(rgb):
    r, g, b = (_lin(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(fg, bg):
    a, b = luminance(fg), luminance(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


def gradient_stops(v):
    """Hex stops of a linear-gradient(...) value."""
    return re.findall(r"#[0-9a-fA-F]{6}\b", v)


# ------------------------------------------------------------------ the pairs the UI uses
# (label, foreground expr, background expr, minimum ratio). An expr is a token name ("--ink"), a
# literal hex, or a color-mix(...) string with token names in place of colours; "{--x}" substitutes.
WHITE = "#ffffff"
PAIRS = [
    ("body ink on page", "--ink", "--bg", 4.5),
    ("body ink on card", "--ink", "--p1", 4.5),
    ("body ink on raised", "--ink", "--p2", 4.5),
    ("body ink on track", "--ink", "--p3", 4.5),
    ("muted on page", "--mu", "--bg", 4.5),
    ("muted on card", "--mu", "--p1", 4.5),
    ("muted on raised", "--mu", "--p2", 4.5),
    ("muted on track", "--mu", "--p3", 4.5),
    ("accent text on card", "--ac-tx", "--p1", 4.5),
    ("accent text on raised", "--ac-tx", "--p2", 4.5),
    ("accent text on track", "--ac-tx", "--p3", 4.5),
    ("ok text on card", "--ok", "--p1", 4.5),
    ("warn text on card", "--wr", "--p1", 4.5),
    ("error text on card", "--er", "--p1", 4.5),
    ("white on accent fill", WHITE, "--ac", 4.5),
    ("white on ok fill", WHITE, "--ok-fill", 4.5),
    ("white on error fill", WHITE, "--er-fill", 4.5),
    ("white on info fill", WHITE, "--info-fill", 4.5),
    ("white on header end", WHITE, "--hdr-b", 4.5),
    # cyan used as text (alwayson label, callout heading, ready-bar total, active icon buttons, tags)
    ("cyan text on card", "--cy-tx", "--p1", 4.5),
    ("cyan text on raised", "--cy-tx", "--p2", 4.5),
    ("cyan text on track", "--cy-tx", "--p3", 4.5),
    ("cyan text on callout tint", "--cy-tx", "color-mix(in srgb,{--cy} 8%,{--p1})", 4.5),
    # family colours as text on a card (family chips and labels)
    ("security family on card", "--c-sec", "--p1", 4.5),
    ("performance family on card", "--c-perf", "--p1", 4.5),
    ("crypto family on card", "--c-cryp", "--p1", 4.5),
    ("replay family on card", "--c-rep", "--p1", 4.5),
    ("custom family on card", "--c-cus", "--p1", 4.5),
]


# Chips and alerts are measured from the rules app.css really contains, so a change to the CSS changes
# the measurement. Each entry: (label, selector in app.css, surface the element sits on).
APP_CSS = os.path.join(os.path.dirname(HERE), "ui", "app.css")
CSS_PAIRS = [
    ("chip good text", ".chip.good,.chip.ok", "--p1"),
    ("chip warn text", ".chip.warn,.chip.wr", "--p1"),
    ("chip bad text", ".chip.bad,.chip.er", "--p1"),
    ("chip accent text", ".chip.ac", "--p1"),
    ("alert bad text on tint", ".alert.bad", "--p1"),
    ("alert warn text on tint", ".alert.warn", "--p1"),
]


def css_rule_decls(css, selector):
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", css):
        if " ".join(m.group(1).split()) == selector:
            return {k.strip(): " ".join(v.split()) for k, v in
                    (p.split(":", 1) for p in m.group(2).split(";") if ":" in p)}
    raise KeyError("no rule %r in app.css" % selector)


def css_expr(val):
    """A declared colour with var(--x) turned into {--x} so _color() can resolve it."""
    return re.sub(r"var\((--[\w-]+)\)", r"{\1}", val.replace("transparent", "{SURFACE}"))


def css_pair_rows(tokens, app_css):
    out = []
    for label, sel, surface in CSS_PAIRS:
        d = css_rule_decls(app_css, sel)
        fg = css_expr(d["color"])
        bg = css_expr(d["background"]) if "background" in d else "{--p1}"
        tk = dict(tokens)
        tk["SURFACE"] = tokens[surface]
        bgc = _color(bg.replace("{SURFACE}", tokens[surface]), tokens)
        out.append((label, ratio(_color(fg, tokens), bgc), 4.5))
    return out


# Non-text contrast (WCAG 1.4.11, >= 3:1): the border of a field against every surface it can sit on, and
# the keyboard focus ring against the page and the card.
NONTEXT = [
    ("field border on page", "--field-ln", "--bg", 3.0),
    ("field border on card", "--field-ln", "--p1", 3.0),
    ("field border on raised", "--field-ln", "--p2", 3.0),
    ("field border on track", "--field-ln", "--p3", 3.0),
    ("focus ring on page", "--cy", "--bg", 3.0),
    ("focus ring on card", "--cy", "--p1", 3.0),
    ("focus ring on raised", "--cy", "--p2", 3.0),
]


def _color(expr, tokens):
    if expr.startswith("--"):
        return parse_color(tokens[expr])
    expr = re.sub(r"\{(--[\w-]+)\}", lambda m: tokens[m.group(1)], expr)
    return parse_color(expr)


def measure(css=None):
    """[(theme, palette, label, ratio, minimum)] for every pair x theme x palette, plus the primary
    button face (white text on each gradient stop; the worst stop is reported)."""
    if css is None:
        with open(THEME_CSS, encoding="utf-8") as fh:
            css = fh.read()
    out = []
    for theme in THEMES:
        for pal in PALETTES:
            tk = resolve_tokens(css, theme, pal)
            for label, fg, bg, mn in PAIRS + NONTEXT:
                out.append((theme, pal, label, ratio(_color(fg, tk), _color(bg, tk)), mn))
            with open(APP_CSS, encoding="utf-8") as fh:
                for label, r, mn in css_pair_rows(tk, fh.read()):
                    out.append((theme, pal, label + " (from app.css)", r, mn))
            stops = gradient_stops(tk["--face"])
            worst = min(ratio(hex_rgb(WHITE), hex_rgb(s)) for s in stops)
            out.append((theme, pal, "white on button face", worst, 4.5))
    return out


def main(argv):
    quiet = "--quiet" in argv
    rows = measure()
    fails = [r for r in rows if r[3] < r[4]]
    if not quiet:
        print("%-6s %-6s %-30s %7s %5s" % ("theme", "pal", "pair", "ratio", "min"))
    for theme, pal, label, r, mn in rows:
        if quiet and r >= mn:
            continue
        print("%-6s %-6s %-30s %7.2f %5.1f%s" % (theme, pal, label, r, mn, "  FAIL" if r < mn else ""))
    print("%d pairs computed (%d themes x %d palettes), %d below minimum"
          % (len(rows), len(THEMES), len(PALETTES), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
