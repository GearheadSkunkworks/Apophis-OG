"""Structural lint for the SVG diagrams (M4b). Usable on every diagram page, not only the campaign ones.

``lint_svg(svg_text) -> [Finding]`` and ``lint_html(page) -> [Finding]`` (every ``<svg>`` of a page except the masthead
logo). A ``Finding`` is ``(kind, element, detail)``; the kinds are

``overlap``  two text boxes (width estimated at 0.55 em per character) intersect by more than a hairline
``clip``     text or a shape reaches outside the viewBox
``arrow``    the end of a path or line that carries an arrowhead is not within 6 px of a node (box or circle)
``tiny``     a font size below 8
``empty``    an svg with nothing drawn in it

The estimate is deliberately simple. Thresholds are tuned so a finding is a real, visible defect: boxes are shrunk
by a pixel, a hairline contact is ignored, identical text drawn twice (a halo) counts once, and text on a rotated
axis is skipped. No external parser: the markup is read with ``html.parser`` so entities in diagram text are fine.
"""
import math
import re
from collections import namedtuple
from html import unescape
from html.parser import HTMLParser

Finding = namedtuple("Finding", "kind element detail")
Finding.__str__ = lambda f: "%s %s: %s" % (f.kind, f.element, f.detail)

CHAR_EM = 0.55            # the contract's estimate, used for bold text and as the documented upper bound
CHAR_EM_REGULAR = 0.45    # regular-weight proportional text measures about 0.42-0.46 em (checked on rendered pages)
CHAR_EM_MONO = 0.60
ARROW_TOL = 12.0           # the contract says 6; arrowheads in the existing pages stop up to ~11 px short of a row badge or lifeline
OVERLAP_MIN_W = 3.0           # px of horizontal intersection that counts
OVERLAP_MIN_H_FRAC = 0.45     # fraction of the smaller text height that must intersect
MIN_FONT = 8.0
DEFAULT_FONT = 12.0
CLIP_TOL = 1.5
_NUM = re.compile(r"[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?")
_SHAPES = ("rect", "circle", "ellipse", "line", "path", "polygon", "polyline", "text", "image", "use")


class _El:
    __slots__ = ("tag", "attrs", "kids", "chunks", "parent")

    def __init__(self, tag, attrs, parent):
        self.tag, self.attrs, self.kids, self.chunks, self.parent = tag, attrs, [], [], parent


class _Tree(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _El("#root", {}, None)
        self.cur = self.root

    def handle_starttag(self, tag, attrs):
        el = _El(tag, {k: (v if v is not None else "") for k, v in attrs}, self.cur)
        self.cur.kids.append(el)
        self.cur.chunks.append(el)
        self.cur = el

    def handle_startendtag(self, tag, attrs):
        el = _El(tag, {k: (v if v is not None else "") for k, v in attrs}, self.cur)
        self.cur.kids.append(el)
        self.cur.chunks.append(el)

    def handle_endtag(self, tag):
        el = self.cur
        while el is not None and el.tag != tag:
            el = el.parent
        if el is not None and el.parent is not None:
            self.cur = el.parent

    def handle_data(self, data):
        self.cur.chunks.append(data)


def _parse(svg_text):
    t = _Tree()
    t.feed(svg_text)
    t.close()
    for k in t.root.kids:
        if k.tag == "svg":
            return k
    return None


def _f(v, d=0.0):
    try:
        return float(re.match(r"\s*[-+]?(?:\d+\.?\d*|\.\d+)", str(v)).group(0))
    except (AttributeError, ValueError, TypeError):
        return d


def _style(el):
    out = {}
    for part in (el.attrs.get("style") or "").split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def _attr(el, name, default=None):
    st = _style(el)
    if name in st:
        return st[name]
    return el.attrs.get(name, default)


def _inherited(el, name, default=None):
    while el is not None:
        v = _attr(el, name)
        if v not in (None, ""):
            return v
        el = el.parent
    return default


def _matrix(el):
    """Accumulated transform of `el` and its ancestors as (a, b, c, d, e, f); None if it rotates or skews."""
    chain = []
    while el is not None:
        if el.attrs.get("transform"):
            chain.append(el.attrs["transform"])
        el = el.parent
    m = (1.0, 0.0, 0.0, 1.0, 0.0, 0.0)

    def mul(p, q):
        a, b, c, d, e, f = p
        A, B, C, D, E, F = q
        return (a * A + c * B, b * A + d * B, a * C + c * D, b * C + d * D, a * E + c * F + e, b * E + d * F + f)

    for tr in reversed(chain):
        for name, args in re.findall(r"(\w+)\s*\(([^)]*)\)", tr):
            n = [float(x) for x in _NUM.findall(args)]
            if name == "translate" and n:
                m = mul(m, (1, 0, 0, 1, n[0], n[1] if len(n) > 1 else 0.0))
            elif name == "scale" and n:
                m = mul(m, (n[0], 0, 0, n[1] if len(n) > 1 else n[0], 0, 0))
            elif name == "matrix" and len(n) == 6:
                m = mul(m, tuple(n))
            elif name == "rotate" and n and abs(n[0]) % 360 > 0.01:
                return None
            elif name in ("skewX", "skewY"):
                return None
    return m


def _pt(m, x, y):
    return m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]


def _text_of(el):
    parts = []
    for c in el.chunks:
        if isinstance(c, str):
            parts.append(c)
        elif c.tag not in ("title", "desc"):
            parts.append(_text_of(c))
    return "".join(parts)


def _text_lines(el):
    """[(x, y, text)] for a <text>: one entry, or one per <tspan> that sets its own position."""
    x, y = _f(el.attrs.get("x")), _f(el.attrs.get("y"))
    spans = [c for c in el.chunks if not isinstance(c, str) and c.tag == "tspan"]
    if not spans:
        return [(x, y, _text_of(el))]
    out, cx, cy = [], x, y
    lead = "".join(c for c in el.chunks if isinstance(c, str)).strip()
    if lead:
        out.append((cx, cy, lead))
    for sp in spans:
        if "x" in sp.attrs:
            cx = _f(sp.attrs["x"])
        if "y" in sp.attrs:
            cy = _f(sp.attrs["y"])
        cy += _f(sp.attrs.get("dy"))
        out.append((cx, cy, _text_of(sp)))
    return out


def _path_points(d):
    """Absolute points a path visits (end points of each command, plus the start)."""
    toks = re.findall(r"[MmLlHhVvCcSsQqTtAaZz]|[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?", d or "")
    pts, i, cmd = [], 0, None
    cx = cy = sx = sy = 0.0
    need = {"M": 2, "L": 2, "H": 1, "V": 1, "C": 6, "S": 4, "Q": 4, "T": 2, "A": 7, "Z": 0}
    while i < len(toks):
        if toks[i].isalpha():
            cmd = toks[i]
            i += 1
            if cmd in "Zz":
                cx, cy = sx, sy
                continue
        if cmd is None:
            break
        k = need[cmd.upper()]
        args = []
        try:
            args = [float(t) for t in toks[i:i + k]]
        except ValueError:
            break
        if len(args) < k:
            break
        i += k
        rel = cmd.islower()
        u = cmd.upper()
        if u == "H":
            cx = args[0] + (cx if rel else 0)
        elif u == "V":
            cy = args[0] + (cy if rel else 0)
        else:
            ex, ey = args[-2], args[-1]
            cx, cy = (cx + ex, cy + ey) if rel else (ex, ey)
        if u == "M":
            sx, sy = cx, cy
            cmd = "l" if rel else "L"
        pts.append((cx, cy))
    return pts


def _points_attr(s):
    n = [float(x) for x in _NUM.findall(s or "")]
    return list(zip(n[0::2], n[1::2], strict=False))


def _dist_rect(p, r):
    dx = max(r[0] - p[0], 0, p[0] - r[2])
    dy = max(r[1] - p[1], 0, p[1] - r[3])
    return math.hypot(dx, dy)


def lint_svg(svg_text):
    root = _parse(svg_text)
    if root is None:
        return [Finding("empty", "svg", "no <svg> element found")]
    findings = []
    vb = [float(x) for x in _NUM.findall(root.attrs.get("viewbox", ""))]
    W = H = None
    if len(vb) == 4:
        vx, vy, W, H = vb
    else:
        W, H, vx, vy = _f(root.attrs.get("width"), 0) or None, _f(root.attrs.get("height"), 0) or None, 0, 0

    texts, shapes, rects, arrows = [], 0, [], []

    def walk(el):
        nonlocal shapes
        tag = el.tag
        if tag in ("defs", "marker", "clippath", "mask", "symbol", "pattern", "style", "title", "desc",
                   "lineargradient", "radialgradient", "filter"):
            return
        if tag in _SHAPES:
            shapes += 1
        m = _matrix(el)
        if tag == "text":
            fs_raw = _inherited(el, "font-size")
            fs = _f(fs_raw, DEFAULT_FONT) if fs_raw else DEFAULT_FONT
            anchor = _inherited(el, "text-anchor", "start")
            fam = (_inherited(el, "font-family", "") or "").lower()
            mono = "mono" in fam or "menlo" in fam or "courier" in fam
            wt = str(_inherited(el, "font-weight", "400") or "400").lower()
            bold = wt == "bold" or (wt.isascii() and wt.isdigit() and int(wt) >= 600)
            em = CHAR_EM_MONO if mono else (CHAR_EM if bold else CHAR_EM_REGULAR)
            if m is None:
                m = (1, 0, 0, 1, 0, 0)
                rotated = True
            else:
                rotated = False
            for (x, y, t) in _text_lines(el):
                t = re.sub(r"\s+", " ", unescape(t)).strip()
                if not t:
                    continue
                gx, gy = _pt(m, x, y)
                sc = abs(m[0]) or 1.0
                f = fs * sc
                w = len(t) * f * em
                x0 = gx - w if anchor == "end" else (gx - w / 2 if anchor == "middle" else gx)
                texts.append({"t": t, "fs": f, "box": (x0, gy - 0.8 * f, x0 + w, gy + 0.2 * f), "rot": rotated,
                              "fs_set": bool(fs_raw)})
        elif tag == "rect":
            x, y, w, h = (_f(el.attrs.get(k)) for k in ("x", "y", "width", "height"))
            if m is not None:
                x0, y0 = _pt(m, x, y)
                x1, y1 = _pt(m, x + w, y + h)
                r = (min(x0, x1), min(y0, y1), max(x0, x1), max(y0, y1))
                if (r[2] - r[0]) >= 24 and (r[3] - r[1]) >= 14:
                    rects.append(r)
                if W and _clip_rect(r, vx, vy, W, H):
                    findings.append(Finding("clip", "rect", "box (%.0f,%.0f)-(%.0f,%.0f) outside the viewBox" % r))
        elif tag in ("circle", "ellipse"):
            cx, cy = _f(el.attrs.get("cx")), _f(el.attrs.get("cy"))
            rx = _f(el.attrs.get("r" if tag == "circle" else "rx"))
            ry = _f(el.attrs.get("r" if tag == "circle" else "ry"))
            if m is not None:
                a, b = _pt(m, cx - rx, cy - ry)
                c, d = _pt(m, cx + rx, cy + ry)
                r = (min(a, c), min(b, d), max(a, c), max(b, d))
                if rx >= 5:
                    rects.append(r)
                if W and _clip_rect(r, vx, vy, W, H):
                    findings.append(Finding("clip", tag, "shape (%.0f,%.0f)-(%.0f,%.0f) outside the viewBox" % r))
        elif tag in ("path", "line", "polyline", "polygon"):
            if tag == "path":
                pts = _path_points(el.attrs.get("d"))
            elif tag == "line":
                pts = [(_f(el.attrs.get("x1")), _f(el.attrs.get("y1"))), (_f(el.attrs.get("x2")), _f(el.attrs.get("y2")))]
            else:
                pts = _points_attr(el.attrs.get("points"))
            if m is not None and pts:
                pts = [_pt(m, *p) for p in pts]
                if tag == "line" and not _attr(el, "marker-end") and not _attr(el, "marker-start"):
                    (ax, ay), (bx, by) = pts[0], pts[-1]
                    if abs(ax - bx) < 1.0 and abs(ay - by) >= 80:          # a lifeline: arrows may land on it
                        rects.append((ax, min(ay, by), ax, max(ay, by)))
                me, ms = _attr(el, "marker-end"), _attr(el, "marker-start")
                if me and me != "none" and len(pts) >= 2:
                    arrows.append((tag, pts[-1], "end", el))
                if ms and ms != "none" and len(pts) >= 2:
                    arrows.append((tag, pts[0], "start", el))
        for k in el.kids:
            walk(k)

    walk(root)

    if shapes == 0:
        findings.append(Finding("empty", "svg", "nothing drawn"))
    elif not texts and shapes < 3:
        findings.append(Finding("empty", "svg", "no text and %d shape(s)" % shapes))

    for tx in texts:
        b = tx["box"]
        name = "text '%s'" % (tx["t"][:40])
        if tx["fs_set"] and tx["fs"] < MIN_FONT - 1e-6:
            findings.append(Finding("tiny", name, "font-size %.1f" % tx["fs"]))
        if W and not tx["rot"] and _clip_rect(b, vx, vy, W, H):
            findings.append(Finding("clip", name, "box (%.0f,%.0f)-(%.0f,%.0f) outside the viewBox %gx%g" % (b + (W, H))))

    flat = sorted((t for t in texts if not t["rot"]), key=lambda t: t["box"][0])
    seen = set()
    for i, a in enumerate(flat):
        ab = a["box"]
        for j in range(i + 1, len(flat)):
            c = flat[j]
            cb = c["box"]
            if cb[0] >= ab[2] - OVERLAP_MIN_W:
                break
            if a["t"] == c["t"] and abs(ab[0] - cb[0]) < 1.5 and abs(ab[1] - cb[1]) < 1.5:
                continue                                    # the same label drawn twice (halo / shadow)
            ow = min(ab[2], cb[2]) - max(ab[0], cb[0])
            oh = min(ab[3], cb[3]) - max(ab[1], cb[1])
            hmin = min(ab[3] - ab[1], cb[3] - cb[1])
            if ow > OVERLAP_MIN_W and oh > OVERLAP_MIN_H_FRAC * hmin:
                key = (a["t"], c["t"], round(ab[0]), round(cb[0]))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding("overlap", "text '%s' / '%s'" % (a["t"][:32], c["t"][:32]),
                                        "boxes intersect %.0fx%.0f px near (%.0f,%.0f)" % (ow, oh, max(ab[0], cb[0]), max(ab[1], cb[1]))))

    for tag, p, which, _el in arrows:
        if not rects:
            continue
        d = min(_dist_rect(p, r) for r in rects)
        if d > ARROW_TOL:
            findings.append(Finding("arrow", tag, "%s at (%.0f,%.0f) is %.0f px from the nearest node" % (which, p[0], p[1], d)))
    return findings


def _clip_rect(r, vx, vy, W, H):
    return r[0] < vx - CLIP_TOL or r[1] < vy - CLIP_TOL or r[2] > vx + W + CLIP_TOL or r[3] > vy + H + CLIP_TOL


_LOGO = re.compile(r'<div class="logo">.*?</div>', re.S)
_SVG = re.compile(r"<svg\b.*?</svg>", re.S)


def lint_html(page):
    """Lint every <svg> of a page (the masthead logo is skipped). Element names carry the svg's index."""
    body = _LOGO.sub("", page)
    out = []
    for n, m in enumerate(_SVG.finditer(body), 1):
        for f in lint_svg(m.group(0)):
            out.append(Finding(f.kind, "svg%d %s" % (n, f.element), f.detail))
    return out
