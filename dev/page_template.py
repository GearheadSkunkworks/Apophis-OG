"""The one shared shell for the server-rendered static pages: header (pulse mark + title), content slot,
theme tokens from ui/theme.css, and the ?theme= / ?palette= handling. Diagram pages (make_diagram.render_page)
use PULSE_MARK and themed() from here; the plain message pages (errors, engine down) use page()."""
import html

# Slate Blue is the default and carries no attribute; "current" is the legacy name for Forge.
PALETTES = ("forge", "teal", "sage", "clay")

# The page header mark: the Gearhead Skunkworks gear-and-skull, drawn from /ui/gearhead-mark.png by theme.css (no script).
PULSE_MARK = '<span class="mark gh" aria-hidden="true"></span>'


def themed(page, theme=None, palette=None):
    """Stamp the user's theme onto a rendered page as <html> attributes. The pages carry no script, so
    the app passes its light/dark mode and palette in the address and the server applies them here.
    Anything outside the allow-lists is ignored, so nothing from the address reaches the markup."""
    attrs = ""
    if theme in ("dark", "light"):
        attrs += ' data-theme="%s"' % theme
    if palette == "current":
        palette = "forge"
    if palette in PALETTES:
        attrs += ' data-palette="%s"' % palette
    return page.replace('<html lang="en">', '<html lang="en"%s>' % attrs, 1) if attrs else page


_CSS = """
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{background:var(--page)}
  body{font-family:var(--font-ui,'Source Sans 3',Arial,sans-serif);color:var(--ink);line-height:1.5;font-size:15px;padding:24px}
  .page{max-width:720px;margin:0 auto;background:var(--surface,var(--page));border:1px solid var(--line,var(--border));
        border-radius:var(--r-card,4px);padding:24px 28px}
  .masthead{display:flex;align-items:center;gap:14px;padding-bottom:12px;border-bottom:2px solid var(--sapphire)}
  .mark{display:grid;place-items:center;width:30px;height:30px;border-radius:3px;background:var(--mist,var(--page));
        border:1px solid var(--line-2,var(--border));color:var(--cyan-tx,var(--cyan))}
  .mark svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
  .mh-title{font-size:24px;font-weight:900;line-height:1;color:var(--ink)}
  h2{font-size:18px;font-weight:700;margin:20px 0 8px;color:var(--tangerine)}
  p{margin:8px 0}
  pre{background:var(--code-bg);padding:10px 12px;border-radius:5px;overflow:auto}
"""


def page(title, heading, body_html, theme=None, palette=None):
    """A full static page. `title` and `heading` are plain text (escaped here); `body_html` is trusted markup."""
    t = html.escape(title)
    doc = ('<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n'
           '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
           '<title>%s</title>\n<style>%s</style>\n<link rel="stylesheet" href="/ui/theme.css">\n</head>\n<body>\n'
           '<div class="page">\n  <div class="masthead">%s<span class="mh-title">%s</span></div>\n'
           '  <h2>%s</h2>\n  %s\n</div>\n</body>\n</html>\n'
           % (t, _CSS, PULSE_MARK, t, html.escape(heading), body_html))
    return themed(doc, theme, palette)
