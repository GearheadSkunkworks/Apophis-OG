"""Reference capability module (v5b Phase 1): a runtime-loadable diagram.

This is the smallest possible demonstration of the module contract. ``register`` wires a
diagram named ``demo`` into ``make_diagram.DIAGRAMS`` and declares its teardown through
``kernel.on_unload``; ``self_test`` renders it. Load this module and the ``demo`` diagram
appears in the picker and at ``/diagram?name=demo``, live; unload it and it is gone — with no
server restart and no change to any core file. A diagram is deliberately chosen first: it is
display-only, so it carries zero risk to the 609,554 wire baseline.
"""
import make_diagram as M

DIAGRAM = "demo"


def _build(c):
    """Diagram builder: ``fn(c) -> dict`` consumed by make_diagram.render_page. Ignores the
    DiagramContext and draws a static panel, since this module exists to prove load/unload."""
    W, H = 1180, 300
    s = [f'<svg viewBox="0 0 {W} {H}" xmlns="http://www.w3.org/2000/svg" role="img" '
         f'aria-label="Demo capability module">',
         f'<rect x="20" y="20" width="{W - 40}" height="{H - 40}" rx="14" '
         f'fill="#fbfbfd" stroke="#e4e4e8"/>',
         f'<rect x="20" y="20" width="{W - 40}" height="5" rx="2.5" fill="{M.SAPPHIRE}"/>',
         f'<text x="{W / 2:.0f}" y="{H / 2 - 8:.0f}" text-anchor="middle" font-size="26" '
         f'font-weight="900" fill="{M.SAPPHIRE}">Loaded at run time by the kernel</text>',
         f'<text x="{W / 2:.0f}" y="{H / 2 + 26:.0f}" text-anchor="middle" font-size="14" '
         f'fill="#4a4760">This diagram is a capability module under /modules. Unload it and '
         f'it disappears &#8212; core never imported it.</text>',
         '</svg>']
    return {"svg": "".join(s),
            "doc_tag": "Capability module<br>v5b reference",
            "h1": "Demo module",
            "subtitle": "A runtime-loadable diagram capability",
            "kpis": [("1.0", "Module version"), ("diagram", "Kind"), ("load / unload", "Lifecycle")]}


def register(kernel):
    """Wire the demo diagram into make_diagram's registry and declare its teardown."""
    M.register(DIAGRAM, "Demo module", "Runtime-loaded reference capability (v5b)",
               order=999)(_build)
    kernel.on_unload(lambda: M.DIAGRAMS.pop(DIAGRAM, None))


def self_test():
    """Render the diagram and confirm the page came back with this module's content."""
    page = M.render(DIAGRAM)
    ok = "Loaded at run time by the kernel" in page
    return {"ok": ok,
            "detail": "rendered /diagram?name=%s (%d bytes)" % (DIAGRAM, len(page))}
