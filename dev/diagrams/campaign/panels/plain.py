"""In plain terms: three to five template sentences, each traced to the stages it comes from."""
from .. import narrate
from . import esc


def render(view, ctx):
    items = narrate.plain(view)
    if not items:
        return None
    li = "".join('<li>%s%s</li>' % (esc(i["text"]), (' <span class="refs">%s</span>' % esc(
        "stage " + ", ".join(i["refs"]) if len(i["refs"]) == 1 else
        ("stages " + ", ".join(i["refs"][:4]) + (" +%d" % (len(i["refs"]) - 4) if len(i["refs"]) > 4 else ""))))
        if i["refs"] else "") for i in items)
    return {"id": "plain", "title": "In plain terms", "sub": "Generated from the stages and actions below",
            "svg": None, "html": '<ul class="cd-plain">%s</ul>' % li, "height": 0,
            "alt": [[i["text"]] for i in items]}
