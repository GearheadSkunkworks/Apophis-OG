"""Notes: generated cautions (mapped addressing, skipped actions, OT zone, plan mode, role shift) and build errors."""


def render(view, ctx):
    notes = [(n["kind"], n["title"], n["body"]) for n in view["notes"]]
    if view["errors"]:
        shown = view["errors"][:8]
        notes.insert(0, ("warn", "Build messages", "; ".join(shown) + (" (+%d more)" % (len(view["errors"]) - 8)
                                                                      if len(view["errors"]) > 8 else "")))
    if not notes:
        return None
    return {"id": "notes", "title": "Notes", "sub": "", "svg": None, "html": None, "height": 0,
            "alt": [[k, t, b] for k, t, b in notes], "notes": notes}
