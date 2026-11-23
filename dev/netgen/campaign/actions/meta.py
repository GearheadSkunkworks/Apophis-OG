"""Per-action explanatory metadata for the campaign diagrams (plain text, tells, capture filters, wire facts).

The data lives in meta_a.py, meta_b.py and meta_c.py (one ``META = {token: {...}}`` each). ``get(token)`` returns the
merged record or None; ``missing()`` lists registered actions without a complete record so a test can fail the build
when a new action ships without one. Fields: plain (str), tells ([str]), filters ([(what, template, expect)]), wire (str).
"""
import importlib

FIELDS = ("plain", "tells", "filters", "wire")
_META = None


def _load():
    global _META
    if _META is None:
        merged = {}
        for name in ("meta_a", "meta_b", "meta_c"):
            try:
                mod = importlib.import_module("." + name, __package__)
            except ModuleNotFoundError as e:           # a part not written yet is fine; a broken one is not
                if e.name != __package__ + "." + name:
                    raise
                continue
            for tok, rec in getattr(mod, "META", {}).items():
                if tok in merged:
                    raise ValueError("duplicate metadata for action " + tok)
                merged[tok] = rec
        try:
            from . import spec_actions
            for tok, rec in spec_actions.meta_records().items():
                merged.setdefault(tok, rec)
        except ImportError:
            pass
        _META = merged
    return _META


def get(token):
    """The metadata record for an action token, or None."""
    return _load().get(token)


def complete(rec):
    return isinstance(rec, dict) and all(rec.get(f) for f in FIELDS)


def missing():
    """Registered action tokens with no complete metadata record."""
    from . import load_all
    return sorted(t for t in load_all() if not complete(get(t)))
