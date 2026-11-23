"""Entry point for the app server: `campaign_diagram(data)` validates the request body and returns page HTML.

Body: {"campaign": object or list of objects, "summary": object?, "score": object?, "company": str?}.
Raises ValueError with a one-line message for bad input; the caller turns that into a 400.
"""
from . import page

MAX_CAMPAIGNS = 8


def _one(c, where):
    if not isinstance(c, dict):
        raise ValueError("%s must be a campaign object" % where)
    from netgen.campaign import schema
    errs = schema.validate(c)
    if errs:
        raise ValueError("%s is not a valid campaign: %s" % (where, str(errs[0])[:160]))


def campaign_diagram(data):
    if not isinstance(data, dict):
        raise ValueError("body must be a JSON object")
    camp = data.get("campaign")
    if camp is None:
        raise ValueError("campaign is required")
    summary, score, company = data.get("summary"), data.get("score"), data.get("company")
    if summary is not None and not isinstance(summary, dict):
        raise ValueError("summary must be an object")
    if score is not None and not isinstance(score, dict):
        raise ValueError("score must be an object")
    if company is not None and (not isinstance(company, str) or len(company) > 100):
        raise ValueError("company must be a string of at most 100 characters")
    if isinstance(camp, list):
        if not camp or len(camp) > MAX_CAMPAIGNS:
            raise ValueError("campaign list must hold 1 to %d campaigns" % MAX_CAMPAIGNS)
        for n, item in enumerate(camp, 1):
            _one(item["campaign"] if isinstance(item, dict) and "campaign" in item and "stages" not in item else item,
                 "campaign %d" % n)
    else:
        _one(camp, "campaign")
    try:
        return page.render(camp, summary, score, company or None)
    except RuntimeError as e:
        raise ValueError(str(e).splitlines()[0]) from None
