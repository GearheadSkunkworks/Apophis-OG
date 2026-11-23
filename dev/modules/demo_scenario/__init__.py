"""Reference capability module (v5b Phase 2): a runtime-loadable incident scenario.

Proves that a *scenario* — not just a diagram — can be dropped in as a module and loaded/
unloaded live. ``register`` adds a scenario to ``netgen.incidents.REGISTRY`` (so it appears in
the scenario grid and is selectable) and declares teardown via ``kernel.on_unload``. The
scenario emits a handful of benign DNS lookups from workstations inside a short window — enough
to be real, selectable traffic without touching the no-module baseline (an unselected or
unloaded scenario emits nothing, so 609,554 is unaffected).
"""
from netgen import incidents as INC
from netgen import flows as F

SCENARIO = "demo-traffic"          # REGISTRY key (scenario names use hyphens)


def _build(ctx, eng, tag, win):
    """Scenario builder: ``fn(ctx, eng, tag, win)``. A few DNS lookups from workstations to the
    DC, spread across the window, scaled down with the build's --scale."""
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    clients = [h for h in ctx.h.values()
               if getattr(h, "role", "") in ("Windows workstation", "macOS workstation")]
    if not clients:
        return
    n = max(3, int(10 * min(1.0, max(0.05, getattr(ctx, "scale", 1.0)))))
    t = lo + 5
    for i in range(n):
        s(t, F.dns_lookup, clients[i % len(clients)], "demo-module.corp.invalid", rcode=3)
        t += 2.0


def register(kernel):
    """Add the scenario to the incident registry and declare its teardown."""
    INC._reg(SCENARIO, "NPM", "demo-traffic", "Demo module traffic (runtime-loaded)",
             ((10, 0), (10, 10)), _build,
             "A few DNS lookups from workstations, emitted by a scenario module loaded at run time.")
    kernel.on_unload(lambda: INC.REGISTRY.pop(SCENARIO, None))


def self_test():
    """Confirm the scenario is registered and its builder is callable."""
    inc = INC.REGISTRY.get(SCENARIO)
    ok = inc is not None and callable(getattr(inc, "builder", None))
    return {"ok": ok,
            "detail": "registered in incidents.REGISTRY as %r (category %s)"
                      % (SCENARIO, getattr(inc, "prefix", "-")) if ok else "not registered"}
