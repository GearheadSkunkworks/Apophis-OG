"""netgen — the OpenGenerator traffic generator engine.

`reseed_all()` is here rather than in a submodule so it can import every one of them without
creating a cycle; the imports are inside the function for the same reason.
"""

# Every module owns its own generator, seeded once at import. That is fine for a process that
# builds one capture and exits -- the CLI -- but the GUI runs `build()` IN-PROCESS on a worker
# thread, so a second generation continued the first one's stream and produced a different
# capture from identical arguments. Measured before this existed: two builds in one interpreter
# with the same scale and the same pinned date gave 1,018,428 packets, then 915,946.
#
# Reseeding restores the property the whole project leans on: the same inputs produce the same
# capture, whether it is the first run of a session or the fifth.
#
# What this does NOT make deterministic, by design: `os.urandom` (TLS randoms, nonces, padding)
# and RSA key generation both draw from the system CSPRNG, so the BYTES of a capture differ
# between runs and fresh server certificates are minted every build. Packet counts, ordering
# and structure are what the seeds govern, and what this restores.
def _engine_modules():
    """The engine's own submodules (netgen/*.py), imported in a stable order. reseed_all()
    reseeds the ones that declare ``rng`` + ``SEED`` and applies the build identity to the ones
    that declare ``apply_identity`` -- both DISCOVERED here rather than hardcoded, so a new
    engine module is picked up automatically: give it ``rng``/``SEED`` to be reseeded and an
    ``apply_identity(identity)`` to follow the company, and nothing in this file changes.
    (Imports are cached by importlib, so this is cheap to call once per build.)

    Discovery goes through ``pkgutil.iter_modules(__path__)`` rather than ``os.listdir`` so it
    works both from source and inside a frozen bundle: PyInstaller embeds ``netgen`` in its
    archive with no real directory on disk, so a raw directory scan raised FileNotFoundError and
    took ``reseed_all()`` -> ``build()`` down with it. ``iter_modules`` is served by the frozen
    importer and lists exactly the collected submodules."""
    import pkgutil
    from importlib import import_module
    mods = []
    for _finder, name, ispkg in sorted(pkgutil.iter_modules(__path__), key=lambda t: t[1]):
        if ispkg or name.startswith("_"):                   # skip sub-packages (platform/) and _-prefixed
            continue
        try:
            mods.append(import_module("." + name, __name__))
        except Exception:                                  # noqa: BLE001 — an unimportable submodule just isn't reseeded
            pass
    return mods


def reseed_all():
    """Return every module-level RNG to its declared seed, then apply the build's company
    identity. Call once per build, before any scheduling. Returns the number of generators
    reset. Reseeding is order-independent (each module reseeds to its own SEED); the identity
    fan-out is too (each module derives its tokens straight from the identity), so for the
    default company a plain build is byte-for-byte unchanged and still pins at 466,343."""
    mods = _engine_modules()
    n = 0
    for m in mods:
        if hasattr(m, "rng") and hasattr(m, "SEED"):
            m.rng.seed(m.SEED)
            n += 1
    from . import identity as _identity
    _ident = _identity.get_current()
    for m in mods:
        apply = getattr(m, "apply_identity", None)
        if callable(apply):
            apply(_ident)
    return n
