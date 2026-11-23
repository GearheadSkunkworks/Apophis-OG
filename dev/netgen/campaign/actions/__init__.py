"""Campaign action registry.

An *action* is one network behaviour a campaign stage can emit: a beacon, a DNS lookup burst, a scan,
an authentication attempt, a file transfer. Each wraps the engine's protocol builders and returns a
list of real packets. Actions describe network *behaviour* only: no exploit code, no shellcode, no
working malware bytes. Any "payload" body is inert filler carrying only the file-type magic bytes.

Contract (see dev/docs/campaign-m1-contracts.md):

    def my_action(ctx, src, dst, *, ts, **params) -> list      # engine packet list, like netgen.flows

``src`` / ``dst`` are netgen.core.Host objects resolved by the runner. The runner schedules the call
exactly like the engine's own scenarios (``sched(ts, fn, src, dst, **params)``), so ``ts`` is passed by
keyword. Randomness comes from ``netgen.flows.rng`` only (never ``random``, ``os.urandom`` or the clock)
so a campaign rebuilds identically.
"""
import functools
import os
import random as _random
import threading
from dataclasses import dataclass, field

_REGISTRY = {}


@dataclass
class ActionSpec:
    token: str                      # unique, lower_snake, e.g. "https_beacon"
    fn: object                      # fn(ctx, src, dst, *, ts, **params) -> packet list
    title: str                      # short human title
    tactic: str                     # ATT&CK tactic slug: execution, command-and-control, discovery, ...
    techniques: list                # default ATT&CK technique ids, e.g. ["T1071.001"]
    protocols: list                 # protocols emitted, e.g. ["DNS", "TLS", "HTTPS"]
    summary: str = ""               # one sentence: what appears on the wire
    params: dict = field(default_factory=dict)      # name -> {"type": "int|float|str|bool|list", "default": ..., "help": str}
    src: str = "internal"           # what src must be: "internal" | "external" | "any"
    dst: str = "external"           # what dst must be: "internal" | "external" | "any"
    needs: tuple = ()               # host-name suffixes that must exist in the build, e.g. ("DC1",)
    min_duration_s: float = 1.0     # typical wire duration, used by the runner for stage layout
    ot: bool = False                # True when it needs the OT subnet


_P256_N = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
_P384_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16)


def deterministic(fn):
    """Run an action with the engine builders' entropy made repeatable, so one campaign rebuilds
    byte for byte. ``os.urandom`` (filler, GUIDs, SSH and TLS random fields) and the elliptic-curve key
    generation in netgen.tls are fed from a stream seeded by the engine's reseeded generator.

    The replacements are installed process-wide for the duration of the call, so they only answer for the
    thread that is building the capture; any other thread (for example the GUI's web server) still gets the
    real operating-system entropy. Applied automatically by ``register()``."""
    if getattr(fn, "_og_deterministic", False):
        return fn

    @functools.wraps(fn)
    def run(ctx, src, dst, *, ts, **params):
        from cryptography.hazmat.primitives.asymmetric import ec, x25519
        from ...flows import rng
        owner = threading.get_ident()
        local = _random.Random(rng.getrandbits(64))
        real_urandom, real_gen, real_x = os.urandom, ec.generate_private_key, x25519.X25519PrivateKey

        def urandom(n):
            if threading.get_ident() != owner:
                return real_urandom(n)
            return local.getrandbits(8 * n).to_bytes(n, "big") if n else b""

        def gen_ec(curve, *a, **k):
            n = {"secp256r1": _P256_N, "secp384r1": _P384_N}.get(getattr(curve, "name", ""))
            if n is None or threading.get_ident() != owner:
                return real_gen(curve, *a, **k)
            return ec.derive_private_key(int.from_bytes(urandom(48), "big") % (n - 1) + 1, curve)

        class X25519PrivateKey:
            @staticmethod
            def generate():
                if threading.get_ident() != owner:
                    return real_x.generate()
                return real_x.from_private_bytes(urandom(32))
            from_private_bytes = staticmethod(real_x.from_private_bytes)

        os.urandom, ec.generate_private_key, x25519.X25519PrivateKey = urandom, gen_ec, X25519PrivateKey
        try:
            return fn(ctx, src, dst, ts=ts, **params)
        finally:
            os.urandom, ec.generate_private_key, x25519.X25519PrivateKey = real_urandom, real_gen, real_x
    run._og_deterministic = True
    return run


def register(spec):
    if spec.token in _REGISTRY:
        raise ValueError("duplicate campaign action: " + spec.token)
    spec.fn = deterministic(spec.fn)
    _REGISTRY[spec.token] = spec
    return spec


def get(token):
    try:
        return _REGISTRY[token]
    except KeyError:
        raise KeyError("unknown campaign action %r. Known: %s" % (token, ", ".join(sorted(_REGISTRY)))) from None


def all_specs():
    return dict(sorted(_REGISTRY.items()))


def load_all():
    """Import every actions module once so each registers itself. Safe to call repeatedly."""
    import importlib
    for name in ("c2", "delivery", "exfil", "recon", "access", "lateral", "host", "outside", "exploit", "data"):
        try:
            importlib.import_module("." + name, __name__)
        except ModuleNotFoundError as e:           # a module not written yet is fine; a broken one is not
            if e.name != __name__ + "." + name:
                raise
    return all_specs()
