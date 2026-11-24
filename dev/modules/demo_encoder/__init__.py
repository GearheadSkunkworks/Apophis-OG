"""Reference capability module (v5c Phase 4): a runtime-swappable protocol encoder.

Proves the fourth capability kind -- an individual protocol encoder. ``register`` overrides the
``ftp_line`` encoder in ``netgen.protocols`` so every FTP response line gains a benign tag, and
declares teardown via ``kernel.on_unload`` (which restores the built-in). All engine call sites
(`P.ftp_line(...)`) pick up the override immediately through the encoder registry; unloading
restores byte-for-byte behaviour, so the no-module baseline (609,554) is untouched.
"""
from netgen import protocols as P

ENCODER = "ftp_line"
_builtin = None


def _ftp_line(s):
    # call the captured built-in with a tagged message -- still a valid FTP line (code + text)
    return _builtin(s + " [demo-encoder]")


def register(kernel):
    global _builtin
    prev = P.register_encoder(ENCODER, _ftp_line)          # returns the previous (built-in) impl
    if prev is not _ftp_line:                              # a second register must not make _builtin recurse into itself
        _builtin = prev
    kernel.on_unload(lambda: P.reset_encoder(ENCODER))


def self_test():
    active = P.ENCODERS.get(ENCODER) is _ftp_line
    out = P.ftp_line("220 service ready")                   # routes through the registry
    ok = active and b"[demo-encoder]" in out
    return {"ok": ok, "detail": "ftp_line('220 service ready') -> %r" % out}
