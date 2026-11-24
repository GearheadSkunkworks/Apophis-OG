"""netgen.packkit -- small shared helpers for the incident-replay packs.

Every pack injects its hosts INSIDE ``build()`` (never at import), so a build that does not select
the scenario stays byte-for-byte the baseline. These helpers only remove the repeated host-setup
boilerplate; they never draw from the engine RNG at import time.
"""
from netgen import protocols as P
from netgen.core import Host
from netgen.identity import get_current


def host_name(suffix):
    """The build identity's hostname for a role suffix ('DC1' -> 'EXL-DC1')."""
    return get_current().host(suffix)


def add_internal(ctx, suffix, ip, mac, os_, role, fqdn_label=None):
    """Create (once) an internal host on the server segment and return it."""
    name = host_name(suffix)
    if name not in ctx.h:
        ctx.h[name] = Host(name, ctx.link.place(ip), mac, os_, role, ctx.link.server_net,
                           (fqdn_label or suffix.lower()) + "." + P.DOMAIN)
    return ctx.h[name]


def tls_exchange(ctx, client, host_name, srv, ts, exchanges, profile=None, dns=True):
    """A REAL TLS session (key-logged, decryptable with the capture's key log) to an external host:
    optional DNS first, TCP, handshake, then each (request_bytes, response_bytes) pair as application data.
    Like ``flows.https_session`` but with caller-supplied requests, so POSTs and exact bodies are possible."""
    from netgen import flows as F
    from netgen.tls import TlsSession
    rng = F.rng
    pre = F.dns_lookup(ctx, client, host_name, ts, external=True, answers=[(P.DNS_A, srv.ipb)]) if dns else []
    t = ts + rng.uniform(0.005, 0.05)
    out = ctx.arp_for(client, srv, t)
    s = ctx.tcp(client, srv, 443, t + 0.001).handshake()
    tls = TlsSession(ctx.pki, host_name, ctx.keylog, profile=profile or getattr(client, "tls_profile", "chrome"))
    for from_c, data in tls.handshake():
        if from_c:
            s.c2s(data, think=rng.uniform(0.0005, 0.003))
        else:
            s.s2c(data, think=rng.uniform(0.002, 0.01))
    for i, (req, resp) in enumerate(exchanges):
        s.c2s(tls.app_data(True, req), think=rng.uniform(0.0008, 0.004) if i == 0 else rng.uniform(0.2, 3.0))
        s.s2c(tls.app_data(False, resp), think=rng.uniform(0.02, 0.12))
    s.c2s(tls.close_notify(True), think=rng.uniform(0.5, 6.0))
    return F.merged(pre, out, s.close(think=0.002))


def add_externals(ctx, cache_key, spec, rng):
    """Create (once per build context) the external actors.

    spec: {key: (fqdn, ip, hops)}. Returns {key: Host}. ``rng`` is the pack's engine RNG so the MAC
    draw order is deterministic for a given seed.
    """
    cache = ctx.__dict__.setdefault(cache_key, {})
    for key, (fqdn, ip, hops) in spec.items():
        if key not in cache:
            h = Host(fqdn.split(".")[0].upper(), ip,
                     "02:00:5e:%02x:%02x:%02x" % (rng.randrange(256), rng.randrange(256), rng.randrange(256)),
                     "linux", "external", ip.rsplit(".", 1)[0] + ".0/24", fqdn)
            h.hops = hops
            cache[key] = h
    return cache
