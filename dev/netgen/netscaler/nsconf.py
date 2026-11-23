"""Synthesize a realistic NetScaler ``ns.conf`` of a fixed size for the config-exfil phase.

The incident exfiltrates the stolen ``ns.conf`` as a cleartext HTTP PUT whose body is
**200,015 bytes**; the filename ``ns1_ns.conf`` and that length are the record-fidelity targets a
sensor reads. The text below is plausible NetScaler config (``set ns config``, ``add lb vserver``,
``bind ssl ...``) so an analyst eyeballing the carved file sees a real config, padded deterministic-
ally to the exact byte length. It is built WITHOUT the engine RNG (a fixed string), so it is
identical every build and can never perturb the baseline pin.
"""

_TARGET = 200_015


def ns_conf(vip="203.0.113.10", snip="10.10.20.60", domain="corp.example.local", server_pfx="10.10.20",
            hostname="netscaler-gw01", n0=0) -> bytes:
    """server_pfx: first three octets of the configured server /24 (the default is the stock one)."""
    rehome = lambda t: t.replace("10.10.20.", server_pfx + ".")
    head = [
        "#NS14.1 Build 29.63.nc",
        "# Last modified by `save config`, Fri Oct  9 15:21:04 2026",
        "set ns config -IPAddress %s -netmask 255.255.255.0" % snip,
        "set ns hostName %s" % hostname,
        "enable ns feature LB CS SSL GSLB REWRITE RESPONDER AAA SSLVPN",
        "enable ns mode FR L3 USNIP PMTUD",
        "add ns ip %s 255.255.255.0 -type SNIP" % snip,
        "add ns ip %s 255.255.255.255 -type VIP" % vip,
        "add dns nameServer 10.10.20.10",
        "set ssl parameter -denySSLReneg NONSECURE -defaultProfile ENABLED",
        "add authentication ldapAction LDAP-CORP -serverIP 10.10.20.10 -ldapBase "
        "\"%s\" -ldapBindDn svc_scan@%s -ldapLoginName "
        "sAMAccountName -groupAttrName memberOf" % (",".join("DC=" + l for l in domain.split(".")), domain),
        "add vpn vserver GW-VPN SSL %s 443 -icaOnly OFF -deviceCert vpn-%s" % (vip, domain),
        "bind ssl vserver GW-VPN -certkeyName vpn-%s" % domain,
        "add lb vserver LB-StoreFront SSL 10.10.20.25 443 -persistenceType SOURCEIP",
        "add service svc-sf1 10.10.20.25 SSL 443 -gslb NONE -maxClient 0 -usip NO",
        "bind lb vserver LB-StoreFront svc-sf1",
    ]
    # Deterministic body of repeating, varied, valid-looking stanzas until just under target.
    body = rehome("\n".join(head) + "\n")
    i = n0
    stanzas = (
        "add server web-{n:03d} 10.10.20.{o}\n"
        "add service svc-web-{n:03d} web-{n:03d} HTTP 80 -maxClient 0 -cltTimeout 180\n"
        "bind lb vserver LB-StoreFront svc-web-{n:03d}\n"
        "add rewrite action rw-hdr-{n:03d} insert_http_header X-Fwd \"\\\"ns-{n:03d}\\\"\"\n"
        "add responder policy rsp-{n:03d} \"HTTP.REQ.URL.CONTAINS(\\\"/old/{n:03d}\\\")\" DROP\n"
        "bind ssl vserver GW-VPN -cipherName TLS1.2-ECDHE-RSA-AES256-GCM-SHA384 -priority {n}\n"
    )
    while len(body) < _TARGET - 400:
        o = 100 + (i % 150)
        body += rehome(stanzas.format(n=i, o=o))
        i += 1
    # Pad to the exact byte length with a trailing comment block.
    pad = _TARGET - len(body) - len("\n# end-of-config\n")
    if pad > 0:
        body += "# " + ("x" * (pad - 2)) + "\n"
    body += "# end-of-config\n"
    out = body.encode("latin-1", "replace")
    # Trim/pad to land on the exact target (encoding is 1 byte/char here, but be safe).
    if len(out) > _TARGET:
        out = out[:_TARGET]
    elif len(out) < _TARGET:
        out += b"#" * (_TARGET - len(out))
    return out
