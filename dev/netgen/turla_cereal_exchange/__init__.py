"""netgen.turla_cereal_exchange -- the "Turla 'Cereal' Exchange-as-C2" incident-replay scenario.

A replay of an Exchange-resident implant pattern, inspired by the toolset ESET attributed to Turla (Cereal,
published November 2026): a modular
.NET implant on a government Exchange server that needs NO external command server -- the mail system
itself is the control channel. Operators send ordinary-looking messages to a mailbox on the server; the
implant intercepts them, runs the embedded task in memory, and mails the results to an operator-controlled
address; it also collects selected mail (here, NATO/EU-addressed) and ships it out the same way.

What a sensor sees (real SMTP, port 25, Exchange ESMTP banners, multipart MIME, base64 attachments):
  * inbound task messages from one external sender to a single service mailbox, with innocuous subjects
    ("RE: Q3 vendor invoice ...") and a small base64 "invoice" attachment each;
  * a reply about a minute later: the Exchange server itself opening OUTBOUND SMTP to a first-seen external
    mail host with a similar-sized attachment, to a recipient that no user ever mails;
  * periodic bulk outbound messages with multi-hundred-KB attachments (the collected mail archive), from
    the mail server, at a cadence unlike any user's mail;
  * ordinary inbound and outbound corporate mail on the same server throughout.

NOTE ON FIDELITY: ESET describes Cereal as having no external command server, with its backdoor answering
Exchange-looking web requests. The mail-borne tasking and outbound-SMTP replies replayed here are the older Turla
Exchange-transport-agent pattern (LightNeuron, 2019); they are the network-observable stand-in, not a claim about
Cereal's exact wire protocol.

Registered as ``ir-turla-cereal-exchange`` (category IR), a SIBLING of the other IR replays.

PIN-SAFE: hosts are injected inside ``build()``; a build that does not select this scenario is
byte-for-byte the baseline.
"""
import base64
import os

from netgen import flows as F
from netgen import protocols as P
from netgen.identity import H
from netgen import packkit as K

from netgen.netscaler import phases as NSP

rng = NSP.rng

_EX_SUFFIX, _EX_IP, _EX_MAC = "EXCH1", "10.10.20.130", "00:50:56:bb:13:0a"
_EXTERNAL = {
    "operator": ("mail.tasking-relay.example", "203.0.113.170", 12),     # sends task messages
    "drop": ("mx.reports-hub.example", "192.0.2.170", 14),               # receives results and collected mail
    "partner": ("mx.freightpartner.example", "198.51.100.170", 8),       # benign business correspondent
    "partner2": ("mx.carrier-network.example", "198.51.100.171", 9),
}
_SERVICE_MAILBOX = "reports"


def _inject_hosts(ctx):
    ex = K.add_internal(ctx, _EX_SUFFIX, _EX_IP, _EX_MAC, "Windows Server 2019 / Exchange 2019", "smtp", "mail")
    return K.add_externals(ctx, "_cereal_ext", _EXTERNAL, rng), ex


def _b64_lines(raw):
    b = base64.b64encode(raw)
    return b"\r\n".join(b[i:i + 76] for i in range(0, len(b), 76))


def _message(frm, to, subject, attach_name, attach_bytes, ts):
    bnd = "----=_Part_%d_%s" % (rng.randint(100, 9999), os.urandom(8).hex())
    head = ("From: <%s>\r\nTo: <%s>\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%s@%s>\r\nMIME-Version: 1.0\r\n"
            "Content-Type: multipart/mixed; boundary=\"%s\"\r\n\r\n"
            % (frm, to, subject, P.http_date(ts).replace("GMT", "+0000"), os.urandom(12).hex(), frm.split("@")[1], bnd)).encode()
    text = ("--%s\r\nContent-Type: text/plain; charset=\"utf-8\"\r\nContent-Transfer-Encoding: 7bit\r\n\r\n"
            "Please find the document attached.\r\n\r\n" % bnd).encode()
    att = ("--%s\r\nContent-Type: application/octet-stream; name=\"%s\"\r\nContent-Transfer-Encoding: base64\r\n"
           "Content-Disposition: attachment; filename=\"%s\"\r\n\r\n" % (bnd, attach_name, attach_name)).encode()
    return head + text + att + _b64_lines(attach_bytes) + ("\r\n--%s--\r\n" % bnd).encode()


def smtp_mail(ctx, src, dst, frm, to, subject, attach_name, attach_bytes, vantage, ts=None):
    """One SMTP delivery from `src` to `dst` (port 25). The Exchange side speaks Exchange ESMTP (banner and
    EHLO extension list); any other side speaks a generic MTA. Message framing is complete MIME."""
    out = ctx.arp_for(src, dst, ts, vantage=vantage)
    s = ctx.tcp(src, dst, 25, ts + 0.001, vantage=vantage).handshake()
    ex = vantage  # the Exchange host is always the vantage
    if dst is ex:
        s.s2c(("220 %s Microsoft ESMTP MAIL Service ready at %s\r\n" % (ex.fqdn, P.http_date(ts))).encode(), think=rng.uniform(0.03, 0.1))
        s.c2s(("EHLO %s\r\n" % src.fqdn).encode(), think=rng.uniform(0.03, 0.12))
        s.s2c(("250-%s Hello [%s]\r\n250-SIZE 37748736\r\n250-PIPELINING\r\n250-DSN\r\n250-ENHANCEDSTATUSCODES\r\n"
               "250-STARTTLS\r\n250-8BITMIME\r\n250-BINARYMIME\r\n250-CHUNKING\r\n250 SMTPUTF8\r\n" % (ex.fqdn, src.ip)).encode(),
              think=rng.uniform(0.01, 0.04))
    else:
        s.s2c(("220 %s ESMTP ready\r\n" % dst.fqdn).encode(), think=rng.uniform(0.03, 0.1))
        s.c2s(("EHLO %s\r\n" % ex.fqdn).encode(), think=rng.uniform(0.03, 0.12))
        s.s2c(("250-%s\r\n250-PIPELINING\r\n250-SIZE 52428800\r\n250-STARTTLS\r\n250-8BITMIME\r\n250 ENHANCEDSTATUSCODES\r\n" % dst.fqdn).encode(),
              think=rng.uniform(0.01, 0.04))
    s.c2s(("MAIL FROM:<%s> SIZE=%d BODY=8BITMIME\r\n" % (frm, len(attach_bytes) * 4 // 3 + 900)).encode(), think=rng.uniform(0.02, 0.1))
    s.s2c(b"250 2.1.0 Sender OK\r\n", think=rng.uniform(0.01, 0.03))
    s.c2s(("RCPT TO:<%s>\r\n" % to).encode(), think=rng.uniform(0.02, 0.08))
    s.s2c(b"250 2.1.5 Recipient OK\r\n", think=rng.uniform(0.01, 0.03))
    s.c2s(b"DATA\r\n", think=rng.uniform(0.02, 0.06))
    s.s2c(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n", think=rng.uniform(0.01, 0.03))
    s.c2s(_message(frm, to, subject, attach_name, attach_bytes, ts) + b"\r\n.\r\n", think=rng.uniform(0.03, 0.15))
    s.s2c(("250 2.6.0 <%s@%s> [InternalId=%d] Queued mail for delivery\r\n"
           % (os.urandom(10).hex(), ex.fqdn, rng.randint(10**10, 10**11))).encode(), think=rng.uniform(0.05, 0.4))
    s.c2s(b"QUIT\r\n", think=rng.uniform(0.03, 0.1))
    s.s2c(("221 2.0.0 Service closing transmission channel\r\n").encode(), think=rng.uniform(0.01, 0.03))
    return F.merged(out, s.close(think=rng.uniform(0.01, 0.04)))


def task_message(ctx, op, ex, ts=None):
    """An operator task: inbound message to the service mailbox, small base64 'invoice' attachment."""
    return smtp_mail(ctx, op, ex, "accounts@%s" % op.fqdn.split(".", 1)[1], "%s@%s" % (_SERVICE_MAILBOX, P.DOMAIN),
                     "RE: Q3 vendor invoice #%d" % rng.randint(10000, 99999), "invoice_%d.pdf" % rng.randint(1000, 9999),
                     os.urandom(rng.randint(2200, 6200)), ex, ts)


def result_message(ctx, ex, drop, ts=None):
    """The implant's reply: Exchange itself originates outbound SMTP to a first-seen external mail host."""
    dc = ctx.h.get(H("DC1"))
    pre = F.dns_lookup(ctx, ex, drop.fqdn, ts, external=True, answers=[(P.DNS_A, drop.ipb)], dc=dc) if dc else []
    m = smtp_mail(ctx, ex, drop, "%s@%s" % (_SERVICE_MAILBOX, P.DOMAIN), "archive@%s" % drop.fqdn.split(".", 1)[1],
                  "RE: RE: Q3 vendor invoice #%d" % rng.randint(10000, 99999), "statement_%d.pdf" % rng.randint(1000, 9999),
                  os.urandom(rng.randint(3000, 9000)), ex, ts + 0.08)
    return F.merged(pre, m)


def collected_mail(ctx, ex, drop, size, ts=None):
    """Collected (NATO/EU-addressed) mail leaves as a large archive attachment, outbound from the mail server."""
    return smtp_mail(ctx, ex, drop, "%s@%s" % (_SERVICE_MAILBOX, P.DOMAIN), "archive@%s" % drop.fqdn.split(".", 1)[1],
                     "Weekly reconciliation %d" % rng.randint(100, 999), "reconcile_%d.zip" % rng.randint(1000, 9999),
                     os.urandom(size), ex, ts)


def business_mail(ctx, ex, partner, inbound, ts=None):
    """Benign look-alike: ordinary correspondence with a business partner, in or out."""
    user = P.username_for("WS-%03d" % rng.randint(1, 80))
    att = os.urandom(rng.randint(9000, 120000))
    name = rng.choice(("Manifest-%d.pdf", "Invoice-%d.pdf", "Route-Plan-%d.xlsx")) % rng.randint(1000, 9999)
    subj = rng.choice(("Shipment confirmation", "Updated rate sheet", "Dock appointment"))
    if inbound:
        return smtp_mail(ctx, partner, ex, "dispatch@%s" % partner.fqdn.split(".", 1)[1], "%s@%s" % (user, P.DOMAIN), subj, name, att, ex, ts)
    return smtp_mail(ctx, ex, partner, "%s@%s" % (user, P.DOMAIN), "dispatch@%s" % partner.fqdn.split(".", 1)[1], subj, name, att, ex, ts)


def build(ctx, eng, tag, win):
    """Schedule the Cereal-style incident: operator task messages at irregular intervals, the server's reply
    to each about a minute later, periodic bulk archive mail, and ordinary partner correspondence throughout."""
    ext, ex = _inject_hosts(ctx)
    from netgen import incidents as INC
    s = INC.sched_factory(eng, ctx, tag, win)
    lo, hi = win
    scale = max(0.01, min(1.0, getattr(ctx, "scale", 1.0)))
    op, drop = ext["operator"], ext["drop"]

    t = lo + 300
    while t < hi - 120:
        s(t, task_message, op, ex)
        s(t + rng.uniform(45, 95), result_message, ex, drop)
        t += rng.uniform(900, 1500)
    t = lo + 1800
    while t < hi - 120:
        s(t, collected_mail, ex, drop, rng.randint(350_000, 900_000) if scale < 0.5 else rng.randint(900_000, 2_200_000))
        t += rng.uniform(1500, 2400)

    for _ in range(max(10, int(round(60 * scale)) + 10)):
        s(lo + rng.uniform(0, max(1.0, hi - lo - 60)), business_mail, ex, ext[rng.choice(("partner", "partner2"))], rng.random() < 0.5)
