"""The emulated organisation's identity, derived from a company name + industry.

Everything the capture carries that names the fictional company — the AD/DNS domain and
Kerberos realm, the host prefix, the organisation string, the Root CA subject, the SIP realm,
the MCP assistant user-agent, the web-app namespace, and the exported artifact names — derives
from a single ``Identity``, so one (name, industry) produces one internally consistent
environment. Pass the same pair and you get the same capture.

v5.0 uses the **name** for the technical identity (DNS domain, host prefix, CA, SIP realm,
assistant, namespace) and **name + industry** for the host prefix code and the organisation
label; the industry additionally themes surface content. Later releases vary the host roster
by industry.

The defaults reproduce the historical "Example Logistics" environment **exactly** — same
domain (corp.example.local), prefix (EXL-), org and CA — so a default build is byte-for-byte
what it was and still pins at 466,343 packets.
"""
import re

#: Industry choices offered in the UI. Order is the dropdown order; the first is the default.
INDUSTRIES = ["Logistics", "Manufacturing", "Technology", "Education",
              "Healthcare", "Finance", "Retail", "Energy", "Government"]


def _alnum(s):
    return re.sub(r"[^A-Za-z0-9]", "", s or "")


def _slug(name):
    """The DNS label / SIP realm: lowercase alphanumeric of the name."""
    return _alnum(name).lower() or "example"


def _code(name, industry):
    """Host prefix code: two letters of the name + one of the industry, so
    ("Example","Logistics") -> EXL and ("Acme","Manufacturing") -> ACM. Uppercase."""
    n, i = _alnum(name), _alnum(industry)
    code = (n[:2] + i[:1]) or "EXL"
    return code.upper()


class Identity:
    """The derived identity of the emulated company. Immutable after construction."""

    def __init__(self, name="Example", industry="Logistics"):
        self.name = (name or "").strip() or "Example"
        self.industry = (industry or "").strip() or "Logistics"
        self.slug = _slug(self.name)                        # example
        self.prefix = _code(self.name, self.industry) + "-"  # EXL-
        self.domain = "corp.%s.local" % self.slug           # corp.example.local
        self.realm = self.domain.upper()                    # CORP.EXAMPLE.LOCAL
        self.netbios = "CORP"                               # NetBIOS short name (constant)
        self.org = "%s %s" % (self.name, self.industry)     # Example Logistics
        self.ca = "%s Demo Root CA" % self.name             # Example Demo Root CA
        self.sip_realm = self.slug                          # example
        self.assistant = "%sAssistant" % self.name          # ExampleAssistant
        self.namespace = "%s.Web.Data" % self.name          # Example.Web.Data
        # exported artifact names
        self.collection = "%sThreatCollection" % self.name           # ExampleThreatCollection
        self.stix_basename = "%s-threat-collection" % self.slug      # example-threat-collection
        self.pcap_basename = "%s-all-in-one" % self.slug             # example-all-in-one

    # ---- host naming ------------------------------------------------------
    def host(self, suffix):
        """Full hostname for a stable suffix: ``host('DC1')`` -> ``'EXL-DC1'``."""
        return self.prefix + suffix

    def fqdn(self, suffix):
        """Lowercase FQDN for a stable suffix: ``fqdn('DC1')`` -> ``'exl-dc1.corp.example.local'``."""
        return "%s.%s" % (self.host(suffix).lower(), self.domain)

    def __repr__(self):
        return "Identity(%r, %r)" % (self.name, self.industry)


#: The environment that reproduces the historical baseline (and the 466,343 pin). It is also
#: the TEMPLATE identity: the committed inventory.json and the engine's literals are written
#: in its tokens (EXL- / corp.example.local / Example Logistics), so a build renames FROM it.
DEFAULT = Identity("Example", "Logistics")

# The identity the current build is using. The build sets it from the UI inputs before
# generation (like reseed_all); everything that names the company reads it here, so the whole
# capture stays consistent. Defaults to DEFAULT, which keeps a plain build byte-for-byte what
# it has always been.
_current = DEFAULT


def set_current(identity):
    """Set the identity for the build about to run. Pass None to reset to DEFAULT."""
    global _current
    _current = identity or DEFAULT
    return _current


def get_current():
    """The identity the current build is using."""
    return _current


def H(suffix):
    """The current build's full hostname for a stable suffix, resolved at call time:
    ``H('DC1')`` -> ``'EXL-DC1'`` by default, ``'ACM-DC1'`` for Acme. Use this instead of a
    literal ``'EXL-...'`` wherever the engine references a host by name, so the whole capture
    speaks one company's names. (Call-time only -- never bind it into a module-level constant,
    which would freeze it at import; store the bare suffix there and resolve at use.)"""
    return _current.prefix + suffix
