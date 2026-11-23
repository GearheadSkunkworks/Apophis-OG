"""
The directory: who exists in CORP.EXAMPLE.LOCAL and what state each account is in.

Before this module there was no such thing as an account. Identity was a pure function of a
host name — `P.username_for("EXL-WS-047")` — so an account could not be disabled, could not
have an expired password, could not lock out, and could not exist without a workstation
attached to it. The authentication side of the capture was correspondingly implausible: a
95-seat business day produced 95 user logons, every single one of them successful, and the
only KRB-ERROR on the wire was code 25, which is not a failure at all but the normal first leg
of Windows pre-authentication.

Design notes worth keeping:

* **`P.username_for()` is left alone.** It is baked into captures that have been validated
  against tshark, and into the incident modules (`ndr-password-spray` enumerates
  `username_for("EXL-WS-001..039")`). The directory therefore *wraps* it — a workstation's
  user is still exactly the name it always was — and adds state alongside. Nothing that was
  on the wire before this module moves because of it.
* **Collisions are left in place, deliberately.** `username_for()` hashes the digits of a host
  name, so ~95 workstations map onto ~75 names and some accounts own two machines. That reads
  as a person with a desktop and a laptop, which is realistic, and removing it would rewrite
  usernames in already-validated scenarios.
* **Everything is derived deterministically** from the inventory and a fixed seed, so the same
  people are disabled, expired and locked out on every run. A demo that tells a different
  story each time it is generated is not a demo. It also means a diagram or a lab exercise can
  read this table and describe exactly what the capture contains.
"""
import random

from . import protocols as P
from .identity import H

# Own RNG stream. Sharing flows.rng would shift every downstream random draw and rewrite the
# whole capture; a private generator keeps this module's additions isolated.
SEED = 20260916                 # reseeded per build by netgen.reseed_all()
rng = random.Random(SEED)

# Re-exported from protocols so there is exactly one definition of the domain's identity in
# the engine. These were independent literals, and "CORP" here disagreed with NETBIOS =
# "EXAMPLE" there -- the same environment naming itself two different things on the wire.
REALM = P.REALM                      # CORP.EXAMPLE.LOCAL  (Kerberos)
DOMAIN = P.NETBIOS                   # CORP                  (NetBIOS short name)


def apply_identity(identity):
    """Keep this module's cached domain identity in step with the build's identity (called
    from netgen.reseed_all, right after protocols.apply_identity)."""
    global REALM, DOMAIN
    REALM = identity.realm
    DOMAIN = identity.netbios

# ---------------------------------------------------------------- account states
OK = "ok"                    # normal
DISABLED = "disabled"        # KDC_ERR_CLIENT_REVOKED — the account is switched off
EXPIRED = "expired"          # KDC_ERR_KEY_EXPIRED — password past its maximum age
LOCKOUT = "lockout"          # locks out during the day after repeated bad passwords

# KRB-ERROR codes these map to (RFC 4120 §7.5.9). 18 covers both disabled and locked out —
# Windows returns CLIENT_REVOKED for each and distinguishes them only in the e-data status,
# which is exactly why "account lockout" and "account disabled" look alike on the wire.
KRB_ERR = {
    "preauth_required": 25,     # normal, not a failure
    "preauth_failed": 24,       # wrong password
    "client_revoked": 18,       # disabled OR locked out
    "key_expired": 23,          # password expired
    "client_unknown": 6,        # no such principal (typo'd username)
}

# NT status codes for the same conditions over NTLM/SMB.
NT_STATUS = {
    "success": 0x00000000,
    "more_processing": 0xC0000016,
    "logon_failure": 0xC000006D,
    "account_disabled": 0xC0000072,
    "password_expired": 0xC0000071,
    "account_locked_out": 0xC0000234,
    "no_such_user": 0xC0000064,
}

# LDAP bind failures. Windows returns resultCode 49 for everything and puts the real reason in
# the diagnostic message as "AcceptSecurityContext error, data <hex>" — 52e wrong password,
# 525 no such user, 530 not permitted at this time, 531 not permitted from this workstation,
# 532 password expired, 533 account disabled, 701 account expired, 773 must reset password,
# 775 account locked out. Analysts read that hex, so it has to be present and correct.
LDAP_INVALID_CREDENTIALS = 49
LDAP_DATA = {
    "bad_password": "52e", "no_such_user": "525", "password_expired": "532",
    "account_disabled": "533", "must_reset": "773", "account_locked": "775",
}


class Account:
    """One principal in the directory."""

    __slots__ = ("name", "kind", "state", "host", "spn", "note")

    def __init__(self, name, kind="user", state=OK, host=None, spn=None, note=""):
        self.name = name
        self.kind = kind             # user | service | machine
        self.state = state
        self.host = host             # the workstation this account normally signs in from
        self.spn = spn               # service principal name, for service accounts
        self.note = note

    @property
    def upn(self):
        return f"{self.name}@{REALM.lower()}"

    @property
    def down_level(self):
        return f"{DOMAIN}\\{self.name}"

    def __repr__(self):                                   # pragma: no cover - debugging aid
        return f"<Account {self.name} {self.kind} {self.state}>"


# ---------------------------------------------------------------- service accounts
# Each maps onto a server that actually exists in inventory.json, so the traffic they generate
# has somewhere real to go. Keep this list in step with the inventory: a service account
# authenticating to a host that is not in the capture is worse than no service account at all.
# Host is a stable *suffix* (resolved to the build's prefix via H() at use), not a literal
# name, so a non-default company's service accounts land on its own renamed servers.
SERVICE_ACCOUNTS = [
    ("svc_backup", "BACKUP1", "cifs", "nightly and midday backup agent reading the file server"),
    ("svc_sql", "SQL1", "MSSQLSvc", "SQL Server service account renewing its own ticket"),
    ("svc_scan", "LOG1", "HTTP", "monitoring poller collecting health from the intranet"),
    ("svc_print", "PRINT1", "cifs", "print spooler fetching drivers from the file server"),
    ("svc_legacy", "WEB2", "HTTP", "legacy LOB connector — NTLM only, no SPN registered"),
]


# ---------------------------------------------------------------- privileged accounts
# Tiered, the way a real estate is administered. These matter disproportionately for detection:
# a Domain Admin signing in somewhere unusual, or a failed privileged logon, is a far stronger
# signal than the same event on an ordinary account — so the baseline has to contain enough
# normal privileged activity for the abnormal kind to stand out against.
#
# They sign in from the jump host (EXL-MGMT1), not from desktops, which is the whole point of
# having one. An admin account authenticating from a workstation is the anomaly.
PRIVILEGED_ACCOUNTS = [
    ("adm_claypool-mud", 0, "Domain Admin — tier 0, jump host only"),
    ("adm_helpdesk", 1, "Service desk — resets passwords, joins machines"),
    ("adm_sqlops", 1, "Database operations — SQL and backup servers"),
    ("adm_netops", 2, "Network operations — switches, firewall, WLC"),
]

# Groups an admin actually reads during a normal day. Enumerating these is also what an
# attacker does, which is why the baseline needs a legitimate version of it.
PRIV_GROUPS = ["Domain Admins", "Enterprise Admins", "Server Operators", "Backup Operators",
               "Help Desk", "SQL Admins"]


class Directory:
    """The set of accounts, and the daily identity plan derived from them."""

    def __init__(self, hosts, username_for, workstation_roles=("Windows workstation", "macOS workstation")):
        self.by_name = {}
        self.users = []
        self.services = []
        self.machines = []
        self.privileged = []
        self.tier = {}

        stations = [h for h in hosts.values()
                    if getattr(h, "role", "") in workstation_roles]
        stations.sort(key=lambda h: h.name)

        for h in stations:
            n = username_for(h.name)
            acct = self.by_name.get(n)
            if acct is None:
                acct = Account(n, "user", OK, host=h)
                self.by_name[n] = acct
                self.users.append(acct)
            self.machines.append(Account(h.name + "$", "machine", OK, host=h))

        jump = hosts.get(H("MGMT1"))
        for name, tier, note in PRIVILEGED_ACCOUNTS:
            a = Account(name, "privileged", OK, host=jump, note=note)
            a.spn = None
            self.by_name[name] = a
            self.privileged.append(a)
            self.tier[name] = tier

        for name, host_suffix, svc, note in SERVICE_ACCOUNTS:
            h = hosts.get(H(host_suffix))
            if h is None:                     # inventory changed — skip rather than invent a host
                continue
            a = Account(name, "service", OK, host=h,
                        spn=f"{svc}/{h.fqdn}" if svc else None, note=note)
            self.by_name[name] = a
            self.services.append(a)

        self._assign_states()

    # ------------------------------------------------------------------ states
    def _assign_states(self):
        """Mark the small number of accounts that are not in good standing.

        Proportions are deliberately modest. `ndr-password-spray` is detectable *because* it is
        the only thing producing a burst of KDC_ERR_PREAUTH_FAILED; if the baseline generates
        failures at a comparable rate the scenario stops being distinguishable and the demo
        loses its point. Baseline failures must stay scattered across users and hours, and must
        mostly end in a success.
        """
        pool = [a for a in self.users]
        rng.shuffle(pool)
        picked = iter(pool)

        self.disabled = [next(picked) for _ in range(2)]
        for a in self.disabled:
            a.state = DISABLED
            a.note = "left the company; a stale session still retries"

        self.expired = [next(picked) for _ in range(rng.randint(1, 2))]
        for a in self.expired:
            a.state = EXPIRED
            a.note = "password past maximum age"

        self.lockouts = [next(picked) for _ in range(rng.randint(2, 3))]
        for a in self.lockouts:
            a.state = LOCKOUT
            a.note = "locks out after repeated bad passwords"

        # ~4% of *logons* are mistyped once and succeed on the retry. This is a per-event rate,
        # not a set of clumsy people: anyone can fat-finger a password, and binding it to a
        # fixed handful of users would put a suspicious cluster of failures on those accounts —
        # which is precisely the shape password-spray detection looks for.
        self.fumble_rate = 0.04

        # A few logons for principals that do not exist at all: typo'd names, a decommissioned
        # account still in someone's saved credentials.
        self.unknown_names = ["jmorrsion", "admin1", "tdaviess"][:3]

    # ------------------------------------------------------------------ lookup
    def get(self, name):
        return self.by_name.get(name)

    def for_host(self, host):
        """The user account that normally signs in at this workstation."""
        for a in self.users:
            if a.host is host:
                return a
        return None

    def summary(self):
        return {
            "users": len(self.users), "services": len(self.services),
            "privileged": [f"{a.name}(t{self.tier[a.name]})" for a in self.privileged],
            "machines": len(self.machines),
            "disabled": [a.name for a in self.disabled],
            "expired": [a.name for a in self.expired],
            "lockouts": [a.name for a in self.lockouts],
            "fumble_rate": self.fumble_rate,
            "unknown": list(self.unknown_names),
        }
