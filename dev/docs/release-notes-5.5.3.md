# Apophis 5.5.3

Version 5.5.3 adds eight scenarios and fixes the update path from 5.5.0. The no-module baseline is still pinned at 466,343 packets; the new scenarios are separate modules and change nothing unless you select them.

## Update fix

- **5.5.1 and 5.5.2 cannot be installed by a 5.5.0 app. 5.5.3 can.** Both patches imported a Python module (`secrets`) that the 5.5.0 app does not contain. A 5.5.0 app that installed one failed to start and rolled back to 5.5.0, with settings untouched. 5.5.3 removes that import.
- **What to do.** On 5.5.0, update once, straight to 5.5.3. An app that already rolled back needs nothing else.
- **A permanent check.** `tests/test_frozen_imports.py` fails when the patch tree imports a module the shipped app lacks. The list it uses, `tools/frozen-modules.txt`, is refreshed on every full release (see `docs/release.md`).
- **Clearer text.** If a new version does not start, the dialog now says "The new version did not start. Open the app again from Applications: it starts the version you had, and nothing is lost."

## New scenarios

The scenario count goes from 71 to 79 registry entries (77 ordinary scenarios). Incident replay grows from 9 to 16 scenarios and Security from 34 to 35. Replays carry medium confidence, and the Turla one low. CVE numbers and some details come from secondary reporting and are not checked against the vendors' advisories.

- **ARMORY CASTLE vCenter chain** (`ir-armorycastle-vcenter-cve123890`). An edge appliance is exploited, an internal appliance writes to the vCenter directory with an accepted empty-password bind, adds an SSO administrator and logs in, and secrets leave in bulk.
- **Outlook NTLM leak** (`ir-outlook-ntlm-leak-cve124194`). Workstations send NTLM over SMB and WebDAV to an outside host, then the account is sprayed at the mail portal.
- **FreeSWITCH SIP MESSAGE** (`ir-freeswitch-sip-message-cve116779`). A scanner sweep, SIP MESSAGE requests to the api handler, a callback and premium-rate toll fraud.
- **OPTIMJACK skimmer** (`ir-optimjack-supplychain`). A third-party script changes size and visitors' browsers post card-shaped data to new domains.
- **Puppet report RCE** (`ir-puppet-report-rce-cve115731`). An outside agent enrols and sends an oversized report; the server then calls out, opens SSH and sends a key out.
- **OpenSSH SSHole** (`ir-openssh-sshole-cve123158`). A wave of SSH connections from varied clients, a script fetch and Stratum cryptomining.
- **Turla Exchange implant** (`ir-turla-cereal-exchange`). Mail-borne tasking and outbound SMTP replies from the mail server. It follows the older Turla Exchange pattern, not ESET's description of Cereal, and says so in its card.
- **The Gentlemen ransomware chain** (`ndr-gentlemen`). A Cobalt Strike team server of its own, rclone-style exfiltration and a mass SMB rewrite with a `.gentlemen` extension. It follows vendor threat reports; there is no CISA advisory.
- **Diagrams.** All eight open a diagram from Visualize. The nine older replays (two NetScaler, BeyondTrust, Metabase, SharePoint, PAN-OS GlobalProtect, vCenter, the WordPress upgrade race and the Linux IP-options flaw) now have one too, so every incident replay has a diagram, and a test keeps it that way. Each diagram carries a Facts and limits note.
- **Fact checks.** CVE and exploitation-date notes were re-checked against press and vendor reports. The BeyondTrust note now says its dates were checked that way (advisory BT26-05), not read from NVD.
- **Wider exploit-probe classes.** CVE matching now recognises Puppet and Perforce (remote management), MONAI and REDCap (web applications), and Synology and DiskStation (network devices).

## Docs

The Help gains a note, The incident replays, and updates its Update article and the CVE profile note. The README scenario count and the scenario-metadata and redesign records show the new totals. `docs/release.md` describes the frozen-module check and when to refresh its list.

## The macOS app

Apple Silicon (arm64) only, ad-hoc signed and not notarized. `tcpreplay` is not bundled. This version ships as a signed patch for 5.5.x apps.
