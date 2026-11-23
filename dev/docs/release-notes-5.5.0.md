# Apophis 5.5.0

Version 5.5.0 extends the campaign builder: it turns threat reports and CVEs into traffic you can preview, and lets you add campaign actions without writing Python. Generated captures are unchanged: the no-module baseline is still pinned at 466,343 packets.

## What is new

- **Indicator cards.** Paste a threat report or load a feed and each indicator gets a card. A card names the malware family or tool the indicator is linked to, using a bundled offline catalog of 40 families. Nothing is looked up online.
- **CVE profiles.** A CVE from the CISA known-exploited catalog is matched to a product class by its vendor, product and name. 683 of the 1,790 catalog entries can be played as traffic. The card shows CISA's own description and required action.
- **Traffic preview.** Each indicator shows the traffic it will send before you build, and the plan summary lists the stages a selection will produce.
- **Exploit probe.** A new inert action, `exploit_probe`, sends the request pattern of a CVE without any payload.
- **Actions as data.** A JSON spec can now describe an HTTP or HTTPS campaign action. One example ships (`admin_panel_probe`). To add your own, point `OPENGENERATOR_ACTION_SPECS` at a folder of specs. Specs cover web requests and plain-text TCP conversations (SMTP, FTP, banners), and a spec can name the role it applies to so the compiler places it automatically. Other protocols still need a Python action.
- **Goal modes and starter templates.** The builder offers seven goal modes and five offline starter templates, so a campaign can start from an objective instead of a blank page.
- **CSV and MISP exports.** A build now also writes a CSV and a MISP event file beside the pcap.
- **A cleaner feed list: 27 feeds, each useful.** Feeds whose indicators cannot become traffic were removed: MalwareBazaar (file hashes only), Feodo Tracker (empty after botnet takedowns), the Emerging Threats compromised list (its role sends no traffic) and Botvrij (stale). New: CINS Army, IPsum, Phishing.Database (addresses and domains), PhishTank, SANS ISC DShield, Spamhaus DROP, Shodan search (needs your own key), SiberKapan, Infoblox, APNIC honeynet (SSH, Telnet, malware URLs) and CERT Polska domains.
- **Feed tips.** Each feed's info badge says why it is offered, which indicator types it gives and which of them send traffic.
- **Safer report pasting.** Prose reports keep only addresses and defanged hosts. Live links are treated as citations, and domains that are not real top-level domains (file names, method names) are rejected.
- **Docs.** The campaign guide covers the indicator list, report pasting, adding malware families, CVE profiles and data-defined actions. The action reference is regenerated (52 actions).

## The macOS app

- Apple Silicon (arm64) only. No Python install needed; Python and `cryptography` are inside the app.
- It is **ad-hoc signed, not notarized**. On another Mac the first launch needs right-click > Open (then confirm).
- `tcpreplay` is not bundled. Replay needs `brew install tcpreplay`; everything else works without it.
- This is a full release. Installed 5.4.x apps do not update to it by themselves: download it from the Releases page. From 5.5.0 on, Update in the top bar replaces the whole app with the newest full release from any older version, then offers any patch for it. The old app is kept in the settings folder.
