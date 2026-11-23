# Campaign Builder guide

For someone meeting OpenGenerator for the first time. It covers what a campaign is, what is safe about it, and how to go from a list of threat indicators to a capture, a diagram and a sensor check.

## What a campaign is

OpenGenerator writes a pcap of a normal business day. The Campaign Builder adds a **campaign** to that day: an attack sequence built from threat indicators (addresses, domains, URLs, file hashes, CVE numbers). You give it indicators; it decides what each one would plausibly be used for, arranges the result into stages that follow the MITRE ATT&CK tactics, and writes the matching network behaviour into the capture as real packets.

The aim is to give a network sensor something realistic to detect, and to let you check afterwards whether it did. A campaign is a plan first and traffic second. You can read, edit and save the plan before anything is generated.

Short vocabulary:

- **Indicator**: one item from a feed or your own list, such as `203.0.113.7`, `update.example.net` or `CVE-2026-0001`.
- **Role**: what the indicator is for in an attack: command and control (`c2`), `payload` delivery, `exfil`, `scanner`, `brute`, `phishing`, `tor`, `compromised`, or `vulnerability` for CVEs. Indicators with no clear role stay `unknown` and are never guessed.
- **Action**: one network behaviour the generator can write, such as a beacon, a port scan or an SMB archive write. There are 52 (see [action-reference.md](action-reference.md)); more can be added as data files, see "Adding to the builder" below.
- **Stage**: a group of actions under one ATT&CK tactic, ordered in time.
- **Family profile**: a beacon look-alike for a named malware family, such as its URI paths, user agent, cadence and reply sizes. There are 12.

## Safety model

- **Real packets, not exploits.** Every packet is valid (the independent check `checks/check_rfc791.py` verifies a whole capture), but every body is inert filler. No action carries exploit code, shellcode, working malware or a payload that does anything when decoded. File transfers use the correct file signature followed by random bytes.
- **Mapped addresses by default.** Public indicator addresses are re-addressed into `198.18.0.0/15`, a range reserved for benchmarking, so the capture never contains a real third party's address. Domains, URLs and hashes are kept as written, because they are strings in the traffic and not routable destinations.
- **Real mode needs a typed confirmation.** `--address-mode real` (or the address-mode choice in the GUI) keeps the indicators' own addresses. The CLI also requires `--confirm-real-addresses`, and the GUI asks you to type `REAL`. Use it only when you understand that a replay of that capture puts those addresses on your wire.
- **No real host is contacted.** Building a capture writes a file. Nothing is sent to an indicator's address, resolved or fetched. Feeds are only read from the feed publisher, and the sensor query after a replay is read-only.
- **Deterministic builds.** The same indicators, options and date give the same campaign and the same packets, so a result can be repeated and compared.
- **Feed limits.** The "From a URL" feed accepts only `https` and only public hosts (checked against private and loopback ranges). Your API keys are not written into campaign files or reports.

## Workflow

1. **Indicators.** Take indicators from a public feed, a pasted list or a file. Text, CSV, STIX, MISP and OTX formats are read, and defanged forms such as `hxxp://example[.]com` are fine. Each indicator is classified (type, defanged or not, a score, tags) and given a role from the words around it.
2. **Roles.** Review the roles. You can change a role by hand; a role you set is kept. `--campaign-explain` on the command line prints why each indicator became each stage and action.
3. **Compile.** The compiler turns indicators and roles into stages. For example a `c2` address becomes a beacon, a `scanner` becomes a scan, a `payload` URL becomes a download. A malware family named in an indicator's tags selects a family profile.
4. **Stage editor.** The Build step shows stages and actions with live validation, a timeline and an ATT&CK tactic strip. Reorder, remove, add and set parameters.
5. **Options, goal and family.** Choose which stages to include and pick a family profile for beacons, or leave it on automatic. A **goal** (Lateral movement, Credential theft, Data theft, Ransomware, C2 beaconing, Reconnaissance and initial access) fills in the stages and beacon count for you; you can still change them afterwards. **Start from a template** loads a small indicator set built from documentation addresses and example domains, plus its goal, so a campaign builds with no feed and no network.
6. **Save and library.** Save the campaign JSON. The library lists saved campaigns for reuse.
7. **Generate.** The campaign is built into the capture together with the business day. The address mode is chosen here.
8. **Results.** The results card shows what ran, what was skipped or failed, packet counts and the files written beside the pcap.
9. **Campaign diagram.** "Preview diagram" (before a build) and "Open the campaign diagram" (after) produce a printable page with a timeline, flow map, stage detail, indicator trace, ATT&CK coverage and capture filters. Each filter is checked against packets the action really writes. Country-level locations come from bundled data; no lookup leaves the machine.
10. **Sensor check and scoring.** After you replay the capture, the sensor check asks the sensor which detections fired and scores the campaign per technique and per action (`detected`, `related`, `missed`). The query is read-only.
11. **Board.** A board shows the campaign on a map.

Files written beside the pcap: `<prefix>.campaign.json`, `<prefix>.campaign-iocs.stix.json` (only the indicators that appear on the wire, as they appear), `<prefix>.attack-navigator.json`, `<prefix>.campaign-report.md`, `<prefix>.report.html`, `<prefix>.indicators.csv` (every indicator, the address it has in the capture and whether it is on the wire; cells that start with `=`, `+`, `-` or `@` are quoted so a spreadsheet does not run them) and `<prefix>.misp-event.json` (a MISP event of the indicators that are on the wire; it imports into a MISP server or back into this builder).

## The actions by ATT&CK tactic

The full table, with a description, techniques, protocols and parameters for each action, is [action-reference.md](action-reference.md). It is generated from the registry:

```bash
cd dev
python3 tools/gen_action_table.py          # rewrite docs/action-reference.md
python3 tools/gen_action_table.py --check  # exit 1 if it is out of date
```

To see the same list from the command line: `python3 opengenerator_build.py --list-actions`.

Counts per tactic: Command and Control 9, Credential Access 6, Discovery 5, Exfiltration 5, Collection 3, Initial Access 3, Lateral Movement 3, and 2 each for Reconnaissance, Resource Development, Execution, Persistence, Privilege Escalation, Stealth, Defense Impairment and Impact. The campaign diagram page for the Campaign Builder computes these from the registry on every render, so treat that page and the generated reference as the source if the numbers here ever differ.

## Feeds

`python3 opengenerator_build.py --list-feeds` prints the current list. Feeds marked "key" need a free API key.

| Feed id | Source | Key |
|---|---|---|
| `circl` | CIRCL OSINT (MISP feed) | no |
| `otx` | AlienVault OTX pulses | key (`OTX_API_KEY`) |
| `url` | Any public https URL you give | no |
| `threatfox` | ThreatFox (abuse.ch) | key (`ABUSECH_AUTH_KEY`) |
| `urlhaus` | URLhaus (abuse.ch) | key (`ABUSECH_AUTH_KEY`) |
| `c2intel-ip` | C2IntelFeeds addresses, 30 day | no |
| `c2intel-domain` | C2IntelFeeds domains, 30 day | no |
| `blocklist-ssh` | blocklist.de SSH attackers | no |
| `blocklist-login` | blocklist.de login attackers | no |
| `blocklist-mail` | blocklist.de mail attackers | no |
| `cins-army` | CINS Army bad actors | no |
| `ipsum` | IPsum, listed on 3 or more blocklists | no |
| `phishing-db-ips` | Phishing.Database active phishing addresses | no |
| `phishing-db-domains` | Phishing.Database active phishing domains | no |
| `phishtank` | PhishTank verified online phishing URLs | no |
| `dshield` | SANS ISC attack sources (DShield) | no |
| `spamhaus-drop` | Spamhaus DROP netblocks (one address stands in per block) | no |
| `shodan` | Shodan search (exposed hosts and their CVEs; query box, default `has_vuln:true`) | key (`SHODAN_API_KEY`) |
| `siberkapan` | SiberKapan daily threat feed (MISP feed) | no |
| `infoblox` | Infoblox threat intelligence (MISP feed) | no |
| `honeynet-ssh` | APNIC honeynet SSH brute force | no |
| `honeynet-telnet` | APNIC honeynet Telnet brute force | no |
| `honeynet-urls` | APNIC honeynet malware URLs | no |
| `cert-pl` | CERT Polska malicious domains | no |
| `tor-exit` | Tor exit nodes | no |
| `openphish` | OpenPhish community feed | no |
| `cisa-kev` | CISA Known Exploited Vulnerabilities | no |

Every feed in the builder delivers indicators a campaign can put on the wire. Hover the info badge beside a feed to read which indicator types it gives and which of them send traffic; types that are not seen on the wire by themselves (file hashes, file names, e-mail addresses, CVEs of non-network products) are listed as hidden, and an indicator with no role sends nothing until you give it one. Feeds that could not produce traffic were removed: MalwareBazaar (file hashes only), Feodo Tracker (its datasets are empty after botnet takedowns, per its FAQ, checked 2026-11-23) the Emerging Threats compromised-host list (the compromised role has no campaign traffic) Botvrij (not updated since 2026-02-03) and Dataplane.org (non-commercial use only, no redistribution, which does not suit an open tool).

Each feed has its own terms of use; `--list-feeds` shows them. Feed results are cached, and `--offline` reads only the cache.

**API keys.** A key you type in the page stays in the page and is sent only to that feed's publisher. Optionally, on macOS only, the key can be kept in the macOS Keychain instead so you do not retype it. This is optional and off by default. A key can also come from the environment variable named in the table.

## Command line

Campaign flags of `opengenerator_build.py` (see `--help` for the rest, such as `--company`, `--date`, `--scale` and `--out`):

| Flag | Meaning |
|---|---|
| `--intel-file FILE` | Indicator file (text, CSV, STIX, MISP, OTX). Repeatable; all files form one campaign. |
| `--intel-feed ID[:N]` | Fetch N indicators (default 50) from a feed. Repeatable. |
| `--campaign FILE` | Build a saved campaign JSON. Repeatable. |
| `--save-campaign FILE` | Write the compiled campaign JSON. |
| `--offline` | Feeds read only the local cache. |
| `--address-mode {mapped,real}` | `mapped` (default) re-addresses into 198.18.0.0/15. `real` keeps the indicators' addresses. |
| `--confirm-real-addresses` | Required with `--address-mode real`. |
| `--list-actions` | Print the actions and exit. |
| `--list-feeds` | Print the feeds and exit. |
| `--campaign-explain` | Print why each indicator became each stage and action, no build. |
| `--only CAMPAIGN` | Select only the campaign category among the scenario modules. |

Example:

```bash
cd dev
python3 opengenerator_build.py --intel-file indicators.txt --save-campaign my.campaign.json --out my.pcap
python3 opengenerator_build.py --campaign my.campaign.json --scale 0.05 --out my.pcap
```

## What the indicator list shows

The list shows only indicators that can reasonably appear on the wire. Anything else is moved to the collapsed "Dropped" list with a reason, so nothing disappears silently.

- **Shown:** IPv4 addresses, domains and URLs, and CVEs whose record names a network-facing product (a VPN gateway, mail server, file-transfer or collaboration server, remote-management server, web application or network appliance).
- **Hidden, with a reason:** file hashes, file names, e-mail addresses, IPv6 addresses, address ranges, and CVEs with no network-facing product (browser, Office, kernel and local-privilege flaws).
- **Card per indicator:** what it is, what the campaign will send for it, and for a CVE the feed's own description and required action. A family named in the tags (for example a loader, ransomware group or C2 framework) adds a one-sentence description from a catalog bundled with the app, so nothing needs a lookup.
- **Preview traffic:** each row can show the actions, protocols and hosts that indicator alone would produce, taken from the compiler itself so it cannot disagree with the capture. Above Compile, a plan lists the stages the current selection will build.
- **Pasting a report:** text that reads as prose (an advisory or article) keeps only addresses and defanged hosts (`hxxp`, `[.]`). Live links in a report are citations, so they are not taken. Domains must end in a real top-level domain from the bundled IANA list, which removes file names and method names that look like domains. Government, standards and security-press sites are allow-listed. Hashes, file names and CVEs found in prose cannot be played; paste a list or fetch a feed for those.

## Adding to the builder

- **A family description:** add an entry to `intel/catalog.py` (name, kind, one sentence, aliases). Matching is whole-word on tags, note and source.
- **A CVE product class:** add a profile to `intel/cve_profiles.py` (a pattern, endpoints, port, TLS). The profile describes the shape of an attempt only. A regression test lists real catalog headers and the class each should land in.
- **A new HTTP(S) behaviour as data:** drop a JSON file in `netgen/campaign/actions/specs/` (or in the folder named by the environment variable `OPENGENERATOR_ACTION_SPECS`). It lists the requests a client sends and the replies it gets, plus the ATT&CK tactic and techniques. Every field is validated; bodies and replies are short printable ASCII, so a spec cannot carry a payload. A spec that fails validation is skipped and its errors are kept in `spec_actions.LOAD_ERRORS`. The action appears in the editor like any other and gets its capture filters and plain text generated from the spec. See `specs/admin_panel_probe.json`.
- **Plain-text protocols as data:** a spec with `"kind": "tcp"` describes an SMTP, FTP, IRC or custom-banner conversation instead: an optional `banner` the server sends first, then `exchanges` of `send` and `reply` text (only the `\r` and `\n` escapes, no TLS). Everything else (validation, generated filters, printable ASCII only) works as for HTTP.
- **Automatic placement:** add `"for_role": "scanner"` (or `c2`, `payload`, `exfil`, `brute`, `phishing`, `tor`) to a spec and the compiler adds the action, in its tactic's stage, for up to three indicators of that role. The stage must be switched on. Without `for_role` a spec action is added by hand in the editor. The bundled example has no `for_role`, so default campaigns are unchanged.

## Limits and known gaps

- **Sensor feedback is tested only with fixtures.** The scoring reads detections in the format the platform's API documents. It has not yet been replayed against a live sensor, so treat a score as provisional until it has.
- **Keyed feeds:** abuse.ch feeds and OTX were verified live on 2026-11-20. Other feeds were verified on 2026-11-19, and CINS Army and IPsum on 2026-11-23. A feed can change its format or terms without notice.
- Actions imitate the network behaviour that public reporting documents. A sensor's analytics may or may not flag a given action, which is what the scoring is for. A "missed" result is information, not a failure of the tool.
- A CVE becomes traffic only when its record names a network-facing product (see "What the indicator list shows"). Even then the capture holds the shape of an attempt against that product class, with no exploit content, so whether a sensor flags it depends on the sensor. Other CVEs are hidden from the list.
- The mapped address range is deterministic but not a model of your network; hosts inside the capture come from the generator's company model.
- Family profiles copy documented cadence and size defaults. Real builds are often configurable, so a profile is a look-alike, not a claim about every build.

## Troubleshooting

- **"Feed needs a key".** Add the key in the page, set the environment variable listed above, or use the optional macOS Keychain storage.
- **Feed returns nothing or an error.** Check the network, try `--offline` to use the cache, or use a file instead. The error text never includes your key.
- **Indicators land as `unknown` role.** The surrounding words did not match a role. Set the role by hand, or add a role word such as `c2` or `scanner` to the line in your file.
- **An action was skipped.** The results card and the report give the reason, for example the capture is too short for the action, or no suitable host exists (the OT actions need the OT network enabled).
- **Real mode refused.** Both the address mode and the confirmation are required: `--confirm-real-addresses` on the command line, typing `REAL` in the GUI.
- **Sensor check shows nothing.** Confirm the replay ran, the clocks match (set the time offset in the sensor check if the sensor and the capture dates differ), and the sensor address and credentials are right. A campaign with no matching detections scores every technique `missed`.
- **Capture looks wrong.** Run `python3 checks/check_rfc791.py your.pcap` for an independent packet check.
