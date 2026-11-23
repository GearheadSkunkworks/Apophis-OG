# OpenGenerator 5.1.0

OpenGenerator writes a pcap of a normal business day for a made-up company, for testing and demonstrating network sensors. Version 5.1.0 adds the **Campaign Builder**: you give it threat indicators, and it adds a matching attack sequence to the capture as real, valid packets.

## What is new

**Campaign Builder**
- **Indicators from 17 feeds, or your own list.** Read from public feeds, a pasted list or a file (text, CSV, STIX, MISP and OTX formats; defanged forms such as `hxxp://example[.]com` are accepted). Four feeds need a free API key.
- **50 actions mapped to MITRE ATT&CK**, covering all 15 tactics: beacons, DNS patterns, scans, authentication attempts, remote-service calls and file transfers. Every body is inert filler; there is no exploit code.
- **12 malware-family look-alike beacon profiles** that copy a family's publicly documented URI paths, user agent, cadence and reply sizes. A profile is a look-alike, not a claim about every build.
- **Stage editor** with live validation, a timeline and an ATT&CK tactic strip, plus a saved-campaign library.
- **Campaign diagrams**, in plan mode (before a build) and run mode (after), as printable pages with a timeline, flow map, indicator trace, ATT&CK coverage and capture filters. Locations come from bundled country data; no lookups leave your machine.
- **Safe addressing by default.** Indicator addresses are re-addressed into `198.18.0.0/15` unless you confirm real mode (`--confirm-real-addresses`, or typing `REAL` in the app). Nothing is sent to an indicator.
- **Outputs** beside the pcap: campaign JSON, a STIX bundle of the indicators on the wire, an ATT&CK Navigator layer, and Markdown and HTML reports.
- **Optional sensor scoring.** After a replay, the app can ask a sensor which detections fired and score the campaign per technique. It is built against the documented detection format and tested with fixtures only. **It has not been verified against a live sensor**, so treat scores as provisional.
- **Optional macOS Keychain storage** for feed API keys (macOS only, off by default). Without it, keys stay in the page.

**Hardening and tooling**
- Fuzz testing of the indicator parsers, and SSRF and size limits on feed fetching (the "From a URL" feed accepts only https and public hosts).
- Release tooling: a promote and verify script that checks the release folder, and a build guide for the macOS app.

**Also in this release line:** more scenarios and protocol emitters, and fixes to ordinary-day traffic. As a result the default capture is no longer the same size as in earlier versions (the no-module baseline at `--scale 0.004` is now 466,343 packets).

## The macOS app

- Apple Silicon (arm64) only.
- No Python install needed; Python and `cryptography` are inside the app.
- It is **ad-hoc signed, not notarized**. On another Mac, the first launch needs right-click > Open (then confirm). If macOS says it cannot verify the app, clear quarantine with `xattr -dr com.apple.quarantine OpenGenerator.app`.
- `tcpreplay` is not bundled. Replay needs `brew install tcpreplay`; everything else works without it.

## Getting started

Unzip, open the app, and use the **Campaigns** card; or run from source (`cd dev && python3 server.py`). See `dev/docs/campaign-guide.md` for a walkthrough of the workflow, safety model and command-line flags.
