# Apophis 5.3.0

Apophis (OpenGenerator) writes a pcap of a normal business day for a made-up company, with security, performance and cryptography scenarios on top, for testing and demonstrating network sensors. Version 5.3.0 is a redesign of the interface plus an in-app update system. Generated captures are unchanged: the no-module baseline is still pinned at 466,343 packets.

## What is new

**A new interface**
- **Compose the day.** A capture-day timeline (Timeline or Map view) shows what is in the capture. Starting points (Security, Performance, Crypto posture, OT / ICS day, Incident replay) are toggles: lit means on, and clicking one adds its scenarios without clearing the rest. One button selects all, clears, or selects none.
- **Scenario picker.** Categories open into their scenarios with tick boxes. Each scenario card has an animated explainer, protocol checks, and a note on whether its size is fixed or grows with the size setting.
- **Honest size estimate.** Quick sample, Standard and Full day presets, with an estimate built from measured per-scenario profiles.
- **Captures.** Remove and restore captures (nothing is deleted; removed captures go to a holding folder), see packets by scenario, and open the build manifest.
- **Lab.** A four-step capture import with a plain-English "Check the rebuild".
- **Settings.** Defaults, session restore, API keys, and five palettes in light and dark.
- **Layout stability.** The screen no longer jumps when you select; see `docs/design-language.md`.

**Updates**
- An **Update** button in the top bar checks this repository's Releases and installs signed patch updates (X.Y.Z) by itself. Full releases (X.Y.0), like this one, are downloaded from the Releases page. Every patch is verified with an Ed25519 signature before it is installed, and again on every start. See `docs/release.md`.

**Engine**
- The wireless-degradation scenario now emits its own CAPWAP and DTLS traffic with valid IPv4 fragmentation.
- Each build writes a manifest with the packets per scenario and a checksum.
- A TCP sequence-number wrap that crashed one scenario at full size is fixed.
- New category: Multi-stage campaign.

**Hardening**
- The local server refuses to be framed by other pages, and replay interface names are checked.
- Exported diagrams no longer load fonts from the internet.

## The macOS app

- Apple Silicon (arm64) only. No Python install needed; Python and `cryptography` are inside the app.
- It is **ad-hoc signed, not notarized**. On another Mac the first launch needs right-click > Open (then confirm).
- `tcpreplay` is not bundled. Replay needs `brew install tcpreplay`; everything else works without it.
