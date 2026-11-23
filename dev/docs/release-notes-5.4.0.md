# Apophis 5.4.0

Version 5.4.0 adds a built-in Help view, makes the capture-day timeline easier to read, and gives the macOS app the Gearhead Skunkworks icon. Generated captures are unchanged: the no-module baseline is still pinned at 466,343 packets.

## What is new

- **Help.** A ? icon in the top bar opens Help, and Ctrl or Cmd + K opens it from anywhere. Search in plain words ("replay a capture", "make a pcap") or browse 17 articles: four step-by-step workflows (build a capture, import and validate your own pcap, replay a capture, build a campaign), one explainer for each Lab tool, and short notes on size, networks, reports, sessions, settings and updates. Help lists the articles for the screen you came from first.
- **Clearer capture-day timeline.** Scenario blocks are separated, with a gap between neighbours and alternate shading. Point at a block to see its name; the other blocks dim and its time span is shaded across every lane.
- **App icon.** The app and its zip show the Gearhead Skunkworks mark instead of a generic icon.

## The macOS app

- Apple Silicon (arm64) only. No Python install needed; Python and `cryptography` are inside the app.
- It is **ad-hoc signed, not notarized**. On another Mac the first launch needs right-click > Open (then confirm).
- `tcpreplay` is not bundled. Replay needs `brew install tcpreplay`; everything else works without it.
- This is a full release. Installed 5.3.x apps do not update to it by themselves: download it from the Releases page.
