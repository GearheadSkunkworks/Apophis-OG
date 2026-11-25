# Apophis 5.5.5

Version 5.5.5 is a hardening patch. It adds no feature and changes no capture. The no-module baseline is still pinned at 466,343 packets.

## Hardening

- **Sensor check and detection scoring need the page cookie.** `POST /api/sensor/check` and `POST /api/campaign/feedback` can use the sensor key you stored in Settings, so they now require the session cookie the app's page receives, unless the call arrives as an agent verb. A script or other local program that calls them without the cookie now gets 403, as 5.5.1 did for replay and sensor push. The app's own page sends the cookie, so nothing changes in the interface.
- **The agent verb still works.** `sensor/check` arrives with a token and is written to the audit log, so it is unaffected. An agent token still cannot reach these two routes directly, or any route outside `/agent/v1/`.
- **Clearer message.** The 403 now reads "forbidden: replay, sensor push, sensor check and detection scoring are done by a person in the app".

## What this does and does not stop

Any local program can still read the cookie. The check stops other programs and agent tools that speak HTTP, not someone with a shell on the machine.

## If a script breaks

A script that called Check sensor or detection scoring without the cookie needs to send the page's `og_ui` cookie, or the step is done in the app.

## Docs

The agent API page, the Help article on the agent's limits, and the campaign contract and design notes describe the new rule.

## The macOS app

Apple Silicon (arm64) only, ad-hoc signed and not notarized. `tcpreplay` is not bundled. This version ships as a signed patch for 5.5.x apps.
