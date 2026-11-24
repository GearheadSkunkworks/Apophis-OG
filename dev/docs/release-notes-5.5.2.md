# Apophis 5.5.2

Version 5.5.2 lets you move a scenario in time. With no moves set, the build is unchanged and the no-module baseline is still pinned at 466,343 packets.

## What is new

- **Move a scenario along the capture day.** Drag its marker on the timeline, press Alt with the left or right arrow (1 minute; add Shift for 15), or type minutes in Move by on the scenario card. Reset returns it to its default, and Escape during a drag puts everything back. A faint dashed mark shows where a moved scenario started.
- **Limits.** Scenarios stay inside the capture day, 05:00 to 21:00, with a small margin at each end. The nightly backup, one Volt Typhoon scenario and the three crypto posture scenarios have a narrower range. A value past a limit is refused with the allowed range, never trimmed.
- **Linked scenarios move together.** The firewall update with the edge exploit, and the TCP loss storm with Salt Typhoon.
- **Scenarios that cannot move.** The OT sanctioned writes (tied to the baseline's shift changes), a custom import, and a campaign. A campaign keeps its own Start option in the campaign editor.
- **Moves are visible everywhere.** The diagrams, the generation report and the manifest show the moved times, and moves are saved with the session.
- **Packet counts.** A moved scenario draws from its own random streams, so the rest of the day changes only slightly. The moved scenario's packet count differs from the unmoved one by a few percent.
- **Fixes that follow the window.** Anonymous FTP syslog rows and BeyondTrust session rows now move with their scenario's window.

## Agent API and routes

- `build/submit` and `POST /api/generate` accept `shifts`, an object of scenario name to whole minutes. `/diagram` accepts `shifts` too.
- `/api/modules` (and `catalog/modules`) adds `start_min`, `end_min`, `shift_limits` and `shift_partner` for each scenario.

## Docs

The Help article Move a scenario in time covers the controls, limits and the API, and the agent API page lists `shifts` under `build/submit`.
