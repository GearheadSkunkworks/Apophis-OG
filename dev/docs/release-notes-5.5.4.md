# Apophis 5.5.4

Version 5.5.4 makes the form safer to change and stops a rebuild from overwriting an earlier capture. The no-module baseline is still pinned at 466,343 packets.

## Easier to change your mind

- **Timing indicator.** The capture-day header shows "Timing: N moved" with a Reset all button. It counts every moved scenario, including unticked ones, such as "Timing: 3 moved (1 unticked)". A move on an unticked scenario is kept and returns when you tick it again.
- **Clean baseline clears every move.** It already cleared the ticked scenarios. It now also puts every moved scenario back to its own time.
- **Undo.** After a starting-point button, Select all, Clear selection, loading a named session, Start fresh, Reset all or Import setup, a message with an Undo button appears for ten seconds. Ctrl+Z (Cmd+Z on a Mac) does the same, except while you type in a text field. Undo after Start fresh still works once the page reloads.
- **Leave warning.** The campaign editor asks before you leave the page with unsaved changes.
- **Changed from default.** Settings, Sessions lists what differs from a fresh start: ticked scenarios, timing moves, size, company, industry, recipes and an armed campaign.
- **Export and import a setup.** Settings, Sessions saves the form to `apophis-setup.json` and loads one back. Import checks the file: a file that is not a setup, is too large, is from a newer version or holds nothing is refused, values out of range are brought back into range, and anything named like a key, password or token is ignored.

## Sessions save more

- A session now also saves the size and whether a campaign is armed for the next capture. Sessions saved before 5.5.4 still load.
- A restored size wins over Settings, Default size. Default size applies on a fresh start, when no size is saved, and changing it in Settings sets the size at once.
- A restored armed choice is dropped the first time you open or load a campaign, so a campaign is never armed by surprise.
- The build progress bar now reads against the same size estimate the form shows, so the two agree.

## Builds keep the earlier capture

- **Rebuilding with different settings keeps the earlier build** in `earlier-builds/<UTC time>-<name>/` inside the output folder, with its key log, manifest, reports and certificates. Before, a new build overwrote it.
- **A rebuild with identical settings replaces the files**, so you keep one set. A new app version counts as different settings.
- **A stopped or failed build puts the earlier build back.**
- **Captures.** Kept builds appear under Earlier captures and in the import list of recent captures, with a Kept tag. Open report, Use for replay, Remove and Restore on a kept build act on its own folder, never on the current capture. After a build that displaced one, the result shows "Earlier build kept in" and the folder. The command line prints where the earlier build went.
- **Limits.** Certificates and a key log written outside the output folder (`--certs-dir`, `--keylog`) are still overwritten. If the app stops mid-build, a hidden `.replacing-` folder or a kept folder may remain; nothing is lost.

## Docs

The Help gains three notes: Undo a change, Export and import a setup, and Earlier builds are kept. The Sessions and Move a scenario in time articles describe the new behaviour. The Build a capture, Starting points, Size, Settings, Captures and Campaign articles are updated. The repository README now describes the 5.5 line with the current counts (79 scenarios, 52 actions, 27 feeds), and the release and macOS build pages no longer quote 5.1.0 figures.
