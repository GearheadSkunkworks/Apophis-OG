# Apophis 5.5.1

Version 5.5.1 is a fix release from a full review of the code, plus a local agent API. The no-module baseline is still pinned at 466,343 packets. One generated record changes: the SPF TXT record now carries one proper string, so its bytes differ and its counts do not.

## Fixed

- **Session autosave.** Autosave had stopped working; it is restored and has a test that checks it is wired in.
- **Diagram page.** A company name containing markup is now escaped, so it shows as plain text. `AT&T` still renders correctly.
- **Replay.** A missing tool no longer crashes the preflight check; it shows the install hint.
- **Server.** Certificate push validates before it flags, the session "Last" entry no longer collides, trash and restore ids are handled, a second Generate cannot claim a running one, and a faulty route returns an error instead of taking the handler down.
- **UI.** Failed fetches and status polls are handled, text from the server is escaped, and the campaign busy state clears correctly.
- **Feeds.** The PhishTank parser skips a row that raises a CSV error instead of crashing. The fuzz contract matches the 500-character note limit and the `card` field.
- **Engine.** A duplicate `txt_rdata` is removed, the exploit probe's "Probe requests" filter matches its traffic, the NFS module works on custom networks, stats files are closed, and 23 unused imports and 7 unused variables are gone with no random draw touched.

## Hardening

- **Builds and replay.** A failed build removes its partial capture. A `tcpreplay` run as root must be owned by root, and starting a replay is atomic, so a second start while one runs is refused.
- **Sensors and feeds.** Sensor calls ignore proxy environment variables and validate sensor ids. The feed cache no longer keeps secrets typed into feed URLs.
- **Campaigns and updates.** A campaign run with an invalid campaign returns a 400 error with a message. The updater takes a lock so two updates cannot run together.
- **Diagrams and tools.** Three diagrams follow remapped networks. The release tool accepts an unencrypted patch key with the passphrase read from an environment variable.
- **UI.** Corners and spacing follow the design tokens, explainer text moved into tips, a duplicate About entry is gone, and stop buttons and notes keep a stable layout.
- **Code quality.** Exception chaining and unused locals and loop variables were cleaned up under a ruff policy file, with no random draw touched.

## Agent API

- **A local API for AI agents.** Settings > Agent access turns on `/agent/v1/` and issues a bearer token. An agent can read the catalog and intel, build and validate campaigns, run builds as jobs, read captures and the library, and check a sensor. `docs/agent-api.md` lists the verbs, and `og_mcp.py` offers the same verbs as an MCP server.
- **What an agent cannot do.** Replay and sensor push have no agent verb, and a token gets 403 on every other route. An agent can stage a sensor push, which only records a request for you to confirm in Settings > Agent access. The sensor key never passes through the agent. Every call is written to an audit log in the settings folder.
- **Scripts that call replay or push need the page cookie.** The replay and sensor push POST routes and `/api/agent/*` now require the page's `og_ui` cookie, so a curl script calling `/api/replay/*` or `/api/sensor/push` without it gets 403. Any local HTTP client can still read that cookie, so this stops agent tools, not someone with a shell on the machine.

## The macOS app

- This is a signed patch for 5.5.0 apps. Use Update in the top bar; no reinstall is needed.
- Known remaining items from the review are tracked privately for a later release.
