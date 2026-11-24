# Agent API

An outside assistant (an AI client, a script, a CI job) can drive the app through `/agent/v1/`. It can build and
validate campaigns, run builds, and read captures. It cannot replay traffic to a network and it cannot push to a
sensor: those two stay with a person in the app.

## Turn it on

Settings, Agent access, **Create token**. The token is copied to the clipboard and stored in the system keychain
(a private file beside the settings where there is no keychain). **Replace token** invalidates the old one at once;
**Turn off** removes it. The API is off until a token exists, and answers only on `127.0.0.1`.

## Calling it

Send `Authorization: Bearer <token>`. Every call is logged to `agent-audit.log` in the settings folder (the verb, the
status and the argument names; secret values are never written). A token is refused on every path outside `/agent/v1/`.

| Verb | Method | What it does |
|---|---|---|
| `verbs` | GET | The verbs below |
| `catalog/actions`, `catalog/attack`, `catalog/templates`, `catalog/feeds`, `catalog/modules`, `catalog/capabilities` | GET | What the app can build |
| `intel/fetch`, `intel/parse` | POST | Read a threat feed or pasted report |
| `campaign/compile`, `campaign/validate`, `campaign/estimate`, `campaign/preview`, `campaign/run` | POST | Turn intelligence into a campaign and check it |
| `library/list`, `library/save`, `library/load`, `library/import` | GET, POST | The saved campaign library |
| `build/submit`, `build/status`, `build/cancel` | POST, GET, POST | Start a build, poll it, stop it |
| `capture/list`, `capture/manifest` | GET | Finished captures |
| `sensor/check`, `sensor/preflight` | POST | Read-only checks against a sensor |
| `sensor/stage`, `sensor/pending` | POST, GET | Stage a certificate push for a person to review |

Request and reply bodies are the same JSON the app uses (see the Campaign guide). A build runs in the background:
call `build/submit`, then `build/status` until it stops running.

`build/submit` takes the same fields as the app's Generate, including `shifts`: an object of scenario name to whole minutes that moves a scenario in time, for example `{"npm-nightly-backup": -30}`. A scenario that is not selected, cannot move or is out of its range gets a 400 error with the allowed range. Linked scenarios move together, so give both the same value or leave the partner out. `catalog/modules` lists each scenario's `start_min` and `end_min` (minutes after 05:00), `shift_limits` and `shift_partner`. `campaign/run` has no `shifts`; a campaign's start has its own option.

## Sensors

Send the sensor address only. The app uses the key saved for that sensor in Settings; a request that carries a key is
refused. `sensor/stage` records the sensor and certificate folder as a pending push. A person sees it under Settings,
Agent access, presses **Review**, and presses the push button in the app. A staged push expires after 15 minutes.

## MCP

`og_mcp.py` is a small stdio adapter that exposes each verb as a tool. Point an MCP client at it:

```json
{"command": "python3", "args": ["og_mcp.py"], "env": {"OG_AGENT_TOKEN": "<token>"}}
```

`OG_URL` overrides the address (default `http://127.0.0.1:8765`).

## Limits

The replay and push routes also require the browser session the app gives its own page, so a client that leaves the
token off cannot call them. That check stops an agent tool that speaks HTTP. It does not stop a process that can run
programs on the same machine, which can start replay tools directly.
