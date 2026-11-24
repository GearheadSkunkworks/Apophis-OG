#!/usr/bin/env python3
"""MCP adapter for the agent API: a stdio server that turns each /agent/v1/ verb into one tool.

Add it to an MCP client, for example:
    {"command": "python3", "args": ["og_mcp.py"], "env": {"OG_AGENT_TOKEN": "<token from Settings>"}}
OG_URL defaults to http://127.0.0.1:8765. The adapter holds no logic of its own: the verb list comes from the running
app (GET /agent/v1/verbs), so it cannot drift, and it cannot reach replay or sensor push because the app has no such verb.
Standard library only.
"""
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("OG_URL", "http://127.0.0.1:8765").rstrip("/")
TOKEN = os.environ.get("OG_AGENT_TOKEN", "")
PROTOCOL = "2024-11-05"


def call(method, verb, body=None, query=None):
    url = "%s/agent/v1/%s" % (BASE, verb)
    if query:
        from urllib.parse import urlencode
        url += "?" + urlencode(query)
    data = None if method == "GET" else json.dumps(body or {}).encode()
    rq = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(rq, timeout=300)
    except urllib.error.HTTPError as e:
        r = e
    except OSError as e:
        return 0, {"error": "the app is not reachable at %s (%s)" % (BASE, e)}
    raw = r.read()
    try:
        return r.status, json.loads(raw)
    except ValueError:
        return r.status, {"error": raw[:200].decode("utf-8", "replace")}


def tools():
    status, js = call("GET", "verbs")
    if status != 200:
        return []
    out = []
    for v in js.get("verbs", []):
        get = v["method"] == "GET"
        out.append({"name": "og_" + v["verb"].replace("/", "_"),
                    "description": "%s /agent/v1/%s" % (v["method"], v["verb"]),
                    "inputSchema": {"type": "object", "properties": {
                        ("query" if get else "body"): ({"type": "object", "additionalProperties": {"type": "string"}}
                                                       if get else {"type": "object"})}},
                    "_m": v["method"], "_v": v["verb"]})
    return out


def handle(msg, table):
    """One JSON-RPC message in, a reply dict (or None for a notification) out."""
    mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
    if method == "initialize":
        res = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
               "serverInfo": {"name": "opengenerator-agent", "version": "1"}}
    elif method == "tools/list":
        table.clear()
        table.update({t["name"]: t for t in tools()})
        res = {"tools": [{k: v for k, v in t.items() if not k.startswith("_")} for t in table.values()]}
    elif method == "tools/call":
        t = table.get(params.get("name"))
        if t is None:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}}
        args = params.get("arguments") or {}
        status, js = call(t["_m"], t["_v"], body=args.get("body"), query=args.get("query"))
        res = {"content": [{"type": "text", "text": json.dumps(js)}], "isError": status >= 400 or status == 0}
    elif method == "ping":
        res = {}
    elif mid is None:
        return None
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}
    return {"jsonrpc": "2.0", "id": mid, "result": res}


def main():
    table = {}
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        reply = handle(msg, table)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
