# MCP

Cirvix is an MCP server that fronts other MCP servers. Anything that speaks MCP
can be governed by it, whether or not there is a named integration for it.

## The shape

```
any MCP client ──▶ cirvix gateway ──▶ upstream A (stdio)
                        │        ──▶ upstream B (http)
                        │
                        ├─ tools/list     aggregated, namespaced, pinned
                        ├─ tools/call     evaluated, then forwarded or refused
                        └─ everything else  passed through
```

## Transports

| | Upstream (Cirvix → server) | Downstream (client → Cirvix) |
|---|---|---|
| stdio | ✅ | ✅ |
| Streamable HTTP | ✅ | ✅ |
| HTTP+SSE (2024 spec) | ✅ | — use Streamable HTTP |

A server spec with `command` is spawned over stdio; one with `url` is reached
over HTTP, and which HTTP shape it speaks is discovered on first contact rather
than configured.

## Running it

Over stdio, which is what an editor does:

```bash
cirvix gateway --servers ./servers.json
```

Over HTTP, for an agent that connects to a URL:

```bash
cirvix gateway --servers ./servers.json --http --port 8787
```

The HTTP listener binds to `127.0.0.1` and refuses to bind anywhere else without
`--token`. A policy engine listening on `0.0.0.0` with no authentication is a
remote tool-execution service, and that is never what somebody meant to build.

## Four behaviours worth knowing

**Tool names are namespaced.** Two servers may both expose `search`. Upstream
tools appear as `server__tool`, because without namespacing the gateway cannot
route the call and — worse — a policy written for one server silently governs
the other.

**Tool definitions are pinned.** A tool's description is instruction text that
enters the model's context with the authority of a system message, and it is
supplied by the server, not by you. Each definition is hashed on first sight; a
changed definition is withheld from `tools/list` until it is re-approved.

**Denials are tool results, not transport errors.** A JSON-RPC error is a
transport failure and many agent runtimes surface it as a crash. A tool result
with `isError: true` is data the model reads — so the agent sees the refusal, the
policy that caused it, and the suggested alternative, and re-plans. That single
choice is the difference between a control plane and a kill switch.

**One dead upstream does not end the session.** Its tools disappear from
`tools/list`; calls to it return a clean error; everything else keeps working.

## Governing a framework instead

If your agent does not speak MCP — a LangChain executor, a CrewAI crew, a
hand-rolled loop — wrap the tools instead:

```js
import { guard } from "@cirvix/agent-control/guard";

const governed = guard.wrap(tools, { rules, cwd: process.cwd() });
```

Same engine, same rules, same decision record, same secret brokering. You give
up one property and it is stated plainly: the gateway governs tools you did not
know about because it sits on the wire, and `wrap` governs a list you handed it.

Or connect over the local control socket from any language:

```bash
cirvix runtime
```

```python
import json, socket
s = socket.socket(socket.AF_UNIX); s.connect(".cirvix/cirvix.sock")
s.send(json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize",
                   "params":{"token": open(".cirvix/socket.token").read().strip()}}).encode() + b"\n")
s.recv(65536)
s.send(json.dumps({"jsonrpc":"2.0","id":2,"method":"cirvix/authorize",
                   "params":{"tool":"shell.exec","arguments":{"command":"rm -rf /"}}}).encode() + b"\n")
print(json.loads(s.recv(65536))["result"]["decision"])   # deny
```
