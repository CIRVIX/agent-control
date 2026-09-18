# Cursor

Route Cursor's MCP traffic through the Cirvix gateway.

## Setup

```bash
cirvix init
```

Cursor reads `~/.cursor/mcp.json` (global) and `.cursor/mcp.json` (per project).
Copy the servers you have today into a file Cirvix will front — for example
`.cirvix/servers.json` — and replace the block with a single entry:

```jsonc
{
  "mcpServers": {
    "cirvix": {
      "command": "cirvix",
      "args": ["gateway", "--servers", ".cirvix/servers.json"]
    }
  }
}
```

Restart Cursor. The same tools appear, namespaced `server__tool`, and every call
now produces a decision record.

## Verify it

```bash
cirvix status          # Protected should count Cursor
cirvix logs --last 20  # what it actually did
```

## Hosted servers

Cursor supports MCP servers reached over HTTP as well as stdio. Cirvix governs
both — a spec with a `url` is proxied over Streamable HTTP or HTTP+SSE, a spec
with a `command` is spawned:

```jsonc
{
  "mcpServers": {
    "local-files": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "."]
    },
    "hosted-vendor": {
      "url": "https://mcp.vendor.example/v1",
      "headers": { "authorization": "Bearer sec_handle_02" }
    }
  }
}
```

The hosted case is the one worth governing most: it is the server you did not
write, cannot read the source of, and whose tool descriptions enter the model's
context with the authority of a system message. Cirvix fingerprints each tool
definition on first sight and withholds any that changes until it is re-approved
— so a vendor silently editing a description does not silently change what your
agent believes.

## What this does not cover

- Cursor's own edit and terminal features, which are not MCP.
- Rules files (`.cursorrules`). Cirvix can stop an *agent* from writing one — see
  `policies/filesystem.policy` — but it does not read them.
