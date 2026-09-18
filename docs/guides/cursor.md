# Cursor

Use the same local MCP gateway from Cursor. The gateway is the enforcement
boundary, so a server added later is still evaluated when routed through it.

## Install → init

```bash
npm install -g @cirvix_ai/agent-control
mkdir my-agent-policy && cd my-agent-policy
cirvix init
cirvix policy check
```

## Connect

Copy upstream definitions into a separate `mcp-upstreams.json`, then replace the active client map with a gateway-only entry. Remove direct upstream entries; do not point the gateway back at the file you just replaced:

```json
{
  "mcpServers": {
    "cirvix": {
      "command": "cirvix",
      "args": ["gateway", "--servers", "/absolute/path/to/mcp-upstreams.json", "--policy", "/absolute/path/to/cirvix.policy"]
    }
  }
}
```

Do not put API keys in this file. Use secret handles or the upstream server's
documented environment mechanism.

## Policy → test → verify

```bash
cirvix policy test
cirvix check --action fs.read --resource .env
cirvix check --action shell.exec --resource "rm -rf /"
cirvix audit verify
```

Expected results depend on the loaded policy. `check` is hypothetical and does not write an audit record; a hold also exits `0`. Verify actual benign routed calls and a nonzero expected audit count. Editor built-ins and direct upstream calls remain outside coverage.
