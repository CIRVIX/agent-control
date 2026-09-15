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

In Cursor's MCP configuration, register Cirvix and point `--servers` at the
existing Cursor server map:

```json
{
  "mcpServers": {
    "cirvix": {
      "command": "cirvix",
      "args": ["gateway", "--servers", "/absolute/path/to/.cursor/mcp.json", "--policy", "/absolute/path/to/cirvix.policy"]
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

Expected: policy tests pass, both dangerous examples are denied, and the local
audit chain verifies.
