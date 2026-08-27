# Claude Code

Protect a Claude Code MCP session locally in under ten minutes. The gateway
intercepts calls before they reach configured upstream servers; it does not
inspect or classify prompt-injection text.

## Install → init

```bash
npm install -g @cirvix_ai/agent-control
cirvix --version
cd /path/to/your/project
cirvix init
cirvix policy check
```

## Connect

Point Claude Code at the local gateway as its MCP server:

```json
{
  "mcpServers": {
    "cirvix": {
      "command": "cirvix",
      "args": ["gateway", "--servers", "/absolute/path/to/mcp.json", "--policy", "/absolute/path/to/cirvix.policy"]
    }
  }
}
```

## Policy → test → verify

```bash
cirvix check --action fs.read --resource .env.production
cirvix check --action fs.read --resource src/index.ts
cirvix demo --fast
cirvix audit verify
```

Expected: the credential read is `DENY`, the workspace read is `PERMIT`, and
the demo's downstream credential and exfiltration calls are denied. Poisoned
content remains visible; Cirvix constrains downstream actions rather than
detecting prompt injection.
