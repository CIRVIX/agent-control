# MCP

Cirvix is an MCP gateway, not an MCP server that claims to protect every
deployment automatically. Put it between a client and the upstream server map.

## Install → init

```bash
npm install -g @cirvix_ai/agent-control
cirvix init
```

## Connect

```bash
cirvix gateway \
  --servers /absolute/path/to/mcp.json \
  --policy /absolute/path/to/cirvix.policy
```

Register that command as the only MCP server your client launches. Cirvix
forwards only after policy evaluation.

## Policy → test → verify

```bash
cirvix policy check
cirvix policy test
cirvix check --action database.write --resource production/users --env production
cirvix audit verify
```

The hypothetical write may be held or denied depending on loaded rules; `check` does not append an audit record. Generate benign calls through the actual client/gateway and verify expected decision IDs and a nonzero chain count. Keep the upstream file separate from the client gateway-only configuration. Direct upstream access and built-in tools remain outside this integration.
