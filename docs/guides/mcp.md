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

Expected: the production write is held for `platform-oncall` or denied by your
policy, and the decision is present in the local audit chain. A caller that
connects directly to an upstream MCP server bypasses this integration.
