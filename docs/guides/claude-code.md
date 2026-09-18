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

Store upstream definitions separately in `mcp-upstreams.json`, remove direct upstream entries, and point Claude Code at the local gateway as its only MCP entry. This does not govern editor built-ins or arbitrary subprocesses:

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

## Built-in tools: `PreToolUse` hook

Claude Code's built-in tools (`Bash`, `Write`, `Edit`, `WebFetch`, etc.) do not travel over the MCP wire. To govern built-in commands alongside MCP tools, configure the Cirvix `PreToolUse` hook:

```bash
cirvix runtime
```

Add the hook to `~/.claude/settings.json`:

```jsonc
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|WebFetch",
        "hooks": [
          {
            "type": "command",
            "command": "node /path/to/integrations/claude-code/hook.mjs"
          }
        ]
      }
    ]
  }
}
```

> [!IMPORTANT]
> **Production & CI Posture**:
> By default, `hook.mjs` fails **open** with a stderr warning if the Cirvix runtime is unreachable or stopped (to prevent locking engineers out of their editors).
>
> In production CI/CD pipelines or strict compliance environments, you **must set `CIRVIX_HOOK_FAIL=closed`**. When enabled, any unparseable payload or unreachable runtime strictly denies tool execution.
>
> ```bash
> export CIRVIX_HOOK_FAIL=closed
> ```
