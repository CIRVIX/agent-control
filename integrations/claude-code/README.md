# Claude Code

Route Claude Code's MCP traffic through the Cirvix gateway.

## What this changes

Claude Code launches each MCP server as a subprocess and talks to it over stdio.
Cirvix sits in that pipe: Claude Code launches *Cirvix*, Cirvix launches the real
servers, and every `tools/call` is evaluated before it is forwarded.

```
Claude Code ──stdio──▶ cirvix gateway ──stdio──▶ filesystem server
                            │          ──stdio──▶ github server
                            ├─ policy
                            ├─ risk
                            ├─ secret broker
                            └─ audit chain
```

Nothing about how you use Claude Code changes. Tools appear in the same list,
under the same names, with the same schemas. What changes is that a denied call
comes back as a readable tool result the model can act on — so it re-plans
instead of crashing.

## Setup

```bash
cirvix init
```

Then add Cirvix to `~/.claude.json` (or `~/.claude/settings.json`) and remove the
servers it now fronts:

```jsonc
{
  "mcpServers": {
    "cirvix": {
      "command": "cirvix",
      "args": ["gateway", "--servers", "/absolute/path/to/servers.json"]
    }
  }
}
```

`servers.json` is the block you just removed — Cirvix reads an editor's config
verbatim, so you can point it at a copy of your original file:

```jsonc
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/your/project"]
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "sec_handle_01" }
    }
  }
}
```

That `sec_handle_01` is not a placeholder to fill in. It is the point: run
`cirvix vault load` first and the real token stays in the vault, gets
substituted onto the wire when a permitted call goes out, and never enters the
model's context.

## Verify it

```bash
cirvix status
```

`Protected` should now count Claude Code. Then make Claude Code do something and
look at what happened:

```bash
cirvix logs --last 20
```

## The hook alternative

If you would rather not front the MCP servers, Claude Code's `PreToolUse` hook
can consult the same policy engine over the local control socket. Start the
runtime:

```bash
cirvix runtime
```

and add to `~/.claude/settings.json`:

```jsonc
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|WebFetch",
        "hooks": [{ "type": "command", "command": "node /path/to/integrations/claude-code/hook.mjs" }]
      }
    ]
  }
}
```

This governs Claude Code's **built-in** tools, which the gateway never sees
because they are not MCP. The two are complementary, and running both is the
only configuration that covers everything Claude Code can do.

### Production & CI Posture: Fail-Closed Enforcement

> [!IMPORTANT]
> **FAIL-CLOSED ENFORCEMENT REQUIREMENT**:
> By default, `hook.mjs` fails **open** with a warning if the Cirvix runtime is unreachable, uninitialized, or the payload is unparseable. This design prevents locking developers out of their interactive editor if the background daemon is restarted or stopped during local development.
>
> **In production CI/CD pipelines, automated testing, and enterprise security environments, you MUST set `CIRVIX_HOOK_FAIL=closed`.**
>
> When `CIRVIX_HOOK_FAIL=closed` is set, any unparseable payload, uninitialized state directory, or unreachable Cirvix runtime socket will **strictly deny** the tool call immediately.

Set it in your environment:
```bash
export CIRVIX_HOOK_FAIL=closed
```

Or specify the environment variable in your `~/.claude/settings.json` hook definition:
```jsonc
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|WebFetch",
        "hooks": [
          {
            "type": "command",
            "command": "node /path/to/integrations/claude-code/hook.mjs",
            "env": {
              "CIRVIX_HOOK_FAIL": "closed"
            }
          }
        ]
      }
    ]
  }
}
```

## What this does not cover

- Tools Claude Code implements internally, unless you also install the hook.
- Anything the user runs in their own terminal. Cirvix governs the agent, not
  the human.
- A second Claude Code instance started with a different config. `cirvix scan`
  finds those.
