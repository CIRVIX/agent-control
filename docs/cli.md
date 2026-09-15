# CLI reference

`cirvix` ships in `@cirvix_ai/agent-control`. Zero runtime dependencies, by
design: this binary runs on developer machines and in CI, and a security tool
that drags in a transitive dependency tree is asking to become the supply-chain
incident it exists to prevent.

```bash
npx @cirvix_ai/agent-control scan
```

Requires Node 20 or later.

## Commands

| Command | Needs a control plane | What it does |
|---|---|---|
| [`scan`](#cirvix-scan) | no | Inventory what is ungoverned on this machine |
| [`check`](#cirvix-check) | no | Evaluate a single hypothetical call against policy |
| [`policy`](#cirvix-policy) | no | Print the active rule set |
| [`gateway`](#cirvix-gateway) | optional | Run the MCP gateway — intercepts and enforces |
| [`daemon`](#cirvix-daemon) | yes | Run the endpoint service — policy sync + telemetry |
| [`audit verify`](#cirvix-audit-verify) | no | Recompute the local decision chain and report any break |
| [`why`](#cirvix-why) | yes | Explain one decision, and name the run it belongs to |
| [`replay`](#cirvix-replay) | yes | Re-evaluate a recorded run under a candidate policy |
| [`help`](#help-and-version) | no | Print usage |
| [`version`](#help-and-version) | no | Print the version |

Everything except `why` and `replay` works offline, because enforcement has to.
Those two ask about something already recorded somewhere else.

## Global flags

| Flag | Applies to | Meaning |
|---|---|---|
| `--json` | all reporting commands | Machine-readable output |
| `--cwd <dir>` | all | Workspace root (default: current directory) |
| `--policy <file>` | `check`, `gateway`, `policy`, `replay` | Rule set to evaluate against. Omitted → the starter rules |
| `--api <url>` | `gateway`, `daemon`, `why`, `replay` | Control-plane base URL. Or `CIRVIX_API_URL` |
| `--key <cvx_…>` | `gateway`, `daemon`, `why`, `replay` | API key. Or `CIRVIX_API_KEY` |
| `--state <dir>` | `gateway`, `daemon` | Policy cache + telemetry spool (default `./.cirvix`) |
| `--agent <name>` | `check`, `gateway` | Agent identity used in evaluation (default `local`) |
| `--env <name>` | `check`, `gateway` | Environment context (default `local`) |

---

## `cirvix scan`

Read-only inventory of what an agent on this machine could reach with nothing
in the way. Nothing is changed and nothing is sent.

```bash
cirvix scan
cirvix scan --json --fail-on high
cirvix scan --deep --sarif cirvix-scan.sarif
```

| Flag | Meaning |
|---|---|
| `--json` | Full result as JSON |
| `--deep` | Include MCP command lines in the output |
| `--sarif <file>` | Write SARIF 2.1.0 for code-scanning upload |
| `--fail-on <level>` | Exit non-zero at `high`, `medium`, or `low` findings |

### What it detects

**Runtimes** — Claude Code, Cursor, Windsurf, Cline, VS Code. Reports whether
each is governed and how many MCP servers it has configured.

**Frameworks** — LangChain, CrewAI, OpenAI Agents SDK, Vercel AI SDK, Anthropic
SDK, MCP SDK, detected from project dependencies.

**MCP servers** — from the runtime configs above, flagged for broad filesystem
scope, inline secrets in config, and duplication across runtimes.

**Reachable credentials** — `~/.aws/credentials`, `~/.ssh/id_rsa`,
`~/.ssh/id_ed25519`, `~/.kube/config`, `~/.docker/config.json`, `~/.npmrc`,
`~/.netrc`, `~/.config/gcloud/credentials.db`, and `.env` files in the
workspace.

### Finding codes

| Code | Severity | Raised when |
|---|---|---|
| `runtime-ungoverned` | high | A detected runtime is not routed through a control plane |
| `mcp-broad-scope` | high | An MCP server exposes a path far wider than a workspace |
| `credential-readable` | high / medium | A credential file is readable from agent context |
| `env-readable` | high / medium | A `.env` file is present — `high` if it looks like production |
| `framework-uninstrumented` | medium | An agent framework has no Cirvix middleware on its tool boundary |
| `mcp-inline-secrets` | medium | An MCP server config carries environment values inline |
| `mcp-duplicated` | low | One MCP server is configured separately in more than one runtime |

The SARIF writer runs **before** the exit-code gate, so a failing scan still
produces the artifact CI is about to upload. Fingerprints are stable across
runs, so a dismissal in GitHub code scanning sticks.

### Exit codes

`0` clean or no gate · `1` findings at or above `--fail-on` · `2` unknown
`--fail-on` level

---

## `cirvix check`

Evaluates one hypothetical call. Executes nothing. This is the fastest way to
answer "would this be allowed".

```bash
cirvix check --action fs.read --resource .env.production
```

```
  DENY  fs.read C:/work/app/.env.production
  rule    deny-dotenv-read
  reason  Reading .env files is denied outside an approved secrets flow. …
  fix     Request the value as a handle: secrets.get("STRIPE_KEY")

  considered
    → forbid  deny-dotenv-read
```

| Flag | Required | Meaning |
|---|---|---|
| `--action <action>` | yes | e.g. `fs.read`, `shell.exec`, `k8s.apply` |
| `--resource <resource>` | yes | Path or URL. Canonicalized before matching |
| `--policy <file>` | no | Rule set. Omitted → starter rules |
| `--agent <name>` | no | Default `local` |
| `--env <name>` | no | Default `local` |
| `--json` | no | Full decision record |

The context `check` builds is deliberately minimal: `path.insideWorkspace` is
computed from `--cwd`, and `egress.external`, `egress.allowlisted` and
`session.touchedSecret` are all `false`. To exercise those, use the SDK's
`evaluate()` — see [Node SDK](./sdk-node.md#testing-a-policy).

### Exit codes

`0` permit or hold · `1` deny · `2` missing `--action` or `--resource`

---

## `cirvix policy`

Prints the active rule set.

```bash
cirvix policy
cirvix policy --policy cirvix.policy.json --json
```

| Flag | Meaning |
|---|---|
| `--policy <file>` | Rule set to print. Omitted → the nine starter rules |
| `--json` | The rules verbatim, suitable for piping |

Always exits `0`.

---

## `cirvix gateway`

Runs the MCP gateway over stdio. The agent talks to Cirvix; Cirvix talks to the
upstream MCP servers. Every `tools/call` is evaluated before it is forwarded,
and every result is scanned on the way back.

```bash
cirvix gateway --servers ~/.cursor/mcp.json
cirvix gateway --servers ./mcp.json --policy cirvix.policy.json --env staging
```

| Flag | Required | Meaning |
|---|---|---|
| `--servers <file>` | yes | MCP server map |
| `--policy <file>` | no | Rule set. Omitted → starter rules |
| `--state <dir>` | no | Audit log + spool (default `./.cirvix`) |
| `--agent <name>` | no | Recorded against every decision (default `local`) |
| `--env <name>` | no | Environment context (default `local`) |
| `--api <url>` / `--key <cvx_…>` | no | Attach to a control plane |

### The servers file

Accepts an editor's config verbatim — `mcpServers` (Claude Code, Cursor,
Windsurf) or `servers` (VS Code) — so you point at the file you already have
rather than authoring a new format. stdio transport only.

```json
{
  "mcpServers": {
    "github": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"] }
  }
}
```

An entry named `cirvix` is skipped: pointing the gateway at a governed config
would otherwise make it proxy itself.

### With and without a control plane

Without `--api`/`--key` the gateway enforces from the local rule set and writes
decisions to `<state>/audit.jsonl`. The product is useful before you have an
account.

With them, a [daemon](#cirvix-daemon) starts alongside: it supplies policy,
registers the agent in the fleet inventory, opens a run that every decision in
the session belongs to, and ships telemetry. On shutdown it flushes the spool
before closing the run, so a reader never sees a finished run whose steps have
not landed yet.

### Output discipline

The agent owns stdout. Every diagnostic goes to stderr — one stray `console.log`
would corrupt the JSON-RPC stream and the agent would see a protocol error it
cannot explain.

### Exit codes

`0` clean shutdown · `2` no upstream servers configured

---

## `cirvix daemon`

Runs the endpoint service on its own: pulls policy on an interval, ships spooled
telemetry, and heartbeats so the control plane can tell this host apart from one
that stopped reporting.

```bash
cirvix daemon --api https://api.example.com --key $CIRVIX_API_KEY
```

| Flag | Required | Meaning |
|---|---|---|
| `--api <url>` | yes | Or `CIRVIX_API_URL` |
| `--key <cvx_…>` | yes | Or `CIRVIX_API_KEY` |
| `--state <dir>` | no | Default `./.cirvix` |
| `--interval <ms>` | no | Sync interval, default `30000` |

### Exit codes

`0` clean shutdown · `2` missing `--api` or `--key`

---

## `cirvix audit verify`

Recomputes the local hash chain and reports the first break.

```bash
cirvix audit verify
cirvix audit verify --file .cirvix/audit.jsonl --json
```

| Flag | Meaning |
|---|---|
| `--file <path>` | Chain to verify (default `.cirvix/audit.jsonl`) |
| `--json` | `{ ok, records, brokenAt?, reason? }` |

```
  chain intact  43675 records verified

  Verification proves records were not altered after they were written.
  It does not attest to their content.
```

That caveat is printed every time on purpose. A hash chain proves integrity, not
truth.

`audit` accepts no other subcommand; anything else exits `2`.

### Exit codes

`0` chain intact · `1` chain broken · `2` wrong subcommand

---

## `cirvix why`

Explains one recorded decision, and names the run it belongs to.

```bash
cirvix why dec_01JQ8F2K7M
```

```
  DENY  fs.read /workspace/.env.production
  rule    deny-dotenv-read
  reason  Reading .env files is denied outside an approved secrets flow.
  agent   pr-triage
  when    2026-08-07T14:22:11.418Z
  run     run_01JQ8F2K7M

  considered
    → forbid  deny-dotenv-read
      permit  allow-workspace-read

  cirvix replay run_01JQ8F2K7M --diff
```

Reads `GET /v1/decisions/:decisionId`. Requires `--api` and `--key`, or
`CIRVIX_API_URL` and `CIRVIX_API_KEY`.

The run id is the point of this command in an incident: it hands you the thread
to pull, not just the one bead you arrived holding.

### Exit codes

`0` the decision was a permit or hold · `1` it was a deny · `2` no decision id

---

## `cirvix replay`

Re-evaluates every step of a recorded run under a candidate rule set. **No side
effects are executed** — replay re-decides, it never re-runs.

```bash
cirvix replay run_01JQ8F2K7M                                  # against live policy
cirvix replay run_01JQ8F2K7M --policy proposed.json --diff    # against a candidate
```

| Flag | Meaning |
|---|---|
| `--policy <file>` | Candidate rule set. Omitted → replays against whatever is live |
| `--diff` | Show only the steps whose verdict changed |
| `--json` | Full result |

Omitting `--policy` answers "would today's rules have stopped this" — the
question asked after an incident. Passing one answers "what would this change
break" — the question asked before a merge.

```
  run_01JQ8F2K7M   agent pr-triage   38 calls

  changed decisions                 2 of 36

  00.412  fs.read  /workspace/.env.production
          was  PERMIT allow-workspace-read
          now  DENY   deny-dotenv-read

  No side effects were executed.
```

Steps recorded without enough context to re-decide are reported as **not
replayable** rather than silently counted as unchanged. `changed` is always
stated as a fraction of `replayable`, never of the total.

### Exit codes

`0` nothing changed · `1` at least one decision changed · `2` no run id

Non-zero on change makes this usable as a CI gate against a candidate rule set.

---

## Help and version

```bash
cirvix help        # exit 0
cirvix version     # exit 0 — prints 0.1.0
cirvix --version   # same
cirvix nonsense    # prints help, exit 2
```

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `CIRVIX_API_URL` | `gateway`, `daemon`, `why`, `replay` | Control-plane base URL |
| `CIRVIX_API_KEY` | `gateway`, `daemon`, `why`, `replay` | API key, `cvx_…` |
| `NO_COLOR` / `FORCE_COLOR` / `TERM` | all | Colour control |

Flags take precedence over environment variables.

## Exit-code summary

| Code | Meaning |
|---|---|
| `0` | Success, or a permitted/held decision |
| `1` | A substantive negative: findings over the gate, a deny, a broken chain, a changed replay |
| `2` | Usage error, or an unhandled exception |

`1` and `2` are kept distinct so CI can tell "the tool worked and the answer was
no" from "the tool did not run".
