# Cirvix AgentControl

**Runtime authorization for AI agent tool calls. Every call is evaluated
against policy before it runs, and the decision is recorded either way.**

*Capability is not authority.* An agent that can reach a credential file, a
shell, or production was never thereby permitted to touch them. Cirvix sits
between the agent and its tools — in-process, default-deny — and enforces
that distinction on every tool call.

Apache 2.0. Zero runtime dependencies. Node 20+ and Python 3.9+.

## Install

```bash
npx @cirvix_ai/agent-control scan
```

Read-only. No account, no signup, no telemetry. It reports which agent
runtimes on this machine are ungoverned, which MCP servers they can reach,
and which credential files are readable from agent context right now.

To govern an agent rather than survey a machine:

```bash
npm install @cirvix_ai/agent-control     # or:  pip install cirvix
```

```js
import { guard, CirvixDenied, STARTER_RULES } from "@cirvix_ai/agent-control";

const tools = guard.wrap(myTools, { agent: "pr-triage", rules: STARTER_RULES });

try {
  await agent.invoke(input);
} catch (err) {
  if (err instanceof CirvixDenied) {
    console.log(err.policy, err.remediation, err.decisionId);
  }
  throw err;
}
```

From install to a stopped attack in five minutes:
[docs/quickstart.md](./docs/quickstart.md).

## ALLOW, DENY, APPROVAL

The whole model is three effects, shown here as three real starter rules —
a permit, a forbid, and a hold for a human:

```json
{
  "rules": [
    {
      "name": "allow-workspace-read",
      "effect": "permit",
      "actions": ["fs.read", "fs.list", "fs.stat"],
      "resources": ["*"],
      "when": [{ "path": "path.insideWorkspace", "op": "eq", "value": true }]
    },
    {
      "name": "deny-dotenv-read",
      "effect": "forbid",
      "actions": ["fs.read", "fs.*"],
      "resources": ["**/.env", "**/.env.*"],
      "reason": "Reading .env files is denied outside an approved secrets flow.",
      "remediation": "Request the value as a handle: secrets.get(\"STRIPE_KEY\")"
    },
    {
      "name": "require-approval-destructive",
      "effect": "hold",
      "actions": ["fs.delete", "db.write", "db.migrate", "k8s.apply", "shell.exec"],
      "resources": ["*"],
      "when": [{ "path": "environment", "op": "in", "value": ["production", "prod"] }],
      "approvers": ["platform-oncall"]
    }
  ]
}
```

Decide a single call and read the reasoning:

```bash
npx @cirvix_ai/agent-control check --action fs.read --resource .env
```

```
DENY  fs.read .env
rule    deny-dotenv-read
reason  Reading .env files is denied outside an approved secrets flow. This is
        the single most common path from a prompt injection to a live credential.
fix     Request the value as a handle: secrets.get("STRIPE_KEY")
```

No matching rule means deny, an explicit deny is terminal regardless of
rule order, and a hold outranks any permit. See
[the two behaviours](#two-behaviours-to-know-before-writing-rules) below.

## Architecture

```text
agent ──stdio──▶ MCP gateway ──stdio──▶ upstream MCP servers
                      │  guard.wrap (Node + Python agents)
                      ▼
           Guard.authorize() — one decision core, two transports
                      ▼
           decision (permit / forbid / hold) + hash-chained audit record
```

The gateway and `guard.wrap()` are transports for one question, never two
implementations of the answer. Full decision path:
[docs/architecture.md](./docs/architecture.md).

## Security model

The policy engine is the control; the prompt sanitiser is mitigation.
Cirvix constrains what an injected agent is able to do — it does not
prevent injection, and a permissive policy still says yes. Resolved secrets
live in process memory, so root on the endpoint is out of scope. The full
threat model, including what is deliberately outside it:
<https://www.cirvix.com/threat-model.html> · [SECURITY.md](./SECURITY.md).

## Benchmark

LOCAL BENCHMARK, one machine — per-decision latency **P50 0.079ms /
P95 0.245ms / P99 0.484ms, max 7.707ms**. Reproduce it:

```bash
node benchmarks/decision.mjs
```

That measures what Cirvix adds to a tool call, excluding the upstream tool
round trip and the audit fsync — run with `--audit` to price durable
history separately, never folded in.

## Verification

LOCAL BENCHMARK — adversarial corpus: **11,629 cases (10,877 attacks,
752 benign), 0 false negatives, 0 false positives.** Reproduce it:

```bash
npm run verify:adversarial --workspace @cirvix_ai/agent-control
```

Watch a real attack fail end to end — a poisoned PR title injects an
exfiltration instruction, and the credential read is refused:

```bash
node docs/examples/pr-title-injection.mjs
```

Confirm the decision record is intact:

```bash
npx @cirvix_ai/agent-control audit verify
```

## Docs

[Quickstart (5 min)](./docs/quickstart.md) ·
[Policy reference](./docs/policy.md) · [CLI](./docs/cli.md) ·
[Node SDK](./docs/sdk-node.md) · [Python SDK](./docs/sdk-python.md) ·
[Architecture](./docs/architecture.md) ·
[Deployment](./docs/deployment.md)

---

## What is here

| Package | What it is | Runtime deps |
|---|---|---|
| [`packages/agent-control`](./packages/agent-control) | Policy engine, MCP gateway, local control socket, audit chain, secret broker, scanner, and the `cirvix` CLI | **none** |
| [`packages/cirvix-python`](./packages/cirvix-python) | A second implementation of the same engine, plus `guard.wrap` for Python agents | **none** |
| [`packages/conformance`](./packages/conformance) | Shared cases both engines must pass | — |

Two implementations are held to one fixture. That fixture immediately found a
real path-canonicalisation bug in the Node engine, which is the argument for
having it.

**Documentation:** [`docs/`](./docs) — [quickstart](./docs/quickstart.md),
[policy reference](./docs/policy.md), [CLI](./docs/cli.md),
[Node SDK](./docs/sdk-node.md), [Python SDK](./docs/sdk-python.md).

## Two behaviours to know before writing rules

**No matching rule means deny.** The absence of a rule is never read as
permission. This is irritating on day one, and the list of permits you end up
writing is the useful artefact — most people discover their agent has a shell
they had not thought about.

**An explicit deny is terminal.** No later rule lifts it. Policy whose meaning
depends on file ordering is policy nobody reasons about correctly at 3am.

## What it does not do

Stated here rather than left for you to discover:

- **It does not prevent prompt injection.** It constrains what an injected
  agent is able to do. The sanitiser is a mitigation; the policy engine is the
  control.
- **Root on the endpoint is out of scope.** Resolved secret material sits in
  process memory for the life of a request.
- **It cannot save you from a permissive policy.** `resources: ["**"]` on a
  filesystem write says yes to everything, and it will.
- **No SOC 2, ISO 27001 or FedRAMP.** It produces evidence for those audits and
  does not assert an outcome — the report vocabulary has no word for "pass",
  enforced by a test.
- **Audit retention is not tiered.** Nothing prunes, on any plan.

The full threat model, including what is deliberately outside it:
<https://www.cirvix.com/threat-model.html>

## Security

[`SECURITY.md`](./SECURITY.md) holds the threat model and two adversarial
reviews, published with what they broke:

- The first found and fixed **eight real vulnerabilities**, including an
  admin→owner privilege escalation and an unauthenticated denial of service.
- A later consistency oracle — which checks the decision against what the
  process *actually did*, with a real MCP subprocess's access log as ground
  truth — found **twelve more** that every unit test had passed. One was
  `matchGlob("**/*")` returning `false`: a fail-open, in both engines.

Current corpus: **11,629 attack cases, 0 false negatives, 0 policy bypasses.**

Report anything new to the address in
[`security.txt`](https://www.cirvix.com/.well-known/security.txt).

## Licence

**Apache 2.0** — see [LICENSE](./LICENSE), [NOTICE](./packages/agent-control/NOTICE),
and [LICENSING.md](./LICENSING.md) for which parts of the product this covers.

The engine is the part that decides whether your agent's call runs. A security
control you are not permitted to read is one you are asked to take on faith,
which is a strange thing to ask of the person whose job is not extending faith
to software. Apache rather than MIT for the patent grant, which is not
decorative in this category.

The multi-tenant control plane — shared policy distribution, team vault, SSO and
SCIM, approvals workflow, hosted audit retention, compliance evidence — is a
separate, proprietary product and is not in this repository. Coordination
between people is a different problem from deciding one call, and only the
second one needs to be secret.

## Development

```bash
cd packages/agent-control && npm test
cd packages/cirvix-python && python -m unittest discover -s tests
```

The zero-dependency rule is permanent. The
[conformance fixture](./packages/conformance) must be changed *before* engine
behaviour is. Read [`docs/developer.md`](./docs/developer.md) first.
