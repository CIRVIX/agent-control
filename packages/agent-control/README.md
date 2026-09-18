# @cirvix_ai/agent-control

Local runtime policy enforcement for routed MCP calls and wrapped Node tools. ESM, Node 20+, no declared runtime dependencies. **Apache-2.0**, as declared in [LICENSE](./LICENSE) and `package.json`.

## Install and use

```bash
npm install @cirvix_ai/agent-control
```

This self-contained ESM example uses an in-memory fixture; it does not read a file:

```js
import { guard, CirvixDenied, STARTER_RULES } from "@cirvix_ai/agent-control";

const tools = guard.wrap(
  { read_file: async ({ path }) => `Fixture read: ${path}` },
  { agent: "pr-triage", rules: STARTER_RULES },
);

console.log(await tools.read_file({ path: "src/index.mjs" }));
try {
  await tools.read_file({ path: ".env.production" });
} catch (err) {
  if (!(err instanceof CirvixDenied)) throw err;
  console.log(err.policy, err.decisionId);
}
```

Register the **returned tools** with your framework executor. Wrapping a collection without using the result does not govern the originals. `wrap` accepts a function, a plain named tool map, or an array of functions/tool objects. All supported callable methods are guarded; accessors, unsupported methods and ambiguous shapes are rejected. Calls accept zero arguments or one plain argument object. Frameworks needing other shapes require an explicit adapter.

`rules` takes an in-memory array, not `policyDir`. `CirvixHeld` extends `CirvixDenied`; catch it first when distinguishing approval from refusal. A hold does not execute the callable or automatically resume it later.

### Optional persistence

```js
import { mkdir } from "node:fs/promises";
import { AuditChain, guard, STARTER_RULES } from "@cirvix_ai/agent-control";

await mkdir(".cirvix", { recursive: true });
const audit = await new AuditChain(".cirvix/audit.jsonl").open();
const tools = guard.wrap(
  { read_file: async ({ path }) => `Fixture read: ${path}` },
  { rules: STARTER_RULES, audit },
);
await tools.read_file({ path: "src/index.mjs" });
await audit.flush();
```

Without `audit`, the SDK does not persist decisions. An `onDecision` callback is another explicit integration point. Use one AuditChain instance/writer for a file. The CLI gateway and runtime wire local audit and approval stores themselves.

## CLI

```bash
npx @cirvix_ai/agent-control check --action fs.read --resource .env.production
npx @cirvix_ai/agent-control policy check
npx @cirvix_ai/agent-control help
```

`check` is hypothetical: no tool execution and no audit append. Exit `1` means deny; `0` includes hold as well as permit. Missing rules default to deny, while omitted CLI policy options discover a workspace policy before falling back to starter rules.

`scan` inventories known runtime configurations, dependencies and credential paths. It can inspect home-directory configuration and workspace dotenv metadata. Do not run it without authorization for that scope. Detection is not an exhaustive inventory or proof of enforcement. The scan itself is local, but `npx` may fetch packages and `--sarif` writes a report.

## MCP gateway

```bash
cirvix gateway --servers /absolute/path/to/mcp-upstreams.json --policy /absolute/path/to/cirvix.policy --cwd /absolute/path/to/workspace
```

Keep upstream definitions in a **separate file**; register only the gateway in the client's active MCP map and remove direct upstream entries. Definitions accept `mcpServers`, `servers`, or a bare map; upstreams can be stdio or HTTP. Built-in editor tools and non-MCP traffic are not intercepted. New upstream configuration is not automatically hot-loaded.

Inbound `--http` is MCP transport, not an `HTTP_PROXY` egress proxy. Default host is loopback; use a reviewed authentication/TLS/network boundary for remote access. The package is not a deployable SaaS or general-purpose REST control-plane server.

## Implemented building blocks and their boundaries

| Surface | Implementation and limitation |
|---|---|
| Policy | JSON evaluator and DSL compiler; default deny, forbid precedence, context matching and canonicalization. Tool classification is heuristic; validate the actions/resources extracted for your tool schemas. |
| Guard/wrap and gateway | Shared Guard authorization; optional audit, approvals, brokering, delegation, mission constraints and metering require wiring. Authorization is not proof of successful tool execution. |
| Pipeline/local socket | Separate orchestration path for cooperating clients; optional intent/session/baseline hooks. Submission decides and returns arguments; the executor must obey the result. |
| Approvals | Local JSONL requests, reviewer names, fingerprint matching and consumed grants. No SSO-authenticated human signatures or external-transaction idempotency. |
| Vault/SecretsClient | Local in-memory vault with optional explicit AES-GCM sealing, or a client for an external broker. CLI gateway does not supply a broker; runtime loads environment values only with `--vault`. A one-shot `vault` command does not provision a running gateway. |
| Audit/proof | Linear SHA-256 chain and explicitly issued signed artifacts, not an automatically emitted immutable Merkle receipt for every call. Verification needs a trusted public key/checkpoint and does not prove truthful execution. |
| Passport | Signing/verification and old/new-key-signed rotation helpers; not automatic runtime enrollment, mandatory tool-call authentication or a tenant identity service. |
| Kill switch | Shared in-process checks in Guard (including gateway/wrappers) and Pipeline. The standalone CLI invocation does not update another process, kill OS processes or revoke provider credentials. |
| Sandbox | Path/network check helpers and subprocess timeout. No OS filesystem/network isolation or enforced memory limit; checks do not confine a spawned process. |
| MCP inspection | Metadata/string heuristics. A `VERIFIED` score is not publisher-signature validation or independent supply-chain attestation. |
| Shadow/baseline/intent | Optional local evaluation helpers; no demonstrated fleet-wide continuous monitoring or semantic prompt-injection prevention. |
| Daemon | External API client with cached policy, input snapshots and serialized spool append/drain operations. Shutdown reports remaining backlog. No cross-process coordination, live gateway policy-reload or HA guarantee. |

Never claim that an agent cannot receive secret material solely because the package is installed. Scope handles, route all relevant calls, keep host permissions restrictive, and review downstream tools. Pattern and known-value redaction have limits.

Audit verification detects inconsistencies in available records. A missing/unreadable audit file can appear as an empty valid chain; deletion, tail truncation or recomputation cannot be established without a trusted external checkpoint. No automatic retention, state migration, tool rollback or managed recovery is supplied.

## Product availability

This package ships CLI/runtime libraries and a scan action. It does **not** ship a web console, user authentication/RBAC service, tenant database, SSO/SCIM, hosted API, billing checkout/webhooks, central alerts, production image or Helm chart. Licence/plan tables and remote command clients are not those services; their external availability is unverified.

The Python `cirvix` package implements a separate evaluator and wrapper. Shared policy fixtures constrain evaluator behavior; they do not establish complete runtime parity. Python Guard has no Node audit sink, secret broker or delegation layer.

## Repository documentation and tests

In a source checkout, see `docs/README.md`, `docs/architecture.md`, `docs/deployment.md`, `docs/operations.md`, and `docs/developer.md`. Repository tests/docs/harnesses are not included in the npm tarball; the package's `files` list includes `bin`, `src`, `action`, README, LICENSE and NOTICE.

```bash
npm test
```

Run this in the source workspace, not as a claim that the installed tarball includes tests. The command includes adversarial fixtures and subprocess/transport tests; restricted reviews may require a scoped subset. No lint/typecheck script or compilation build is configured. Current gate output, not historical test totals or zero-bypass marketing counts, is the release evidence.
