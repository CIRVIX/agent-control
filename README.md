# Cirvix AgentControl

Local policy evaluation and enforcement for **tool calls routed through the MCP gateway or returned SDK wrappers**. It does not intercept all activity on a machine.

Apache-2.0. No declared runtime dependencies. Node 20+; Python 3.9+.

## Quickstart

```bash
npm install @cirvix_ai/agent-control
```

Run this ESM example from your project. The tool below is deliberately an in-memory fixture, not a filesystem reader:

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

The first call runs; the second is denied before the fixture is invoked. When integrating a framework, register the **returned** tools with its executor, not the originals. The Node SDK does not persist an audit chain unless an `audit` sink is supplied; Python uses an `on_decision` callback instead. See [Quickstart](./docs/quickstart.md), [Node SDK](./docs/sdk-node.md), and [Python SDK](./docs/sdk-python.md).

For a hypothetical decision without executing or recording a tool call:

```bash
npx @cirvix_ai/agent-control check --action fs.read --resource .env.production
```

With starter rules this exits `1` (deny). `check` exits `0` for both permit and hold, so exit status alone is not an execution authorization. An existing workspace policy can change the result.

Optional inventory:

```bash
npx @cirvix_ai/agent-control scan
```

The scanner examines known runtime configurations and credential-path accessibility, including locations outside the workspace. Configuration detection is heuristic, not proof of routed execution or an exhaustive inventory. The scan itself is local; `npx` may download a package, and `--sarif` writes a report. Do not run discovery where home/configuration inspection is unauthorized.

## What is here

| Component | Available implementation |
|---|---|
| [`packages/agent-control`](./packages/agent-control) | ESM policy engine and DSL, MCP gateway/transports, Guard/wrappers, local socket/Pipeline, audit and approval stores, vault, reporting primitives, scanner/adapters, CLI |
| [`packages/cirvix-python`](./packages/cirvix-python) | Native policy evaluator, synchronous/asynchronous tool wrappers, testing helpers; not the full Node runtime |
| [`packages/conformance`](./packages/conformance) | Shared policy fixtures and Node delegation fixtures |
| [`tools`](./tools), [`demo`](./demo), [`benchmarks`](./benchmarks) | Repository validation and local demonstration/performance harnesses; not hosted product services |
| [Documentation](./docs/README.md) | Architecture, SDKs, policy, deployment limits, operational recovery, and release gates |

**Not shipped here:** a SaaS server, web frontend, tenant database/migrations, user authentication/RBAC, SSO/SCIM, billing checkout/webhooks, hosted retention, or enterprise deployment manifests. Client-side login, remote API calls, licence tables and organization fields do not implement these services. Ignored control-plane environment/database/dependency remnants are not deployable source. External/private product availability is unverified.

## Enforcement and operational limits

- Default deny; a matching explicit forbid outranks hold and permit. JSON rules and the Node DSL are described in [Policy](./docs/policy.md).
- The gateway governs routed MCP calls only. Direct upstream entries, editor built-ins, arbitrary subprocesses, and unwrapped callables remain outside its boundary.
- Guard and Pipeline are separate orchestration paths. Optional exported modules are not automatically enabled on every path. In particular, the standalone kill command does not control another running process; the sandbox helper is not OS isolation.
- Local approval records name a reviewer; they are not authenticated dual-key signatures. An approval authorizes a retry, not an automatically resumed or exactly-once external transaction.
- A configured audit sink records authorization, not successful execution. The SHA-256 chain detects internal inconsistencies, not complete deletion, truncation or rewritten history without a trusted external checkpoint. Local signed proofs are not independent compliance evidence.
- Secret brokering requires explicit wiring. Values exist in process memory and downstream tools; redaction is not a universal information-flow guarantee. Host permissions and destination controls remain necessary.
- No automatic rollback of tool effects, managed disaster recovery, audit rotation, or demonstrated high-availability deployment is supplied. See [Deployment](./docs/deployment.md) and [Operations](./docs/operations.md).

Cirvix does not prevent prompt injection or compensate for permissive policy. No SOC 2, ISO 27001 or FedRAMP certification is established here.

## Security evidence

[`SECURITY.md`](./SECURITY.md) includes historical reviews, including private control-plane material absent from this checkout. It is not proof of current hosted-service security. Historical corpus totals and zero-bypass counts are not a guarantee about arbitrary agents or configurations. Use current, scoped test output and [Security](./docs/security.md) to interpret the evidence.

The PR-title example under `docs/examples` is a scripted policy demonstration with fixtures, not a live model attack reproduction. It does not establish that a model was compromised or that a third-party service was protected.

## Development and release

From the repository root:

```bash
npm test
npm run verify:version
npm run verify:license
npm run verify:public
npm run verify:package
```

Run Python tests from `packages/cirvix-python`:

```bash
python -m unittest discover -s tests -v
```

`npm test` includes adversarial fixtures and subprocess/transport integration tests; review their access requirements before running them in a restricted environment. No lint/typecheck script or Node compilation build is configured. Python packaging uses `python -m build`; Node distribution uses `npm pack`. See [Developer guide](./docs/developer.md) for command scope and the current release gate; do not infer a release pass from a subset of tests.

## Licence

Apache-2.0 — [LICENSE](./LICENSE), [NOTICE](./packages/agent-control/NOTICE), and [LICENSING.md](./LICENSING.md). The separately described proprietary control plane is not part of this source distribution.
