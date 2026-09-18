# Architecture

## Available components

```text
MCP client -> Gateway -> Guard.authorize -> upstream MCP server
Node tools -> guard.wrap -> Guard.authorize -> wrapped function
Socket client -> UdsServer -> Pipeline.submit -> cooperating executor
                                    |
                    policy / risk / approvals / authority / vault / audit

Gateway or standalone Daemon -> optional external control-plane API
```

`packages/agent-control/bin/cirvix.mjs` dispatches commands, loads policies, wires stores, and starts transports. `src/commands` provides setup, reporting, policy operations, proofs, and demos. `src/adapters` detects client configurations and generates integration plans; detection is not evidence of routed execution.

`src/core/guard.mjs` and `src/core/pipeline.mjs` are distinct orchestration paths sharing policy and other components. Gateway uses Guard; the local control socket uses Pipeline. They require cross-path tests; a shared evaluator alone does not establish parity.

Rules are evaluated locally, with default deny and forbid taking precedence over hold and permit. Optional mission and delegation constraints narrow authority. On permitted calls a configured broker substitutes handles; responses are scrubbed. Audit records describe authorization, not necessarily successful tool execution. Pipeline submission alone never performs a refund, deployment, or filesystem edit.

The package exports SDK modules through `package.json`; its tarball includes `bin`, `src`, `action`, README, LICENSE, and NOTICE. Repository demo harnesses, tests, docs, tools, and conformance fixtures are not in that tarball. The Python engine is a separate implementation with a shared conformance fixture, not the full Node orchestration stack.

## Integration limits

The gateway governs only traffic routed through it. Client configurations that retain direct upstream entries permit ungoverned access. Fleet integration therefore refuses those generated plans instead of claiming protection. Built-in editor tools, arbitrary subprocesses, and framework executors using unwrapped tools remain outside the boundary.

A configuration entry is not a handshake; an authorization permit is not a verified end-to-end execution. Fleet detection does not infer VERIFIED from a permit record.

Gateway forwarded routes have timeouts and capacity bounds, carry their authorization decision into response scrubbing, and reject unsupported client methods. Pipeline selects agent identity from trusted submission context or configuration, not the raw request agent field; the embedding transport is responsible for authenticating that context. Node wrappers guard supported callable entrypoints and reject unsupported shapes rather than passing them through.

## Persistence and trust

Local audit records form a SHA-256 hash chain, not a Merkle tree. Internal consistency cannot prove truthful recording or detect complete deletion/replacement without a trusted external checkpoint. `prove` produces a signed compact token; local signing keys remain under the state directory. A local proof is not independent evidence.

Local approvals bind request fingerprints (including server/environment in Guard) and record reviewer names. They do not implement SSO-authenticated dual-key signatures. Vault handles and missions require explicit wiring; exported modules are not proof that every CLI transport enables every feature. Avoid multiple processes writing the same state files without verified coordination.

## Feature wiring is not uniform

| Entry point | Actual wiring |
|---|---|
| `guard.wrap` / SDK Guard | Policy/risk, taint, shared in-process kill checks and supplied optional audit/approval/broker/delegation/mission/meter objects. No default persistent audit sink. |
| CLI MCP gateway | Guard plus local audit/approval stores and metering. Optional daemon handles remote synchronization; the CLI does not pass a secret broker, mission/delegation registry or Pipeline-only controls. |
| CLI local runtime | Pipeline plus audit/approvals/metering; vault only populated with `--vault`. Socket clients cooperate; no upstream operation is executed by Pipeline submission. |
| Pipeline library | Additional optional intent, session tracker and behavioral baseline; process-local kill engine. The kill context does not supply every scope advertised by the helper. |
| Python Guard | Native policy/wrapper and decision callback; no Node audit sink, broker or delegation implementation. |

`AgentSandbox.execute` spawns a subprocess with a checked working directory and timeout; it does not impose OS filesystem/network confinement or its configured memory ceiling. MCP inspection scores supplied metadata/strings rather than verifying publisher signatures. Passport rotation verifies the current passport and requires signatures from old and new keys. Passport and action-receipt helpers remain explicitly invoked primitives, not runtime enrollment, mandatory transport authentication or automatic per-call immutable receipts. Mission budgets and revocation are not atomically coupled to the final external execution boundary.

Daemon policy cache/spool and process-local taint/kill state are not a distributed control plane. The CLI selects gateway rules at construction and does not hot-update them when the daemon refreshes. See [Operations](./operations.md#current-local-operations-and-recovery) for state, restart and recovery boundaries.

## Not shipped here

No runnable control-plane server, Next.js console, tenant database implementation, SSO/SCIM service, alert delivery, billing checkout/webhooks, hosted proof issuer, Helm chart, or production deployment manifests are present. The daemon, remote commands, commercial entitlement tables, and links are client-side integration surfaces, not those systems themselves. Local control-plane data remnants are not deployable software.

Historical API/administration/operations documents describe an external or private product contract. Its availability, security claims, and tests are not established by this repository. Use [Deployment](./deployment.md) for supported local launch instructions and [Developer guide](./developer.md) for reproducible gates.
