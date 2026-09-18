# Security and threat model

This page describes the public runtime, not a hosted multi-tenant service. [`SECURITY.md`](../SECURITY.md) also contains historical private control-plane reviews and references to absent source/tests; those claims are not validated by this checkout. No SOC 2, ISO 27001, FedRAMP certification or independent security assurance is established here.

## Enforcement boundary

| Asset/control | Available mechanism | Limit |
|---|---|---|
| Tool authorization | Local default-deny evaluator, forbid precedence, normalization, risk and configured constraints | Only routed MCP traffic and returned wrappers; arbitrary host activity is not intercepted. Validate extracted actions/resources against actual tool behavior. |
| Policy | JSON parsing/validation, Node DSL and policy tests | An operator must load the intended version. No shipped central policy review service; gateway live refresh is not wired. |
| Decision history | Optional SDK audit sink; CLI gateway/runtime JSONL hash chain | Records authorization, not successful external effects. Single-instance append serialization is not multi-process coordination. |
| Secrets | Explicit local Vault or external SecretsClient, bounded known-value/pattern scrubbing | Values exist in memory/downstream tools. Gateway CLI does not supply a broker. Scoping and host permissions remain essential. |
| Approvals | Local request fingerprints, named reviewers and consumed grants | Reviewer names are not authenticated identities/signatures; no transaction spans approval consumption and tool execution. |
| Local transport | Socket token; optional inbound HTTP bearer token | Not per-tenant auth/RBAC. Use separate trusted process/state/network boundaries for mutually untrusted callers. |
| MCP definitions | In-session definition fingerprints and heuristic inspection | Not proof of benign tools, publisher-signature verification or persistent independent attestation. |

Guard and Pipeline both run shared process-local kill checks but remain distinct orchestration paths. Pipeline additionally supports optional intent/session/baseline hooks. Guard fingerprints include server/environment; Pipeline uses the agent supplied by trusted context or configuration. These controls do not authenticate the embedding transport or make mission budgets/revocation atomic with final execution. See [Architecture](./architecture.md).

## Explicit limitations

- Prompt injection is not prevented. Policy constrains authorized actions; sanitizer/intent heuristics do not establish semantic safety.
- An agent retaining direct tools, host credentials or direct upstream routes is outside the mediated boundary for those actions. Same-user code execution can access process memory and local files; root is not the only relevant host privilege.
- `AgentSandbox` does not impose OS filesystem, network or memory confinement. Its checks and subprocess timeout are helpers, not isolation.
- `cirvix kill` does not communicate with another process, terminate agents, or revoke credentials at a provider. No distributed emergency response system is shipped.
- Local organization/agent fields are labels/context, not an authenticated SaaS tenancy boundary. Auth/RBAC/SSO/SCIM database implementations and their historical review tests are absent.
- A permitted tool can perform behavior different from its name/schema or target representation. Policy is not a general information-flow monitor or transaction verifier.
- Redaction is bounded by supported payload shapes, scan depth, value patterns and material known to the broker; do not claim universal non-disclosure. Audit metadata, paths and commands can themselves be sensitive.

## Audit and proof semantics

The audit structure is a **linear SHA-256 hash chain**, not a Merkle tree. Verification recomputes available records and their links. It does not establish truthful recording, complete history, successful execution or trusted identity.

A local operator can delete a file, truncate its tail, or replace/recompute an entire chain without an internal inconsistency in the remaining records. `AuditChain.read()` also converts read failures into an empty list, so a successful zero-record verification is not proof that an expected log survived. Independently retain trusted head/count checkpoints and check file existence/readability.

Local signed proofs establish integrity against the supplied public key, not independent compliance. Trust in the key must come from outside the artifact; issuer text is not independent issuer authentication. Signing/receipt helpers are explicitly invoked, not automatic immutable receipts for every tool call.

## Operational hardening

1. Remove alternate ungoverned routes and verify actual allowed/held/denied calls with benign fixtures.
2. Pin the intended policy/package/upstream versions and inspect feature wiring rather than startup branding.
3. Keep HTTP on loopback unless an authenticated, reviewed TLS/network boundary is supplied. Use OS-level isolation for hostile workloads.
4. Use one audit writer per chain; protect state, credentials and backups with filesystem ACLs. No portable Windows ACL policy is supplied merely by requesting POSIX modes.
5. Preserve independent checkpoints, monitor nonzero expected history and disk errors, and reconcile external effects before retrying an approved call.
6. Follow [Operations](./operations.md#current-local-operations-and-recovery) for backups, stale locks, restart state and limits. No tested RPO/RTO or HA guarantee is supplied.

## Evidence and reporting

Tests and fixtures exercise specific behaviors, not all possible integrations. Historical test totals, attack-corpus counts and zero-bypass statements must not be presented as a current universal guarantee. The [Developer guide](./developer.md) describes current gates and remaining boundaries; final results belong in the main agent's final report, not historical subset tables.

Use the reporting guidance in [`SECURITY.md`](../SECURITY.md). This review did not contact the product site, verify hosted services, inspect operator credential files or conduct live/offensive testing.
