# Developer guide

## Checkout layout

- `packages/agent-control/bin`: CLI entry points.
- `packages/agent-control/src/commands` and `src/adapters`: local operations, reporting, configuration detection and integration planning.
- `packages/agent-control/src/core`: policy/DSL, Guard/Pipeline, gateway/transports, local stores and optional controls.
- `packages/agent-control/test` and `action`: Node tests/fixtures and composite scan action.
- `packages/cirvix-python`: native Python evaluator, wrappers, tests and artifact checker.
- `packages/conformance`: shared policy and Node delegation fixtures.
- `tools`, `demo`, `benchmarks`, `docs`: repository validation, fixture demonstrations, benchmarks and documentation.
- `.github/workflows`: CI and release automation.

No runnable SaaS/control-plane server, frontend, auth/billing/tenant service or production deployment templates are shipped. Ignored control-plane environment/database/dependency artifacts are not server source.

## Verification commands

Run from the repository root unless stated otherwise:

| Purpose | Command |
|---|---|
| Node suite | `npm test` |
| Example policy tests | `node --test docs/examples/policy.test.mjs` |
| Version / licence / public provenance | `npm run verify:version`, `npm run verify:license`, `npm run verify:public` |
| Node pack and offline clean-install gate | `npm run verify:package` |
| Python tests | `python -m unittest discover -s tests -v` from `packages/cirvix-python` |
| Python build | `python -m build packages/cirvix-python --outdir .artifacts/python` |
| Python artifact inventory/source check | `python packages/cirvix-python/check_artifacts.py .artifacts/python` |

Node uses `node:test`, not Jest. `npm test` also includes adversarial fixtures and subprocess/transport tests; select tests according to the review's permitted scope. `npm run verify:adversarial` is a separate gate, not an ordinary unit-test substitute. Do not run discovery over operator configuration or credentials in a restricted review.

No lint/typecheck script or Node compilation build is configured. `node --check <file>` validates syntax only. Python packaging requires the `build` module and `hatchling`; a missing build module blocks artifact validation and is not a successful build. The artifact checker requires exactly the current wheel/sdist, compares runtime bytes with source, validates metadata/licences/conformance inventory, and rejects unexpected members.

`verify:package` checks the Node package inventory and required exports, packs and installs offline, checks CLI version/policy behavior and imports the SDK. Setting `CIRVIX_PACKAGE_OUTPUT_DIR` to an existing directory exports the same verified tarball; it does not repack for publication. Isolate operator environment/home/cache as required by the test scope. `verify:public` is a provenance check, not certification. The npm script first runs its own `--self-test` against a seeded fixture, because a guard that has never been seen to fail is not a guard, then fails on credential stores, SQLite databases or WAL sidecars present anywhere in the audited tree — the artifacts one stray `git add -A` publishes — before the existing secret and proprietary-path scans.

Optional harnesses include `npm run proof-suite`, `npm run demos`, `npm run demo`, `npm run demo:scenarios`, `npm run bench` and `npm run bench:system`. Fixture demonstrations do not execute real payment/cloud integrations, and benchmark output is not an SLA.

## Current implementation

- Guard and Pipeline use the shared in-process kill checks, including a recheck after asynchronous brokering. This does not give the standalone kill CLI cross-process delivery.
- Guard approval fingerprints include server and environment. Pipeline selects the agent from trusted submission context or its configured default rather than the raw request's agent field; the embedding transport must establish that context.
- Node wrappers guard all supported callable entrypoints, reject ambiguous/accessor/unsupported shapes, and accept zero arguments or one plain argument object. Python wrappers bind inspectable signatures and guard supported methods on independent copies. See the SDK guides for their differences.
- Gateway forwarded routes have timeout/capacity bounds, retain decisions for response scrubbing, and refuse unsupported client methods.
- Daemon records snapshot their input and serialize append/drain operations within the instance. Shutdown reports whether its final batch emptied the backlog rather than treating any successful batch as complete delivery. This is not multi-process coordination or a crash-durability guarantee.
- `AuditChain.open()` verifies loaded history before extending it. Read-error handling remains a final-review checkpoint: at this documentation pass, `read()` still catches errors as an empty list. Verify the main agent's pending correction before release.
- Passport rotation requires the old private key and signs the rotated payload with old and new keys. These remain standalone identity primitives, not automatic runtime enrollment.

## Release workflow and gate

Release build runs Node and Python tests, metadata/licence/provenance gates, verified Node packing, Python build and Python artifact checking. Tag-push publication fails early without npm credentials. npm publishes the exported verified tarball; PyPI does not skip existing artifacts. GitHub release creation depends on build and both publisher jobs. Manual dispatch builds without publishing.

**Final release status is pending the main agent's final run.** Earlier ordinary-suite results included failures being fixed, and local Python artifact building was blocked by a missing build module. Prior subset counts and intermediate package checks are not a full-suite or final-artifact pass. Record exact commands, runtime versions, failures/skips and artifact results in the final report; do not reuse historical gate tables as current evidence.

## Remaining boundaries

- Mission budget assessment/accounting and revocation checks are not an atomic transaction at the final execution boundary. Approval consumption, audit persistence and external effects also lack exactly-once coupling; reconcile failures before retrying.
- Signed passports/rotation do not establish mandatory authenticated runtime enrollment or SaaS tenant isolation.
- `cirvix kill` changes only its process-local state; fleet/process containment requires separate delivery and supervisor controls.
- Remote policy refresh does not hot-reload the running CLI gateway. Rules are selected at construction; plan controlled restart and review empty-policy fallback semantics.
- Local file stores, sandbox helpers and proofs do not supply OS isolation, managed HA, independent compliance evidence or automatic recovery. See [Architecture](./architecture.md), [Deployment](./deployment.md) and [Operations](./operations.md).

Preserve concurrent work and coordinate ownership of code, tests, workflows and docs. This documentation pass changes no runtime code and runs no network or release operations. Source inspection describes implementation, not a guarantee that all tests pass.
