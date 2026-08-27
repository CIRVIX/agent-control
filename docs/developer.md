# Developer guide

Working on Cirvix itself.

## Layout

```
packages/
  agent-control/       the CLI, engine, gateway, daemon, audit, secrets, scanner
    bin/cirvix.mjs     the CLI entry point
    src/core/          policy · guard · gateway · daemon · audit · secrets · jsonrpc · detect · format
    src/commands/      scan · sarif
    src/testing.mjs    evaluate / expectNoLoosening / loadPolicy
    action/            the GitHub Action (composite)
    test/              8 suites, node:test
  cirvix-python/       the Python engine and SDK
    cirvix/            policy.py · guard.py · testing.py
    tests/             2 suites, unittest
  conformance/
    policy-conformance.json    the contract between the two engines
  control-plane/       the multi-tenant API
    bin/serve.mjs      entry point
    src/               api · auth · store-sql · db/ · governance · runs · secrets ·
                       sso · oidc · scim · alerts · compliance · metrics · events · egress
    deploy/            Dockerfile · docker-compose · helm · k8s
    test/              11 suites, node:test
src/                   the Next.js console and marketing site
docs/                  this documentation set
```

## Running the suites

```bash
# Node — agent-control (150 tests)
cd packages/agent-control && npm test

# Node — control-plane (322 tests)
cd packages/control-plane && npm test

# Python (63 tests)
cd packages/cirvix-python && python -m unittest discover -s tests

# Console: types, lint, build
npm run verify
```

`npm run verify` is `typecheck && lint && build`, and lint runs with
`--max-warnings 0`.

No test framework is installed anywhere. Node uses `node:test`, Python uses
`unittest`. Both are in the standard library, and a security package with a
dev-dependency tree has the same supply-chain problem as one with runtime
dependencies — just on a different day.

## The dependency rule

| Package | Runtime dependencies | Enforced by |
|---|---|---|
| `@cirvix_ai/agent-control` | **none** | no `dependencies` key in `package.json` |
| `cirvix` (PyPI) | **none** | `dependencies = []` in `pyproject.toml` |
| `@cirvix/control-plane` | `@cirvix_ai/agent-control` only | `package.json` |

This is permanent, not aspirational. A security tool that drags in a transitive
dependency tree is asking to become the supply-chain incident it exists to
prevent.

Consequences you will hit:

- **No Express.** The control plane uses `node:http` and a hand-rolled router.
- **No `jsonwebtoken`.** JWT is ~60 lines of HMAC and base64url in `auth.mjs`.
  A control plane taking a dependency for its own token verification is taking a
  dependency on someone else's release process for its most security-critical
  path.
- **No SQL library.** `node:sqlite`, via `src/db/index.mjs`.
- **No glob library.** `matchGlob` in `policy.mjs`.

## The conformance contract

[`packages/conformance/policy-conformance.json`](../packages/conformance/policy-conformance.json)
is the contract between every implementation of the policy engine. 44 cases,
loaded by both suites from the **same file** — neither language is allowed a
private copy.

**Changing engine behaviour means changing that file first, in a commit a
reviewer can see.** Adding an engine means making it pass.

The fixture is not ceremony. It immediately caught a real Windows path-
canonicalization bug in the Node engine — `path.resolve` prepending the current
drive to `/etc/passwd` on Windows — that no single-language suite would have
found.

Paths in the fixture are POSIX and `cwd` is always explicit, so resolution is
deterministic regardless of where the tests run.

A case looks like:

```json
{
  "name": "forbid wins over a permit that comes after it",
  "cwd": "/workspace",
  "rules": [
    { "name": "deny-env", "effect": "forbid", "actions": ["fs.read"], "resources": ["**/.env"] },
    { "name": "allow-reads", "effect": "permit", "actions": ["fs.read"], "resources": ["*"] }
  ],
  "request": { "agent": "a", "action": "fs.read", "resource": "/workspace/.env" },
  "expect": { "verdict": "deny", "rule": "deny-env" }
}
```

`expect` may additionally assert `resource` (the canonical form), `approvers`,
and the full `considered` trace.

Each suite also runs one meta-test asserting the fixture loaded and has no
duplicate case names — a suite that silently loads zero cases passes forever.

## Adding a route

Every route declares the permission it needs:

```js
route("GET", "/v1/thing", "org:read", (ctx) => ok(ctx.res, store.listThings(ctx.orgId)));
```

`route()` **throws at startup** if the permission is not in `PERMISSIONS`, is
not `null` for an explicitly public route, and is not the SCIM scope. An
endpoint cannot be added unauthenticated by omission.

Two rules for the handler:

1. **Never read `orgId` from a body, query, or path.** It comes from
   `ctx.principal` only. Every store method that touches tenant data takes an
   `orgId` and puts `org_id = ?` in its SQL.
2. **Anything that assigns a role goes through `cannotGrant`.** Otherwise it is
   privilege escalation with one extra step.

Audit anything an operator would want to see later:

```js
audit(ctx, "thing.created", thing.id, { name: thing.name });
```

## Adding a migration

Append to the array in `src/db/migrations.mjs` with the next version number.
Forward-only; there is no down-migration. Each runs inside a transaction with
its version bump, so a failure leaves the schema untouched and the process exits
rather than serving against a half-applied schema.

Never edit an applied migration. Add another.

## Adding a policy operator or context field

1. Add the case to `packages/conformance/policy-conformance.json`.
2. Watch **both** suites fail.
3. Implement in `packages/agent-control/src/core/policy.mjs`.
4. Implement in `packages/cirvix-python/cirvix/policy.py`.
5. Both suites pass.
6. Document it in [`docs/policy.md`](./policy.md).

Step 1 first is the whole discipline. Implementing in one language and then
"porting" is how the two engines drift.

Unknown operators must continue to **fail closed**.

## Style

The codebase explains *why*, not *what*. A comment that restates the code is
noise; a comment recording a decision — why it is not a regex, why the id is
rewritten, why the default is deny — is the thing a reader six months later
actually needs.

Where a design has a sharp edge, the comment states it plainly rather than
softening it. `audit.mjs` says what the chain does not prove. `egress.mjs` says
it does not close DNS rebinding. That honesty is load-bearing: an operator who
finds one overstated claim discards the rest.

## The console

Next.js 16 App Router, React 19, Tailwind v4. See `DESIGN.md` (console design contract, not in this repository)
before writing a component. The short version:

**Chroma means state.** Four saturated colours, each a runtime verdict —
`permit` green, `deny` red, `pending` amber, `route` blue. Nothing decorative
may use them, so green on a Cirvix screen always means a decision was made.

**Content lives in `src/content/*`, not in pages.** Pages render the content
model. Routes are declared once in `ROUTES` in `src/config/site.ts` — never
hard-code a path.

Documentation on the site is a typed block model in `src/content/docs.ts`, not
MDX. A content typo shows up as a type error rather than a silent bad render.

### Keeping the site and this directory in agreement

`docs/` is derived from the code and is canonical. When you change behaviour:

1. Update the code.
2. Update `docs/`.
3. Update `src/content/docs.ts` if the change is user-facing.

The site docs previously described a product that did not exist — Cedar, a
`cirvix.toml`, commands like `cirvix init` and `cirvix run`. That is the failure
mode this directory exists to prevent: documentation written ahead of the code
and never reconciled.

## Security review

See [`SECURITY.md`](../SECURITY.md) for the threat model and the findings from
the adversarial review. If you are touching auth, tenancy, secrets, or the
policy engine, read it first — it lists eight real vulnerabilities that were
found and fixed, and the patterns that produced them.

## Before opening a pull request

```bash
cd packages/agent-control  && npm test
cd packages/control-plane  && npm test
cd packages/cirvix-python  && python -m unittest discover -s tests
npm run verify
```

All four green, no exceptions. If you changed engine behaviour, the conformance
fixture change should be the first thing a reviewer sees in the diff.
