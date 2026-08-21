# Conformance — adding an engine

The decision engine exists twice: once in Node, once in Python. This document is
the contract a third one satisfies.

It is written with a Rust implementation in mind, because that is the one the
original architecture called for and the only piece of it still missing. Nothing
here is Rust-specific.

## The position

**The Node engine is the oracle. A new engine is correct when it agrees with it.**

This is deliberate, and it is the opposite of rewriting the enforcement path in
Rust and hoping the behaviour survived:

```
Node implementation
       ↓
packages/conformance/policy-conformance.json
       ↓
Rust implementation
       ↓
must produce identical decisions
```

The fixture is not documentation of the Node engine's behaviour. It *is* the
behaviour, extracted into a form another language can execute. Node happens to
have been first.

> Changing engine behaviour means changing the fixture first, in a commit a
> reviewer can see. An engine that quietly stops matching is a bypass; a fixture
> diff is an argument.

## The fixture

`packages/conformance/policy-conformance.json` — plain JSON, no imports, POSIX
paths, `cwd` always explicit so resolution does not depend on where the tests
run.

| Section | Cases | Required of |
|---|---|---|
| `cases` | 82 | every engine |
| `delegationCases` | 24 | engines that implement delegation |
| `capabilities` | — | declares which engine implements which layer |

Both existing suites load this one file. Neither is allowed a private copy,
because the entire value is that a case cannot be made to pass in one language
and quietly skipped in the other.

### `cases` — the policy core

Each case is a rule set, a request, and the expected decision:

```json
{
  "name": "a matching permit permits",
  "cwd": "/workspace",
  "rules": [{ "name": "allow-reads", "effect": "permit",
              "actions": ["fs.read"], "resources": ["*"] }],
  "request": { "agent": "a", "action": "fs.read", "resource": "/workspace/app.ts" },
  "expect": { "verdict": "permit", "rule": "allow-reads" }
}
```

`verdict` and `rule` are always asserted. `decision`, `resource`, `approvers`,
and `considered` are asserted only when the case names them, so a new engine can
be brought up incrementally without weakening what the existing cases test.

### `delegationCases` — the scope algebra

Three operations, and intersection is **probed rather than compared**:

| `op` | Asserts |
|---|---|
| `permits` | `scopePermits(scope, request) === expect` |
| `narrows` | `isNarrowing(parent, child) === expect` |
| `intersect` | what `intersectScopes(a, b)` permits, via `probes[]` |

Two correct implementations may represent the same authority differently —
different ordering, or `a/**` where another engine keeps the two patterns it
subsumes. Asserting on the returned structure would pin an accident of
representation and fail a correct engine. Only what a scope *permits* has
security meaning, so that is what is checked.

Cases carry a `$why` where they pin a shape that was once a real defect:
`matchGlob("**/*")` returning false (fail-open), and `normalizeScope([])`
becoming `["*"]` — which turned the intersection of two disjoint authorities
into universal authority.

### `capabilities` — declared, then verified

An engine may legitimately ship without a layer. The Python SDK has no
delegation and says so. What is not acceptable is implementing a layer and
skipping its cases, so **each suite asserts its own declaration against
reality** — Node asserts it is listed for delegation and runs those cases;
Python asserts it is not listed, and that nothing delegation-shaped is exported.

## Running it

```bash
node --test packages/agent-control/test/conformance.test.mjs
```

```bash
cd packages/cirvix-python && python -m unittest discover -s tests
```

A new engine adds a third runner: load the JSON, execute each case against its
own evaluator, compare. Roughly 60 lines. Regenerate the delegation section with
`node packages/conformance/build-delegation-cases.mjs` after editing the case
list.

## What passing this does NOT prove

**Read this part.** The fixture covers the policy evaluator and the scope
algebra. It does not cover the layers around them, and every real bypass found
in this codebase so far has been in those layers rather than in `evaluate`.

Two engines calling the same correct evaluator still diverged, repeatedly:

- **Risk rules fired over the local socket and never over MCP.** `Pipeline` ran
  risk classification; the gateway went through `Guard`, which did not. Rules
  saying `risk >= HIGH` loaded, validated, appeared in `cirvix policy list`, and
  matched nothing arriving over MCP.
- **Approvals could be granted and had no release path.** The feature worked
  end to end except for the part where an approved call runs.
- **`resources/read` was ungoverned.** The same file, denied as a tool call and
  served as a resource.
- **Delegation was unenforced on every transport.** `Pipeline` accepted a
  presented grant; the UDS handler never forwarded the field, and `Guard` had no
  concept of delegation at all. Since delegation only ever *narrows*, dropping
  it did not fail safe — a worker delegated `fs.read` got everything policy
  allowed the moment its call arrived over MCP instead of the socket.

Each of those passed every conformance case, because each was a wiring failure
between correct components rather than a wrong answer from one.

So an engine is conformant when it passes the fixture, and it is **safe** when it
also has:

1. **One decision path per surface, or one shared core.** See
   `applyDelegation` in `core/delegation.mjs` — a single implementation both
   engines call, with a test asserting the two produce the same rule for the
   same call.
2. **The adversarial suites**, in `packages/agent-control/test/adversarial/`.
   `cross-boundary.test.mjs` is the one that maps to this warning: it attacks
   each place a call can enter the runtime, not the evaluator.
3. **An end-to-end proof that is not the engine's own output.** Anyone can write
   a gateway that prints DENIED. `test/e2e-mcp.test.mjs` asserts an *empty
   access log* from a real MCP subprocess — the file was not opened.

A Rust engine that passes 82 cases and is wired into one surface out of three
is not a Rust port of this product. It is a fourth place for the same bug to
live.
