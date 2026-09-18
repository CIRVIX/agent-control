# Python SDK

```bash
pip install cirvix
```

Zero dependencies, standard library only. Python 3.9 or later.

A security package that drags in a transitive dependency tree is asking to
become the supply-chain incident it exists to prevent — the same reason the Node
package has none.

## Quick start

```python
import os
from cirvix import guard, CirvixDenied, CirvixHeld, STARTER_RULES

def read_file(path):
    return f"Fixture read: {path}"

tools = guard.wrap(
    {"read_file": read_file},
    agent="support-triage",
    environment=os.environ.get("CIRVIX_ENV", "local"),
    rules=STARTER_RULES,
)

print(tools["read_file"](path="src/index.py"))
try:
    tools["read_file"](path=".env.production")
except CirvixHeld as err:
    print(err.approvers)
except CirvixDenied as err:
    print(err.policy, err.remediation, err.decision_id)
```

The example invokes the returned wrappers directly and reads no files. Register those returned tools with your framework; wrapping and then calling a pre-existing crew/executor with its original tools does not govern it. Decision IDs are not automatically persisted or discoverable by the Node CLI.

> **`rules` is the option, not `policy_dir`.** `wrap` forwards its keyword
> arguments to `Guard(**options)`, which takes an in-memory rule sequence. To
> load from disk use `load_policy` from `cirvix.testing`, or `parse_rules` on
> your own `json.load`. An unrecognised keyword raises `TypeError`; an empty
> rule set denies everything.

```python
import json
from cirvix import guard, parse_rules

with open("cirvix.policy.json", encoding="utf-8") as fh:
    rules = parse_rules(json.load(fh))

tools = guard.wrap(my_tools, agent="support-triage", rules=rules)
```

## Why this is a real evaluator, not an HTTP client

`cirvix` contains a **second implementation** of the policy engine, not a
wrapper that calls the Node one over a socket. Decisions are made in-process,
with no network on the enforcement path.

The Python and Node suites load the same policy cases rather than maintaining private copies. The fixture constrains evaluator behavior on covered inputs; it does not establish runtime parity.

The fixture earns its keep. It immediately caught a real Windows path-
canonicalization bug in the *Node* engine that no single-language test suite
would have found.

## Shapes `wrap` accepts

```python
guard.wrap(tools, guard=None, **options)
```

| Input | Behaviour |
|---|---|
| `Mapping[str, Callable]` | Each callable replaced; non-callables passed through |
| `list` / `tuple` of tool objects | Each **shallow-copied** with its callable attribute replaced |
| A single callable | Wrapped; name from `name=` or `__name__` |

For sequence tool objects, every supported callable among `func`, `_run`, `run`, `invoke`, `call`, `execute` and `handler` is wrapped. A tool without a supported entrypoint is rejected. Node has a separate shape contract; neither list establishes blanket framework compatibility.

**Async is preserved.** An async tool stays async — otherwise the framework's
`await` receives a coroutine-returning wrapper it does not expect.
`__name__`, `__doc__` and `__wrapped__` are all set on the governed callable.

Sequence tool objects must support an independent `copy.copy`; returning the original object is rejected rather than silently governing it in place. Callables require an inspectable signature. Positional/keyword arguments and defaults are bound before authorization; nonempty variadic positional arguments are rejected when their resources cannot be inferred.

## `Guard`

A dataclass.

```python
from cirvix import Guard

g = Guard(
    rules=rules,                  # default [] — which denies everything
    agent="support-triage",       # default "local"
    environment="production",     # default "local"
    cwd=None,                     # default: os.getcwd()
    on_decision=lambda rec: None,
    log=lambda msg: None,
    run_id=None,
)

decision = g.authorize(tool="read_file", args={"path": ".env"})
if decision.verdict != "permit":
    raise g.to_error(decision)
```

`authorize` is **synchronous** and executes nothing. `g.stats` is
`{"calls", "permitted", "denied", "held"}`. `g.touched_secret` is set once the
session reads secret-shaped material and never resets.

## Errors

```python
class CirvixDenied(Exception):
    policy: str | None          # the rule that decided it
    decision_id: str | None     # pass to `cirvix why`
    reason: str | None
    remediation: str | None
    appealable: bool
    resource: str | None
    action: str | None

class CirvixHeld(CirvixDenied):
    approvers: list[str]
    approval_id: str | None
    # appealable is always True
```

Catch `CirvixHeld` **before** `CirvixDenied` — it is a subclass, so the broad
clause matches both. A denial means re-plan; a hold means this exact call may
still happen once somebody says yes.

## Testing a policy

```python
from cirvix.testing import evaluate

def test_production_writes_are_held():
    decision = evaluate(
        policy_dir="./policies",
        agent="deploy-bot",
        action="k8s.apply",
        resource="production/checkout",
        context={"environment": "production"},
    )

    assert decision.verdict == "hold"
    assert "platform-oncall" in decision.approvers
```

`evaluate` is keyword-only. One rule source: `rules`, `policy_file`, or
`policy_dir` (every `.json`/`.policy` in the directory, sorted, duplicate rule
names rejected). With none, the starter rules are used.

The default context is permissive on purpose — inside the workspace, no external
egress, no secret touched — so a test asserting a denial is denied by the rule
it is testing rather than by a restrictive default.

### `expect_no_loosening`

```python
from cirvix.testing import expect_no_loosening

result = expect_no_loosening(
    before={"policy_file": "policies/main.json"},
    after={"policy_file": "policies/candidate.json"},
    calls=[
        {"action": "fs.read", "resource": ".env.production"},
        {"action": "k8s.apply", "resource": "production/api",
         "context": {"environment": "production"}},
    ],
)

assert result["ok"], result["loosened"]
```

Only widening counts. Tightening passes — a security policy is allowed to move
that way without surprising a reviewer.

## Everything exported

```python
from cirvix import (
    guard, wrap, Guard,
    CirvixDenied, CirvixHeld,
    Decision,
    EFFECT, VERDICT, STARTER_RULES,
    evaluate, parse_rules, match_glob, canonicalize_resource,
    action_for_tool, resource_for_call, destination_for,
)
from cirvix.testing import evaluate, expect_no_loosening, load_policy
```

`cirvix.evaluate` is the raw engine — it takes a request dict and a rule list.
`cirvix.testing.evaluate` is the ergonomic one, with context defaults and rule
loading. They are different functions with the same name in different modules;
import the one you mean.

`guard` is a namespace object rather than a module, so
`from cirvix import guard` reads the same way as the Node SDK's
`import { guard }`.

## What `wrap` does not do

- **It does not govern tools you did not hand it.** A tool the agent reaches
  directly is never evaluated. The [gateway](./cli.md#cirvix-gateway) governs only MCP calls actually routed through it, not arbitrary activity.
- **It does not broker secrets.** The Python `Guard` has no `secrets` parameter.
  A Python agent that needs handle substitution and return-path redaction routes
  its tool calls through the gateway, which does.
- **It does not write an audit chain.** The Python `Guard` has no `audit`
  parameter. Use `on_decision` to forward records wherever you keep them, or run
  the gateway.
- **It cannot sanitize.** The evaluator can return `sanitize`, but Python Guard
  converts a required transformation to a denial before sync or async execution.
  This fail-closed capability difference is retained for the release candidate;
  it is not Node runtime parity. Node has transformation support, while Python
  has neither argument transformation nor result scrubbing. Shared evaluator
  fixtures do not prove equivalent wrapper enforcement.
- **It has no built-in approval store or grant-release path.** `CirvixHeld`
  prevents execution; it does not enqueue or release an approval automatically.
- **It does not reach the network.** No telemetry is shipped and no policy is
  pulled. Both are the daemon's job.
