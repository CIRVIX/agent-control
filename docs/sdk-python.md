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
from cirvix import guard, CirvixDenied, CirvixHeld, STARTER_RULES

tools = guard.wrap(
    my_tools,
    agent="support-triage",
    environment=os.environ.get("CIRVIX_ENV", "local"),
    rules=STARTER_RULES,
)

try:
    crew.kickoff()
except CirvixHeld as err:
    print(err.approvers)     # ["platform-oncall"] — a person can release this
    raise
except CirvixDenied as err:
    print(err.policy)        # "deny-dotenv-read"
    print(err.remediation)   # 'secrets.get("STRIPE_KEY")'
    print(err.decision_id)   # pass to `cirvix why`
    raise
```

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

Two engines that can silently disagree about a security decision are worse than
one engine and an honest gap: an agent denied by the Node gateway and permitted
by the Python SDK is a bypass nobody would find until it mattered. That is
prevented by [`packages/conformance/policy-conformance.json`](../packages/conformance/policy-conformance.json)
— 44 cases both suites load from the same file, neither allowed a private copy.

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

For tool objects, the first of `func`, `_run`, `run`, `invoke`, `call`,
`execute`, `handler` that is callable is the one wrapped. (The Node SDK's order
differs — `func`, `invoke`, `call`, `execute`, `handler`, `_call`, `run` —
because the frameworks in each ecosystem differ.)

**Async is preserved.** An async tool stays async — otherwise the framework's
`await` receives a coroutine-returning wrapper it does not expect.
`__name__`, `__doc__` and `__wrapped__` are all set on the governed callable.

A tool using `__slots__` or a custom `__new__` cannot be shallow-copied. Those
are governed **in place**: governing the original is better than refusing to
govern it at all, and the docstring says so.

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
  directly is never evaluated. The [gateway](./cli.md#cirvix-gateway) does not
  have this limitation because it sits on the wire.
- **It does not broker secrets.** The Python `Guard` has no `secrets` parameter.
  A Python agent that needs handle substitution and return-path redaction routes
  its tool calls through the gateway, which does.
- **It does not write an audit chain.** The Python `Guard` has no `audit`
  parameter. Use `on_decision` to forward records wherever you keep them, or run
  the gateway.
- **It does not reach the network.** No telemetry is shipped and no policy is
  pulled. Both are the daemon's job.
