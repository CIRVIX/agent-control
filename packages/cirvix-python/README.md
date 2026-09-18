# cirvix

Runtime governance for Python AI agents. Every tool call is evaluated against
policy before it executes.

**Zero dependencies.** Standard library only, permanently — the same reason the
Node package has none.

```bash
pip install cirvix
```

**Full documentation:** [`docs/`](../../docs/) — [Python SDK](../../docs/sdk-python.md), [policy reference](../../docs/policy.md), [quickstart](../../docs/quickstart.md).

## Governing an agent

```python
from cirvix import guard, CirvixDenied, CirvixHeld

tools = guard.wrap(
    my_tools,
    agent="pr-triage",
    environment=os.environ.get("CIRVIX_ENV", "local"),
    rules=rules,
)

try:
    crew.kickoff()
except CirvixHeld as held:
    print(held.approvers)     # ["platform-oncall"] — this call is waiting
except CirvixDenied as err:
    print(err.policy)         # "deny-dotenv-read"
    print(err.remediation)    # 'secrets.get("STRIPE_KEY")'
    print(err.decision_id)    # pass to `cirvix why`
```

`wrap` accepts the shapes Python tool collections actually come in and returns
the same shape:

| It accepts | Framework |
|---|---|
| A mapping of `name -> callable` | hand-rolled loops, AutoGen function maps |
| A sequence of objects carrying `func` | LangChain |
| A sequence of objects carrying `_run` | CrewAI |
| A single callable | anything |

Async tools stay async. Tool objects keep their descriptions and schemas, and
the list you passed in is left alone — a framework holding the originals does
not find them governed by surprise.

**`CirvixDenied` vs `CirvixHeld`.** A denial means re-plan. A hold means this
exact call may still happen once a person says yes. They are separate types
because collapsing them teaches an agent to treat both as failure.

## Why this is a real evaluator and not an HTTP client

The easy version of this package asks a control plane over the network for
every decision. That would have been a fraction of the work and it would have
been wrong twice over: it puts a round trip in the enforcement path, and it
breaks the offline-first property the whole product rests on — a control plane
that stops enforcing when the network blips is worse than none, because the
failure is invisible.

So this is a native port. Which raises the real risk: **two engines that can
silently disagree are worse than one engine and an honest gap.** An agent
denied by the Node gateway and permitted here is a bypass nobody would find
until it mattered.

Both evaluators use `packages/conformance/policy-conformance.json` for covered
verdicts, rules, canonical resources and traces. This fixture does not establish
runtime feature parity: Python Guard denies required sanitization before sync
or async execution, whereas Node has transformation support. Python returns
permitted tool results unchanged; it has no result scrubber.

It has already earned its keep: writing it surfaced a bug where the Node engine
canonicalized `/etc/passwd` to `C:/etc/passwd` on Windows, so a rule written
`resources: ["/etc/**"]` silently did not match on the machine it was most
likely written to protect.

```bash
python -m unittest discover -s tests
```

## Testing a policy like code

```python
from cirvix.testing import evaluate, expect_no_loosening

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

`expect_no_loosening(before=…, after=…, calls=…)` reports any call a policy
change would newly permit. Tightening passes — a security policy is allowed to
move that way without surprising a reviewer.

## What `wrap` does not do

The MCP gateway governs supported calls actually routed through it. `wrap`
governs only returned wrappers registered with the executor, not originals or
other tools. Python provides an optional `on_decision` callback, not a built-in
audit chain or approval store. A hold prevents execution but does not enqueue
or release a human approval automatically.

If your agent speaks MCP — Claude Code, Cursor, or anything else — use the
gateway instead:

```bash
cirvix gateway --servers ~/.cursor/mcp.json
```

## Status

Pre-release. Python provides the policy evaluator, `guard.wrap`, and testing
helpers. It lacks sanitization/result scrubbing, secret-handle brokering,
built-in approval release, audit-chain persistence, and telemetry shipping.
Required sanitization is denied rather than silently ignored. Route supported
MCP calls through a correctly configured gateway when those capabilities are
needed; routing does not establish unrestricted security parity.
