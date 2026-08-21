"""Policy testing, for the same reason the Node package has it.

A rule set is code, and code that decides what an agent may do deserves unit
tests running in CI next to everything else::

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

The context defaults matter. A test that has to spell out
``path.insideWorkspace`` every time will stop spelling it out correctly, and a
policy test that passes because the context was wrong is worse than no test.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

from .policy import STARTER_RULES, Decision, evaluate as evaluate_rules, parse_rules

__all__ = ["evaluate", "expect_no_loosening", "load_policy"]

#: The *permissive* baseline, on purpose: a test asserting something is denied
#: should be denied by the rule under test, not by a restrictive default that
#: would have denied anything.
DEFAULT_CONTEXT: dict[str, Any] = {
    "environment": "local",
    "path": {"insideWorkspace": True},
    "egress": {"external": False, "allowlisted": False},
    "session": {"touchedSecret": False},
}


def load_policy(
    rules: Sequence[Mapping[str, Any]] | None = None,
    policy_file: str | os.PathLike[str] | None = None,
    policy_dir: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    """Loads a rule set from an inline list, a file, or a directory."""
    if rules is not None:
        return parse_rules(list(rules))

    if policy_file is not None:
        with Path(policy_file).open(encoding="utf-8") as handle:
            return parse_rules(json.load(handle))

    if policy_dir is not None:
        directory = Path(policy_dir)
        files = sorted(p for p in directory.iterdir() if p.suffix in (".json", ".policy"))
        if not files:
            raise ValueError(f"No policy files in {directory}. Expected .json files.")

        loaded: list[dict[str, Any]] = []
        for path in files:
            with path.open(encoding="utf-8") as handle:
                loaded.extend(parse_rules(json.load(handle)))

        # A duplicate name across files is a rule silently shadowing another,
        # which is exactly the bug a directory of policies invites.
        seen: set[str] = set()
        for rule in loaded:
            if rule["name"] in seen:
                raise ValueError(f"Duplicate rule {rule['name']!r} across files in {directory}.")
            seen.add(rule["name"])
        return loaded

    return list(STARTER_RULES)


def _merged_context(context: Mapping[str, Any] | None) -> dict[str, Any]:
    supplied = dict(context or {})
    merged = dict(DEFAULT_CONTEXT)
    merged.update(supplied)
    for key in ("path", "egress", "session"):
        merged[key] = {**DEFAULT_CONTEXT[key], **dict(supplied.get(key) or {})}
    return merged


def evaluate(
    *,
    action: str,
    resource: str = "",
    agent: str = "test-agent",
    context: Mapping[str, Any] | None = None,
    rules: Sequence[Mapping[str, Any]] | None = None,
    policy_file: str | os.PathLike[str] | None = None,
    policy_dir: str | os.PathLike[str] | None = None,
    cwd: str | None = None,
) -> Decision:
    """Evaluates one hypothetical call. Executes nothing."""
    if not action:
        raise ValueError('evaluate needs an action, e.g. "fs.read".')
    rule_set = load_policy(rules=rules, policy_file=policy_file, policy_dir=policy_dir)
    return evaluate_rules(
        {"agent": agent, "action": action, "resource": resource, "context": _merged_context(context)},
        rule_set,
        cwd=cwd or os.getcwd(),
    )


def expect_no_loosening(
    *,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    calls: Sequence[Mapping[str, Any]],
    cwd: str | None = None,
) -> dict[str, Any]:
    """Reports any call a policy change would newly permit.

    The pull-request counterpart to ``cirvix replay``, for a policy diff where
    there is no recorded run to replay against. Tightening passes — a security
    policy is allowed to move that way without surprising a reviewer.
    """
    previous = load_policy(**dict(before))
    candidate = load_policy(**dict(after))
    rank = {"deny": 0, "hold": 1, "permit": 2}
    loosened: list[dict[str, Any]] = []

    for call in calls:
        request = {
            "agent": call.get("agent", "test-agent"),
            "action": call.get("action"),
            "resource": call.get("resource", ""),
            "context": _merged_context(call.get("context")),
        }
        was = evaluate_rules(request, previous, cwd=cwd or os.getcwd()).verdict
        now = evaluate_rules(request, candidate, cwd=cwd or os.getcwd()).verdict
        if rank[now] > rank[was]:
            loosened.append({**dict(call), "was": was, "now": now})

    return {"loosened": loosened, "ok": len(loosened) == 0}
