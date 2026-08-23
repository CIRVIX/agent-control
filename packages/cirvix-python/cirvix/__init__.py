"""Cirvix AgentControl — runtime governance for Python AI agents.

Zero dependencies, standard library only. A security tool that drags in a
transitive dependency tree is asking to become the supply-chain incident it
exists to prevent.

    from cirvix import guard, CirvixDenied

    tools = guard.wrap(my_tools, agent="pr-triage", rules=rules)

    try:
        crew.kickoff()
    except CirvixDenied as err:
        print(err.policy)       # "deny-dotenv-read"
        print(err.remediation)  # 'secrets.get("STRIPE_KEY")'
        print(err.decision_id)  # pass to `cirvix why`

Enforcement is identical to the Node SDK and the MCP gateway, and that is not a
claim resting on care: all three run the shared conformance suite in
``packages/conformance/policy-conformance.json``.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version as package_version

from .guard import (
    CirvixDenied,
    CirvixHeld,
    Guard,
    action_for_tool,
    destination_for,
    resource_for_call,
    wrap,
)
from .policy import (
    EFFECT,
    STARTER_RULES,
    VERDICT,
    Decision,
    canonicalize_resource,
    evaluate,
    match_glob,
    parse_rules,
)

try:
    __version__ = package_version("cirvix")
except PackageNotFoundError:
    # Source checkouts are not installed distributions. The package metadata
    # and VERSION file are checked together by tools/check-version.mjs.
    __version__ = "0.1.0"

__all__ = [
    "CirvixDenied",
    "CirvixHeld",
    "Decision",
    "EFFECT",
    "Guard",
    "STARTER_RULES",
    "VERDICT",
    "action_for_tool",
    "canonicalize_resource",
    "destination_for",
    "evaluate",
    "guard",
    "match_glob",
    "parse_rules",
    "resource_for_call",
    "wrap",
]


class _GuardNamespace:
    """The documented entry point: ``guard.wrap(tools, ...)``.

    A namespace rather than a module so ``from cirvix import guard`` reads the
    same way as the Node SDK's ``import { guard }``.
    """

    wrap = staticmethod(wrap)
    Guard = Guard


guard = _GuardNamespace()
