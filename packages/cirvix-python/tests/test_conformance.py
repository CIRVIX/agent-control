"""The shared conformance suite, run against the Python engine.

``packages/agent-control/test/conformance.test.mjs`` runs the same file against
the Node engine. The fixture is the contract; neither implementation gets a
private copy, because the whole value is that a case cannot be made to pass in
one language and quietly skipped in the other.

Standard-library ``unittest`` rather than pytest, so this runs anywhere Python
does and adds no dependency to a security package.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cirvix.policy import evaluate  # noqa: E402

FIXTURE = Path(__file__).resolve().parents[2] / "conformance" / "policy-conformance.json"


def load_suite() -> dict:
    with FIXTURE.open(encoding="utf-8") as handle:
        return json.load(handle)


class ConformanceSuite(unittest.TestCase):
    """One test method per fixture case, generated below."""

    def test_fixture_is_present_and_non_trivial(self) -> None:
        # A suite that silently loads zero cases passes forever.
        suite = load_suite()
        self.assertEqual(suite["version"], 1)
        self.assertGreaterEqual(len(suite["cases"]), 40)
        names = [case["name"] for case in suite["cases"]]
        self.assertEqual(len(set(names)), len(names), "duplicate case names")


def _make_test(case: dict):
    def run(self: ConformanceSuite) -> None:
        decision = evaluate(
            {
                "agent": case["request"].get("agent"),
                "action": case["request"].get("action"),
                "resource": case["request"].get("resource"),
                "context": case["request"].get("context") or {},
            },
            case["rules"],
            cwd=case["cwd"],
        )
        expected = case["expect"]

        self.assertEqual(decision.verdict, expected["verdict"], "verdict")
        self.assertEqual(decision.rule, expected.get("rule"), "rule")

        # The five-outcome vocabulary. Asserted only when the case names it, so
        # the pre-existing cases keep testing exactly what they tested before.
        if "decision" in expected:
            self.assertEqual(decision.decision, expected["decision"], "decision")

        if "resource" in expected:
            self.assertEqual(decision.resource, expected["resource"], "canonical resource")
        if "approvers" in expected:
            self.assertEqual(decision.approvers, expected["approvers"], "approvers")
        if "considered" in expected:
            self.assertEqual(decision.considered, expected["considered"], "rule trace")

    return run


for _index, _case in enumerate(load_suite()["cases"]):
    _slug = "".join(ch if ch.isalnum() else "_" for ch in _case["name"]).strip("_").lower()
    setattr(ConformanceSuite, f"test_{_index:02d}_{_slug}", _make_test(_case))


class DeclaredCapabilities(unittest.TestCase):
    """What this engine claims to implement, checked against what it does.

    The fixture declares a capability matrix. A declaration nobody verifies is a
    comment, and the failure it is meant to catch is precise: a layer that
    exists on one engine, is absent on another, and has nothing anywhere
    comparing the two. That is how the Node gateway ended up enforcing
    delegation while the Node MCP path did not — for a whole release, with every
    suite green.

    So the check runs from both sides. Node asserts it IS listed for delegation
    and runs those cases. Python asserts it is NOT listed, and that the
    declaration is honest.
    """

    def test_python_implements_the_policy_core(self) -> None:
        capabilities = load_suite()["capabilities"]
        self.assertIn("python", capabilities["policy"])

    def test_python_declares_no_delegation_and_has_none(self) -> None:
        capabilities = load_suite()["capabilities"]
        self.assertNotIn(
            "python",
            capabilities["delegation"],
            "the fixture claims Python implements delegation",
        )

        # And the declaration is true. If delegation is ever added to this
        # package, this fails — which is the point: the engine cannot gain a
        # security layer without also gaining its conformance cases.
        import cirvix

        self.assertFalse(
            any("delegat" in name.lower() for name in dir(cirvix)),
            "cirvix exports something delegation-shaped but declares no delegation support",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
