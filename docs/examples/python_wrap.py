"""Governing a Python agent's tools.

Run from the repository root::

    python docs/examples/python_wrap.py

``guard.wrap`` replaces each tool's callable with one that evaluates the call
first, and returns the same shape it was given — a mapping stays a mapping, a
list of framework tool objects stays a list of framework tool objects with their
schemas and descriptions intact.

This prints the same four outcomes as ``node-wrap.mjs``. That is the point: two
implementations of one engine, held in agreement by the shared conformance
fixture rather than by care.

WHAT ``wrap`` DOES NOT DO, in Python specifically: it does not broker secrets
and it does not write an audit chain. The Python ``Guard`` has no ``secrets`` or
``audit`` parameter. An agent that needs those routes through the gateway.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "packages" / "cirvix-python"))

from cirvix import CirvixDenied, CirvixHeld, guard, parse_rules  # noqa: E402

# The rule set is data — the same file the Node example reads. `rules` is the
# keyword `wrap` understands; there is no `policy_dir`.
with (HERE / "cirvix.policy.json").open(encoding="utf-8") as handle:
    rules = parse_rules(json.load(handle))


# --------------------------------------------------------------------------- #
#  The tools, ungoverned                                                       #
# --------------------------------------------------------------------------- #


def read_file(path: str) -> str:
    return f"<contents of {path}>"


def write_file(path: str, content: str) -> str:
    return f"wrote {len(content)} bytes to {path}"


def apply_manifest(target: str) -> str:
    return f"applied {target}"


# --------------------------------------------------------------------------- #
#  The same tools, governed                                                    #
# --------------------------------------------------------------------------- #

tools = guard.wrap(
    {"read_file": read_file, "write_file": write_file, "apply_manifest": apply_manifest},
    agent="pr-triage",
    environment=os.environ.get("CIRVIX_ENV", "production"),
    rules=rules,
)


# --------------------------------------------------------------------------- #


def attempt(label: str, call) -> None:
    try:
        print(f"PERMIT  {label}\n        {call()}\n")
    except CirvixHeld as err:
        # Caught before CirvixDenied — it is a subclass, so the broad clause
        # would swallow it and teach the agent that a hold is a failure.
        print(f"HOLD    {label}")
        print(f"        rule      {err.policy}")
        print(f"        approvers {', '.join(err.approvers)}\n")
    except CirvixDenied as err:
        print(f"DENY    {label}")
        print(f"        rule   {err.policy}")
        print(f"        reason {err.reason}")
        if err.remediation:
            print(f"        fix    {err.remediation}")
        print(f"        why    cirvix why {err.decision_id}\n")


print("\n  agent: pr-triage · environment: production\n")

attempt("read_file src/index.ts", lambda: tools["read_file"](path="src/index.ts"))
attempt("read_file .env.production", lambda: tools["read_file"](path=".env.production"))
attempt(
    "write_file src/out.txt",
    lambda: tools["write_file"](path="src/out.txt", content="hello"),
)
attempt(
    "apply_manifest production/checkout",
    lambda: tools["apply_manifest"](target="production/checkout"),
)
