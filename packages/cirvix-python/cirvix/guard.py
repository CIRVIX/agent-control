"""``guard.wrap`` — governing a Python agent that does not speak MCP.

The MCP gateway governs everything an agent does, including tools added after
you deployed it, because it sits on the wire. It also requires the agent to
speak MCP. CrewAI, AutoGen, and LangGraph do not, so this is the boundary for
them: wrap the tool collection, keep the same engine, the same rules, and the
same decision record.

**The trade, stated rather than glossed.** You give up the property that makes
the gateway worth deploying — it governs tools nobody told it about — because
you are wrapping a list. An operator who believes ``wrap`` is equivalent to the
gateway will not understand why a tool the agent reached directly was never
evaluated.

Enforcement semantics are identical to the Node SDK by construction: both run
the shared conformance suite in ``packages/conformance``.
"""

from __future__ import annotations

import inspect
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit

from .policy import VERDICT, Decision, evaluate

__all__ = [
    "CirvixDenied",
    "CirvixHeld",
    "Guard",
    "action_for_tool",
    "destination_for",
    "resource_for_call",
    "wrap",
]


class CirvixDenied(Exception):
    """A refusal the agent can read and plan around.

    Raised rather than returned because a wrapped tool has to interrupt the
    call, and carrying structure rather than a string is what lets an agent
    re-plan instead of retrying the same thing — ``remediation`` frequently
    names the legitimate path.
    """

    def __init__(
        self,
        *,
        policy: str | None = None,
        decision_id: str | None = None,
        reason: str | None = None,
        remediation: str | None = None,
        appealable: bool = False,
        resource: str | None = None,
        action: str | None = None,
    ) -> None:
        super().__init__(reason or f"Denied by {policy or 'policy'}.")
        self.policy = policy
        self.decision_id = decision_id
        self.reason = reason
        self.remediation = remediation
        self.appealable = appealable
        self.resource = resource
        self.action = action


class CirvixHeld(CirvixDenied):
    """A call suspended for a person.

    A distinct type from a denial because they call for different behaviour: a
    denial means re-plan, a hold means this exact call may still happen once
    somebody says yes. Collapsing them teaches agents to treat both as failure.
    """

    def __init__(self, *, approvers: Sequence[str] | None = None, approval_id: str | None = None, **kwargs: Any) -> None:
        kwargs["appealable"] = True
        super().__init__(**kwargs)
        self.approvers = list(approvers or [])
        self.approval_id = approval_id


_ACTION_PATTERNS = [
    (re.compile(r"(^|[._-])(read|get|cat|fetch)($|[._-])"), "fs.read"),
    (re.compile(r"(^|[._-])(write|create|put|save|edit)($|[._-])"), "fs.write"),
    (re.compile(r"(^|[._-])(delete|remove|rm|unlink|drop)($|[._-])"), "fs.delete"),
    (re.compile(r"(^|[._-])(list|ls|search|find|query|grep)($|[._-])"), "fs.list"),
    (re.compile(r"(^|[._-])(exec|run|shell|command|spawn)($|[._-])"), "shell.exec"),
    (re.compile(r"(^|[._-])(request|http|curl|browse|scrape)($|[._-])"), "http.request"),
    (re.compile(r"(^|[._-])(apply|deploy|rollout)($|[._-])"), "k8s.apply"),
]

_RESOURCE_KEYS = (
    "path", "file", "filename", "filepath", "uri", "url", "resource", "target", "query", "sql",
)


def action_for_tool(server: str | None, tool: str) -> str:
    """Maps a tool name to the action vocabulary policy is written against.

    An unrecognised name falls back to a namespaced action rather than to a
    permissive default, so a rule can always be written for it.
    """
    lowered = str(tool).lower()
    for pattern, action in _ACTION_PATTERNS:
        if pattern.search(lowered):
            return action
    return f"mcp.{server}.{tool}" if server else f"tool.{tool}"


def resource_for_call(args: Any) -> str:
    """Extracts the resource a call targets. Best-effort: an unrecognised shape
    yields the empty string, so the call is still evaluated rather than skipped.
    """
    if not isinstance(args, Mapping):
        return ""
    for key in _RESOURCE_KEYS:
        value = args.get(key)
        if isinstance(value, str) and value:
            return value
    for value in args.values():
        if isinstance(value, str) and value:
            return value
    return ""


def destination_for(resource: str, args: Any) -> str | None:
    """The endpoint a call will reach, or ``None``.

    Only an absolute http(s) URL counts. A relative path or a bare tool name is
    not somewhere a credential can be sent, and treating one as a destination
    would let a handle resolve against a string the broker cannot meaningfully
    authorize.
    """
    candidates = [resource]
    if isinstance(args, Mapping):
        candidates += [args.get("url"), args.get("uri"), args.get("endpoint"), args.get("href")]
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.lower().startswith(("http://", "https://")):
            return candidate
    return None


@dataclass
class Guard:
    """One decision, made the same way wherever it is made from.

    Holds the session-scoped state a verdict can depend on — most importantly
    ``touched_secret``, which is what makes "read a credential, then post it
    somewhere" fail even when both calls are individually allowed.
    """

    rules: Sequence[Mapping[str, Any]] = field(default_factory=list)
    agent: str = "local"
    environment: str = "local"
    cwd: str | None = None
    on_decision: Callable[[dict[str, Any]], None] = lambda record: None
    log: Callable[[str], None] = lambda message: None
    run_id: str | None = None
    touched_secret: bool = False
    stats: dict[str, int] = field(
        default_factory=lambda: {"calls": 0, "permitted": 0, "denied": 0, "held": 0}
    )
    _next_id: int = 1

    def __post_init__(self) -> None:
        """Resolves the workspace root once, at construction.

        ``cwd`` defaults to ``None`` so the dataclass field is optional, but
        every use of it downstream is a path join. Left unresolved, the join
        produced the literal string ``"None/src/index.ts"``, which is inside no
        workspace — so a ``Guard`` built the documented way, without an explicit
        ``cwd``, denied every filesystem call via ``deny-workspace-escape``.

        The conformance fixture could not catch this: it exercises ``evaluate``
        directly and always passes ``cwd`` explicitly. The defect lived in the
        wrapper, one layer above the engine the fixture pins.
        """
        if self.cwd is None:
            self.cwd = os.getcwd()

    def authorize(self, *, tool: str, args: Mapping[str, Any] | None = None, server: str | None = None) -> Decision:
        """Decides one call. Executes nothing."""
        args = args or {}
        action = action_for_tool(server, tool)
        resource = resource_for_call(args)

        context = {
            "environment": self.environment,
            "path": {"insideWorkspace": self.inside_workspace(resource)},
            "egress": {"external": self.is_external(resource), "allowlisted": False},
            "session": {"touchedSecret": self.touched_secret},
            "mcp": {"server": server, "tool": tool},
        }

        decision = evaluate(
            {"agent": self.agent, "action": action, "resource": resource, "context": context},
            self.rules,
            cwd=self.cwd,
        )
        decision.decision_id = f"dec_{int(time.time() * 1000):x}{self._next_id:x}"
        self._next_id += 1
        self.stats["calls"] += 1

        record = {
            "decision_id": decision.decision_id,
            "runId": self.run_id,
            "agent": self.agent,
            "server": server,
            "tool": tool,
            "action": action,
            "resource": decision.resource,
            "verdict": decision.verdict,
            "rule": decision.rule,
            "reason": decision.reason,
            "context": context,
            "considered": decision.considered[:200],
        }
        self.on_decision({"kind": "decision", **record})

        if decision.verdict == VERDICT.DENY:
            self.stats["denied"] += 1
        elif decision.verdict == VERDICT.HOLD:
            self.stats["held"] += 1
        else:
            self.stats["permitted"] += 1
            # Any successful read of secret-shaped material taints the session,
            # which the egress rule then keys on.
            if re.search(r"secret|credential|token|password|\.env", decision.resource, re.IGNORECASE):
                self.touched_secret = True

        return decision

    def to_error(self, decision: Decision) -> CirvixDenied:
        """Turns a non-permit verdict into the exception a caller should see."""
        fields = {
            "policy": decision.rule,
            "decision_id": decision.decision_id,
            "reason": decision.reason,
            "remediation": decision.remediation,
            "resource": decision.resource,
        }
        if decision.verdict == VERDICT.HOLD:
            return CirvixHeld(approvers=decision.approvers, **fields)
        return CirvixDenied(**fields)

    def inside_workspace(self, resource: str) -> bool:
        if not resource:
            return True
        if re.match(r"^[a-z][a-z0-9+.-]*://", resource, re.IGNORECASE):
            return False

        def norm(value: str) -> str:
            return str(value).replace("\\", "/").rstrip("/").lower()

        root = norm(self.cwd or "")
        absolute = resource if re.match(r"^([A-Za-z]:|/)", resource) else f"{self.cwd}/{resource}"
        parts: list[str] = []
        for segment in norm(absolute).split("/"):
            if segment == "..":
                if parts:
                    parts.pop()
            elif segment != ".":
                parts.append(segment)
        flat = "/".join(parts)
        return flat == root or flat.startswith(root + "/")

    def is_external(self, resource: str) -> bool:
        if not str(resource).lower().startswith(("http://", "https://")):
            return False
        try:
            host = urlsplit(resource).hostname or ""
        except ValueError:
            return True
        return not re.match(
            r"^(localhost|127\.|::1|0\.0\.0\.0|.*\.internal|.*\.local)$", host, re.IGNORECASE
        )


# --------------------------------------------------------------------------- #
#  wrap                                                                         #
# --------------------------------------------------------------------------- #

#: Attribute names the Python agent frameworks put their callable on.
#: LangChain uses ``func`` and ``_run``; CrewAI uses ``_run``; AutoGen registers
#: plain callables.
CALLABLE_ATTRS = ("func", "_run", "run", "invoke", "call", "execute", "handler")


def wrap(tools: Any, guard: Guard | None = None, **options: Any) -> Any:
    """Governs a collection of tools in place, returning the same shape.

    Accepts the shapes Python tool collections actually come in:

    * a mapping of ``name -> callable``
    * a sequence of tool objects carrying a callable attribute (LangChain,
      CrewAI, AutoGen)
    * a single callable, named by ``name=``

    Both sync and async callables are handled — an async tool stays async, or
    the framework's ``await`` would receive a coroutine-returning wrapper it
    does not expect.
    """
    active = guard or Guard(**options)

    if callable(tools) and not isinstance(tools, (Mapping, list, tuple)):
        return _wrap_callable(tools, options.get("name") or getattr(tools, "__name__", "tool"), active)

    if isinstance(tools, Mapping):
        return {
            name: (_wrap_callable(value, name, active) if callable(value) else value)
            for name, value in tools.items()
        }

    if isinstance(tools, (list, tuple)):
        wrapped = []
        for tool in tools:
            if callable(tool) and not hasattr(tool, "__dict__"):
                wrapped.append(_wrap_callable(tool, getattr(tool, "__name__", "tool"), active))
                continue
            attr = next((a for a in CALLABLE_ATTRS if callable(getattr(tool, a, None))), None)
            if attr is None:
                wrapped.append(tool)
                continue
            name = getattr(tool, "name", None) or getattr(tool, "__name__", "tool")
            # The tool object is mutated in place only after being copied, so a
            # framework holding the original list does not find it governed as a
            # side effect of us reading it.
            clone = _shallow_clone(tool)
            setattr(clone, attr, _wrap_callable(getattr(tool, attr), name, active))
            wrapped.append(clone)
        return type(tools)(wrapped) if isinstance(tools, tuple) else wrapped

    raise TypeError("guard.wrap expects a callable, a sequence of tools, or a mapping of tools.")


def _shallow_clone(tool: Any) -> Any:
    try:
        clone = object.__new__(type(tool))
        clone.__dict__.update(getattr(tool, "__dict__", {}))
        return clone
    except TypeError:
        # Some framework tools use __slots__ or a custom __new__. Governing the
        # original is better than refusing to govern it at all; the caller is
        # told by the docstring that this case mutates.
        return tool


def _wrap_callable(fn: Callable[..., Any], name: str, guard: Guard) -> Callable[..., Any]:
    def prepare(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Mapping[str, Any]:
        # Frameworks call tools with keyword arguments, with a single mapping,
        # or positionally. Only the first two carry anything a policy can read;
        # pretending otherwise would evaluate against an empty resource and
        # report the result as if it meant something.
        if kwargs:
            return kwargs
        if len(args) == 1 and isinstance(args[0], Mapping):
            return args[0]
        return {"input": args[0]} if args else {}

    if inspect.iscoroutinefunction(fn):

        async def governed_async(*args: Any, **kwargs: Any) -> Any:
            decision = guard.authorize(tool=name, args=prepare(args, kwargs))
            if decision.verdict != VERDICT.PERMIT:
                raise guard.to_error(decision)
            return await fn(*args, **kwargs)

        governed_async.__name__ = name
        governed_async.__doc__ = fn.__doc__
        governed_async.__wrapped__ = fn
        return governed_async

    def governed(*args: Any, **kwargs: Any) -> Any:
        decision = guard.authorize(tool=name, args=prepare(args, kwargs))
        if decision.verdict != VERDICT.PERMIT:
            raise guard.to_error(decision)
        return fn(*args, **kwargs)

    # Frameworks introspect ``__name__`` to build their tool registry, and an
    # anonymous wrapper would silently rename every governed tool.
    governed.__name__ = name
    governed.__doc__ = fn.__doc__
    governed.__wrapped__ = fn
    return governed
