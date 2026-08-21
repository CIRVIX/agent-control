"""The policy engine, in Python.

This is a second implementation of a security decision, which is a dangerous
thing to own. Two engines that can silently disagree are worse than one engine
and an honest gap: an agent denied by the Node gateway and permitted by the
Python SDK is a bypass nobody would find until it mattered.

What makes it safe to have is ``packages/conformance/policy-conformance.json``.
Both engines load that file and must produce identical verdicts, rules,
canonical resources, and rule traces. It is the contract; neither language gets
a private copy of it, and changing behaviour means changing the fixture first,
in a commit a reviewer can see.

Three properties are load-bearing and shared with the Node engine:

1. **Forbid always wins.** A ``forbid`` match cannot be overridden by any
   ``permit``, regardless of order. That is what makes a rule set safe to
   extend — adding a permissive rule can never silently punch a hole through an
   existing prohibition.
2. **Default deny.** A request matching nothing is denied. Fail-open is how a
   control plane becomes decorative the first time a rule file fails to parse.
3. **Resources are canonicalized before matching.** ``./x/../.env`` and an
   absolute path to the same file are one resource. Rules that match raw
   strings are bypassed by the first traversal attempt.

Zero dependencies, standard library only — the same reason the Node package
has none. A security tool that drags in a transitive dependency tree is asking
to become the supply-chain incident it exists to prevent.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlsplit

from .canonical import canonical_url, expand_home, fold_path

__all__ = [
    "DECISION",
    "EFFECT",
    "VERDICT",
    "Decision",
    "canonicalize_resource",
    "evaluate",
    "match_glob",
    "parse_rules",
    "to_decision",
    "STARTER_RULES",
]


class EFFECT:
    PERMIT = "permit"
    FORBID = "forbid"
    HOLD = "hold"
    #: Forward the call, but not as written — see ``DECISION.SANITIZE``.
    SANITIZE = "sanitize"
    #: Record that this rule matched, and authorize nothing.
    AUDIT_ONLY = "audit_only"


class VERDICT:
    PERMIT = "permit"
    DENY = "deny"
    HOLD = "hold"


class DECISION:
    """The five outcomes, matching ``core/decisions.mjs`` exactly.

    Kept in lockstep with the Node vocabulary because the two engines are joined
    by a shared conformance fixture, and a decision named differently in one
    language is a decision that cannot be reconciled across a fleet running
    both.
    """

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    SANITIZE = "sanitize"
    AUDIT_ONLY = "audit_only"


#: The accepted on-disk effects, in the order ``parse_rules`` names them.
#: Ordered to match the Node engine's error message exactly — the two are
#: compared by a conformance case, so a reordering here is a real failure.
_EFFECTS = (
    EFFECT.PERMIT,
    EFFECT.FORBID,
    EFFECT.HOLD,
    EFFECT.SANITIZE,
    EFFECT.AUDIT_ONLY,
)

_VERDICT_TO_DECISION = {
    VERDICT.PERMIT: DECISION.ALLOW,
    VERDICT.DENY: DECISION.DENY,
    VERDICT.HOLD: DECISION.REQUIRE_APPROVAL,
}


def to_decision(verdict: str | None) -> str:
    """Widens a three-state verdict into the five-outcome vocabulary."""
    return _VERDICT_TO_DECISION.get(str(verdict or "").lower(), DECISION.DENY)


_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
_DRIVE = re.compile(r"^([A-Za-z]:)(/.*)$")
_DRIVE_ABS = re.compile(r"^[A-Za-z]:/")


# --------------------------------------------------------------------------- #
#  Matching                                                                     #
# --------------------------------------------------------------------------- #


def match_glob(pattern: Any, value: Any) -> bool:
    """Glob matching: ``*`` within a segment, ``**`` across, ``?`` one character.

    Deliberately not a regular expression, for the same reason the Node engine
    is not one: ``*a*a*a*a*b`` against a long run of ``a`` makes a backtracking
    matcher explore every split of the input, and here the *pattern* comes from
    a policy rule while the *input* comes from whatever resource an agent named
    — so the party choosing the pathological input sits on the far side of the
    enforcement boundary, and a hung evaluator is a hung guard.

    MATCHED WITH DYNAMIC PROGRAMMING, NOT TWO POINTERS.

    Both engines used a two-pointer match, which remembers exactly one star
    position. That is correct only when every star has the same semantics, and
    here they do not: ``**`` crosses ``/`` and ``*`` does not. Once the matcher
    committed to an inner ``*`` it had forgotten the outer ``**`` and could not
    backtrack far enough, so ``match_glob("**/*", "/workspace/src/app.ts")``
    returned False — a rule written the natural way to say "any file at all"
    loaded, validated, and matched nothing.

    The DP is O(n·m) time and O(m) space: the same guarantee the two-pointer
    version was chosen for, and nothing an attacker can pick makes it explore
    exponentially.
    """
    if pattern in ("*", "**"):
        return True

    p = str(pattern).lower()
    v = str(value).lower()

    tokens: list[str] = []
    i = 0
    while i < len(p):
        if p[i] == "*":
            doubled = i + 1 < len(p) and p[i + 1] == "*"
            tokens.append("**" if doubled else "*")
            i += 2 if doubled else 1
        else:
            tokens.append(p[i])
            i += 1

    total = len(tokens)

    def is_star(token: str) -> bool:
        return token in ("*", "**")

    # dp[t] — the first `t` tokens match the value consumed so far.
    dp = [False] * (total + 1)
    dp[0] = True
    for t in range(total):
        if dp[t] and is_star(tokens[t]):
            dp[t + 1] = True

    for ch in v:
        nxt = [False] * (total + 1)
        for t in range(total):
            token = tokens[t]
            if token == "**":
                if dp[t] or dp[t + 1]:
                    nxt[t + 1] = True
            elif token == "*":
                if (dp[t] or dp[t + 1]) and ch != "/":
                    nxt[t + 1] = True
            elif token == "?":
                if dp[t] and ch != "/":
                    nxt[t + 1] = True
            elif dp[t] and ch == token:
                nxt[t + 1] = True

        # Stars that matched nothing at this position.
        for t in range(total):
            if nxt[t] and is_star(tokens[t]):
                nxt[t + 1] = True

        dp = nxt

    return dp[total]


def _match_any(patterns: Any, value: Any) -> bool:
    if patterns is None or patterns == "*":
        return True
    candidates = patterns if isinstance(patterns, (list, tuple)) else [patterns]
    if len(candidates) == 0:
        return True
    return any(match_glob(p, value) for p in candidates)


def canonicalize_resource(resource: Any, cwd: str | None = None) -> str:
    """Collapses equivalent references to one string.

    Filesystem paths resolve against ``cwd``; URLs normalize scheme and host and
    drop the fragment.
    """
    if not isinstance(resource, str) or resource == "":
        return ""

    if _SCHEME.match(resource):
        # Delegated so URLs canonicalize identically in both engines: alternate
        # IPv4 spellings, IPv4-mapped IPv6, trailing dots, and userinfo all
        # collapse. Hand-rolled URL handling here is how `169.254.169.254` and
        # `http://2852039166/` became two resources to the same rule.
        return canonical_url(resource) or resource

    # Fold before resolving. `~%2F.aws%2Fcredentials` has no literal separator,
    # so without this it stayed a bare token, was judged inside the workspace,
    # and a workspace-read rule permitted a credential read.
    folded = expand_home(fold_path(resource))
    if folded != resource:
        # One level only: `fold_path` is idempotent, so a second pass cannot
        # change the answer, and unbounded recursion on attacker-controlled
        # input would be its own bug.
        return canonicalize_resource(folded, cwd)

    # ``~`` is a real path, and agents write it constantly.
    #
    # Left unexpanded it resolved against the WORKSPACE — ``~/.aws/credentials``
    # became ``<cwd>/~/.aws/credentials``, a directory that does not exist — so a
    # rule written against the absolute home path failed to match the single most
    # common way an agent names a credential file. Matched to the Node engine's
    # behaviour; the conformance fixture pins it.
    if resource == "~" or resource.startswith("~/") or resource.startswith("~\\"):
        home = os.path.expanduser("~").replace("\\", "/").rstrip("/")
        return _resolve_path(home + resource[1:].replace("\\", "/"), cwd or os.getcwd())

    if "/" in resource or "\\" in resource or resource.startswith("."):
        return _resolve_path(resource, cwd if cwd is not None else os.getcwd())

    return resource


def _resolve_path(resource: str, cwd: str) -> str:
    """Resolves a path the same way on every platform.

    Deliberately **not** ``os.path.abspath`` or ``pathlib``, for the same reason
    the Node engine no longer uses ``path.resolve``: those are platform-aware,
    and on Windows they prepend the current drive to a drive-less absolute path.
    ``/etc/passwd`` would canonicalize to ``C:/etc/passwd`` there and
    ``/etc/passwd`` everywhere else, so a rule written ``resources: ["/etc/**"]``
    would match on a Linux runner and silently not match on a developer's
    Windows laptop — the machine the rule was most likely written to protect.
    """
    def norm(value: str) -> str:
        return str(value or "").replace("\\", "/")

    target = norm(resource)
    is_absolute = target.startswith("/") or bool(_DRIVE_ABS.match(target))
    combined = target if is_absolute else f"{norm(cwd).rstrip('/')}/{target}"

    # A drive letter is carried through untouched rather than invented.
    drive_match = _DRIVE.match(combined)
    drive = drive_match.group(1) if drive_match else ""
    body = drive_match.group(2) if drive_match else combined

    parts: list[str] = []
    for segment in body.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if parts:
                parts.pop()
            continue
        parts.append(segment)

    leading = "/" if body.startswith("/") else ""
    return drive + leading + "/".join(parts)


# --------------------------------------------------------------------------- #
#  Conditions                                                                   #
# --------------------------------------------------------------------------- #


def _is_number(value: Any) -> bool:
    # `bool` is a subclass of `int` in Python and is not a number here — the
    # Node engine's `typeof x === "number"` excludes booleans, and a comparator
    # that silently treated `True` as `1` would be a divergence.
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _eq(a: Any, b: Any) -> bool:
    # `1 == 1.0` is true in Python and `1 === 1.0` is also true in JavaScript,
    # but `1 == True` is true in Python and `1 === true` is false in JS. Types
    # are compared explicitly so the two engines agree.
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    return a == b


COMPARATORS = {
    "eq": _eq,
    "ne": lambda a, b: not _eq(a, b),
    "in": lambda a, b: isinstance(b, (list, tuple)) and any(_eq(a, x) for x in b),
    "nin": lambda a, b: isinstance(b, (list, tuple)) and not any(_eq(a, x) for x in b),
    "gt": lambda a, b: _is_number(a) and _is_number(b) and a > b,
    "gte": lambda a, b: _is_number(a) and _is_number(b) and a >= b,
    "lt": lambda a, b: _is_number(a) and _is_number(b) and a < b,
    "lte": lambda a, b: _is_number(a) and _is_number(b) and a <= b,
    "matches": lambda a, b: isinstance(a, str) and match_glob(str(b), a),
    "exists": lambda a, b: (a is not None) if b else (a is None),
    "contains": lambda a, b: isinstance(a, (list, tuple)) and any(_eq(x, b) for x in a),
    "supersetOf": lambda a, b: (
        isinstance(a, (list, tuple))
        and isinstance(b, (list, tuple))
        and all(any(_eq(x, y) for y in a) for x in b)
    ),
}


def _read_path(obj: Any, path: str) -> Any:
    current = obj
    for key in path.split("."):
        if isinstance(current, Mapping):
            current = current.get(key)
        else:
            return None
        if current is None:
            # Distinguishing "absent" from "present and null" would be a
            # divergence: JavaScript's optional chain yields `undefined` for
            # both, and `exists` is defined against that.
            return None
    return current


def _conditions_hold(conditions: Any, context: Mapping[str, Any]) -> bool:
    if not conditions:
        return True
    for condition in conditions:
        comparator = COMPARATORS.get((condition or {}).get("op"))
        # An unknown comparator fails closed. A policy file gets templated by
        # scripts, and a typo that silently matched everything would be the
        # worst possible failure mode.
        if comparator is None:
            return False
        if not comparator(_read_path(context, condition.get("path", "")), condition.get("value")):
            return False
    return True


# --------------------------------------------------------------------------- #
#  Evaluation                                                                   #
# --------------------------------------------------------------------------- #


@dataclass
class Decision:
    """A verdict and the reason for it.

    The explanation is a first-class output rather than a log line, because a
    refusal an agent cannot read is a refusal it cannot recover from.
    """

    verdict: str
    rule: str | None
    reason: str
    resource: str
    considered: list[dict[str, Any]] = field(default_factory=list)
    remediation: str | None = None
    approvers: list[str] = field(default_factory=list)
    decision_id: str | None = None
    #: The five-outcome vocabulary. ``verdict`` stays three-state so a caller
    #: that only understands permit/deny/hold keeps working unchanged.
    decision: str | None = None
    #: True when a named rule decided this, false for default-deny. Read by the
    #: risk floor, which may escalate an unnamed decision but never an explicit one.
    explicit: bool = False
    #: Populated on a SANITIZE decision: which sanitizers to run, and over what.
    sanitize: list[dict[str, Any]] = field(default_factory=list)
    #: The permit a sanitize decision was layered on top of.
    permitted_by: str | None = None
    #: ``audit_only`` rules that matched. Recorded; they authorize nothing.
    observed: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "verdict": self.verdict,
            "decision": self.decision or to_decision(self.verdict),
            "rule": self.rule,
            "reason": self.reason,
            "resource": self.resource,
            "considered": self.considered,
            "remediation": self.remediation,
            "approvers": self.approvers,
            "explicit": self.explicit,
            "decisionId": self.decision_id,
        }
        # Optional fields are omitted rather than emitted as null, matching the
        # Node engine's record shape so the two serialize identically.
        if self.sanitize:
            payload["sanitize"] = self.sanitize
        if self.permitted_by:
            payload["permittedBy"] = self.permitted_by
        if self.observed:
            payload["observed"] = self.observed
        return payload


def evaluate(
    request: Mapping[str, Any],
    rules: Sequence[Mapping[str, Any]],
    cwd: str | None = None,
) -> Decision:
    """Evaluates a request against an ordered rule set."""
    resource = canonicalize_resource(request.get("resource", ""), cwd)
    agent = request.get("agent")
    action = request.get("action")

    context: dict[str, Any] = dict(request.get("context") or {})
    context["agent"] = agent
    context["action"] = action

    considered: list[dict[str, Any]] = []
    first_permit: Mapping[str, Any] | None = None
    first_hold: Mapping[str, Any] | None = None
    #: Every matching sanitize rule, not just the first — sanitizers compose.
    sanitizers: list[Mapping[str, Any]] = []
    #: Matching ``audit_only`` rules. Recorded, never authorizing.
    observed: list[dict[str, Any]] = []

    for rule in rules or []:
        matched = (
            _match_any(rule.get("agents"), agent)
            and _match_any(rule.get("actions"), action)
            and _match_any(rule.get("resources"), resource)
            and _conditions_hold(rule.get("when"), context)
        )
        considered.append(
            {"rule": rule.get("name"), "effect": rule.get("effect"), "matched": matched}
        )

        if not matched:
            continue

        # forbid short-circuits — nothing after it can change the outcome.
        if rule.get("effect") == EFFECT.FORBID:
            return Decision(
                verdict=VERDICT.DENY,
                decision=DECISION.DENY,
                rule=rule.get("name"),
                reason=rule.get("reason") or f"Denied by {rule.get('name')}.",
                remediation=rule.get("remediation"),
                explicit=True,
                considered=considered,
                resource=resource,
                observed=observed,
            )
        if rule.get("effect") == EFFECT.HOLD and first_hold is None:
            first_hold = rule
        if rule.get("effect") == EFFECT.SANITIZE:
            sanitizers.append(rule)
        if rule.get("effect") == EFFECT.PERMIT and first_permit is None:
            first_permit = rule
        # ``audit_only`` lands here and nowhere else: recorded, contributing
        # nothing. A matching observation must never authorize a call, or
        # anyone who can add a rule has a bypass for every prohibition.
        if rule.get("effect") == EFFECT.AUDIT_ONLY:
            observed.append({"rule": rule.get("name"), "reason": rule.get("reason")})

    # A hold outranks a permit: if any rule says a human must see this, some
    # other permissive rule must not quietly skip them.
    if first_hold is not None:
        return Decision(
            verdict=VERDICT.HOLD,
            decision=DECISION.REQUIRE_APPROVAL,
            rule=first_hold.get("name"),
            reason=first_hold.get("reason") or f"Held by {first_hold.get('name')} pending approval.",
            approvers=list(first_hold.get("approvers") or []),
            explicit=True,
            considered=considered,
            resource=resource,
            observed=observed,
        )

    # Sanitize outranks permit: a rule saying "clean this first" must not be
    # skipped because some other rule also said the call was fine. It still
    # requires the call to be permitted at all — a sanitizer alone is not an
    # authorization, so a lone sanitize rule falls through to default-deny.
    if sanitizers and first_permit is not None:
        return Decision(
            verdict=VERDICT.PERMIT,
            decision=DECISION.SANITIZE,
            rule=sanitizers[0].get("name"),
            reason=(
                sanitizers[0].get("reason")
                or f"Permitted by {first_permit.get('name')}, with sanitization required by "
                f"{sanitizers[0].get('name')}."
            ),
            explicit=True,
            sanitize=[
                {
                    "rule": rule.get("name"),
                    "targets": _normalize_targets((rule.get("sanitize") or {}).get("targets")),
                    "strategies": list((rule.get("sanitize") or {}).get("strategies") or []),
                    "reason": rule.get("reason"),
                }
                for rule in sanitizers
            ],
            permitted_by=first_permit.get("name"),
            considered=considered,
            resource=resource,
            observed=observed,
        )

    if first_permit is not None:
        return Decision(
            verdict=VERDICT.PERMIT,
            decision=DECISION.ALLOW,
            rule=first_permit.get("name"),
            reason=first_permit.get("reason") or f"Permitted by {first_permit.get('name')}.",
            explicit=True,
            considered=considered,
            resource=resource,
            observed=observed,
        )

    return Decision(
        verdict=VERDICT.DENY,
        decision=DECISION.DENY,
        rule=None,
        reason=(
            f"No rule permits this call. {sanitizers[0].get('name')} would have sanitized it, "
            "but a sanitizer cleans an authorized call — it does not authorize one."
            if sanitizers
            else "No rule permits this call. The policy set is default-deny: an action "
            "must be explicitly allowed."
        ),
        remediation=(
            "Add a permit rule for this action, or run the engine in audit mode to log "
            "without enforcing."
        ),
        explicit=False,
        considered=considered,
        resource=resource,
        observed=observed,
    )


def _normalize_targets(targets: Any) -> list[str]:
    everything = ["arguments", "result"]
    if not targets:
        return everything
    candidates = targets if isinstance(targets, (list, tuple)) else [targets]
    chosen = [t for t in candidates if t in everything]
    return chosen or everything


def parse_rules(payload: Any) -> list[dict[str, Any]]:
    """Validates a rule set. Raises rather than dropping a rule it cannot read."""
    rules = payload if isinstance(payload, list) else (payload or {}).get("rules")
    if not isinstance(rules, list):
        raise ValueError("Policy must be a list of rules, or {'rules': [...]}.")

    for rule in rules:
        if not rule.get("name"):
            raise ValueError("Every rule needs a name.")
        if rule.get("effect") not in _EFFECTS:
            raise ValueError(
                f"Rule {rule.get('name')!r} has effect {rule.get('effect')!r}; "
                f"expected {', '.join(_EFFECTS)}."
            )
        for condition in rule.get("when") or []:
            if condition.get("op") not in COMPARATORS:
                raise ValueError(
                    f"Rule {rule.get('name')!r} uses unknown operator {condition.get('op')!r}."
                )
    return rules


#: The default rule set, identical to the Node package's ``STARTER_RULES``.
STARTER_RULES: list[dict[str, Any]] = [
    {
        "name": "deny-dotenv-read",
        "effect": EFFECT.FORBID,
        "actions": ["fs.read", "fs.*"],
        "resources": ["**/.env", "**/.env.*"],
        "reason": (
            "Reading .env files is denied outside an approved secrets flow. This is the "
            "single most common path from a prompt injection to a live credential."
        ),
        "remediation": 'Request the value as a handle: secrets.get("STRIPE_KEY")',
    },
    {
        "name": "deny-credential-files",
        "effect": EFFECT.FORBID,
        "actions": ["fs.read", "fs.*"],
        "resources": [
            "**/.aws/**",
            "**/.ssh/**",
            "**/.kube/config",
            "**/.npmrc",
            "**/.netrc",
            "**/.docker/config.json",
        ],
        "reason": "Cloud, SSH, and registry credentials are never readable by an agent.",
        "remediation": "Use a scoped secret handle instead of the credential file.",
    },
    {
        "name": "deny-workspace-escape",
        "effect": EFFECT.FORBID,
        "actions": ["fs.*"],
        "resources": ["*"],
        "when": [{"path": "path.insideWorkspace", "op": "eq", "value": False}],
        "reason": (
            "The resolved path is outside the workspace root. Traversal and symlinks are "
            "resolved before this check."
        ),
    },
    {
        "name": "require-approval-destructive",
        "effect": EFFECT.HOLD,
        "actions": ["fs.delete", "db.write", "db.migrate", "k8s.apply", "shell.exec"],
        "resources": ["*"],
        "when": [{"path": "environment", "op": "in", "value": ["production", "prod"]}],
        "approvers": ["platform-oncall"],
        "reason": (
            "Destructive or state-changing action in production. Held for a named human; "
            "the call waits rather than failing."
        ),
    },
    {
        "name": "deny-external-egress-after-secret",
        "effect": EFFECT.FORBID,
        "actions": ["http.request", "net.*"],
        "resources": ["*"],
        "when": [
            {"path": "egress.external", "op": "eq", "value": True},
            {"path": "session.touchedSecret", "op": "eq", "value": True},
        ],
        "reason": (
            "This session read secret material, so outbound requests to external "
            "destinations are blocked for the remainder of it."
        ),
    },
    {
        "name": "allow-workspace-read",
        "effect": EFFECT.PERMIT,
        "actions": ["fs.read", "fs.list", "fs.stat"],
        "resources": ["*"],
        "when": [{"path": "path.insideWorkspace", "op": "eq", "value": True}],
        "reason": "Read inside the workspace root.",
    },
    {
        "name": "allow-workspace-write",
        "effect": EFFECT.PERMIT,
        "actions": ["fs.write"],
        "resources": ["*"],
        "when": [{"path": "path.insideWorkspace", "op": "eq", "value": True}],
        "reason": "Write inside the workspace root.",
    },
    {
        "name": "allow-allowlisted-egress",
        "effect": EFFECT.PERMIT,
        "actions": ["http.request", "net.*"],
        "resources": ["*"],
        "when": [{"path": "egress.allowlisted", "op": "eq", "value": True}],
        "reason": "Destination is on the egress allowlist.",
    },
    {
        "name": "allow-read-only-tools",
        "effect": EFFECT.PERMIT,
        "actions": ["*.read", "*.list", "*.search", "*.get", "*.query"],
        "resources": ["*"],
        "reason": "Read-only tool call.",
    },
]
