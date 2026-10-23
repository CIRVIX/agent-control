"""Structural classification of a SQL statement, and of a git invocation.

WHY THIS EXISTS

``guard.action_for_tool`` mapped a tool named ``sql_query`` to **``fs.list``**,
because the pattern for filesystem listing included the word ``query``. A
database query was therefore authorized as a directory listing, and
``allow-workspace-read`` — which permits ``fs.list`` — permitted
``DROP TABLE users``. There was no database action in the vocabulary at all,
and no rule could name one.

The two engines are joined by a shared conformance fixture, so their *policy
evaluation* agrees by construction. Their *classification* did not, which is
the half a caller can exploit: the same call is refused by one engine and
allowed by the other, and no fixture comparing policy evaluation can see it.

This module is the Python counterpart of ``core/sql.mjs`` and
``risk.analyzeGitPush``. It is deliberately smaller — the Python guard has no
risk engine — but it answers the same two questions the same way, so a
statement or a flag is classified identically whichever engine is in front of
the agent.

FAIL CLOSED

A statement whose governing verb is not recognised is ``unknown``, never
``read``. The only statements that come back ``read`` are ones whose verb is
provably read-only.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["SQL_KIND", "analyze_sql", "analyze_git_push", "is_sql_tool", "looks_like_sql"]

_READ_VERBS = frozenset({"select", "table", "values", "show", "describe", "desc"})
_WRITE_VERBS = frozenset(
    {
        "insert", "update", "delete", "merge", "upsert", "replace", "create", "load",
        "import", "set", "pragma", "vacuum", "analyze", "analyse", "reindex", "cluster",
        "refresh", "reset", "move", "comment", "label", "lock", "listen", "notify", "prepare",
    }
)
_DESTRUCTIVE_VERBS = frozenset(
    {
        "drop", "truncate", "alter", "grant", "revoke", "rename", "copy", "attach",
        "detach", "call", "do", "execute", "exec", "impersonate", "kill", "deny", "shutdown",
    }
)
_BENIGN_VERBS = frozenset(
    {
        "begin", "commit", "rollback", "start", "savepoint", "release", "end", "explain",
        "deallocate", "use", "discard",
    }
)
_ALL_VERBS = _READ_VERBS | _WRITE_VERBS | _DESTRUCTIVE_VERBS | _BENIGN_VERBS | {"with"}

_RANK = {"read": 0, "write": 1, "unknown": 1, "destructive": 2}


class SQL_KIND:
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"
    UNKNOWN = "unknown"


_LINE_COMMENT = re.compile(r"--|#")
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*|[()]|,")


def _strip_noise(source: str) -> str:
    """Remove comments and replace string literals with a marker.

    Both halves matter. A comment can carry a semicolon that would split a
    statement in the wrong place, or a verb that would fabricate one, and a
    literal can do the same (``SELECT 'DROP TABLE x'``). What survives is the
    SQL the server will actually parse.
    """
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if (ch == "-" and nxt == "-") or ch == "#":
            while i < n and source[i] != "\n":
                i += 1
            out.append(" ")
            continue

        if ch == "/" and nxt == "*":
            i += 2
            depth = 1
            while i < n and depth > 0:
                if source[i] == "/" and i + 1 < n and source[i + 1] == "*":
                    depth += 1
                    i += 2
                elif source[i] == "*" and i + 1 < n and source[i + 1] == "/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
            out.append(" ")
            continue

        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            while i < n:
                if source[i] == "\\" and quote != '"':
                    i += 2
                    continue
                if source[i] == quote:
                    if i + 1 < n and source[i + 1] == quote:
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            out.append(" '' ")
            continue

        if ch == "$":
            marker = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$", source[i : i + 64])
            if marker:
                tag = marker.group(0)
                close = source.find(tag, i + len(tag))
                if close == -1:
                    out.append(" '' ")
                    break
                i = close + len(tag)
                out.append(" '' ")
                continue

        out.append(ch)
        i += 1
    return "".join(out)


def _skip_group(tokens: list[str], i: int) -> int:
    if i >= len(tokens) or tokens[i] != "(":
        return i
    depth = 0
    while i < len(tokens):
        if tokens[i] == "(":
            depth += 1
        elif tokens[i] == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(tokens)


def _skip_ctes(tokens: list[str], i: int) -> int:
    """Index after a leading ``WITH … AS (…) [, …]`` CTE list.

    The verb of ``WITH x AS (SELECT 1) DELETE FROM y`` is ``delete``, and it
    sits behind an arbitrary number of parenthesized bodies. Skipping the CTE
    list is what lets the classifier see it.
    """
    while i < len(tokens):
        token = tokens[i]
        if not re.match(r"^[A-Za-z_]", token) or token.lower() in _ALL_VERBS:
            break
        i += 1
        if i < len(tokens) and tokens[i] == "(":
            i = _skip_group(tokens, i)
        if (tokens[i] if i < len(tokens) else "").lower() != "as":
            break
        i += 1
        for wrapper in ("not", "materialized"):
            if (tokens[i] if i < len(tokens) else "").lower() == wrapper:
                i += 1
        if i >= len(tokens) or tokens[i] != "(":
            break
        i = _skip_group(tokens, i)
        if i < len(tokens) and tokens[i] == ",":
            i += 1
            continue
        break
    return i


def _governing_verbs(fragment: str) -> list[str]:
    tokens = _TOKEN.findall(fragment)
    if not tokens:
        return []
    i = 0
    while i < len(tokens) and tokens[i] in ("(", ","):
        i += 1
    if (tokens[i] if i < len(tokens) else "").lower() == "with":
        i += 1
        if (tokens[i] if i < len(tokens) else "").lower() == "recursive":
            i += 1
        i = _skip_ctes(tokens, i)
        while i < len(tokens) and tokens[i] in ("(", ","):
            i += 1

    first = (tokens[i] if i < len(tokens) else "").lower()
    if not first:
        return []
    verbs = [first]

    # ``EXPLAIN`` / ``EXPLAIN ANALYZE``: the second verb is what runs.
    if first == "explain":
        j = i + 1
        for wrapper in ("analyze", "analyse", "verbose", "buffers", "format"):
            if (tokens[j] if j < len(tokens) else "").lower() == wrapper:
                j += 1
        inner = (tokens[j] if j < len(tokens) else "").lower()
        if inner and inner != "select":
            verbs.append(inner)
    return verbs


def _kind_of(verb: str) -> str | None:
    if not verb:
        return None
    if verb in _READ_VERBS or verb in _BENIGN_VERBS:
        return SQL_KIND.READ
    if verb in _WRITE_VERBS:
        return SQL_KIND.WRITE
    if verb in _DESTRUCTIVE_VERBS:
        return SQL_KIND.DESTRUCTIVE
    return None


def analyze_sql(source: Any) -> dict[str, Any]:
    """Classify a SQL statement, or a batch of them.

    Returns the most severe kind across every statement, so
    ``SELECT 1; DROP TABLE users`` is ``destructive`` — an appended statement
    cannot ride in behind a read.
    """
    if not isinstance(source, str) or not source.strip():
        return {"kind": "empty", "verbs": [], "statements": 0}

    fragments = [f.strip() for f in _strip_noise(source).split(";") if f.strip()]
    if not fragments:
        return {"kind": "empty", "verbs": [], "statements": 0}

    verbs: list[str] = []
    kind = SQL_KIND.READ
    saw_known = False

    for fragment in fragments:
        governing = _governing_verbs(fragment)
        kinds = [k for k in (_kind_of(v) for v in governing) if k]
        for verb in governing:
            if verb not in verbs:
                verbs.append(verb)
        if not kinds:
            # A statement whose verb is not in the table is not a read.
            if _RANK[SQL_KIND.UNKNOWN] > _RANK[kind]:
                kind = SQL_KIND.UNKNOWN
            continue
        saw_known = True
        for candidate in kinds:
            if _RANK[candidate] > _RANK[kind]:
                kind = candidate

    if not saw_known:
        kind = SQL_KIND.UNKNOWN

    return {"kind": kind, "verbs": verbs, "statements": len(fragments)}


def looks_like_sql(text: Any) -> bool:
    """True when the text plausibly is a SQL statement rather than a name."""
    if not isinstance(text, str):
        return False
    clean = _strip_noise(text).strip()
    if not clean:
        return False
    if clean.startswith("("):
        return True
    first = re.match(r"^[A-Za-z_][A-Za-z0-9_]*", clean)
    if not first:
        return False
    return first.group(0).lower() in _ALL_VERBS


def is_sql_tool(name: Any) -> bool:
    """True when a tool name says it runs SQL, whatever verb it is spelled with."""
    text = str(name or "")
    if re.search(r"sql", text, re.IGNORECASE):
        return True
    return bool(
        re.search(
            r"(^|[._\- ])(db|database|postgres|postgresql|mysql|mariadb|sqlite|mssql"
            r"|clickhouse|snowflake|bigquery|redshift|oracle|duckdb)([._\- ]|$)",
            text,
            re.IGNORECASE,
        )
    )


def is_read_escalating(kind: Any) -> bool:
    """True when the canonical read action must be raised to a write."""
    return kind in (SQL_KIND.WRITE, SQL_KIND.DESTRUCTIVE, SQL_KIND.UNKNOWN)


# --------------------------------------------------------------------------- #
#  Git                                                                        #
# --------------------------------------------------------------------------- #

_PROTECTED_REF = re.compile(
    r"^(refs/heads/)?(main|master|trunk|production|prod|release)$|^release/", re.IGNORECASE
)


def analyze_git_push(command: Any) -> dict[str, Any] | None:
    """Decide, from the argument tokens, whether a command is a git push and how it forces.

    Quotes are STRIPPED rather than treated as grouping, so
    ``sh -c "git push --force origin main"`` is seen through. Every git
    invocation in the command is examined: ``git status && git push --force``
    names the dangerous call second.
    """
    if not isinstance(command, str) or not command:
        return None
    tokens = [t.replace('"', "").replace("'", "") for t in command.split()]
    tokens = [t for t in tokens if t]
    if not tokens:
        return None

    found: list[dict[str, Any]] = []
    for index, token in enumerate(tokens):
        if re.search(r"(^|[/\\])git(\.exe)?$", token, re.IGNORECASE):
            parsed = _parse_push_at(tokens, index)
            if parsed:
                found.append(parsed)
    if not found:
        return None

    return {
        "force": any(f["force"] for f in found),
        "force_with_lease": any(f["force_with_lease"] for f in found),
        "protected_ref": any(f["protected_ref"] for f in found),
    }


def _parse_push_at(tokens: list[str], start: int) -> dict[str, Any] | None:
    i = start + 1
    while i < len(tokens):
        token = tokens[i]
        if token in ("-C", "-c"):
            i += 2
            continue
        if token.startswith("-"):
            i += 1
            continue
        break

    if (tokens[i] if i < len(tokens) else "").lower() != "push":
        return None

    force = False
    force_with_lease = False
    remote: str | None = None
    refspecs: list[str] = []

    for token in tokens[i + 1 :]:
        lower = token.lower()
        if lower == "--force-with-lease" or lower.startswith("--force-with-lease="):
            force_with_lease = True
            continue
        if lower in ("--force-if-includes",):
            continue
        if lower == "--force":
            force = True
            continue
        # A single-dash cluster such as -f, -uf, -fu. `-o` takes a value and is
        # the one short push flag whose operand can be the letter f.
        if re.match(r"^-[A-Za-z]+$", token) and not token.startswith("-o"):
            if "f" in token:
                force = True
            continue
        if token.startswith("-"):
            continue
        if remote is None:
            remote = token
            continue
        refspecs.append(token)

    if any(r.startswith("+") for r in refspecs):
        force = True

    protected = False
    for ref in refspecs:
        dst = ref.split(":", 1)[1] if ":" in ref else ref
        if _PROTECTED_REF.search(dst.lstrip("+")):
            protected = True

    return {
        "force": force,
        "force_with_lease": force_with_lease,
        "protected_ref": protected,
        "remote": remote,
    }
