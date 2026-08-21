"""Canonicalization — collapsing every spelling of a thing to one string.

A line-for-line counterpart of ``core/canonical.mjs``. The two are joined by the
shared conformance fixture, and every rule in this file exists because the same
rule in the Node engine closed a real bypass:

* alternate IPv4 spellings — ``http://2852039166/`` is 169.254.169.254 in
  decimal, and every HTTP client dials it. A destination rule naming the dotted
  address did not match it.
* percent-encoded paths — ``~%2F.aws%2Fcredentials`` contains no literal
  separator, so it was judged a bare filename inside the workspace and a
  workspace-read rule permitted a credential read.
* Unicode homoglyph separators and zero-width characters — ``.aws`` written with
  U+2024 ONE DOT LEADER is a different string and the same directory.
* trailing dots and spaces — NTFS strips them on open, so ``.env `` and ``.env``
  are one file and two strings.

THE PRINCIPLE, RESTATED HERE BECAUSE IT DECIDES EVERY CASE

Canonicalize toward what the *receiving system* will do, not toward what the
string looks like. Where a spelling is ambiguous, take the reading that reaches
the sensitive resource — that is the reading an attacker is relying on.
"""

from __future__ import annotations

import os
import re
import unicodedata
from urllib.parse import unquote, urlsplit

__all__ = [
    "canonical_host",
    "canonical_url",
    "decode_path",
    "expand_home",
    "fold_path",
    "numeric_to_ipv4",
]

_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)


# --------------------------------------------------------------------------- #
#  Hosts and URLs                                                             #
# --------------------------------------------------------------------------- #


def numeric_to_ipv4(value: str) -> str | None:
    """Resolves a numeric host spelling to dotted-quad, or ``None``.

    Implements the ``inet_aton`` forms every resolver still accepts: one 32-bit
    number, two parts, three, or four — each part decimal, octal (leading zero),
    or hex (leading ``0x``).
    """
    s = str(value or "").strip()
    if not s or not re.fullmatch(r"[0-9a-fx.]+", s, re.IGNORECASE):
        return None

    parts = s.split(".")
    if len(parts) > 4 or any(p == "" for p in parts):
        return None

    nums: list[int] = []
    for part in parts:
        try:
            if re.fullmatch(r"0x[0-9a-f]+", part, re.IGNORECASE):
                n = int(part, 16)
            elif re.fullmatch(r"0[0-7]+", part):
                n = int(part, 8)
            elif re.fullmatch(r"\d+", part):
                n = int(part, 10)
            else:
                return None
        except ValueError:
            return None
        if n < 0:
            return None
        nums.append(n)

    # A plain dotted-quad is already canonical; returning it unchanged keeps
    # `canonical_host` idempotent.
    if len(nums) == 4 and all(n <= 255 for n in nums) and re.fullmatch(r"\d+(\.\d+){3}", s):
        return ".".join(str(n) for n in nums)

    # inet_aton packing: the last part absorbs the remaining octets.
    max_last = 2 ** (8 * (4 - len(nums) + 1))
    if any(n > 255 for n in nums[:-1]):
        return None
    if nums[-1] >= max_last:
        return None

    packed = 0
    for i, n in enumerate(nums[:-1]):
        packed |= n << (8 * (3 - i))
    packed = (packed + nums[-1]) & 0xFFFFFFFF

    return ".".join(str((packed >> shift) & 255) for shift in (24, 16, 8, 0))


def canonical_host(value: str) -> str | None:
    """Normalizes a hostname to one comparable form."""
    if not isinstance(value, str) or not value:
        return None

    host = value.strip().lower().rstrip(".")
    bare = host.strip("[]")

    # IPv4-mapped and IPv4-compatible IPv6 route to the embedded v4 address.
    mapped = re.fullmatch(r"::ffff:(\d{1,3}(?:\.\d{1,3}){3})", bare, re.IGNORECASE) or re.fullmatch(
        r"::(\d{1,3}(?:\.\d{1,3}){3})", bare
    )
    if mapped:
        return mapped.group(1)

    # The same address after a URL parser has compressed it to hex.
    hex_mapped = re.fullmatch(r"::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})", bare, re.IGNORECASE)
    if hex_mapped:
        high = int(hex_mapped.group(1), 16)
        low = int(hex_mapped.group(2), 16)
        return ".".join(str(x) for x in ((high >> 8) & 255, high & 255, (low >> 8) & 255, low & 255))

    numeric = numeric_to_ipv4(bare)
    if numeric:
        return numeric

    return bare


def canonical_url(value: str) -> str | None:
    """Normalizes a URL. Returns ``None`` when the value is not one.

    Userinfo is DROPPED rather than preserved: it is not where the request goes,
    and keeping it lets a destination rule be defeated by prefixing a host that
    looks innocuous (``http://docs.example.com@169.254.169.254/``).
    """
    if not isinstance(value, str) or not _SCHEME.match(value):
        return None

    try:
        parts = urlsplit(value)
    except ValueError:
        return None

    raw_host = parts.hostname or ""
    host = canonical_host(raw_host) or raw_host.lower()
    port = f":{parts.port}" if parts.port else ""
    path = parts.path.rstrip("/")
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme.lower()}://{host}{port}{path}{query}"


# --------------------------------------------------------------------------- #
#  Paths                                                                      #
# --------------------------------------------------------------------------- #

MAX_DECODE_PASSES = 3

#: Separator look-alikes NFKC does not fold. U+2024 ONE DOT LEADER survives
#: NFKC, and it is the one an attacker reaches for.
_HOMOGLYPHS = {
    "．": ".",
    "․": ".",
    "。": ".",
    "／": "/",
    "∕": "/",
    "⧸": "/",
    "＼": "\\",
    "∖": "\\",
    "～": "~",
    "∼": "~",
}

#: Invisible characters, removed outright: never legitimate in a path.
_INVISIBLE = re.compile(
    "[​-‏  ‪-‮⁠-⁤﻿­]"
)


def decode_path(value: str) -> str:
    """Percent-decodes until stable, bounded at three passes.

    Bounded because double-encoding is the obvious next move once single
    encoding is handled, and an unbounded loop on attacker-controlled input is
    its own bug.
    """
    current = str(value or "")
    for _ in range(MAX_DECODE_PASSES):
        if not re.search(r"%[0-9a-f]{2}", current, re.IGNORECASE):
            break
        nxt = unquote(current, errors="replace")
        if nxt == current:
            break
        current = nxt
    return current


def _strip_trailing_punctuation(value: str) -> str:
    """Strips trailing dots and spaces from each path segment.

    Windows does this when opening a file, so ``.env `` and ``.env`` are one
    file. Applied on every platform: policy files are shared across a fleet, and
    a rule that protects a Linux runner and not a Windows laptop is a rule
    nobody can reason about.

    ``.`` and ``..`` are preserved — stripping their dots would erase the
    traversal semantics the resolver depends on.
    """
    if not re.search(r"[. ]([/\\]|$)", value):
        return value

    out: list[str] = []
    for part in re.split(r"([/\\])", value):
        if part in ("/", "\\", ".", ".."):
            out.append(part)
        else:
            out.append(re.sub(r"[. ]+$", "", part))
    return "".join(out)


def fold_path(value: str) -> str:
    """Folds a path to a comparable form.

    Order is not arbitrary: NFKC first, then the homoglyphs it leaves alone,
    then invisibles, then percent-decoding — because decoding can introduce
    separators the earlier steps should then see. A second fold catches anything
    decoding produced.
    """
    s = str(value or "")

    try:
        s = unicodedata.normalize("NFKC", s)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        pass

    s = "".join(_HOMOGLYPHS.get(ch, ch) for ch in s)
    s = _INVISIBLE.sub("", s)
    s = decode_path(s)

    s = "".join(_HOMOGLYPHS.get(ch, ch) for ch in s)
    s = _INVISIBLE.sub("", s)

    return _strip_trailing_punctuation(s)


_HOME_VARS = re.compile(
    r"^(\$\{?HOME\}?|%USERPROFILE%|\$env:USERPROFILE|%HOMEPATH%|\$HOMEPATH)(?=[/\\]|$)",
    re.IGNORECASE,
)


def expand_home(value: str) -> str:
    """Expands ``~`` and the common home-directory environment variables.

    These are expanded by the shell or the tool before the path is opened, so a
    rule written against the real path has to match them.
    """
    s = str(value or "")
    home = os.path.expanduser("~").replace("\\", "/").rstrip("/")

    if s == "~" or s.startswith("~/") or s.startswith("~\\"):
        return home + s[1:].replace("\\", "/")

    return _HOME_VARS.sub(home, s, count=1)
