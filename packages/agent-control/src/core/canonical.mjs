/**
 * Canonicalization — collapsing every spelling of a thing to one string.
 *
 * This module exists because two adversarial findings had the same root cause:
 * the policy engine matched rules against the string an agent *wrote*, while
 * the risk engine and the operating system resolved it to something else.
 * Wherever those two disagree, a rule that reads correctly does not fire.
 *
 * FINDING 1 — ALTERNATE IP REPRESENTATIONS
 *
 *   deny: network.destination = 169.254.169.254
 *
 * did not match `http://2852039166/latest/meta-data/`, nor the octal, hex, or
 * dotted-hex forms. All four resolve to the same address, and every HTTP client
 * in existence connects to it. The risk engine already scored them CRITICAL —
 * because it read the hostname through `new URL()`, which normalizes them —
 * but the policy condition tested the raw string, so the deny rule watched the
 * attack go past.
 *
 * FINDING 2 — PERCENT-ENCODED PATHS
 *
 * `~%2F.aws%2Fcredentials` contains no literal separator, so path
 * canonicalization treated it as a bare filename, `insideWorkspace` returned
 * true, and a workspace-read rule permitted a credential read.
 *
 * THE PRINCIPLE
 *
 * Canonicalize toward what the *receiving system* will do, not toward what the
 * string looks like. An MCP server handed `~%2F.aws%2Fcredentials` may well
 * decode it; an HTTP client handed `http://0xA9FEA9FE/` certainly connects to
 * link-local. When a spelling is ambiguous, the safe reading is the one that
 * reaches the sensitive resource — because that is the reading an attacker is
 * relying on.
 */

import { homedir } from "node:os";

/* -------------------------------------------------------------------------- */
/*  Hosts and URLs                                                             */
/* -------------------------------------------------------------------------- */

/**
 * Normalizes a URL to its canonical form.
 *
 * Uses the WHATWG parser rather than hand-rolled parsing, because the whole
 * point is to agree with what an HTTP client does, and `new URL()` *is* the
 * algorithm those clients implement. It resolves every IPv4 spelling —
 * decimal, octal, hex, dotted-hex, and mixed — lowercases the host, strips a
 * trailing dot, drops the fragment, and normalizes the path.
 *
 * Credentials in the authority (`http://evil.com@169.254.169.254/`) are
 * DROPPED, not preserved: the userinfo is not where the request goes, and
 * leaving it in lets a destination rule be defeated by prefixing a host that
 * looks innocuous.
 *
 * @returns {string|null} the canonical URL, or null if it is not one
 */
export function canonicalUrl(value) {
  if (typeof value !== "string" || !/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return null;
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }

  const host = canonicalHost(url.hostname) ?? url.hostname.toLowerCase();
  const port = url.port ? `:${url.port}` : "";
  const path = url.pathname.replace(/\/$/, "");
  return `${url.protocol.toLowerCase()}//${host}${port}${path}${url.search}`;
}

/**
 * Normalizes a hostname.
 *
 * `new URL()` already collapses numeric IPv4 forms, so the heavy lifting is
 * done by the time this sees the value. What remains is the handful of things
 * the URL parser preserves and a policy should not distinguish:
 *
 *   - a trailing dot (`metadata.google.internal.` is the same name)
 *   - bracketed IPv6, which is syntax rather than identity
 *   - IPv4-mapped IPv6 (`::ffff:169.254.169.254`), which routes to the v4 address
 *
 * @returns {string|null}
 */
export function canonicalHost(value) {
  if (typeof value !== "string" || !value) return null;
  let host = value.trim().toLowerCase();

  // A fully-qualified name with the root label spelled out.
  host = host.replace(/\.+$/, "");

  // IPv6 literals arrive bracketed from a URL and bare from a config.
  const bare = host.replace(/^\[|\]$/g, "");

  // IPv4-mapped and IPv4-compatible IPv6 route to the embedded v4 address, so a
  // rule naming that address must match them.
  const mapped = bare.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i) ?? bare.match(/^::(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mapped) return mapped[1];

  // The same address after a URL parser has been at it.
  //
  // `new URL("http://[::ffff:169.254.169.254]/")` yields the hostname
  // `::ffff:a9fe:a9fe` — the dotted form is gone by the time this is called
  // from `canonicalUrl`, so matching only the dotted spelling above left the
  // bracketed URL form as a live bypass.
  const hexMapped = bare.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (hexMapped) {
    const high = parseInt(hexMapped[1], 16);
    const low = parseInt(hexMapped[2], 16);
    return [(high >> 8) & 255, high & 255, (low >> 8) & 255, low & 255].join(".");
  }

  // A numeric form the URL parser did not see because it arrived as a bare
  // host rather than inside a URL.
  const numeric = numericToIpv4(bare);
  if (numeric) return numeric;

  return bare;
}

/**
 * Resolves a numeric host spelling to dotted-quad, or null.
 *
 * Implements the historical `inet_aton` forms that every resolver still
 * accepts: one 32-bit number, two parts, three parts, or four — each part in
 * decimal, octal (leading zero), or hex (leading 0x).
 *
 * Written out rather than delegated to `new URL()` because a bare host string
 * from a config file or a `host:port` argument never passes through a URL
 * parser, and that is exactly where a destination rule is written.
 */
export function numericToIpv4(value) {
  const s = String(value ?? "").trim();
  if (!/^[0-9a-fx.]+$/i.test(s) || s === "") return null;

  const parts = s.split(".");
  if (parts.length > 4 || parts.some((p) => p === "")) return null;

  const nums = [];
  for (const part of parts) {
    let n;
    if (/^0x[0-9a-f]+$/i.test(part)) n = parseInt(part, 16);
    else if (/^0[0-7]+$/.test(part)) n = parseInt(part, 8);
    else if (/^\d+$/.test(part)) n = parseInt(part, 10);
    else return null;
    if (!Number.isFinite(n) || n < 0) return null;
    nums.push(n);
  }

  // A dotted-quad of plain decimals is already canonical; returning it
  // unchanged keeps `canonicalHost` idempotent.
  if (nums.length === 4 && nums.every((n) => n <= 255) && /^\d+(\.\d+){3}$/.test(s)) {
    return nums.join(".");
  }

  // The inet_aton packing rules: the last part absorbs the remaining octets.
  const maxLast = 2 ** (8 * (4 - nums.length + 1));
  if (nums.slice(0, -1).some((n) => n > 255)) return null;
  if (nums[nums.length - 1] >= maxLast) return null;

  let packed = 0;
  for (let i = 0; i < nums.length - 1; i++) packed |= nums[i] << (8 * (3 - i));
  packed = (packed >>> 0) + nums[nums.length - 1];
  packed = packed >>> 0;

  return [(packed >>> 24) & 255, (packed >>> 16) & 255, (packed >>> 8) & 255, packed & 255].join(".");
}

/* -------------------------------------------------------------------------- */
/*  Paths                                                                      */
/* -------------------------------------------------------------------------- */

/** How many times to decode. Bounded so a decode bomb cannot spin. */
const MAX_DECODE_PASSES = 3;

/**
 * Percent-decodes a path until it stops changing.
 *
 * Repeated because double-encoding is the obvious next move once single
 * encoding is handled: `%252e%252f` decodes to `%2e%2f` decodes to `./`.
 * Bounded at three passes — deeper nesting is not a spelling anyone uses by
 * accident, and an unbounded loop on attacker-controlled input is its own bug.
 *
 * A value that fails to decode is returned as-is rather than thrown on: a
 * stray `%` in a legitimate filename is far more common than an attack, and
 * refusing to canonicalize is not the same as refusing the call.
 */
export function decodePath(value) {
  let current = String(value ?? "");
  for (let i = 0; i < MAX_DECODE_PASSES; i++) {
    if (!/%[0-9a-f]{2}/i.test(current)) break;
    let next;
    try {
      next = decodeURIComponent(current);
    } catch {
      // Malformed escapes: decode what we can, character by character, so a
      // single bad sequence does not shield the rest of the string.
      next = current.replace(/%([0-9a-f]{2})/gi, (m, hex) => {
        const code = parseInt(hex, 16);
        return code === 0 ? "" : String.fromCharCode(code);
      });
    }
    if (next === current) break;
    current = next;
  }
  return current;
}

/**
 * Unicode look-alikes for the characters that matter in a path.
 *
 * A policy matching `.aws` should not be defeated by writing it with U+FF0E
 * FULLWIDTH FULL STOP or U+2024 ONE DOT LEADER. These are folded to their
 * ASCII equivalents *for matching only* — the resource recorded in the audit
 * chain keeps the folded form so the record and the decision agree, and the
 * original is never silently rewritten anywhere it would be executed.
 */
const HOMOGLYPHS = new Map([
  ["．", "."], // fullwidth full stop
  ["․", "."], // one dot leader
  ["。", "."], // ideographic full stop
  ["／", "/"], // fullwidth solidus
  ["∕", "/"], // division slash
  ["⧸", "/"], // big solidus
  ["＼", "\\"], // fullwidth reverse solidus
  ["∖", "\\"], // set minus
  ["～", "~"], // fullwidth tilde
  ["∼", "~"], // tilde operator
]);

/** Characters removed outright: they are invisible and never legitimate here. */
const INVISIBLE = /[\u200B-\u200F\u2028\u2029\u202A-\u202E\u2060-\u2064\uFEFF\u00AD]/g;

/**
 * Folds a path to a comparable form.
 *
 * Normalization order matters and is not arbitrary:
 *
 *   1. NFKC first, which folds most compatibility variants in one step.
 *   2. Explicit homoglyph replacement for the separators NFKC leaves alone —
 *      U+2024 ONE DOT LEADER survives NFKC, and it is the one an attacker uses.
 *   3. Invisible characters removed, so `.a​ws` and `.aws` are one string.
 *   4. Percent-decoding last, because decoding can introduce new separators
 *      that steps 1–3 should then see.
 */
export function foldPath(value) {
  let s = String(value ?? "");

  try {
    s = s.normalize("NFKC");
  } catch {
    /* an unpaired surrogate; keep going with what we have */
  }

  let folded = "";
  for (const ch of s) folded += HOMOGLYPHS.get(ch) ?? ch;

  folded = folded.replace(INVISIBLE, "");
  folded = decodePath(folded);

  // A second fold: decoding may have produced homoglyphs or invisibles of its
  // own, and one pass would leave them in place.
  let second = "";
  for (const ch of folded) second += HOMOGLYPHS.get(ch) ?? ch;
  second = second.replace(INVISIBLE, "");

  return stripTrailingPunctuation(second);
}

/**
 * Strips trailing dots and spaces from each path segment.
 *
 * Windows does this when opening a file: `".env "` and `".env."` both open
 * `.env`. So a rule naming `.env` had a live bypass — the agent appends one
 * space, the matcher sees a different string, and NTFS opens the credential
 * file anyway. The generated corpus found 378 of them at once.
 *
 * Applied on every platform, not only Windows. Policy files are shared across a
 * fleet, and a rule that protects a Linux CI runner and not a developer's
 * laptop is a rule nobody can reason about. On POSIX a filename really may end
 * in a space, so this can over-match — the cost is denying access to a very
 * strangely-named file, which is the right direction to be wrong in.
 *
 * `.` and `..` are preserved intact: stripping their dots would erase the
 * traversal semantics that `resolvePath` depends on.
 */
function stripTrailingPunctuation(value) {
  if (!/[. ]([/\\]|$)/.test(value)) return value;

  return value
    .split(/([/\\])/)
    .map((part) => {
      if (part === "/" || part === String.fromCharCode(92)) return part;
      if (part === "." || part === "..") return part;
      return part.replace(/[. ]+$/, "");
    })
    .join("");
}

/** Expands `~` and the common home-directory environment variables. */
export function expandHome(value) {
  const s = String(value ?? "");
  const home = homedir().replace(/\\/g, "/").replace(/\/+$/, "");

  if (s === "~" || s.startsWith("~/") || s.startsWith("~\\")) {
    return home + s.slice(1).replace(/\\/g, "/");
  }
  // `$HOME`, `${HOME}`, `%USERPROFILE%`, `$env:USERPROFILE`. These are expanded
  // by the shell or the tool before the path is opened, so a rule written
  // against the real path must match them.
  return s.replace(
    /^(\$\{?HOME\}?|%USERPROFILE%|\$env:USERPROFILE|%HOMEPATH%|\$HOMEPATH)(?=[/\\]|$)/i,
    home,
  );
}
