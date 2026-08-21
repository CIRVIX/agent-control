/**
 * Generates the `delegationCases` section of the conformance fixture.
 *
 * A script rather than hand-edited JSON because the cases are systematic — the
 * same scope shapes crossed against the same three operations — and a table
 * that is written out by hand acquires gaps exactly where the author got bored.
 *
 * Run after changing the case list:
 *
 *   node packages/conformance/build-delegation-cases.mjs
 *
 * THE OPERATIONS ARE PROBED, NOT COMPARED STRUCTURALLY.
 *
 * `intersectScopes` returns a scope, and two correct implementations may
 * represent the same authority differently — different ordering, different
 * choice between `a/**` and the two patterns it subsumes. Asserting on the
 * returned structure would pin an accident of representation and fail a correct
 * engine. So intersection is checked by asking what the result PERMITS, which
 * is the only thing that has security meaning.
 */

import { readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(HERE, "policy-conformance.json");

const S = (actions, resources) => ({ actions, resources });

/* -------------------------------------------------------------------------- */

const cases = [
  /* ---- normalizeScope: absent and empty are different -------------------- */
  {
    name: "scope: an absent axis is unconstrained",
    $why: "`undefined` means 'not constrained on this axis'. Only absence becomes `*`.",
    op: "permits",
    scope: { resources: ["/w/**"] },
    request: { action: "fs.read", resource: "/w/app.ts" },
    expect: true,
  },
  {
    name: "scope: an empty axis permits nothing",
    $why:
      "The escalation this pins: `[]` normalized to `['*']` turned the intersection of two " +
      "disjoint authorities into universal authority. Two agents with nothing in common, " +
      "delegating through each other, could do anything.",
    op: "permits",
    scope: { actions: [], resources: ["**"] },
    request: { action: "fs.read", resource: "/w/app.ts" },
    expect: false,
  },
  {
    name: "scope: an empty resource axis permits nothing",
    op: "permits",
    scope: { actions: ["fs.read"], resources: [] },
    request: { action: "fs.read", resource: "/w/app.ts" },
    expect: false,
  },
  {
    name: "scope: a wildcard action permits any action",
    op: "permits",
    scope: S(["*"], ["**"]),
    request: { action: "db.write", resource: "salaries" },
    expect: true,
  },
  {
    name: "scope: a double-star resource matches a nested path",
    $why:
      "`matchGlob('**/*', x)` once returned FALSE, which is fail-open for a scope: the " +
      "delegation appeared to permit nothing and the caller fell through to policy alone.",
    op: "permits",
    scope: S(["fs.read"], ["**/*"]),
    request: { action: "fs.read", resource: "/w/src/deep/app.ts" },
    expect: true,
  },
  {
    name: "scope: a single star does not cross a separator",
    op: "permits",
    scope: S(["fs.read"], ["/w/*"]),
    request: { action: "fs.read", resource: "/w/src/app.ts" },
    expect: false,
  },
  {
    name: "scope: an action outside the list is refused",
    op: "permits",
    scope: S(["fs.read"], ["**"]),
    request: { action: "fs.write", resource: "/w/app.ts" },
    expect: false,
  },

  /* ---- isNarrowing: the rule that makes narrowing mean narrowing --------- */
  {
    name: "narrowing: a subpath of the parent narrows",
    op: "narrows",
    parent: S(["fs.read"], ["/w/src/**"]),
    child: S(["fs.read"], ["/w/src/lib/**"]),
    expect: true,
  },
  {
    name: "narrowing: adding a sibling action widens",
    $why: "One extra action is still widening, and is refused rather than clamped.",
    op: "narrows",
    parent: S(["fs.read"], ["/w/src/**"]),
    child: S(["fs.read", "fs.write"], ["/w/src/**"]),
    expect: false,
  },
  {
    name: "narrowing: a wildcard action widens a concrete one",
    op: "narrows",
    parent: S(["fs.read"], ["/w/src/**"]),
    child: S(["*"], ["/w/src/**"]),
    expect: false,
  },
  {
    name: "narrowing: a wildcard resource widens a scoped one",
    op: "narrows",
    parent: S(["fs.read"], ["/w/src/**"]),
    child: S(["fs.read"], ["**"]),
    expect: false,
  },
  {
    name: "narrowing: wildcard to wildcard is not a widening",
    op: "narrows",
    parent: S(["*"], ["*"]),
    child: S(["**"], ["**"]),
    expect: true,
  },
  {
    name: "narrowing: a child crossing separators the parent did not is widening",
    $why: "`/w/*` to `/w/**` reaches deeper than the parent could. Depth is authority.",
    op: "narrows",
    parent: S(["fs.read"], ["/w/*"]),
    child: S(["fs.read"], ["/w/**"]),
    expect: false,
  },
  {
    name: "narrowing: an unrelated prefix is not a narrowing",
    op: "narrows",
    parent: S(["fs.read"], ["/w/src/**"]),
    child: S(["fs.read"], ["/etc/**"]),
    expect: false,
  },
  {
    name: "narrowing: an empty child narrows anything",
    $why: "Delegating nothing is always legal. It is the one scope that can never escalate.",
    op: "narrows",
    parent: S(["fs.read"], ["/w/**"]),
    child: S([], []),
    expect: true,
  },
  {
    name: "narrowing: a child cannot widen an empty parent",
    op: "narrows",
    parent: S([], []),
    child: S(["fs.read"], ["/w/**"]),
    expect: false,
  },

  /* ---- intersectScopes: probed behaviorally ------------------------------ */
  {
    name: "intersection: keeps only what both permit",
    op: "intersect",
    a: S(["fs.read", "fs.write"], ["**"]),
    b: S(["fs.read"], ["/w/**"]),
    probes: [
      { action: "fs.read", resource: "/w/app.ts", expect: true },
      { action: "fs.write", resource: "/w/app.ts", expect: false },
      { action: "fs.read", resource: "/etc/passwd", expect: false },
    ],
  },
  {
    name: "intersection: disjoint authorities permit nothing",
    $why:
      "The one that must never become `*`. Two agents with nothing in common must end up " +
      "with nothing, not with everything.",
    op: "intersect",
    a: S(["fs.read"], ["/w/**"]),
    b: S(["db.write"], ["salaries"]),
    probes: [
      { action: "fs.read", resource: "/w/app.ts", expect: false },
      { action: "db.write", resource: "salaries", expect: false },
      { action: "shell.exec", resource: "anything", expect: false },
    ],
  },
  {
    name: "intersection: the narrower resource wins",
    op: "intersect",
    a: S(["fs.read"], ["/w/**"]),
    b: S(["fs.read"], ["/w/public/**"]),
    probes: [
      { action: "fs.read", resource: "/w/public/readme.md", expect: true },
      { action: "fs.read", resource: "/w/private/keys.txt", expect: false },
    ],
  },
  {
    name: "intersection: a wildcard side does not widen the other",
    op: "intersect",
    a: S(["*"], ["*"]),
    b: S(["fs.read"], ["/w/**"]),
    probes: [
      { action: "fs.read", resource: "/w/app.ts", expect: true },
      { action: "db.write", resource: "salaries", expect: false },
    ],
  },
  {
    name: "intersection: is order independent",
    $why: "A ∩ B and B ∩ A must describe the same authority, or chain order becomes authority.",
    op: "intersect",
    a: S(["fs.read"], ["/w/public/**"]),
    b: S(["fs.read", "fs.write"], ["/w/**"]),
    symmetric: true,
    probes: [
      { action: "fs.read", resource: "/w/public/a.md", expect: true },
      { action: "fs.write", resource: "/w/public/a.md", expect: false },
      { action: "fs.read", resource: "/w/private/a.md", expect: false },
    ],
  },
  {
    name: "intersection: with an empty scope is empty",
    op: "intersect",
    a: S(["*"], ["*"]),
    b: S([], []),
    probes: [{ action: "fs.read", resource: "/w/app.ts", expect: false }],
  },

  /* ---- action canonicalization ------------------------------------------ */
  {
    name: "scope: action aliases canonicalize before matching",
    $why:
      "`filesystem.read` and `fs.read` are the same authority. An engine that treats them as " +
      "different strings lets a scope be bypassed by spelling.",
    op: "permits",
    scope: S(["filesystem.read"], ["**"]),
    request: { action: "fs.read", resource: "/w/app.ts" },
    expect: true,
  },
  {
    name: "scope: a namespaced action is not folded into a taxonomy bucket",
    $why: "An unrecognised action keeps its own identity; guessing would inherit a rule's permission.",
    op: "permits",
    scope: S(["fs.read"], ["**"]),
    request: { action: "mcp.acme.getRid", resource: "/w/app.ts" },
    expect: false,
  },
];

/* -------------------------------------------------------------------------- */

const suite = JSON.parse(await readFile(FIXTURE, "utf8"));

const names = cases.map((c) => c.name);
if (new Set(names).size !== names.length) {
  throw new Error("duplicate delegation case names");
}

suite.delegationCases = cases;
await writeFile(FIXTURE, JSON.stringify(suite, null, 2) + "\n");

console.log(`wrote ${cases.length} delegation cases to ${FIXTURE}`);
