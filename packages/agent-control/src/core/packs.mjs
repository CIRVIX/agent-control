/**
 * Policy packs — installable, forkable, provenanced rule sets.
 *
 * The four files in `policies/` were already packs in everything but name: a
 * curated set of rules with a stated purpose. What they lacked was the
 * metadata that makes a pack shareable — who wrote it, what version it is,
 * what it is for, what it was forked from, and whether the rules still match
 * the hash somebody reviewed.
 *
 * WHY THE MANIFEST LIVES IN COMMENTS
 * ----------------------------------
 * A pack is a `.policy` file and nothing else. The manifest is carried on
 * `#@ key: value` lines, which the DSL parser already skips as comments.
 *
 * The alternative — a sidecar `.pack.json` — was rejected because it splits a
 * pack into two files that can drift apart, and the failure mode of that drift
 * is a manifest describing rules that are no longer there. One file cannot
 * disagree with itself about what it contains.
 *
 * WHAT THE HASH COVERS
 * --------------------
 * The rules, not the manifest. Bumping a description or adding an author must
 * not invalidate a review of the rules, and editing a single `deny` must
 * invalidate it. Hashing the whole file would get both of those backwards.
 */

import { createHash } from "node:crypto";

/** Manifest fields a pack may declare. Anything else is ignored, not an error:
 *  a pack written against a newer Cirvix must still install on an older one. */
const FIELDS = new Set([
  "id", "name", "version", "description", "author", "homepage",
  "risk", "targets", "requires", "forked-from", "forked-at", "official",
]);

const MANIFEST_LINE = /^#@\s*([a-z-]+)\s*:\s*(.*)$/i;

/**
 * Split a pack file into its manifest and its rule text.
 *
 * The rule text is returned verbatim, including comments that are not manifest
 * lines, because those comments are the author explaining their reasoning and
 * dropping them would make an installed pack less useful than the one on disk.
 */
export function parsePack(text, { source = null } = {}) {
  const manifest = {};
  const ruleLines = [];

  for (const line of String(text ?? "").split(/\r?\n/)) {
    const m = line.match(MANIFEST_LINE);
    if (m && FIELDS.has(m[1].toLowerCase())) {
      const key = m[1].toLowerCase();
      const value = m[2].trim();
      if (key === "targets" || key === "requires") {
        manifest[key] = value.split(/[,\s]+/).filter(Boolean);
      } else if (key === "official") {
        manifest[key] = value === "true";
      } else {
        manifest[key] = value;
      }
      continue;
    }
    ruleLines.push(line);
  }

  const rules = ruleLines.join("\n");
  return {
    manifest: {
      id: manifest.id ?? null,
      name: manifest.name ?? manifest.id ?? "untitled pack",
      version: manifest.version ?? "0.0.0",
      description: manifest.description ?? "",
      author: manifest.author ?? "unknown",
      risk: manifest.risk ?? "unspecified",
      targets: manifest.targets ?? [],
      requires: manifest.requires ?? [],
      official: manifest.official ?? false,
      forkedFrom: manifest["forked-from"] ?? null,
      forkedAt: manifest["forked-at"] ?? null,
      homepage: manifest.homepage ?? null,
      source,
    },
    rules,
    hash: hashRules(rules),
  };
}

/** sha256 over the rule text with trailing whitespace normalised, so a pack
 *  that survives a round trip through an editor still verifies. */
export function hashRules(rules) {
  const normalised = String(rules ?? "")
    .split(/\r?\n/)
    .map((l) => l.replace(/\s+$/, ""))
    .join("\n")
    .replace(/\n+$/, "\n");
  return "sha256:" + createHash("sha256").update(normalised, "utf8").digest("hex");
}

/** Does this pack still contain the rules somebody reviewed? */
export function verifyPack(pack, expectedHash) {
  const actual = hashRules(pack.rules);
  return { ok: actual === expectedHash, expected: expectedHash, actual };
}

/**
 * Render a pack back to a file.
 *
 * Manifest first, then the rules exactly as they were. Round-tripping a pack
 * through parse → render must not change its hash, which the tests assert.
 */
export function renderPack(pack) {
  const m = pack.manifest;
  const head = [
    `#@ id: ${m.id}`,
    `#@ name: ${m.name}`,
    `#@ version: ${m.version}`,
    m.description ? `#@ description: ${m.description}` : null,
    `#@ author: ${m.author}`,
    `#@ risk: ${m.risk}`,
    m.targets?.length ? `#@ targets: ${m.targets.join(", ")}` : null,
    m.requires?.length ? `#@ requires: ${m.requires.join(", ")}` : null,
    m.official ? `#@ official: true` : null,
    m.forkedFrom ? `#@ forked-from: ${m.forkedFrom}` : null,
    m.forkedAt ? `#@ forked-at: ${m.forkedAt}` : null,
    m.homepage ? `#@ homepage: ${m.homepage}` : null,
  ].filter(Boolean);
  return head.join("\n") + "\n" + pack.rules.replace(/^\n+/, "\n");
}

/**
 * Fork a pack under a new identity, keeping provenance.
 *
 * The fork records the parent's id AND the parent's rule hash. The id alone
 * would be a claim; the hash is what lets anyone check which version of the
 * parent this actually came from, including after the parent has moved on.
 */
export function forkPack(pack, { id, name, author = "unknown", now = new Date() } = {}) {
  if (!id) throw new Error("A fork needs an id.");
  return {
    manifest: {
      ...pack.manifest,
      id,
      name: name ?? `${pack.manifest.name} (fork)`,
      version: "0.1.0",
      author,
      official: false,
      forkedFrom: `${pack.manifest.id ?? "unknown"}@${hashRules(pack.rules)}`,
      forkedAt: now.toISOString(),
    },
    rules: pack.rules,
    hash: hashRules(pack.rules),
  };
}

/**
 * The difference between two packs, as rule names.
 *
 * Reported by name rather than by line, because a pack update that reorders
 * rules or rewrites a comment is not a change anyone needs to review, and a
 * line diff would present it as though it were.
 */
export function diffPacks(before, after) {
  const names = (p) => {
    const out = [];
    for (const m of String(p?.rules ?? "").matchAll(/^\s*name\s*=\s*(\S+)/gm)) out.push(m[1]);
    return out;
  };
  const a = new Set(names(before));
  const b = new Set(names(after));
  return {
    added: [...b].filter((n) => !a.has(n)),
    removed: [...a].filter((n) => !b.has(n)),
    kept: [...a].filter((n) => b.has(n)),
    changed: hashRules(before?.rules) !== hashRules(after?.rules),
  };
}

/**
 * Sort packs for a listing.
 *
 * Official first, then by risk posture descending, then by name. A developer
 * scanning this list is looking for "the safe default written by the vendor",
 * and that should not be somewhere in the middle alphabetically.
 */
const RISK_WEIGHT = { strict: 3, balanced: 2, permissive: 1, unspecified: 0 };
export function sortPacks(packs) {
  return [...packs].sort((x, y) => {
    if (x.manifest.official !== y.manifest.official) return x.manifest.official ? -1 : 1;
    const rw = (RISK_WEIGHT[y.manifest.risk] ?? 0) - (RISK_WEIGHT[x.manifest.risk] ?? 0);
    if (rw) return rw;
    return String(x.manifest.name).localeCompare(String(y.manifest.name));
  });
}
