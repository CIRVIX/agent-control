/**
 * The manifest a package is actually published with.
 *
 * WHY THIS EXISTS
 *
 * `packages/agent-control` publishes an allowlist of `files` — `bin`, `src`,
 * `action`, `README.md`, `LICENSE`, `NOTICE` — and deliberately does not
 * publish `test/`. Its `package.json` still declared the developer scripts that
 * live there:
 *
 *     "test":  "node --test test/*.test.mjs test/adversarial/*.test.mjs"
 *     "corpus": "node test/corpus/report.mjs"
 *     "bench": "node ../../benchmarks/decision.mjs"
 *     "verify:adversarial": "node test/adversarial/verify.mjs"
 *
 * Installing the published tarball and running `npm test` inside it reported
 * `tests 0 / pass 0 / fail 0` and exited **0** — a green light that verified
 * nothing at all, which is worse than a failure. It is also the shape of
 * contract bug that goes unnoticed for years, because nobody runs `npm test`
 * inside their own `node_modules`.
 *
 * The dev scripts stay in the repository: `npm test` from a clean checkout is
 * the documented command and must keep working. What changes is the manifest
 * that goes into the tarball, and the rule deciding what stays is a property of
 * the command — does every file it names exist in what is being shipped? —
 * rather than a hand-maintained list that would drift.
 *
 * A script is therefore dropped **with a reason**, and the artifact verifier
 * prints what was dropped. Dropping is visible; it is not silent.
 */

/** True when a command token names a file inside the package. */
function isPackageRelativeFile(token) {
  if (!token || token.startsWith("-")) return false;
  // A URL, a protocol prefix, or a Windows drive path is not package-relative.
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(token)) return false;
  // A bare word is a subcommand, a script name, or a flag operand — `node`,
  // `cirvix`, `demo`, `--cwd`. It is not a file reference.
  if (!token.includes("/") && !token.includes(".")) return false;
  // Glob characters make the token a pattern, not a path. It still names
  // unpublished files, so it is treated as a reference and will not resolve.
  return /\.(mjs|cjs|js|json|ts|wasm|yml|yaml|txt|md)(\b|$)/i.test(token) || token.startsWith("./");
}

/**
 * Every package-relative file a script command names.
 *
 * @param {string} command
 * @returns {string[]}
 */
export function referencedPaths(command) {
  return String(command ?? "")
    .split(/\s+/)
    .map((token) => token.replace(/^["']|["']$/g, ""))
    .filter(isPackageRelativeFile);
}

/**
 * The manifest to publish, given the set of files that will be in the tarball.
 *
 * @param {object} manifest      the repository manifest
 * @param {Set<string>} present  forward-slash paths of the files being shipped
 * @returns {{manifest: object, dropped: Array<{name: string, command: string, missing: string[]}>}}
 */
export function publishedManifest(manifest, present) {
  const scripts = {};
  const dropped = [];

  for (const [name, command] of Object.entries(manifest.scripts ?? {})) {
    const missing = referencedPaths(command).filter((path) => !present.has(path));
    if (missing.length) dropped.push({ name, command, missing });
    else scripts[name] = command;
  }

  return { manifest: { ...manifest, scripts }, dropped };
}
