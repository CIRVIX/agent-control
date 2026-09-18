#!/usr/bin/env node
/**
 * Provenance audit for the curated public repository.
 *
 * Run as `npm run verify:public`. Exits non-zero on anything that must not be
 * published from this tree, so CI fails rather than a reviewer having to notice.
 *
 * `--root <dir>`  audit another tree (used by the self-test).
 * `--self-test`   prove the guards fire against a fixture, then exit.
 * `--write <file>` write the pass report.
 */
import { mkdtemp, mkdir, readdir, readFile, rm, stat as statFn, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../", import.meta.url));
const argv = process.argv.slice(2);
const flagValue = (name, fallback = null) => {
  const at = argv.indexOf(name);
  return at === -1 ? fallback : (argv[at + 1] ?? fallback);
};

const textExtensions = new Set([".js", ".mjs", ".cjs", ".json", ".md", ".py", ".toml", ".yml", ".yaml", ".sh", ".ps1", ".txt"]);

/*
 * AUDIT SCOPE: THE PUBLICATION INVENTORY, NOT THE CONVENIENT SUBSET.
 *
 * Skipping `.env*`, `.cirvix/`, `.e2e/` etc. by name would make the gate
 * blind to exactly the file a force-add puts into the release: an ignored
 * `.env` reaches `git add -A -f` just as easily as anything else. What may
 * differ is *when* it is inspected — see the classified skip below.
 *
 * `.git` is excluded unconditionally: object contents are history, not the
 * publication inventory, and history review is a separate controlled task
 * (redacted history scanning; no automatic rewrite).
 */
const auditScopeSkips = new Set([".git"]);
const workingTreeOnlySkips = new Set(["node_modules", ".npm-cache", ".cirvix", ".demo", ".e2e", "__pycache__", ".artifacts", ".git"]);
const sensitiveNames = new Set([".env", ".env.local", ".env.production", ".env.development"]);


/*
 * ARTIFACTS THAT MUST NEVER BE PUBLISHED FROM ANY TREE IN THIS PROJECT.
 *
 * `.gitignore` lists them, and `.gitignore` is advisory: a stale ignore, a
 * `git add -f`, or an extraction into a fresh tree defeats it. This check fails
 * the build instead, which is the difference between a convention and a
 * control. `--self-test` proves it fires, so it cannot rot into a passing
 * no-op — the failure mode of every untested guard.
 */
const forbiddenArtifacts = [
  [/(^|\/)secrets\.(?:json(?:\.bak[^/]*)?|bak[^/]*)$/i, "credential store"],
  [/(^|\/)data(?:-(?:shm|wal))?$/i, "SQLite database or WAL sidecar"],
  [/\.sqlite(?:3)?(?:-(?:shm|wal))?$/i, "SQLite database or WAL sidecar"],
];

const contentPatterns = [
  ["private hostname", /https?:\/\/(?:[^/]*\.)?(?:internal|corp|intranet)(?:[./]|$)/i],
  ["RFC1918 URL", /https?:\/\/(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/i],
  ["private key material", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s*[A-Za-z0-9+/=]{20,}/],
  ["live GitHub token", /\bgh[pousr]_[A-Za-z0-9]{30,}\b/],
  ["live AWS access key", /\bAKIA[0-9A-Z]{16}\b/],
  ["live Stripe secret", /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/],
];

/**
 * The publication inventory is what a release actually publishes.
 *
 * Primary: the Git index (staged + tracked files) — a force-added `.env` or
 * `.cirvix` state file lands here, while never-staged local state does not.
 * Fallback: whole-tree audit when Git is unavailable (the conservative
 * direction; the working tree is a superset of the index).
 */
async function publicationInventory(root) {
  const probe = spawnSync("git", ["rev-parse", "--git-dir"], { cwd: root, encoding: "utf8" });
  if (probe.error || probe.status !== 0) return null;
  const listing = spawnSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"], {
    cwd: root, encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
  });
  if (listing.error || listing.status !== 0) return null;
  return listing.stdout.split("\0").filter(Boolean).map((p) => p.replaceAll("\\", "/"));
}

/**
 * Lists every path under `dir`, and the text files among them. No shared
 * state, so the audit below runs identically against the repository and
 * against the self-test's fixture.
 */
async function collect(root, inventory = null) {
  const text = [];
  const findings = [];
  const track = (name, full) => {
    const ext = name.includes(".") ? "." + name.split(".").pop().toLowerCase() : "";
    if (textExtensions.has(ext) || name.startsWith(".env")) text.push(full);
  };

  if (inventory) {
    // Index-driven scope: exactly what would ship. Still read from disk, so a
    // staged-then-modified file is audited as it would actually be committed.
    for (const name of inventory) {
      if (name.startsWith(".git/") || name === ".git") continue;
      const full = join(root, ...name.split("/"));
      // Deleted-from-worktree but still staged paths cannot be read; report them.
      let stat;
      try { stat = await statFn(full); } catch { findings.push(`staged file missing from tree: ${name}`); continue; }
      if (!stat.isFile()) continue;
      await trackOrFlag(name, full, text, findings);
    }
    return { text, findings };
  }

  const visit = async (current) => {
    let entries;
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch (err) {
      throw new Error(`cannot audit ${current}: ${err.code ?? err.message}`);
    }
    for (const entry of entries) {
      if (auditScopeSkips.has(entry.name)) continue;
      const full = join(current, entry.name);
      if (entry.isDirectory()) { await visit(full); continue; }
      await trackOrFlag(entry.name, full, text, findings);
    }
  };
  await visit(root);
  return { text, findings };
}

/** Name-level checks and content-collection decisions shared by both scopes. */
async function trackOrFlag(name, full, text, findings) {
  const base = name.split("/").pop();
  const ext = base.includes(".") ? "." + base.split(".").pop().toLowerCase() : "";
  if (sensitiveNames.has(base)) {
    findings.push(`sensitive env file must not exist in this tree: ${name}`);
  } else {
    for (const [pattern, label] of forbiddenArtifacts) {
      if (pattern.test(name)) { findings.push(`${label} must not exist in this tree: ${name}`); break; }
    }
  }
  if (textExtensions.has(ext) || base.startsWith(".env")) text.push(full);
}


/** Returns every finding for `root`. Empty array means clean. */
async function audit(root) {
  const inventory = await publicationInventory(root);
  const { text, findings: inventoryFindings } = await collect(root, inventory);
  const findings = [...inventoryFindings];
  /** path -> file count, so the report stays readable. */
  const proprietary = new Map();

  for (const file of text) {
    const name = relative(root, file).replaceAll("\\", "/");
    if (/^packages\/control-plane(?:\/|$)/i.test(name)) {
      proprietary.set("packages/control-plane", (proprietary.get("packages/control-plane") ?? 0) + 1);
      continue;
    }
    const source = await readFile(file, "utf8");
    for (const [label, pattern] of contentPatterns) {
      if (!pattern.test(source)) continue;
      if (name === "docs/api.md" && /example\.com/i.test(source)) continue;
      if (name.startsWith("packages/conformance/") && /metadata\.google\.internal/i.test(source)) continue;
      if ((name.startsWith("packages/agent-control/test/") || name.startsWith("benchmarks/")) && /EXAMPLE|dummy|fake|DEMO|AAAA|ABCDEFGHIJKLMNOPQRSTUVWXYZ/i.test(source)) continue;
      if (name === "packages/agent-control/src/commands/demo.mjs" && /EXAMPLE/i.test(source)) continue;
      // AWS's own published example key, quoted in prose. It is in AWS's
      // documentation and authenticates nothing; the pattern cannot tell it
      // apart from a live key, so it is named here explicitly.
      if (label === "live AWS access key" && !/AKIA(?!IOSFODNN7EXAMPLE)[0-9A-Z]{16}/.test(source)) continue;
      findings.push(`${label}: ${name}`);
    }
  }

  // Proprietary directories can only appear in the fallback (no-Git) scope:
  // the ignore rules keep them out of the publication inventory, which is the
  // desired state, and a force-add puts them back in scope automatically.
  for (const [dirPath, count] of proprietary) {
    findings.push(`proprietary path must not be published: ${dirPath}/ (${count} file${count === 1 ? "" : "s"})`);
  }

  return { findings, inspected: text.length };
}

/**
 * Proves the guards fire, on a fixture, using the production code path above.
 * The mistake this catches — a credential store committed by a stray
 * `git add -A` — is invisible until it is public.
 */
async function selfTest() {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-public-audit-"));
  const failures = [];
  try {
    await mkdir(join(dir, "packages/agent-control"), { recursive: true });
    await writeFile(join(dir, "secrets.json"), JSON.stringify({ apiKey: "placeholder" }), "utf8");
    await writeFile(join(dir, "data"), "SQLite format 3", "utf8");
    await writeFile(join(dir, "secrets.json.bak-fixture"), "placeholder", "utf8");
    await writeFile(join(dir, "backup.sqlite-wal"), "wal", "utf8");

    const dirty = (await audit(dir)).findings;
    for (const [label, needle] of [
      ["credential store", "secrets.json"],
      ["credential store", "secrets.json.bak-fixture"],
      ["SQLite database or WAL sidecar", "data"],
      ["SQLite database or WAL sidecar", "backup.sqlite-wal"],
    ]) {
      if (!dirty.some((f) => f.startsWith(label) && f.includes(needle))) {
        failures.push(`self-test: ${label} was not detected for ${needle}`);
      }
    }

    await rm(join(dir, "secrets.json"));
    await rm(join(dir, "secrets.json.bak-fixture"));
    await rm(join(dir, "data"));
    await rm(join(dir, "backup.sqlite-wal"));
    const clean = (await audit(dir)).findings;
    if (clean.length) failures.push(`self-test: a clean fixture reported findings: ${clean.join("; ")}`);

    // Publication-inventory scope: with Git available, the audit covers what a
    // release would actually publish. A force-added sensitive file is caught;
    // ignored-but-unstaged local state does not fail the gate.
    const runGit = (args) => {
      const r = spawnSync("git", args, { cwd: repo, encoding: "utf8" });
      if (r.status !== 0) throw new Error(`fixture git ${args.join(" ")} failed: ${r.stderr}`);
    };
    const repo = await mkdtemp(join(tmpdir(), "cirvix-public-inventory-"));
    try {
      await writeFile(join(repo, "README.md"), "# fixture\n", "utf8");
      runGit(["init"]);
      runGit(["add", "README.md"]);
      runGit(["-c", "user.email=f@e.x", "-c", "user.name=f", "commit", "-qm", "fixture"]);
      await writeFile(join(repo, ".env"), "STRIPE_SECRET=fixture-not-a-real-credential\n", "utf8");
      runGit(["add", "-f", ".env"]);
      const forced = (await audit(repo)).findings;
      if (!forced.some((f) => f.startsWith("sensitive env file") && f.includes(".env"))) {
        failures.push("self-test: a force-added .env was not detected in the publication inventory");
      }
      runGit(["rm", "--cached", ".env"]);
      await writeFile(join(repo, ".gitignore"), ".env\n", "utf8");
      runGit(["add", ".gitignore"]);
      const localState = (await audit(repo)).findings;
      if (localState.length) failures.push(`self-test: unstaged ignored local state failed the inventory audit: ${localState.join("; ")}`);
      await writeFile(join(repo, "leak.txt"), `token ${"ghp_" + "F".repeat(7)}${"X".repeat(31)}\n`, "utf8");
      runGit(["add", "-f", "leak.txt"]);
      const staged = (await audit(repo)).findings;
      if (!staged.some((f) => f.startsWith("live GitHub token") && f.includes("leak.txt"))) {
        failures.push("self-test: staged secret-shaped content was not detected");
      }
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
  return failures;
}

if (argv.includes("--self-test")) {
  const failures = await selfTest();
  if (failures.length) {
    console.error("Public-repo audit self-test failed:");
    for (const failure of failures) console.error(`  ${failure}`);
    process.exit(1);
  }
  console.log("public-repo audit self-test passed");
  process.exit(0);
}

let findings;
let inspected;
try {
  ({ findings, inspected } = await audit(resolve(flagValue("--root", repoRoot))));
} catch (err) {
  console.error(`Public-repo audit could not run: ${err.message}`);
  process.exit(2);
}
if (findings.length) {
  console.error("Public-repo audit failed:");
  for (const finding of findings) console.error(`  ${finding}`);
  process.exit(1);
}
const report = `# Public repository audit\n\n- Audited: ${new Date().toISOString()}\n- Text files inspected: ${inspected}\n- Proprietary-path findings: 0\n- High-confidence live-secret findings: 0\n- Forbidden-artifact findings: 0\n\nThis audit does not replace GitHub secret scanning or an independent review.\n`;
const output = flagValue("--write");
if (output) await writeFile(join(repoRoot, output), report, "utf8");
console.log(`public-repo audit passed (${inspected} text files)`);
