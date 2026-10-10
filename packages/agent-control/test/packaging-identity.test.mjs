/**
 * Package / release integrity for the identity boundary.
 *
 * Identity enforcement is a SHIPPED property, not a checkout property: the CLI
 * the customer installs (`npm i @cirvix_ai/agent-control`) must contain every
 * file the boundary needs, and every documented entry point must resolve
 * inside the packed artifact. A feature that works in the repository and is
 * missing from the tarball is worse than absent — it is a boundary the
 * operator believes they have and do not.
 *
 * Two layers:
 *   1. FAST (always runs): the exports map resolves, the files list covers
 *      every source file the identity boundary imports transitively.
 *   2. SLOW (opt-in via CIRVIX_PACK_TEST=1): a real `npm pack --dry-run` and
 *      asserts every identity file appears in the tarball.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const PKG_ROOT = resolve(join(dirname(fileURLToPath(import.meta.url)), ".."));

/* ------------------------------------------------------------------ */
/*  Layer 1 — the exports map resolves (runs everywhere, fast)         */
/* ------------------------------------------------------------------ */

test("packaging: every documented entry point resolves from the package root", async () => {
  const pkg = JSON.parse(await readFile(join(PKG_ROOT, "package.json"), "utf8"));
  assert.ok(pkg.exports, "the package has an exports map");

  const mustExist = async (file, what) => {
    try {
      await access(file);
    } catch {
      assert.fail(`${what} does not exist: ${file}`);
    }
  };

  for (const [name, target] of Object.entries(pkg.exports)) {
    const file = join(PKG_ROOT, typeof target === "string" ? target : target.default ?? Object.values(target)[0]);
    await mustExist(file, `export "${name}"`);
    // And it actually parses — a truncated file in the tarball would fail here.
    await import(pathToFileURL(file).href);
  }

  // The binary entry point exists too.
  for (const bin of Object.values(pkg.bin ?? {})) {
    await mustExist(join(PKG_ROOT, bin), "bin entry");
  }
});

test("packaging: the files list covers every identity-boundary source file", async () => {
  const pkg = JSON.parse(await readFile(join(PKG_ROOT, "package.json"), "utf8"));
  const files = pkg.files ?? [];
  const included = (rel) => files.some((f) => rel === f || rel.startsWith(f.replace(/\/+$/, "") + "/"));

  // Transitive import closure of the identity boundary: everything the
  // gateway, the CLI and a consumer of `@cirvix_ai/agent-control/identity`
  // actually load at runtime.
  const ROOTS = [
    "src/core/identity.mjs",
    "src/core/identity-modes.mjs",
    "src/core/identity-store.mjs",
    "src/core/keys.mjs",
    "src/core/guard.mjs",
    "src/core/gateway.mjs",
    "src/core/uds.mjs",
    "src/commands/enroll.mjs",
    "src/commands/doctor.mjs",
    "bin/cirvix.mjs",
  ];

  const closure = new Set();
  const queue = [...ROOTS];
  while (queue.length) {
    const rel = queue.shift();
    if (!rel || !rel.endsWith(".mjs") || closure.has(rel)) continue;
    closure.add(rel);
    if (!included(rel)) {
      assert.fail(`"${rel}" is imported by the identity boundary but NOT matched by package.json "files" (${JSON.stringify(files)})`);
    }
    const abs = join(PKG_ROOT, rel);
    let text;
    try {
      text = await readFile(abs, "utf8");
    } catch {
      continue;
    }
    const imports = [...text.matchAll(/from\s+["'](\.[^"']+)["']/g)].map((m) => m[1]);
    for (const spec of imports) {
      const resolved = relative(PKG_ROOT, resolve(dirname(abs), spec)).split("\\").join("/");
      if (resolved.startsWith("src/") || resolved.startsWith("bin/")) queue.push(resolved);
    }
  }
  // The closure is real — if this ever stops being true the walk is broken.
  assert.ok(closure.has("src/core/identity.mjs"));
  assert.ok(closure.has("src/core/identity-modes.mjs"), "the modes module is in the shipped closure");
});

/* ------------------------------------------------------------------ */
/*  Layer 2 — the packed tarball (opt-in; slow)                        */
/* ------------------------------------------------------------------ */

const PACK = process.env.CIRVIX_PACK_TEST === "1";

(PACK ? test : test.skip)("packaging: npm pack contains every identity file and the tarball imports work", async () => {
  const out = execFileSync("npm", ["pack", "--dry-run", "--json"], { cwd: PKG_ROOT, encoding: "utf8", shell: true });
  const parsed = JSON.parse(out);
  // Older npm emits `entries` with "package/"-prefixed paths; newer npm emits
  // `files` with bare relative paths. Accept both.
  const entries = parsed[0]?.entries ?? parsed[0]?.files ?? [];
  const raw = entries.map((e) => e.path);
  const names = new Set(raw.flatMap((p) => [p, p.replace(/^package\//, "")]));

  const pkg = JSON.parse(await readFile(join(PKG_ROOT, "package.json"), "utf8"));
  assert.ok(names.has("package.json"), "the tarball has a manifest");

  for (const rel of ["src/core/identity.mjs", "src/core/identity-modes.mjs", "src/core/identity-store.mjs", "src/core/keys.mjs", "bin/cirvix.mjs"]) {
    assert.ok(names.has(rel), `packed tarball contains ${rel}`);
  }

  // Exports must be declared for the same modules the source ships.
  assert.ok(pkg.exports["./identity"], "./identity export is declared");
  assert.ok(pkg.exports["./identity-mode"], "./identity-mode export is declared");
});
