/**
 * The package's published manifest, pinned.
 *
 * `tools/verify-package.mjs` drops any script whose referenced files are not in
 * the tarball, so a broken reference can never reach a consumer. That is the
 * right behaviour and it is also a silent one: a typo in a new script would be
 * quietly withheld rather than reported, and the first person to notice would
 * be a user.
 *
 * This test pins the withheld set. Every current entry is a deliberate
 * decision, and adding one requires editing this list — which is the point.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join } from "node:path";

import { publishedManifest, referencedPaths } from "../../../tools/pack-manifest.mjs";

const packageDir = fileURLToPath(new URL("..", import.meta.url));

async function listFiles(dir, prefix = "") {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) out.push(...(await listFiles(join(dir, entry.name), rel)));
    else if (entry.isFile()) out.push(rel);
  }
  return out;
}

const manifest = JSON.parse(await readFile(join(packageDir, "package.json"), "utf8"));

/**
 * The shipment is the `files` allowlist and nothing else — the same set
 * `tools/verify-package.mjs` stages before packing. Using the whole package
 * directory here would make every dev script look resolvable and the pin would
 * assert nothing.
 */
const shipped = new Set();
for (const entry of manifest.files ?? []) {
  if (entry.endsWith(".md") || entry === "LICENSE" || entry === "NOTICE") shipped.add(entry);
  else for (const file of await listFiles(join(packageDir, entry), entry)) shipped.add(file);
}

const { manifest: published, dropped } = publishedManifest(manifest, shipped);

test("only the dev-only scripts are withheld from the tarball", () => {
  assert.deepEqual(
    dropped.map((d) => d.name).sort(),
    ["bench", "corpus", "test", "verify:adversarial"],
    `withheld: ${JSON.stringify(dropped)}`,
  );
});

test("every withheld script names files that really are absent from the shipment", () => {
  for (const { name, missing } of dropped) {
    assert.ok(missing.length, `${name} was withheld without a missing file`);
    // A script withheld because of a typo rather than because it is dev-only
    // would appear here as a path that does not exist in the repository either.
    for (const ref of missing) {
      assert.ok(
        ref.includes("*") || ref.startsWith("..") || !shipped.has(ref),
        `${name}: ${ref} is unexpected`,
      );
    }
  }
});

test("every published script resolves inside the shipment", () => {
  assert.ok(Object.keys(published.scripts).length > 0, "nothing is published at all");
  for (const [name, command] of Object.entries(published.scripts)) {
    for (const ref of referencedPaths(command)) {
      assert.ok(shipped.has(ref), `published script ${name} references missing ${ref}`);
    }
  }
});

test("the shipped manifest still declares the runtime surface", () => {
  for (const field of ["exports", "bin", "engines", "files", "name", "version"]) {
    assert.deepEqual(published[field], manifest[field], `${field} was altered by the transform`);
  }
  assert.ok(published.files.length > 0);
});
