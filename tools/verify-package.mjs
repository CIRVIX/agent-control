#!/usr/bin/env node
import { copyFile, constants, cp, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

import { publishedManifest, referencedPaths } from "./pack-manifest.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const packageDir = join(root, "packages", "agent-control");
const npmCli = process.env.npm_execpath ?? join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");

function run(command, args, cwd, expected = 0) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      env: { ...process.env, npm_config_offline: "true", npm_config_audit: "false", npm_config_fund: "false" },
    });
    let stdout = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.resume();
    child.on("error", reject);
    child.on("close", (code) => code === expected ? resolve(stdout) : reject(new Error(`Package verification subprocess exited ${code}, expected ${expected}`)));
  });
}

/** Every regular file under `dir`, as forward-slash paths relative to it. */
async function listFiles(dir, prefix = "") {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) out.push(...(await listFiles(join(dir, entry.name), rel)));
    else if (entry.isFile()) out.push(rel);
  }
  return out;
}

const temp = await mkdtemp(join(tmpdir(), "cirvix-package-"));
try {
  const manifest = JSON.parse(await readFile(join(packageDir, "package.json"), "utf8"));
  for (const field of ["dependencies", "optionalDependencies", "peerDependencies", "bundledDependencies", "bundleDependencies"]) {
    if (Object.keys(manifest[field] ?? {}).length) throw new Error("Runtime dependencies are forbidden");
  }

  /*
   * Pack a STAGED copy rather than the repository directory.
   *
   * Two things are true at once and only a staged copy satisfies both:
   *
   *   1. `npm publish` in the release workflow publishes the tarball this
   *      script builds (`npm publish dist/node/*.tgz`), so this script is the
   *      artifact builder. Whatever it verifies IS what ships.
   *   2. The manifest inside that tarball must be the one a consumer receives,
   *      which is not the repository manifest — the repository keeps its
   *      developer scripts, the tarball must not advertise scripts whose files
   *      it does not contain.
   *
   * Staging means `pack --ignore-scripts` can stay: no lifecycle hook has to
   * run to produce the published manifest, so this verifier still never
   * executes repository code to do its job.
   */
  const stage = join(temp, "stage");
  await mkdir(stage, { recursive: true });
  for (const entry of manifest.files ?? []) {
    await cp(join(packageDir, entry), join(stage, entry), { recursive: true });
  }

  const staged = new Set(await listFiles(stage));
  const { manifest: published, dropped } = publishedManifest(manifest, staged);
  await writeFile(join(stage, "package.json"), JSON.stringify(published, null, 2) + "\n", "utf8");

  const packJson = JSON.parse(await run(process.execPath, [npmCli, "pack", "--offline", "--ignore-scripts", "--json", "--pack-destination", temp], stage));
  if (!Array.isArray(packJson) || packJson.length !== 1) throw new Error("Expected exactly one packed package");
  const packEntry = packJson[0];
  const tarball = packEntry.filename;
  if (!tarball || basename(tarball) !== tarball || !tarball.endsWith(".tgz")) throw new Error("Invalid package filename");
  if (!Array.isArray(packEntry.files) || !packEntry.files.length) throw new Error("Missing package inventory");
  const names = new Set();
  for (const file of packEntry.files) {
    const name = file.path;
    if (typeof name !== "string" || name.split("/").some((part) => !part || part.startsWith(".")) || name.includes("\\")) throw new Error("Unsafe package member");
    if (!/^(?:(?:bin|src)\/(?:[\w-]+\/)*[\w-]+\.mjs|action\/(?:report\.mjs|action\.yml|README\.md)|package\.json|README\.md|LICENSE|NOTICE)$/.test(name)) throw new Error("Unexpected package member");
    if (names.has(name) || !(await lstat(join(stage, name))).isFile()) throw new Error("Duplicate or non-regular package member");
    names.add(name);
    const source = await readFile(join(stage, name), "utf8");
    if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=]{64,}|\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bAKIA[A-Z0-9]{16}\b/.test(source)) throw new Error(`Potential secret in ${name}; content suppressed`);
  }
  for (const required of ["package.json", "LICENSE", "NOTICE", "README.md", "bin/cirvix.mjs", ...Object.values(manifest.exports)]) {
    if (!names.has(required.replace(/^\.\//, ""))) throw new Error("Required package member missing");
  }
  const archive = join(temp, tarball);
  await writeFile(join(temp, "package.json"), JSON.stringify({ name: "cirvix-package-smoke", version: "1.0.0", private: true }), "utf8");
  await run(process.execPath, [npmCli, "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", archive], temp);
  const installedRoot = join(temp, "node_modules", "@cirvix_ai", "agent-control");

  /*
   * The check the defect needed: read the manifest out of the INSTALLED
   * artifact and prove every script it still declares can actually run there.
   * `npm test` inside the published package used to exit 0 while running zero
   * tests, because the script survived and its files did not.
   */
  const installed = JSON.parse(await readFile(join(installedRoot, "package.json"), "utf8"));
  if (JSON.stringify(installed.scripts ?? {}) !== JSON.stringify(published.scripts)) {
    throw new Error("Installed manifest scripts differ from the manifest this script built");
  }
  for (const [name, command] of Object.entries(installed.scripts ?? {})) {
    const missing = referencedPaths(command).filter((ref) => !names.has(ref));
    if (missing.length) throw new Error(`Published script "${name}" references unpublished ${missing.join(", ")}`);
  }
  if (!Object.keys(installed.scripts ?? {}).length) throw new Error("Published manifest declares no scripts at all");

  const cli = join(installedRoot, "bin", "cirvix.mjs");
  const version = (await run(process.execPath, [cli, "--version"], temp)).trim();
  if (version !== manifest.version) throw new Error("Installed CLI version differs from package metadata");
  await run(process.execPath, [cli, "init", "--cwd", temp], temp);
  await run(process.execPath, [cli, "policy", "check", "--cwd", temp], temp);
  await run(process.execPath, [cli, "check", "--action", "fs.read", "--resource", ".env.production", "--cwd", temp], temp, 1);
  await run(process.execPath, [cli, "check", "--action", "fs.read", "--resource", "src/index.mjs", "--cwd", temp], temp);
  const smoke = join(temp, "smoke.mjs");
  await writeFile(smoke, "import { guard, STARTER_RULES } from '@cirvix_ai/agent-control';\nconst t = guard.wrap({ read_file: async () => 'ok' }, { rules: STARTER_RULES });\nawait t.read_file({ path: 'src/index.mjs' });\n", "utf8");
  await run(process.execPath, [smoke], temp);
  if (process.env.CIRVIX_PACKAGE_OUTPUT_DIR) {
    const output = process.env.CIRVIX_PACKAGE_OUTPUT_DIR;
    if (!(await lstat(output)).isDirectory()) throw new Error("Package output must be an existing directory");
    await copyFile(archive, join(output, tarball), constants.COPYFILE_EXCL);
  }
  console.log(
    `package verification passed: ${tarball}, version ${version}, ${names.size} approved files, offline install, ` +
      `${Object.keys(published.scripts).length} published scripts`,
  );
  for (const { name, command, missing } of dropped) {
    // Visible, not silent: a dropped script is a decision somebody made.
    console.log(`  not published: ${name} — references ${missing.join(", ")} ("${command}")`);
  }
} finally {
  await rm(temp, { recursive: true, force: true });
}
