#!/usr/bin/env node
import { copyFile, constants, lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

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

const temp = await mkdtemp(join(tmpdir(), "cirvix-package-"));
try {
  const manifest = JSON.parse(await readFile(join(packageDir, "package.json"), "utf8"));
  for (const field of ["dependencies", "optionalDependencies", "peerDependencies", "bundledDependencies", "bundleDependencies"]) {
    if (Object.keys(manifest[field] ?? {}).length) throw new Error("Runtime dependencies are forbidden");
  }
  const packJson = JSON.parse(await run(process.execPath, [npmCli, "pack", "--offline", "--ignore-scripts", "--json", "--pack-destination", temp], packageDir));
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
    if (names.has(name) || !(await lstat(join(packageDir, name))).isFile()) throw new Error("Duplicate or non-regular package member");
    names.add(name);
    const source = await readFile(join(packageDir, name), "utf8");
    if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=]{64,}|\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bAKIA[A-Z0-9]{16}\b/.test(source)) throw new Error(`Potential secret in ${name}; content suppressed`);
  }
  for (const required of ["package.json", "LICENSE", "NOTICE", "README.md", "bin/cirvix.mjs", ...Object.values(manifest.exports)]) {
    if (!names.has(required.replace(/^\.\//, ""))) throw new Error("Required package member missing");
  }
  const archive = join(temp, tarball);
  await writeFile(join(temp, "package.json"), JSON.stringify({ name: "cirvix-package-smoke", version: "1.0.0", private: true }), "utf8");
  await run(process.execPath, [npmCli, "install", "--offline", "--ignore-scripts", "--no-audit", "--no-fund", archive], temp);
  const cli = join(temp, "node_modules", "@cirvix_ai", "agent-control", "bin", "cirvix.mjs");
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
  console.log(`package verification passed: ${tarball}, version ${version}, ${names.size} approved files, offline install`);
} finally {
  await rm(temp, { recursive: true, force: true });
}
