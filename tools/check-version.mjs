#!/usr/bin/env node
/** Verify that checked-in release metadata has one canonical version. */
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const text = async (file) => readFile(join(root, file), "utf8");
const version = (await text("VERSION")).trim();
const rootManifest = JSON.parse(await text("package.json"));
const nodeManifest = JSON.parse(await text("packages/agent-control/package.json"));
const lock = JSON.parse(await text("package-lock.json"));
const pyproject = await text("packages/cirvix-python/pyproject.toml");

const checks = [
  ["VERSION", version],
  ["package.json", rootManifest.version],
  ["packages/agent-control/package.json", nodeManifest.version],
  ["package-lock.json root", lock.version],
  ["package-lock.json package", lock.packages?.["packages/agent-control"]?.version],
  ["packages/cirvix-python/pyproject.toml", pyproject.match(/^version\s*=\s*[\"']([^\"']+)[\"']/m)?.[1]],
];
const mismatches = checks.filter(([, actual]) => actual !== version);
if (mismatches.length) {
  console.error(`Version mismatch; canonical VERSION is ${version}:`);
  for (const [name, actual] of mismatches) console.error(`  ${name}: ${actual ?? "missing"}`);
  process.exit(1);
}
console.log(`version ${version} is consistent across ${checks.length} release surfaces`);
