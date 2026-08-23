#!/usr/bin/env node
/** Lightweight provenance audit for the curated public repository. */
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const ignored = new Set([".git", "node_modules", ".npm-cache"]);
const textExtensions = new Set([".js", ".mjs", ".cjs", ".json", ".md", ".py", ".toml", ".yml", ".yaml", ".sh", ".ps1", ".txt"]);
const files = [];
async function walk(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (ignored.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) await walk(full);
    else if (textExtensions.has(entry.name.includes(".") ? "." + entry.name.split(".").pop().toLowerCase() : "")) files.push(full);
  }
}
await walk(root);

const findings = [];
const contentPatterns = [
  ["private hostname", /https?:\/\/(?:[^/]*\.)?(?:internal|corp|intranet)(?:[./]|$)/i],
  ["RFC1918 URL", /https?:\/\/(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/i],
  ["private key material", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s*[A-Za-z0-9+/=]{20,}/],
  ["live GitHub token", /\bgh[pousr]_[A-Za-z0-9]{30,}\b/],
  ["live AWS access key", /\bAKIA[0-9A-Z]{16}\b/],
  ["live Stripe secret", /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/],
];
for (const file of files) {
  const name = relative(root, file).replaceAll("\\", "/");
  if (/^packages\/control-plane(?:\/|$)/i.test(name)) findings.push(`proprietary path: ${name}`);
  const source = await readFile(file, "utf8");
  for (const [label, pattern] of contentPatterns) {
    if (!pattern.test(source)) continue;
    if (name === "docs/api.md" && /example\.com/i.test(source)) continue;
    if (name.startsWith("packages/conformance/") && /metadata\.google\.internal/i.test(source)) continue;
    if ((name.startsWith("packages/agent-control/test/") || name.startsWith("benchmarks/")) && /EXAMPLE|dummy|fake|DEMO|AAAA|ABCDEFGHIJKLMNOPQRSTUVWXYZ/i.test(source)) continue;
    if (name === "packages/agent-control/src/commands/demo.mjs" && /EXAMPLE/i.test(source)) continue;
    findings.push(`${label}: ${name}`);
  }
}
if (findings.length) {
  console.error("Public-repo audit failed:");
  for (const finding of findings) console.error(`  ${finding}`);
  process.exit(1);
}
const report = `# Public repository audit\n\n- Audited: ${new Date().toISOString()}\n- Text files inspected: ${files.length}\n- Proprietary-path findings: 0\n- High-confidence live-secret findings: 0\n\nThis audit does not replace GitHub secret scanning or an independent review.\n`;
const output = process.argv[2] === "--write" ? process.argv[3] : null;
if (output) await writeFile(join(root, output), report, "utf8");
console.log(`public-repo audit passed (${files.length} text files)`);
