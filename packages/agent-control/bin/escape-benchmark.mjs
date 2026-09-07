#!/usr/bin/env node
/**
 * Runs the Agent Escape Benchmark and prints the result.
 *
 * Exits non-zero when anything escapes, so it can gate a release. A benchmark
 * that always exits 0 is a slideshow.
 *
 *   node bin/escape-benchmark.mjs             # human-readable
 *   node bin/escape-benchmark.mjs --json      # machine-readable
 *   node bin/escape-benchmark.mjs --out FILE  # write JSON evidence
 */
import { writeFileSync } from "node:fs";
import { runBenchmark } from "../src/core/escape-benchmark.mjs";

const argv = process.argv.slice(2);
const asJson = argv.includes("--json");
const outAt = argv.indexOf("--out");
const outFile = outAt === -1 ? null : argv[outAt + 1];

const r = await runBenchmark();

if (outFile) {
  /* The full results, including every step — the summary alone is a claim,
     and the steps are what let someone else check it. */
  writeFileSync(outFile, JSON.stringify(r, null, 2));
}

if (asJson) {
  console.log(JSON.stringify(r, null, 2));
} else {
  const bar = "─".repeat(58);
  console.log(bar);
  console.log(" CIRVIX AGENT ESCAPE BENCHMARK");
  console.log(bar);
  console.log(` Scenarios                    ${String(r.scenarios).padStart(5)}`);
  console.log(` Escape attempts              ${String(r.attempts).padStart(5)}`);
  console.log(` Blocked                      ${String(r.blocked).padStart(5)}`);
  console.log(` Successful escapes           ${String(r.escaped).padStart(5)}`);
  console.log(` Authorization integrity      ${String(r.integrity + "%").padStart(5)}`);
  console.log(` Controls held                ${String(`${r.controls.held}/${r.controls.total}`).padStart(5)}`);
  console.log(bar);
  for (const [k, v] of Object.entries(r.byCategory)) {
    console.log(` ${k.replace(/_/g, " ").toUpperCase().padEnd(26)} ${String(v.attempts).padStart(4)}`);
    console.log(`   blocked                  ${String(v.blocked).padStart(4)}${v.escaped ? `   ESCAPED ${v.escaped}` : ""}`);
  }
  console.log(bar);
  if (r.escapes.length) {
    console.log("\n ESCAPES — investigate before shipping:");
    for (const e of r.escapes) {
      console.log(`   ${e.id}  ${e.name}  [${e.category}, level ${e.level}]`);
      for (const s of e.steps) console.log(`      ${s.tool} → ${s.verdict} (${s.rule})`);
    }
  }
  if (r.brokenControls.length) {
    console.log("\n BROKEN CONTROLS — the mission cannot do its own job:");
    for (const b of r.brokenControls) {
      console.log(`   ${b.id}  ${b.name}`);
      for (const s of b.steps) console.log(`      ${s.tool} → ${s.verdict} (${s.rule})`);
    }
  }
  if (!r.escapes.length && !r.brokenControls.length) {
    console.log("\n Every attempt contained; every mission still able to work.");
  }
  console.log(`\n ${r.generatedAt}`);
}

process.exit(r.escaped > 0 || r.brokenControls.length > 0 ? 1 : 0);
