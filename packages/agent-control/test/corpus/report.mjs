#!/usr/bin/env node
/**
 * `npm run corpus` — the adversarial report, printed.
 *
 * The same run `corpus.test.mjs` asserts against, rendered for a human instead
 * of reduced to pass/fail. Use it when tuning a rule set: the per-family
 * breakdown and the false-positive list are what tell you whether a change made
 * the policy tighter or merely noisier.
 *
 * Exits non-zero on any false negative or false positive, so it also works as a
 * CI gate on a policy change.
 *
 *   node test/corpus/report.mjs
 *   node test/corpus/report.mjs --policy ../../policies/default.policy
 *   node test/corpus/report.mjs --json
 */

import { readFile } from "node:fs/promises";

import { run, render } from "./harness.mjs";
import { STARTER_POLICY } from "../../src/commands/init.mjs";

const args = process.argv.slice(2);
const json = args.includes("--json");
const policyFlag = args.indexOf("--policy");

const source =
  policyFlag !== -1 ? await readFile(args[policyFlag + 1], "utf8") : STARTER_POLICY;

const cwd = process.platform === "win32" ? "C:/workspace" : "/workspace";
const report = await run({ policySource: source, cwd });

process.stdout.write(json ? JSON.stringify(report, null, 2) + "\n" : render(report));

process.exit(report.falseNegatives.count + report.falsePositives.count + report.crashes.count > 0 ? 1 : 0);
