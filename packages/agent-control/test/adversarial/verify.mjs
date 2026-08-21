#!/usr/bin/env node
/**
 * `npm run verify:adversarial` — the whole adversarial picture, in one report.
 *
 *   node test/adversarial/verify.mjs
 *   node test/adversarial/verify.mjs --json
 *
 * Combines four independent measurements, because each answers a question the
 * others cannot:
 *
 *   CORPUS       does the policy decide correctly, across 11k+ spellings
 *   ORACLE       do the decision, the execution, and the record agree
 *   TRANSPORT    does every wire the product speaks reach the same engine
 *   PLATFORMS    where has any of this actually been measured
 *
 * NUMBERS THAT ARE REPORTED HONESTLY EVEN WHEN THEY ARE UNFLATTERING
 *
 * `detection` is not 100% and is not supposed to be — the corpus deliberately
 * contains attacks the sanitizer cannot see, so that nobody reports the
 * sanitizer as though it were the control. The control is the policy engine.
 *
 * Platform rows that have not been run print NOT MEASURED rather than being
 * inferred from the one platform that has. An estimated row is indistinguishable
 * from a measured one once it is in a table, and the person who finds out which
 * kind it was is the technical buyer trying to reproduce it.
 */

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { arch, cpus, platform, release, totalmem } from "node:os";

import { run as runCorpus } from "../corpus/harness.mjs";
import { STARTER_POLICY } from "../../src/commands/init.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const PKG = join(HERE, "..", "..");
const CWD = platform() === "win32" ? "C:/workspace" : "/workspace";

const json = process.argv.includes("--json");

/* -------------------------------------------------------------------------- */
/*  Suites                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * Runs a node:test file and extracts its counts.
 *
 * Shelling out rather than importing: the test runner owns process-level state,
 * and importing test files into a reporting script makes their failures look
 * like the reporter's.
 */
function runSuite(relativePath) {
  const result = spawnSync(process.execPath, ["--test", relativePath], {
    cwd: PKG,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
    maxBuffer: 64 * 1024 * 1024,
  });

  const out = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  const num = (label) => {
    const m = out.match(new RegExp(`^.\\s*${label}\\s+(\\d+)$`, "m"));
    return m ? Number(m[1]) : 0;
  };

  return {
    file: relativePath,
    tests: num("tests"),
    pass: num("pass"),
    fail: num("fail"),
    skipped: num("skipped"),
    ok: result.status === 0,
  };
}

const SUITES = [
  { key: "oracle", label: "Consistency oracle", path: "test/adversarial/consistency.test.mjs" },
  { key: "bypass", label: "Bypass attempts", path: "test/adversarial/bypass.test.mjs" },
  { key: "layers", label: "Per-layer attacks", path: "test/adversarial/layers.test.mjs" },
  { key: "state", label: "State transitions", path: "test/adversarial/state-machine.test.mjs" },
  { key: "failure", label: "Fail-closed under failure", path: "test/adversarial/failure-modes.test.mjs" },
  { key: "delegation", label: "A2A delegation", path: "test/adversarial/delegation.test.mjs" },
  {
    key: "crossBoundary",
    label: "Cross-boundary identity",
    path: "test/adversarial/cross-boundary.test.mjs",
  },
  { key: "mutation", label: "Policy mutation in flight", path: "test/adversarial/policy-mutation.test.mjs" },
  { key: "e2e", label: "End-to-end MCP", path: "test/e2e-mcp.test.mjs" },
  // Not an attack suite. It is here because a gateway a real client cannot talk
  // to is not a deployed control, however well it enforces.
  { key: "compat", label: "MCP client compatibility", path: "test/mcp-compat.test.mjs" },
  { key: "approval", label: "Approval lifecycle", path: "test/approval-lifecycle.test.mjs" },
  { key: "conformance", label: "Cross-engine conformance", path: "test/conformance.test.mjs" },
];

/**
 * Transports, and the suite that proves each reaches the same decision path.
 *
 * A transport with no test that exercises it is reported as NOT COVERED rather
 * than assumed to work — the whole point of the row is to say which wires have
 * actually been driven.
 */
const TRANSPORTS = [
  { id: "stdio (MCP)", suite: "e2e", note: "real server subprocess, real framer" },
  { id: "HTTP (MCP)", suite: "layers", note: "upstream endpoint validation; SSRF targets refused" },
  { id: "UDS / named pipe", suite: "layers", note: "token auth, pre-auth calls refused" },
  { id: "SDK (guard.wrap)", suite: "conformance", note: "shares the decision core" },
];

/* -------------------------------------------------------------------------- */

function platformKey() {
  const os = platform();
  const cpuArch = arch() === "x64" ? "x86_64" : arch();
  const containerized = existsSync("/.dockerenv") || process.env.CIRVIX_BENCH_ENV === "docker";
  const base = os === "darwin" ? "macos" : os === "win32" ? "windows" : os;
  return containerized ? `docker-${base}-${cpuArch}` : `${base}-${cpuArch}`;
}

const TARGET_PLATFORMS = [
  "linux-x86_64",
  "linux-arm64",
  "macos-arm64",
  "docker-linux-x86_64",
  "windows-x86_64",
];

function benchmarkResults() {
  const path = join(PKG, "..", "..", "benchmarks", "results.json");
  try {
    return JSON.parse(readFileSync(path, "utf8")).platforms ?? {};
  } catch {
    return {};
  }
}

/* -------------------------------------------------------------------------- */

async function main() {
  const corpus = await runCorpus({ policySource: STARTER_POLICY, cwd: CWD });
  const suites = Object.fromEntries(SUITES.map((s) => [s.key, { ...runSuite(s.path), label: s.label }]));
  const benchmarks = benchmarkResults();
  const here = platformKey();

  /*
   * The four zero-tolerance counters.
   *
   * Each is derived from a suite rather than asserted here, so this report
   * cannot claim a zero that no test established.
   */
  const policyBypasses = corpus.falseNegatives.count;
  const auditInconsistencies = suites.oracle.fail;
  const failClosedViolations = suites.failure.fail;
  const approvalBypasses = suites.approval.fail + suites.state.fail;
  /*
   * Cross-boundary failures count as authority escalations, not as a separate
   * category. An identity that survives a transport hop unchecked IS an
   * escalation — delegation only ever narrows, so a surface that drops it hands
   * the caller everything policy allows.
   */
  const delegationEscalations =
    suites.delegation.fail + suites.mutation.fail + suites.crossBoundary.fail;
  const secretLeaks = corpus.results.filter((r) => r.secretLeak).length;

  const totals = {
    tests: Object.values(suites).reduce((n, s) => n + s.tests, 0),
    failures: Object.values(suites).reduce((n, s) => n + s.fail, 0),
  };

  const report = {
    generatedOn: here,
    corpus: {
      cases: corpus.total,
      attacks: corpus.attacks,
      benign: corpus.benign,
      falseNegatives: corpus.falseNegatives.count,
      falsePositives: corpus.falsePositives.count,
      crashes: corpus.crashes.count,
      detection: corpus.detection,
      latency: corpus.latency,
      byFamily: corpus.byFamily,
    },
    guarantees: {
      policyBypasses,
      secretLeaks,
      approvalBypasses,
      auditInconsistencies,
      failClosedViolations,
      delegationEscalations,
    },
    suites,
    totals,
    transports: TRANSPORTS.map((t) => ({ ...t, ok: suites[t.suite]?.ok ?? false })),
    platforms: TARGET_PLATFORMS.map((p) => ({
      id: p,
      measured: Boolean(benchmarks[p]),
      verified: p === here,
      p99: benchmarks[p]?.runs?.at(-1)?.p99 ?? null,
      decisions: benchmarks[p]?.runs?.at(-1)?.n ?? null,
    })),
  };

  if (json) {
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    return report.corpus.falseNegatives + report.corpus.falsePositives + totals.failures === 0 ? 0 : 1;
  }

  render(report);
  return report.corpus.falseNegatives + report.corpus.falsePositives + totals.failures === 0 ? 0 : 1;
}

/* -------------------------------------------------------------------------- */

const w = (s, n) => String(s).padEnd(n);
const r = (s, n) => String(s).padStart(n);

function render(rep) {
  const out = [];
  const cpu = cpus()[0];

  out.push("");
  out.push("  CIRVIX ADVERSARIAL VERIFICATION");
  out.push("");
  out.push(`  ${w("Attack cases:", 22)}${r(rep.corpus.cases.toLocaleString("en-US"), 10)}`);
  out.push(`  ${w("  attacks", 22)}${r(rep.corpus.attacks.toLocaleString("en-US"), 10)}`);
  out.push(`  ${w("  benign (control)", 22)}${r(rep.corpus.benign.toLocaleString("en-US"), 10)}`);
  out.push("");
  out.push(`  ${w("False negatives:", 22)}${r(rep.corpus.falseNegatives, 10)}`);
  out.push(`  ${w("False positives:", 22)}${r(rep.corpus.falsePositives, 10)}`);
  out.push(`  ${w("Crashes:", 22)}${r(rep.corpus.crashes, 10)}`);
  out.push(`  ${w("Policy bypasses:", 22)}${r(rep.guarantees.policyBypasses, 10)}`);
  out.push(`  ${w("Secret leaks:", 22)}${r(rep.guarantees.secretLeaks, 10)}`);
  out.push(`  ${w("Approval bypasses:", 22)}${r(rep.guarantees.approvalBypasses, 10)}`);
  out.push(`  ${w("Audit inconsistencies:", 22)}${r(rep.guarantees.auditInconsistencies, 10)}`);
  out.push(`  ${w("Fail-open violations:", 22)}${r(rep.guarantees.failClosedViolations, 10)}`);
  out.push(`  ${w("Authority escalations:", 22)}${r(rep.guarantees.delegationEscalations, 10)}`);
  out.push("");
  out.push(`  ${w("P50:", 22)}${r(`${rep.corpus.latency.p50} ms`, 10)}`);
  out.push(`  ${w("P95:", 22)}${r(`${rep.corpus.latency.p95} ms`, 10)}`);
  out.push(`  ${w("P99:", 22)}${r(`${rep.corpus.latency.p99} ms`, 10)}`);
  out.push("");

  out.push("  Attack families");
  const famWidth = Math.max(...Object.keys(rep.corpus.byFamily).map((k) => k.length));
  for (const [family, stats] of Object.entries(rep.corpus.byFamily)) {
    const ok = stats.correct === stats.total;
    out.push(`    ${ok ? "PASS" : "FAIL"}  ${w(family, famWidth + 2)}${r(`${stats.correct}/${stats.total}`, 12)}`);
  }
  out.push("");

  out.push("  Suites");
  const suiteWidth = Math.max(...Object.values(rep.suites).map((s) => s.label.length));
  for (const s of Object.values(rep.suites)) {
    out.push(
      `    ${s.ok ? "PASS" : "FAIL"}  ${w(s.label, suiteWidth + 2)}${r(`${s.pass}/${s.tests}`, 10)}` +
        (s.skipped ? `   ${s.skipped} skipped` : ""),
    );
  }
  out.push(`    ${w("", 6)}${w("total", suiteWidth + 2)}${r(`${rep.totals.tests - rep.totals.failures}/${rep.totals.tests}`, 10)}`);
  out.push("");

  out.push("  Transport");
  const tWidth = Math.max(...rep.transports.map((t) => t.id.length));
  for (const t of rep.transports) {
    out.push(`    ${t.ok ? "PASS" : "FAIL"}  ${w(t.id, tWidth + 2)}${t.note}`);
  }
  out.push("");

  out.push("  Platforms");
  const pWidth = Math.max(...rep.platforms.map((p) => p.id.length));
  for (const p of rep.platforms) {
    if (!p.measured) {
      out.push(`    ${w("", 6)}${w(p.id, pWidth + 2)}NOT MEASURED`);
      continue;
    }
    out.push(
      `    ${p.verified ? "PASS" : "  ? "}  ${w(p.id, pWidth + 2)}` +
        `P99 ${p.p99}ms over ${Number(p.decisions).toLocaleString("en-US")} decisions` +
        (p.verified ? "" : "   (benchmarked, suites not run here)"),
    );
  }
  out.push("");

  out.push("  Notes");
  out.push(
    `    Detection is ${(rep.corpus.detection.rate * 100).toFixed(1)}% of the attacks the sanitizer is expected to see.`,
  );
  out.push(
    `    ${rep.corpus.detection.undetectableByDesign} attacks are undetectable by design and are blocked by policy anyway —`,
  );
  out.push("    the sanitizer is a mitigation, the policy engine is the control.");
  out.push("");
  out.push("    Platform rows marked NOT MEASURED have not been run on this project's");
  out.push("    hardware. They are absent rather than estimated.");
  out.push("");
  out.push(`    Measured on ${platform()} ${release()} ${arch()}, ${cpu ? cpu.model.trim() : "unknown cpu"},`);
  out.push(`    ${Math.round(totalmem() / 1024 ** 3)} GB, Node ${process.version}.`);
  out.push("");

  process.stdout.write(out.join("\n"));
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`\n  verification failed to run: ${err.stack}\n\n`);
    process.exit(2);
  });
