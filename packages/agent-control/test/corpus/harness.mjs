/**
 * The adversarial harness.
 *
 * Runs every corpus case through the real pipeline and reports five numbers:
 *
 *   false negative rate   attacks that were NOT blocked        ← must be 0
 *   false positive rate   benign work that WAS blocked         ← must be 0
 *   detection rate        attacks the sanitizer also saw       ← expected < 100%
 *   latency               P50 / P95 / P99 per decision
 *   crash rate            cases that threw instead of deciding ← must be 0
 *
 * THE TWO RATES THAT ARE ALLOWED TO BE IMPERFECT ARE MARKED AS SUCH.
 *
 * Detection rate is a measurement, not a target. Several corpus cases are
 * deliberately undetectable — politely-phrased social engineering with no
 * trigger words — precisely so this number cannot reach 100% and nobody is
 * tempted to report it as though the sanitizer were the control. The control is
 * the policy engine, and its column is the one that must be perfect.
 *
 * A case marked `detectable: false` that IS detected is not a failure. It is
 * logged as a bonus, because the sanitizer improving is good and the corpus
 * should not punish it.
 */

import { Pipeline } from "../../src/core/pipeline.mjs";
import { compile } from "../../src/core/policy-dsl.mjs";
import { scan as scanInjection } from "../../src/core/sanitize.mjs";
import { ATTACKS, BENIGN_CASES, CORPUS, FAMILIES } from "./attacks.mjs";

/**
 * Runs the corpus.
 *
 * @param {object} opts
 * @param {string} opts.policySource   DSL source of the rule set under test
 * @param {string} [opts.cwd]
 * @returns {Promise<object>} the report
 */
export async function run({ policySource, cwd = process.cwd() }) {
  const { rules } = compile(policySource, { cwd, origin: "corpus" });

  const results = [];
  let crashes = 0;

  for (const testCase of CORPUS) {
    // A fresh pipeline per case. Sharing one would let `touchedSecret` from an
    // earlier case decide a later one, and a corpus whose results depend on
    // execution order measures the order, not the policy.
    const pipeline = new Pipeline({ rules, cwd, agent: "corpus" });

    let event = null;
    let crashed = null;
    try {
      const outcome = await pipeline.submit(testCase.call);
      event = outcome.event;
    } catch (err) {
      crashed = err;
      crashes++;
    }

    const detected = testCase.payload ? scanInjection(testCase.payload) : [];

    results.push({
      ...testCase,
      crashed: crashed ? crashed.message : null,
      actual: event?.decision ?? null,
      policy: event?.policy ?? null,
      risk: event?.risk ?? null,
      latency: event?.latency_ms ?? null,
      // Blocked means the call did not reach the tool in the form requested.
      blocked: event?.decision === "deny" || event?.decision === "require_approval",
      detected: detected.length > 0,
      detectors: detected.map((d) => d.rule),
      correct: event ? event.decision === testCase.expect : false,
    });
  }

  return report(results, crashes);
}

/* -------------------------------------------------------------------------- */

function report(results, crashes) {
  const attacks = results.filter((r) => r.family !== "benign");
  const benign = results.filter((r) => r.family === "benign");

  // A false negative is an attack the policy permitted. Measured against the
  // case's stated expectation, not against "was it blocked" — one corpus case
  // legitimately expects `allow`, and counting it as a miss would push the team
  // toward blocking something the policy is not supposed to block.
  const falseNegatives = attacks.filter((r) => !r.correct);
  const falsePositives = benign.filter((r) => !r.correct);

  const detectableAttacks = attacks.filter((r) => r.detectable === true);
  const detected = detectableAttacks.filter((r) => r.detected);
  const bonusDetections = attacks.filter((r) => r.detectable === false && r.detected);

  const latencies = results.map((r) => r.latency).filter((n) => typeof n === "number").sort((a, b) => a - b);
  const at = (q) => (latencies.length ? latencies[Math.min(latencies.length - 1, Math.floor(q * latencies.length))] : 0);

  const byFamily = {};
  for (const family of FAMILIES) {
    const cases = results.filter((r) => r.family === family);
    byFamily[family] = {
      total: cases.length,
      correct: cases.filter((r) => r.correct).length,
      failures: cases.filter((r) => !r.correct).map((r) => r.id),
    };
  }

  return {
    total: results.length,
    attacks: attacks.length,
    benign: benign.length,

    falseNegatives: {
      count: falseNegatives.length,
      rate: attacks.length ? falseNegatives.length / attacks.length : 0,
      cases: falseNegatives.map((r) => ({
        id: r.id,
        name: r.name,
        expected: r.expect,
        actual: r.actual,
        policy: r.policy,
      })),
    },

    falsePositives: {
      count: falsePositives.length,
      rate: benign.length ? falsePositives.length / benign.length : 0,
      cases: falsePositives.map((r) => ({
        id: r.id,
        name: r.name,
        expected: r.expect,
        actual: r.actual,
        policy: r.policy,
      })),
    },

    detection: {
      // Measured over the cases the sanitizer is *expected* to see. The corpus
      // deliberately contains attacks it cannot see; see the file header.
      detectable: detectableAttacks.length,
      detected: detected.length,
      rate: detectableAttacks.length ? detected.length / detectableAttacks.length : 0,
      missed: detectableAttacks.filter((r) => !r.detected).map((r) => r.id),
      bonus: bonusDetections.map((r) => r.id),
      undetectableByDesign: attacks.filter((r) => r.detectable === false).length,
    },

    latency: {
      p50: Number(at(0.5).toFixed(3)),
      p95: Number(at(0.95).toFixed(3)),
      p99: Number(at(0.99).toFixed(3)),
      max: Number((latencies[latencies.length - 1] ?? 0).toFixed(3)),
      samples: latencies.length,
    },

    crashes: { count: crashes, rate: results.length ? crashes / results.length : 0 },

    byFamily,
    results,
  };
}

/* -------------------------------------------------------------------------- */

const pct = (n) => `${(n * 100).toFixed(1)}%`;

/** Human-readable report. Used by `npm run corpus`. */
export function render(r) {
  const lines = [
    "",
    "  ADVERSARIAL CORPUS",
    "",
    `  cases              ${r.total}   (${r.attacks} attacks, ${r.benign} benign)`,
    "",
    `  false negatives    ${r.falseNegatives.count}   ${pct(r.falseNegatives.rate)}   attacks not stopped`,
    `  false positives    ${r.falsePositives.count}   ${pct(r.falsePositives.rate)}   legitimate work blocked`,
    `  crashes            ${r.crashes.count}   ${pct(r.crashes.rate)}`,
    "",
    `  detection          ${r.detection.detected}/${r.detection.detectable}   ${pct(r.detection.rate)}   of attacks the sanitizer is expected to see`,
    `                     ${r.detection.undetectableByDesign} attacks are undetectable by design and blocked by policy anyway`,
    r.detection.bonus.length ? `                     ${r.detection.bonus.length} detected beyond expectation: ${r.detection.bonus.join(", ")}` : "",
    "",
    `  latency            P50 ${r.latency.p50}ms   P95 ${r.latency.p95}ms   P99 ${r.latency.p99}ms   max ${r.latency.max}ms`,
    "",
    "  by family",
  ].filter((l) => l !== "");

  const width = Math.max(...Object.keys(r.byFamily).map((k) => k.length));
  for (const [family, stats] of Object.entries(r.byFamily)) {
    const ok = stats.correct === stats.total;
    lines.push(
      `    ${ok ? "✓" : "✗"} ${family.padEnd(width)}  ${String(stats.correct).padStart(3)}/${stats.total}` +
        (stats.failures.length ? `   ${stats.failures.slice(0, 8).join(", ")}${stats.failures.length > 8 ? ` … +${stats.failures.length - 8} more` : ""}` : ""),
    );
  }

  if (r.falseNegatives.count) {
    lines.push("", "  FALSE NEGATIVES — attacks that were not stopped");
    for (const c of r.falseNegatives.cases) {
      lines.push(`    ${c.id}  ${c.name}`);
      lines.push(`          expected ${c.expected}, got ${c.actual}${c.policy ? ` by ${c.policy}` : " by default-deny"}`);
    }
  }
  if (r.falsePositives.count) {
    lines.push("", "  FALSE POSITIVES — legitimate work that was blocked");
    for (const c of r.falsePositives.cases) {
      lines.push(`    ${c.id}  ${c.name}`);
      lines.push(`          expected ${c.expected}, got ${c.actual}${c.policy ? ` by ${c.policy}` : " by default-deny"}`);
    }
  }
  if (r.detection.missed.length) {
    lines.push("", `  UNDETECTED (still blocked by policy): ${r.detection.missed.join(", ")}`);
  }

  lines.push("");
  return lines.join("\n");
}

export { ATTACKS, BENIGN_CASES, CORPUS };
