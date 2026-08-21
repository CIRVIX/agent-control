/**
 * The adversarial corpus, as a test.
 *
 * The whole rule set is exercised against every attack shape on every run, and
 * the two numbers that must be perfect are asserted rather than reported:
 *
 *   zero false negatives   no attack gets through
 *   zero false positives   no legitimate call is blocked
 *   zero crashes           nothing throws instead of deciding
 *
 * Detection rate is asserted only above a floor, because it is a mitigation and
 * the corpus deliberately contains attacks it cannot see. Asserting it at 100%
 * would either be false or would require deleting the honest cases.
 */

import test from "node:test";
import assert from "node:assert/strict";

import { run, render } from "./corpus/harness.mjs";
import { CORPUS } from "./corpus/attacks.mjs";
import { STARTER_POLICY } from "../src/commands/init.mjs";

const CWD = "/workspace";

let report;

test("corpus runs", async () => {
  report = await run({ policySource: STARTER_POLICY, cwd: CWD });
  if (process.env.CIRVIX_CORPUS_REPORT) process.stdout.write(render(report));
  // A floor, and a real one: the generator produces several hundred cases, so
  // a number near this means the generator silently stopped emitting.
  assert.ok(report.total >= 400, `only ${report.total} cases`);
});

test("the corpus is both hand-written and generated", () => {
  const handwritten = CORPUS.filter((c) => !c.generated);
  const generated = CORPUS.filter((c) => c.generated);

  // The hand-written core exists so a failure is traceable to a technique
  // somebody deliberately encoded; the generated set exists so the spellings
  // nobody thought of are covered evenly. Losing either is a regression.
  assert.ok(handwritten.length >= 60, `${handwritten.length} hand-written cases`);
  assert.ok(generated.length >= 300, `${generated.length} generated cases`);
});

test("no attack gets through — false negative rate is zero", () => {
  assert.equal(
    report.falseNegatives.count,
    0,
    `attacks not stopped:\n${report.falseNegatives.cases
      .map((c) => `  ${c.id} ${c.name}: expected ${c.expected}, got ${c.actual}`)
      .join("\n")}`,
  );
});

test("no legitimate call is blocked — false positive rate is zero", () => {
  assert.equal(
    report.falsePositives.count,
    0,
    `legitimate work blocked:\n${report.falsePositives.cases
      .map((c) => `  ${c.id} ${c.name}: expected ${c.expected}, got ${c.actual}`)
      .join("\n")}`,
  );
});

test("nothing crashes — a hostile input must not take down the decision path", () => {
  assert.equal(report.crashes.count, 0);
});

test("the sanitizer sees most of what it is expected to see", () => {
  // A floor, not a target. See the harness header for why this is not 100%.
  assert.ok(
    report.detection.rate >= 0.8,
    `detection rate ${(report.detection.rate * 100).toFixed(1)}% is below the 80% floor; missed: ${report.detection.missed.join(", ")}`,
  );
});

test("every family is covered", () => {
  for (const [family, stats] of Object.entries(report.byFamily)) {
    assert.equal(stats.correct, stats.total, `${family}: ${stats.failures.join(", ")}`);
  }
});

test("the benign control group is a real control, not filler", () => {
  // A corpus of only attacks can be passed by a rule set that denies
  // everything. This asserts the control group is big enough to prevent that.
  /*
   * Measured as an absolute count and a diversity check, not as a ratio.
   *
   * The ratio was the original guard, and it stopped being the right one when
   * the attack set became a full cross-product: 10,000 spellings of the same
   * dozen attacks is one axis explored exhaustively, not ten thousand
   * independent chances to false-positive. What makes a false-positive rate
   * meaningful is that the control group is large enough to measure and covers
   * every *shape* of legitimate work — reads, writes, shell, network, database
   * — which is what these two assertions check.
   */
  assert.ok(report.benign >= 500, `only ${report.benign} benign cases`);

  const benignShapes = new Set(
    CORPUS.filter((c) => c.family === "benign").map((c) => String(c.call.tool).replace(/[._-].*$/, "")),
  );
  assert.ok(
    benignShapes.size >= 8,
    `the control group covers only ${benignShapes.size} kinds of tool: ${[...benignShapes].join(", ")}`,
  );
});

test("every case has a distinct id", () => {
  const ids = CORPUS.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length, "duplicate case ids make failures ambiguous");
});

test("decisions stay fast under adversarial input", () => {
  // Generous, because this runs on shared CI. It exists to catch a pathological
  // regression — a regex that backtracks on a crafted payload — not to publish
  // a performance number. The benchmark harness does that.
  assert.ok(report.latency.p99 < 50, `P99 ${report.latency.p99}ms`);
});
