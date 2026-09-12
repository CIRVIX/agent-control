/**
 * Cinematic terminal runtime — contract tests.
 *
 * Everything animated is gated behind a live human TTY, and this suite
 * runs piped, so these tests pin the hermetic parts: the pure builders,
 * the gates (which must stay closed here), the no-op paths (which must
 * never write), and the spinner/phase lifecycle with an injected writer.
 * Real pixels are proven by running the binary on a terminal, not here.
 */

import test from "node:test";
import assert from "node:assert/strict";

import {
  animatedStartup,
  bannerAllowed,
  buildStartupBanner,
  CIRVIX_LOGO,
  paintLogoRow,
  runPhase,
  startSpinner,
  startupBanner,
  truecolorOn,
  ttyProgress,
} from "../src/core/cinematic.mjs";

test("banner builder carries the exact wordmark and version", () => {
  const out = buildStartupBanner({ version: "0.1.1" });
  for (const row of CIRVIX_LOGO) assert.ok(out.includes(row), `missing row: ${row.slice(0, 12)}…`);
  assert.ok(out.includes("cirvix v0.1.1"));
});

test("gates stay closed for json, gateway and demo regardless of terminal", () => {
  assert.equal(bannerAllowed({ command: "scan", json: true }), false);
  assert.equal(bannerAllowed({ command: "gateway", json: false }), false);
  assert.equal(bannerAllowed({ command: "demo", json: false }), false);
  assert.equal(startupBanner({ command: "scan", json: true }), null);
  assert.equal(startupBanner({ command: "gateway", json: false }), null);
  assert.equal(startupBanner({ command: "demo", json: false }), null);
});

test("animated startup with animated:false writes nothing", async () => {
  const writes = [];
  await animatedStartup({ write: (s) => writes.push(s), animated: false });
  assert.deepEqual(writes, []);
});

test("animated startup renders the wordmark and version", async () => {
  const writes = [];
  await animatedStartup({
    write: (s) => writes.push(s),
    version: "0.1.1",
    rulesCount: 17,
    pace: 1,
    animated: true,
  });
  const out = writes.join("");
  for (const row of CIRVIX_LOGO) assert.ok(out.includes(row));
  assert.ok(out.includes("cirvix v0.1.1"));
  assert.ok(out.includes("17 rules loaded"));
});

test("gradient stays off without a capable terminal", () => {
  assert.equal(truecolorOn(), false);
  const painted = paintLogoRow(CIRVIX_LOGO[0], 0);
  assert.ok(painted.includes(CIRVIX_LOGO[0]));
  assert.ok(!painted.includes("38;2;"));
});

test("runPhase disabled just runs the function", async () => {
  const writes = [];
  const result = await runPhase("anything", async () => 42, {
    write: (s) => writes.push(s),
    enabled: false,
  });
  assert.equal(result, 42);
  assert.deepEqual(writes, []);
});

test("runPhase enabled reports the real outcome", async () => {
  const writes = [];
  const result = await runPhase("detecting things", async () => [1, 2], {
    write: (s) => writes.push(s),
    enabled: true,
    detail: (r) => `${r.length} found`,
  });
  assert.deepEqual(result, [1, 2]);
  const out = writes.join("");
  assert.ok(out.includes("detecting things"));
  assert.ok(out.includes("2 found"));
});

test("runPhase enabled surfaces failure and rethrows", async () => {
  const writes = [];
  await assert.rejects(
    runPhase("breaking", async () => {
      throw new Error("boom");
    }, { write: (s) => writes.push(s), enabled: true }),
    /boom/,
  );
  assert.ok(writes.join("").includes("breaking"));
});

test("spinner lifecycle always terminates", () => {
  const writes = [];
  const s = startSpinner("working", { write: (x) => writes.push(x) });
  s.succeed("done");
  s.succeed("done"); // second call is a no-op, never a second line
  assert.ok(writes.join("").includes("working"));
});

test("ttyProgress disabled is a silent pass-through", () => {
  const p = ttyProgress({ enabled: false });
  const probe = p.start("anything");
  probe.succeed("x");
  probe.fail("y");
});
