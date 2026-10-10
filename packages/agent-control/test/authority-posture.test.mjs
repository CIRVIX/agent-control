/**
 * THE AUTHORITY POSTURE IS DERIVED, NOT ASSUMED (P0-D exit-gate criterion 9).
 *
 * `--require-authority` used to be the only way a shipped boundary required
 * signed human authority; a host with a delegation verifier and registered
 * principals that never passed the flag was decided by policy alone. Now the
 * posture is derived once (core/authority-posture.mjs) from what the host has:
 * an explicit flag wins, an authority model makes REQUIRED the hardened
 * default, and policy-only survives only as an explicit compatibility
 * selection — visible in doctor and status, never a silent fallback.
 *
 * The attack the derivation closes: a downgrade-by-omission, where an operator
 * who set up principals and grants but never passed a flag gets policy-only
 * enforcement, and an attacker routes around every signature by simply not
 * presenting one.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { resolveAuthorityPosture } from "../src/core/authority-posture.mjs";
import { describeAuthorityPosture } from "../src/core/authority-posture.mjs";
import { PrincipalStore } from "../src/core/principal.mjs";
import { ensureRoleKey, KEY_ROLE } from "../src/core/keys.mjs";

const CLI = fileURLToPath(new URL("../bin/cirvix.mjs", import.meta.url));
const HERE = dirname(fileURLToPath(import.meta.url));

/** A store with at least one registered principal — "an authority model". */
async function storeWithPrincipal(stateDir) {
  const store = new PrincipalStore(stateDir);
  const authority = await ensureRoleKey(stateDir, KEY_ROLE.AUTHORITY);
  await store.enroll({ principalId: "principal-human", authority });
  return store;
}

/* ------------------------------------------------------------------ */
/*  The derivation matrix                                              */
/* ------------------------------------------------------------------ */

test("a host with NO authority model defaults to policy-only, and says it is compatibility", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-posture-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  const posture = await resolveAuthorityPosture({ principalStore: new PrincipalStore(state) });
  assert.equal(posture.required, false);
  assert.equal(posture.hasAuthorityModel, false);
  assert.match(posture.source, /compatibility default/);
  assert.ok(posture.note, "an unexplained compatibility posture is the thing this gate forbids");
});

test("a host WITH an authority model defaults to REQUIRED — the hardened default", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-posture-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  const store = await storeWithPrincipal(state);
  const posture = await resolveAuthorityPosture({ principalStore: store });
  assert.equal(posture.required, true);
  assert.equal(posture.hasAuthorityModel, true);
  assert.match(posture.source, /hardened default/);
});

test("an explicit --authority-policy=required wins, even with no authority model", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-posture-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  const posture = await resolveAuthorityPosture({
    authorityPolicy: "required",
    principalStore: new PrincipalStore(state),
  });
  assert.equal(posture.required, true);
  assert.match(posture.source, /--authority-policy=required/);
});

test("an explicit --authority-policy=policy-only wins over the hardened default — and is labelled compatibility", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-posture-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  const store = await storeWithPrincipal(state);
  const posture = await resolveAuthorityPosture({ authorityPolicy: "policy-only", principalStore: store });
  assert.equal(posture.required, false);
  assert.equal(posture.hasAuthorityModel, true, "the host COULD require authority — it chose not to");
  assert.match(posture.source, /explicit compatibility/);
});

test("--require-authority still selects REQUIRED", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-posture-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  const posture = await resolveAuthorityPosture({
    requireAuthority: true,
    principalStore: new PrincipalStore(state),
  });
  assert.equal(posture.required, true);
  assert.match(posture.source, /--require-authority/);
});

test("an unrecognized --authority-policy value is rejected, not ignored", async (t) => {
  await assert.rejects(
    () => resolveAuthorityPosture({ authorityPolicy: "opne" }),
    /must be "required" or "policy-only"/,
  );
});

test("the statement names the source, so the operator can tell a choice from a default", () => {
  const required = describeAuthorityPosture({ required: true, source: "--require-authority" });
  assert.match(required, /REQUIRED/);
  assert.match(required, /--require-authority/);
  const compat = describeAuthorityPosture({ required: false, source: "compatibility default (no authority model configured)" });
  assert.match(compat, /POLICY-ONLY/);
  assert.match(compat, /compatibility/);
});

/* ------------------------------------------------------------------ */
/*  The shipped composition roots honour the derivation                */
/* ------------------------------------------------------------------ */

/**
 * The shipped `cirvix runtime` is started as a real process — the first test
 * anywhere that does — and the startup line it prints is the evidence that the
 * derived posture is in force. stderr is where every startup statement goes.
 */
function startCliRuntime({ stateDir, policyPath, extra = [] }) {
  const child = spawn(
    process.execPath,
    [CLI, "runtime", "--state", stateDir, "--policy", policyPath, ...extra],
    { stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, NO_COLOR: "1" } },
  );
  const diagnostics = [];
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => diagnostics.push(chunk));
  const exited = new Promise((resolve) => child.once("exit", (code) => resolve(code)));
  return {
    child,
    exited,
    diagnostics: () => diagnostics.join(""),
    async close() {
      child.kill();
      await Promise.race([exited, new Promise((r) => setTimeout(r, 5000))]);
    },
  };
}

async function writePolicy(dir) {
  const policyPath = join(dir, "cirvix.policy");
  /* The block syntax the policy parser actually accepts (same fixture shape
     the P0-B suite writes). */
  await writeFile(
    policyPath,
    "allow:\n  name = allow-workspace-read\n  tool = filesystem.read\n  workspace = true\n",
    "utf8",
  );
  return policyPath;
}

test("P0-D/LIVE: the SHIPPED `cirvix runtime` derives REQUIRED when this host has an authority model", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-rt-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  await storeWithPrincipal(state);
  const policyPath = await writePolicy(state);

  const rt = startCliRuntime({ stateDir: state, policyPath });
  t.after(() => rt.close());
  /* Wait for the posture statement (or failure) instead of sleeping. */
  await new Promise((resolve, reject) => {
    const started = Date.now();
    const poll = setInterval(() => {
      const out = rt.diagnostics();
      if (/authority posture = /.test(out)) { clearInterval(poll); resolve(); }
      if (rt.child.exitCode !== null || rt.child.signalCode !== null) { clearInterval(poll); reject(new Error(`runtime exited: ${out}`)); }
      if (Date.now() - started > 20000) { clearInterval(poll); reject(new Error(`no posture statement within 20s: ${out}`)); }
    }, 100);
  }).catch((err) => assert.fail(`${err.message}`));

  const out = rt.diagnostics();
  assert.match(out, /authority posture = REQUIRED/);
  assert.match(out, /hardened default/);
  await rt.close();
  assert.ok(true);
});

test("P0-D/LIVE: the SHIPPED `cirvix runtime` stays policy-only only when nothing can issue a grant, and says so", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-rt-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  const policyPath = await writePolicy(state);

  const rt = startCliRuntime({ stateDir: state, policyPath });
  t.after(() => rt.close());
  await new Promise((resolve, reject) => {
    const started = Date.now();
    const poll = setInterval(() => {
      const out = rt.diagnostics();
      if (/authority posture = /.test(out)) { clearInterval(poll); resolve(); }
      if (rt.child.exitCode !== null || rt.child.signalCode !== null) { clearInterval(poll); reject(new Error(`runtime exited: ${out}`)); }
      if (Date.now() - started > 20000) { clearInterval(poll); reject(new Error(`no posture statement within 20s: ${out}`)); }
    }, 100);
  }).catch((err) => assert.fail(`${err.message}`));

  const out = rt.diagnostics();
  assert.match(out, /authority posture = POLICY-ONLY/);
  assert.match(out, /compatibility/);
  await rt.close();
});

test("P0-D/LIVE: the shipped runtime honours --authority-policy=policy-only as an explicit compatibility selection", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-rt-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  await storeWithPrincipal(state);
  const policyPath = await writePolicy(state);

  const rt = startCliRuntime({ stateDir: state, policyPath, extra: ["--authority-policy", "policy-only"] });
  t.after(() => rt.close());
  await new Promise((resolve, reject) => {
    const started = Date.now();
    const poll = setInterval(() => {
      const out = rt.diagnostics();
      if (/authority posture = /.test(out)) { clearInterval(poll); resolve(); }
      if (rt.child.exitCode !== null || rt.child.signalCode !== null) { clearInterval(poll); reject(new Error(`runtime exited: ${out}`)); }
      if (Date.now() - started > 20000) { clearInterval(poll); reject(new Error(`no posture statement within 20s: ${out}`)); }
    }, 100);
  }).catch((err) => assert.fail(`${err.message}`));

  const out = rt.diagnostics();
  assert.match(out, /POLICY-ONLY/);
  assert.match(out, /explicit compatibility/);
  await rt.close();
});

/* ------------------------------------------------------------------ */
/*  doctor reports the derived posture                                 */
/* ------------------------------------------------------------------ */

test("doctor reports the derived authority posture, not a flag echo", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "cirvix-doctor-"));
  t.after(() => rm(state, { recursive: true, force: true }));
  await mkdir(state, { recursive: true });
  await storeWithPrincipal(state);
  const policyPath = await writePolicy(state);

  /* Run the SHIPPED command — `doctor --json` prints its report to stdout (and
     exits 1 when it has warnings), so the report is read from the process. */
  const { spawnSync } = await import("node:child_process");
  const run = spawnSync(process.execPath, [CLI, "doctor", "--json", "--state", state, "--policy", policyPath], {
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
    timeout: 60000,
  });
  const jsonStart = run.stdout.indexOf("{");
  assert.ok(jsonStart !== -1, `no JSON report on stdout (exit ${run.status}): ${run.stderr.slice(0, 400)}`);
  const report = JSON.parse(run.stdout.slice(jsonStart));
  const core = (report.results ?? []).find((row) => row.name === "Authorization core");
  assert.ok(core, `no "Authorization core" row in: ${JSON.stringify((report.results ?? []).map((r) => r.name))}`);
  const text = JSON.stringify(core);
  assert.match(text, /REQUIRED/);
  assert.match(text, /hardened default/);
});
