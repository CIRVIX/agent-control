/**
 * P0-B — HUMAN AUTHORITY IN PRODUCTION, tested as a security property.
 *
 * The claims these tests exist to prove, in the order the exit criteria state
 * them:
 *
 *   1. an AUTHENTICATED HUMAN/ORG PRINCIPAL exists, with an identity separate
 *      from the signing keys, and a name alone issues nothing;
 *   2. authority is ISSUED through a real production path (`cirvix authority`),
 *      not constructed in a test;
 *   3. a human-issued grant reaches the REAL composition roots (Guard and
 *      Pipeline, the same objects the gateway and socket runtime build) and
 *      ACTUALLY GATES a consequential call — proven with an independent
 *      execution oracle in a separate OS process;
 *   4. missions and capabilities have production issuance paths and gate live
 *      calls: covered permits, uncovered/revoked/expired refuses;
 *   5. AUDIENCE is explicit and enforced, not implied by tenant;
 *   6. consumption (single-use, max-uses, or reusable) is durable and atomic
 *      under concurrent requests;
 *   7. the production path cannot silently downgrade to the legacy HMAC broker;
 *   8. cross-instance trust works with PUBLIC KEYS ONLY and no shared secret.
 *
 * Every row reports identity → authority → decision → EFFECT, and the effect is
 * observed from outside the process that decided (the oracle file).
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

import { Ed25519DelegationIssuer, Ed25519DelegationVerifier } from "../src/core/delegation-ed25519.mjs";
import { Guard } from "../src/core/guard.mjs";
import { Pipeline } from "../src/core/pipeline.mjs";
import { loadRoleKey, KEY_ROLE } from "../src/core/keys.mjs";
import { MissionStore } from "../src/core/authority-store.mjs";
import { signRequest } from "../src/core/identity.mjs";

const execFileAsync = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..");
const CLI = join(packageRoot, "bin", "cirvix.mjs");
const ORACLE_CHILD = join(here, "fixtures", "oracle-child.mjs");

const MOCK_SERVER = join(here, "fixtures", "mock-mcp-server.mjs");

const RULES = [
  { name: "allow-reads", effect: "permit", actions: ["fs.read"], resources: ["**"] },
  { name: "allow-egress", effect: "permit", actions: ["net.egress"], resources: ["**"] },
];
const TENANT = "acme";
const AUDIENCE = "agent:worker";

async function stateDirFor(label) {
  return mkdtemp(join(tmpdir(), `cirvix-p0b-${label}-`));
}

/**
 * A test harness must never hang. `child.once("exit")` after the child has
 * ALREADY exited never fires — which turns "the boundary crashed on startup"
 * into an unbounded wait that hides the real assertion failure. Wait for the
 * exit event whether it is still pending or already delivered, and escalate to
 * SIGKILL so a wedged child cannot hold the runner open either.
 */
async function killChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((resolve) => child.once("exit", resolve));
  try {
    child.stdin.end();
  } catch {}
  child.kill();
  const killed = await Promise.race([exited.then(() => true), new Promise((r) => setTimeout(() => r(false), 5_000))]);
  if (!killed) {
    child.kill("SIGKILL");
    await Promise.race([exited, new Promise((r) => setTimeout(r, 2_000))]);
  }
}

async function writeRules(dir, rules = RULES) {
  const path = join(dir, "rules.json");
  await writeFile(path, JSON.stringify(rules), "utf8");
  return path;
}

/**
 * Runs the CLI and returns `{ ok, data }`.
 *
 * `ok` is the EXIT CODE, because for this product the exit code is part of the
 * contract: a refused lifecycle act must not look like a successful one to a
 * script. Stdout is parsed as JSON (every call here passes --json).
 */
async function cli(args, { stateDir } = {}) {
  const argv = [CLI, ...args];
  if (stateDir) argv.push("--state", stateDir);
  argv.push("--json");
  try {
    const { stdout } = await execFileAsync(process.execPath, argv, { cwd: packageRoot });
    return { ok: true, data: JSON.parse(stdout.slice(stdout.indexOf("{")).trim()) };
  } catch (err) {
    const raw = (err.stdout ?? "").trim();
    let data = null;
    try {
      data = JSON.parse(raw.slice(raw.indexOf("{")));
    } catch {
      data = { error: "unparsed", stdout: raw, stderr: String(err.stderr ?? "").slice(0, 400) };
    }
    return { ok: false, data };
  }
}

/** An enrolled agent + an enrolled principal whose private key is on disk. */
async function bootstrap(label, { role = "owner", principalId = "dana@acme" } = {}) {
  const stateDir = await stateDirFor(label);
  const rules = await writeRules(stateDir);
  const enrolled = await cli(["enroll", "worker", "--tenant", TENANT, "--env", "prod"], { stateDir });
  assert.equal(enrolled.ok, true, "enroll should succeed: " + JSON.stringify(enrolled.data));
  const credential = enrolled.data.credentialToken;
  const identityKey = await readFile(enrolled.data.privateKeyPath, "utf8");
  const principal = await cli(
    ["authority", "principal", "enroll", "--id", principalId, "--role", role, "--tenant", TENANT, "--name", "Dana"],
    { stateDir },
  );
  assert.equal(principal.ok, true, "principal enrollment should succeed: " + JSON.stringify(principal.data));
  const keyPath = join(stateDir, `${principalId}.principal.key`);
  await writeFile(keyPath, principal.data.privateKey, "utf8");
  return { stateDir, rules, principalKey: keyPath, principalId, credential, identityKey };
}

/** Issues a root grant through the CLI, as the authenticated principal. */
async function issueGrant(bootstrapCtx, extra = []) {
  return cli(
    [
      "authority",
      "grant",
      "issue",
      "--agent",
      "worker",
      "--principal",
      bootstrapCtx.principalId,
      "--principal-key",
      bootstrapCtx.principalKey,
      "--tenant",
      TENANT,
      "--audience",
      AUDIENCE,
      "--actions",
      "fs.read",
      "--resources",
      "**",
      ...extra,
    ],
    { stateDir: bootstrapCtx.stateDir },
  );
}

function startChild({ stateDir, oracle, rules, extra = [] }) {
  const child = spawn(process.execPath, [ORACLE_CHILD, "--state", stateDir, "--oracle", oracle, "--rules", rules, ...extra], {
    cwd: packageRoot,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stderr = [];
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => stderr.push(chunk));
  const waiters = [];
  let buffer = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    let index;
    while ((index = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, index).trim();
      buffer = buffer.slice(index + 1);
      if (!line) continue;
      const message = JSON.parse(line);
      if (message.ready) continue;
      waiters.shift()?.(message);
    }
  });
  return {
    async send(call) {
      const answer = new Promise((resolve) => waiters.push(resolve));
      child.stdin.write(JSON.stringify(call) + "\n");
      return answer;
    },
    async close() {
      await killChild(child);
    },
    stderr: () => stderr.join(""),
  };
}

async function oracleLines(path) {
  try {
    return (await readFile(path, "utf8")).split("\n").filter((l) => l.trim());
  } catch {
    return [];
  }
}

/** The production boundary: authority context + required authority. */
function boundaryArgs({ stateDir, oracle, rules, extra = [] }) {
  return {
    stateDir,
    oracle,
    rules,
    extra: [
      "--agent",
      "worker",
      "--revocation",
      "--authority-context",
      "--require-authority",
      "--tenant",
      TENANT,
      "--audience",
      AUDIENCE,
      ...extra,
    ],
  };
}

const READ = { tool: "read_file", arguments: { path: "/workspace/src/app.ts" } };

/**
 * Forges a token by flipping a bit of the SIGNATURE BYTES.
 *
 * Not by editing the last base64url character: a 64-byte signature is 86
 * characters, so the final character carries only two significant bits and
 * four padding bits are discarded on decode. Swapping it for another character
 * with the same top bits leaves the signed bytes IDENTICAL — the artifact still
 * verifies, and a test that "proved" forgery was refused would have proved
 * nothing. This helper changes real bytes so the refusal is genuine.
 */
function tamperToken(token) {
  const [body, signature] = token.split(".");
  const bytes = Buffer.from(signature, "base64url");
  bytes[0] ^= 0x01;
  return `${body}.${bytes.toString("base64url")}`;
}

/* ================================================================== */
/*  1. The authenticated principal, and a name that issues nothing     */
/* ================================================================== */

test("P0-B: a principal is an identity of its own, and a NAME alone issues no authority", async () => {
  const ctx = await bootstrap("principal-model");

  // The enrolled principal carries its OWN key id, tenant, role and status —
  // the host authority key only vouches for the record.
  const shown = await cli(["authority", "principal", "show", ctx.principalId], { stateDir: ctx.stateDir });
  assert.equal(shown.ok, true);
  assert.equal(shown.data.role, "owner");
  assert.equal(shown.data.tenantId, TENANT);
  assert.equal(shown.data.computedStatus, "active");
  assert.ok(shown.data.keyId, "the principal has its own key id");
  assert.notEqual(
    shown.data.keyId,
    (await loadRoleKey(ctx.stateDir, KEY_ROLE.AUTHORITY)).keyId,
    "the principal's key is NOT the host authority key",
  );

  // Issuing without an authenticated principal is refused outright.
  const unauthenticated = await cli(
    ["authority", "grant", "issue", "--agent", "worker", "--principal", ctx.principalId, "--audience", AUDIENCE, "--tenant", TENANT],
    { stateDir: ctx.stateDir },
  );
  assert.equal(unauthenticated.ok, false, "no principal key ⇒ no grant");
  assert.equal(unauthenticated.data.error, "principal_authentication_required");

  // A name that is not enrolled cannot issue either, even with a key file.
  const strangerKey = join(ctx.stateDir, "stranger.key");
  await writeFile(strangerKey, "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n", "utf8");
  const stranger = await cli(
    ["authority", "grant", "issue", "--agent", "worker", "--principal", "nobody@acme", "--principal-key", strangerKey, "--audience", AUDIENCE, "--tenant", TENANT],
    { stateDir: ctx.stateDir },
  );
  assert.equal(stranger.ok, false);
  assert.ok(
    ["principal_unknown", "principal_key_unreadable", "principal_bad_signature"].includes(stranger.data.error),
    "an unknown principal or unreadable key is a refusal, got " + stranger.data.error,
  );

  // The CLI reports the REAL posture, including the anchors it holds.
  const doctor = await execFileAsync(process.execPath, [CLI, "doctor", "--state", ctx.stateDir, "--json"], { cwd: packageRoot });
  const report = JSON.parse(doctor.stdout.slice(doctor.stdout.indexOf("{")));
  const names = report.results.map((c) => c.name);
  for (const name of ["Trust anchors", "Human authority", "Release authority", "Mission authority", "Binding strength"]) {
    assert.ok(names.includes(name), `doctor reports "${name}"`);
  }
  const authorityRow = report.results.find((c) => c.name === "Human authority");
  assert.match(authorityRow.detail, /dana@acme \(owner\)/);
  const releaseRow = report.results.find((c) => c.name === "Release authority");
  assert.match(releaseRow.detail, /IMPOSSIBLE/, "a host with no release authority says so plainly");
});

/* ================================================================== */
/*  3. A human grant gates a live consequential call, with an oracle    */
/* ================================================================== */

test("P0-B/LIVE: an authenticated human grant gates a real call, and no grant means no effect", async () => {
  const ctx = await bootstrap("live-grant");
  const issued = await issueGrant(ctx);
  assert.equal(issued.ok, true, "grant issuance: " + JSON.stringify(issued.data));
  assert.equal(issued.data.issuerPrincipalId, ctx.principalId);
  assert.equal(issued.data.issuerRole, "owner");
  assert.equal(issued.data.audience, AUDIENCE);
  assert.equal(issued.data.tenant, TENANT);

  // Inspectable and resolvable from the CLI, the way an operator would check it.
  const listed = await cli(["authority", "grant", "list"], { stateDir: ctx.stateDir });
  assert.equal(listed.data.count, 1);
  assert.equal(listed.data.grants[0].grantId, issued.data.grantId);
  const verified = await cli(["authority", "verify", issued.data.grantId, "--agent", "worker", "--audience", AUDIENCE, "--tenant", TENANT], {
    stateDir: ctx.stateDir,
  });
  assert.equal(verified.ok, true, "the CLI agrees the chain resolves: " + JSON.stringify(verified.data));
  assert.deepEqual(verified.data.scope.actions, ["fs.read"]);

  const oracle = join(ctx.stateDir, "oracle.log");
  const child = startChild(boundaryArgs({ stateDir: ctx.stateDir, oracle, rules: ctx.rules }));
  try {
    const unsigned = await child.send({ id: "c1", ...READ, agent: "worker" });
    assert.equal(unsigned.verdict, "deny");
    assert.equal(unsigned.rule, "delegation-required", "authority is REQUIRED on this boundary");
    assert.deepEqual(await oracleLines(oracle), [], "the call did not happen");

    const signed = await child.send({ id: "c2", ...READ, agent: "worker", delegation: [issued.data.token] });
    assert.equal(signed.verdict, "permit", "the grant authorizes the call: " + JSON.stringify(signed));
    assert.equal(signed.executed, true);
    assert.equal((await oracleLines(oracle)).length, 1, "exactly one effect, observed outside the deciding process");
  } finally {
    await child.close();
  }
});

/* ================================================================== */
/*  6. Audience, tenant, subject, issuer, expiry, revocation, replay    */
/* ================================================================== */

test("P0-B/LIVE: every wrong-authority presentation is refused and NOTHING executes", async () => {
  const ctx = await bootstrap("attack-matrix");
  const grant = await issueGrant(ctx);
  const oracle = join(ctx.stateDir, "oracle.log");

  /* A second tenant and a second agent exist so "wrong tenant" and "wrong
     subject" are real refusals rather than missing-data accidents. The globex
     grant is issued by a globex PRINCIPAL: a principal can only issue into its
     own tenant, which is itself asserted below. */
  await cli(["enroll", "other", "--tenant", "globex", "--env", "prod"], { stateDir: ctx.stateDir });
  const globexPrincipal = await cli(
    ["authority", "principal", "enroll", "--id", "ivan@globex", "--role", "owner", "--tenant", "globex"],
    { stateDir: ctx.stateDir },
  );
  assert.equal(globexPrincipal.ok, true);
  const globexKey = join(ctx.stateDir, "ivan.key");
  await writeFile(globexKey, globexPrincipal.data.privateKey, "utf8");
  const otherTenantGrant = await cli(
    [
      "authority", "grant", "issue", "--agent", "worker", "--principal", "ivan@globex", "--principal-key", globexKey,
      "--tenant", "globex", "--audience", AUDIENCE, "--actions", "fs.read", "--resources", "**",
    ],
    { stateDir: ctx.stateDir },
  );
  assert.equal(otherTenantGrant.ok, true, "a globex principal may issue for globex: " + JSON.stringify(otherTenantGrant.data));
  const otherSubjectGrant = await cli(
    [
      "authority", "grant", "issue", "--agent", "other", "--principal", ctx.principalId, "--principal-key", ctx.principalKey,
      "--tenant", TENANT, "--audience", AUDIENCE, "--actions", "fs.read", "--resources", "**",
    ],
    { stateDir: ctx.stateDir },
  );
  assert.equal(otherSubjectGrant.ok, true);
  const wrongAudienceGrant = await cli(
    [
      "authority", "grant", "issue", "--agent", "worker", "--principal", ctx.principalId, "--principal-key", ctx.principalKey,
      "--tenant", TENANT, "--audience", "runtime:somewhere-else", "--actions", "fs.read", "--resources", "**",
    ],
    { stateDir: ctx.stateDir },
  );
  assert.equal(wrongAudienceGrant.ok, true);

  // An EXPIRED grant: issued with a lifetime that has already passed.
  const expiredGrant = await cli(
    [
      "authority", "grant", "issue", "--agent", "worker", "--principal", ctx.principalId, "--principal-key", ctx.principalKey,
      "--tenant", TENANT, "--audience", AUDIENCE, "--actions", "fs.read", "--resources", "**", "--ttl", "-1000",
    ],
    { stateDir: ctx.stateDir },
  );
  assert.equal(expiredGrant.ok, true, "a negative ttl is refused at issue time or issued expired: " + JSON.stringify(expiredGrant.data));

  const revokedGrant = await cli(
    [
      "authority", "grant", "issue", "--agent", "worker", "--principal", ctx.principalId, "--principal-key", ctx.principalKey,
      "--tenant", TENANT, "--audience", AUDIENCE, "--actions", "fs.read", "--resources", "**",
    ],
    { stateDir: ctx.stateDir },
  );
  assert.equal(revokedGrant.ok, true);
  const revoked = await cli(
    ["authority", "grant", "revoke", revokedGrant.data.grantId, "--principal", ctx.principalId, "--principal-key", ctx.principalKey, "--reason", "leaked"],
    { stateDir: ctx.stateDir },
  );
  assert.equal(revoked.ok, true, "revocation: " + JSON.stringify(revoked.data));

  // A grant minted under a DIFFERENT policy generation than this boundary pins.
  const stalePolicyGrant = await cli(
    [
      "authority", "grant", "issue", "--agent", "worker", "--principal", ctx.principalId, "--principal-key", ctx.principalKey,
      "--tenant", TENANT, "--audience", AUDIENCE, "--actions", "fs.read", "--resources", "**", "--policy-version", "1",
    ],
    { stateDir: ctx.stateDir },
  );
  assert.equal(stalePolicyGrant.ok, true);

  /* The control row is issued under the SAME policy generation this boundary
     pins (2), so it is a genuine control: if it failed, every other row's
     refusal would prove nothing. */
  const controlGrant = await cli(
    [
      "authority", "grant", "issue", "--agent", "worker", "--principal", ctx.principalId, "--principal-key", ctx.principalKey,
      "--tenant", TENANT, "--audience", AUDIENCE, "--actions", "fs.read", "--resources", "**", "--policy-version", "2",
    ],
    { stateDir: ctx.stateDir },
  );
  assert.equal(controlGrant.ok, true, "control grant: " + JSON.stringify(controlGrant.data));

  const forged = tamperToken(controlGrant.data.token);
  const child = startChild(
    boundaryArgs({ stateDir: ctx.stateDir, oracle, rules: ctx.rules, extra: ["--policy-version", "2"] }),
  );
  try {
    const rows = [
      ["forged signature", [forged], "deny"],
      ["wrong tenant", [otherTenantGrant.data.token], "deny"],
      ["wrong subject", [otherSubjectGrant.data.token], "deny"],
      ["wrong audience", [wrongAudienceGrant.data.token], "deny"],
      ["expired grant", [expiredGrant.data.token], "deny"],
      ["revoked grant", [revokedGrant.data.token], "deny"],
      ["stale policy version", [stalePolicyGrant.data.token], "deny"],
      ["empty chain", [], "deny"],
      ["garbage chain", ["not-a-token"], "deny"],
      ["valid grant (the control row)", [controlGrant.data.token], "permit"],
    ];
    const results = [];
    let index = 0;
    for (const [label, chain, expected] of rows) {
      index += 1;
      const result = await child.send({ id: `a${index}`, ...READ, agent: "worker", delegation: chain.length ? chain : null });
      results.push({ label, expected, got: result.verdict, rule: result.rule });
      assert.equal(result.verdict, expected, `${label}: expected ${expected}, got ${result.verdict} (${result.rule})`);
      assert.equal(result.executed, expected === "permit", `${label}: the effect must match the decision`);
    }
    assert.equal(
      (await oracleLines(oracle)).length,
      1,
      "exactly one effect across the whole matrix — the control row. Rows: " + JSON.stringify(results),
    );
  } finally {
    await child.close();
  }
});

test("P0-B/LIVE: revoking the PRINCIPAL withdraws every grant it issued", async () => {
  const ctx = await bootstrap("revoke-principal");
  const other = await bootstrap("revoke-principal-owner", { principalId: "ops@acme" });
  const grant = await issueGrant(ctx);
  const oracle = join(ctx.stateDir, "oracle.log");
  const child = startChild(boundaryArgs({ stateDir: ctx.stateDir, oracle, rules: ctx.rules }));

  try {
    const before = await child.send({ id: "p1", ...READ, agent: "worker", delegation: [grant.data.token] });
    assert.equal(before.verdict, "permit");

    /* A SECOND principal with an owner role performs the withdrawal, because
       revoking a principal is an owner act and must itself be attributable. */
    const opsKey = join(other.stateDir, "ops@acme.principal.key");
    const opsEnroll = await cli(["authority", "principal", "enroll", "--id", "ops@acme", "--role", "owner", "--tenant", TENANT], {
      stateDir: ctx.stateDir,
    });
    assert.equal(opsEnroll.ok, true, "enrolling an operator: " + JSON.stringify(opsEnroll.data));
    await writeFile(opsKey, opsEnroll.data.privateKey, "utf8");
    const revoked = await cli(
      ["authority", "principal", "revoke", ctx.principalId, "--principal", "ops@acme", "--principal-key", opsKey, "--reason", "account closed"],
      { stateDir: ctx.stateDir },
    );
    assert.equal(revoked.ok, true, "revocation must be authenticated: " + JSON.stringify(revoked.data));
    assert.equal(revoked.data.status, "revoked");

    // The grant is intact and still signed — but the human behind it is gone,
    // so the authority it carries is gone too.
    const after = await child.send({ id: "p2", ...READ, agent: "worker", delegation: [grant.data.token] });
    assert.equal(after.verdict, "deny");
    assert.equal(after.executed, false);
    assert.equal((await oracleLines(oracle)).length, 1, "only the pre-revocation call produced an effect");
  } finally {
    await child.close();
  }
});

/* ================================================================== */
/*  2, 4. Missions and capabilities, issued in production               */
/* ================================================================== */

test("P0-B/LIVE: a mission issued through the CLI gates a live call, and expiry/revocation propagate", async () => {
  const ctx = await bootstrap("missions");
  const grant = await issueGrant(ctx, [], );
  assert.equal(grant.ok, true);
  const oracle = join(ctx.stateDir, "oracle.log");

  const mission = await cli(
    [
      "authority", "mission", "create", "--agent", "worker", "--principal", ctx.principalId, "--principal-key", ctx.principalKey,
      "--tenant", TENANT, "--actions", "fs.read", "--resources", "/workspace/src/**", "--name", "src-sweep", "--ttl", "600000",
    ],
    { stateDir: ctx.stateDir },
  );
  assert.equal(mission.ok, true, "mission issuance: " + JSON.stringify(mission.data));
  assert.equal(mission.data.issuerPrincipalId, ctx.principalId);

  const child = startChild(boundaryArgs({ stateDir: ctx.stateDir, oracle, rules: ctx.rules }));
  const onGrant = (id, path) => ({ id, tool: "read_file", arguments: { path }, agent: "worker", delegation: [grant.data.token] });
  try {
    const covered = await child.send(onGrant("m1", "/workspace/src/app.ts"));
    assert.equal(covered.verdict, "permit", "covered by the capability: " + JSON.stringify(covered));
    assert.equal(covered.executed, true);

    const uncovered = await child.send(onGrant("m2", "/workspace/secrets.env"));
    assert.equal(uncovered.verdict, "deny");
    assert.equal(uncovered.rule, "authority-capability_not_granted", "outside the mission's resources");
    assert.equal(uncovered.executed, false);

    const wrongAction = await child.send({ id: "m3", tool: "http_request", arguments: { url: "https://example.com" }, agent: "worker", delegation: [grant.data.token] });
    assert.equal(wrongAction.verdict, "deny", "an action the mission grants no capability for");

    // Durable revocation of the mission: refused on the live boundary.
    const revokedMission = await cli(
      ["authority", "mission", "revoke", mission.data.missionId, "--principal", ctx.principalId, "--principal-key", ctx.principalKey, "--reason", "objective changed"],
      { stateDir: ctx.stateDir },
    );
    assert.equal(revokedMission.ok, true, JSON.stringify(revokedMission.data));
    const afterRevoke = await child.send(onGrant("m4", "/workspace/src/app.ts"));
    assert.equal(afterRevoke.verdict, "deny", "a revoked mission stops the call: " + JSON.stringify(afterRevoke));

    // Capability-level revocation inside a live mission.
    const mission2 = await cli(
      [
      "authority", "mission", "create", "--agent", "worker", "--principal", ctx.principalId, "--principal-key", ctx.principalKey,
      "--tenant", TENANT, "--actions", "fs.read", "--resources", "/workspace/src/**", "--name", "second", "--capability", "src-sweep",
    ],
    { stateDir: ctx.stateDir },
  );
  assert.equal(mission2.ok, true, JSON.stringify(mission2.data));
  const capability = await cli(
    [
      "authority", "mission", "capability", "revoke", "--mission", mission2.data.missionId, "--capability", "src-sweep",
        "--principal", ctx.principalId, "--principal-key", ctx.principalKey, "--reason", "capability withdrawn",
      ],
      { stateDir: ctx.stateDir },
    );
    assert.equal(capability.ok, true, "capability revocation: " + JSON.stringify(capability.data));
    const afterCapability = await child.send(onGrant("m5", "/workspace/src/app.ts"));
    assert.equal(afterCapability.verdict, "deny", "a revoked capability stops the call");

    assert.equal((await oracleLines(oracle)).length, 1, "only the covered call produced an effect");
  } finally {
    await child.close();
  }

  // An EXPIRED mission is refused where it is loaded, without touching disk by hand.
  const shortLived = await cli(
    [
      "authority", "mission", "create", "--agent", "worker", "--principal", ctx.principalId, "--principal-key", ctx.principalKey,
      "--tenant", TENANT, "--actions", "fs.read", "--resources", "/workspace/src/**", "--name", "ephemeral", "--ttl", "1",
    ],
    { stateDir: ctx.stateDir },
  );
  assert.equal(shortLived.ok, true);
  await new Promise((resolve) => setTimeout(resolve, 15));
  const expiredChild = startChild(boundaryArgs({ stateDir: ctx.stateDir, oracle, rules: ctx.rules }));
  try {
    const expired = await expiredChild.send(onGrant("m6", "/workspace/src/app.ts"));
    assert.equal(expired.verdict, "deny", "a mission past its expiry refuses: " + JSON.stringify(expired));
    assert.equal((await oracleLines(oracle)).length, 1);
  } finally {
    await expiredChild.close();
  }
});

/* ================================================================== */
/*  5. Consumption: single-use, max-uses, durable, atomic               */
/* ================================================================== */

test("P0-B/LIVE: consumption is bounded, durable and atomic under concurrent requests", async () => {
  const ctx = await bootstrap("consumption");
  const singleUse = await issueGrant(ctx, ["--single-use"]);
  assert.equal(singleUse.ok, true);
  const bounded = await issueGrant(ctx, ["--max-uses", "2"]);
  assert.equal(bounded.ok, true);
  const oracle = join(ctx.stateDir, "oracle.log");
  const child = startChild(boundaryArgs({ stateDir: ctx.stateDir, oracle, rules: ctx.rules }));

  try {
    /* CONCURRENT. Two calls are in flight together; exactly one may consume a
       single-use grant, and the effect proves which — a lost update here would
       show up as two lines in the oracle. */
    const [first, second] = await Promise.all([
      child.send({ id: "s1", ...READ, agent: "worker", delegation: [singleUse.data.token] }),
      child.send({ id: "s2", ...READ, agent: "worker", delegation: [singleUse.data.token] }),
    ]);
    const verdicts = [first.verdict, second.verdict].sort();
    assert.deepEqual(verdicts, ["deny", "permit"], "exactly one concurrent use of a single-use grant: " + JSON.stringify([first, second]));
    assert.equal((await oracleLines(oracle)).length, 1);

    // A process that starts AFTER the use agrees: consumption is durable.
    const fresh = startChild(boundaryArgs({ stateDir: ctx.stateDir, oracle, rules: ctx.rules }));
    try {
      const afterRestart = await fresh.send({ id: "s3", ...READ, agent: "worker", delegation: [singleUse.data.token] });
      assert.equal(afterRestart.verdict, "deny", "single-use survives a restart: " + JSON.stringify(afterRestart));
    } finally {
      await fresh.close();
    }

    // maxUses = 2: two permits, then a refusal.
    const one = await child.send({ id: "b1", ...READ, agent: "worker", delegation: [bounded.data.token] });
    const two = await child.send({ id: "b2", ...READ, agent: "worker", delegation: [bounded.data.token] });
    const three = await child.send({ id: "b3", ...READ, agent: "worker", delegation: [bounded.data.token] });
    assert.deepEqual([one.verdict, two.verdict], ["permit", "permit"]);
    assert.equal(three.verdict, "deny", "the third use of a two-use grant is refused");
    assert.equal((await oracleLines(oracle)).length, 3, "three effects: one single-use + two bounded");

    const listed = await cli(["authority", "grant", "list"], { stateDir: ctx.stateDir });
    const usesById = Object.fromEntries(listed.data.grants.map((g) => [g.grantId, g.uses]));
    assert.equal(usesById[singleUse.data.grantId], 1, "the ledger records one use for the single-use grant");
    assert.equal(usesById[bounded.data.grantId], 2, "the ledger records two uses for the bounded grant");
  } finally {
    await child.close();
  }
});

/* ================================================================== */
/*  7. No silent downgrade to the legacy HMAC broker                    */
/* ================================================================== */

test("P0-B: production cannot silently downgrade Ed25519 authority to the legacy HMAC broker", async () => {
  const ctx = await bootstrap("downgrade");
  const parsed = await readFile(CLI, "utf8");
  assert.ok(!/new DelegationBroker\(/.test(parsed), "the shipped CLI never constructs the legacy HMAC broker");
  assert.ok(/Ed25519DelegationVerifier/.test(parsed), "the shipped CLI builds the Ed25519 verifier");

  const authorityKey = await loadRoleKey(ctx.stateDir, KEY_ROLE.AUTHORITY);
  const verifier = await new Ed25519DelegationVerifier({
    stateDir: ctx.stateDir,
    authorityPublicKey: authorityKey.publicKey,
    // A single-root chain never needs the delegation key; supplying the
    // authority's public half keeps the verifier public-key-only either way.
    delegationPublicKey: authorityKey.publicKey,
    expectedTenant: TENANT,
    expectedAudience: AUDIENCE,
    requireIssuerPrincipal: true,
  }).init();
  // A verifier given public keys holds no private key material at all — no
  // shared symmetric secret exists on the verifying side.
  assert.equal(verifier.delegation?.privateKey, undefined, "the verifier holds no delegation private key");
  assert.equal(verifier.authority?.privateKey, undefined, "the verifier holds no authority private key");

  // An HMAC-minted token is not accepted by the Ed25519 verifier, and a chain
  // presented to a boundary with NO verifier is refused rather than ignored.
  const hmacShaped = Buffer.from(JSON.stringify({ id: "dlg_legacy", issuer: "human", subject: "worker" }), "utf8").toString("base64url") + ".AAAA";
  const resolved = await verifier.resolve([hmacShaped], "worker");
  assert.equal(resolved.ok, false, "a legacy HMAC artifact does not resolve as a grant");

  const oracle = join(ctx.stateDir, "oracle.log");
  const rules = ctx.rules;
  const guard = new Guard({ rules, agent: "worker", cwd: "/workspace", requireDelegation: true });
  const unverifiable = await guard.authorize({ tool: "read_file", args: { path: "/workspace/a.ts" }, delegation: [hmacShaped] });
  assert.equal(unverifiable.decision.verdict, "deny", "authority presented without a verifier is refused");
  assert.equal(unverifiable.decision.rule, "delegation-unverifiable");

  // The same chain on the SOCKET path (a Pipeline) is refused on its own
  // terms: delegation arrives as trusted transport context, never as a field in
  // the untrusted payload.
  const pipeline = new Pipeline({ rules, agent: "worker", cwd: "/workspace", delegation: verifier });
  const viaPipeline = await pipeline.submit(
    { tool: "read_file", args: { path: "/workspace/a.ts" } },
    { delegation: [hmacShaped], agent: "worker", session: "s1" },
  );
  assert.equal(viaPipeline.decision.verdict, "deny", "the socket path refuses an unverifiable chain");
  assert.match(String(viaPipeline.decision.rule), /^delegation-/);
  assert.equal((await oracleLines(oracle)).length, 0);
});

/* ================================================================== */
/*  8. Cross-instance trust with public keys only                       */
/* ================================================================== */

test("P0-B/LIVE: instance B enforces authority issued by instance A, with public keys only", async () => {
  const issuerSide = await bootstrap("cross-a");
  const grant = await issueGrant(issuerSide);
  assert.equal(grant.ok, true);

  /* Instance B: its own state directory and its own revocation journal, but the
     ISSUING instance's public keys and nothing else from A. */
  const verifierSide = await stateDirFor("cross-b");
  const verifierRules = await writeRules(verifierSide);
  const authorityKey = await loadRoleKey(issuerSide.stateDir, KEY_ROLE.AUTHORITY);
  const delegationKey = await loadRoleKey(issuerSide.stateDir, KEY_ROLE.DELEGATION);
  const authorityPubPath = join(verifierSide, "authority.pub.pem");
  const delegationPubPath = join(verifierSide, "delegation.pub.pem");
  await writeFile(authorityPubPath, authorityKey.publicKey, "utf8");
  await writeFile(delegationPubPath, delegationKey.publicKey, "utf8");

  const oracle = join(verifierSide, "oracle.log");
  const child = startChild({
    stateDir: verifierSide,
    oracle,
    rules: verifierRules,
    extra: [
      "--agent", "worker", "--authority-context", "--require-authority", "--tenant", TENANT, "--audience", AUDIENCE,
      "--authority-public-key", authorityPubPath, "--delegation-public-key", delegationPubPath,
    ],
  });
  const call = (id, delegation) => ({ id, ...READ, agent: "worker", delegation });

  try {
    const valid = await child.send(call("x1", [grant.data.token]));
    assert.equal(valid.verdict, "permit", "B trusts A's authority: " + JSON.stringify(valid));
    assert.equal(valid.executed, true);

    const rows = [
      ["modified grant", [tamperToken(grant.data.token)]],
      ["modified envelope-shaped token", [tamperToken(grant.data.token)]],
      ["chain from an unknown issuer", [hmacShapedToken()]],
    ];
    const audienceMismatch = startChild({
      stateDir: verifierSide, oracle, rules: verifierRules,
      extra: [
        "--agent", "worker", "--authority-context", "--require-authority", "--tenant", TENANT, "--audience", "runtime:elsewhere",
        "--authority-public-key", authorityPubPath, "--delegation-public-key", delegationPubPath,
      ],
    });
    try {
      const wrongAudience = await audienceMismatch.send(call("x2", [grant.data.token]));
      assert.equal(wrongAudience.verdict, "deny", "a grant for another audience is refused at B");
      assert.equal(wrongAudience.executed, false);
    } finally {
      await audienceMismatch.close();
    }

    for (const [label, chain] of rows) {
      const result = await child.send(call(`x-${label.replace(/\W/g, "")}`, chain));
      assert.equal(result.verdict, "deny", `${label}: ${JSON.stringify(result)}`);
      assert.equal(result.executed, false);
    }

    assert.equal((await oracleLines(oracle)).length, 1, "only the valid cross-instance call had an effect");
  } finally {
    await child.close();
  }
});

function hmacShapedToken() {
  return Buffer.from(
    JSON.stringify({ id: "dlg_legacy", issuer: "human", subject: "worker", scope: { actions: ["*"], resources: ["**"] } }),
    "utf8",
  ).toString("base64url") + ".AAAA";
}

/* ================================================================== */
/*  5. Missions are durable state, not process memory                   */
/* ================================================================== */

test("P0-B: mission and capability records are durable, host-signed and tenant-bound", async () => {
  const ctx = await bootstrap("mission-durability");
  const mission = await cli(
    [
      "authority", "mission", "create", "--agent", "worker", "--principal", ctx.principalId, "--principal-key", ctx.principalKey,
      "--tenant", TENANT, "--actions", "fs.read", "--resources", "/workspace/src/**", "--ttl", "600000",
    ],
    { stateDir: ctx.stateDir },
  );
  assert.equal(mission.ok, true);

  // A fresh MissionStore in a NEW process is the authority source: nothing is
  // carried in memory between them.
  const store = new MissionStore(ctx.stateDir);
  const authorityKey = await loadRoleKey(ctx.stateDir, KEY_ROLE.AUTHORITY);
  const record = await store.get(mission.data.missionId);
  assert.ok(record, "the record exists on disk");
  assert.equal(store.verify(record, authorityKey.publicKey).ok, true, "the record is signed by the host authority key");
  assert.equal(record.issuerPrincipalId, ctx.principalId, "the principal that issued it is inside the signed payload");

  // An edited record is not authority.
  const tampered = { ...record, agent: "attacker" };
  const verdict = store.verify(tampered, authorityKey.publicKey);
  assert.equal(verdict.ok, false, "an edited mission does not verify");

  // Another tenant's boundary never even loads it.
  const otherTenant = await store.registry({ tenantId: "someone-else", authorityPublicKey: authorityKey.publicKey });
  assert.equal(otherTenant.forAgent("worker"), null, "no cross-tenant authority");

  const mine = await store.registry({ tenantId: TENANT, authorityPublicKey: authorityKey.publicKey });
  assert.ok(mine.forAgent("worker"), "the owning tenant loads it");

  // A registry built with a DIFFERENT authority key refuses to load it.
  const otherAuthority = await new Ed25519DelegationIssuer({ stateDir: await stateDirFor("other-issuer") }).init();
  const foreign = await store.registry({ tenantId: TENANT, authorityPublicKey: otherAuthority.authority.publicKey });
  assert.equal(foreign.forAgent("worker"), null, "a record that does not verify is not loaded as authority");
  assert.equal(foreign.rejected.length, 1);
});

test("P0-B: a second authenticated principal cannot be impersonated, and its authority is scoped to its tenant", async () => {
  const ctx = await bootstrap("principal-scope");
  const other = await cli(["authority", "principal", "enroll", "--id", "mallory@globex", "--role", "owner", "--tenant", "globex"], {
    stateDir: ctx.stateDir,
  });
  assert.equal(other.ok, true);
  const malloryKey = join(ctx.stateDir, "mallory.key");
  await writeFile(malloryKey, other.data.privateKey, "utf8");

  // Mallory is a real principal, but her act is bound to her own tenant: a
  // grant for dana's tenant is refused because the TENANT in the challenge
  // action and the principal's record disagree.
  const crossTenant = await cli(
    [
      "authority", "grant", "issue", "--agent", "worker", "--principal", "mallory@globex", "--principal-key", malloryKey,
      "--tenant", TENANT, "--audience", AUDIENCE, "--actions", "fs.read", "--resources", "**",
    ],
    { stateDir: ctx.stateDir },
  );
  assert.equal(crossTenant.ok, false, "a principal cannot issue into another tenant");
  assert.equal(crossTenant.data.error, "principal_tenant");

  // Mallory's signature does not authenticate DANA's principal id.
  const impersonation = await cli(
    [
      "authority", "grant", "issue", "--agent", "worker", "--principal", ctx.principalId, "--principal-key", malloryKey,
      "--tenant", TENANT, "--audience", AUDIENCE, "--actions", "fs.read", "--resources", "**",
    ],
    { stateDir: ctx.stateDir },
  );
  assert.equal(impersonation.ok, false, "possession of one key never authenticates another principal");
  assert.equal(impersonation.data.error, "principal_bad_signature");
});

/* ================================================================== */
/*  3'. The SHIPPED gateway, spawned as a process                       */
/* ================================================================== */

/**
 * Drives the real `cirvix gateway` over stdio.
 *
 * The gateway is spawned as a CHILD PROCESS, not constructed in-process: this
 * is the artifact an operator runs, with the flags the CLI documents, talking
 * JSON-RPC ndjson on stdout. The effect is observed in the mock MCP server's
 * access log, which is written before it opens anything.
 */
function startCliGateway({ stateDir, workspace, serversFile, policyPath, extra = [] }) {
  const child = spawn(
    process.execPath,
    [
      CLI, "gateway", "--servers", serversFile, "--state", stateDir, "--policy", policyPath,
      "--agent", "worker", "--tenant", TENANT, "--audience", AUDIENCE, ...extra,
    ],
    { cwd: workspace, stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, CIRVIX_IDENTITY_MODE: "production" } },
  );
  const pending = new Map();
  const diagnostics = [];
  let buffer = "";
  let nextId = 1;
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffer += chunk;
    let index;
    while ((index = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, index).trim();
      buffer = buffer.slice(index + 1);
      if (!line) continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        continue;
      }
      const resolve = pending.get(message.id);
      if (resolve) {
        pending.delete(message.id);
        resolve(message);
      }
    }
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => diagnostics.push(chunk));

  return {
    async request(method, params = {}, timeoutMs = 15_000) {
      const id = nextId++;
      const answer = new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`timed out on ${method}: ${diagnostics.join("")}`)), timeoutMs);
        pending.set(id, (message) => {
          clearTimeout(timer);
          resolve(message);
        });
      });
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
      return answer;
    },
    notify(method, params = {}) {
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
    },
    async close() {
      await killChild(child);
    },
    diagnostics: () => diagnostics.join(""),
  };
}

test("P0-B/LIVE: the SHIPPED `cirvix gateway` refuses a call with no human authority and executes the one that has it", async () => {
  const ctx = await bootstrap("cli-gateway");
  const grant = await issueGrant(ctx);
  assert.equal(grant.ok, true, "grant issuance: " + JSON.stringify(grant.data));

  // A workspace the policy permits reading, and a policy written the way a
  // user writes one.
  const workspace = join(ctx.stateDir, "workspace");
  await mkdir(join(workspace, "src"), { recursive: true });
  await writeFile(join(workspace, "src", "app.ts"), "export const answer = 42;\n", "utf8");
  const policyPath = join(workspace, "cirvix.policy");
  await writeFile(policyPath, "allow:\n  name = allow-workspace-read\n  tool = filesystem.read\n  workspace = true\n", "utf8");

  const accessLog = join(ctx.stateDir, "access.jsonl");
  await writeFile(accessLog, "", "utf8");
  const serversFile = join(ctx.stateDir, "servers.json");
  await writeFile(
    serversFile,
    JSON.stringify({
      mcpServers: {
        files: {
          command: process.execPath,
          args: [MOCK_SERVER],
          env: { CIRVIX_TEST_SERVER_NAME: "files", CIRVIX_TEST_ACCESS_LOG: accessLog },
        },
      },
    }),
    "utf8",
  );

  /* The caller signs the EXACT params it sends, and presents the credential
     next to the proof: the credential names the agent, the signature proves
     possession, and neither half alone verifies. */
  const signed = (params, delegation) => {
    const proof = signRequest({ privateKey: ctx.identityKey, agentId: "worker", method: "tools/call", params });
    return {
      ...params,
      _meta: { cirvix: { credential: ctx.credential, ...proof, ...(delegation ? { delegation } : {}) } },
    };
  };

  const gateway = startCliGateway({ stateDir: ctx.stateDir, workspace, serversFile, policyPath, extra: ["--require-authority"] });
  try {
    await gateway.request("initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "p0b-test", version: "1.0.0" },
    });
    gateway.notify("notifications/initialized");

    const path = `${workspace}/src/app.ts`;

    // 1. Verified identity, NO human authority: the shipped gateway refuses.
    const noAuthority = await gateway.request("tools/call", signed({ name: "files__read_file", arguments: { path } }));
    assert.equal(noAuthority.result?.isError, true, "no authority ⇒ refusal: " + JSON.stringify(noAuthority));
    assert.equal(noAuthority.result?._meta?.["cirvix/rule"], "delegation-required");
    assert.deepEqual(await oracleLines(accessLog), [], "the upstream server was never asked to read anything");

    // 2. The same call WITH the principal's grant: executed for real.
    const allowed = await gateway.request(
      "tools/call",
      signed({ name: "files__read_file", arguments: { path } }, [grant.data.token]),
    );
    assert.ok(!allowed.result?.isError, "a human-issued grant authorizes the call: " + JSON.stringify(allowed));
    assert.match(JSON.stringify(allowed.result?.content ?? []), /export const answer = 42/);
    const log = await oracleLines(accessLog);
    assert.equal(log.length, 1, "the upstream server read the file exactly once");

    // 3. A grant issued for another AUDIENCE is refused by the shipped gateway.
    const elsewhere = await cli(
      [
        "authority", "grant", "issue", "--agent", "worker", "--principal", ctx.principalId, "--principal-key", ctx.principalKey,
        "--tenant", TENANT, "--audience", "runtime:elsewhere", "--actions", "fs.read", "--resources", "**",
      ],
      { stateDir: ctx.stateDir },
    );
    assert.equal(elsewhere.ok, true);
    const wrongAudience = await gateway.request(
      "tools/call",
      signed({ name: "files__read_file", arguments: { path } }, [elsewhere.data.token]),
    );
    assert.equal(wrongAudience.result?.isError, true, "a grant for another audience is refused");
    assert.equal((await oracleLines(accessLog)).length, 1, "still exactly one effect");
  } finally {
    await gateway.close();
  }
});

/* ================================================================== */
/*  An issued grant survives a process restart                          */
/* ================================================================== */

test("P0-B: an issued grant and its revocations survive a restart of the enforcing process", async () => {
  const ctx = await bootstrap("restart");
  const grant = await issueGrant(ctx);
  const oracle = join(ctx.stateDir, "oracle.log");

  const first = startChild(boundaryArgs({ stateDir: ctx.stateDir, oracle, rules: ctx.rules }));
  try {
    const ok = await first.send({ id: "r1", ...READ, agent: "worker", delegation: [grant.data.token] });
    assert.equal(ok.verdict, "permit");
  } finally {
    await first.close();
  }

  await cli(
    ["authority", "grant", "revoke", grant.data.grantId, "--principal", ctx.principalId, "--principal-key", ctx.principalKey, "--reason", "rotated"],
    { stateDir: ctx.stateDir },
  );

  const second = startChild(boundaryArgs({ stateDir: ctx.stateDir, oracle, rules: ctx.rules }));
  try {
    const after = await second.send({ id: "r2", ...READ, agent: "worker", delegation: [grant.data.token] });
    assert.equal(after.verdict, "deny", "the revocation outlived the process that made it");
    assert.equal(after.executed, false);
    assert.equal((await oracleLines(oracle)).length, 1);
  } finally {
    await second.close();
  }
});
