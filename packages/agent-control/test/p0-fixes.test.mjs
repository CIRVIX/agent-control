import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Vault } from "../src/core/vault.mjs";
import { Guard } from "../src/core/guard.mjs";
import { Pipeline } from "../src/core/pipeline.mjs";
import { ApprovalStore } from "../src/core/approvals.mjs";
import { MissionRegistry } from "../src/core/authority.mjs";
import { buildEvidencePack, verifyEvidencePack, digestPackV1, digestPackV2, EVIDENCE_VERSION, DIGEST_FORMAT } from "../src/core/evidence.mjs";
import { verify as verifyCmd } from "../src/commands/prove.mjs";
import { AuditChain } from "../src/core/audit.mjs";

async function makeTmp() {
  const dir = await mkdtemp(join(tmpdir(), "cvx-p0-"));
  await mkdir(join(dir, ".cirvix"), { recursive: true });
  return dir;
}

test("P0-3: Vault revocation prevents handle resolution with 'revoked' outcome", async () => {
  const v = new Vault();
  const handle = v.issue("TEST_KEY", "super-secret-token-12345", {
    destinations: ["api.example.com"],
  });

  // Active handle substitutes fine
  const sub1 = await v.substitute({ Authorization: `Bearer ${handle}` }, { destination: "https://api.example.com/v1" });
  assert.equal(sub1.ok, true);
  assert.equal(sub1.value.Authorization, "Bearer super-secret-token-12345");

  // Revoke by handle
  const revoked = v.revoke(handle);
  assert.equal(revoked, true);

  // Inventory marks it revoked
  const inv = v.inventory();
  const item = inv.find((i) => i.handle === handle);
  assert.equal(item.revoked, true);
  assert.ok(item.revokedAt);

  // Substitute now fails with outcome: revoked
  const sub2 = await v.substitute({ Authorization: `Bearer ${handle}` }, { destination: "https://api.example.com/v1" });
  assert.equal(sub2.ok, false);
  assert.equal(sub2.outcome, "revoked");
  assert.match(sub2.reason, /revoked/i);
});

test("P0-3: Vault revocation by name works as expected", async () => {
  const v = new Vault();
  const handle = v.issue("STRIPE_KEY", "sk_live_1234567890123456", { destinations: ["api.stripe.com"] });
  assert.equal(v.revokeByName("STRIPE_KEY"), true);
  const sub = await v.substitute({ key: handle }, { destination: "https://api.stripe.com" });
  assert.equal(sub.ok, false);
  assert.equal(sub.outcome, "revoked");
});

test("P0-1: Guard properly requests and releases approvals using ApprovalStore", async () => {
  const tmp = await makeTmp();
  try {
    const approvals = await new ApprovalStore(join(tmp, ".cirvix", "approvals.jsonl")).open();
    const rules = [
      {
        name: "allow-db",
        effect: "permit",
        actions: ["db.write"],
        resources: ["*"],
      },
      {
        name: "hold-prod-db",
        effect: "hold",
        actions: ["db.write"],
        resources: ["*"],
        risk: "high",
        reason: "Production mutations need approval",
      },
    ];

    const guard = new Guard({
      rules,
      approvals,
    });

    // 1. First invocation generates a hold and an approval request
    const res1 = await guard.authorize({
      tool: "database.write",
      args: { id: 123, resource: "prod/users" },
    });
    assert.equal(res1.decision.verdict, "hold");
    assert.ok(res1.decision.approvalId, "approvalId must be set");

    const pending = approvals.pending();
    assert.equal(pending.length, 1);
    assert.equal(pending[0].id, res1.decision.approvalId);

    // 2. Operator approves
    await approvals.decide(res1.decision.approvalId, "approved", "lead@example.com");

    // 3. Exact replay call is permitted
    const res2 = await guard.authorize({
      tool: "database.write",
      args: { id: 123, resource: "prod/users" },
    });
    assert.equal(res2.decision.verdict, "permit");
    assert.equal(res2.decision.approvedBy, "lead@example.com");
    assert.equal(res2.decision.approvalId, res1.decision.approvalId);

    // 4. Spent approval cannot be re-spent
    const res3 = await guard.authorize({
      tool: "database.write",
      args: { id: 123, resource: "prod/users" },
    });
    assert.equal(res3.decision.verdict, "hold");
  } finally {
    await rm(tmp, { recursive: true, force: true }).catch(() => {});
  }
});

test("P0-2: Pipeline evaluates activeMission and assessAuthority, attaching authority to event", async () => {
  const tmp = await makeTmp();
  try {
    const missions = new MissionRegistry();
    const audit = await new AuditChain(join(tmp, ".cirvix", "audit.jsonl")).open();
    const m = missions.issue({
      agent: "claude",
      capabilities: [
        { actions: ["fs.read", "filesystem.read"], resources: ["*"] },
      ],
      constraints: {
        disallowedTools: ["exec_shell"],
        maxSpendUsd: 10.0,
      },
    });

    const pipe = new Pipeline({
      rules: [
        { name: "allow-read", effect: "permit", tool: "fs_read" },
        { name: "allow-exec", effect: "permit", tool: "exec_shell" },
      ],
      missions,
      mission: m.id,
      audit,
    });

    // Allowed action within mission. Identity comes from the trusted context,
    // never from the request payload — a wire-declared agent could claim
    // another agent's mission. See pipeline.test.mjs.
    // Trusted context supplies the cost; request prices are informational only.
    const res1 = await pipe.submit(
      {
        tool: "fs_read",
        arguments: { path: "logs/app.log", costUsd: 0.05 },
      },
      { agent: "claude", costUsd: 0.05 },
    );
    assert.equal(res1.decision.verdict, "permit");
    assert.ok(res1.event.authority, "Authority must be attached to event");
    assert.ok(res1.event.authority.capability, "Capability was authorized");

    // Disallowed tool in mission escapes authority
    const res2 = await pipe.submit(
      {
        tool: "exec_shell",
        arguments: { command: "bin/rm" },
      },
      { agent: "claude" },
    );
    assert.equal(res2.decision.verdict, "deny");
    assert.match(res2.decision.rule, /authority/i);
    assert.ok(res2.event.escape, "Escape must be recorded on event");

    // Escapes recorded in registry
    const escapes = missions.escapes({ missionId: m.id });
    assert.equal(escapes.length, 1);
    assert.equal(escapes[0].blocked, true);

    // Mission recorded the cost of permitted action
    const updated = missions.get(m.id);
    assert.ok(updated.usage.spendUsd > 0);
  } finally {
    await rm(tmp, { recursive: true, force: true }).catch(() => {});
  }
});

test("P0-4: Evidence pack retains authority, secrets_brokered, context, and command", () => {
  const sampleRecords = [
    {
      decision_id: "dec_1",
      ts: "2026-09-15T12:00:00.000Z",
      agent: "dev-agent",
      action: "db:read",
      tool: "query",
      resource: "prod/users",
      verdict: "permit",
      decision: "allow",
      rule: "allow-read",
      authority: { missionId: "msn_1", within_bounds: true },
      secrets_brokered: ["STRIPE_KEY"],
      context: { environment: "prod" },
      command: "SELECT 1 FROM users",
    },
  ];

  const pack = buildEvidencePack({
    records: sampleRecords,
    agent: "dev-agent",
  });

  assert.equal(pack.decisions.length, 1);
  const d = pack.decisions[0];
  assert.equal(d.authority.missionId, "msn_1");
  assert.deepEqual(d.secrets_brokered, ["STRIPE_KEY"]);
  assert.deepEqual(d.context, { environment: "prod" });
  assert.equal(d.command, "SELECT 1 FROM users");
});

test("P0-5: evidence digest formats are explicit and backward compatible", () => {
  // Current packs carry v2 and verify.
  const current = buildEvidencePack({ records: [], agent: "dev-agent" });
  assert.equal(current.v, EVIDENCE_VERSION);
  assert.equal(current.digestFormat, DIGEST_FORMAT.V2_EXPLICIT);
  const verified = verifyEvidencePack(current);
  assert.equal(verified.ok, true);
  assert.equal(verified.format, DIGEST_FORMAT.V2_EXPLICIT);

  // A legacy v1 pack (no digestFormat, v: 1, legacy digest) still verifies —
  // under its ORIGINAL format, not reinterpreted as v2.
  const legacy = { ...JSON.parse(JSON.stringify(current)), v: 1 };
  delete legacy.digestFormat;
  legacy.digest = digestPackV1(legacy);
  const legacyVerified = verifyEvidencePack(legacy);
  assert.equal(legacyVerified.ok, true);
  assert.equal(legacyVerified.format, DIGEST_FORMAT.V1_LEGACY);

  // v1 and v2 coincide for in-memory objects too, because deletion and
  // undefined-omission name the same canonical form. The explicit format still
  // matters: without it a verifier cannot tell which contract a pack was
  // built under, and a future canonicalizer change would silently reinterpret
  // history. The test proves both formats verify the same stored bytes.
  const raw = { v: 1, kind: "evidence_pack", extra: undefined, nested: { missing: undefined, kept: 1 } };
  assert.equal(digestPackV2(raw), digestPackV1(raw));
  assert.equal(digestPackV2(JSON.parse(JSON.stringify(raw))), digestPackV1(JSON.parse(JSON.stringify(raw))));

  // Tampering fails under both formats.
  const tampered = JSON.parse(JSON.stringify(current));
  tampered.summary.decisions = 999;
  assert.equal(verifyEvidencePack(tampered).ok, false);
  const tamperedLegacy = JSON.parse(JSON.stringify(legacy));
  tamperedLegacy.summary = { ...(tamperedLegacy.summary ?? {}), denied: 999 };
  assert.equal(verifyEvidencePack(tamperedLegacy).ok, false);

  // Unknown formats are refused with a version reason, not mis-hashed.
  const unknown = { ...JSON.parse(JSON.stringify(current)), digestFormat: 99 };
  const refused = verifyEvidencePack(unknown);
  assert.equal(refused.ok, false);
  assert.match(refused.reason, /unsupported evidence digest format/);
  assert.equal(verifyEvidencePack(null).ok, false);
});

test("P0-6: Verify command returns clear file_not_found error for missing proof path", async () => {
  const res = await verifyCmd({
    proof: "nonexistent_proof_file.jwt",
    json: true,
  });
  assert.equal(res.exitCode, 1);
  assert.equal(res.result.failed, "file_not_found");
  assert.match(res.result.reason, /File not found/);
});
