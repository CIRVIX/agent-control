import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AuditChain, canonicalJson, hashRecord } from "../src/core/audit.mjs";

async function chainIn() {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-audit-"));
  return { dir, file: join(dir, "audit.jsonl") };
}

const TS = "2026-08-06T09:00:00.000Z";

test("canonical json is key-order independent", () => {
  assert.equal(
    canonicalJson({ b: 1, a: { d: 2, c: 3 } }),
    canonicalJson({ a: { c: 3, d: 2 }, b: 1 }),
  );
});

test("an intact chain verifies", async () => {
  const { file } = await chainIn();
  const chain = await new AuditChain(file).open();
  await chain.append({ decision: "dec_1", verdict: "permit" }, TS);
  await chain.append({ decision: "dec_2", verdict: "deny" }, TS);
  await chain.append({ decision: "dec_3", verdict: "hold" }, TS);

  const res = await chain.verify();
  assert.equal(res.ok, true);
  assert.equal(res.records, 3);
});

test("each record commits to its predecessor", async () => {
  const { file } = await chainIn();
  const chain = await new AuditChain(file).open();
  const a = await chain.append({ decision: "dec_1" }, TS);
  const b = await chain.append({ decision: "dec_2" }, TS);
  assert.equal(b.prev_hash, a.hash);
});

test("editing a record is detected, and the break is located", async () => {
  const { file } = await chainIn();
  const chain = await new AuditChain(file).open();
  await chain.append({ decision: "dec_1", verdict: "deny" }, TS);
  await chain.append({ decision: "dec_2", verdict: "deny" }, TS);
  await chain.append({ decision: "dec_3", verdict: "deny" }, TS);

  // Flip a denial to a permit — the exact tamper the chain exists to catch.
  const lines = (await readFile(file, "utf8")).trim().split("\n");
  const tampered = JSON.parse(lines[1]);
  tampered.verdict = "permit";
  lines[1] = JSON.stringify(tampered);
  await writeFile(file, lines.join("\n") + "\n");

  const res = await new AuditChain(file).verify();
  assert.equal(res.ok, false);
  assert.equal(res.brokenAt, 2);
  assert.match(res.reason, /modified/);
});

test("removing a record is detected", async () => {
  const { file } = await chainIn();
  const chain = await new AuditChain(file).open();
  await chain.append({ decision: "dec_1" }, TS);
  await chain.append({ decision: "dec_2" }, TS);
  await chain.append({ decision: "dec_3" }, TS);

  const lines = (await readFile(file, "utf8")).trim().split("\n");
  lines.splice(1, 1); // delete the middle record
  await writeFile(file, lines.join("\n") + "\n");

  const res = await new AuditChain(file).verify();
  assert.equal(res.ok, false);
  assert.match(res.reason, /altered or removed/);
});

test("re-opening continues the chain instead of forking it", async () => {
  const { file } = await chainIn();
  const first = await new AuditChain(file).open();
  await first.append({ decision: "dec_1" }, TS);

  const second = await new AuditChain(file).open();
  const r = await second.append({ decision: "dec_2" }, TS);

  assert.equal(r.seq, 2);
  const res = await second.verify();
  assert.equal(res.ok, true);
  assert.equal(res.records, 2);
});

test("identical input hashes identically", () => {
  const a = { seq: 1, ts: TS, prev_hash: "sha256:0", verdict: "permit" };
  const b = { verdict: "permit", prev_hash: "sha256:0", ts: TS, seq: 1 };
  assert.equal(hashRecord(a), hashRecord(b));
});

test("a malformed line is reported rather than silently skipped", async () => {
  const { file } = await chainIn();
  const chain = await new AuditChain(file).open();
  await chain.append({ decision: "dec_1" }, TS);
  await writeFile(file, (await readFile(file, "utf8")) + "{not json\n");

  const res = await new AuditChain(file).verify();
  assert.equal(res.ok, false);
  assert.match(res.reason, /Malformed/);
});
