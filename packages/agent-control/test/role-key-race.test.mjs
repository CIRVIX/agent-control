/**
 * A ROLE KEY IS A TRUST ANCHOR, AND CREATING ONE IS EXCLUSIVE.
 *
 * `ensureRoleKey` used to be a check-then-act: load, find nothing, generate,
 * write. Two processes starting together therefore each minted a different key
 * for the same role and the last write won — which is not a cosmetic loss. The
 * loser's key no longer exists anywhere, so every event it signed becomes
 * UNVERIFIABLE: `cirvix kill` run twice at once wrote a revocation that no
 * verifier could ever accept, and the enforcing engine fail-closed against its
 * own journal. The synchronization test that caught it is
 * `test/revocation.test.mjs` ("two processes killing at once…"); this file pins
 * the property directly, without a subprocess.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ensureRoleKey, loadRoleKey, roleKeyPath, KEY_ROLE, KEY_ROLES } from "../src/core/keys.mjs";

async function stateDir(label) {
  return mkdtemp(join(tmpdir(), `cirvix-rolekey-${label}-`));
}

test("concurrent assurance of one role yields ONE key, and every caller gets it", async () => {
  const dir = await stateDir("concurrent");
  try {
    const records = await Promise.all(
      Array.from({ length: 12 }, () => ensureRoleKey(dir, KEY_ROLE.REVOCATION)),
    );
    const keyIds = new Set(records.map((r) => r.keyId));
    assert.equal(keyIds.size, 1, `12 callers minted ${keyIds.size} different revocation keys`);

    const onDisk = await loadRoleKey(dir, KEY_ROLE.REVOCATION);
    assert.equal(onDisk.keyId, records[0].keyId, "the file holds the key every caller received");
    assert.equal(onDisk.privateKey, records[0].privateKey);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("an existing role key is adopted, never replaced", async () => {
  const dir = await stateDir("existing");
  try {
    const first = await ensureRoleKey(dir, KEY_ROLE.AUTHORITY);
    const [again, andAgain] = await Promise.all([
      ensureRoleKey(dir, KEY_ROLE.AUTHORITY),
      ensureRoleKey(dir, KEY_ROLE.AUTHORITY),
    ]);
    assert.equal(again.keyId, first.keyId, "the host's authority key never changes underneath its verifiers");
    assert.equal(andAgain.privateKey, first.privateKey);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a process that loses the claim adopts the winner instead of overwriting it", async () => {
  const dir = await stateDir("adopt");
  try {
    /* Stand in for the winner: a key already on disk when this caller starts,
       which is exactly the state the loser sees after its EEXIST. */
    const winner = await ensureRoleKey(dir, KEY_ROLE.RECEIPT);
    const adopted = await ensureRoleKey(dir, KEY_ROLE.RECEIPT);
    assert.deepEqual(adopted, winner);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a half-written key is waited for, not reported as corruption", async () => {
  const dir = await stateDir("partial");
  try {
    await mkdir(join(dir, "keys"), { recursive: true });
    const path = roleKeyPath(dir, KEY_ROLE.POLICY);
    /* The winner has claimed the file and not finished writing it. */
    await writeFile(path, "", "utf8");
    const finishing = (async () => {
      await new Promise((r) => setTimeout(r, 30));
      const full = await ensureRoleKey(await stateDir("writer"), KEY_ROLE.POLICY);
      await writeFile(path, JSON.stringify(full, null, 2), "utf8");
      return full;
    })();
    const ensured = await ensureRoleKey(dir, KEY_ROLE.POLICY);
    const written = await finishing;
    assert.equal(ensured.keyId, written.keyId, "the adopting process returned the winner's key");
    assert.equal((await readFile(path, "utf8")).includes(written.keyId), true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("every role has its own file, and only the enumerated roles exist", async () => {
  const dir = await stateDir("roles");
  try {
    const seen = new Set();
    for (const role of KEY_ROLES) {
      const record = await ensureRoleKey(dir, role);
      assert.equal(record.role, role);
      assert.equal(seen.has(record.keyId), false, `role ${role} reused another role's key`);
      seen.add(record.keyId);
    }
    await assert.rejects(() => ensureRoleKey(dir, "not-a-role"), /Unknown key role/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
