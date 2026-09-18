import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Vault } from "../src/core/vault.mjs";

test("sealed vault preserves subject bindings, revocation and consumed uses", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "cirvix-vault-persistence-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const path = join(dir, "vault.json");
  const passphrase = "local regression passphrase";
  const vault = new Vault();
  const bound = vault.issue("BOUND", "bound-test-material", { subject: "owner" });
  const revoked = vault.issue("REVOKED", "revoked-test-material");
  const limited = vault.issue("LIMITED", "limited-test-material", { maxUses: 1 });
  await vault.seal(path, passphrase);
  vault.revoke(revoked);
  assert.equal((await vault.substitute({ key: limited })).ok, true);
  await vault.seal(path, passphrase);
  const restored = new Vault();
  await restored.unseal(path, passphrase);
  assert.deepEqual(restored.inventory(), vault.inventory());
  assert.equal((await restored.substitute({ key: bound }, { subject: "other" })).outcome, "wrong_subject");
  assert.equal((await restored.substitute({ key: bound }, { subject: "owner" })).ok, true);
  assert.equal((await restored.substitute({ key: revoked })).outcome, "revoked");
  assert.equal((await restored.substitute({ key: limited })).outcome, "exhausted");
});
