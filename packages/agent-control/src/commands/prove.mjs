/**
 * `cirvix prove <decision-id>` and `cirvix verify <proof>`.
 *
 * prove  — finds the decision in the local audit chain, takes the segment that
 *          covers it, and signs it.
 * verify — checks a proof offline. No network, and no Cirvix.
 *
 * THE KEY. A workspace signs with a key it generates on first use and keeps in
 * `.cirvix/proof-key.json` at 0600. That file is the whole security of a local
 * proof, which is exactly why `verify` refuses to describe a locally-signed
 * artifact as independent evidence: the holder of that key could sign a
 * doctored history just as easily as a true one.
 *
 * The private half is never printed, never included in a proof, and never
 * leaves the machine. Only the public half and the key id travel.
 */

import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";

import { AuditChain } from "../core/audit.mjs";
import { buildProof, verifyProof, generateProofKeys, keyIdFor } from "../core/proof.mjs";
import { bold, dim, green, red, amber, gray } from "../core/format.mjs";
import { panel } from "../core/ui/primitives.mjs";

const KEY_FILE = "proof-key.json";

/**
 * Loads this workspace's signing key, generating one on first use.
 *
 * 0600 because the file is the only thing standing between "this proof came
 * from here" and "anyone who read the repo can mint one". chmod is
 * best-effort: on Windows it is close to a no-op, which is a real limitation
 * and is stated rather than hidden.
 */
export async function loadOrCreateKey(stateDir) {
  const path = join(stateDir, KEY_FILE);
  try {
    const existing = JSON.parse(await readFile(path, "utf8"));
    if (existing.privateKey && existing.publicKey) return { ...existing, created: false, path };
  } catch {
    /* absent or unreadable — generate below */
  }
  await mkdir(stateDir, { recursive: true });
  const keys = generateProofKeys();
  await writeFile(path, JSON.stringify(keys, null, 2), "utf8");
  await chmod(path, 0o600).catch(() => {});
  return { ...keys, created: true, path };
}

/**
 * The segment a proof covers.
 *
 * Everything from the start of the chain up to and including the decision,
 * because a link is only checkable against the record before it. Taking the
 * single record would produce an artifact that proves the record hashes to
 * itself and nothing about where it sits.
 */
function segmentFor(records, decisionId) {
  const index = records.findIndex((r) => r.decision_id === decisionId || r.decisionId === decisionId);
  if (index === -1) return null;
  return records.slice(0, index + 1);
}

export async function prove({
  decisionId,
  cwd = process.cwd(),
  stateDir = join(cwd, ".cirvix"),
  policy = null,
  json = false,
  out = null,
  write = (s) => process.stdout.write(s),
} = {}) {
  const chain = new AuditChain(join(stateDir, "audit.jsonl"));
  const records = await chain.read();

  if (!records.length) {
    const err = { error: "no_audit_records", message: "There is no audit chain in this workspace yet." };
    if (json) return { result: err, output: JSON.stringify(err, null, 2), exitCode: 1 };
    write(`\n  ${red("No audit chain in this workspace.")}\n  ${dim("Run `cirvix protect` or `cirvix runtime` first.")}\n\n`);
    return { result: err, exitCode: 1 };
  }

  const segment = segmentFor(records, decisionId);
  if (!segment) {
    const err = { error: "decision_not_found", message: `No decision "${decisionId}" in this chain.`, records: records.length };
    if (json) return { result: err, output: JSON.stringify(err, null, 2), exitCode: 1 };
    write(`\n  ${red(`No decision "${decisionId}" in this chain.`)}\n  ${dim(`${records.length} records searched. Try \`cirvix logs\`.`)}\n\n`);
    return { result: err, exitCode: 1 };
  }

  const key = await loadOrCreateKey(stateDir);
  const decision = segment[segment.length - 1];

  const { token, payload } = buildProof({
    privateKey: key.privateKey,
    keyId: key.keyId,
    issuer: "local",
    decisionId,
    records: segment,
    policy,
    agent: decision.agent ?? null,
  });

  if (out) await writeFile(out, token + "\n", "utf8");

  const result = {
    decisionId,
    issuer: "local",
    keyId: key.keyId,
    records: segment.length,
    chainHead: payload.chainHead,
    issuedAt: payload.issuedAt,
    writtenTo: out ?? null,
    proof: token,
  };
  if (json) return { result, output: JSON.stringify(result, null, 2), exitCode: 0 };

  write(`\n  ${bold("PROOF")}  ${dim(decisionId)}\n\n`);
  write(
    panel({
      lines: [
        `${"Issuer".padEnd(11)} local (this workspace)`,
        `${"Key".padEnd(11)} ${key.keyId}`,
        `${"Records".padEnd(11)} ${segment.length}`,
        `${"Chain head".padEnd(11)} ${payload.chainHead.slice(0, 30)}…`,
        `${"Issued".padEnd(11)} ${payload.issuedAt}`,
      ],
      width: 62,
    }) + "\n",
  );
  if (out) write(`\n  ${green("✓")} written to ${bold(out)}\n`);
  else write(`\n${gray(token)}\n`);
  write(`\n  ${dim("Check it:")}  ${bold(`cirvix verify ${out ?? "<proof>"}`)}\n`);
  /* Said here as well as in verify, because this is where someone decides
     whether to send it to an auditor. */
  write(`  ${dim("A local proof shows this workspace has not altered the artifact since")}\n`);
  write(`  ${dim("signing. It is not independent evidence — the key that signed it lives here.")}\n\n`);
  return { result, exitCode: 0 };
}

/* -------------------------------------------------------------------------- */

export async function verify({
  proof,
  publicKey = null,
  cwd = process.cwd(),
  stateDir = join(cwd, ".cirvix"),
  json = false,
  write = (s) => process.stdout.write(s),
} = {}) {
  let token = String(proof ?? "").trim();
  if (!token) {
    const err = { verified: false, failed: "input", reason: "No proof token or file provided." };
    if (json) return { result: err, output: JSON.stringify(err, null, 2), exitCode: 1 };
    write(`\n  ${red("No proof token or file provided.")}\n\n`);
    return { result: err, exitCode: 1 };
  }

  // A path or the artifact itself. If it is not in JWT format (3 dot-separated segments starting with eyJ), treat as a file path.
  const isJwtShape = token.split(".").length === 3 && token.startsWith("eyJ");
  if (!isJwtShape) {
    try {
      token = (await readFile(proof, "utf8")).trim();
    } catch {
      const err = { verified: false, failed: "file_not_found", reason: `File not found: ${proof}` };
      if (json) return { result: err, output: JSON.stringify(err, null, 2), exitCode: 1 };
      write(`\n  ${red(`File not found: ${proof}`)}\n\n`);
      return { result: err, exitCode: 1 };
    }
  } else if (token.length < 512) {
    const fromFile = await readFile(proof, "utf8").catch(() => null);
    if (fromFile) token = fromFile.trim();
  }

  let pub = publicKey;
  if (!pub) {
    // No key given: fall back to this workspace's own. That only ever verifies
    // proofs this machine issued, which is the honest default — verifying
    // someone else's proof requires their public key and should not silently
    // appear to succeed without it.
    try {
      pub = JSON.parse(await readFile(join(stateDir, KEY_FILE), "utf8")).publicKey;
    } catch {
      const err = { verified: false, failed: "key", reason: "No public key given, and this workspace has none to fall back on." };
      if (json) return { result: err, output: JSON.stringify(err, null, 2), exitCode: 1 };
      write(`\n  ${red("No key to verify against.")}\n  ${dim("Pass --key <public-key.pem>.")}\n\n`);
      return { result: err, exitCode: 1 };
    }
  } else if (!String(pub).includes("BEGIN")) {
    pub = await readFile(pub, "utf8");
  }

  const result = verifyProof(pub, token);

  if (json) return { result, output: JSON.stringify(result, null, 2), exitCode: result.verified ? 0 : 1 };

  if (!result.verified) {
    /* Which of the three checks failed, by name. "Invalid" tells an auditor
       nothing they can act on; "the signature does not verify" and "the chain
       breaks at record 4" lead to completely different investigations. */
    write(`\n  ${red(bold("NOT VERIFIED"))}  ${dim("(" + result.failed + ")")}\n\n`);
    write(`  ${result.reason}\n\n`);
    return { result, exitCode: 1 };
  }

  write(`\n  ${green(bold("VERIFIED"))}  ${dim("signature · chain · integrity")}\n\n`);
  write(
    panel({
      lines: [
        `${"Decision".padEnd(11)} ${result.decisionId}`,
        `${"Issuer".padEnd(11)} ${result.issuer}`,
        `${"Key".padEnd(11)} ${result.keyId ?? "—"}`,
        `${"Agent".padEnd(11)} ${result.agent ?? "—"}`,
        `${"Records".padEnd(11)} ${result.records}`,
        `${"Policy".padEnd(11)} ${String(result.policy?.hash ?? "—").slice(0, 30)}…`,
        `${"Issued".padEnd(11)} ${result.issuedAt}`,
      ],
      width: 62,
    }) + "\n",
  );
  write(`\n  ${result.issuer === "cirvix" ? green("●") : amber("●")} ${dim(result.attests)}\n\n`);
  return { result, exitCode: 0 };
}
