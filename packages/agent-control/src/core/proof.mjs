/**
 * Proof of Control — a signed, self-contained artifact for one decision.
 *
 * WHAT A PROOF IS FOR. Someone outside your organisation asks: on this date,
 * did your agent try X, and what did your control plane do about it? Today the
 * answer is a screenshot of a dashboard, which proves nothing. A proof answers
 * it with an artifact they can check themselves, offline, without trusting us
 * or you.
 *
 * WHY THE AUDIT CHAIN WAS NOT ENOUGH ON ITS OWN
 *
 * The chain is a linear SHA-256 hash chain and it is UNSIGNED. That is a real
 * guarantee and a bounded one: it proves no record was altered or removed
 * after the record that follows it was written. It does not prove who wrote
 * it, and anyone holding the file can recompute every hash after doctoring a
 * record — the chain would verify perfectly.
 *
 * MASTER-PLAN-RECONCILIATION.md records this explicitly as a correction to the
 * original plan ("it is a linear SHA-256 hash chain, unsigned. Different
 * structure, different guarantees"). Signing is what closes the gap, and
 * nothing here is allowed to describe the unsigned chain as third-party
 * verifiable.
 *
 * TWO ISSUERS, AND THE DIFFERENCE IS NOT COSMETIC
 *
 *   issuer: "local"   Signed by a key this workspace generated and holds. It
 *                     proves the artifact has not been altered since it was
 *                     signed, and that the chain segment is internally
 *                     consistent. It does NOT prove the records are true,
 *                     because whoever holds the private key could sign a
 *                     doctored chain. Useful to you. Not evidence to a
 *                     third party, and verify() says so in those words.
 *
 *   issuer: "cirvix"  Signed by the control plane, which observed the
 *                     decision and does not hand out its private key. That
 *                     one IS third-party verifiable, against a published
 *                     public key.
 *
 * Conflating the two would be the most valuable lie this product could tell,
 * so the artifact carries the issuer, verify() reports it, and the wording for
 * each is different.
 *
 * VERIFY IS THREE INDEPENDENT CHECKS. Signature, chain recomputation, and
 * artifact integrity. VERIFIED requires all three. A single failure names
 * which one, because "invalid" tells an auditor nothing they can act on.
 */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as signBytes,
  verify as verifyBytes,
} from "node:crypto";

/* IMPORTED, NOT REIMPLEMENTED.
   A proof recomputes the audit chain's hashes, so it must canonicalise bytes
   exactly as the chain did. A second local copy of that rule would be
   byte-identical on the day it was written and free to drift afterwards — and
   the failure mode is silent: every proof would verify against itself and
   against nothing else. This repository has already been bitten by split-brain
   classifiers; one implementation, imported. */
import { canonicalJson, hashRecord } from "./audit.mjs";

export const PROOF_VERSION = 1;
const ENCODING = "base64url";

/** The genesis hash the audit chain starts from. Mirrors core/audit.mjs. */
const GENESIS = "sha256:" + "0".repeat(64);

/**
 * Canonical JSON: sorted keys, recursively.
 *
 * The chain's own serialiser, re-exported under the name this module uses. The
 * bytes signed and the bytes verified must be identical regardless of how the
 * object was built, and a shallow key sort is not enough — a nested object
 * serialised in a different order produces different bytes and a signature
 * that fails for no reason a reader could diagnose.
 */
export const canonical = canonicalJson;

const sha256 = (s) => "sha256:" + createHash("sha256").update(s).digest("hex");

/** Generates a proof signing keypair. */
export function generateProofKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    publicKey: pub,
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    // A short, stable name for the key, so an artifact says which key signed
    // it and rotation does not invalidate everything issued before it.
    keyId: sha256(pub).slice(7, 23),
  };
}

/** The key id for a public key, so a verifier can select without guessing. */
export function keyIdFor(publicKeyPem) {
  return sha256(String(publicKeyPem)).slice(7, 23);
}

/**
 * Recomputes a chain segment.
 *
 * Returns the first break rather than a boolean, because "the chain is bad" is
 * not actionable and "record 4 does not link to record 3" is.
 *
 * A segment need not start at genesis — a proof covers a window, not a whole
 * history — so the first record's `prev_hash` is taken as the anchor and every
 * link after it is checked.
 */
export function verifyChainSegment(records) {
  if (!Array.isArray(records) || records.length === 0) {
    return { ok: false, reason: "the proof carries no audit records" };
  }
  let prev = records[0].prev_hash ?? GENESIS;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (r.prev_hash !== prev) {
      return { ok: false, brokenAt: i, reason: `record ${i} does not link to the record before it` };
    }
    // hashRecord() is the chain's own function, so this cannot disagree with
    // how the record was hashed when it was written.
    const recomputed = hashRecord(r);
    if (recomputed !== r.hash) {
      return { ok: false, brokenAt: i, reason: `record ${i} does not match its own hash — its content was changed` };
    }
    prev = r.hash;
  }
  return { ok: true, records: records.length, head: prev };
}

/**
 * Builds and signs a proof.
 *
 * `records` is the chain segment covering the decision, in order, each with
 * the `prev_hash` and `hash` the chain wrote. Nothing is recomputed here from
 * a convenient shape: a proof that regenerated its own hashes would verify
 * against itself and mean nothing.
 */
export function buildProof({
  privateKey,
  keyId,
  issuer = "local",
  decisionId,
  records,
  policy,
  agent = null,
  orgId = null,
  now = () => new Date().toISOString(),
}) {
  if (!privateKey) throw new Error("A proof needs a signing key.");
  if (!decisionId) throw new Error("A proof needs a decision id.");
  if (!Array.isArray(records) || !records.length) throw new Error("A proof needs its audit records.");
  if (!issuer || !["local", "cirvix"].includes(issuer)) {
    throw new Error(`Unknown issuer "${issuer}". A proof must say who signed it.`);
  }

  const segment = verifyChainSegment(records);
  if (!segment.ok) {
    // Refusing to sign a broken chain is the point. A signature over records
    // that do not link would be a valid signature on a false claim, which is
    // strictly worse than no proof at all.
    throw Object.assign(new Error(`Refusing to sign a broken chain: ${segment.reason}`), { segment });
  }

  const payload = {
    v: PROOF_VERSION,
    issuer,
    decisionId,
    orgId,
    agent,
    // The policy is part of what is being attested. A decision is only
    // meaningful against the rules that produced it, and a proof that omitted
    // them would let the same record be presented under any policy at all.
    policy: {
      hash: policy?.hash ?? sha256(canonical(policy?.rules ?? [])),
      version: policy?.version ?? null,
      ruleCount: Array.isArray(policy?.rules) ? policy.rules.length : (policy?.ruleCount ?? null),
    },
    records,
    chainHead: segment.head,
    issuedAt: now(),
    keyId: keyId ?? null,
  };

  const body = Buffer.from(canonical(payload), "utf8");
  const signature = signBytes(null, body, createPrivateKey(privateKey));
  return {
    payload,
    // The wire form: two base64url segments, the same shape as a licence, so
    // one artifact can be pasted into a terminal or an email without escaping.
    token: `${body.toString(ENCODING)}.${signature.toString(ENCODING)}`,
  };
}

/**
 * Verifies a proof with no network access.
 *
 * ORDER MATTERS. The signature is checked BEFORE anything inside the payload
 * is read or trusted, so a malformed or hostile artifact cannot steer the
 * verifier through its own contents first.
 */
export function verifyProof(publicKeyPem, token, { now = () => new Date() } = {}) {
  const fail = (check, reason) => ({ ok: false, verified: false, failed: check, reason });

  if (typeof token !== "string" || !token.includes(".")) {
    return fail("integrity", "This is not a Cirvix proof — it has no signature section.");
  }
  const [bodyPart, sigPart] = token.split(".");
  let body;
  let signature;
  try {
    body = Buffer.from(bodyPart, ENCODING);
    signature = Buffer.from(sigPart, ENCODING);
  } catch {
    return fail("integrity", "The proof is not decodable.");
  }

  /* ------------------------------------------------------ 1. signature */
  let signatureOk = false;
  try {
    signatureOk = verifyBytes(null, body, createPublicKey(publicKeyPem), signature);
  } catch {
    return fail("signature", "The signature could not be checked against this key.");
  }
  if (!signatureOk) {
    return fail("signature", "The signature does not verify. This proof was not signed by that key, or it has been altered.");
  }

  let payload;
  try {
    payload = JSON.parse(body.toString("utf8"));
  } catch {
    return fail("integrity", "The proof body is not readable JSON.");
  }

  /* ------------------------------------------------------ 2. integrity */
  for (const field of ["v", "issuer", "decisionId", "records", "chainHead", "policy", "issuedAt"]) {
    if (payload[field] === undefined) return fail("integrity", `The proof is missing "${field}".`);
  }
  if (payload.v !== PROOF_VERSION) {
    return fail("integrity", `This proof is version ${payload.v}; this verifier understands ${PROOF_VERSION}.`);
  }
  // Canonical form, re-derived. A payload that does not round-trip to the
  // bytes that were signed means the signature covers something other than
  // what is being read — which is how a verifier gets shown one thing and
  // checks another.
  if (canonical(payload) !== body.toString("utf8")) {
    return fail("integrity", "The proof body is not in canonical form — the signed bytes and the readable bytes differ.");
  }
  if (!payload.records.some((r) => r?.decision_id === payload.decisionId || r?.decisionId === payload.decisionId)) {
    return fail("integrity", "The proof does not contain the decision it claims to be about.");
  }

  /* ---------------------------------------------------------- 3. chain */
  const segment = verifyChainSegment(payload.records);
  if (!segment.ok) return fail("chain", segment.reason);
  if (segment.head !== payload.chainHead) {
    return fail("chain", "The recorded chain head does not match the records in the proof.");
  }

  /* -------------------------------------------------------- all three */
  return {
    ok: true,
    verified: true,
    issuer: payload.issuer,
    decisionId: payload.decisionId,
    agent: payload.agent ?? null,
    orgId: payload.orgId ?? null,
    policy: payload.policy,
    records: payload.records.length,
    chainHead: payload.chainHead,
    issuedAt: payload.issuedAt,
    keyId: payload.keyId ?? null,
    /* What this actually establishes, in the words a reader needs, and
       different for each issuer. A locally-signed proof is not evidence to a
       third party and must never be presented as though it were. */
    attests:
      payload.issuer === "cirvix"
        ? "Signed by the Cirvix control plane, which observed this decision. Verifiable by anyone holding the published public key."
        : "Signed by the key held in the workspace that produced it. This shows the artifact has not been altered since signing and that the chain is internally consistent. It is not independent evidence: whoever holds that private key could have signed a different history.",
  };
}

/* ==========================================================================
   THE ENVELOPE, SHARED
   --------------------------------------------------------------------------
   buildProof/verifyProof are about a decision. The signing and checking
   underneath them are about neither — they are "sign this object" and "check
   these bytes", and the Agent Passport needs exactly the same two operations.

   Factored out rather than copied. Two signing implementations in one product
   is how a verifier ends up checking one format while trusting another, and
   the failure is silent: every artifact verifies against itself and against
   nothing else.
   ========================================================================== */

/** Signs any object into the two-segment base64url wire form. */
export function buildProofEnvelope({ payload, privateKey, keyId = null }) {
  if (!privateKey) throw new Error("An envelope needs a signing key.");
  const full = keyId === null ? payload : { ...payload, keyId };
  const body = Buffer.from(canonical(full), "utf8");
  const signature = signBytes(null, body, createPrivateKey(privateKey));
  return { payload: full, token: `${body.toString(ENCODING)}.${signature.toString(ENCODING)}` };
}

/**
 * Checks the signature and the canonical round trip, and nothing else.
 *
 * ORDER MATTERS, and it is the same order verifyProof uses: the signature is
 * checked BEFORE any field inside the payload is read, so a hostile artifact
 * cannot steer the verifier through its own contents first. Semantic checks
 * belong to the caller, which knows what kind of artifact it asked for.
 */
export function verifyProofEnvelope(publicKeyPem, token) {
  const fail = (check, reason) => ({ ok: false, verified: false, failed: check, reason });

  if (typeof token !== "string" || !token.includes(".")) {
    return fail("integrity", "This is not a Cirvix artifact — it has no signature section.");
  }
  const [bodyPart, sigPart] = token.split(".");
  let body, signature;
  try {
    body = Buffer.from(bodyPart, ENCODING);
    signature = Buffer.from(sigPart, ENCODING);
  } catch {
    return fail("integrity", "The artifact is not decodable.");
  }

  let signatureOk = false;
  try {
    signatureOk = verifyBytes(null, body, createPublicKey(publicKeyPem), signature);
  } catch {
    return fail("signature", "The signature could not be checked against this key.");
  }
  if (!signatureOk) {
    return fail("signature", "The signature does not verify. This artifact was not signed by that key, or it has been altered.");
  }

  let payload;
  try {
    payload = JSON.parse(body.toString("utf8"));
  } catch {
    return fail("integrity", "The body is not readable JSON.");
  }
  if (canonical(payload) !== body.toString("utf8")) {
    return fail("integrity", "The body does not round-trip to the bytes that were signed.");
  }
  return { ok: true, verified: true, payload };
}

/* ==========================================================================
   CRYPTOGRAPHIC ACTION RECEIPTS (Section 17)
   ========================================================================== */

import { randomUUID } from "node:crypto";

/**
 * Issues a cryptographic, tamper-evident Action Receipt.
 */
export function issueActionReceipt({
  agentId,
  sponsor = null,
  intent = null,
  action,
  target = null,
  policy = null,
  decision,
  evidence = {},
  prevReceiptHash = GENESIS,
}, privateKey = null) {
  const id = `rcp_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
  const ts = new Date().toISOString();

  const evidenceStr = typeof evidence === "string" ? evidence : canonical(evidence);
  const evidenceHash = sha256(evidenceStr);

  const receiptBody = {
    id,
    agent: agentId,
    sponsor,
    intent,
    action,
    target,
    policy,
    decision,
    timestamp: ts,
    evidenceHash,
    prevReceiptHash,
  };

  const receiptHash = sha256(canonical(receiptBody));

  let signature = null;
  if (privateKey) {
    const priv = createPrivateKey(privateKey);
    signature = signBytes(null, Buffer.from(receiptHash, "utf8"), priv).toString("base64url");
  }

  return {
    ...receiptBody,
    receiptHash,
    signature,
  };
}

/**
 * Verifies an Action Receipt's hash integrity and signature.
 */
export function verifyActionReceipt(receipt, publicKeyPem = null) {
  if (!receipt || typeof receipt !== "object") {
    return { ok: false, reason: "Receipt object is invalid." };
  }

  const { signature, receiptHash, ...body } = receipt;
  const expectedHash = sha256(canonical(body));

  if (receiptHash !== expectedHash) {
    return {
      ok: false,
      reason: `Receipt hash mismatch — receipt content has been tampered with. Expected: ${expectedHash}, Found: ${receiptHash}`,
    };
  }

  if (signature && publicKeyPem) {
    try {
      const pub = createPublicKey(publicKeyPem);
      const verified = verifyBytes(null, Buffer.from(receiptHash, "utf8"), pub, Buffer.from(signature, "base64url"));
      if (!verified) {
        return { ok: false, reason: "Cryptographic signature is invalid for the supplied public key." };
      }
    } catch (err) {
      return { ok: false, reason: `Signature verification failed: ${err.message}` };
    }
  }

  return { ok: true, verified: true, id: receipt.id, receiptHash };
}
