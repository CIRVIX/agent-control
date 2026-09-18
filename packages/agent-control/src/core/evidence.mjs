/**
 * Evidence packs.
 *
 * The primitives already existed — prove.mjs signs a decision, the audit chain
 * verifies, buildPassport describes an agent. What did not exist was the thing
 * a security reviewer actually asks for: one bundle, for one scope, that
 * answers "show me this agent was controlled" without the reviewer having to
 * know which four commands to run.
 *
 * THE ONE RULE THIS FILE EXISTS TO ENFORCE
 * ---------------------------------------
 * A pack maps controls. It never claims compliance.
 *
 * "SOC 2 CC6.1" appearing next to a decision means Cirvix believes this
 * evidence is relevant to that control. It does not mean the control is met,
 * that an auditor agreed, or that anybody is certified. The vocabulary below
 * has no word for "compliant" and a test asserts it never acquires one —
 * because the moment a generated PDF says "SOC 2 compliant", somebody forwards
 * it to a customer and the claim is ours.
 *
 * WHAT NEVER GOES IN
 * ------------------
 * Arguments and results are excluded wholesale rather than redacted. A
 * redactor is a filter that has to be right every time; an exclusion is right
 * by construction. The pack carries what was decided, under which rule, and
 * whether the chain verifies — none of which needs the payload.
 */

import { createHash } from "node:crypto";
import { canonicalJson } from "./audit.mjs";

export const EVIDENCE_VERSION = 2;

/**
 * Digest format_versions. Packs carry `digestFormat` so a verifier can tell
 * whether it is looking at a current pack or a legacy one — and refuse rather
 * than silently reinterpret.
 *
 * v1: digest over the canonical form with `digest` spread as `undefined`.
 *     Stable for any object that survives JSON round-trip (the only shape a
 *     stored pack can have), but its in-memory semantics depended on how the
 *     canonicalizer spelled `undefined`.
 * v2: digest over the canonical form with the digest-bearing fields DELETED
 *     before hashing. Deletion is unambiguous: no canonicalizer option can
 *     change what "the object without this key" means.
 */
export const DIGEST_FORMAT = Object.freeze({ V1_LEGACY: 1, V2_EXPLICIT: 2 });

/**
 * Coverage vocabulary. Deliberately has no "pass" and no "compliant".
 *
 * `mapped` is the strongest word available and it only means evidence exists.
 * Adding a stronger term is the one change to this file that would turn a
 * useful artifact into a liability.
 */
export const COVERAGE = Object.freeze({
  MAPPED: "mapped",           // evidence exists and is attached
  PARTIAL: "partial",         // some evidence, with a stated gap
  NOT_COVERED: "not_covered", // in scope, nothing found
  OUT_OF_SCOPE: "out_of_scope",
});

/**
 * Control mappings. Intentionally few, and each says what it is evidenced BY.
 *
 * A long list of frameworks would look more impressive and mean less: every
 * row Cirvix cannot actually evidence is a row a reviewer will find empty.
 */
const CONTROLS = [
  { id: "SOC2.CC6.1", framework: "SOC 2", title: "Logical access controls restrict access to protected resources",
    evidencedBy: "decisions" },
  { id: "SOC2.CC6.3", framework: "SOC 2", title: "Access is removed or modified when no longer appropriate",
    evidencedBy: "policyVersions" },
  { id: "SOC2.CC7.2", framework: "SOC 2", title: "Anomalies are identified and analysed",
    evidencedBy: "denials" },
  { id: "SOC2.CC7.3", framework: "SOC 2", title: "Security events are evaluated and acted upon",
    evidencedBy: "approvals" },
  { id: "ISO27001.A.8.16", framework: "ISO/IEC 27001:2022", title: "Monitoring activities",
    evidencedBy: "decisions" },
  { id: "ISO27001.A.5.15", framework: "ISO/IEC 27001:2022", title: "Access control",
    evidencedBy: "policyVersions" },
  { id: "NIST.AI.RMF.MEASURE.2.7", framework: "NIST AI RMF", title: "AI system security and resilience are evaluated",
    evidencedBy: "denials" },
  { id: "NIST.AI.RMF.MANAGE.4.1", framework: "NIST AI RMF", title: "Post-deployment monitoring plans are implemented",
    evidencedBy: "chain" },
];

/** Fields that may appear on a decision inside a pack. Everything else is dropped. */
const DECISION_FIELDS = [
  "decision_id", "request_id", "ts", "timestamp", "agent", "action", "tool", "resource", "destination",
  "command", "verdict", "decision", "rule", "policy", "reason", "risk", "risk_signals", "environment",
  "run_id", "hash", "prev_hash", "authority", "delegation", "approval_id", "approved_by",
  "secrets_brokered", "secrets_detected", "context", "latency_ms", "stages",
];

function slimDecision(record) {
  const out = {};
  for (const f of DECISION_FIELDS) if (record[f] !== undefined) out[f] = record[f];
  return out;
}

/**
 * Assembles a pack.
 *
 * `records` are audit records already read from the chain — this function does
 * no I/O, so it is testable and so the caller decides what it is allowed to
 * read.
 */
export function buildEvidencePack({
  records = [],
  agent = null,
  org = null,
  from = null,
  to = null,
  passport = null,
  policyVersions = [],
  proofs = [],
  approvals = [],
  chain = null,
  now = () => new Date().toISOString(),
} = {}) {
  const inWindow = (r) => {
    const t = r.ts ?? r.timestamp;
    if (from && t && t < from) return false;
    if (to && t && t > to) return false;
    return true;
  };
  const scoped = records
    .filter((r) => (agent ? r.agent === agent : true))
    .filter(inWindow);

  const decisions = scoped.map(slimDecision);
  const denials = decisions.filter((d) => d.verdict === "deny" || d.decision === "deny");
  const held = decisions.filter((d) => d.decision === "require_approval" || d.verdict === "hold");

  const evidence = {
    decisions: decisions.length,
    denials: denials.length,
    approvals: approvals.length,
    policyVersions: policyVersions.length,
    chain: chain?.ok === true ? 1 : 0,
  };

  const coverage = CONTROLS.map((c) => {
    const n = evidence[c.evidencedBy] ?? 0;
    return {
      control: c.id,
      framework: c.framework,
      title: c.title,
      coverage: n > 0 ? COVERAGE.MAPPED : COVERAGE.NOT_COVERED,
      evidence: `${n} ${c.evidencedBy}`,
    };
  });

  const pack = {
    v: EVIDENCE_VERSION,
    digestFormat: DIGEST_FORMAT.V2_EXPLICIT,
    kind: "evidence_pack",
    generatedAt: now(),
    scope: { agent, org, from, to },
    summary: {
      decisions: decisions.length,
      denied: denials.length,
      heldForApproval: held.length,
      distinctRules: [...new Set(decisions.map((d) => d.rule).filter(Boolean))].length,
      chainVerified: chain?.ok === true,
      chainRecords: chain?.records ?? null,
      chainHead: chain?.head ?? null,
    },
    passport: passport ?? null,
    policyVersions: policyVersions.map((p) => ({ version: p.version ?? null, hash: p.hash ?? null, publishedAt: p.publishedAt ?? null })),
    decisions,
    approvals: approvals.map((a) => ({ id: a.id ?? null, decidedBy: a.decidedBy ?? null, decision: a.decision ?? null, at: a.at ?? null })),
    proofs: proofs.map((p) => (typeof p === "string" ? { token: p } : { token: p.token ?? null, decisionId: p.decisionId ?? null })),
    controlMapping: coverage,
    /* Load-bearing. Read by humans who will forward this onward. */
    disclaimer:
      "This pack maps evidence to control identifiers. It is not an audit, a certification, " +
      "or a statement of compliance. No control is asserted to be met, and no framework " +
      "listed here has assessed this system. Coverage of 'mapped' means only that relevant " +
      "evidence is attached.",
  };

  pack.digest = digestPackV2(pack);
  return pack;
}

/** v2 digest: hash the canonical form with digest-bearing fields removed. */
export function digestPackV2(pack) {
  const { digest: _dropDigest, digestFormat: _dropFormat, ...body } = pack;
  return "sha256:" + createHash("sha256").update(canonicalJson(body)).digest("hex");
}

/** v1 digest: the legacy `{ ...pack, digest: undefined }` spelling. */
export function digestPackV1(pack) {
  return "sha256:" + createHash("sha256").update(canonicalJson({ ...pack, digest: undefined })).digest("hex");
}

/** The human-readable report. Plain text so it survives every pipeline. */
export function renderEvidenceReport(pack) {
  const s = pack.summary;
  const lines = [
    "CIRVIX EVIDENCE PACK",
    "",
    `Generated    ${pack.generatedAt}`,
    `Agent        ${pack.scope.agent ?? "(all agents)"}`,
    `Window       ${pack.scope.from ?? "(open)"} → ${pack.scope.to ?? "(open)"}`,
    `Digest       ${pack.digest}`,
    "",
    "SUMMARY",
    `  Decisions recorded     ${s.decisions}`,
    `  Denied                 ${s.denied}`,
    `  Held for approval      ${s.heldForApproval}`,
    `  Distinct rules applied ${s.distinctRules}`,
    `  Audit chain            ${s.chainVerified ? `verified, ${s.chainRecords} records` : "NOT VERIFIED"}`,
    "",
  ];

  if (pack.passport?.trust) {
    const t = pack.passport.trust;
    lines.push("TRUST", `  Score  ${t.score ?? "unscored"}${t.band ? ` (${t.band})` : ""}`, "");
  }

  lines.push("CONTROL MAPPING", "");
  for (const c of pack.controlMapping) {
    lines.push(`  ${c.coverage === COVERAGE.MAPPED ? "▪" : "·"} ${c.control.padEnd(28)} ${c.coverage.padEnd(12)} ${c.evidence}`);
  }
  lines.push("", "  " + pack.disclaimer.replace(/(.{1,72})(\s|$)/g, "$1\n  ").trim(), "");
  return lines.join("\n");
}

/**
 * Re-derives the digest.
 *
 * A pack that has been edited after generation fails here. The digest is over
 * the canonical form minus itself, so it is stable across serialisation.
 *
 * Format handling is explicit, not guessed:
 * - v2 (digestFormat 2, or a pack that carries no format marker but verifies
 *   under v2): verified with the deletion-based digest.
 * - legacy v1 packs (v: 1, no digestFormat): verified with the legacy digest.
 * - anything else: refused with an explicit version reason — never silently
 *   reinterpreted under the wrong hash.
 */
export function verifyEvidencePack(pack) {
  if (!pack || typeof pack !== "object" || Array.isArray(pack)) {
    return { ok: false, expected: null, actual: null, reason: "not an evidence pack" };
  }
  const format = pack.digestFormat ?? (pack.v === 1 ? DIGEST_FORMAT.V1_LEGACY : null);
  if (format === DIGEST_FORMAT.V2_EXPLICIT || (format === null && typeof pack.digest === "string")) {
    const expected = digestPackV2(pack);
    return { ok: expected === pack.digest, expected, actual: pack.digest, format: DIGEST_FORMAT.V2_EXPLICIT };
  }
  if (format === DIGEST_FORMAT.V1_LEGACY) {
    const expected = digestPackV1(pack);
    return { ok: expected === pack.digest, expected, actual: pack.digest, format: DIGEST_FORMAT.V1_LEGACY };
  }
  return { ok: false, expected: null, actual: pack.digest ?? null, reason: `unsupported evidence digest format (v=${pack.v ?? "?"}, digestFormat=${pack.digestFormat ?? "?"})` };
}
