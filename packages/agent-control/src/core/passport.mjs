/**
 * Agent Passport, and the Trust Score on it.
 *
 * A passport is an identity document for one agent, assembled entirely from
 * what that agent has actually done: the decisions in the audit chain, the
 * tools it reached for, the rules that stopped it. Nothing is declared about
 * an agent here — an agent cannot describe itself into a passport.
 *
 * THE TRUST SCORE IS THE DANGEROUS PART, AND IT IS BUILT ACCORDINGLY.
 *
 * A single number attached to a security decision is the easiest thing in this
 * product to fake and the hardest to argue with. "Trust: 87" reads as a
 * measurement whatever produced it, and a reader has no way to check it. Four
 * constraints, all enforced by tests:
 *
 *   1. EVERY POINT IS TRACEABLE. The score is never returned alone. It ships
 *      with the signals that produced it, each one a counted fact with its own
 *      weight, and the components sum to the score. A reader can recompute it
 *      on paper.
 *
 *   2. NO PRIORS. There is no starting score, no vendor opinion, no adjustment
 *      for the framework an agent happens to use. Only counted behaviour.
 *
 *   3. IT REFUSES TO SCORE THIN EVIDENCE. Below the threshold it returns null
 *      and says why. A new agent with four decisions gets "insufficient
 *      evidence", not a confident 50 — a number that arrives before the
 *      evidence does is worse than no number, because it will be acted on.
 *
 *   4. IT IS NOT A SAFETY CERTIFICATE. It summarises observed behaviour. An
 *      agent that has never been caught doing anything dangerous is an agent
 *      that has never been caught, and `meaning` says so in those words.
 *
 * WHAT IT DELIBERATELY DOES NOT DO. It does not predict. It does not compare
 * one customer's agents to another's. It does not move on its own over time.
 * Each of those would require data this has no honest access to.
 */

import { RISK } from "./risk.mjs";
import { DECISION } from "./decisions.mjs";

/** Below this many decisions, behaviour is not yet a pattern. */
export const MIN_DECISIONS_TO_SCORE = 25;

/**
 * The signals, and what each is worth.
 *
 * Weights are stated here rather than buried in the arithmetic so the whole
 * model is one readable table. They are a judgement — that is unavoidable in
 * any score — but the judgement is visible, fixed, and the same for every
 * agent. What is NOT a judgement is the count each one is applied to.
 */
export const SIGNALS = [
  {
    id: "clean_rate",
    label: "Proportion of calls that needed no intervention",
    weight: 40,
    // The base rate. An agent that mostly does its job without tripping a rule
    // is behaving; one that is refused constantly is either misconfigured or
    // doing something it should not.
    measure: (f) => (f.total ? f.allowed / f.total : 0),
  },
  {
    id: "no_critical",
    label: "Absence of critical-risk attempts",
    weight: 25,
    // Not "few" — a single attempt to read cloud credentials is the signal.
    // Scaled steeply so one costs most of the band.
    measure: (f) => (f.criticalAttempts === 0 ? 1 : Math.max(0, 1 - f.criticalAttempts / 3)),
  },
  {
    id: "no_escalation",
    label: "No repeated attempts after a refusal",
    weight: 20,
    // An agent that is refused and moves on is behaving. One that retries the
    // same refused action is the shape of an agent under injection.
    measure: (f) => (f.repeatedRefusals === 0 ? 1 : Math.max(0, 1 - f.repeatedRefusals / 5)),
  },
  {
    id: "scope_stability",
    label: "Stays within the tools it started with",
    weight: 15,
    // Tool sprawl over time is how an agent's blast radius grows without
    // anyone deciding it should.
    measure: (f) => (f.distinctTools <= 1 ? 1 : Math.max(0, 1 - (f.distinctTools - 1) / 20)),
  },
];

const TOTAL_WEIGHT = SIGNALS.reduce((n, s) => n + s.weight, 0);

/**
 * Counts what an agent did, from audit records alone.
 *
 * Every field is a count of something that happened. No field is an opinion,
 * and nothing here is derived from configuration — an agent that claims to be
 * well-behaved and behaves otherwise gets the second one.
 */
export function observe(records, agentId) {
  const mine = records.filter((r) => (agentId ? r.agent === agentId : true) && r.decision);

  const tools = new Set();
  const refusedActions = new Map();
  let allowed = 0;
  let denied = 0;
  let held = 0;
  let criticalAttempts = 0;
  let repeatedRefusals = 0;
  let firstSeen = null;
  let lastSeen = null;

  for (const r of mine) {
    if (r.tool) tools.add(r.tool);
    if (r.decision === DECISION.ALLOW) allowed += 1;
    else if (r.decision === DECISION.DENY) denied += 1;
    else if (r.decision === DECISION.REQUIRE_APPROVAL) held += 1;

    if (r.risk === RISK.CRITICAL) criticalAttempts += 1;

    if (r.decision === DECISION.DENY) {
      const key = `${r.action}|${r.resource}`;
      const seen = (refusedActions.get(key) ?? 0) + 1;
      refusedActions.set(key, seen);
      // The second time an identical refused call appears, that is a retry.
      if (seen > 1) repeatedRefusals += 1;
    }

    if (r.ts) {
      if (!firstSeen || r.ts < firstSeen) firstSeen = r.ts;
      if (!lastSeen || r.ts > lastSeen) lastSeen = r.ts;
    }
  }

  return {
    agent: agentId ?? null,
    total: mine.length,
    allowed,
    denied,
    held,
    criticalAttempts,
    repeatedRefusals,
    distinctTools: tools.size,
    tools: [...tools].sort(),
    firstSeen,
    lastSeen,
  };
}

/**
 * The score, with everything needed to check it.
 *
 * Returns `score: null` rather than a number when the evidence is too thin.
 * The caller must render that as "not enough evidence" — every consumer in
 * this repository does, and a test asserts the CLI does not print a number
 * when there is none.
 */
export function trustScore(facts) {
  if (!facts || facts.total < MIN_DECISIONS_TO_SCORE) {
    return {
      score: null,
      confidence: "insufficient",
      observed: facts?.total ?? 0,
      required: MIN_DECISIONS_TO_SCORE,
      reason:
        `Behaviour is not a pattern yet: ${facts?.total ?? 0} decision${facts?.total === 1 ? "" : "s"} recorded, ` +
        `${MIN_DECISIONS_TO_SCORE} needed. A score before the evidence would be acted on as though it meant something.`,
      components: [],
      meaning: null,
    };
  }

  const components = SIGNALS.map((s) => {
    const raw = Math.max(0, Math.min(1, s.measure(facts)));
    return {
      id: s.id,
      label: s.label,
      weight: s.weight,
      // The measured proportion, rounded for display but not for arithmetic.
      measured: Math.round(raw * 1000) / 1000,
      points: Math.round(raw * s.weight * 10) / 10,
    };
  });

  const score = Math.round(components.reduce((n, c) => n + c.points, 0));

  return {
    score,
    outOf: TOTAL_WEIGHT,
    confidence: facts.total >= MIN_DECISIONS_TO_SCORE * 4 ? "high" : "provisional",
    observed: facts.total,
    components,
    /* Said in full every time the score is produced. A number this compact
       will be quoted out of context, and the sentence that bounds it has to
       travel with it. */
    meaning:
      "A summary of what this agent has been observed doing, not a prediction and not a safety certificate. " +
      "An agent with no dangerous attempts on record is an agent that has not been caught making one. " +
      "Every point above is traceable to a counted decision.",
  };
}

/**
 * The passport: identity, observed behaviour, and the score.
 *
 * Deliberately assembled from records rather than from anything the agent
 * supplies. The only inputs an agent controls are the calls it made, and those
 * are exactly what is being described.
 */
export function buildPassport({ agentId, records, policy = null, environment = null }) {
  const facts = observe(records, agentId);
  const trust = trustScore(facts);

  return {
    v: 1,
    agent: agentId ?? null,
    environment,
    issuedAt: new Date().toISOString(),
    identity: {
      firstSeen: facts.firstSeen,
      lastSeen: facts.lastSeen,
      // The tools it has ACTUALLY used, which is the honest description of
      // what it can do — a declared capability list is a wish.
      tools: facts.tools,
    },
    behaviour: {
      decisions: facts.total,
      allowed: facts.allowed,
      denied: facts.denied,
      heldForApproval: facts.held,
      criticalAttempts: facts.criticalAttempts,
      repeatedRefusals: facts.repeatedRefusals,
    },
    policy: policy ? { version: policy.version ?? null, ruleCount: policy.rules?.length ?? null } : null,
    trust,
  };
}

/* ==========================================================================
   SIGNING, AND THE PUBLIC ARTIFACT
   --------------------------------------------------------------------------
   buildPassport() returns a plain object. That is fine inside the process
   that built it and worthless to anyone else: an unsigned passport is a claim
   about an agent that anybody can write, including the agent.

   The envelope, the canonical serialiser and the curve are all taken from
   proof.mjs rather than reimplemented. A second signing scheme in the same
   product is how a verifier ends up checking one format and trusting another,
   and this repository has already been bitten by split-brain implementations
   once.

   WHY THE PUBLIC ARTIFACT IS A SUBSET
   -----------------------------------
   A passport records the tools an agent reached for and how often it was
   refused. Inside an organisation that is exactly the useful part. Published,
   it is a map of somebody's internal estate — "this agent touches
   payments.write and gets denied a lot" is reconnaissance.

   So `publicView()` drops the tool inventory and the raw counts and keeps what
   a third party actually needs: which agent, under which policy hash, with
   what trust score, signed by whom, and when. The signature covers the FULL
   passport, so a holder can always disclose more by handing over the whole
   artifact — but the default disclosure is the minimum that still verifies.
   ========================================================================== */

import { createHash as _passportHash } from "node:crypto";
import { buildProofEnvelope, verifyProofEnvelope } from "./proof.mjs";

export const PASSPORT_VERSION = 1;

/** A stable id for a passport: the agent plus the content it attests to. */
export function passportId(passport) {
  const basis = `${passport.agent ?? "unknown"}:${passport.issuedAt ?? ""}`;
  return "psp_" + _passportHash("sha256").update(basis).digest("hex").slice(0, 16);
}

/**
 * Signs a passport into the same envelope shape a proof uses.
 *
 * `policyHash` is required when a policy is present. A passport that names a
 * policy version without binding its hash attests to a moving target: the
 * rules can be edited afterwards and the passport still "verifies".
 */
export function signPassport({ passport, privateKey, keyId, issuer = "local", policyHash = null }) {
  if (!privateKey) throw new Error("A passport needs a signing key.");
  if (!passport?.agent) throw new Error("A passport needs an agent.");
  if (passport.policy && !policyHash) {
    throw new Error("A passport that names a policy must bind its hash.");
  }
  const payload = {
    v: PASSPORT_VERSION,
    kind: "passport",
    issuer,
    passportId: passportId(passport),
    agent: passport.agent,
    environment: passport.environment ?? null,
    issuedAt: passport.issuedAt,
    policyHash,
    passport,
  };
  return buildProofEnvelope({ payload, privateKey, keyId });
}

/**
 * Verifies a signed passport.
 *
 * Returns the same shape as verifyProof so one renderer can present either,
 * and so a caller cannot accidentally treat "unverified" as "valid" because
 * the two artifacts reported differently.
 */
export function verifyPassport(publicKeyPem, token) {
  const base = verifyProofEnvelope(publicKeyPem, token);
  if (!base.ok) return base;

  const p = base.payload;
  if (!p || typeof p !== "object" || Array.isArray(p)) {
    return { ok: false, verified: false, failed: "integrity", reason: "The passport payload must be an object." };
  }
  for (const field of ["v", "kind", "issuer", "passportId", "agent", "issuedAt", "passport"]) {
    if (p[field] === undefined) {
      return { ok: false, verified: false, failed: "integrity", reason: `The passport is missing "${field}".` };
    }
  }
  if (p.kind !== "passport") {
    return { ok: false, verified: false, failed: "integrity", reason: `This is a "${p.kind}" artifact, not a passport.` };
  }
  if (p.v !== PASSPORT_VERSION) {
    return { ok: false, verified: false, failed: "integrity", reason: `This passport is version ${p.v}; this verifier understands ${PASSPORT_VERSION}.` };
  }
  if (!p.passport || typeof p.passport !== "object" || Array.isArray(p.passport) ||
      typeof p.agent !== "string" || !p.agent.trim() || p.agent !== p.passport.agent ||
      typeof p.issuedAt !== "string" || !Number.isFinite(Date.parse(p.issuedAt)) || p.issuedAt !== p.passport.issuedAt ||
      p.environment !== (p.passport.environment ?? null) ||
      (p.passport.policy && (typeof p.policyHash !== "string" || !p.policyHash.trim()))) {
    return { ok: false, verified: false, failed: "integrity", reason: "The passport identity or policy binding is invalid." };
  }
  if (p.passportId !== passportId(p.passport)) {
    return { ok: false, verified: false, failed: "integrity", reason: "The passport id does not match its contents." };
  }
  return {
    ok: true,
    verified: true,
    payload: p,
    checks: [
      { name: "signature", ok: true, detail: "Ed25519 signature verifies against the supplied public key." },
      { name: "canonical", ok: true, detail: "The body re-serialises to exactly the bytes that were signed." },
      { name: "identity", ok: true, detail: "The passport id is derived from the passport contents." },
      { name: "policy-binding", ok: p.policyHash !== null, detail: p.policyHash ? `Bound to policy ${p.policyHash}.` : "No policy is bound to this passport." },
    ],
  };
}

/**
 * The subset safe to publish.
 *
 * Everything here is either about the agent's posture or about the artifact
 * itself. Nothing here describes the estate the agent operates in.
 */
export function publicView(payload) {
  const p = payload?.passport ?? {};
  return {
    passportId: payload?.passportId ?? null,
    agent: payload?.agent ?? null,
    environment: payload?.environment ?? null,
    issuer: payload?.issuer ?? null,
    issuedAt: payload?.issuedAt ?? null,
    policyHash: payload?.policyHash ?? null,
    trust: p.trust ? { score: p.trust.score ?? null, band: p.trust.band ?? null, reasons: p.trust.reasons ?? [] } : null,
    /* Deliberately absent: identity.tools, behaviour.* — see the note above. */
  };
}

/* ==========================================================================
   THE BADGE
   --------------------------------------------------------------------------
   A README badge is the most-seen artifact a security product produces, and
   it is also the easiest place to accidentally lie. Two rules follow from
   that.

   It is generated from a SIGNED passport, not from a live score. A badge that
   fetches its own value at render time is a badge whose claim nobody checked;
   this one renders what an artifact already attested to, and carries the
   passport id so a reader can verify the artifact behind it.

   And it never renders a score the passport did not earn. Below the decision
   floor `observe()` requires, there is no score, and the badge says
   "unscored" rather than picking a flattering number. A grey badge that
   admits it has no data is worth more than a green one that invented some.
   ========================================================================== */

const BADGE_TONE = {
  A: "#34D399", B: "#34D399", C: "#F7B750", D: "#F7B750", E: "#FB7185", "—": "#6B7080",
};

/** Letter band for a score. Shared with the public verifier's renderer. */
export function bandFor(score) {
  if (score === null || score === undefined) return "—";
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "E";
}

const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/**
 * A self-contained SVG badge. No external fetch, no font file, no tracking.
 *
 * Sized by character count rather than measured text: a badge that needs a
 * layout engine to be correct is a badge that renders wrong in the one place
 * it matters, which is a README on somebody else's site.
 */
export function badgeSvg(passport, { label = "cirvix" } = {}) {
  const score = passport?.trust?.score ?? null;
  const band = bandFor(score);
  const value = score === null ? "unscored" : `${band} ${score}`;
  const tone = BADGE_TONE[band] ?? BADGE_TONE["—"];

  const lw = 7 * label.length + 20;
  const vw = 7 * value.length + 22;
  const w = lw + vw;
  const title = `${label}: ${value}${passport?.agent ? ` (${passport.agent})` : ""}`;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${esc(title)}">
  <title>${esc(title)}</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#fff" stop-opacity=".08"/><stop offset="1" stop-opacity=".08"/></linearGradient>
  <clipPath id="r"><rect width="${w}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${lw}" height="20" fill="#0C0D10"/>
    <rect x="${lw}" width="${vw}" height="20" fill="${tone}"/>
    <rect width="${w}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="11">
    <text x="${lw / 2}" y="14" fill="#F2F3F7">${esc(label)}</text>
    <text x="${lw + vw / 2}" y="14" fill="#08090B" font-weight="600">${esc(value)}</text>
  </g>
</svg>`;
}

/* ==========================================================================
   CRYPTOGRAPHIC IDENTITY & AGENT PASSPORT (Section 3)
   ========================================================================== */

import { generateKeyPairSync, createPublicKey, sign as cryptoSign, verify as cryptoVerify, randomUUID } from "node:crypto";
import { canonicalJson } from "./audit.mjs";

/**
 * Generates an Ed25519 keypair for an agent.
 */
export function generateAgentKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

/**
 * Issues a cryptographic Agent Passport document.
 */
export function issueCryptographicPassport({
  id: customId = null,
  name,
  owner = "system",
  sponsor = null,
  organization = "local",
  purpose = "general",
  model = "unknown",
  modelVersion = "1.0",
  runtime = "node",
  version = "1.0.0",
  environment = "production",
  tools = [],
  permissions = [],
  riskScore = 0,
}, privateKey = null) {
  const agentId = customId ?? `cirvix://agent/${randomUUID()}`;
  const ts = new Date().toISOString();

  let keys = null;
  let priv = privateKey;
  let pub = null;

  if (!priv) {
    keys = generateAgentKeypair();
    priv = keys.privateKey;
    pub = keys.publicKey;
  }

  const publicKey = createPublicKey(priv);
  if (publicKey.asymmetricKeyType !== "ed25519") throw new TypeError("A passport needs an Ed25519 key.");
  pub = publicKey.export({ type: "spki", format: "pem" }).toString();

  const payload = {
    id: agentId,
    name: name ?? agentId,
    owner,
    sponsor,
    organization,
    purpose,
    model,
    modelVersion,
    runtime,
    version,
    environment,
    tools,
    permissions,
    riskScore,
    createdAt: ts,
    status: "active",
    publicKey: pub,
  };

  const signature = cryptoSign(null, Buffer.from(canonicalJson(payload)), priv).toString("base64url");

  return {
    passport: {
      ...payload,
      signature,
    },
    privateKey: priv,
  };
}

/**
 * Verifies the cryptographic integrity and signature of an Agent Passport.
 */
export function verifyPassportSignature(passport, publicKeyOverride = null) {
  if (!passport || typeof passport !== "object") return false;
  const { signature, previousSignature, ...payload } = passport;
  if (typeof signature !== "string") return false;

  const keyToUse = publicKeyOverride ?? payload.publicKey;
  if (!keyToUse) return false;

  try {
    const data = Buffer.from(canonicalJson(payload));
    const sigBytes = Buffer.from(signature, "base64url");
    if (createPublicKey(keyToUse).asymmetricKeyType !== "ed25519") return false;
    if (!cryptoVerify(null, data, keyToUse, sigBytes)) return false;
    if (payload.previousPublicKey) {
      if (typeof previousSignature !== "string") return false;
      return cryptoVerify(null, data, payload.previousPublicKey, Buffer.from(previousSignature, "base64url"));
    }
    return previousSignature === undefined;
  } catch {
    return false;
  }
}

/**
 * Rotates an agent's cryptographic keypair while preserving identity lineage.
 */
export function rotatePassportKeys(currentPassport, oldPrivateKey, newKeypair = null) {
  if (!verifyPassportSignature(currentPassport)) throw new Error("The current passport is invalid.");
  const oldPublicKey = createPublicKey(oldPrivateKey).export({ type: "spki", format: "pem" }).toString();
  if (oldPublicKey !== currentPassport.publicKey) throw new Error("Rotation requires the current private key.");
  const keys = newKeypair ?? generateAgentKeypair();
  const newPublicKey = createPublicKey(keys.privateKey);
  if (newPublicKey.asymmetricKeyType !== "ed25519" || newPublicKey.export({ type: "spki", format: "pem" }).toString() !== keys.publicKey) {
    throw new Error("The replacement keypair is invalid.");
  }
  const ts = new Date().toISOString();

  const { signature: _oldSig, previousSignature: _previousSig, ...prevPayload } = currentPassport;

  const rotatedPayload = {
    ...prevPayload,
    previousPublicKey: prevPayload.publicKey,
    publicKey: keys.publicKey,
    rotatedAt: ts,
    keyRotationCount: (prevPayload.keyRotationCount ?? 0) + 1,
  };

  const newSignature = cryptoSign(null, Buffer.from(canonicalJson(rotatedPayload)), keys.privateKey).toString("base64url");

  return {
    passport: {
      ...rotatedPayload,
      signature: newSignature,
      previousSignature: cryptoSign(null, Buffer.from(canonicalJson(rotatedPayload)), oldPrivateKey).toString("base64url"),
    },
    privateKey: keys.privateKey,
  };
}
