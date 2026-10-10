/**
 * `cirvix authority …` — the production lifecycle for WHO may authorize WHAT.
 *
 * WHY THIS COMMAND EXISTS. Everything upstream of it was cryptographic and
 * everything downstream of it was enforced, but there was no way for an
 * authenticated person to actually ISSUE authority on a real host:
 *
 *   - a root grant's `human` field was a display name vouched for by the
 *     authority key the runtime itself holds — a string, not a principal;
 *   - `MissionRegistry` was constructed by tests and the escape benchmark, so
 *     on a real deployment authority was inert and policy alone decided;
 *   - a grant could not be listed, inspected or withdrawn from a shell.
 *
 * So "a human authorized this" had no production answer. This module is that
 * answer, and it is deliberately shaped so the answer is checkable:
 *
 *   principal  — an identity SEPARATE from the signing keys: its own key,
 *                role, tenant, status, expiry, revocation state. Enrolled by
 *                the host (the host vouches for the record) but authenticated
 *                by POSSESSION of its own private key over a fresh challenge.
 *   grant      — a signed, narrowing authority chain rooted in one principal id
 *                and bound to an explicit AUDIENCE, tenant, scope, constraints,
 *                policy generation and validity window.
 *   mission    — durable, host-signed capabilities for one agent and tenant,
 *                attributed to the issuing principal.
 *   capability — a bounded slice of one mission, revocable without revoking the
 *                mission around it.
 *   release    — the ONE act that undoes a containment, separated onto its own
 *                key role and its own principal roles.
 *
 * NOTHING HERE TRUSTS A NAME. `--principal dana@acme` is resolved to an
 * enrolled record, and every mutating act carries a signature over a challenge
 * that binds the principal id, the exact action and a single-use nonce. A name
 * that is not enrolled cannot issue anything, and the private key of an
 * enrolled principal is the only thing that can act as it.
 */

import { readFile } from "node:fs/promises";
import { isAbsolute, join } from "node:path";

import { KEY_ROLE, loadRoleKey, loadRolePublicKey, registerRolePublicKey } from "../core/keys.mjs";
import {
  ISSUER_ROLES,
  PRINCIPAL_ERROR,
  PRINCIPAL_KIND,
  PRINCIPAL_ROLE,
  PrincipalStore,
  authenticatePrincipal,
  challengeBody,
  issueChallenge,
  principalStatusAt,
  releaseAuthorities,
  signChallenge,
} from "../core/principal.mjs";
import { DelegationStore, Ed25519DelegationIssuer, Ed25519DelegationVerifier } from "../core/delegation-ed25519.mjs";
import { MissionStore } from "../core/authority-store.mjs";
import { RevocationEngine, REVOCATION_SCOPE } from "../core/revocation.mjs";
import { amber, bold, dim, gray, green, red } from "../core/format.mjs";

/* ------------------------------------------------------------------ */
/*  Shared plumbing                                                    */
/* ------------------------------------------------------------------ */

function fail(code, message, extra = {}) {
  const err = new Error(message);
  err.code = code;
  Object.assign(err, extra);
  return err;
}

/** The host's authority key — the anchor every principal record and mission hangs off. */
async function authorityKey(stateDir) {
  const record = await loadRoleKey(stateDir, KEY_ROLE.AUTHORITY);
  if (!record?.privateKey) {
    throw fail(
      "authority_key_missing",
      `This host has no authority key in ${join(stateDir, "keys")}. Run \`cirvix enroll <agent>\` first: issuance is signed by the host authority key.`,
    );
  }
  return record;
}

/** Reads a PEM (or a private key) from an inline value, an env reference or a file path. */
async function readPem(source, { cwd = process.cwd() } = {}) {
  if (typeof source !== "string" || !source) return null;
  if (source.startsWith("env:")) return process.env[source.slice(4)] ?? null;
  if (source.includes("-----BEGIN")) return source;
  const path = isAbsolute(source) ? source : join(cwd, source);
  return readFile(path, "utf8");
}

/**
 * The authenticated-principal half of every mutating authority act.
 *
 * Two equally valid presentations, ONE verifier:
 *
 *   1. `--principal-key <path|env:VAR|PEM>` — the CLI issues a challenge and
 *      signs it with the principal's own key. This is the person proving
 *      possession, and it is why the key file is meant to live off-host.
 *   2. `--authorization <path|JSON>` — `{principalId, nonce, signature}`,
 *      produced anywhere else (a release officer's workstation, a control
 *      plane) from `cirvix authority challenge`.
 *
 * Either way the same `authenticatePrincipal` runs: record signature, status,
 * expiry, tenant, role, signature over the exact challenge, and replay.
 */
async function authenticateForAction({
  stateDir,
  principalId,
  action,
  principalKey = null,
  authorization = null,
  expectedTenant = null,
  requiredRoles = ISSUER_ROLES,
  cwd = process.cwd(),
  now = null,
}) {
  const store = new PrincipalStore(stateDir);
  const key = await authorityKey(stateDir);

  let presented = null;
  if (principalKey) {
    if (!principalId) throw fail("principal_required", "Presenting a principal key also needs --principal <principalId>.");
    const pem = await readPem(principalKey, { cwd });
    if (!pem) throw fail("principal_key_unreadable", `The principal key at "${principalKey}" could not be read.`);
    const challenge = issueChallenge({ principalId, action });
    let signature;
    try {
      signature = signChallenge({ privateKey: pem, principalId, action, nonce: challenge.nonce });
    } catch (err) {
      /* An unusable key file is a clean refusal with a code, never an OpenSSL
         error escaping as an unexpected failure — the difference matters to a
         script deciding whether to retry or to stop. */
      throw fail("principal_key_unreadable", `The principal key at "${principalKey}" could not be used to sign: ${err.message}`);
    }
    presented = { principalId, nonce: challenge.nonce, signature };
  } else if (authorization) {
    const raw = typeof authorization === "string" && authorization.trim().startsWith("{") ? authorization : await readPem(authorization, { cwd });
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw fail("authorization_unreadable", "The authorization is not valid JSON.");
    }
    presented = { principalId: parsed?.principalId ?? principalId, nonce: parsed?.nonce ?? null, signature: parsed?.signature ?? null };
  } else {
    throw fail(
      "principal_authentication_required",
      `Issuing this act requires an authenticated principal. Pass --principal-key <path> (the principal signs a challenge) or --authorization <file>.`,
    );
  }

  const check = await authenticatePrincipal({
    store,
    authorityPublicKey: key.publicKey,
    authorityKeyId: key.keyId,
    principalId: presented.principalId,
    action,
    nonce: presented.nonce,
    signature: presented.signature,
    requiredRoles,
    expectedTenant,
    now: () => (now ? new Date(now) : new Date()),
  });
  if (!check.authenticated) {
    throw fail(check.code ?? PRINCIPAL_ERROR.BAD_SIGNATURE, `The principal could not be authenticated: ${check.reason}`, { presented });
  }
  return { principal: check.principal, action, store, authorityKey: key, authentication: check.authenticationMethod };
}

/** `--actions a,b --resources r,s`, or `--action`/`--resource` for one axis. */
function scopeFrom(flags) {
  const list = (value) =>
    [].concat(value ?? []).flatMap((v) => (typeof v === "string" ? v.split(",").map((s) => s.trim()).filter(Boolean) : []));
  const actions = list(flags.actions ?? flags.action);
  const resources = list(flags.resources ?? flags.resource ?? flags.path);
  // A grant with no scope is universal within its tenant; say so rather than
  // letting an empty flag silently mean "everything" without a trace.
  if (actions.length === 0 && resources.length === 0) return { actions: ["*"], resources: ["*"] };
  return { actions: actions.length ? actions : ["*"], resources: resources.length ? resources : ["*"] };
}

function parseJsonFlag(value, what) {
  if (value == null) return null;
  if (typeof value === "object") return value;
  try {
    return JSON.parse(value);
  } catch {
    throw fail("invalid_json", `${what} must be valid JSON.`);
  }
}

/* ------------------------------------------------------------------ */
/*  Principals                                                         */
/* ------------------------------------------------------------------ */

async function principalCommand({ stateDir, action, args, flags, json, write, cwd }) {
  const store = new PrincipalStore(stateDir);

  if (action === "enroll") {
    const principalId = flags.id ?? args[0] ?? null;
    if (!principalId) throw fail("principal_id_required", "cirvix authority principal enroll --id <principalId> [--role grant-issuer]");
    const key = await authorityKey(stateDir);
    const operatorPublicKey = await readPem(flags["public-key"], { cwd });
    const enrolled = await store.enroll({
      principalId,
      name: flags.name ?? null,
      kind: flags.kind ?? PRINCIPAL_KIND.HUMAN,
      role: flags.role ?? PRINCIPAL_ROLE.GRANT_ISSUER,
      organizationId: flags.org ?? null,
      tenantId: flags.tenant ?? "local",
      email: flags.email ?? null,
      ...(operatorPublicKey ? { publicKey: operatorPublicKey } : {}),
      expiresAt: flags.expires ?? null,
      authority: key,
    });
    const payload = {
      principalId,
      role: enrolled.record.role,
      kind: enrolled.record.kind,
      tenantId: enrolled.record.tenantId,
      organizationId: enrolled.record.organizationId,
      authenticationMethod: enrolled.record.authenticationMethod,
      keyId: enrolled.principalKeyId,
      expiresAt: enrolled.record.expiresAt,
      recordPath: join(stateDir, "principals"),
      // The private half is returned ONCE and never written into the state
      // directory: if it lived beside the host keys the two would collapse into
      // a single compromise, which is the whole point of separating them.
      privateKey: operatorPublicKey ? null : enrolled.privateKey,
    };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    write(
      `\n  ${green("Enrolled principal")} ${bold(principalId)} ${dim("· role " + enrolled.record.role + " · tenant " + enrolled.record.tenantId)}\n\n` +
        `  ${dim("key id")}   ${enrolled.principalKeyId}\n` +
        (operatorPublicKey
          ? `  ${dim("key")}       registered from the operator's own public key\n`
          : `  ${dim("private")}  ${amber("stored nowhere — keep this, it is the only copy")}\n\n${enrolled.privateKey}\n`) +
        `\n  ${gray("This principal's own key authenticates its acts. The host authority key only vouches for the record.")}\n` +
        `  ${gray("Issue authority with:")} cirvix authority grant issue --principal ${principalId} --principal-key <file> --agent <agent>\n\n`,
    );
    return { result: payload, exitCode: 0 };
  }

  if (action === "list") {
    const records = await store.list();
    const payload = {
      count: records.length,
      principals: records.map((r) => ({
        principalId: r.principalId,
        name: r.name,
        kind: r.kind,
        role: r.role,
        tenantId: r.tenantId ?? null,
        organizationId: r.organizationId ?? null,
        status: principalStatusAt(r),
        keyId: r.keyId,
        issuedAt: r.issuedAt,
        expiresAt: r.expiresAt ?? null,
      })),
    };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    if (records.length === 0) {
      write(`\n  ${dim("No principals on this host.")} Start with ${bold("cirvix authority principal enroll --id owner@acme --role owner")}\n\n`);
      return { result: payload, exitCode: 0 };
    }
    const lines = payload.principals.map(
      (p) =>
        `  ${p.status === "active" ? green("active  ") : red(String(p.status).padEnd(8))}  ${bold(p.principalId)}` +
        `${dim("  · " + p.role)}${dim(p.tenantId ? " · tenant " + p.tenantId : "")}\n          ${dim("key " + p.keyId + "  · expires " + (p.expiresAt ?? "never"))}`,
    );
    write(`\n  ${bold("Principals")} ${dim("· " + stateDir)}\n\n${lines.join("\n")}\n\n`);
    return { result: payload, exitCode: 0 };
  }

  if (action === "show") {
    const principalId = flags.id ?? args[0] ?? null;
    const record = await store.get(principalId);
    if (!record) throw fail("principal_unknown", `No principal "${principalId}" on this host.`);
    const payload = { ...record, computedStatus: principalStatusAt(record) };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    write(
      `\n  ${bold(record.principalId)} ${dim("· " + record.role + " · " + principalStatusAt(record))}\n` +
        `  ${dim("kind")}        ${record.kind}\n` +
        `  ${dim("tenant")}      ${record.tenantId ?? "(none)"}\n` +
        `  ${dim("org")}         ${record.organizationId ?? "(none)"}\n` +
        `  ${dim("auth method")} ${record.authenticationMethod}\n` +
        `  ${dim("key id")}      ${record.keyId}\n` +
        `  ${dim("issued")}      ${record.issuedAt}  ${dim("expires")} ${record.expiresAt ?? "never"}\n\n`,
    );
    return { result: payload, exitCode: 0 };
  }

  if (action === "revoke" || action === "suspend" || action === "activate") {
    const principalId = flags.id ?? args[0] ?? null;
    if (!principalId) throw fail("principal_id_required", `cirvix authority principal ${action} <principalId> --principal <issuer> --principal-key <file>`);
    const status = action === "revoke" ? "revoked" : action === "suspend" ? "suspended" : "active";
    /* Managing principals is an OWNER act, and it is authenticated like every
       other mutating act: withdrawing someone's authority must itself be
       attributable, or an incident review cannot say who did it. */
    const auth = await authenticateForAction({
      stateDir,
      principalId: flags.principal ?? null,
      action: `${action}-principal:${principalId}`,
      principalKey: flags["principal-key"] ?? null,
      authorization: flags.authorization ?? null,
      requiredRoles: [PRINCIPAL_ROLE.OWNER, PRINCIPAL_ROLE.ADMIN],
      cwd,
    });
    const record = await store.setStatus(principalId, status, { reason: flags.reason ?? `${action} via CLI`, by: auth.principal.principalId });
    if (!record) throw fail("principal_unknown", `No principal "${principalId}" on this host.`);
    const payload = { principalId, status: record.status, reason: record.statusReason, by: auth.principal.principalId };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    write(`\n  ${green("Principal updated")} ${bold(principalId)} ${dim("· " + record.status + " · by " + auth.principal.principalId)}\n\n`);
    return { result: payload, exitCode: 0 };
  }

  if (action === "rotate") {
    const principalId = flags.id ?? args[0] ?? null;
    const publicKey = await readPem(flags["public-key"], { cwd });
    if (!principalId || !publicKey) {
      throw fail("public_key_required", "cirvix authority principal rotate <principalId> --public-key <file|PEM>");
    }
    const key = await authorityKey(stateDir);
    const rotated = await store.rotate(principalId, { authority: key, publicKey });
    const payload = { principalId, keyId: rotated.principalKeyId, rotatedFrom: rotated.record.rotateOf };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    write(`\n  ${green("Key rotated")} ${bold(principalId)} ${dim("· new key id " + rotated.principalKeyId)}\n\n`);
    return { result: payload, exitCode: 0 };
  }

  throw fail("unknown_authority_command", `Unknown principal subcommand "${action ?? ""}". Try enroll, list, show, revoke, suspend, activate, rotate.`);
}

/* ------------------------------------------------------------------ */
/*  Release authority                                                  */
/* ------------------------------------------------------------------ */

async function releaseKeyCommand({ stateDir, action, flags, json, write, cwd }) {
  if (action === "register") {
    const publicKey = await readPem(flags["public-key"], { cwd });
    if (!publicKey) throw fail("public_key_required", "cirvix authority release-key register --public-key <file|PEM>");
    const record = await registerRolePublicKey(stateDir, KEY_ROLE.RELEASE, publicKey);
    const payload = { registered: true, role: KEY_ROLE.RELEASE, keyId: record.keyId, publicKeyPath: join(stateDir, "keys", "release.pub.json") };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    write(
      `\n  ${green("Release authority registered")} ${dim("· key id " + record.keyId)}\n\n` +
        `  ${gray("No private material was written: this host can VERIFY releases, not mint them.")}\n\n`,
    );
    return { result: payload, exitCode: 0 };
  }

  if (action === "show") {
    const registered = await loadRolePublicKey(stateDir, KEY_ROLE.RELEASE).catch(() => null);
    const officers = await releaseAuthorities(new PrincipalStore(stateDir));
    const payload = {
      registered: Boolean(registered?.publicKey),
      keyId: registered?.keyId ?? null,
      registeredAt: registered?.registeredAt ?? null,
      releaseOfficers: officers,
    };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    write(
      `\n  ${bold("Release authority")}\n\n` +
        `  ${dim("key")}      ${registered?.publicKey ? registered.keyId + dim("  registered " + (registered.registeredAt ?? "")) : red("none — this host cannot release a containment")}\n` +
        `  ${dim("officers")} ${officers.length ? officers.map((o) => `${o.principalId} (${o.role})`).join(", ") : amber("none")}\n\n`,
    );
    return { result: payload, exitCode: 0 };
  }

  throw fail("unknown_authority_command", `Unknown release-key subcommand "${action ?? ""}". Try register or show.`);
}

/* ------------------------------------------------------------------ */
/*  Grants                                                             */
/* ------------------------------------------------------------------ */

async function issuerFor(stateDir, flags) {
  const issuer = new Ed25519DelegationIssuer({
    stateDir,
    policyVersion: flags["policy-version"] ?? null,
    /* Every CLI-issued root names the authenticated principal that issued it. */
    requireIssuerPrincipal: true,
    defaultAudience: flags.audience ?? null,
  });
  await issuer.init();
  return issuer;
}

async function grantCommand({ stateDir, action, args, flags, json, write, cwd }) {
  if (action === "issue") {
    const agent = flags.agent ?? args[0] ?? null;
    const principalId = flags.principal ?? null;
    if (!agent) throw fail("agent_required", "cirvix authority grant issue --agent <agent> --principal <principalId> --principal-key <file> [--actions a,b --resources r,s]");
    if (!principalId) throw fail("principal_required", "A grant must name the AUTHENTICATED principal that issues it: --principal <principalId>.");

    const scope = scopeFrom(flags);
    const audience = flags.audience ?? null;
    if (!audience) {
      throw fail(
        "audience_required",
        "A grant must name the AUDIENCE it is for (--audience runtime:prod-runner, agent:worker): a boundary pinned to an audience refuses an unbound grant, so authority that names none is authority that travels anywhere.",
      );
    }
    const action_ = `issue-grant:${agent}:${audience}`;
    const auth = await authenticateForAction({
      stateDir,
      principalId,
      action: action_,
      principalKey: flags["principal-key"] ?? null,
      authorization: flags.authorization ?? null,
      expectedTenant: flags.tenant ?? null,
      cwd,
    });

    const issuer = await issuerFor(stateDir, flags);
    const { grant, token } = await issuer.root({
      agent,
      scope,
      tenant: flags.tenant ?? auth.principal.tenantId ?? null,
      human: auth.principal.name ?? principalId,
      principalId: auth.principal.principalId,
      principalRole: auth.principal.role,
      audience,
      purpose: flags.purpose ?? null,
      constraints: parseJsonFlag(flags.constraints, "--constraints"),
      policyVersion: flags["policy-version"] ?? null,
      singleUse: Boolean(flags["single-use"]),
      maxUses: flags["max-uses"] != null ? Number(flags["max-uses"]) : null,
      ttlMs: flags.ttl != null ? Number(flags.ttl) : null,
    });
    const payload = {
      grantId: grant.id,
      subject: grant.subject,
      tenant: grant.tenant,
      audience: grant.audience,
      scope: grant.scope,
      constraints: grant.constraints ?? null,
      issuedAt: grant.issuedAt,
      expiresAt: grant.expiresAt ?? null,
      policyVersion: grant.policyVersion ?? null,
      issuerPrincipalId: grant.issuerPrincipalId,
      issuerRole: grant.issuerRole,
      issuerKeyId: auth.authorityKey.keyId,
      singleUse: grant.singleUse ?? false,
      maxUses: grant.maxUses ?? null,
      token,
    };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    write(
      `\n  ${green("Grant issued")} ${bold(grant.id)}\n\n` +
        `  ${dim("principal")}  ${grant.issuerPrincipalId} ${dim("(" + grant.issuerRole + ")")}\n` +
        `  ${dim("subject")}    ${grant.subject}\n` +
        `  ${dim("tenant")}     ${grant.tenant ?? "(none)"}\n` +
        `  ${dim("audience")}   ${grant.audience}\n` +
        `  ${dim("actions")}    ${grant.scope.actions.join(", ")}\n` +
        `  ${dim("resources")}  ${grant.scope.resources.join(", ")}\n` +
        `  ${dim("expires")}    ${grant.expiresAt ?? "never (bounded by the agent's credential)"}\n\n` +
        `  ${dim("token")}\n  ${token}\n\n` +
        `  ${gray("Present it as _meta.cirvix.delegation (child-first array) on the agent's calls.")}\n\n`,
    );
    return { result: payload, exitCode: 0 };
  }

  if (action === "list") {
    const delegationStore = new DelegationStore(stateDir);
    await delegationStore.init();
    // The consumption ledger is read from disk: a use taken by ANOTHER process
    // is still a use, and reporting it as 0 would understate spent authority.
    await delegationStore.refreshUsage();
    const grants = (await delegationStore.listGrants())
      .filter((g) => (flags.agent ? g.subject === flags.agent : true))
      .filter((g) => (flags.principal ? g.issuerPrincipalId === flags.principal : true));
    const payload = {
      count: grants.length,
      grants: grants.map((g) => ({
        grantId: g.id,
        subject: g.subject,
        issuer: g.issuer,
        issuerPrincipalId: g.issuerPrincipalId ?? null,
        audience: g.audience ?? null,
        tenant: g.tenant ?? null,
        depth: g.depth ?? 0,
        expiresAt: g.expiresAt ?? null,
        revoked: delegationStore.isRevoked(g.id),
        uses: delegationStore.uses(g.id),
        singleUse: g.singleUse ?? false,
        maxUses: g.maxUses ?? null,
      })),
    };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    if (grants.length === 0) {
      write(`\n  ${dim("No grants on this host.")} Issue one with ${bold("cirvix authority grant issue")}\n\n`);
      return { result: payload, exitCode: 0 };
    }
    const lines = payload.grants.map(
      (g) =>
        `  ${g.revoked ? red("revoked ") : green("active  ")}  ${bold(g.grantId)} ${dim("· " + g.subject + " · " + (g.audience ?? "no audience"))}\n` +
        `          ${dim("principal " + (g.issuerPrincipalId ?? "(none)") + " · depth " + g.depth + " · expires " + (g.expiresAt ?? "never"))}`,
    );
    write(`\n  ${bold("Grants")} ${dim("· " + stateDir)}\n\n${lines.join("\n")}\n\n`);
    return { result: payload, exitCode: 0 };
  }

  if (action === "show") {
    const grantId = args[0] ?? flags.id ?? null;
    const store = new DelegationStore(stateDir);
    await store.init();
    await store.refreshUsage();
    const token = store.token(grantId);
    if (!token) throw fail("unknown_grant", `No grant "${grantId}" on this host.`);
    const grant = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString("utf8"));
    const payload = {
      grant,
      revoked: store.isRevoked(grant.id),
      uses: store.uses(grant.id),
      token,
    };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    write(
      `\n  ${bold(grant.id)} ${store.isRevoked(grant.id) ? red("revoked") : green("active")}\n\n` +
        `  ${dim("principal")}  ${grant.issuerPrincipalId ?? "(none)"} ${dim("(" + (grant.issuerRole ?? "?") + ")")}\n` +
        `  ${dim("subject")}    ${grant.subject}  ${dim("· audience " + (grant.audience ?? "(none)"))}\n` +
        `  ${dim("tenant")}     ${grant.tenant ?? "(none)"}\n` +
        `  ${dim("scope")}      ${(grant.scope?.actions ?? []).join(", ")} → ${(grant.scope?.resources ?? []).join(", ")}\n` +
        `  ${dim("policy")}     ${grant.policyVersion ?? "(unpinned)"}\n` +
        `  ${dim("uses")}       ${store.uses(grant.id)}${grant.maxUses ? "/" + grant.maxUses : grant.singleUse ? " (single use)" : ""}\n\n`,
    );
    return { result: payload, exitCode: 0 };
  }

  if (action === "revoke") {
    const grantId = args[0] ?? flags.id ?? null;
    if (!grantId) throw fail("grant_required", "cirvix authority grant revoke <grantId> --principal <issuer> --principal-key <file>");
    const auth = await authenticateForAction({
      stateDir,
      principalId: flags.principal ?? null,
      action: `revoke-grant:${grantId}`,
      principalKey: flags["principal-key"] ?? null,
      authorization: flags.authorization ?? null,
      cwd,
    });
    const store = new DelegationStore(stateDir);
    await store.init();
    const revoked = await store.revoke(grantId, flags.reason ?? `revoked by ${auth.principal.principalId}`);
    /* Durable in BOTH places: the delegation journal (which the verifier checks
       at use time) and the revocation fabric (which every process reads, even
       ones that never loaded the delegation store). */
    const engine = new RevocationEngine({ stateDir });
    await engine.init();
    const [event] = await engine.revoke({
      scope: REVOCATION_SCOPE.DELEGATION,
      subject: grantId,
      reason: flags.reason ?? "grant revoked",
      principal: auth.principal.principalId,
    });
    const payload = { grantId, revoked, cascade: revoked?.length ?? 0, revocationId: event?.revocationId ?? null, by: auth.principal.principalId };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    write(
      `\n  ${green("Grant revoked")} ${bold(grantId)} ${dim("· " + payload.cascade + " derived grant(s) · by " + auth.principal.principalId)}\n` +
        `  ${dim("revocation")} ${payload.revocationId}\n\n`,
    );
    return { result: payload, exitCode: 0 };
  }

  throw fail("unknown_authority_command", `Unknown grant subcommand "${action ?? ""}". Try issue, list, show, revoke.`);
}

/* ------------------------------------------------------------------ */
/*  Missions and capabilities                                          */
/* ------------------------------------------------------------------ */

function capabilityFrom(flags, args) {
  /* `--capability` names the CAPABILITY; `--name` names the mission, and is
     only a fallback so a single-capability mission reads naturally. Naming one
     command's resource with another's flag is how an operator revokes the
     wrong thing, so the two are separable. */
  const name = flags.capability ?? flags.name ?? args[0] ?? null;
  const scope = scopeFrom(flags);
  return {
    ...(name ? { name } : {}),
    actions: scope.actions,
    resources: scope.resources,
    ...(flags.expires ? { expiresAt: flags.expires } : {}),
    ...(flags.conditions ? { conditions: parseJsonFlag(flags.conditions, "--conditions") } : {}),
  };
}

async function missionCommand({ stateDir, action, args, flags, json, write, cwd }) {
  const store = new MissionStore(stateDir);

  if (action === "create") {
    const agent = flags.agent ?? args[0] ?? null;
    if (!agent) throw fail("agent_required", "cirvix authority mission create --agent <agent> --principal <id> --principal-key <file> --actions a,b --resources r,s");
    const tenantId = flags.tenant ?? "local";
    const auth = await authenticateForAction({
      stateDir,
      principalId: flags.principal ?? null,
      action: `issue-mission:${agent}:${tenantId}`,
      principalKey: flags["principal-key"] ?? null,
      authorization: flags.authorization ?? null,
      expectedTenant: tenantId,
      cwd,
    });
    const key = await authorityKey(stateDir);
    const record = await store.issue({
      agent,
      tenantId,
      name: flags.name ?? null,
      objective: flags.objective ?? "",
      capabilities: [capabilityFrom(flags, args.slice(1))],
      constraints: parseJsonFlag(flags.constraints, "--constraints") ?? {},
      ttlMs: flags.ttl != null ? Number(flags.ttl) : null,
      expiresAt: flags.expires ?? null,
      issuerPrincipalId: auth.principal.principalId,
      issuerRole: auth.principal.role,
      authority: key,
    });
    const payload = {
      missionId: record.missionId,
      agent: record.agent,
      tenantId: record.tenantId,
      issuerPrincipalId: record.issuerPrincipalId,
      capabilities: record.capabilities.map((c) => ({ name: c.name, actions: c.scope.actions, resources: c.scope.resources })),
      expiresAt: record.expiresAt,
      recordPath: join(stateDir, "missions", `${record.missionId}.json`),
    };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    write(
      `\n  ${green("Mission issued")} ${bold(record.missionId)}\n\n` +
        `  ${dim("agent")}      ${record.agent}\n` +
        `  ${dim("tenant")}     ${record.tenantId}\n` +
        `  ${dim("principal")}  ${record.issuerPrincipalId} ${dim("(" + record.issuerRole + ")")}\n` +
        `  ${dim("expires")}    ${record.expiresAt ?? "never"}\n` +
        `  ${dim("record")}     ${payload.recordPath}\n\n` +
        `  ${gray("A boundary pinned to this tenant loads it automatically; a call outside its capabilities is refused.")}\n\n`,
    );
    return { result: payload, exitCode: 0 };
  }

  if (action === "list") {
    const records = await store.list({ tenantId: flags.tenant ?? null, agent: flags.agent ?? null });
    const payload = {
      count: records.length,
      missions: records.map((r) => ({
        missionId: r.missionId,
        agent: r.agent,
        tenantId: r.tenantId,
        status: store.statusAt(r),
        issuerPrincipalId: r.issuerPrincipalId,
        capabilities: r.capabilities.map((c) => c.name),
        expiresAt: r.expiresAt ?? null,
      })),
    };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    if (records.length === 0) {
      write(`\n  ${dim("No missions on this host.")} Issue one with ${bold("cirvix authority mission create")}\n\n`);
      return { result: payload, exitCode: 0 };
    }
    const lines = payload.missions.map(
      (m) =>
        `  ${m.status === "active" ? green("active  ") : red(String(m.status).padEnd(8))}  ${bold(m.missionId)} ${dim("· " + m.agent)}\n` +
        `          ${dim("principal " + m.issuerPrincipalId + " · " + m.capabilities.join(", "))}`,
    );
    write(`\n  ${bold("Missions")} ${dim("· " + stateDir)}\n\n${lines.join("\n")}\n\n`);
    return { result: payload, exitCode: 0 };
  }

  if (action === "show") {
    const missionId = args[0] ?? flags.id ?? null;
    const record = await store.get(missionId);
    if (!record) throw fail("unknown_mission", `No mission "${missionId}" on this host.`);
    const key = await loadRoleKey(stateDir, KEY_ROLE.AUTHORITY);
    const verification = key ? store.verify(record, key.publicKey) : { ok: false, reason: "no authority key to verify with" };
    const payload = { record, verified: verification.ok, verification, status: store.statusAt(record) };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    write(
      `\n  ${bold(record.missionId)} ${store.statusAt(record) === "active" ? green("active") : red(store.statusAt(record))} ${verification.ok ? green("signed") : red("UNVERIFIED: " + verification.reason)}\n\n` +
        `  ${dim("agent")}      ${record.agent}\n  ${dim("tenant")}     ${record.tenantId}\n  ${dim("principal")}  ${record.issuerPrincipalId}\n` +
        `  ${dim("expires")}    ${record.expiresAt ?? "never"}\n\n`,
    );
    return { result: payload, exitCode: 0 };
  }

  if (action === "revoke") {
    const missionId = args[0] ?? flags.id ?? null;
    const auth = await authenticateForAction({
      stateDir,
      principalId: flags.principal ?? null,
      action: `revoke-mission:${missionId}`,
      principalKey: flags["principal-key"] ?? null,
      authorization: flags.authorization ?? null,
      cwd,
    });
    const key = await authorityKey(stateDir);
    const record = await store.revoke(missionId, { reason: flags.reason ?? "revoked via CLI", authority: key, issuerPrincipalId: auth.principal.principalId });
    if (!record) throw fail("unknown_mission", `No mission "${missionId}" on this host.`);
    /* Both places again: the durable record (which the boundary loads) and the
       revocation fabric (which every process reads, including ones pinned to a
       different tenant). */
    const engine = new RevocationEngine({ stateDir });
    await engine.init();
    const [event] = await engine.revoke({
      scope: REVOCATION_SCOPE.MISSION,
      subject: missionId,
      tenant: record.tenantId ?? null,
      reason: flags.reason ?? "mission revoked",
      principal: auth.principal.principalId,
    });
    const payload = { missionId, status: record.status, revocationId: event?.revocationId ?? null, by: auth.principal.principalId };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    write(`\n  ${green("Mission revoked")} ${bold(missionId)} ${dim("· by " + auth.principal.principalId + " · revocation " + payload.revocationId)}\n\n`);
    return { result: payload, exitCode: 0 };
  }

  if (action === "rotate") {
    const missionId = args[0] ?? flags.id ?? null;
    const auth = await authenticateForAction({
      stateDir,
      principalId: flags.principal ?? null,
      action: `rotate-mission:${missionId}`,
      principalKey: flags["principal-key"] ?? null,
      authorization: flags.authorization ?? null,
      cwd,
    });
    const key = await authorityKey(stateDir);
    const record = await store.rotate(missionId, {
      ttlMs: flags.ttl != null ? Number(flags.ttl) : null,
      expiresAt: flags.expires ?? null,
      authority: key,
      issuerPrincipalId: auth.principal.principalId,
    });
    if (!record) throw fail("unknown_mission", `No mission "${missionId}" on this host.`);
    const payload = { missionId, expiresAt: record.expiresAt, by: auth.principal.principalId };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
    write(`\n  ${green("Mission rotated")} ${bold(missionId)} ${dim("· expires " + record.expiresAt)}\n\n`);
    return { result: payload, exitCode: 0 };
  }

  if (action === "capability") {
    const verb = args[0] ?? null;
    const missionId = flags.mission ?? args[1] ?? null;
    if (verb === "issue") {
      const auth = await authenticateForAction({
        stateDir,
        principalId: flags.principal ?? null,
        action: `issue-capability:${missionId}`,
        principalKey: flags["principal-key"] ?? null,
        authorization: flags.authorization ?? null,
        cwd,
      });
      const key = await authorityKey(stateDir);
      const record = await store.addCapability(missionId, capabilityFrom(flags, args.slice(2)), {
        authority: key,
        issuerPrincipalId: auth.principal.principalId,
      });
      if (!record) throw fail("unknown_mission", `No mission "${missionId}" on this host.`);
      const payload = { missionId, capabilities: record.capabilities.map((c) => c.name), by: auth.principal.principalId };
      if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
      write(`\n  ${green("Capability issued")} ${dim("· mission " + missionId + " · " + payload.capabilities.join(", "))}\n\n`);
      return { result: payload, exitCode: 0 };
    }
    if (verb === "revoke") {
      const name = flags.capability ?? flags.name ?? args[2] ?? null;
      const auth = await authenticateForAction({
        stateDir,
        principalId: flags.principal ?? null,
        action: `revoke-capability:${missionId}:${name}`,
        principalKey: flags["principal-key"] ?? null,
        authorization: flags.authorization ?? null,
        cwd,
      });
      const key = await authorityKey(stateDir);
      const record = await store.revokeCapability(missionId, name, {
        reason: flags.reason ?? "capability revoked via CLI",
        authority: key,
        issuerPrincipalId: auth.principal.principalId,
      });
      if (!record) throw fail("unknown_capability", `Mission "${missionId}" has no capability "${name}".`);
      /* The revocation fabric also gets a CAPABILITY event, so a process that
         never loaded the mission record still refuses the call. */
      const engine = new RevocationEngine({ stateDir });
      await engine.init();
      const [event] = await engine.revoke({
        scope: REVOCATION_SCOPE.CAPABILITY,
        subject: name,
        tenant: record.tenantId ?? null,
        reason: flags.reason ?? "capability revoked",
        principal: auth.principal.principalId,
      });
      const payload = { missionId, capability: name, revocationId: event?.revocationId ?? null, by: auth.principal.principalId };
      if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
      write(`\n  ${green("Capability revoked")} ${bold(name)} ${dim("· mission " + missionId + " · revocation " + payload.revocationId)}\n\n`);
      return { result: payload, exitCode: 0 };
    }
    if (verb === "list") {
      const record = await store.get(missionId);
      if (!record) throw fail("unknown_mission", `No mission "${missionId}" on this host.`);
      const payload = {
        missionId,
        capabilities: record.capabilities.map((c) => ({ name: c.name, actions: c.scope.actions, resources: c.scope.resources, status: c.status })),
      };
      if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
      write(`\n  ${bold("Capabilities")} ${dim("· " + missionId)}\n\n${payload.capabilities.map((c) => `  ${c.status === "active" ? green("active  ") : red(c.status)}  ${c.name} ${dim("· " + c.actions.join(",") + " → " + c.resources.join(","))}`).join("\n")}\n\n`);
      return { result: payload, exitCode: 0 };
    }
    throw fail("unknown_authority_command", `Unknown capability subcommand "${verb ?? ""}". Try issue, revoke, list.`);
  }

  throw fail("unknown_authority_command", `Unknown mission subcommand "${action ?? ""}". Try create, list, show, revoke, rotate, capability.`);
}

/* ------------------------------------------------------------------ */
/*  Challenges (so a release officer can sign off-host)                */
/* ------------------------------------------------------------------ */

async function challengeCommand({ stateDir, args, flags, json, write }) {
  const principalId = flags.principal ?? args[0] ?? null;
  const action = flags.action ?? args[1] ?? null;
  if (!principalId || !action) throw fail("challenge_requires_action", "cirvix authority challenge --principal <id> --action <action>");
  const challenge = issueChallenge({ principalId, action });
  const payload = { principalId, action, nonce: challenge.nonce, body: challengeBody({ principalId, action, nonce: challenge.nonce }), issuedAt: challenge.issuedAt };
  if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };
  write(
    `\n  ${bold("Sign this exact body")} ${dim("· single use")}\n\n  ${challengeBody({ principalId, action, nonce: challenge.nonce })}\n\n` +
      `  ${dim("then present it as")} --authorization '{"principalId":"${principalId}","nonce":"${challenge.nonce}","signature":"<base64url>"}'\n\n`,
  );
  return { result: payload, exitCode: 0 };
}

/* ------------------------------------------------------------------ */
/*  Entry point                                                        */
/* ------------------------------------------------------------------ */

/**
 * Dispatches `cirvix authority <group> [action] …`.
 *
 * Every group returns `{ output | result, code }` like the other command
 * modules, and every refusal is a coded error rather than a printed warning:
 * a caller scripting authority lifecycle must be able to tell "refused" from
 * "done".
 */
export async function executeAuthorityCommand({ stateDir, group, action = null, args = [], flags = {}, json = false, cwd = process.cwd() } = {}) {
  const write = (s) => process.stdout.write(s);
  const ctx = { stateDir, action, args, flags, json, write, cwd };
  try {
    let outcome;
    switch (group) {
      case "principal":
        outcome = await principalCommand(ctx);
        break;
      case "release-key":
      case "release":
        outcome = await releaseKeyCommand(ctx);
        break;
      case "grant":
        outcome = await grantCommand(ctx);
        break;
      case "mission":
        outcome = await missionCommand(ctx);
        break;
      case "challenge":
        outcome = await challengeCommand({ stateDir, args: [action, ...args], flags, json, write });
        break;
      case "verify":
        outcome = await verifyCommand({ stateDir, args: [action, ...args], flags, json, write });
        break;
      default:
        throw fail(
          "unknown_authority_command",
          `Unknown authority group "${group ?? ""}". Try principal, grant, mission, release-key, challenge, verify.`,
        );
    }
    return { result: outcome.result, output: outcome.output, code: outcome.exitCode ?? 0 };
  } catch (err) {
    const payload = { error: err.code ?? "authority_failed", message: err.message };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), code: 1 };
    write(`\n  ${red("error")}  ${err.message}\n${err.code ? `          ${dim("code: " + err.code)}\n` : ""}\n`);
    return { result: payload, code: 1 };
  }
}

/**
 * `cirvix authority verify <grantId|token>` — resolve a chain the way a
 * boundary would, and say WHO issued it, for WHICH audience and tenant, and
 * whether the principal behind it still exists and is active.
 */
async function verifyCommand({ stateDir, args, flags, json, write }) {
  const presented = args[0] ?? flags.token ?? null;
  if (!presented) throw fail("grant_required", "cirvix authority verify <grantId|token> [--agent <presenter> --audience <a> --tenant <t>]");
  const key = await loadRoleKey(stateDir, KEY_ROLE.AUTHORITY);
  const delegation = await loadRoleKey(stateDir, KEY_ROLE.DELEGATION);
  const verifier = new Ed25519DelegationVerifier({
    stateDir,
    authorityPublicKey: key?.publicKey ?? null,
    delegationPublicKey: delegation?.publicKey ?? null,
    expectedTenant: flags.tenant ?? null,
    expectedAudience: flags.audience ?? null,
    requireIssuerPrincipal: !flags["allow-anonymous-root"],
    principalStore: new PrincipalStore(stateDir),
  });
  await verifier.init();
  /* A grant ID is what an operator has in hand after issuing; the stored token
     is looked up so `verify <grantId>` and `verify <token>` are the same act. */
  let tokens;
  if (Array.isArray(presented)) {
    tokens = presented;
  } else if (typeof presented === "string" && !presented.includes(".")) {
    const store = new DelegationStore(stateDir);
    await store.init();
    const token = store.token(presented);
    if (!token) throw fail("unknown_grant", `No grant "${presented}" on this host.`);
    tokens = [token];
  } else {
    tokens = [presented];
  }
  const resolved = await verifier.resolve(tokens, flags.agent ?? args[1] ?? null);
  const payload = resolved;
  if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: resolved?.ok ? 0 : 1 };
  if (!resolved?.ok) {
    write(`\n  ${red("refused")}  ${resolved?.reason ?? "the chain does not resolve"}\n${resolved?.error ? `          ${dim("code: " + resolved.error)}\n` : ""}\n`);
    return { result: payload, exitCode: 1 };
  }
  write(
    `\n  ${green("verified")}  ${dim("· " + resolved.scope.actions.join(",") + " → " + resolved.scope.resources.join(","))}\n\n` +
      `  ${dim("principal")}  ${resolved.issuerPrincipalId ?? "(none)"} ${dim("(" + (resolved.issuerRole ?? "?") + ")")}\n` +
      `  ${dim("audience")}   ${resolved.audience ?? "(none)"}\n` +
      `  ${dim("path")}       ${resolved.principals.join(" → ")}\n\n`,
  );
  return { result: payload, exitCode: 0 };
}
