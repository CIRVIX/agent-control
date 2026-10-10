/**
 * `cirvix kill` — durable revocation across processes, written to a journal.
 *
 * WHAT THIS USED TO BE. `globalKillSwitch.arm(...)`, a Map inside the CLI
 * process, followed by `process.exit`. The freeze existed for the duration of
 * the command: a gateway running in another process never saw it, a restart
 * forgot it, and there was nothing to audit. "Kill" that only works in the
 * shell you typed it in is a console.
 *
 * WHAT IT IS NOW. An operator act that writes a SIGNED RevocationEvent into
 * the durable journal under the state directory (core/revocation.mjs):
 *
 *   - every enforcement process reads that journal before every decision, so
 *     the freeze is in force on the next call, without a restart;
 *   - the event is signed with the REVOCATION role key and hash-chained to its
 *     predecessor, so a state file is verifiable rather than merely present;
 *   - the manifest's monotonic epoch means restoring an older journal cannot
 *     un-kill anything — a rollback is detected and the boundary fails closed;
 *   - revoking an agent cascades: its enrolled record is marked revoked (the
 *     identity boundary refuses its credentials) and the delegations it issued
 *     are revoked in the delegation store AND as revocation events.
 *
 * `--list` reads the journal, so what an operator sees is what the enforcement
 * processes enforce, not what one process happens to remember.
 */

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { AgentStore } from "../core/identity-store.mjs";
import { DelegationStore } from "../core/delegation-ed25519.mjs";
import { PrincipalStore, signChallenge } from "../core/principal.mjs";
import {
  REVOCATION_ACTION,
  REVOCATION_SCOPE,
  REVOCATION_SCOPES,
  RevocationEngine,
  cascadeRevocation,
} from "../core/revocation.mjs";
import { bold, dim, green, red, amber, cyan } from "../core/format.mjs";

/** Scopes whose revocation must also revoke everything derived from them. */
const CASCADING_SCOPES = new Set([
  REVOCATION_SCOPE.AGENT,
  REVOCATION_SCOPE.IDENTITY,
  REVOCATION_SCOPE.PRINCIPAL,
]);

export async function executeKillCommand({
  stateDir,
  scope = REVOCATION_SCOPE.AGENT,
  target = null,
  reason = "Emergency freeze invoked via CLI",
  release = null,
  /* RELEASE IS A SEPARATE AUTHORITY (P0-C hardening): either an authorization
     a release officer signed elsewhere, or their own key signing a fresh
     challenge here. A bare `--release <id>` no longer undoes a containment. */
  authorization = null,
  principalKey = null,
  /* The release AUTHORITY's private key, kept wherever the release officer
     keeps it (a workstation, a control plane). It is deliberately NOT read
     from the runtime's state directory. */
  releaseKey = null,
  list = false,
  json = false,
  ttlMs = null,
  cascade = true,
  issuer = null,
  principal = null,
  policyVersion = null,
} = {}) {
  if (!stateDir) {
    return {
      output: `\n  ${red("Error:")} A state directory is required — that is where the revocation journal lives. Pass --state or run inside a workspace with .cirvix/.\n`,
      code: 2,
    };
  }

  const engine = await new RevocationEngine({
    stateDir,
    log: () => {},
    // The release path authenticates a PRINCIPAL against the host authority
    // key, so the engine is given the principal store on every CLI act — the
    // refusal then comes from the one authorization implementation, not from a
    // second check written here.
    principalStore: new PrincipalStore(stateDir),
    releaseKey: releaseKey ? { privateKey: await resolvePem(releaseKey) } : null,
  }).init();
  const state = engine.store.verification();

  if (list) {
    const active = engine.list();
    if (json) {
      return { output: JSON.stringify({ active, journal: state }, null, 2), code: state.ok ? 0 : 1 };
    }
    const lines = [
      "",
      `  ${bold("REVOCATION POSTURE")}`,
      "",
      `    ${dim("Journal:")}      ${state.count} event${state.count === 1 ? "" : "s"} · epoch ${state.epoch} · sequence ${state.sequence}`,
      `    ${dim("Integrity:")}    ${state.ok ? green("verified") : red("FAILED — enforcement refuses")}`,
      `    ${dim("State dir:")}    ${stateDir}`,
      "",
    ];
    if (active.length === 0) {
      lines.push(`  ${green("✓")} ${dim("No active revocations.")}`, "");
    } else {
      lines.push(`  ${bold("ACTIVE REVOCATIONS")}`, "");
      for (const event of active) {
        lines.push(
          `  ${red("●")} [${event.scope.toUpperCase()}] ${bold(event.subject)} — ${event.reason ?? "(no reason)"} ${dim(
            `revocationId=${event.revocationId} · issuer=${event.issuer} · seq=${event.sequence}`,
          )}`,
        );
      }
      lines.push("");
    }
    return { output: lines.join("\n"), code: state.ok ? 0 : 1 };
  }

  if (release) {
    try {
      const presented = await buildReleaseAuthorization({ engine, revocationId: release, authorization, principal, principalKey });
      const event = await engine.release({ revocationId: release, reason, authorization: presented });
      if (json) return { output: JSON.stringify(event, null, 2), code: 0 };
      return {
        output: `\n  ${green("✓")} ${dim(`Release recorded for ${release} (event ${event.revocationId}).`)}\n`,
        code: 0,
      };
    } catch (err) {
      if (json) return { output: JSON.stringify({ released: release, error: err.message }), code: 1 };
      return { output: `\n  ${red("✗")} ${dim(err.message)}\n`, code: 1 };
    }
  }

  if (!target) {
    return {
      output: `\n  ${red("Error:")} Specify a target to revoke, e.g. cirvix kill AGENT_ID --scope agent --reason "Suspicious activity"\n  ${dim(`Scopes: ${REVOCATION_SCOPES.join(", ")}`)}\n`,
      code: 2,
    };
  }
  if (!REVOCATION_SCOPES.includes(scope)) {
    return { output: `\n  ${red("Error:")} Unknown scope "${scope}". Known scopes: ${REVOCATION_SCOPES.join(", ")}\n`, code: 2 };
  }

  const operator = issuer ?? principal ?? (process.env.USER || process.env.USERNAME || "operator");

  let events;
  try {
    events = await engine.revoke({
      scope,
      subject: target,
      reason,
      issuer: operator,
      principal: principal ?? operator,
      ttlMs,
      policyVersion,
    });
  } catch (err) {
    if (json) return { output: JSON.stringify({ scope, target, error: err.message }), code: 1 };
    return { output: `\n  ${red("✗")} ${dim(`The revocation could not be recorded: ${err.message}`)}\n`, code: 1 };
  }

  /* THE CASCADE. Marking an agent "killed" while its credentials, delegations
     and derived authority stay usable is not a revocation — it is a label. */
  let derived = [];
  if (cascade && CASCADING_SCOPES.has(scope)) {
    try {
      derived = await cascadeRevocation({
        engine,
        event: events[0],
        delegationStore: await new DelegationStore(stateDir).init(),
        agentStore: new AgentStore(stateDir),
        reason: reason ?? "parent authority revoked",
        issuer: operator,
      });
    } catch (err) {
      derived = [{ kind: "cascade-failed", error: err.message }];
    }
  }

  const record = { events, derived, journal: engine.store.verification() };
  if (json) return { output: JSON.stringify(record, null, 2), code: 0 };

  const lines = [
    "",
    `  ${red(bold("REVOCATION RECORDED"))}`,
    "",
    `    ${dim("Scope:")}        ${scope.toUpperCase()}`,
    `    ${dim("Target:")}       ${bold(target)}`,
    `    ${dim("Reason:")}       ${reason}`,
    `    ${dim("Issuer:")}       ${operator}`,
    `    ${dim("Event ID:")}     ${events[0].revocationId}`,
    `    ${dim("Epoch:")}        ${record.journal.epoch} ${dim(`· sequence ${record.journal.sequence}`)}`,
    `    ${dim("Status:")}       ${red(bold("REVOKED"))} ${dim("(durable — enforced by every process reading this state dir)")}`,
  ];
  if (derived.length) {
    lines.push("", `  ${dim("Cascaded:")}`);
    for (const item of derived) {
      lines.push(`    ${amber("→")} ${item.kind}${item.id ? ` ${item.id}` : ""}${item.agentId ? ` ${item.agentId}` : ""}${item.error ? ` ${red(item.error)}` : ""}`);
    }
  }
  lines.push(
    "",
    `  ${dim("Release requires the release authority:")}`,
    `  ${dim("  cirvix authority release-key register --public-key <release.pub>")}`,
    `  ${dim("  cirvix kill --release " + events[0].revocationId + " --principal <releaseOfficer> --principal-key <their key>")}`,
    "",
  );
  return { output: lines.join("\n"), code: 0 };
}

/** Reads a PEM from inline text, an env reference or a file path. */
async function resolvePem(source) {
  if (typeof source !== "string" || !source) return null;
  if (source.startsWith("env:")) return process.env[source.slice(4)] ?? null;
  if (source.includes("-----BEGIN")) return source;
  return readFile(resolve(source), "utf8");
}

/**
 * Assembles the release authorization, in one place, so the CLI, a script and
 * a control plane all produce the artifact `RevocationEngine.release` checks.
 *
 * The action string comes from the ENGINE (`release:<scope>:<subject>`), not
 * from this file: if the two ever disagreed, an authorization signed for one
 * revocation would verify against another.
 */
async function buildReleaseAuthorization({ engine, revocationId, authorization, principal, principalKey }) {
  if (authorization) {
    const raw = typeof authorization === "string" && authorization.trim().startsWith("{") ? authorization : await resolvePem(authorization);
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      const err = new Error("The --authorization value is not valid JSON.");
      err.code = "authorization_unreadable";
      throw err;
    }
    return { principalId: parsed.principalId, nonce: parsed.nonce ?? null, signature: parsed.signature ?? null, tenantId: parsed.tenantId ?? null };
  }
  if (!principal || !principalKey) {
    const err = new Error(
      "Releasing a revocation requires an authenticated release officer: pass --authorization <file> (signed elsewhere) or --principal <principalId> --principal-key <their key>.",
    );
    err.code = "release_authorization_required";
    throw err;
  }
  const challenge = await engine.issueReleaseChallenge({ principalId: principal, revocationId });
  const pem = await resolvePem(principalKey);
  if (!pem) {
    const err = new Error(`The release officer's key at "${principalKey}" could not be read.`);
    err.code = "principal_key_unreadable";
    throw err;
  }
  return {
    principalId: principal,
    nonce: challenge.nonce,
    signature: signChallenge({ privateKey: pem, principalId: principal, action: challenge.action, nonce: challenge.nonce }),
  };
}

export { REVOCATION_ACTION, REVOCATION_SCOPE };
