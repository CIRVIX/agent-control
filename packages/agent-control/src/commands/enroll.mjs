/**
 * `cirvix enroll <agent-id>` — give an agent a verifiable identity.
 *
 * Generates the agent runtime keypair, signs an identity credential with the
 * host authority key, stores the agent record, and writes the runtime private
 * key to the state directory so the runtime can sign its requests.
 *
 * THE OUTPUT IS THE CONTRACT. The credential token is what callers attach to
 * requests; the private key file is what they sign with; the record is what
 * the boundary checks the credential against. Each is printed with its path so
 * the wiring step is copyable rather than guessed.
 */


import { agentIdentityKeyPath, enrollAgent } from "../core/identity.mjs";
import { AgentStore, AGENT_STATUS } from "../core/identity-store.mjs";
import { bold, dim, green, red, gray } from "../core/format.mjs";

/**
 * Enrols one agent.
 *
 * @param {object} opts
 * @param {string} opts.agentId          the identity being created
 * @param {string} opts.stateDir         the state directory (default .cirvix)
 * @param {string} [opts.runtime]        runtime label bound into the credential
 * @param {string} [opts.tenant]         tenant/organisation scope
 * @param {string} [opts.environment]    environment scope
 * @param {string} [opts.owner]          owning principal, recorded not verified
 * @param {number} [opts.ttlHours]       credential lifetime in hours
 * @param {boolean} [opts.json]          machine-readable output
 * @returns {{ result: object, output?: string, exitCode: number }}
 */
export async function enroll({
  agentId,
  stateDir,
  runtime = null,
  tenant = "local",
  environment = "local",
  owner = null,
  ttlHours = null,
  json = false,
  write = (s) => process.stdout.write(s),
} = {}) {
  if (!agentId) {
    const err = { error: "agent_id_required", message: "cirvix enroll needs an agent id." };
    if (json) return { result: err, output: JSON.stringify(err, null, 2), exitCode: 2 };
    write(`\n  ${red("error")}  An enrolment names one agent.\n          Usage: ${bold("cirvix enroll AGENT_ID")} ${dim("(add --runtime, --tenant, --env)")}\n\n`);
    return { result: err, exitCode: 2 };
  }

  try {
    const ttlMs = Number.isFinite(Number(ttlHours)) && Number(ttlHours) !== 0
      ? Number(ttlHours) * 3_600_000
      : undefined;

    const result = await enrollAgent({
      stateDir,
      agentId,
      runtime,
      tenant,
      environment,
      owner,
      ...(ttlMs === undefined ? {} : { ttlMs }),
    });

    // `enrollAgent` owns where the runtime key lives and writes it; this only
    // reports the path, so the CLI and the caller-side loader cannot drift.
    const keyPath = agentIdentityKeyPath(stateDir, agentId);

    const payload = {
      agentId,
      status: result.record.status,
      credentialToken: result.credentialToken,
      identityKeyId: result.identityKeyId,
      issuerKeyId: result.issuerKeyId,
      privateKeyPath: keyPath,
      expiresAt: result.record.expiresAt,
      binding: result.record.binding,
      stateDir,
    };

    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 0 };

    write(
      `\n  ${green("Enrolled")} ${bold(agentId)} ${dim("· binding: " + result.record.binding)}\n\n` +
      `  ${dim("credential")}   ${result.credentialToken}\n\n` +
      `  ${dim("runtime key")}  ${keyPath}\n` +
      `  ${dim("expires")}      ${result.record.expiresAt}\n\n` +
      `  ${dim("Attach the credential and a signed proof to every request:")}\n` +
      `  ${dim("  signRequest({ privateKey: <runtime key>, agentId: \"" + agentId + "\", params })")}\n` +
      `  ${dim("  then send _meta.cirvix = { credential, ...proof } with the call.")}\n\n` +
      `  ${gray("The gateway enforces identity automatically once any agent is enrolled.")}\n\n`,
    );
    return { result: payload, exitCode: 0 };
  } catch (err) {
    const payload = { error: "enroll_failed", message: err.message, agentId };
    if (json) return { result: payload, output: JSON.stringify(payload, null, 2), exitCode: 1 };
    write(`\n  ${red("error")}  ${err.message}\n\n`);
    return { result: payload, exitCode: 1 };
  }
}

/** `cirvix identity` — the enrolled agents on this host, and their state. */
export async function identity({ stateDir, json = false, write = (s) => process.stdout.write(s) } = {}) {
  const agents = new AgentStore(stateDir);
  const records = await agents.list();
  const summary = {
    stateDir,
    count: records.length,
    binding: records[0]?.binding ?? null,
    agents: records.map((r) => ({
      agentId: r.agentId,
      status: r.status,
      runtime: r.runtime ?? null,
      tenant: r.tenant ?? null,
      keyId: r.keyId ?? null,
      issuedAt: r.issuedAt ?? null,
      expiresAt: r.expiresAt ?? null,
      lastSeen: r.lastSeen ?? null,
    })),
  };
  if (json) return { result: summary, output: JSON.stringify(summary, null, 2), exitCode: 0 };
  if (records.length === 0) {
    write(`\n  ${dim("No agents enrolled on this host.")} Start with ${bold("cirvix enroll AGENT_ID")}\n\n`);
    return { result: summary, exitCode: 0 };
  }
  const lines = summary.agents.map(
    (a) =>
      `  ${a.status === AGENT_STATUS.ACTIVE ? green("active  ") : red(a.status)}  ${bold(a.agentId)}` +
      `${a.runtime ? dim("  · " + a.runtime) : ""}${a.tenant ? dim("  · tenant " + a.tenant) : ""}` +
      `\n          ${dim("key " + (a.keyId ?? "none") + "  · expires " + (a.expiresAt ?? "never"))}`,
  );
  write(`\n  ${bold("Enrolled agents")} ${dim("· binding " + (summary.binding ?? "cooperative") + " · " + stateDir)}\n\n${lines.join("\n")}\n\n`);
  return { result: summary, exitCode: 0 };
}
