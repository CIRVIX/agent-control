/**
 * A governed TOOL-EXECUTION child process.
 *
 * This fixture exists to be an INDEPENDENT EXECUTION ORACLE: the authorization
 * decision happens inside this process, but the EFFECT of the call is a line
 * appended to a separate oracle file. Nothing else in the test writes that
 * file, so:
 *
 *   DENY  => the oracle file gains nothing   (the consequential effect did not
 *                                             occur, observed from outside)
 *   ALLOW => exactly one line appears
 *
 * It is deliberately a separate OS process, so the cross-process revocation
 * test can revoke an agent from a SECOND process and prove the effect stops —
 * rather than proving that a variable changed inside one process.
 *
 * Usage:
 *   node oracle-child.mjs --state <dir> --oracle <file> --rules <file>
 *        [--agent <id>] [--identity] [--delegation] [--revocation] [--mission <file>]
 *        [--authority-context] [--tenant <t>] [--audience <a>] [--policy-version <v>]
 *
 * `--authority-context` is the PRODUCTION shape: the durable mission registry
 * for the tenant, the principal store that resolves who issued a grant, tenant
 * and audience pinning, and a refusal of any root grant with no authenticated
 * issuer principal. It is what `cirvix gateway` and `cirvix runtime` build, so
 * a test that uses it is testing the shipped boundary rather than a class.
 *
 * stdin  (NDJSON): {"id":"c1","tool":"read_file","arguments":{...},"agent":"worker"}
 * stdout (NDJSON): {"id","verdict","rule","executed"}
 */
import { appendFile, readFile } from "node:fs/promises";

function arg(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1] ?? true;
}

const stateDir = arg("state");
const oraclePath = arg("oracle");
const rulesPath = arg("rules");
const agentId = arg("agent", "worker");
const useIdentity = Boolean(arg("identity", false));
const useDelegation = Boolean(arg("delegation", false));
const useRevocation = Boolean(arg("revocation", false));
const missionPath = arg("mission");
const useAuthorityContext = Boolean(arg("authority-context", false));
const tenant = arg("tenant", null);
const audience = arg("audience", null);
const policyVersion = arg("policy-version", null);
const releaseRoleKey = arg("release-key", null);

const { Guard } = await import("../../src/core/guard.mjs");
const { MissionRegistry } = await import("../../src/core/authority.mjs");
const { createCallerVerifier } = await import("../../src/core/identity.mjs");

const rules = JSON.parse(await readFile(rulesPath, "utf8"));
const options = { rules, agent: agentId, cwd: "/workspace", log: () => {} };

if (useIdentity) {
  options.identity = await createCallerVerifier({ stateDir });
  options.identityMode = "production";
}
if (useDelegation) {
  const { Ed25519DelegationVerifier } = await import("../../src/core/delegation-ed25519.mjs");
  options.delegation = await new Ed25519DelegationVerifier({ stateDir }).init();
}
if (useAuthorityContext) {
  const { Ed25519DelegationVerifier } = await import("../../src/core/delegation-ed25519.mjs");
  const { PrincipalStore } = await import("../../src/core/principal.mjs");
  const { MissionStore } = await import("../../src/core/authority-store.mjs");
  const { loadRoleKey, KEY_ROLE } = await import("../../src/core/keys.mjs");
  const authorityKey = await loadRoleKey(stateDir, KEY_ROLE.AUTHORITY).catch(() => null);
  /* CROSS-INSTANCE mode: this host verifies with the ISSUING instance's PUBLIC
     keys alone. No symmetric secret exists on either side. */
  const authorityPublicKey = arg("authority-public-key", null) ? await readFile(arg("authority-public-key"), "utf8") : null;
  const delegationPublicKey = arg("delegation-public-key", null) ? await readFile(arg("delegation-public-key"), "utf8") : null;
  options.delegation = await new Ed25519DelegationVerifier({
    stateDir,
    ...(authorityPublicKey ? { authorityPublicKey } : {}),
    ...(delegationPublicKey ? { delegationPublicKey } : {}),
    expectedTenant: tenant,
    expectedAudience: audience,
    expectedPolicyVersion: policyVersion,
    // A verifier that holds only public keys cannot resolve a principal RECORD
    // it does not have, so the issuer principal is checked where the record
    // lives; here the chain is verified for authenticity, tenant, audience,
    // subject, scope and expiry.
    requireIssuerPrincipal: !arg("allow-anonymous-root", false),
    principalStore: authorityPublicKey ? null : new PrincipalStore(stateDir),
  }).init();
  options.missions = await new MissionStore(stateDir).registry({ tenantId: tenant, authorityPublicKey: authorityKey?.publicKey ?? null });
}
if (useRevocation) {
  const { RevocationEngine } = await import("../../src/core/revocation.mjs");
  const { PrincipalStore } = await import("../../src/core/principal.mjs");
  options.revocation = await new RevocationEngine({
    stateDir,
    log: () => {},
    principalStore: new PrincipalStore(stateDir),
    /* A host that holds the RELEASE role key may release; one that does not
       (the shipped default) can only verify. */
    releaseKey: releaseRoleKey ? { privateKey: await readFile(releaseRoleKey, "utf8") } : null,
  }).init();
}
if (arg("require-authority", false)) options.requireDelegation = true;
if (missionPath) {
  const registry = new MissionRegistry();
  registry.issue(JSON.parse(await readFile(missionPath, "utf8")));
  options.missions = registry;
}

const guard = new Guard(options);

let buffer = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buffer += chunk;
  let index;
  while ((index = buffer.indexOf("\n")) !== -1) {
    const line = buffer.slice(0, index).trim();
    buffer = buffer.slice(index + 1);
    if (line) void handle(line);
  }
});

async function handle(line) {
  let call;
  try {
    call = JSON.parse(line);
  } catch {
    process.stdout.write(JSON.stringify({ id: null, verdict: "deny", rule: "invalid-json", executed: false }) + "\n");
    return;
  }
  const request = { tool: call.tool, args: call.arguments ?? {} };
  if (call.agent != null) request.agent = call.agent;
  if (call.delegation != null) request.delegation = call.delegation;
  const ctx = call.callerMeta ? { callerMeta: call.callerMeta, method: "tools/call", params: call.params ?? {} } : {};

  let result;
  try {
    result = await guard.authorize(request, ctx);
  } catch (err) {
    process.stdout.write(JSON.stringify({ id: call.id, verdict: "error", rule: err.message, executed: false }) + "\n");
    return;
  }

  // THE EFFECT. A denial never reaches this line, which is what makes the
  // oracle file evidence rather than instrumentation.
  let executed = false;
  if (result.decision.verdict === "permit") {
    await appendFile(oraclePath, `${call.id} ${call.tool} ${JSON.stringify(result.args)}\n`, "utf8");
    executed = true;
  }
  process.stdout.write(
    JSON.stringify({
      id: call.id,
      verdict: result.decision.verdict,
      rule: result.decision.rule ?? null,
      executed,
    }) + "\n",
  );
}

process.stdout.write(JSON.stringify({ ready: true }) + "\n");
