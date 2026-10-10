/**
 * `cirvix doctor` — diagnose this installation.
 *
 * Every check reports three states: OK, WARN (works but worth fixing) and
 * FAIL (something is broken for real). The exit code is 1 only when at least
 * one check FAILs — a warning should inform, not fail a CI job.
 *
 * Checks run from cheapest/safest to slowest, and the network is touched at
 * most once: control-plane reachability is only probed when a credential file
 * exists, with a hard timeout, because `doctor` must never hang a shell.
 */

import { access, readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

import { parseRules } from "../core/policy.mjs";
import { loadPolicyFile } from "./policy.mjs";
import { detectFleet } from "../adapters/index.mjs";
import { resolveExecutable } from "../core/windows.mjs";
import { AuditChain } from "../core/audit.mjs";
import { UdsClient, defaultEndpoint, tokenPath } from "../core/uds.mjs";
import { loadRoleKey, loadRolePublicKey, KEY_ROLE } from "../core/keys.mjs";
import { AgentStore, AGENT_STATUS } from "../core/identity-store.mjs";
import { IDENTITY_MODE, resolveIdentityMode } from "../core/identity-modes.mjs";
import { RevocationEngine } from "../core/revocation.mjs";
import { Pipeline } from "../core/pipeline.mjs";
import { Gateway } from "../core/gateway.mjs";
import { SessionTracker } from "../core/session.mjs";
import { BehavioralBaseline } from "../core/baseline.mjs";
import { MODE } from "../core/decisions.mjs";
import { STAGE_STATUS, SURFACE_BOUND_STAGES } from "../core/authorize.mjs";
import { resolveAuthorityPosture } from "../core/authority-posture.mjs";
import { HOOK_POSTURE, readHookState, resolveHookPosture } from "../core/hook-posture.mjs";
import { createCallerVerifier } from "../core/identity.mjs";
import { ISSUER_ROLES, RELEASE_ROLES, PrincipalStore, principalStatusAt } from "../core/principal.mjs";
import { MissionStore } from "../core/authority-store.mjs";
import { bold, dim, green, red, amber, gray } from "../core/format.mjs";
import { panel } from "../core/ui/primitives.mjs";

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

/** One probe with a verdict. `fix` is shown verbatim when the check fails. */
function check(name, status, detail, fix) {
  return { name, status: status ?? "warn", detail: detail ?? "", fix };
}

/** GET with a hard timeout. Resolves { ok, status } and never rejects. */
async function probeUrl(url, timeoutMs = 4000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    return { ok: res.ok, status: res.status };
  } catch {
    return { ok: false, status: null };
  } finally {
    clearTimeout(timer);
  }
}

export async function doctor({
  cwd = process.cwd(),
  json = false,
  /* The state directory to inspect. Every other command honours `--state`; a
     doctor that ignored it would report the posture of a DIFFERENT directory
     than the one enforcement is reading, which is worse than no report. */
  stateDir: stateDirOption = null,
  identityModeFlag = undefined,
  revocationPolicy = "deny",
  revocationFeed = null,
  /* The authority-posture inputs, passed explicitly so the derivation here is
     the same one the composition roots run — not a re-guess from env. */
  requireAuthorityFlag = false,
  authorityPolicyFlag = null,
} = {}) {
  const stateDir = stateDirOption ? String(stateDirOption) : join(cwd, ".cirvix");
  const credFile = join(homedir(), ".cirvix", "credentials.json");
  const results = [];
  const nodeMajor = Number(process.versions.node.split(".")[0]);

  /* 1 — runtime itself */
  results.push(
    nodeMajor >= 20
      ? check("Node runtime", "ok", `v${process.versions.node}`)
      : check("Node runtime", "warn", `v${process.versions.node} — 20+ recommended`, "Upgrade Node to 20 or newer."),
  );

  /* 2 — workspace policy */
  let policyPath = null;
  for (const candidate of ["cirvix.policy", "cirvix.policy.json", ".cirvix/policy.json"]) {
    if (await exists(join(cwd, candidate))) { policyPath = join(cwd, candidate); break; }
  }
  if (policyPath) {
    try {
      const loaded = await loadPolicyFile(policyPath, { cwd });
      const rules = loaded.rules ?? [];
      const testMsg = loaded.tests?.length ? `, ${loaded.tests.length} test${loaded.tests.length === 1 ? "" : "s"}` : "";
      results.push(check("Policy file", "ok", `${rules.length} rule${rules.length === 1 ? "" : "s"}${testMsg} (${policyPath})`));
    } catch (err) {
      results.push(check("Policy file", "fail", `${policyPath}: ${String(err?.message ?? err).slice(0, 80)}`, "Check policy syntax, or run `cirvix init --force` to regenerate a starter policy."));
    }
  } else {
    results.push(check("Policy file", "warn", "no cirvix.policy in this workspace", "Run `cirvix init` to detect agents and write a starter policy."));
  }

  /* 2b — agent fleet detection */
  try {
    const fleet = await detectFleet(cwd, { stateDir });
    const detected = fleet.runtimes ?? [];
    if (detected.length === 0) {
      results.push(check("Agent fleet", "ok", "no agent configurations detected (local/generic mode)"));
    } else {
      const ungoverned = detected.filter((d) => !d.isIntegrated);
      if (ungoverned.length === 0) {
        results.push(check("Agent fleet", "ok", `${detected.length} agent${detected.length === 1 ? "" : "s"} detected, all integrated`));
      } else {
        results.push(
          check(
            "Agent fleet",
            "warn",
            `${ungoverned.length} of ${detected.length} agent${detected.length === 1 ? "" : "s"} ungoverned (${ungoverned.map((u) => u.label).join(", ")})`,
            "Run `cirvix init --apply` to automatically configure gateway interception.",
          ),
        );
      }
    }
  } catch (err) {
    results.push(check("Agent fleet", "warn", `fleet discovery error: ${String(err?.message ?? err).slice(0, 60)}`));
  }

  /* 2c — platform engine */
  if (process.platform === "win32") {
    const shell = resolveExecutable("cmd", { cwd }) || resolveExecutable("powershell", { cwd });
    results.push(
      check(
        "Platform engine",
        shell ? "ok" : "warn",
        shell ? `Windows native (named pipes, PATHEXT, process-tree kill)` : "cmd/powershell not found in PATH",
      ),
    );
  } else {
    results.push(check("Platform engine", "ok", `POSIX native (UDS sockets, signal lifecycle)`));
  }

  /* 3 — local state */
  if (await exists(stateDir)) {
    results.push(check("State directory", "ok", stateDir));
    const auditPath = join(stateDir, "audit.jsonl");
    if (await exists(auditPath)) {
      try {
        const chain = new AuditChain(auditPath);
        const verdict = await chain.verify();
        /* verify() returns { ok, records, brokenAt, reason }. This read
           `verdict.invalid ?? verdict.broken` — neither of which it has ever
           returned — so `broken` was always `undefined > 0`, i.e. false, and
           doctor reported "integrity verified" on a TAMPERED chain.
           A false green in the one check whose entire job is detecting
           tampering. */
        const broken = verdict?.ok !== true;
        results.push(
          broken
            ? check(
                "Audit chain",
                "fail",
                verdict?.reason
                  ? String(verdict.reason).slice(0, 90)
                  : `chain breaks at record ${verdict?.brokenAt ?? "?"}`,
                "Do not delete the chain. Run `cirvix audit verify` for the exact record and investigate before removing anything.",
              )
            : check("Audit chain", "ok", `${verdict.records} record${verdict.records === 1 ? "" : "s"} verified to genesis`),
        );
      } catch (err) {
        results.push(check("Audit chain", "warn", String(err?.message ?? err).slice(0, 80)));
      }
    } else {
      results.push(check("Audit chain", "ok", "no decisions recorded yet"));
    }
  } else {
    results.push(check("State directory", "warn", "no .cirvix/ in this workspace", "Run `cirvix init` — it creates state, a starter policy and a gateway config."));
  }

  /* 3b — identity posture */
  try {
    /* The mode a shipped boundary will actually run in. The CLI resolves the
       same way (flag, then env, then PRODUCTION), so this never reports a
       different posture than the gateway enforces. */
    const identityMode = resolveIdentityMode({
      env: process.env.CIRVIX_IDENTITY_MODE,
      flag: identityModeFlag,
    });
    results.push(
      check(
        "Identity mode",
        identityMode === IDENTITY_MODE.PRODUCTION ? "ok" : "warn",
        identityMode +
          (identityMode === IDENTITY_MODE.BOOTSTRAP
            ? " — unverified callers are accepted until enrolment closes this window"
            : identityMode === IDENTITY_MODE.DEV_INSECURE
              ? " — callers are NOT verified (explicit developer compatibility mode)"
              : " — callers must prove who they are"),
      ),
    );
    const authority = await loadRoleKey(stateDir, KEY_ROLE.AUTHORITY);
    if (!authority) {
      results.push(
        check(
          "Agent identity",
          identityMode === IDENTITY_MODE.PRODUCTION ? "warn" : "warn",
          identityMode === IDENTITY_MODE.PRODUCTION
            ? "no agents enrolled — in production mode the gateway REFUSES callers until an agent is enrolled"
            : "no agents enrolled and mode is " + identityMode + " — callers are NOT authenticated (cooperative enforcement only)",
          "Run `cirvix enroll AGENT_ID` so the gateway can verify who is calling.",
        ),
      );
    } else {
      const agents = new AgentStore(stateDir);
      const records = await agents.list();
      const revoked = records.filter((r) => r.status === AGENT_STATUS.REVOKED).length;
      const expired = records.filter((r) => r.expiresAt && Date.parse(r.expiresAt) + 60_000 < Date.now()).length;
      const active = records.filter((r) => r.status === AGENT_STATUS.ACTIVE).length;
      results.push(
        check(
          "Agent identity",
          "ok",
          active + " enrolled agent" + (active === 1 ? "" : "s") +
            (revoked ? ", " + revoked + " revoked" : "") +
            (expired ? ", " + expired + " credential" + (expired === 1 ? "" : "s") + " expired" : ""),
        ),
      );
      if (revoked + expired > 0) {
        results.push(
          check(
            "Identity hygiene",
            "warn",
            revoked + " revoked, " + expired + " expired credential" + (revoked + expired === 1 ? "" : "s"),
            "Re-enrol affected agents; expired credentials deny at the boundary.",
          ),
        );
      }
    }
  } catch (err) {
    results.push(check("Agent identity", "warn", String(err?.message ?? err).slice(0, 80)));
  }

  /* The published policy stamp, if an operator or the control plane wrote one
     (`<state>/policy.stamp.json` as `{ version, hash }`). Absent is reported as
     "nothing published to compare against", never as agreement. */
  const readPolicyStampFile = async (dir) => {
    try {
      const raw = JSON.parse(await readFile(join(dir, "policy.stamp.json"), "utf8"));
      if (!raw || typeof raw !== "object") return null;
      const hash = typeof raw.hash === "string" && raw.hash ? raw.hash : null;
      const version = raw.version ?? raw.policyVersion ?? null;
      return hash || version !== null ? { version, hash } : null;
    } catch {
      return null;
    }
  };

  /* 3c — revocation / kill posture (P0-C).
     Reports the REAL fabric: how many signed events exist, the epoch every
     process is enforcing, whether the journal verifies, and what happens when
     it cannot. "No active revocations" is a fact read from the journal, not
     from a process-local Map that a restart would have emptied. */
  try {
    const engine = await new RevocationEngine({ stateDir, log: () => {} }).init();
    const state = engine.store.verification();
    const active = engine.list();
    if (!state.ok) {
      results.push(
        check(
          "Revocation state",
          "fail",
          state.rollbackDetected
            ? "the revocation journal rolled back or its hash chain is broken — every boundary refuses"
            : "the revocation journal failed verification — every boundary refuses",
          "Investigate .cirvix/revocations/ before restoring service; a rollback is never repaired by deleting state.",
        ),
      );
    } else {
      results.push(
        check(
          "Revocation state",
          "ok",
          state.count + " signed event" + (state.count === 1 ? "" : "s") +
            " · epoch " + state.epoch + " · " + active.length + " active",
        ),
      );
    }
    results.push(
      check(
        "Revocation policy",
        "ok",
        "untrusted state ⇒ " + (revocationPolicy === "hold" ? "HOLD for approval" : "DENY") +
          (revocationFeed ? " (control-plane feed configured)" : " (local journal only)"),
      ),
    );
  } catch (err) {
    results.push(check("Revocation state", "warn", String(err?.message ?? err).slice(0, 80)));
  }

  /* 3d — THE TRUST ANCHORS THIS RUNTIME ACTUALLY HOLDS (P0-B/P0-C).
     An operator must be able to answer "which keys and which principals does
     this process trust?" without reading source. Every line below is read from
     the state directory, so it reports what enforcement will use — including
     the anchors that are ABSENT, which is the answer that matters most after
     an incident. */
  try {
    const held = {};
    for (const role of [
      KEY_ROLE.IDENTITY,
      KEY_ROLE.AUTHORITY,
      KEY_ROLE.DELEGATION,
      KEY_ROLE.REVOCATION,
      KEY_ROLE.RECEIPT,
      KEY_ROLE.POLICY,
    ]) {
      const key = await loadRoleKey(stateDir, role).catch(() => null);
      held[role] = key ? key.keyId ?? "(no key id)" : null;
    }
    const releasePublic = await loadRolePublicKey(stateDir, KEY_ROLE.RELEASE).catch(() => null);
    const anchorLine = Object.entries(held)
      .map(([role, keyId]) => `${role} ${keyId ? keyId : "NONE"}`)
      .join(" · ");
    const missing = Object.entries(held).filter(([, keyId]) => !keyId).map(([role]) => role);
    results.push(
      check(
        "Trust anchors",
        missing.length <= 1 ? "ok" : "warn",
        anchorLine + (releasePublic ? ` · release ${releasePublic.keyId} (public half only)` : " · release NONE"),
        missing.length
          ? `No key for ${missing.join(", ")}: those roles cannot sign or verify anything yet. \`cirvix enroll AGENT_ID\` mints the identity and authority anchors.`
          : undefined,
      ),
    );

    const principals = await new PrincipalStore(stateDir).list();
    const activePrincipals = principals.filter((p) => principalStatusAt(p) === "active");
    const issuers = activePrincipals.filter((p) => ISSUER_ROLES.includes(p.role));
    results.push(
      check(
        "Human authority",
        issuers.length ? "ok" : "warn",
        issuers.length
          ? `${issuers.length} authenticated principal${issuers.length === 1 ? "" : "s"} may issue authority: ${issuers.map((p) => `${p.principalId} (${p.role})`).join(", ")}`
          : "no principal may issue authority — grants and missions cannot be issued on this host",
        issuers.length ? undefined : "Run `cirvix authority principal enroll --id owner@acme --role owner`.",
      ),
    );

    const officers = activePrincipals.filter((p) => RELEASE_ROLES.includes(p.role));
    const releasable = Boolean(releasePublic?.publicKey) && officers.length > 0;
    results.push(
      check(
        "Release authority",
        releasable ? "ok" : "warn",
        releasable
          ? `releases require ${officers.map((p) => p.principalId).join(", ")} AND the registered release key (${releasePublic.keyId})`
          : `releases are IMPOSSIBLE on this host (${!releasePublic?.publicKey ? "no release key registered" : "no release officer enrolled"}) — a containment cannot be undone locally`,
        releasable ? undefined : "Register the release public key with `cirvix authority release-key register --public-key <release.pub>` and enrol a release-officer principal.",
      ),
    );

    const authorityKey = await loadRoleKey(stateDir, KEY_ROLE.AUTHORITY).catch(() => null);
    const missionPosture = await new MissionStore(stateDir).posture({ authorityPublicKey: authorityKey?.publicKey ?? null });
    results.push(
      check(
        "Mission authority",
        missionPosture.unverified ? "fail" : missionPosture.total ? "ok" : "warn",
        missionPosture.unverified
          ? `${missionPosture.unverified} of ${missionPosture.total} mission record(s) are NOT signed by this host's authority key — they are refused, not enforced`
          : `${missionPosture.total} mission${missionPosture.total === 1 ? "" : "s"} · ${missionPosture.active} active, ${missionPosture.expired} expired, ${missionPosture.revoked} revoked` +
            (missionPosture.issuers.length ? ` · issued by ${missionPosture.issuers.map((i) => `${i.principalId} (${i.count})`).join(", ")}` : ""),
        missionPosture.total ? undefined : "Issue one with `cirvix authority mission create --agent <agent> --principal <id> --principal-key <file>`.",
      ),
    );

    if (held[KEY_ROLE.AUTHORITY]) {
      results.push(
        check(
          "Binding strength",
          "warn",
          "COOPERATIVE — keys are 0600 files on this host; identity is cryptographic possession, not process or hardware binding",
          "Hard binding (SO_PEERCRED, process/runtime attestation, OS keychain, TPM/TEE) is not implemented; see SECURITY_INVARIANTS.md.",
        ),
      );
    }

    /* 3d' — THE CLAUDE CODE HOOK'S FAILURE POSTURE (P0-D).
     *
     *  The hook governs Bash, Write and WebFetch — tools the MCP gateway never
     *  sees — and it runs BEFORE the boundary, so what it does when it cannot
     *  reach a decision is a security posture in its own right. It is reported
     *  here, in the same place as every other trust decision, rather than being
     *  a line in a settings file that nobody re-reads. */
    const hookState = await readHookState(stateDir);
    const effectiveHookPosture = hookState?.posture ?? resolveHookPosture({
      fail: process.env.CIRVIX_HOOK_FAIL ?? null,
      identityMode: process.env.CIRVIX_IDENTITY_MODE ?? null,
    }).posture;
    if (!hookState) {
      results.push(
        check(
          "Claude Code hook",
          "warn",
          `posture ${effectiveHookPosture}, but the hook has NEVER RUN against ${stateDir} — nothing installed or exercised it here`,
          "Install the PreToolUse hook (integrations/claude-code) and run `cirvix runtime` so hook calls reach a boundary.",
        ),
      );
    } else if (effectiveHookPosture === HOOK_POSTURE.ENFORCING) {
      results.push(
        check(
          "Claude Code hook",
          "ok",
          `fail-closed (${hookState.source ?? "hardened default"}) · ${hookState.unevaluatedDenied ?? 0} unevaluated call(s) denied`,
          null,
        ),
      );
    } else {
      results.push(
        check(
          "Claude Code hook",
          (hookState.unevaluatedAllowed ?? 0) > 0 ? "error" : "warn",
          `COMPATIBILITY posture (${hookState.source ?? "explicit"}) — unevaluated calls are ALLOWED: ` +
            `${hookState.unevaluatedAllowed ?? 0} of ${hookState.unevaluatedCalls ?? 0} allowed` +
            (hookState.lastUnevaluated ? ` · last ${hookState.lastUnevaluated.tool ?? "(unparsed payload)"} at ${hookState.lastUnevaluated.at} (${hookState.lastUnevaluated.reason})` : ""),
          "Unset CIRVIX_HOOK_FAIL (or leave the dev profile) so unevaluated consequential calls are denied, and run `cirvix runtime` so the hook can reach the boundary.",
        ),
      );
    }

    /* 3e — THE CANONICAL AUTHORIZATION POSTURE (P0-D §9).
     *
     *  A boundary is a set of stages, and the honest question is not "which
     *  features are enabled" but "which stages are actually wired". A stage the
     *  canonical core runs but this boundary has nothing to give is INERT, and
     *  an operator has to be able to see that without reading source — that is
     *  how the two engines drifted apart in the first place (one advertised
     *  controls it never ran).
     *
     *  Reported from `securityPosture()` on the SHIPPED construction, with the
     *  same profile the gateway and the runtime resolve. */
    /*  The durable fabric this host actually has. Constructed for the posture
     *  report rather than shared with 3c above, whose engine is scoped to its
     *  own block — and an uninitialised one here would make the posture
     *  describe a runtime nobody deploys. */
    const postureRevocation = await new RevocationEngine({ stateDir, log: () => {} }).init();
    const canonicalPosture = new Pipeline({
      rules: [],
      cwd,
      /* The posture a SHIPPED boundary resolves, which is what the gateway and
         the runtime are constructed with — not a library default. */
      identity: await createCallerVerifier({ stateDir }),
      /* The same explicit resolution the gateway and the runtime use — never
         inferred from enrolment state. */
      identityMode: resolveIdentityMode({ flag: identityModeFlag, env: process.env.CIRVIX_IDENTITY_MODE }),
      mode: MODE.ENFORCE,
      sessionTracker: new SessionTracker("doctor"),
      baseline: new BehavioralBaseline(),
      /* The durable fabric this host actually has, so the report describes the
         deployed posture rather than an empty shell. */
      revocation: postureRevocation,
      publishedPolicy: await readPolicyStampFile(stateDir),
      compatibility: false,
    }).securityPosture();
    const inert = Object.entries(canonicalPosture.stages)
      .filter(([, status]) => status === STAGE_STATUS.INERT || status === STAGE_STATUS.OPTIONAL)
      .map(([name]) => name);
    /* THE AUTHORITY POSTURE, DERIVED THE SAME WAY THE COMPOSITION ROOTS DERIVE
       IT (P0-D gate item 5). `doctor` must not re-guess: with an authority
       model on this host the hardened default REQUIRED the grant, and a
       policy-only posture here is a named compatibility selection — reported
       as such, never as a silent default. */
    const doctorPosture = await resolveAuthorityPosture({
      requireAuthority: Boolean(requireAuthorityFlag ?? process.env.CIRVIX_REQUIRE_AUTHORITY ?? false),
      authorityPolicy: authorityPolicyFlag ?? process.env.CIRVIX_AUTHORITY_POLICY ?? null,
      principalStore: new PrincipalStore(stateDir),
    });
    /*  The MCP path, reported from the object the CLI actually constructs.
     *  It is a different construction from the socket (it supplies its own
     *  session tracker, baseline and durable tool-drift pin registry), so
     *  reporting only the socket would understate what most traffic meets —
     *  and "drift" in particular is wired HERE and not there (P0-D §9). */
    const gatewayPosture = new Gateway({
      servers: {},
      rules: [],
      cwd,
      identity: await createCallerVerifier({ stateDir }),
      identityMode: resolveIdentityMode({ flag: identityModeFlag, env: process.env.CIRVIX_IDENTITY_MODE }),
      mode: MODE.ENFORCE,
      revocation: postureRevocation,
      publishedPolicy: await readPolicyStampFile(stateDir),
      compatibility: false,
      log: () => {},
    }).securityPosture();

    results.push(
      check(
        "Authorization core",
        canonicalPosture.hardened && gatewayPosture.hardened && doctorPosture.required ? "ok" : "warn",
        `profile ${canonicalPosture.profile} · authority ${doctorPosture.required ? "REQUIRED" : "POLICY-ONLY"}` +
          (doctorPosture.required
            ? ` (REQUIRED via ${doctorPosture.source}: a governed call carrying no signed human authority is refused)`
            : ` (POLICY-ONLY compatibility posture via ${doctorPosture.source}: presented authority is always verified, never required — pass --require-authority or --authority-policy=required to require one)`) +
          (canonicalPosture.hardened ? "" : " · COMPATIBILITY profile (policy-only; a shipped boundary must state a mode)"),
        "The canonical core (core/authorize.mjs) is the one implementation of the stage order; Guard and Pipeline are transport adapters over it. The authority posture is derived once (core/authority-posture.mjs), the same way both composition roots derive it.",
      ),
    );
    results.push(
      check(
        "Stage coverage",
        inert.length ? "warn" : "ok",
        inert.length
          ? `${inert.length} stage(s) not enforcing on this construction: ${inert.join(", ")} — inert means nothing is wired, NOT that the control passed`
          : "every canonical stage is wired and enforcing",
        "Wire a stage with the matching option (sessionTracker, baseline, drift, revocation, approvals, secrets, audit).",
      ),
    );
    /* The same question, per TRANSPORT. Two surfaces that disagree here are the
       defect P0-D exists to remove, so the report states both rather than
       describing one construction and letting the reader assume the other. */
    const surfaces = [
      { name: "local socket", posture: canonicalPosture },
      { name: "MCP gateway", posture: gatewayPosture },
    ].map(({ name, posture }) => {
      const inertHere = Object.entries(posture.stages)
        .filter(([, status]) => status === STAGE_STATUS.INERT)
        .map(([stage]) => stage);
      return `${name}: ${inertHere.length ? `inert ${inertHere.join(", ")}` : "every stage wired"}`;
    });
    /*  A difference is only a finding when NEITHER surface could be excused for
     *  it. `drift` is excused on the socket because that surface owns no tool
     *  definitions to compare; anything else that differs is a control one
     *  boundary has and the other does not, and it is reported as such rather
     *  than flattened into one construction's posture. */
    const differing = Object.keys(canonicalPosture.stages).filter(
      (stage) => canonicalPosture.stages[stage] !== gatewayPosture.stages[stage],
    );
    const unexplained = differing.filter((stage) => {
      const owners = SURFACE_BOUND_STAGES[stage] ?? [];
      return !(owners.includes(canonicalPosture.surface) || owners.includes(gatewayPosture.surface));
    });
    results.push(
      check(
        "Surface parity",
        unexplained.length ? "warn" : "ok",
        surfaces.join(" · ") +
          (unexplained.length
            ? ` — ${unexplained.length} stage(s) differ without a surface reason`
            : differing.length
              ? ` — difference confined to surface-specific stages (${differing.join(", ")})`
              : ""),
        "A stage inert on ONE surface and wired on another is the asymmetry P0-D removes: pass the same dependency to both, or state on the stage why it cannot apply on that surface (SURFACE_BOUND_STAGES in core/authorize.mjs).",
      ),
    );
    results.push(
      check(
        "Policy identity",
        canonicalPosture.policyStamp.publishedHash
          ? canonicalPosture.policyStamp.stale
            ? "error"
            : "ok"
          : "warn",
        canonicalPosture.policyStamp.publishedHash
          ? canonicalPosture.policyStamp.stale
            ? `ENFORCING A STALE POLICY — running ${String(canonicalPosture.policyStamp.policyHash).slice(0, 20)}…, published ${String(canonicalPosture.policyStamp.publishedHash).slice(0, 20)}…; calls are refused with stale-policy`
            : `enforcing the published policy (${String(canonicalPosture.policyStamp.policyHash).slice(0, 20)}…)`
          : `nothing published to compare against (enforcing ${String(canonicalPosture.policyStamp.policyHash).slice(0, 20)}…)`,
        "Publish a stamp at <state>/policy.stamp.json ({ version, hash }) so a runtime can prove which policy it enforces.",
      ),
    );
  } catch (err) {
    results.push(check("Trust anchors", "warn", String(err?.message ?? err).slice(0, 80)));
  }

  /* 4 — runtime liveness */
  const endpoint = defaultEndpoint(stateDir);
  if (await exists(tokenPath(stateDir))) {
    try {
      const client = new UdsClient(endpoint);
      await client.ping();
      results.push(check("Runtime daemon", "ok", endpoint));
    } catch (err) {
      results.push(
        check("Runtime daemon", "warn", `not answering on ${endpoint} — ${String(err?.message ?? err).slice(0, 60)}`, "Start it with `cirvix init` (it launches the runtime) or `cirvix daemon`."),
      );
    }
  } else {
    results.push(check("Runtime daemon", "ok", "not configured (no session token yet)"));
  }

  /* 5 — control-plane credentials */
  let creds = null;
  if (await exists(credFile)) {
    try {
      creds = JSON.parse(await readFile(credFile, "utf8"));
      if (creds && creds.apiKey && String(creds.apiKey).startsWith("cvx_")) {
        results.push(check("Credentials", "ok", `${credFile} (key ${String(creds.apiKey).slice(0, 8)}…)`));
      } else {
        results.push(check("Credentials", "warn", `${credFile} has no usable apiKey`, "Re-run `cirvix login`."));
      }
    } catch (err) {
      results.push(check("Credentials", "fail", `${credFile} is not valid JSON — ${String(err?.message ?? err).slice(0, 60)}`, "Delete the file and run `cirvix login` again."));
    }
  } else {
    results.push(check("Credentials", "ok", "not linked (local-only mode — nothing to fix)"));
  }

  /* 6 — control plane reachability: only probed when a URL is configured */
  const url = creds && creds.controlPlaneUrl ? String(creds.controlPlaneUrl).replace(/\/+$/, "") : null;
  if (url) {
    const probe = await probeUrl(`${url}/health`);
    results.push(
      probe.ok
        ? check("Control plane", "ok", `${url}/health → ${probe.status}`)
        : check("Control plane", probe.status === null ? "warn" : "fail", `${url}/health → ${probe.status ?? "unreachable"}`, "Check your connection, or the deployment's tunnel/origin."),
    );
  }

  const failed = results.filter((r) => r.status === "fail");
  const warned = results.filter((r) => r.status === "warn");

  if (json) {
    process.stdout.write(JSON.stringify({ ok: failed.length === 0, results }, null, 2) + "\n");
    return failed.length === 0 ? 0 : 1;
  }

  const lines = results.map((r) => {
    const mark = r.status === "ok" ? green("✓") : r.status === "fail" ? red("✗") : amber("!");
    return `  ${mark} ${bold(r.name).padEnd(18)} ${gray(r.detail)}`;
  });
  if (!process.stdout.isTTY) {
    // Accessible fallback: marks alone carry no meaning to a screen reader.
    for (const r of results) process.stdout.write(`${r.status.toUpperCase().padEnd(5)} ${r.name} — ${r.detail}${r.fix ? ` (fix: ${r.fix})` : ""}\n`);
  } else {
    process.stdout.write(panel({ title: "CIRVIX DOCTOR", lines }) + "\n");
    for (const r of results.filter((x) => x.fix)) {
      process.stdout.write(`  ${amber("→")} ${bold(r.name)}: ${r.fix}\n`);
    }
  }
  const summary = [
    failed.length ? `${failed.length} failed` : null,
    warned.length ? `${warned.length} warning${warned.length === 1 ? "" : "s"}` : null,
    `${results.length - failed.length - warned.length} ok`,
  ]
    .filter(Boolean)
    .join(", ");
  process.stdout.write(`\n  ${dim(summary)}\n\n`);
  return failed.length === 0 ? 0 : 1;
}
