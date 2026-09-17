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

export async function doctor({ cwd = process.cwd(), json = false } = {}) {
  const stateDir = join(cwd, ".cirvix");
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
