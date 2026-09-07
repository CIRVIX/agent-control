/**
 * The default `cirvix` experience.
 *
 * Runs when someone types `cirvix` with no command — which is how every new
 * user starts and how returning users check in. It must therefore answer two
 * questions in under a second, entirely from local state (no network — that is
 * `cirvix doctor`'s job):
 *
 *   1. Is AgentControl protecting anything on this machine right now?
 *   2. What is the one sensible next action?
 *
 * FIRST RUN has no state directory at all, and gets an onboarding path:
 * welcome → what CIRVIX is in one line → three commands that take them from
 * zero to protected. RETURNING runs get a measured digest — every number here
 * comes from the journal and the runtime probe, never asserted.
 *
 * Output is plain (no animations of its own): this screen renders on every
 * launch, and a delay here would be paid on every launch. Anything animated
 * lives behind commands the user chose deliberately (demo, live).
 */

import { access } from "node:fs/promises";
import { join } from "node:path";

import { bold, dim, green, gray, cyan, red } from "../core/format.mjs";
import { brandHeader, panel, separator } from "../core/ui/primitives.mjs";
import { status as statusCmd } from "./status.mjs";
import { readCredentials, DEFAULT_CONTROL_PLANE, DASHBOARD_URL } from "./login.mjs";

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export async function welcome({ cwd = process.cwd(), json = false } = {}) {
  if (json) {
    // `cirvix --json` still needs a machine-readable default.
    const st = await statusCmd({ cwd, json: true }).catch(() => null);
    process.stdout.write(typeof st === "string" ? st : JSON.stringify({ command: "welcome" }) + "\n");
    return 0;
  }

  const stateDir = join(cwd, ".cirvix");
  const firstRun = !(await exists(stateDir));
  const creds = await readCredentials();

  process.stdout.write(brandHeader() + "\n");

  if (firstRun) {
    process.stdout.write(
      [
        "",
        `  ${bold("Welcome to CIRVIX.")}`,
        `  ${dim("A security boundary between your AI agents and everything they touch.")}`,
        "",
        `  ${dim("This workspace is not protected yet. Three commands fix that:")}`,
        "",
        `  ${cyan("1.")} ${bold("cirvix init")}      ${dim("detect agents & MCP servers, write a policy, start protecting")}`,
        `  ${cyan("2.")} ${bold("cirvix demo")}      ${dim("watch an injected exfiltration attempt get stopped, live")}`,
        `  ${cyan("3.")} ${bold("cirvix status")}    ${dim("what is protected, what was blocked, at what cost")}`,
        "",
        `  ${dim("Or see everything:")} ${bold("cirvix --help")}`,
        "",
      ].join("\n"),
    );
    if (!creds) {
      process.stdout.write(
        [
          "",
          `  ${dim("When you are ready to govern a whole team:")}`,
          `  ${bold("cirvix login")}      ${dim(`link this machine · ${DASHBOARD_URL.replace("https://", "")}`)}`,
          "",
        ].join("\n"),
      );
    }
    return 0;
  }

  /* Returning run: measured digest from the same source `cirvix status` uses. */
  let digest = null;
  try {
    digest = (await statusCmd({ cwd })).output;
  } catch {
    digest = null;
  }
  if (digest) process.stdout.write(digest.trimEnd() + "\n\n");

  const next = [];
  if (digest && /RUNNING/i.test(String(digest))) {
    next.push(["cirvix status", "the full picture: decisions, latency, approvals"]);
    if (/approvals?\s+[1-9]/i.test(String(digest))) next.push(["cirvix approvals", "actions are waiting for a human decision"]);
    next.push(["cirvix logs --last 10", "the most recent decisions, with reasons"]);
  } else {
    next.push(["cirvix init", "detect agents and start protecting this workspace"]);
  }
  if (!creds) next.push(["cirvix login", `link this machine to ${DEFAULT_CONTROL_PLANE.replace("https://", "")}`]);

  const lines = next.map(([cmd, why]) => `  ${cyan("$")} ${bold(cmd.padEnd(22))} ${gray(why)}`);
  process.stdout.write(panel({ title: "NEXT STEPS", lines }) + "\n\n");
  return 0;
}
