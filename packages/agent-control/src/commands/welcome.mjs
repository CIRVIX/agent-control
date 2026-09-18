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
 * The screen itself renders plain and instantly: it runs on every launch, so a
 * delay here would be paid on every launch. The one exception is the brand
 * plate, which is owned by `core/ui/launch.mjs`, plays only in a real terminal,
 * is bounded to under a second, is skipped by any keypress, and is skipped
 * outright for `--fast`, `--no-animation`, `CIRVIX_NO_ANIM`, `NO_COLOR`,
 * CI, a pipe, or a terminal too narrow to hold the box.
 */

import { access, readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { bold, dim, green, gray, cyan, amber, red } from "../core/format.mjs";
import { glyphs, boxChars } from "../core/ui/theme.mjs";
import { launchBanner } from "../core/ui/launch.mjs";
import { status as statusCmd } from "./status.mjs";
import * as journal from "../core/journal.mjs";
import { UdsClient, defaultEndpoint, tokenPath } from "../core/uds.mjs";

const VERSION = (() => {
  try {
    return JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")).version;
  } catch {
    return "0.2.2";
  }
})();

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function checkRuntime(stateDir) {
  const endpoint = defaultEndpoint(stateDir);
  const tp = tokenPath(stateDir);
  if (!(await exists(tp))) return false;
  try {
    const token = (await readFile(tp, "utf8")).trim();
    const client = new UdsClient({ endpoint, token, timeoutMs: 800 });
    const res = await client.call("cirvix/status", {});
    return Boolean(res);
  } catch {
    return false;
  }
}

/**
 * Everything the home screen reports, read from local state only.
 *
 * Split out so the launch sequence can play *while* this runs: the runtime probe
 * alone waits up to 800ms on a socket, and drawing over that wait rather than
 * blocking through it is the difference between an opening and a hang.
 */
async function collectState({ cwd, stateDir }) {
  // Detect agents and MCP servers
  let fleet = { runtimes: [], mcpServers: [] };
  try {
    const { detectFleet } = await import("../adapters/index.mjs");
    fleet = await detectFleet(cwd, { stateDir });
  } catch {}

  // Check policy and runtime state
  const hasPolicy = (await exists(join(cwd, "cirvix.policy"))) ||
                    (await exists(join(cwd, "cirvix.policy.json"))) ||
                    (await exists(join(stateDir, "policy.json")));
  const isRuntimeUp = await checkRuntime(stateDir);

  // Read quick activity summary if audit records exist
  let activitySummary = null;
  const auditPath = join(stateDir, "audit.jsonl");
  if (await exists(auditPath)) {
    try {
      const records = await journal.read(auditPath);
      if (records.length > 0) {
        const stats = journal.summarize(records);
        activitySummary = `${stats.counts?.allow ?? 0} allowed  ·  ${stats.counts?.sanitize ?? 0} sanitized  ·  ${stats.counts?.deny ?? 0} blocked`;
      }
    } catch {}
  }

  return { fleet, hasPolicy, isRuntimeUp, activitySummary };
}

export async function welcome({
  cwd = process.cwd(),
  json = false,
  stdin = process.stdin,
  stdout = process.stdout,
  pace,
  animate,
} = {}) {
  if (json) {
    const st = await statusCmd({ cwd, json: true }).catch(() => null);
    stdout.write(typeof st === "string" ? st : JSON.stringify({ command: "welcome", version: VERSION, cwd }) + "\n");
    return 0;
  }

  const stateDir = join(cwd, ".cirvix");
  const g = glyphs();
  const ch = boxChars();

  // The launch plays while local state is read, not before it.
  const statePromise = collectState({ cwd, stateDir });
  const { animated } = await launchBanner({ stdout, stdin, pace, force: animate });
  const { fleet, hasPolicy, isRuntimeUp, activitySummary } = await statePromise;

  const isProtected = hasPolicy;

  const protectionBadge = isProtected ? green(bold("ACTIVE")) : amber(bold("NOT ACTIVE"));
  const runtimeBadge = isRuntimeUp ? green(bold("● RUNNING")) : dim("○ STOPPED");

  const detectedAgents = (fleet.runtimes ?? []).map((r) => r.label);
  const agentText = detectedAgents.length > 0
    ? `${detectedAgents.length} detected ${dim(`(${detectedAgents.join(", ")})`)}`
    : dim("none detected");
  const mcpCount = (fleet.mcpServers ?? []).length;
  const mcpText = mcpCount > 0 ? `${mcpCount} configured` : dim("none configured");

  const lines = [""];
  if (animated) {
    // The plate above already carries the wordmark and the subtitle; repeating
    // them here would print the brand twice in two different styles.
    lines.push(`  ${bold(`v${VERSION}`)} ${dim("· Runtime authorization for AI agents.")}`);
  } else {
    lines.push(`  ${cyan(bold(g.diamond + " CIRVIX"))} ${bold(`v${VERSION}`)}`);
    lines.push(`  ${bold("AI AGENT RUNTIME GOVERNANCE")} ${dim("· Runtime authorization for AI agents.")}`);
  }
  lines.push(
    "",
    `  ${dim("Protect your AI agents before they touch files,")}`,
    `  ${dim("credentials, APIs, or other tools.")}`,
    "",
    `  ${dim(ch.h.repeat(58))}`,
    "",
    `  ${bold("Workspace:")}    ${cwd}`,
    `  ${bold("Protection:")}   ${protectionBadge}`,
    `  ${bold("Runtime:")}      ${runtimeBadge}`,
    `  ${bold("Agents:")}       ${agentText}`,
    `  ${bold("MCP Servers:")}  ${mcpText}`,
  );

  if (activitySummary) {
    lines.push(`  ${bold("Decisions:")}    ${dim(activitySummary)}`);
  }

  lines.push("");

  if (!isProtected) {
    lines.push(`  ${amber("Cirvix is installed, but this workspace is not protected yet.")}`);
    lines.push(`  ${dim("→ Run 'cirvix init' to generate policy and start protecting.")}`);
    lines.push("");
  }

  lines.push(`  ${bold("GET STARTED")}`);
  lines.push("");
  lines.push(`    ${cyan("1")}  ${bold("cirvix init")}       ${dim("Protect this workspace & generate policy")}`);
  lines.push(`    ${cyan("2")}  ${bold("cirvix demo")}       ${dim("See Cirvix intercept & stop an attack live")}`);
  lines.push(`    ${cyan("3")}  ${bold("cirvix console")}    ${dim("Open interactive authorization console")}`);
  lines.push(`    ${cyan("4")}  ${bold("cirvix status")}     ${dim("Check runtime health, rules, and telemetry")}`);
  lines.push(`    ${cyan("5")}  ${bold("cirvix --help")}     ${dim("View command reference and documentation")}`);
  lines.push("");
  lines.push(`  ${dim(ch.h.repeat(58))}`);
  lines.push("");
  lines.push(`  ${dim("? Help:")} ${bold("cirvix --help")}   ${dim("q Quit:")} ${bold("Ctrl+C")}`);
  lines.push("");

  stdout.write(lines.join("\n"));

  // If stdin and stdout are interactive TTY, allow one-key action
  const isInteractiveTTY = stdin.isTTY && stdout.isTTY && !process.env.CI && process.env.TERM !== "dumb";
  if (isInteractiveTTY && typeof stdin.setRawMode === "function") {
    stdout.write(`  ${dim("Choose an option (1-5, or q to quit): ")}`);
    return new Promise((resolve) => {
      let cleaned = false;
      const cleanup = () => {
        if (cleaned) return;
        cleaned = true;
        try { stdin.setRawMode(false); } catch {}
        try { stdin.pause(); } catch {}
        stdin.removeListener("data", onKey);
      };

      const onKey = async (chunk) => {
        const char = chunk.toString("utf8");
        cleanup();
        stdout.write("\n\n");

        if (char === "\x03" || char.toLowerCase() === "q") {
          resolve(0);
          return;
        }

        if (char === "1") {
          const { init } = await import("./init.mjs");
          resolve(await init({ cwd }));
        } else if (char === "2") {
          const { demo } = await import("./demo.mjs");
          resolve(await demo({ cwd }));
        } else if (char === "3") {
          const { interactive } = await import("./interactive.mjs");
          const { STARTER_RULES } = await import("../core/policy.mjs");
          resolve(await interactive({ cwd, rules: STARTER_RULES, stdin, stdout }));
        } else if (char === "4") {
          const { status } = await import("./status.mjs");
          resolve(await status({ cwd }));
        } else if (char === "5" || char === "?") {
          const { getHelpText } = await import("../../bin/cirvix.mjs").catch(() => ({ getHelpText: null }));
          if (getHelpText) stdout.write(getHelpText() + "\n");
          else stdout.write(`  Run: ${bold("cirvix --help")}\n\n`);
          resolve(0);
        } else {
          resolve(0);
        }
      };

      try {
        stdin.setRawMode(true);
        stdin.resume();
        stdin.on("data", onKey);
      } catch {
        cleanup();
        resolve(0);
      }
    });
  }

  return 0;
}
