/**
 * `cirvix onboard` — the 10-second first run.
 *
 * A guided demo, not a man page: it shows one allowed call and one real
 * blocked credential read, then hands the user the console.
 */

import { Pipeline } from "../core/pipeline.mjs";
import { compile } from "../core/policy-dsl.mjs";
import { STARTER_POLICY } from "./init.mjs";
import { blockedCard, policyCard } from "../tui/cards.mjs";
import { bold, dim, style } from "../core/theme.mjs";

export async function onboard({ cwd = process.cwd(), pace = 500, write = (s) => process.stdout.write(s) } = {}) {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const rules = compile(STARTER_POLICY, { cwd, origin: "onboard" }).rules;
  const pipeline = new Pipeline({ rules, cwd, agent: "you" });

  write("\n");
  write(`  ${bold("◆ CIRVIX")}\n`);
  write(`  ${dim("Runtime Authorization Engine")}\n\n`);
  write(`  ${dim("Cirvix evaluates what your AI agents are allowed to do.")}\n\n`);
  write(`  ${style("✓", "allow")} ${dim("Identity")}   ${style("✓", "allow")} ${dim("Policy")}   ${style("✓", "allow")} ${dim("Context")}   ${style("✓", "allow")} ${dim("Risk")}\n\n`);
  await sleep(pace);

  write(`  ${bold("Let's test it.")}\n`);
  write(`  ${dim("> Read ~/.aws/credentials")}\n\n`);
  await sleep(pace);

  const { event } = await pipeline.submit({ tool: "read_file", arguments: { path: "~/.aws/credentials" } });
  write(blockedCard({
    tool: event.tool,
    target: "~/.aws/credentials",
    policy: event.policy ?? "credential-protection",
    reason: event.reason ?? "This path contains credentials.",
  }).split("\n").map((l) => "  " + l).join("\n") + "\n\n");
  write(`  ${style("Cirvix protected your credentials.", "allow")}\n\n`);
  await sleep(pace);

  const { event: ok } = await pipeline.submit({ tool: "read_file", arguments: { path: "./src/app.ts" } });
  write(policyCard({
    action: ok.tool,
    risk: ok.risk,
    policy: ok.policy ?? "allow-workspace-read",
    identity: "agent:you",
    reason: "Ordinary workspace reads keep working.",
  }).split("\n").map((l) => "  " + l).join("\n") + "\n\n");

  write(`  ${dim("Next:")}  ${bold("cirvix console")}  ${dim("— the interactive runtime")}\n`);
  write(`  ${dim("Or:")}    ${bold("cirvix demo")}     ${dim("— the full live interception")}\n\n`);
  return { ok: true };
}
