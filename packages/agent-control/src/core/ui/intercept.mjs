/**
 * SecurityIntercept — visually distinctive blocked-action panel.
 *
 * Animation MUST NOT delay enforcement. Decision is already computed.
 * This only visualizes it with a short 300-800ms sequence.
 */

import { bold, dim, red, stripAnsi } from "../format.mjs";
import { shouldAnimate, sleep } from "./controller.mjs";
import { boxChars, truncate, padVisible } from "./theme.mjs";

export function interceptBox(event) {
  const W = 58;
  const ch = boxChars();
  const useAscii = ch.tl === "+";
  // Use red border for intercept.
  const h = useAscii ? ch.h : "═";
  const v = useAscii ? ch.v : "║";
  const tl = useAscii ? ch.tl : "╔";
  const tr = useAscii ? ch.tr : "╗";
  const bl = useAscii ? ch.bl : "╚";
  const br = useAscii ? ch.br : "╝";
  const mj = useAscii ? ch.lt : "╠";
  const mid = mj + h.repeat(W + 2) + (useAscii ? ch.rt : "╣");

  const rows = [
    ["Agent", event.agent ?? "—"],
    ["Tool", event.tool ?? event.action ?? "—"],
    ["Target", event.resource ?? event.destination ?? "—"],
    ["Risk", String(event.risk ?? "—").toUpperCase()],
    ["Decision", "BLOCKED"],
    ["Policy", event.policy ?? event.rule ?? "default-deny"],
    ["Latency", `${event.latency_ms ?? "—"}ms`],
  ];

  const pad = (text) => {
    const s = String(text);
    const vis = stripAnsi(s).length;
    if (vis > W) return s.slice(0, W - 1) + "…";
    return s + " ".repeat(W - vis);
  };

  const lines = [];
  lines.push(`  ${red(tl + h.repeat(W + 2) + tr)}`);
  lines.push(`  ${red(v)} ${bold(pad("CIRVIX SECURITY INTERCEPT"))} ${red(v)}`);
  lines.push(`  ${red(mid)}`);
  for (const [k, val] of rows) {
    const body = `${k}:`.padEnd(11) + String(val);
    const painted = k === "Risk" || k === "Decision" ? red(pad(body)) : pad(body);
    lines.push(`  ${red(v)} ${painted} ${red(v)}`);
  }
  lines.push(`  ${red(bl + h.repeat(W + 2) + br)}`);

  const reason = event.reason ? `\n  ${dim(truncate(event.reason, 72))}\n` : "";
  return lines.join("\n") + reason;
}

/**
 * Animated intercept: spinner → risk → BLOCKED → policy.
 * Total 300-800ms, but decision already made.
 */
export async function animateIntercept(event, { stream = process.stdout, pace = 700 } = {}) {
  const enabled = shouldAnimate({ pace, json: false });
  if (!enabled) {
    stream.write(interceptBox(event) + "\n");
    return;
  }
  const write = (s) => {
    try {
      stream.write(s);
    } catch {}
  };
  const timers = [];
  const hide = () => {
    try {
      stream.write("\u001b[?25l");
    } catch {}
  };
  const show = () => {
    try {
      stream.write("\u001b[?25h");
    } catch {}
  };
  hide();
  // Phase 1: evaluating
  write("  ◌ evaluating request...\r");
  await sleep(Math.min(260, pace * 0.35), timers);
  write("\x1b[2K");
  // Phase 2: risk
  const riskTone = event.risk === "critical" ? red : event.risk === "high" ? "\u001b[33m" : "";
  write(`  ${riskTone}⚠ ${String(event.risk ?? "").toUpperCase()}\u001b[39m\n`);
  await sleep(Math.min(160, pace * 0.2), timers);
  // Phase 3: BLOCKED
  write(`  ${red("✕ BLOCKED")}\n`);
  await sleep(Math.min(160, pace * 0.2), timers);
  // Phase 4: policy
  write(`  ${dim(String(event.policy ?? event.rule ?? ""))}\n`);
  await sleep(Math.min(120, pace * 0.15), timers);
  // Phase 5: full box
  write(interceptBox(event) + "\n");
  show();
  for (const t of timers) clearTimeout(t);
}
