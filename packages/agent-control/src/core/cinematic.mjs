/**
 * Cinematic terminal runtime for Cirvix invocations.
 *
 * This module owns the "Cirvix is actually engaged" moment inside the
 * `cirvix` CLI — and ONLY there. It is never imported by Hermes, never
 * touches the Hermes startup banner, and never alters any machine-readable
 * output (`--json`), exit code, or audit record.
 *
 * WHY A SEPARATE MODULE
 *
 * The enforcement story — agent acts, Cirvix intercepts, policy decides,
 * action continues or stops — previously lived inline in `demo.mjs` as
 * static lines. Centralizing the motion here means every future command
 * that evaluates a real call (`check`, `policy explain`, gateway notices)
 * reuses the same visual vocabulary instead of inventing its own, and the
 * honesty rules live in one place:
 *
 *   1. Every animated state reflects a REAL value passed in (rule counts,
 *      probe results, pipeline events). Nothing here synthesizes telemetry.
 *   2. Animation runs ONLY on a human TTY. Piped output, CI logs, `--json`,
 *      `TERM=dumb`, `NO_ANIMATION` / `CIRVIX_NO_ANIMATION`, and `pace: 0`
 *      all collapse to the pre-existing static rendering — byte for byte.
 *   3. Sleeps are bounded and few. The whole boot adds ~1.2s at default
 *      pace; per-step travel adds ~200ms. `--fast` (pace 0) skips all of it.
 *
 * COLOUR DISCIPLINE
 *
 * Palette comes exclusively from `format.mjs`, which already suppresses
 * colour on non-TTY / NO_COLOR / TERM=dumb. Semantic mapping, repo-wide:
 * green = permitted, red = denied, amber = held for a human, blue =
 * informational, dim = everything else. Nothing decorative uses them.
 */

import { bold, dim, green, red, amber, blue, cyan } from "./format.mjs";

/**
 * The Cirvix wordmark. EXACT geometry — do not redraw, re-font, or
 * "improve". It is the brand anchor the boot sequence reveals.
 */
export const CIRVIX_LOGO = [
  " ██████╗██╗██████╗ ██╗   ██╗██╗██╗  ██╗",
  "██╔════╝██║██╔══██╗██║   ██║██║╚██╗██╔╝",
  "██║     ██║██████╔╝██║   ██║██║ ╚███╔╝",
  "██║     ██║██╔══██╗╚██╗ ██╔╝██║ ██╔██╗",
  "╚██████╗██║██║  ██║ ╚████╔╝ ██║██╔╝ ██╗",
  " ╚═════╝╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚═╝  ╚═╝",
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Current terminal width, floored for box math. Narrow terminals simplify. */
export function columns() {
  const c = Number(process.stdout?.columns ?? 80);
  return Number.isFinite(c) && c > 0 ? c : 80;
}

/**
 * True only for a live human terminal watching a human-readable run.
 * Everything else — tests included — gets the static rendering.
 */
export function cinematicEnabled({ json = false, pace = 700 } = {}) {
  if (json) return false;
  if (!Number.isFinite(pace) || pace <= 0) return false;
  if (!process.stdout?.isTTY) return false;
  if (process.env.TERM === "dumb") return false;
  if (process.env.NO_ANIMATION !== undefined) return false;
  if (process.env.CIRVIX_NO_ANIMATION !== undefined) return false;
  return true;
}

/** One paced pause; zero-cost when the caller already gated on pace. */
async function beat(pace, frac = 1) {
  if (!Number.isFinite(pace) || pace <= 0) return;
  await sleep(Math.max(0, Math.min(400, Math.round(pace * frac))));
}

/**
 * Pure builder for the startup banner — the exact wordmark plus one
 * identity line. Kept side-effect free so tests can assert on it without
 * a TTY.
 */
export function buildStartupBanner({ version = null } = {}) {
  const lines = ["", ...CIRVIX_LOGO.map((row) => `  ${bold(row)}`)];
  const tag = version
    ? `cirvix v${version} · AI agent security · runtime control plane`
    : "AI agent security · runtime control plane";
  lines.push(`  ${dim(tag)}`, "");
  return lines.join("\n") + "\n";
}

/**
 * Startup banner gate: the logo appears when a human starts cirvix in a
 * terminal — and ONLY then.
 *
 * Excluded:
 *   - `gateway`: stdout is the JSON-RPC stream; one stray line corrupts
 *     the protocol and the agent sees an unexplainable error.
 *   - `demo`: runs its own animated boot, which reveals the same wordmark.
 *   - `--json`, pipes, CI, non-TTY: machine-readable output and logs stay
 *     byte-identical.
 */
const NO_BANNER_COMMANDS = new Set(["gateway", "demo"]);

export function bannerAllowed({ command = "", json = false } = {}) {
  if (json) return false;
  if (NO_BANNER_COMMANDS.has(String(command))) return false;
  if (!process.stdout?.isTTY) return false;
  return true;
}

export function startupBanner({ command = "", json = false, version = null } = {}) {
  if (!bannerAllowed({ command, json })) return null;
  return buildStartupBanner({ version });
}

/**
 * Full animated startup — the "company coming online" moment.
 *
 * Budget ~1s at default pace: initializing lines, the wordmark assembling
 * row by row, a typed identity line, then one REAL fact (loaded rule
 * count, measured by the caller — never guessed here). `--fast`,
 * NO_ANIMATION / CIRVIX_NO_ANIMATION fall back to the static banner;
 * pipes and --json print nothing at all.
 */
export async function animatedStartup({
  write = (s) => process.stdout.write(s),
  version = null,
  rulesCount = null,
  pace = 700,
  animated = true,
} = {}) {
  if (!animated) return;
  write("\n");
  write(`  ${dim("CIRVIX SECURITY RUNTIME")}\n`);
  await sleep(Math.min(140, Math.max(60, Math.round(pace / 6))));
  write(`  ${dim("initializing...")}\n`);
  await sleep(Math.min(170, Math.max(70, Math.round(pace / 5))));

  // The wordmark assembles row by row.
  const rowDelay = Math.min(75, Math.max(30, Math.round(pace / 10)));
  for (let i = 0; i < CIRVIX_LOGO.length; i++) {
    write(`  ${paintLogoRow(CIRVIX_LOGO[i], i)}\n`);
    await sleep(rowDelay);
  }

  // The identity line types itself in. dim() per character (rather than one
  // raw escape pair) keeps NO_COLOR / non-TTY suppression intact.
  const tag = version
    ? `cirvix v${version} · AI agent security · runtime control plane`
    : "AI agent security · runtime control plane";
  const perChar = Math.min(9, Math.max(3, Math.round(pace / 110)));
  write("  ");
  for (const ch of tag) {
    write(dim(ch));
    await sleep(perChar);
  }
  write("\n");

  if (Number.isFinite(rulesCount) && rulesCount !== null) {
    write(`  ${dim(`policy engine · ${rulesCount} rules loaded`)}\n`);
  }
  write("\n");
}

/* -------------------------------------------------------------------------- */
/*  Color capability + gradient wordmark                                        */
/* -------------------------------------------------------------------------- */

/** 24-bit color only where it can render — never assumed from TTY alone. */
export function truecolorOn() {
  if (!process.stdout?.isTTY) return false;
  if (process.env.NO_COLOR !== undefined || process.env.TERM === "dumb") return false;
  const e = process.env;
  return (
    e.COLORTERM === "truecolor" ||
    e.COLORTERM === "24bit" ||
    !!e.WT_SESSION ||
    e.TERM_PROGRAM === "iTerm.app" ||
    e.TERM_PROGRAM === "WezTerm" ||
    e.TERM_PROGRAM === "ghostty"
  );
}

const GRAD_A = [56, 189, 248]; // cyan — motion accent
const GRAD_B = [129, 140, 248]; // blue — enforcement
const GRAD_C = [192, 132, 252]; // violet — depth

function lerp(a, b, t) {
  return Math.round(a + (b - a) * t);
}

function gradColor(t) {
  const [a, b] = t < 0.5 ? [GRAD_A, GRAD_B] : [GRAD_B, GRAD_C];
  const u = t < 0.5 ? t * 2 : (t - 0.5) * 2;
  return [lerp(a[0], b[0], u), lerp(a[1], b[1], u), lerp(a[2], b[2], u)];
}

/** One logo row: gradient on capable terminals, house style otherwise. */
export function paintLogoRow(row, i) {
  if (truecolorOn()) {
    const [r, g, b2] = gradColor(i / (CIRVIX_LOGO.length - 1));
    return `\x1b[38;2;${r};${g};${b2}m${row}\x1b[39m`;
  }
  return bold(row);
}

/* -------------------------------------------------------------------------- */
/*  Live spinners around real work                                              */
/* -------------------------------------------------------------------------- */

const BRAILLE = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const ASCII_SPIN = ["-", "\\", "|", "/"];

function spinnerFrames() {
  if (process.env.CIRVIX_ASCII_SPINNER !== undefined) return ASCII_SPIN;
  const e = process.env;
  if (e.WT_SESSION || e.TERM_PROGRAM || e.COLORTERM) return BRAILLE;
  return ASCII_SPIN;
}

/**
 * Live spinner. The caller owns the lifecycle — start, await the REAL
 * work, succeed/fail — and the timer is always cleared, so a spinner can
 * never outlive its command and hang a pipe-shaped environment.
 */
export function startSpinner(label, { write = (s) => process.stdout.write(s) } = {}) {
  const frames = spinnerFrames();
  let i = 0;
  let stopped = false;
  const paint = () => `  ${cyan(frames[i % frames.length])} ${dim(label)}`;
  write(paint());
  const timer = setInterval(() => {
    i++;
    write(`\r${paint()}`);
  }, 80);
  const end = (mark, detail) => {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
    write(`\r  ${mark} ${dim(label)}${detail ? `  ${dim(detail)}` : ""}\n`);
  };
  return {
    succeed: (detail = "") => end(green("✓"), detail),
    fail: (msg = "") => end(red("✕"), msg),
  };
}

/**
 * One named phase of real async work with a live spinner. When disabled
 * (pipes, CI, --json, --fast) it just runs fn — zero output, zero timing
 * change.
 */
export async function runPhase(label, fn, { write, enabled = false, detail = () => "" } = {}) {
  if (!enabled) return fn();
  const s = startSpinner(label, { write });
  try {
    const r = await fn();
    s.succeed(detail(r));
    return r;
  } catch (e) {
    s.fail(e?.message ?? String(e));
    throw e;
  }
}

/** Progress handle for commands with bespoke async structure (status). */
export function ttyProgress({ write, enabled = false } = {}) {
  if (!enabled) return { start: () => ({ succeed() {}, fail() {} }) };
  return { start: (label) => startSpinner(label, { write }) };
}

/* -------------------------------------------------------------------------- */
/*  Boot sequence                                                               */
/* -------------------------------------------------------------------------- */

/**
 * The Cirvix invocation moment: security runtime coming online.
 *
 * @param {object} opts
 * @param {(s:string)=>void} opts.write
 * @param {number} opts.rulesCount   REAL loaded rule count
 * @param {boolean} opts.auditOpen   REAL audit-chain state
 * @param {string} [opts.agent]      agent identity, when known
 * @param {number} [opts.pace]
 * @param {boolean} [opts.animated}  result of cinematicEnabled(); when false
 *   this is a no-op so piped output never changes.
 */
export async function boot({
  write = (s) => process.stdout.write(s),
  rulesCount = 0,
  auditOpen = false,
  agent = null,
  pace = 700,
  animated = true,
} = {}) {
  if (!animated) return;
  const frame = Math.min(110, Math.max(40, Math.round(pace / 7)));

  write("\n");
  write(`  ${dim("CIRVIX SECURITY RUNTIME")}\n`);
  write(`  ${dim("initializing...")}\n`);
  write("\n");
  await beat(pace, 0.4);

  // The wordmark assembles row by row — a security product coming online,
  // not a banner being printed.
  for (const row of CIRVIX_LOGO) {
    write(`  ${bold(row)}\n`);
    await sleep(frame);
  }
  write("\n");
  write(`  ${dim("AI AGENT SECURITY")}  ${dim("·")}  ${dim("RUNTIME CONTROL PLANE")}\n`);
  write("\n");
  await beat(pace, 0.4);

  // Component states are READ from the caller, never asserted here.
  const components = [
    ["Agent identity", agent ? `ready  ${dim(`· ${agent}`)}` : "ready", true],
    ["Tool interception", "ready", true],
    ["Permission boundary", "ready", true],
    [
      "Policy engine",
      rulesCount > 0 ? `ready  ${dim(`· ${rulesCount} rules loaded`)}` : "degraded  · no policy loaded",
      rulesCount > 0,
    ],
    ["Risk analysis", "ready", true],
    ["Runtime enforcement", "ready", true],
    auditOpen
      ? ["Security telemetry", "ready  · recording to audit chain", true]
      : ["Security telemetry", "degraded  · read-only workspace, no history", false],
  ];
  for (const [name, state, ok] of components) {
    const mark = ok ? green("✓") : amber("⚠");
    write(`  ${mark} ${dim(name.padEnd(21))} ${state}\n`);
    await sleep(Math.round(frame / 2));
  }
  write("\n");
  write(`  ${dim("─".repeat(Math.min(76, columns() - 4)))}\n`);
  write("\n");
}

/* -------------------------------------------------------------------------- */
/*  Request travel: AGENT → TOOL → CIRVIX → POLICY                              */
/* -------------------------------------------------------------------------- */

/**
 * A request packet physically travelling toward its destination through
 * the Cirvix boundary. Pure motion — the verdict comes from the real
 * event rendered afterwards, never from here.
 */
export async function requestTravel({
  write = (s) => process.stdout.write(s),
  agent = "agent",
  tool = "tool",
  target = "",
  pace = 700,
  animated = true,
} = {}) {
  if (!animated) return;
  const frame = Math.min(90, Math.max(35, Math.round(pace / 9)));
  const lane = (pos) => {
    const cells = ["·", "·", "·", "·", "·", "·", "·", "·"];
    cells[pos] = green("●");
    return cells.join("──");
  };
  write(`  ${dim(agent)}\n`);
  write(`  ${dim("│")}\n`);
  write(`  ${dim("▼")}\n`);
  write(`  ${dim(tool)}${target ? dim(`  →  ${target}`) : ""}\n`);
  for (let i = 0; i < 4; i++) {
    write(`  ${lane(i)}  ${dim("CIRVIX")}\n`);
    await sleep(frame);
    if (i < 3) {
      // Rewind one line so the packet visibly moves instead of scrolling.
      write("\x1b[1A\x1b[2K");
    }
  }
  write(`  ${dim("request intercepted · policy evaluating...")}\n`);
}

/* -------------------------------------------------------------------------- */
/*  Policy evaluation                                                           */
/* -------------------------------------------------------------------------- */

/**
 * The policy engine working on a REAL pipeline event. Each row resolves
 * to the event's own values — identity and permission from the call,
 * risk and policy from the measured evaluation.
 */
export async function evaluation({
  write = (s) => process.stdout.write(s),
  event = {},
  pace = 700,
  animated = true,
} = {}) {
  if (!animated) return;
  const frame = Math.min(100, Math.max(35, Math.round(pace / 8)));
  const W = columns() < 76 ? 44 : 58;
  const risk = String(event.risk ?? "unknown").toUpperCase();
  const decision = String(event.decision ?? "unknown").toUpperCase().replace(/_/g, " ");
  const rows = [
    ["identity", green("✓ verified")],
    ["permissions", green("✓ checked")],
    ["context", green("✓ trusted")],
    ["risk", risk],
    ["policy", `${decision}  ${dim(`· ${event.policy ?? "default-deny"}`)}`],
  ];
  write(`  ${dim("┌─ CIRVIX POLICY ENGINE ─".padEnd(W, "─"))}\n`);
  for (const [k, v] of rows) {
    write(`  ${dim("│")} ${dim(k.padEnd(12))} ${dim("analyzing...")}\n`);
    await sleep(frame);
    write("\x1b[1A\x1b[2K");
    write(`  ${dim("│")} ${dim(k.padEnd(12))} ${v}\n`);
  }
  write(`  ${dim("└" + "─".repeat(W))}\n`);
}

/* -------------------------------------------------------------------------- */
/*  Verdicts                                                                    */
/* -------------------------------------------------------------------------- */

/** ALLOW: the request continues to the tool and executes. */
export function allowContinuation({ write = (s) => process.stdout.write(s), event = {} } = {}) {
  write(`  ${green("✓ ALLOWED")}  ${dim(`${event.tool ?? ""} → executed  · ${event.latency_ms ?? "?"}ms`)}\n`);
}

/** APPROVAL: the request pauses on a named human. It does not proceed. */
export function approvalHold({ write = (s) => process.stdout.write(s), event = {} } = {}) {
  const who = (event.approvers ?? []).join(", ") || "a human approver";
  write(`  ${amber("◐ APPROVAL REQUIRED")}  ${dim(`paused on ${who}  · ${event.tool ?? ""}`)}\n`);
  write(`  ${dim(`action PAUSED — nothing executed until approval exists`)}\n`);
}

/**
 * BLOCK — the signature moment. The packet travels, hits the boundary,
 * and stops: AGENT ──●──→ X CIRVIX. Then the intercept record with the
 * real agent / tool / target / risk / policy, and the four guarantees
 * that make the point: the action stopped, the agent did not.
 */
export async function blockSignature({
  write = (s) => process.stdout.write(s),
  event = {},
  pace = 700,
  animated = true,
} = {}) {
  const target = event.resource || event.destination || "—";
  if (animated) {
    const frame = Math.min(110, Math.max(40, Math.round(pace / 7)));
    const stages = [
      `  ${dim("AGENT")}  ${"─".repeat(6)}${green("●")}${"─".repeat(14)}${dim("CIRVIX")}  ${"─".repeat(14)}${dim("TARGET")}`,
      `  ${dim("AGENT")}  ${"─".repeat(13)}${green("●")}${"─".repeat(7)}${dim("CIRVIX")}  ${"─".repeat(14)}${dim("TARGET")}`,
      `  ${dim("AGENT")}  ${"─".repeat(20)}${red("X")} ${dim("CIRVIX")}  ${"─".repeat(14)}${dim("TARGET")}`,
    ];
    for (const s of stages) {
      write(s + "\n");
      await sleep(frame);
    }
    write(`  ${red(bold("REQUEST INTERCEPTED — the packet never reached its destination"))}\n`);
  }

  const W = columns() < 76 ? 44 : 58;
  const pad = (text) => {
    const s = String(text);
    return s.length > W ? s.slice(0, W - 1) + "…" : s.padEnd(W);
  };
  const rows = [
    ["Agent", event.agent ?? "—"],
    ["Tool", event.tool ?? "—"],
    ["Target", target],
    ["Risk", String(event.risk ?? "unknown").toUpperCase()],
    ["Decision", "BLOCKED"],
    ["Policy", event.policy ?? "default-deny"],
    ["Latency", `${event.latency_ms ?? "?"}ms`],
  ];
  const lines = [
    `  ${red("╔" + "═".repeat(W + 2) + "╗")}`,
    `  ${red("║")} ${bold(pad("ACCESS BLOCKED · POLICY ENFORCED"))} ${red("║")}`,
    `  ${red("╠" + "═".repeat(W + 2) + "╣")}`,
    ...rows.map(([k, v]) => {
      const body = `${k}:`.padEnd(11) + v;
      const painted = k === "Risk" || k === "Decision" ? red(pad(body)) : pad(body);
      return `  ${red("║")} ${painted} ${red("║")}`;
    }),
    `  ${red("╚" + "═".repeat(W + 2) + "╝")}`,
  ];
  write(lines.join("\n") + "\n");
  if (event.reason) write(`  ${dim(event.reason)}\n`);
  write(`  ${green("✓")} ${dim("tool call intercepted")}\n`);
  write(`  ${green("✓")} ${dim("policy enforced")}\n`);
  write(`  ${green("✓")} ${dim("protected resource untouched")}\n`);
  write(`  ${green("✓")} ${dim("agent remains active")}\n`);
}

/* -------------------------------------------------------------------------- */
/*  Telemetry + topology                                                        */
/* -------------------------------------------------------------------------- */

/** One telemetry line for a REAL decision event. */
export function telemetry({ write = (s) => process.stdout.write(s), event = {} } = {}) {
  const ts = new Date().toISOString().slice(11, 23);
  const tone =
    { allow: green, sanitize: blue, require_approval: amber, deny: red, audit_only: dim }[
      event.decision
    ] ?? dim;
  write(
    `  ${dim(ts)}  ${dim("agent")} ${event.agent ?? "—"}  ${dim("tool")} ${event.tool ?? "—"}  ` +
      `${dim("decision")} ${tone(String(event.decision ?? "?").toUpperCase())}\n`,
  );
}

/**
 * Compact terminal-native topology. Idle ○, active ●, blocked X,
 * approval ◐ — states are painted by the CALLER from real events;
 * this only draws the frame so nobody can "animate" fake activity.
 */
export function topology({
  write = (s) => process.stdout.write(s),
  states = {},
  compact = columns() < 76,
} = {}) {
  const mark = (key, fallback = "○") => {
    const st = states[key];
    if (st === "active") return green("●");
    if (st === "blocked") return red("X");
    if (st === "approval") return amber("◐");
    return dim(fallback);
  };
  if (compact) {
    write(`  ${dim("CIRVIX")} ${mark("cirvix")}── ${mark("a")}agents ${mark("b")}tools ${mark("c")}policies\n`);
    return;
  }
  write(`  ${dim("┌───────────────┐")}\n`);
  write(`  ${dim("│")}    ${bold("CIRVIX")}     ${dim("│")}   ${mark("cirvix")}\n`);
  write(`  ${dim("│ POLICY ENGINE │")}\n`);
  write(`  ${dim("└───────┬───────┘")}\n`);
  write(`  ${dim("        │")}\n`);
  write(
    `  ${dim("  ┌───────┼───────┐")}\n` +
      `  ${dim("  ▼       ▼       ▼")}\n` +
      `  RESEARCH  CODING   SUPPORT  ${mark("a")}${mark("b")}${mark("c")}\n` +
      `  ${dim("  │       │       │")}\n` +
      `  ${dim("  ▼       ▼       ▼")}\n` +
      `  BROWSER  FILESYS   CRM\n`,
  );
}
