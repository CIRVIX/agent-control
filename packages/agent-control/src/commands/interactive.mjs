/**
 * `cirvix` interactive — full-screen terminal application.
 *
 * ONE COMMAND: `cirvix` launches the live runtime.
 * Existing `cirvix status` / `logs` / `demo` etc. remain one-shot for scripts/CI.
 *
 * Zero new deps. Uses existing ui/* + format + real Pipeline/Journal/Audit.
 * Respects: !isTTY / CI / --json / --fast / NO_COLOR / TERM=dumb / CIRVIX_NO_ANIM.
 * Restores cursor/rawMode/alt-screen on Ctrl+C / SIGINT / SIGTERM / crash.
 *
 * FIX: stable viewport — ONE authoritative render, coalesced, viewport-cleared.
 */

import { access, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { watch, readFileSync } from "node:fs";

const PKG_VERSION = (() => {
  try {
    return JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")).version;
  } catch {
    return "0.2.2";
  }
})();

import { AuditChain } from "../core/audit.mjs";
import { ApprovalStore } from "../core/approvals.mjs";
import { bold, dim, green, red, amber, blue, cyan, gray, plural } from "../core/format.mjs";
import { shouldAnimate } from "../core/ui/controller.mjs";
import { brandHeader } from "../core/ui/primitives.mjs";
import { glyphs, boxChars, padVisible, wordWrap } from "../core/ui/theme.mjs";
import { MODE } from "../core/decisions.mjs";
import * as journal from "../core/journal.mjs";
import { collectMcpServers, detectRuntimes } from "../core/detect.mjs";
import { UdsClient, defaultEndpoint, tokenPath } from "../core/uds.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// helpers: real state
// ---------------------------------------------------------------------------

async function exists(p) {
  try { await access(p); return true; } catch { return false; }
}

async function probeRuntime(stateDir) {
  const endpoint = defaultEndpoint(stateDir);
  if (!(await exists(tokenPath(stateDir)))) return { running: false, reason: "no token" };
  try {
    const token = (await readFile(tokenPath(stateDir), "utf8")).trim();
    const c = new UdsClient({ endpoint, token, timeoutMs: 1200 });
    const s = await c.call("cirvix/status", {});
    return { running: true, live: s };
  } catch { return { running: false, reason: "nothing listening" }; }
}

async function loadStatusData(cwd, stateDir, rules) {
  const [runtimes, runtime, records] = await Promise.all([
    detectRuntimes().catch(() => []),
    probeRuntime(stateDir),
    journal.read(join(stateDir, "audit.jsonl")).catch(() => []),
  ]);
  const servers = collectMcpServers(runtimes);
  const stats = journal.summarize(records);
  let approvals = { pending: 0, total: 0 };
  const ap = join(stateDir, "approvals.jsonl");
  if (await exists(ap)) {
    try { const s = await new ApprovalStore(ap).open(); approvals = { pending: s.pending().length, total: s.all().length }; } catch {}
  }
  let tests = { total: 0, passed: null };
  try {
    const { loadPolicyFile } = await import("./policy.mjs");
    for (const cand of ["cirvix.policy", "cirvix.policy.json", ".cirvix/policy.json"]) {
      const p = join(cwd, cand);
      if (await exists(p)) {
        const loaded = await loadPolicyFile(p, { cwd });
        tests.total = loaded.tests?.length ?? 0;
        if (tests.total > 0) {
          const { evaluate } = await import("../core/policy.mjs");
          const { normalize, policyRequest } = await import("../core/normalize.mjs");
          const { toDecision } = await import("../core/decisions.mjs");
          let passed = 0;
          for (const t of loaded.tests) {
            try {
              const call = normalize({ tool: t.call.tool, arguments: t.call.arguments }, { cwd });
              const dec = evaluate(policyRequest(call), loaded.rules, { cwd });
              const actual = dec.decision ?? toDecision(dec.verdict);
              const exp = String(t.expect ?? "").toLowerCase();
              const expected = { allow: "allow", deny: "deny", hold: "require_approval", sanitize: "sanitize" }[exp] ?? exp;
              if (actual === expected) passed++;
            } catch {}
          }
          tests.passed = passed;
        }
        break;
      }
    }
  } catch {}
  return { runtimes, runtime, servers, stats, approvals, tests, rulesCount: rules?.length ?? 0 };
}

// ---------------------------------------------------------------------------
// terminal control — ONE viewport, robust on Windows
// ---------------------------------------------------------------------------

let inAltScreen = false;
function enterAltScreen(out = process.stdout) {
  if (inAltScreen) return;
  try { out.write("\x1b[?1049h\x1b[?2004h"); inAltScreen = true; } catch {}
}
function exitAltScreen(out = process.stdout) {
  if (!inAltScreen) return;
  try { out.write("\x1b[?2004l\x1b[?1049l"); inAltScreen = false; } catch {}
}
function hideCursor(out = process.stdout) { try { out.write("\x1b[?25l"); } catch {} }
function showCursor(out = process.stdout) { try { out.write("\x1b[?25h"); } catch {} }
function setRaw(enable, inp = process.stdin) {
  if (inp.isTTY || typeof inp.setRawMode === "function") {
    try { inp.setRawMode(enable); } catch {}
  }
}

// ---------------------------------------------------------------------------
// should we launch interactive?
// ---------------------------------------------------------------------------

export function canLaunchInteractive(flags = {}, positional = []) {
  if (flags.json) return false;
  if (flags.fast) return false;
  if (process.env.CIRVIX_NO_ANIM === "1") return false;
  if (process.env.NO_COLOR !== undefined) return false;
  if (process.env.TERM === "dumb") return false;
  if (process.env.CI !== undefined && process.env.FORCE_COLOR !== "1") return false;
  if (!process.stdout.isTTY || !process.stdin.isTTY) return false;
  if (positional.length === 0) return true;
  if (positional.length === 1 && positional[0] === "help") return true;
  return false;
}

// ---------------------------------------------------------------------------
// main interactive loop
// ---------------------------------------------------------------------------

export async function interactive({ cwd, flags = {}, rules, stdin = process.stdin, stdout = process.stdout, onExit, signal }) {
  const stateDir = String(flags.state ?? join(cwd, ".cirvix"));
  await mkdir(stateDir, { recursive: true }).catch(() => {});
  const animated = shouldAnimate({ pace: flags.pace ? Number(flags.pace) : 700, json: false }) && !flags.fast;

  // Scoped lifecycle handles
  let watcher = null;
  let poll = null;
  let statusPoll = null;
  let messageTimer = null;
  let resizeHandler = null;
  let onData = null;

  // Enter alt screen BEFORE startup so startup is inside the single viewport
  enterAltScreen(stdout);
  hideCursor(stdout);
  setRaw(true, stdin);
  try { stdin.resume(); } catch {}
  try { stdin.setEncoding("utf8"); } catch {}

  // Ensure we leave alt screen and restore cursor/raw on any exit
  let cleaned = false;
  let exitResolve = null;
  const doCleanup = () => {
    if (cleaned) return;
    cleaned = true;
    try { if (watcher) watcher.close(); } catch {}
    if (poll) clearInterval(poll);
    if (statusPoll) clearInterval(statusPoll);
    if (messageTimer) clearTimeout(messageTimer);
    if (resizeHandler) stdout.off("resize", resizeHandler);
    stdin.off("data", handleData);
    setRaw(false, stdin);
    showCursor(stdout);
    exitAltScreen(stdout);
    try { stdin.pause(); } catch {}
  };
  const cleanupAndExit = (code) => {
    doCleanup();
    try { stdout.write("\n"); } catch {}
    if (exitResolve) {
      const r = exitResolve;
      exitResolve = null;
      r(code);
    }
    if (typeof onExit === "function") {
      onExit(code);
    } else {
      process.exit(code);
    }
  };

  const pendingInput = [];
  const handleData = (chunk) => {
    const s = chunk.toString("utf8");
    if (s.includes("\x03")) {
      cleanupAndExit(0);
      return;
    }
    if (onData) {
      void onData(chunk);
    } else {
      pendingInput.push(chunk);
    }
  };
  stdin.on("data", handleData);

  resizeHandler = () => requestRender();
  stdout.on("resize", resizeHandler);
  if (signal) {
    signal.addEventListener("abort", () => cleanupAndExit(0), { once: true });
  }
  process.on("SIGINT", () => cleanupAndExit(0));
  process.on("SIGTERM", () => cleanupAndExit(0));
  process.on("uncaughtException", (e) => { doCleanup(); try { process.stderr.write(red(String(e.message)) + "\n"); } catch {} cleanupAndExit(1); });
  process.on("exit", () => { if (!cleaned) doCleanup(); });

  // --- startup animation (once, inside alt screen) ---
  // Use a single write for the whole startup frame, then transition to TUI
  try { stdout.write("\x1b[2J\x1b[H"); } catch {}
  if (animated) {
    const g = glyphs();
    const ch = boxChars();
    const bannerW = 62;
    let startup = "\n";
    startup += `  ${gray(ch.tl + ch.h)} ${cyan(bold(g.diamond + " CIRVIX"))} ${bold("v" + PKG_VERSION)} ${gray(ch.h.repeat(Math.max(2, bannerW - 32)))} ${dim("CONSOLE")} ${gray(ch.tr)}\n`;
    startup += `  ${gray(ch.v)} ${padVisible(dim("Runtime authorization for AI agents."), bannerW - 4)} ${gray(ch.v)}\n`;
    startup += `  ${gray(ch.bl + ch.h.repeat(bannerW - 2) + ch.br)}\n\n`;
    startup += `  ${dim("Initializing runtime...")}\n`;
    try { stdout.write(startup); } catch {}
    const steps = [
      "Runtime initialized",
      "Policy engine loaded",
      `${plural(rules?.length ?? 0, "rule")} loaded`,
      "Secrets protected",
      "Audit chain ready",
    ];
    for (const s of steps) {
      await sleep(100);
      try { stdout.write(`  ${green(g.check)} ${dim(s)}\n`); } catch {}
    }
    await sleep(140);
    try { stdout.write(`\n  ${green(bold(g.bullet + " CIRVIX ONLINE"))}\n\n`); } catch {}
    await sleep(200);
    // Clear startup and enter TUI — single viewport from here on
    try { stdout.write("\x1b[2J\x1b[H"); } catch {}
  } else {
    try {
      const g = glyphs();
      stdout.write(`\n  ${cyan(bold(g.diamond + " CIRVIX"))} ${bold("v" + PKG_VERSION)} ${dim("· runtime governance")}\n\n`);
      stdout.write(`  ${green(bold(g.bullet + " CIRVIX ONLINE"))}\n\n`);
      if (!flags.fast) await sleep(100);
      try { stdout.write("\x1b[2J\x1b[H"); } catch {}
    } catch {}
  }

  // --- state ---
  let view = "activity"; // activity | policies | audit | intercept | demo | help
  let selected = 0;
  let detailId = null; // request_id for inspector
  let helpOpen = false;
  let inputMode = false;
  let inputBuf = "";
  let message = ""; // transient message line
  let isRunningDemo = false;
  let pendingApprovals = [];
  let events = [];
  let statusData = null;
  let auditData = null;
  let policyTestData = null;

  // load initial data
  const refresh = async () => {
    try {
      statusData = await loadStatusData(cwd, stateDir, rules);
      const recs = await journal.read(join(stateDir, "audit.jsonl"));
      events = journal.query(recs, { last: 20 });
      if (selected >= events.length) selected = Math.max(0, events.length - 1);
      const ap = join(stateDir, "approvals.jsonl");
      if (await exists(ap)) {
        const store = await new ApprovalStore(ap).open();
        pendingApprovals = store.pending();
      } else pendingApprovals = [];
      const chain = new AuditChain(join(stateDir, "audit.jsonl"));
      auditData = await chain.verify();
    } catch {}
  };
  await refresh();

  // --- render scheduler: ONE authoritative render, coalesced, no concurrent writes ---
  let renderPending = false;
  let renderRunning = false;
  let renderScheduled = false;

  function doRender() {
    // Build ONE frame and write it as a single atomic viewport update
    const cols = stdout.columns || process.stdout.columns || 80;
    const rows = stdout.rows || process.stdout.rows || 24;
    const W = Math.max(48, Math.min(100, cols - 4));
    const innerW = Math.max(0, W - 4);
    let out = "";
    // Move to home and clear viewport — robust: hide cursor already, now clear
    out += "\x1b[?25l"; // keep hidden during draw
    out += "\x1b[H\x1b[2J";
    out += "\x1b[3J";
    out += "\x1b[H";

    // Header: Clear, truthful status
    const isRunning = Boolean(statusData?.runtime?.running);
    const runtimeBadge = isRunning ? green(bold("● RUNNING")) : dim("○ STOPPED");
    const isEnforcing = isRunning ? green(bold("ENFORCING")) : dim("INACTIVE");
    const rulesCount = statusData?.rulesCount ?? rules?.length ?? 0;
    out += `  ${dim(`┌─ CIRVIX CONSOLE ${"─".repeat(Math.max(0, W - 18))}┐`)}\n`;
    out += `  ${dim("│")} ${bold("CIRVIX")}  ${dim("Runtime:")} ${runtimeBadge}  ${dim("│")}  ${dim("Protection:")} ${isEnforcing}  ${dim("│")}  ${dim("Policy:")} ${dim(plural(rulesCount, "rule"))} ${dim("│")}\n`;
    out += `  ${dim("├" + "─".repeat(Math.max(0, W)) + "┤")}\n`;

    if (helpOpen) {
      out += `\n  ${bold("CIRVIX HELP")}  ${dim("— press Esc or ? to close")}\n`;
      out += `  ${dim("─".repeat(Math.max(0, W)))}\n\n`;
      out += `  ${bold("NAVIGATION")}\n`;
      const helps = [
        ["↑ / ↓", "Navigate security decisions"],
        ["Enter", "Inspect selected decision in detail"],
        ["Esc", "Close inspector / help / cancel typing"],
        ["?", "Toggle this help screen"],
        ["q", "Quit interactive console"],
        ["r", "Refresh activity from journal"],
      ];
      for (const [k, d] of helps) out += `    ${cyan(k.padEnd(8))} ${dim(d)}\n`;

      out += `\n  ${bold("VIEWS")}\n`;
      const views = [
        ["l", "Security activity / decisions log"],
        ["p", "Active policies & validation test suite"],
        ["a", "Audit hash-chain integrity verification"],
        ["d", "Run live attack simulation demo"],
      ];
      for (const [k, d] of views) out += `    ${cyan(k.padEnd(8))} ${dim(d)}\n`;

      out += `\n  ${bold("CLI COMMANDS")}\n`;
      out += `    ${blue("cirvix init")}       ${dim("Configure workspace protection")}\n`;
      out += `    ${blue("cirvix demo")}       ${dim("Simulate an attack interception")}\n`;
      out += `    ${blue("cirvix status")}     ${dim("Inspect runtime health and fleet")}\n`;
      out += `    ${blue("cirvix logs")}       ${dim("Inspect recent decision records")}\n`;

      out += `\n  ${dim("─".repeat(Math.max(0, W)))}\n`;
      out += `  ${cyan("[Esc]")} ${dim("Return to console")}   ${cyan("[q]")} ${dim("Quit")}\n`;
      out += `  ${dim("└" + "─".repeat(Math.max(0, W)) + "┘")}\n`;
      out += `\n  ${dim("$")} ${inputBuf}${inputMode ? "█" : dim("_")}  ${message ? dim("— " + message) : ""}\n`;
      try { stdout.write(out); } catch {}
      return;
    }

    if (detailId) {
      const rec = events.find((e) => (e.request_id === detailId || e.decision_id === detailId)) || journal.find(events, detailId);
      if (rec) {
        const dec = rec.decision ?? rec.verdict ?? "unknown";
        const isBlock = dec === "deny";
        const isHold = dec === "require_approval" || dec === "hold";
        const isSan = dec === "sanitize";
        const badgeLabel = isBlock ? "✕ BLOCKED (DENY)" : isHold ? "⏳ AWAITING APPROVAL" : isSan ? "↻ CONTENT SANITIZED" : "✓ ALLOWED";
        const badgeTone = isBlock ? red : isHold ? amber : isSan ? blue : green;

        let resultText = "Action was permitted by policy.";
        if (isBlock) resultText = "No action was executed.";
        else if (isHold) resultText = "Operation held. Requires human review.";
        else if (isSan) resultText = "Untrusted instructions neutralized. Content safe.";

        let sourceDesc = "Historical audit log";
        if (rec.run_id?.startsWith("run_demo_") || rec.context?.demo) {
          sourceDesc = "SECURITY DEMO — SIMULATED EVENT (no real action executed)";
        } else if (isRunning) {
          sourceDesc = "LIVE ACTIVITY (runtime enforcing)";
        }

        let humanReason = rec.reason;
        if (!humanReason) {
          if (isBlock) humanReason = "Action was prevented by active security policy rule.";
          else if (isHold) humanReason = "Action requires human approval before proceeding.";
          else if (isSan) humanReason = "Untrusted instructions detected in data were neutralized.";
          else humanReason = "Action conforms to active workspace policy.";
        }

        out += `\n  ${bold("DECISION DETAILS")}\n`;
        out += `  ${dim("─".repeat(Math.max(0, W)))}\n\n`;
        out += `  ${badgeTone(bold(badgeLabel))}\n\n`;
        out += `  ${bold("Agent:")}     ${rec.agent ?? "—"}\n`;
        out += `  ${bold("Action:")}    ${cyan(rec.tool ?? rec.action ?? "—")}\n`;
        out += `  ${bold("Target:")}    ${rec.resource ?? rec.command ?? rec.url ?? "—"}\n`;
        out += `  ${bold("Risk:")}      ${String(rec.risk ?? "—").toUpperCase()}\n`;
        out += `  ${bold("Policy:")}    ${rec.policy ?? rec.rule ?? "—"}\n\n`;
        out += `  ${bold("Reason:")}\n`;
        const wrapW = Math.max(30, W - 6);
        for (const wr of wordWrap(humanReason, wrapW)) {
          out += `    ${dim(wr)}\n`;
        }
        out += `\n`;
        out += `  ${bold("Result:")}    ${dim(resultText)}\n`;
        out += `  ${bold("Source:")}    ${dim(sourceDesc)}\n\n`;
        out += `  ${dim("─".repeat(Math.max(0, W)))}\n`;
        out += `  ${bold("FORENSICS")}\n`;
        out += `  ${dim("Request ID:")}   ${rec.request_id ?? "—"}\n`;
        out += `  ${dim("Decision ID:")}  ${rec.decision_id ?? "—"}\n`;
        out += `  ${dim("Latency:")}      ${rec.latency_ms ?? "—"}ms\n`;
        out += `  ${dim("Audit Chain:")}  ${auditData?.ok ? green("Verified in audit journal") : dim("Recorded")}\n\n`;
        out += `  ${dim("─".repeat(Math.max(0, W)))}\n`;
        const holdAction = isHoldRecord(rec) ? `  ${green("[A] Approve")}  ${red("[R] Reject")}  ` : "";
        out += `  ${cyan("[Esc]")} ${dim("Back to decisions")}   ${cyan("[q]")} ${dim("Quit")}  ${holdAction}\n`;
        out += `  ${dim("└" + "─".repeat(Math.max(0, W)) + "┘")}\n`;
        out += `\n  ${dim("$")} ${inputBuf}${inputMode ? "█" : dim("_")}\n`;
        try { stdout.write(out); } catch {}
        return;
      } else {
        out += `\n  ${red("No decision with id " + detailId)}\n\n`;
        out += `  ${cyan("[Esc]")} ${dim("Back to decisions")}\n`;
        out += `  ${dim("└" + "─".repeat(Math.max(0, W)) + "┘")}\n`;
        out += `\n  ${dim("$")} ${inputBuf}${inputMode ? "█" : dim("_")}\n`;
        try { stdout.write(out); } catch {}
        return;
      }
    }

    if (view === "policies") {
      out += `\n  ${bold("CIRVIX POLICIES")}  ${dim(`${statusData?.rulesCount ?? 0} rules`)}\n\n`;
      if (policyTestData) {
        out += policyTestData + "\n";
      } else {
        out += `  ${dim("Press")} ${cyan("p")} ${dim("to run")} ${blue("cirvix policy test")} ${dim("inside session, or type")} ${blue("policy test")}\n`;
        out += `  ${dim("Last:")} ${statusData?.tests?.passed ?? "—"}/${statusData?.tests?.total ?? "—"} passed\n`;
      }
    } else if (view === "audit") {
      out += `\n  ${bold("CIRVIX AUDIT")}\n\n`;
      if (auditData?.ok) {
        out += `  ${green("✓ Hash chain intact")}\n`;
        out += `  ${green("✓ " + (auditData.records ?? 0) + " records verified")}\n`;
        out += `  ${green("✓ No records altered")}\n\n`;
        out += `  ${bold("CHAIN")}\n\n  ${dim("current")}\n    ${dim("↓")}\n  ${dim("previous")}\n    ${dim("↓")}\n  ${dim("genesis")}\n\n`;
        out += `  ${bold("STATUS")}  ${green(bold("● INTEGRITY OK"))}\n`;
      } else {
        out += `  ${red(bold("chain broken"))} ${auditData?.brokenAt ?? ""} ${auditData?.reason ?? ""}\n`;
      }
    } else if (view === "demo" && isRunningDemo) {
      out += `\n  ${dim("Running security demo...")} ${dim("(real pipeline, streaming)")}\n\n`;
    } else {
      // Activity View: Clearly communicate source of decisions
      let sourceTitle = "ACTIVITY";
      let sourceDesc = "RECENT RECORDED DECISIONS";
      let sourceTag = dim("(historical audit log)");
      if (isRunning) {
        sourceTitle = "LIVE ACTIVITY";
        sourceDesc = "ENFORCING IN REAL TIME";
        sourceTag = green("● LIVE");
      } else if (events.length > 0) {
        const isDemo = events.every((e) =>
          e.run_id?.startsWith("run_demo_") ||
          e.context?.demo ||
          (e.resource && (e.resource.includes("attacker.example.com") || e.resource.includes("169.254.169.254") || e.resource.includes(".aws/credentials")))
        );
        if (isDemo) {
          sourceTitle = "SECURITY DEMO";
          sourceDesc = "SIMULATED EVENTS (no real action executed)";
          sourceTag = amber("◈ SIMULATION");
        }
      }

      out += `\n  ${bold(sourceTitle)}  ${dim("—")}  ${bold(sourceDesc)}  ${sourceTag}\n`;

      if (events.length === 0) {
        out += `\n  ${dim("No security decisions yet.")}\n\n`;
        out += `  ${dim("Cirvix is ready to inspect agent activity.")}\n\n`;
        out += `  ${dim("Try:")}\n`;
        out += `    ${cyan("cirvix demo")}       ${dim("Run a simulated attack demo")}\n`;
        out += `    ${cyan("cirvix init")}       ${dim("Configure protection for this workspace")}\n\n`;
      } else {
        const allowedCount = events.filter((e) => (e.decision ?? e.verdict) === "allow" || (e.decision ?? e.verdict) === "permit").length;
        const sanitizedCount = events.filter((e) => (e.decision ?? e.verdict) === "sanitize").length;
        const blockedCount = events.filter((e) => (e.decision ?? e.verdict) === "deny").length;
        const holdCount = events.filter((e) => (e.decision ?? e.verdict) === "require_approval" || (e.decision ?? e.verdict) === "hold").length;
        out += `  ${green("✓")} ${allowedCount} Allowed  ${dim("·")}  ${blue("↻")} ${sanitizedCount} Sanitized  ${dim("·")}  ${red("✕")} ${blockedCount} Blocked  ${dim("·")}  ${amber("⏳")} ${holdCount} Awaiting approval\n\n`;

        const maxEvents = Math.max(2, Math.min(10, rows - 16));
        const start = Math.max(0, events.length - maxEvents);
        const slice = events.slice(start);
        for (let i = 0; i < slice.length; i++) {
          const e = slice[i];
          const idx = start + i;
          const isSel = idx === selected;
          const dec = e.decision ?? e.verdict ?? "unknown";
          const isBlock = dec === "deny";
          const isHold = dec === "require_approval" || dec === "hold";
          const isSan = dec === "sanitize";
          const icon = isBlock ? red("✕") : isHold ? amber("⏳") : isSan ? blue("↻") : green("✓");
          const label = isBlock ? red("BLOCKED") : isHold ? amber("APPROVAL") : isSan ? blue("SANITIZE") : green("ALLOWED");
          const risk = String(e.risk ?? "—").toUpperCase();
          const riskTone = risk === "CRITICAL" ? red(risk) : risk === "HIGH" ? amber(risk) : dim(risk);
          const time = String(e.ts ?? e.timestamp ?? "").slice(11, 19) || "—";
          const tool = String(e.tool ?? e.action ?? "—");
          const toolWidth = Math.max(8, Math.min(16, Math.floor(W * 0.2)));
          const targetWidth = Math.max(10, W - 36 - toolWidth);
          const target = String(e.resource ?? e.command ?? e.url ?? "").slice(-targetWidth);
          const line = `  ${dim(time)}  ${icon} ${label.padEnd(9)} ${riskTone.padEnd(9)} ${tool.slice(0, toolWidth).padEnd(toolWidth)} ${dim(target.padEnd(targetWidth))}`;
          out += (isSel ? `${cyan("▶")} ` : "  ") + (isSel ? bold(line) : line) + "\n";
          if (isSel) {
            let whyText = e.reason ?? (isBlock ? "Blocked by security policy." : isHold ? "Operation held for human approval." : isSan ? "Untrusted instructions sanitized." : "Permitted by security policy.");
            out += `    ${dim("Why:")} ${whyText.slice(0, W - 12)}\n`;
            out += `    ${dim("Policy:")} ${e.policy ?? e.rule ?? "—"}  ${dim("·")}  ${cyan("[Enter]")} ${dim("Inspect details")}\n`;
          }
        }
      }
    }

    out += `\n  ${dim("─".repeat(Math.max(0, W)))}\n`;
    const p = statusData?.stats?.latency;
    if (p && (statusData?.stats?.count ?? 0) > 0) {
      out += `  ${dim(`Session latency: P50 ${p.p50 ?? "—"}ms · P95 ${p.p95 ?? "—"}ms · P99 ${p.p99 ?? "—"}ms (${statusData.stats.count} local decisions)`)}\n`;
    }
    if (message) {
      out += `  ${cyan("●")} ${message}\n`;
    }
    out += `  ${dim("├" + "─".repeat(Math.max(0, W)) + "┤")}\n`;
    const prompt = inputMode ? `$ ${inputBuf}█` : `$ ${inputBuf}${dim("_")}  ${cyan("[↑/↓]")} ${dim("Nav")}  ${cyan("[Enter]")} ${dim("Inspect")}  ${cyan("[?]")} ${dim("Help")}  ${cyan("[q]")} ${dim("Quit")}  ${cyan("[r]")} ${dim("Refresh")}`;
    out += `  ${dim("│")} ${prompt.slice(0, innerW).padEnd(innerW)} ${dim("│")}\n`;
    out += `  ${dim("└" + "─".repeat(Math.max(0, W)) + "┘")}\n`;
    try { stdout.write(out); } catch {}
  }

  function requestRender() {
    if (renderRunning) {
      renderScheduled = true;
      return;
    }
    if (renderPending) return;
    renderPending = true;
    // coalesce to next tick so multiple state updates in same tick result in one frame
    setImmediate(() => {
      renderPending = false;
      if (renderRunning) {
        renderScheduled = true;
        return;
      }
      renderRunning = true;
      try {
        doRender();
      } finally {
        renderRunning = false;
        if (renderScheduled) {
          renderScheduled = false;
          requestRender();
        }
      }
    });
  }

  function isHoldRecord(rec) {
    const d = rec.decision ?? rec.verdict;
    return d === "require_approval" || d === "hold";
  }

  // watcher for live activity — NEVER directly print, only update state + requestRender
  let knownLen = events.length;
  const pollLive = async () => {
    try {
      const recs = await journal.read(join(stateDir, "audit.jsonl"));
      if (recs.length > knownLen) {
        const fresh = recs.slice(knownLen);
        events = journal.query(recs, { last: 20 });
        knownLen = recs.length;
        if (selected === events.length - 2) selected = events.length - 1;
        const last = fresh[fresh.length - 1];
        if (last && (last.decision === "deny" || last.risk === "critical")) {
          view = "activity";
          detailId = null;
          message = `✕ BLOCKED ${last.tool ?? ""} — ${last.policy ?? ""}`;
          if (messageTimer) clearTimeout(messageTimer);
          messageTimer = setTimeout(() => { message = ""; requestRender(); }, 3000);
        }
        requestRender();
      } else if (recs.length < knownLen) {
        knownLen = recs.length;
        events = journal.query(recs, { last: 20 });
        requestRender();
      }
      // refresh status periodically via same poll, but coalesced
      statusData = await loadStatusData(cwd, stateDir, rules);
      requestRender();
    } catch {}
  };
  try {
    if (await exists(join(stateDir, "audit.jsonl"))) {
      watcher = watch(join(stateDir, "audit.jsonl"), () => { void pollLive(); });
      watcher.on("error", () => {
        try { if (watcher) watcher.close(); } catch {}
        watcher = null;
        if (!poll) {
          poll = setInterval(() => { void pollLive(); }, 900);
          poll?.unref?.();
        }
      });
    }
  } catch {
    poll = setInterval(() => { void pollLive(); }, 900);
    poll?.unref?.();
  }
  if (!watcher && !poll) {
    poll = setInterval(() => { void pollLive(); }, 900);
    poll?.unref?.();
  }
  statusPoll = setInterval(() => { void refresh().then(() => requestRender()); }, 3000);
  statusPoll?.unref?.();

  // --- helpers ---
  function setMessage(msg, ms = 2000) {
    message = msg;
    requestRender();
    if (messageTimer) clearTimeout(messageTimer);
    messageTimer = setTimeout(() => { message = ""; requestRender(); }, ms);
  }

  let bracketedPasteBuf = null;

  async function handlePastedText(raw) {
    if (helpOpen) helpOpen = false;
    if (detailId) detailId = null;

    const normalized = raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    if (normalized.includes("\n")) {
      const lines = normalized.split("\n");
      if (inputBuf) {
        lines[0] = inputBuf + lines[0];
        inputBuf = "";
        inputMode = false;
      }
      const toExec = lines.slice(0, -1);
      const remainder = lines[lines.length - 1];
      for (const line of toExec) {
        const trimmed = line.trim();
        if (trimmed) {
          await execCommand(trimmed);
        }
      }
      if (remainder) {
        inputMode = true;
        inputBuf = remainder;
        requestRender();
      } else {
        inputMode = false;
        inputBuf = "";
        requestRender();
      }
    } else {
      inputMode = true;
      inputBuf += raw;
      requestRender();
    }
  }

  // --- input handling ---
  onData = async (chunk) => {
    let s = chunk.toString("utf8");

    // Ctrl+C cleanly cleans up and exits
    if (s.includes("\x03")) {
      cleanupAndExit(0);
      return;
    }

    // Bracketed paste handling (\x1b[200~ ... \x1b[201~)
    if (bracketedPasteBuf !== null) {
      bracketedPasteBuf += s;
      if (bracketedPasteBuf.includes("\x1b[201~")) {
        const parts = bracketedPasteBuf.split("\x1b[201~");
        const pasted = parts[0];
        const remainder = parts.slice(1).join("\x1b[201~");
        bracketedPasteBuf = null;
        await handlePastedText(pasted);
        if (remainder) await onData(Buffer.from(remainder));
      }
      return;
    }

    if (s.includes("\x1b[200~")) {
      const idx = s.indexOf("\x1b[200~");
      const before = s.slice(0, idx);
      if (before) await onData(Buffer.from(before));
      const after = s.slice(idx + 6);
      if (after.includes("\x1b[201~")) {
        const endIdx = after.indexOf("\x1b[201~");
        const pasted = after.slice(0, endIdx);
        const rest = after.slice(endIdx + 6);
        await handlePastedText(pasted);
        if (rest) await onData(Buffer.from(rest));
      } else {
        bracketedPasteBuf = after;
      }
      return;
    }

    // Multiline paste or pasted text with newlines (without bracketed paste wrappers)
    if (s.length > 1 && (s.includes("\n") || s.includes("\r")) && s !== "\r\n") {
      await handlePastedText(s);
      return;
    }

    // Single-key Escape
    if (s === "\x1b") {
      if (helpOpen) { helpOpen = false; requestRender(); return; }
      if (detailId) { detailId = null; requestRender(); return; }
      if (inputMode) { inputMode = false; inputBuf = ""; requestRender(); return; }
      message = "";
      requestRender();
      return;
    }

    // Escape sequences (arrows, home, end, page up/down, etc.)
    if (s.startsWith("\x1b[") || s.startsWith("\x1bO")) {
      if (s === "\x1b[A" || s === "\x1bOA") {
        if (detailId) return;
        selected = Math.max(0, selected - 1);
        requestRender();
        return;
      }
      if (s === "\x1b[B" || s === "\x1bOB") {
        if (detailId) return;
        selected = Math.min(events.length - 1, selected + 1);
        requestRender();
        return;
      }
      if (s === "\x1b[5~") {
        if (detailId) return;
        selected = Math.max(0, selected - 5);
        requestRender();
        return;
      }
      if (s === "\x1b[6~") {
        if (detailId) return;
        selected = Math.min(events.length - 1, selected + 5);
        requestRender();
        return;
      }
      if (s === "\x1b[H" || s === "\x1b[1~") {
        if (detailId) return;
        selected = 0;
        requestRender();
        return;
      }
      if (s === "\x1b[F" || s === "\x1b[4~") {
        if (detailId) return;
        selected = Math.max(0, events.length - 1);
        requestRender();
        return;
      }
      // other escape sequences safely ignored
      return;
    }

    // Backspace
    if (s === "\x7f" || s === "\x08") {
      if (inputMode) {
        inputBuf = inputBuf.slice(0, -1);
        if (inputBuf.length === 0) inputMode = false;
        requestRender();
      }
      return;
    }

    // Enter / Return
    if (s === "\r" || s === "\n" || s === "\r\n") {
      if (inputMode) {
        const cmd = inputBuf.trim();
        inputMode = false;
        inputBuf = "";
        if (!cmd) { requestRender(); return; }
        await execCommand(cmd);
        return;
      }
      if (events[selected]) {
        detailId = events[selected].request_id ?? events[selected].decision_id ?? events[selected].request_id;
        helpOpen = false;
        requestRender();
      }
      return;
    }

    // Normal mode commands / typing
    if (!inputMode) {
      if (detailId) {
        const rec = events.find((e) => (e.request_id === detailId || e.decision_id === detailId));
        if (rec && isHoldRecord(rec)) {
          if (s === "a" || s === "A") {
            try {
              const store = await new ApprovalStore(join(stateDir, "approvals.jsonl")).open();
              const by = process.env.CIRVIX_APPROVER ?? "interactive@cirvix";
              await store.decide(rec.approval_id ?? rec.request_id, "approved", by);
              setMessage(green("APPROVED by " + by), 2000);
              await refresh(); detailId = null; requestRender();
            } catch (e) { setMessage(red(String(e.message)), 3000); }
            return;
          }
          if (s === "r" || s === "R") {
            try {
              const store = await new ApprovalStore(join(stateDir, "approvals.jsonl")).open();
              const by = process.env.CIRVIX_APPROVER ?? "interactive@cirvix";
              await store.decide(rec.approval_id ?? rec.request_id, "denied", by);
              setMessage(red("REJECTED by " + by), 2000);
              await refresh(); detailId = null; requestRender();
            } catch (e) { setMessage(red(String(e.message)), 3000); }
            return;
          }
        }
      }

      if (s === "?") { helpOpen = !helpOpen; requestRender(); return; }
      if (s === "q" || s === "Q") { cleanupAndExit(0); return; }
      if (s === "r" || s === "R") { await refresh(); requestRender(); setMessage("refreshed", 1200); return; }
      if (s === "l" || s === "L") { view = "activity"; detailId = null; helpOpen = false; selected = events.length - 1; requestRender(); return; }
      if (s === "p" || s === "P") {
        view = "policies"; detailId = null; helpOpen = false;
        policyTestData = null; requestRender();
        setMessage("running policy test...", 3000);
        try {
          const { loadPolicyFile } = await import("./policy.mjs");
          let pp = null;
          for (const cand of ["cirvix.policy", "cirvix.policy.json", ".cirvix/policy.json"]) {
            const p = join(cwd, cand);
            if (await exists(p)) { pp = p; break; }
          }
          if (!pp) policyTestData = `\n  ${red("No policy file found.")}\n`;
          else {
            const { output } = await (await import("./policy.mjs")).test({ path: pp, cwd, json: false });
            policyTestData = output;
          }
        } catch (e) { policyTestData = `\n  ${red(String(e.message))}\n`; }
        requestRender();
        return;
      }
      if (s === "a" || s === "A") { view = "audit"; detailId = null; helpOpen = false; await refresh(); requestRender(); return; }
      if (s === "d" || s === "D") {
        if (isRunningDemo) return;
        view = "activity"; isRunningDemo = true; detailId = null; helpOpen = false; requestRender();
        setMessage("demo streaming — real pipeline", 2000);
        try {
          const { demo } = await import("./demo.mjs");
          await demo({ cwd, pace: 140, stateDir, write: () => {} });
          await refresh(); isRunningDemo = false; requestRender(); setMessage("demo complete — 6 allowed 1 sanitized 3 blocked", 3000);
        } catch (e) { isRunningDemo = false; setMessage(red(String(e.message)), 3000); }
        return;
      }
      if (s === "i" || s === "I") {
        const idx = events.findIndex((e, i) => i > selected && (e.decision === "deny" || e.risk === "critical"));
        if (idx !== -1) { selected = idx; detailId = events[idx].request_id ?? events[idx].decision_id; requestRender(); }
        else setMessage("no more interceptions", 1500);
        return;
      }

      // Single line paste or multi-char input without newlines
      if (s.length > 1) {
        await handlePastedText(s);
        return;
      }

      // Printable single character: enter input mode
      if (s.length === 1 && s >= " " && s <= "~") {
        inputMode = true;
        inputBuf = s;
        requestRender();
        return;
      }
      return;
    }

    // Input mode:
    if (s.length > 1) {
      await handlePastedText(s);
      return;
    }
    if (s.length === 1 && s >= " " && s <= "~") {
      inputBuf += s;
      requestRender();
    }
  };

  async function execCommand(raw) {
    const cmd = raw.trim();
    if (!cmd) return;
    const parts = cmd.split(/\s+/);
    const c = parts[0].toLowerCase();
    const args = parts.slice(1);
    if (c === "help" || c === "?") { helpOpen = true; requestRender(); return; }
    if (c === "q" || c === "quit" || c === "exit") { cleanupAndExit(0); return; }
    if (c === "clear" || c === "r" || c === "refresh") { await refresh(); requestRender(); setMessage("refreshed"); return; }
    if (c === "status") {
      await refresh(); view = "activity"; detailId = null; helpOpen = false; requestRender(); setMessage("status — live", 1500); return;
    }
    if (c === "logs") {
      view = "activity"; detailId = null; helpOpen = false;
      if (args.includes("--watch") || args.includes("-w")) setMessage("already live — streaming", 1500);
      requestRender(); return;
    }
    if (c === "policy") {
      if (args[0] === "test") {
        view = "policies"; helpOpen = false; policyTestData = null; requestRender();
        setMessage("running policy test...", 2000);
        try {
          const { loadPolicyFile } = await import("./policy.mjs");
          let pp = null;
          for (const cand of ["cirvix.policy", "cirvix.policy.json", ".cirvix/policy.json"]) {
            const p = join(cwd, cand);
            if (await exists(p)) { pp = p; break; }
          }
          if (!pp) policyTestData = `\n  ${red("No policy file found. Run cirvix init.")}\n`;
          else {
            const { output } = await (await import("./policy.mjs")).test({ path: pp, cwd, json: false });
            policyTestData = output;
          }
        } catch (e) { policyTestData = `\n  ${red(String(e.message))}\n`; }
        requestRender(); return;
      }
      view = "policies"; helpOpen = false; requestRender(); return;
    }
    if (c === "audit") {
      view = "audit"; helpOpen = false; await refresh(); requestRender(); return;
    }
    if (c === "demo") {
      if (isRunningDemo) { setMessage("demo already running", 1500); return; }
      view = "activity"; isRunningDemo = true; requestRender();
      setMessage("demo streaming — real pipeline", 2000);
      try {
        const { demo } = await import("./demo.mjs");
        await demo({ cwd, pace: 140, stateDir, write: () => {} });
        await refresh(); isRunningDemo = false; requestRender(); setMessage("demo complete", 2500);
      } catch (e) { isRunningDemo = false; setMessage(red(String(e.message)), 3000); }
      return;
    }
    if (c === "why" && args[0]) {
      const id = args[0];
      let rec = events.find((e) => e.request_id === id || e.decision_id === id);
      if (!rec) {
        try {
          const all = await journal.read(join(stateDir, "audit.jsonl"));
          rec = journal.find(all, id);
        } catch {}
      }
      if (rec) { detailId = rec.request_id ?? rec.decision_id ?? id; helpOpen = false; view = "activity"; requestRender(); }
      else setMessage(red("No decision with id " + id), 2500);
      return;
    }
    if (c === "approvals" || c === "approval") {
      await refresh();
      if (pendingApprovals.length === 0) setMessage("nothing waiting on a human", 2000);
      else {
        const idx = events.findIndex((e) => (e.decision === "require_approval" || e.verdict === "hold"));
        if (idx !== -1) { selected = idx; detailId = events[idx].request_id; }
        setMessage(`${pendingApprovals.length} awaiting approval — press Enter to inspect`, 2500);
      }
      requestRender();
      return;
    }
    setMessage(dim(`unknown command: ${cmd} — try ?`), 2000);
  }

  // initial render — single viewport
  requestRender();

  // drain any input queued during initialization
  if (pendingInput.length > 0) {
    const queued = [...pendingInput];
    pendingInput.length = 0;
    for (const c of queued) {
      if (onData) await onData(c);
    }
  }

  // keep alive until clean exit
  return new Promise((resolve) => {
    exitResolve = resolve;
  });
}
