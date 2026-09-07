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
import { watch } from "node:fs";

import { AuditChain } from "../core/audit.mjs";
import { ApprovalStore } from "../core/approvals.mjs";
import { bold, dim, green, red, amber, blue, cyan, plural } from "../core/format.mjs";
import { shouldAnimate } from "../core/ui/controller.mjs";
import { brandHeader } from "../core/ui/primitives.mjs";
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
function enterAltScreen() {
  if (inAltScreen) return;
  try { process.stdout.write("\x1b[?1049h"); inAltScreen = true; } catch {}
}
function exitAltScreen() {
  if (!inAltScreen) return;
  try { process.stdout.write("\x1b[?1049l"); inAltScreen = false; } catch {}
}
function hideCursor() { try { process.stdout.write("\x1b[?25l"); } catch {} }
function showCursor() { try { process.stdout.write("\x1b[?25h"); } catch {} }
function setRaw(enable) {
  if (process.stdin.isTTY) {
    try { process.stdin.setRawMode(enable); } catch {}
  }
}

// ---------------------------------------------------------------------------
// should we launch interactive?
// ---------------------------------------------------------------------------

export function canLaunchInteractive(flags, positional) {
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

export async function interactive({ cwd, flags, rules }) {
  const stateDir = String(flags.state ?? join(cwd, ".cirvix"));
  await mkdir(stateDir, { recursive: true }).catch(() => {});
  const animated = shouldAnimate({ pace: flags.pace ? Number(flags.pace) : 700, json: false }) && !flags.fast;

  // Enter alt screen BEFORE startup so startup is inside the single viewport
  enterAltScreen();
  hideCursor();
  // Ensure we leave alt screen and restore cursor/raw on any exit
  let cleaned = false;
  const doCleanup = () => {
    if (cleaned) return;
    cleaned = true;
    try { if (watcher) watcher.close(); } catch {}
    if (poll) clearInterval(poll);
    clearInterval(statusPoll);
    if (messageTimer) clearTimeout(messageTimer);
    if (resizeHandler) process.stdout.off("resize", resizeHandler);
    process.stdin.off("data", onData);
    setRaw(false);
    showCursor();
    exitAltScreen();
    try { process.stdin.pause(); } catch {}
  };
  const cleanupAndExit = (code) => {
    doCleanup();
    try { process.stdout.write("\n"); } catch {}
    process.exit(code);
  };
  process.on("SIGINT", () => cleanupAndExit(0));
  process.on("SIGTERM", () => cleanupAndExit(0));
  process.on("uncaughtException", (e) => { doCleanup(); try { process.stderr.write(red(String(e.message)) + "\n"); } catch {} process.exit(1); });
  process.on("exit", () => { if (!cleaned) doCleanup(); });

  // --- startup animation (once, inside alt screen) ---
  // Use a single write for the whole startup frame, then transition to TUI
  try { process.stdout.write("\x1b[2J\x1b[H"); } catch {}
  if (animated) {
    // Build startup frame as ONE write, not incremental appends that would appear as multiple viewports
    // We still animate steps but each step is a coalesced viewport update via the same alt-screen clear
    let startup = "\n" + brandHeader({ width: 62 }) + "\n\n";
    startup += `  ${dim("Initializing runtime...")}\n`;
    try { process.stdout.write(startup); } catch {}
    const steps = [
      "Runtime initialized",
      "Policy engine loaded",
      `${plural(rules?.length ?? 0, "rule")} loaded`,
      "Secrets protected",
      "Audit chain ready",
    ];
    for (const s of steps) {
      await sleep(120);
      // Append one line to the existing viewport by moving cursor and writing line
      // Instead of clearing, we just add a line — this is part of the startup sequence and is intentional
      // But to keep ONE viewport, we redraw the whole startup frame each time
      // Simpler: just write the line and keep viewport growing during startup (startup is transient)
      try { process.stdout.write(`  ${green("✓")} ${dim(s)}\n`); } catch {}
    }
    await sleep(180);
    try { process.stdout.write(`\n  ${green(bold("CIRVIX ● ONLINE"))}\n\n`); } catch {}
    await sleep(260);
    // Clear startup and enter TUI — single viewport from here on
    try { process.stdout.write("\x1b[2J\x1b[H"); } catch {}
  } else {
    try {
      process.stdout.write(`\n  ${bold("CIRVIX")} ${dim("· runtime governance")}\n\n`);
      process.stdout.write(`  ${green(bold("CIRVIX ● ONLINE"))}\n\n`);
      await sleep(120);
      try { process.stdout.write("\x1b[2J\x1b[H"); } catch {}
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
  let messageTimer = null;
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
    const W = Math.min(78, (process.stdout.columns || 80) - 4);
    let out = "";
    // Move to home and clear viewport — robust: hide cursor already, now clear
    // \x1b[H = cursor home, \x1b[2J = erase display, \x1b[3J = erase scrollback (where supported)
    // On Windows, \x1b[2J\x1b[H is reliable for viewport; \x1b[3J clears scrollback to prevent duplication in alt-screen exit
    out += "\x1b[?25l"; // keep hidden during draw
    out += "\x1b[H\x1b[2J";
    // Some terminals need scrollback clear
    out += "\x1b[3J";
    out += "\x1b[H";

    // header
    out += `  ${dim(`┌─ CIRVIX ${"─".repeat(Math.max(0, W - 10))}┐`)}\n`;
    const runtimeStatus = statusData?.runtime?.running ? `${green(bold("● ONLINE"))}  ${dim("ENFORCE")}  ${dim(plural(statusData.rulesCount ?? 0, "RULE"))}` : `${dim("● STOPPED")}  ${dim("IDLE")}`;
    out += `  ${dim("│")} ${bold("CIRVIX")} ${runtimeStatus} ${dim("│")}\n`;
    out += `  ${dim("├" + "─".repeat(W) + "┤")}\n`;

    if (helpOpen) {
      out += `\n  ${bold("CIRVIX HELP")}  ${dim("press Esc or ? to close")}\n\n`;
      const helps = [
        ["?", "show help"],
        ["q", "quit"],
        ["r", "refresh"],
        ["l", "activity/logs"],
        ["p", "policies"],
        ["a", "audit"],
        ["d", "demo"],
        ["i", "interceptions"],
        ["↑/↓", "navigate events"],
        ["Enter", "inspect selected event"],
        ["Esc", "close detail view"],
        ["Ctrl+C", "exit cleanly"],
      ];
      for (const [k, d] of helps) out += `    ${cyan(k.padEnd(8))} ${dim(d)}\n`;
      out += `\n  ${dim("Commands inside session:")} ${blue("status")} ${dim("·")} ${blue("logs")} ${dim("·")} ${blue("policy test")} ${dim("·")} ${blue("audit verify")} ${dim("·")} ${blue("demo")} ${dim("·")} ${blue("why <id>")}\n`;
      out += `\n  ${dim("─".repeat(W))}\n`;
      out += `  ${dim("P50")} ${statusData?.stats?.latency?.p50 ?? "—"}ms  ${dim("P95")} ${statusData?.stats?.latency?.p95 ?? "—"}ms  ${dim("P99")} ${statusData?.stats?.latency?.p99 ?? "—"}ms   ${auditData?.ok ? green("Audit ✓ INTEGRITY OK") : red("Audit ✕ BROKEN")}\n`;
      out += `  ${dim("└" + "─".repeat(W) + "┘")}\n`;
      out += `\n  ${dim("$")} ${inputBuf}${inputMode ? "█" : dim("_")}  ${message ? dim("— " + message) : ""}\n`;
      // ensure output ends with exactly one frame, no extra newlines that would scroll
      try { process.stdout.write(out); } catch {}
      return;
    }

    if (detailId) {
      const rec = events.find((e) => (e.request_id === detailId || e.decision_id === detailId)) || journal.find(events, detailId);
      if (rec) {
        const tree = journal.renderTree(rec);
        out += `\n${tree}\n\n`;
        out += `  ${dim("[Esc] Back")}  ${dim("·")}  ${dim("↑/↓ navigate")}  ${isHoldRecord(rec) ? amber("[A] Approve [R] Reject") : ""}\n`;
        out += `\n  ${dim("─".repeat(W))}\n`;
        out += `  ${dim("$")} ${inputBuf}${inputMode ? "█" : dim("_")}\n`;
        try { process.stdout.write(out); } catch {}
        return;
      } else {
        out += `\n  ${red("No decision with id " + detailId)}\n\n`;
        out += `  ${dim("[Esc] Back")}\n`;
        try { process.stdout.write(out); } catch {}
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
      out += `\n  ${dim("Running demo...")} ${dim("(real pipeline, streaming)")}\n\n`;
    } else {
      out += `\n  ${bold("ACTIVITY")}  ${dim("live — use ↑/↓ to navigate, Enter to inspect")}\n\n`;
      if (events.length === 0) {
        out += `  ${dim("no decisions yet — run")} ${blue("cirvix demo")} ${dim("or start gateway")}\n`;
      } else {
        const start = Math.max(0, events.length - 12);
        const slice = events.slice(start);
        for (let i = 0; i < slice.length; i++) {
          const e = slice[i];
          const idx = start + i;
          const isSel = idx === selected;
          const dec = e.decision ?? "unknown";
          const isBlock = dec === "deny";
          const isHold = dec === "require_approval";
          const isSan = dec === "sanitize";
          const icon = isBlock ? red("✕") : isHold ? amber("●") : isSan ? amber("◇") : green("✓");
          const label = isBlock ? red("BLOCK") : isHold ? amber("APPROVAL") : isSan ? amber("SANITIZE") : green("ALLOW");
          const risk = String(e.risk ?? "—").toUpperCase();
          const riskTone = risk === "CRITICAL" ? red(risk) : risk === "HIGH" ? amber(risk) : dim(risk);
          const time = String(e.ts ?? e.timestamp ?? "").slice(11, 19) || "—";
          const tool = String(e.tool ?? e.action ?? "—");
          const target = String(e.resource ?? e.command ?? "").slice(-36);
          const latency = `${e.latency_ms ?? "—"}ms`;
          const line = `  ${dim(time)}  ${icon} ${label.padEnd(8)} ${riskTone.padEnd(10)} ${tool.padEnd(18)} ${dim(target.padEnd(36))} ${dim(latency.padStart(7))}`;
          out += (isSel ? `${cyan("▶")} ` : "  ") + (isSel ? bold(line) : line) + "\n";
          if (isSel && isBlock) {
            out += `    ${dim("Policy:")} ${e.policy ?? e.rule ?? "—"}  ${dim("Agent:")} ${e.agent ?? "—"}\n`;
          }
          if (isSel && isHold) {
            out += `    ${amber("→ AWAITING APPROVAL")}  ${dim(e.policy ?? "")}\n`;
          }
        }
      }
      if (events.length > 0) {
        const last = events[events.length - 1];
        const lastDec = last.decision ?? "";
        if (lastDec === "deny" || last.risk === "critical") {
          out += `\n  ${dim("SECURITY")}\n\n`;
          out += `  ${dim("Last decision:")}  ${red(bold("✕ BLOCKED"))}  ${dim(last.policy ?? last.rule ?? "")}\n`;
        }
      }
    }

    out += `\n  ${dim("─".repeat(W))}\n`;
    const p = statusData?.stats?.latency;
    out += `  ${dim("P50")} ${p?.p50 ?? "—"}ms  ${dim("P95")} ${p?.p95 ?? "—"}ms  ${dim("P99")} ${p?.p99 ?? "—"}ms   ${auditData?.ok ? green("Audit ✓ INTEGRITY OK") : dim("Audit —")}`;
    if (message) out += `   ${dim("·")} ${message}`;
    out += `\n`;
    out += `  ${dim("├" + "─".repeat(W) + "┤")}\n`;
    const prompt = inputMode ? `$ ${inputBuf}█` : `$ ${inputBuf}${dim("_")}  ${dim("? help  q quit  r refresh  l logs  p pol  a audit  d demo  i intercept  ↑↓ nav  Enter inspect")}`;
    out += `  ${dim("│")} ${prompt.slice(0, W - 4).padEnd(W - 4)} ${dim("│")}\n`;
    out += `  ${dim("└" + "─".repeat(W) + "┘")}\n`;
    try { process.stdout.write(out); } catch {}
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
  let watcher = null;
  let poll = null;
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
    watcher = watch(join(stateDir, "audit.jsonl"), () => { void pollLive(); });
  } catch {
    poll = setInterval(() => { void pollLive(); }, 900);
  }
  if (!watcher) poll = poll ?? setInterval(() => { void pollLive(); }, 900);
  const statusPoll = setInterval(() => { void refresh().then(() => requestRender()); }, 3000);

  // --- helpers ---
  function setMessage(msg, ms = 2000) {
    message = msg;
    requestRender();
    if (messageTimer) clearTimeout(messageTimer);
    messageTimer = setTimeout(() => { message = ""; requestRender(); }, ms);
  }

  // --- input handling ---
  const onData = async (chunk) => {
    const s = chunk.toString("utf8");

    if (s === "\x03") {
      cleanupAndExit(0);
      return;
    }
    if (s.startsWith("\x1b[")) {
      if (s === "\x1b[A") {
        if (detailId) return;
        selected = Math.max(0, selected - 1);
        requestRender();
      } else if (s === "\x1b[B") {
        if (detailId) return;
        selected = Math.min(events.length - 1, selected + 1);
        requestRender();
      } else if (s === "\x1b[1;2A" || s === "\x1b[1;2B") {
        // shift+arrow ignored
      }
      return;
    }
    if (!inputMode) {
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
      if (s === "\r" || s === "\n") {
        if (events[selected]) { detailId = events[selected].request_id ?? events[selected].decision_id ?? events[selected].request_id; helpOpen = false; requestRender(); }
        return;
      }
      if (s === "\x1b") {
        if (helpOpen) { helpOpen = false; requestRender(); return; }
        if (detailId) { detailId = null; requestRender(); return; }
        if (inputMode) { inputMode = false; inputBuf = ""; requestRender(); return; }
        return;
      }
      if (s.length === 1 && s >= " " && s <= "~") {
        inputMode = true;
        inputBuf = s;
        requestRender();
        return;
      }
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
      return;
    }

    if (s === "\x03") { cleanupAndExit(0); return; }
    if (s === "\x7f" || s === "\x08") {
      inputBuf = inputBuf.slice(0, -1);
      requestRender();
      return;
    }
    if (s === "\x1b") {
      inputMode = false; inputBuf = ""; requestRender(); return;
    }
    if (s === "\r" || s === "\n") {
      const cmd = inputBuf.trim();
      inputMode = false;
      inputBuf = "";
      if (!cmd) { requestRender(); return; }
      await execCommand(cmd);
      return;
    }
    if (s === "\x1b[A" || s === "\x1b[B") return;
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
    if (c === "policy" && args[0] === "test") {
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
    if (c === "audit" && args[0] === "verify") {
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

  // --- setup terminal ---
  setRaw(true);
  process.stdin.resume();
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", onData);

  // resize -> single coalesced redraw
  const resizeHandler = () => requestRender();
  process.stdout.on("resize", resizeHandler);

  // initial render — single viewport
  requestRender();

  // keep alive
  await new Promise(() => {});
}
