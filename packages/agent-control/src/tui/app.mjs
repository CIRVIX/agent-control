/**
 * Cirvix console — the primary interactive UX.
 *
 * Layout (wide terminals):
 *   ┌ header ────────────────────────────────┐
 *   │ CONVERSATION            │ ACTIVITY     │
 *   │ user asks / cirvix      │ ◐ policy.eval│
 *   │ responds / policy cards │ ✓ shell.exec │
 *   ├ composer ──────────────────────────────┤
 *   │ status bar                             │
 *   └────────────────────────────────────────┘
 *
 * Narrow terminals (<90 cols): the activity pane collapses into the
 * transcript automatically. No horizontal scrolling, ever.
 *
 * Engine separation: the app owns a Pipeline + EventBus. It emits events,
 * reduces them to state, and renders cards from state. Policy code never
 * touches the terminal.
 *
 * Non-TTY / piped usage: `runOnce(text)` evaluates one line and returns
 * the rendered output without starting readline — used by tests, CI, and
 * `echo "…" | cirvix console`.
 */

import { Pipeline } from "../core/pipeline.mjs";
import { decideNow } from "../core/journal.mjs";
import { EventBus, createEvent, initialState, reduce, attachPipeline } from "../core/events.mjs";
import { header, policyCard, toolCard, blockedCard, heldCard, explainDecision, userRow, cirvixRow, spinnerFrame } from "./cards.mjs";
import { statusBar } from "./status.mjs";
import { collapsedFeed } from "./activity.mjs";
import { paletteBox } from "./palette.mjs";
import { setTheme, THEME_NAMES, bold, dim, style } from "../core/theme.mjs";
import { startComposer } from "./composer.mjs";

const VERSION = "0.1.0";

export class ConsoleApp {
  constructor({ cwd = process.cwd(), rules = [], mode = "enforce", agent = "local", write = (s) => process.stdout.write(s) } = {}) {
    this.cwd = cwd;
    this.rules = rules;
    this.agent = agent;
    this.write = write;
    this.bus = new EventBus();
    this.state = initialState();
    this.state.status.mode = mode;
    this.expanded = false;
    this.overlay = null; // 'palette' | null

    this.pipeline = new Pipeline({ rules, cwd, agent, mode, onEvent: () => {} });
    attachPipeline(this.pipeline, this.bus);
    this.bus.onAny((e) => {
      this.state = reduce(this.state, e);
    });
    this.bus.emit(createEvent.sessionStarted({ agent }));
  }

  /* ---------------------------------------------------------- rendering */

  renderHeader() {
    return header({ mode: this.state.status.mode === "audit" ? "AUDIT MODE" : "PROTECTED", version: VERSION });
  }

  renderStatus() {
    return statusBar(this.state, { version: VERSION });
  }

  renderActivity() {
    return collapsedFeed(this.state.activity, { expanded: this.expanded });
  }

  /** Full re-render of the transcript region (used on clear / toggle). */
  renderTranscript() {
    const out = [this.renderHeader(), ``];
    for (const m of this.state.messages) {
      out.push(m.role === "user" ? userRow(m.text) : cirvixRow(m.text), ``);
    }
    if (this.narrow()) {
      out.push(`▼ Activity`, this.renderActivity(), ``);
    }
    out.push(this.renderStatus());
    return out.join("\n");
  }

  narrow() {
    return (process.stdout.columns ?? 80) < 90;
  }

  /* ------------------------------------------------------------- events */

  /** Animated "evaluating" line. Resolves with a stop() that clears it. */
  animate(label) {
    if (!process.stdout.isTTY) {
      this.write(`${dim("◐")} ${label}...\n`);
      return () => {};
    }
    let i = 0;
    const timer = setInterval(() => {
      process.stdout.write(`\r${dim(spinnerFrame(i++))} ${dim(label)}...`);
    }, 90);
    return () => {
      clearInterval(timer);
      process.stdout.write("\r" + " ".repeat(label.length + 6) + "\r");
    };
  }

  /** Evaluate one free-text line through policy and render the product UI. */
  async runOnce(input) {
    const text = String(input ?? "").trim();
    if (!text) return "";
    if (text.startsWith("/")) return this.runSlash(text);

    this.bus.emit(createEvent.userMessage(text));
    const lines = [userRow(text), ``, cirvixRow(`${dim("◐ Evaluating authorization...")}`)];
    const stop = this.animate("Evaluating policy");
    const parsed = parseRequest(text, { agent: this.agent });
    let decision;
    try {
      ({ decision } = decideNow({ ...parsed, rules: this.rules, cwd: this.cwd }));
    } finally {
      stop();
    }
    const event = {
      decision_id: `dec_local`,
      request_id: `req_local`,
      agent: this.agent,
      tool: parsed.tool,
      resource: parsed.args.path ?? parsed.args.url ?? parsed.args.command ?? "",
      risk: decision.risk ?? "medium",
      decision: decision.decision ?? "deny",
      policy: decision.rule,
      reason: decision.reason,
      latency_ms: 0,
    };
    this.bus.emit(createEvent.policyDecision(event));
    if (event.decision === "require_approval") this.bus.emit(createEvent.approvalRequested({ tool: event.tool, resource: event.resource }));
    this.bus.emit(createEvent.agentMessage(`Decision: ${event.decision}`));

    return [...lines, ``, this.renderDecision(event, parsed), ``, this.renderStatus()].join("\n");
  }

  renderDecision(event, parsed = {}) {
    const d = event.decision;
    if (d === "deny") {
      const target = event.resource || parsed.args?.command || "";
      return [blockedCard({ tool: event.tool, target, policy: event.policy, reason: event.reason }), ``, explainDecision(event)].join("\n");
    }
    if (d === "require_approval") {
      return heldCard({ tool: event.tool, target: event.resource, approvers: event.approvers ?? [], reason: event.reason });
    }
    return [
      policyCard({
        action: event.tool,
        risk: event.risk,
        policy: event.policy ?? "default",
        identity: `agent:${event.agent}`,
        reason: event.reason,
        latencyMs: event.latency_ms,
      }),
      ...(d === "sanitize" ? [``, explainDecision(event)] : []),
    ].join("\n");
  }

  /* ---------------------------------------------------------------- slash */

  async runSlash(input) {
    const [cmd, ...rest] = input.trim().split(/\s+/);
    const arg = rest.join(" ");
    switch (cmd.toLowerCase()) {
      case "/help":
        return paletteBox("/");
      case "/quit":
      case "/exit":
        return "quit";
      case "/clear":
        return "\x1b[2J\x1b[0;0H" + this.renderTranscript();
      case "/expand":
        this.expanded = true;
        return this.renderActivity();
      case "/collapse":
        this.expanded = false;
        return this.renderActivity();
      case "/theme": {
        if (!arg) return `Usage: /theme <${THEME_NAMES.join("|")}>\nCurrent: ${bold(process.env.CIRVIX_THEME ?? "dark")}`;
        try {
          setTheme(arg);
          process.env.CIRVIX_THEME = arg;
          return `${style("✓", "allow")} Theme → ${bold(arg)}`;
        } catch (err) {
          return `${style("✕", "block")} ${err.message}`;
        }
      }
      case "/audit":
      case "/logs":
        return this.renderActivity();
      case "/policies": {
        const names = this.rules.map((r) => `  • ${r.name ?? "(unnamed)"}  ${dim(r.effect ?? "")}`).join("\n");
        return `${bold("Policies")} ${dim(`(${this.rules.length} rules)`)}\n${names || dim("  (no rules loaded)")}`;
      }
      case "/sessions":
        return `${bold("Session")}  ${this.state.session?.id ?? "—"}  ${dim(`agent ${this.state.session?.agent ?? this.agent}`)}\n${dim(`${this.state.status.requests} requests this session`)}`;
      case "/doctor":
        return doctor(this.rules, this.state);
      case "/demo":
        return dim("Run `cirvix demo` in a fresh terminal for the full live interception demo.");
      case "/approvals": {
        if (!this.state.approvals.length) return dim("nothing waiting on a human");
        return this.state.approvals.map((a) => `  ${bold(a.approval_id ?? a.id ?? "approval")}  ${a.tool ?? ""}  ${dim(a.resource ?? "")}`).join("\n");
      }
      case "/config":
        return `${bold("Config")}\n  ${dim("theme")}  ${process.env.CIRVIX_THEME ?? "dark"}\n  ${dim("agent")}  ${this.agent}\n  ${dim("mode")}   ${this.state.status.mode}`;
      default: {
        // Prefix completion: "/pol" → show matches instead of erroring.
        const { filterCommands } = await import("./palette.mjs");
        const matches = filterCommands(input);
        if (matches.length) return paletteBox(input);
        return dim(`Unknown command "${cmd}". Type / for the palette.`);
      }
    }
  }

  /* ---------------------------------------------------------- interactive */

  async start() {
    this.write(this.renderTranscript() + "\n\n");
    this.write(dim("Type / for commands. Ctrl+K palette · Ctrl+O activity · Esc close.\n"));
    const rl = startComposer({
      prompt: "> ",
      onLine: async (line) => {
        if (!line) return;
        if (line === "/quit" || line === "/exit") return "quit";
        const out = await this.runOnce(line);
        if (out === "quit") return "quit";
        this.write("\n" + out + "\n\n");
        if (!this.narrow()) {
          // Side-pane refresh on wide terminals: reprint compact activity.
          this.write(dim("─ Activity ─") + "\n" + this.renderActivity() + "\n\n" + this.renderStatus() + "\n");
        }
      },
      onKey: (key) => {
        if (key === "toggle-activity") {
          this.expanded = !this.expanded;
          this.write("\n" + this.renderActivity() + "\n");
        } else if (key === "palette") {
          this.write("\n" + paletteBox("/") + "\n");
        } else if (key === "policies") {
          this.write("\n" + `Policies: ${this.rules.length} loaded` + "\n");
        }
      },
    });
    await new Promise((resolve) => rl.on("close", resolve));
    this.bus.emit(createEvent.sessionEnded({}));
    this.write("\n" + dim("Session ended. Audit chain intact.") + "\n");
  }
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/**
 * Heuristic: turn "Can the deploy bot run `rm -rf /`?" into a policy
 * request. Deliberately conservative — unknown shapes become a low-risk
 * workspace read that policy will judge on its merits, never an implicit
 * permit of something dangerous.
 */
export function parseRequest(text, { agent = "local" } = {}) {
  const t = String(text);
  const url = t.match(/https?:\/\/[^\s"'`]+/i)?.[0];
  const credPath = t.match(/(~\/\.aws\/credentials|\.env[^\s]*|\.aws[^\s]*)/i)?.[0];
  const cmd = t.match(/`([^`]+)`/)?.[1] ?? t.match(/run\s+"([^"]+)"/i)?.[1];

  if (credPath) return { tool: "read_file", server: null, args: { path: credPath }, agent };
  if (url && /collect|attacker|exfil|send|post/i.test(t)) {
    return { tool: "http_request", server: null, args: { url }, agent };
  }
  if (url) return { tool: "http_request", server: null, args: { url }, agent };
  if (cmd) return { tool: "shell_exec", server: null, args: { command: cmd }, agent };
  if (/deploy|production/i.test(t)) return { tool: "shell_exec", server: null, args: { command: "deploy production" }, agent };
  if (/database|db|sql/i.test(t)) return { tool: "db_query", server: null, args: { sql: t.slice(0, 200) }, agent };
  return { tool: "read_file", server: null, args: { path: "./" + t.slice(0, 60) }, agent };
}

function doctor(rules, state) {
  const rows = [
    ["Engine", style("✓ reachable", "allow")],
    ["Rules", rules.length ? `${rules.length} loaded` : style("none — run cirvix init", "warning")],
    ["Session", `${state.status.requests} requests`],
    ["Blocked", state.status.blocked > 0 ? style(`${state.status.blocked} denied`, "block") : "0"],
    ["Terminal", `${process.stdout.columns ?? 80} cols ${process.stdout.isTTY ? "(TTY)" : "(piped)"}`],
  ];
  return `${bold("Doctor")}\n` + rows.map(([k, v]) => `  ${dim(k.padEnd(9))} ${v}`).join("\n");
}
