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

import { readFileSync } from "node:fs";
import readline from "node:readline";
import { decideNow } from "../core/journal.mjs";
import { EventBus, createEvent, initialState, reduce } from "../core/events.mjs";
import { header, policyCard, blockedCard, heldCard, explainDecision, userRow, cirvixRow } from "./cards.mjs";
import { statusBar } from "./status.mjs";
import { collapsedFeed } from "./activity.mjs";
import { paletteBox } from "./palette.mjs";
import { setTheme, THEME_NAMES, bold, dim, style } from "../core/theme.mjs";
import { startComposer, KEY_HINT } from "./composer.mjs";

const VERSION = JSON.parse(
  readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
).version;

export class ConsoleApp {
  constructor({ cwd = process.cwd(), rules = [], policyFilePresent = null, mode = "enforce", agent = "local", input = process.stdin, output = process.stdout, write = (s) => output.write(s) } = {}) {
    this.cwd = cwd;
    this.rules = rules;
    this.policyFilePresent = policyFilePresent;
    this.agent = agent;
    this.write = write;
    this.input = input;
    this.output = output;
    this.transient = { palette: null };
    this.composer = null;
    this.redrawScheduled = false;
    this.bus = new EventBus();
    this.state = initialState();
    this.state.status.mode = mode;
    this.expanded = false;
    this.overlay = null; // 'palette' | null
    this.entries = [];
    this.errors = [];

    this.bus.onAny((e) => {
      this.state = reduce(this.state, e);
      this.entries.push({ ...e });
    });
    this.bus.emit(createEvent.sessionStarted({ agent }));
  }

  /* ---------------------------------------------------------- rendering */

  renderOptions() {
    return { width: this.output.columns ?? 80, preview: true };
  }

  renderHeader() {
    return header({ mode: "PREVIEW", version: VERSION, ...this.renderOptions() });
  }

  renderStatus() {
    return statusBar(this.state, { version: VERSION, ...this.renderOptions() });
  }

  renderActivity() {
    return collapsedFeed(this.state.activity, { expanded: this.expanded, ...this.renderOptions() });
  }

  /** Full re-render of the transcript region (used on clear / toggle). */
  renderTranscript() {
    const out = [this.renderHeader(), ``];
    for (const entry of this.entries) {
      if (entry.type === "USER_MESSAGE") out.push(userRow(entry.text, this.renderOptions()), ``);
      else if (entry.type === "POLICY_DECISION") out.push(this.renderDecision(entry.raw), ``);
      else if (entry.type === "response") out.push(cirvixRow(entry.text, this.renderOptions()), ``);
      else if (entry.type === "RUNTIME_ERROR") out.push(cirvixRow(`Error: ${entry.message}`, this.renderOptions()), ``);
    }
    out.push(`Activity (preview)`, this.renderActivity(), ``, this.renderStatus());
    if (this.transient.palette) out.push(paletteBox(this.transient.palette.query, { ...this.renderOptions(), selected: this.transient.palette.selected }));
    return out.join("\n");
  }

  narrow() {
    return (this.output.columns ?? 80) < 90;
  }

  /* ------------------------------------------------------------- events */

  requestRedraw() {
    if (this.redrawScheduled || !this.composer) return;
    this.redrawScheduled = true;
    queueMicrotask(() => {
      this.redrawScheduled = false;
      if (!this.composer) return;
      readline.cursorTo(this.output, 0, 0);
      readline.clearScreenDown(this.output);
      this.write(this.renderTranscript() + "\n" + KEY_HINT + "\n");
      this.composer.refresh();
    });
  }

  /** Evaluate one free-text line through policy and render the product UI. */
  async runOnce(input) {
    const text = String(input ?? "").trim();
    if (!text) return "";
    if (text.startsWith("/")) {
      const result = await this.runSlash(text);
      if (result && result !== "quit" && text !== "/clear") this.entries.push({ type: "response", text: result });
      return result;
    }

    this.bus.emit(createEvent.userMessage(text));
    const lines = [userRow(text, this.renderOptions()), ``, cirvixRow("Authorization preview", this.renderOptions())];
    const parsed = parseRequest(text, { agent: this.agent });
    const { decision } = decideNow({ ...parsed, rules: this.rules, cwd: this.cwd });
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
      remediation: decision.remediation,
      explicit: decision.explicit,
      latency_ms: 0,
    };
    this.bus.emit(createEvent.policyDecision(event));
    this.bus.emit(createEvent.agentMessage(`Decision: ${event.decision}`));

    return [...lines, ``, this.renderDecision(event, parsed), ``, this.renderStatus()].join("\n");
  }

  renderDecision(event, parsed = {}) {
    const d = event.decision;
    if (d === "deny") {
      const target = event.resource || parsed.args?.command || "";
      return [blockedCard({ tool: event.tool, target, policy: event.policy, reason: event.reason }, this.renderOptions()), ``, explainDecision(event, { policyFilePresent: this.policyFilePresent, ...this.renderOptions() })].join("\n");
    }
    if (d === "require_approval") {
      return heldCard({ tool: event.tool, target: event.resource, approvers: event.approvers ?? [], reason: event.reason }, this.renderOptions());
    }
    return [
      policyCard({
        action: event.tool,
        risk: event.risk,
        policy: event.policy ?? "default",
        identity: `agent:${event.agent}`,
        reason: event.reason,
        latencyMs: event.latency_ms,
        decision: d,
      }, this.renderOptions()),
      ...(d === "sanitize" ? [``, explainDecision(event, this.renderOptions())] : []),
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
      case "/clear": {
        this.entries = [];
        this.entries.push({ type: "response", text: "Preview cleared; decisions and activity above are gone from view only." });
        return "\x1b[2J\x1b[0;0H" + this.renderTranscript();
      }
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
    if (!this.input.isTTY || !this.output.isTTY) throw new Error("Interactive console requires input and output TTYs.");
    this.write(this.renderTranscript() + "\n" + KEY_HINT + "\n");
    const resize = () => this.requestRedraw();
    this.composer = startComposer({
      input: this.input,
      output: this.output,
      transient: this.transient,
      onLine: async (line, { signal }) => {
        if (signal.aborted) return;
        const out = await this.runOnce(line);
        if (signal.aborted) return;
        if (out === "quit") return "quit";
        this.requestRedraw();
      },
      onChange: () => {
        if (this.transient.palette || this.overlay) this.requestRedraw();
        this.overlay = this.transient.palette ? "palette" : null;
      },
      onError: (error) => {
        this.bus.emit(createEvent.runtimeError(error?.message ?? String(error)));
        this.requestRedraw();
      },
      onKey: (key) => {
        if (key === "toggle-activity") this.expanded = !this.expanded;
        else if (key === "policies") this.entries.push({ type: "response", text: `Policies: ${this.rules.length} loaded` });
        else if (key === "audit") this.entries.push({ type: "response", text: "Preview activity only; no audit records are written." });
        else if (key === "session") this.entries.push({ type: "response", text: `Preview session: ${this.state.status.requests} evaluations` });
        this.requestRedraw();
      },
    });
    this.output.on("resize", resize);
    await new Promise((resolve) => this.composer.once("close", resolve));
    this.output.removeListener("resize", resize);
    this.composer = null;
    this.bus.emit(createEvent.sessionEnded({}));
    this.write("\n" + dim("Preview session ended. No actions run or audit records written.") + "\n");
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
  const exact = t.trim().replace(/^[Rr][Uu][Nn][ \t]+/, "");
  if (/^(?:git[ \t]+status|(["'`])git[ \t]+status\1)$/.test(exact)) {
    return { tool: "git_status", server: null, args: {}, agent };
  }
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
