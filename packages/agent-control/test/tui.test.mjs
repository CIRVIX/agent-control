import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { consoleCmd } from "../src/commands/console.mjs";
import { demo } from "../src/commands/demo.mjs";
import { STARTER_POLICY } from "../src/commands/init.mjs";
import { compile } from "../src/core/policy-dsl.mjs";
import { STARTER_RULES } from "../src/core/policy.mjs";
import { decideNow } from "../src/core/journal.mjs";
import { normalize } from "../src/core/normalize.mjs";

import {
  THEME_NAMES, setTheme, style, colors, roleForDecision, badgeForDecision,
} from "../src/core/theme.mjs";
import { EventBus, createEvent, initialState, reduce, EVENT } from "../src/core/events.mjs";
import { policyCard, toolCard, blockedCard, heldCard, explainDecision, header, frame, userRow, cirvixRow, displayWidth, clipText, wrapText } from "../src/tui/cards.mjs";
import { statusBar } from "../src/tui/status.mjs";
import { collapsedFeed, activityRow } from "../src/tui/activity.mjs";
import { filterCommands } from "../src/tui/palette.mjs";
import { ConsoleApp, parseRequest } from "../src/tui/app.mjs";

const cli = fileURLToPath(new URL("../bin/cirvix.mjs", import.meta.url));
const gitStatusRequests = ["Run git status", "run git status", "RUN git status", "git status", 'Run "git status"', "Run 'git status'", "Run `git status`", '"git status"', "'git status'", "`git status`", "  Run\tgit  status  "];
const plain = (text) => text.replace(/\x1b\[[0-9;]*m/g, "");
const runCli = (args) => spawnSync(process.execPath, [cli, ...args], {
  encoding: "utf8", env: { ...process.env, NO_COLOR: "1" }, timeout: 15000,
});

describe("TUI regressions", () => {
  it("renders an exact 50-column blocked preview card", () => {
    const row = (text) => `│ ${text.padEnd(42)} │`;
    const expected = [
      `┌─ AUTHORIZATION PREVIEW ${"─".repeat(20)}┐`,
      row("Would block"),
      row(""),
      row("read_file"),
      row(""),
      row(""),
      row("No action executed by preview."),
      `└${"─".repeat(44)}┘`,
    ].join("\n");
    assert.equal(plain(blockedCard({ tool: "read_file" }, { width: 50, preview: true })), expected);
  });
  it("header and status use the same manifest version as the CLI", () => {
    const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    const result = runCli(["--version"]);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), version);
    const app = new ConsoleApp({ write: () => {} });
    assert.ok(plain(app.renderHeader()).includes(`v${version}`));
    const columns = Object.getOwnPropertyDescriptor(process.stdout, "columns");
    try {
      Object.defineProperty(process.stdout, "columns", { configurable: true, value: 100 });
      assert.ok(plain(app.renderStatus()).includes(`v${version}`));
    } finally {
      if (columns) Object.defineProperty(process.stdout, "columns", columns);
      else delete process.stdout.columns;
    }
  });
  it("reason truncation keeps the beginning in every card", () => {
    const reason = "No rule permits this call. " + "Long explanation. ".repeat(10);
    for (const [render, length] of [[policyCard, 60], [toolCard, 64], [blockedCard, 72], [heldCard, 68]]) {
      const out = plain(render({ tool: "read_file", reason, decision: "deny" }, { width: 120 }));
      assert.ok(out.includes(reason.slice(0, length - 1) + "…"), out);
      assert.ok(!out.includes("…" + reason.slice(-(length - 1))), out);
    }
  });
  it("path and URL truncation still keeps the tail", () => {
    for (const target of ["/workspace/".repeat(12) + "credentials", "https://docs.example.com/" + "segment/".repeat(15) + "deploy"]) {
      for (const [render, length] of [[toolCard, 64], [blockedCard, 72], [heldCard, 72], [explainDecision, 76]]) {
        const out = plain(render({ tool: "read_file", target, detail: target, resource: target, decision: "deny" }, { width: 120 }));
        assert.ok(out.includes("…" + target.slice(-(length - 1))), out);
      }
    }
  });
  it("only exact git status requests use the existing git_status normalization", () => {
    const expected = normalize({ tool: "git_status", arguments: {} });
    for (const text of gitStatusRequests) {
      const parsed = parseRequest(text, { agent: "test-agent" });
      assert.deepEqual(parsed, { tool: "git_status", server: null, args: {}, agent: "test-agent" }, text);
      const call = normalize(parsed);
      for (const key of ["tool", "action", "resource", "command", "risk"]) {
        assert.equal(call[key], expected[key], `${text}: ${key}`);
      }
    }
  });
  it("does not alias arbitrary commands, arguments, compounds or injected text", () => {
    for (const text of [
      "Run npm test", "Run git log", "Run Git Status", "Run git status --short", "Run git status .",
      "Run git -C other status", "Run git status; echo extra", "Run git status && echo extra",
      "Run git status || echo extra", "Run git status | cat", "Run git status > output",
      "Run git status\necho extra", "Run git\nstatus", "Run $(git status)", "Run git status $(echo extra)",
      'Run "git status; echo extra"', "Run `git status && echo extra`", 'Run "git status" --short',
      "Run `git status` && echo extra", "Run `git status` `echo extra`", "Please run `git status` then deploy",
      "Run 'git status\"", "Run git status\u0000", "Run git status # extra", "Run git status & echo extra",
    ]) {
      assert.notEqual(parseRequest(text).tool, "git_status", text);
      assert.notEqual(normalize(parseRequest(text)).action, "vcs.read", text);
    }
    assert.deepEqual(parseRequest('Run "npm test"').args, { command: "npm test" });
    assert.equal(parseRequest('Run "npm test"').tool, "shell_exec");
  });
  it("matches the real demo git decision under identical rules", async () => {
    const cwd = mkdtempSync(join(tmpdir(), "cirvix-tui-demo-"));
    try {
      for (const rules of [compile(STARTER_POLICY, { cwd, origin: "test" }).rules, []]) {
        const { result } = await demo({ cwd, rules, pace: 0, json: true, write: () => {} });
        const git = result.steps.find((step) => step.tool === "git.status");
        assert.ok(git);
        for (const text of gitStatusRequests) {
          const app = new ConsoleApp({ cwd, rules, agent: "claude-code", write: () => {} });
          let event;
          app.bus.on(EVENT.POLICY_DECISION, (e) => { event = e; });
          await app.runOnce(text);
          assert.equal(event.decision, git.decision, text);
          assert.equal(event.policy, git.policy, text);
        }
      }
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  });
  it("adds init only for known-missing policy and default deny, preserving engine fields and remediation", async () => {
    for (const policyFilePresent of [false, true, null]) {
      for (const rules of [STARTER_RULES, [], [{ name: "explicit-deny", effect: "forbid", remediation: "Ask the policy owner." }]]) {
        const text = 'Run "unknown-command"';
        const { decision } = decideNow({ ...parseRequest(text), rules });
        const { app, output } = await consoleCmd({ rules, policyFilePresent, evalText: text, write: () => {} });
        const event = app.state.activity.find((e) => e.type === EVENT.POLICY_DECISION);
        assert.ok(event);
        assert.equal(event.decision, decision.decision);
        assert.equal(event.policy, decision.rule);
        assert.equal(event.reason, decision.reason);
        assert.equal(event.raw.remediation, decision.remediation);
        assert.equal(event.raw.explicit, decision.explicit);
        const out = plain(output).replace(/\s+/g, " ");
        assert.equal(out.includes("cirvix init"), policyFilePresent === false && decision.explicit === false);
        assert.ok(out.includes(decision.remediation));
        assert.doesNotMatch(out, /cirvix logs --tree|req_local|dec_local/);
        assert.ok(out.includes("cirvix policy list"));
      }
    }
    const app = new ConsoleApp({ rules: STARTER_RULES, policyFilePresent: false, write: () => {} });
    assert.doesNotMatch(await app.runOnce("Run git status"), /cirvix init/);
    const out = await app.runOnce("Read ~/.aws/credentials");
    assert.doesNotMatch(out, /cirvix init/);
    assert.match(out, /Use a scoped secret handle/);
    for (const decision of ["allow", "sanitize", "require_approval"]) {
      assert.doesNotMatch(explainDecision({ decision, explicit: false }, { policyFilePresent: false }), /cirvix init/);
    }
  });
  it("CLI carries policy presence for missing, discovered and explicit files", () => {
    const cwd = mkdtempSync(join(tmpdir(), "cirvix-tui-policy-"));
    try {
      const args = ["console", "--cwd", cwd, "--eval", 'Run "unknown-command"'];
      const missing = runCli(args);
      assert.equal(missing.status, 0, missing.stderr);
      assert.match(missing.stdout, /No policy file found.*cirvix init/);
      for (const name of ["cirvix.policy", "cirvix.policy.json", ".cirvix/policy.json", "custom.json"]) {
        const path = join(cwd, name);
        mkdirSync(dirname(path), { recursive: true });
        writeFileSync(path, "[]");
        const result = runCli(name === "custom.json" ? [...args, "--policy", path] : args);
        assert.equal(result.status, 0, result.stderr);
        assert.match(result.stdout, /No rule permits this call/);
        assert.doesNotMatch(result.stdout, /cirvix init/);
        assert.match(result.stdout, /Add a permit rule/);
        rmSync(path);
      }
      const explicit = runCli(["console", "--cwd", cwd, "--eval", "Read ~/.aws/credentials"]);
      assert.equal(explicit.status, 0, explicit.stderr);
      assert.doesNotMatch(explicit.stdout, /cirvix init/);
      assert.match(explicit.stdout, /Use a scoped secret handle/);
      const absent = runCli([...args, "--policy", join(cwd, "absent.json")]);
      assert.notEqual(absent.status, 0);
      assert.doesNotMatch(absent.stdout, /cirvix init/);
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  });
});

describe("display-cell geometry and truthful previews", () => {
  const samples = [["a", 1], ["\u{1f534}", 2], ["界", 2], ["e\u0301", 1], ["\u{1f469}\u200d\u{1f4bb}", 2], ["\u{1f1fa}\u{1f1f8}", 2], ["1\ufe0f\u20e3", 2], ["\u{1f44d}\u{1f3fd}", 2]];
  const measured = (text) => [...new Intl.Segmenter(undefined, { granularity: "grapheme" }).segment(plain(text))].reduce((sum, { segment }) => sum + (samples.find(([value]) => value === segment)?.[1] ?? 1), 0);
  const fits = (text, width) => {
    for (const line of text.split("\n")) assert.ok(measured(line) <= width, `${width}: ${line}`);
  };
  it("counts graphemes and SGR by cells, never splitting emoji or combining marks", () => {
    for (const [text, cells] of samples) {
      assert.equal(displayWidth(`\x1b[38;2;1;2;3m${text}\x1b[0m`), cells);
      assert.equal(plain(clipText(text.repeat(4), cells + 1)), text + "…");
      assert.equal(plain(clipText(text.repeat(4), cells + 1, { tail: true })), "…" + text);
      assert.equal(plain(wrapText(text.repeat(4), cells)), Array(4).fill(text).join("\n"));
    }
    assert.equal(displayWidth("e\x1b[31m\u0301"), 1);
    const wrapped = wrapText("\x1b[31m" + "界".repeat(6) + "\x1b[39m", 4);
    for (const line of wrapped.split("\n")) {
      assert.ok(line.startsWith("\x1b[31m"));
      assert.ok(line.endsWith("\x1b[0m"));
      assert.equal(measured(line), 4);
    }
    assert.ok(clipText("\x1b[31mabcdef", 3).includes("\x1b[0m"));
  });
  for (const width of [50, 80, 120, 140]) {
    it(`bounds every renderer and frame edge at ${width} cells`, () => {
      const long = "\x1b[31m" + samples.map(([text]) => text).join("").repeat(20) + "\x1b[0m";
      const reason = "No rule permits this call. " + "Long explanation. ".repeat(20);
      const target = "/workspace/".repeat(30) + "credentials";
      const data = { tool: long, action: long, risk: long, identity: long, policy: long, reason, detail: target, target, resource: target, approvers: [long], checks: [{ ok: true, label: long }], decision: "deny", remediation: long };
      const state = initialState();
      state.status.policyName = long;
      state.status.requests = 123456789012345;
      for (const preview of [false, true]) {
        const options = { width, preview, version: "0.2.1" };
        for (const render of [policyCard, toolCard, blockedCard, heldCard]) {
          const out = render(data, options);
          fits(out, width);
          assert.deepEqual(new Set(out.split("\n").map(measured)), new Set([width - 4]));
          assert.match(plain(out), /No rule permits this call\./);
        }
        for (const render of [toolCard, blockedCard, heldCard, explainDecision]) assert.match(plain(render(data, options)), /credentials/);
        for (const out of [header(options), statusBar(state, options), userRow(long, options), cirvixRow(long, options), explainDecision(data, options), collapsedFeed([data], options), collapsedFeed([data], { ...options, expanded: true }), activityRow(data, options)]) fits(out, width);
        const box = frame(long, [long, "short\n" + long], options);
        assert.deepEqual(new Set(box.split("\n").map(measured)), new Set([width - 4]));
      }
    });
    it(`keeps preview wording and manifest version at ${width} cells`, async () => {
      const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
      const app = new ConsoleApp({ output: { columns: width }, write: () => {} });
      for (const text of [app.renderHeader(), app.renderStatus()]) {
        assert.match(plain(text), /AUTHORIZATION PREVIEW/);
        assert.ok(plain(text).includes(`v${version}`));
        assert.doesNotMatch(plain(text), /PROTECTED|Audit\s*✓|P(?:50|95).*ms/);
        fits(text, width);
      }
      for (const [decision, wording] of [["allow", "Would allow"], ["deny", "Would block"], ["sanitize", "Would sanitize"], ["require_approval", "Would require approval"]]) {
        const event = { decision, tool: "read_file", agent: "local", request_id: "req_local", latency_ms: 0, latencyMs: 0 };
        for (const text of [app.renderDecision(event), policyCard(event, { width, preview: true }), toolCard(event, { width, preview: true }), explainDecision(event, { width, preview: true }), collapsedFeed([event], { width, preview: true, expanded: true })]) {
          const out = plain(text).replace(/\s+/g, " ");
          assert.ok(out.includes(wording), out);
          assert.match(out, /No action executed by preview/);
          assert.doesNotMatch(out, /ALLOWED|SANITIZED|BLOCKED|HELD|forwarded|received a safe version|suspended|Waits on|cirvix approvals|req_local|cirvix logs --tree|Latency.*ms/);
          fits(text, width);
        }
      }
      await app.runOnce("Read " + "界".repeat(90));
      fits(app.renderTranscript(), width);
      assert.doesNotMatch(plain(app.renderTranscript()), /all clear|blocked\/held|\d+ actions|PROTECTED/);
    });
  }
  it("preserves runtime explanations and sanitize badges without preview", () => {
    assert.match(policyCard({ decision: "sanitize" }), /SANITIZED/);
    assert.doesNotMatch(policyCard({ decision: "sanitize" }), /ALLOWED/);
    assert.match(explainDecision({ decision: "sanitize" }), /forwarded this call/);
    assert.match(heldCard({}), /suspended/);
    assert.match(explainDecision({ decision: "deny", request_id: "real-id" }), /cirvix logs --tree real-id/);
  });
});

describe("theme: semantic roles, never raw colors", () => {
  it("ships dark/light/midnight/high-contrast (+monochrome)", () => {
    for (const name of ["dark", "light", "midnight", "high-contrast", "monochrome"]) {
      assert.ok(THEME_NAMES.includes(name), `missing theme ${name}`);
    }
  });
  it("setTheme rejects unknowns instead of silently staying", () => {
    assert.throws(() => setTheme("casino"), /Unknown theme/);
    setTheme("dark");
  });
  it("decision → role mapping is total", () => {
    assert.equal(roleForDecision("allow"), "allow");
    assert.equal(roleForDecision("deny"), "block");
    assert.equal(roleForDecision("require_approval"), "hold");
    assert.equal(roleForDecision("sanitize"), "sanitize");
  });
  it("badges carry icon AND word (never icon-only)", () => {
    const b = badgeForDecision("deny");
    assert.equal(b.label, "BLOCKED");
    assert.ok(b.icon.length > 0);
  });
  it("NO_COLOR-safe: style() degrades to plain text", () => {
    process.env.NO_COLOR = "1";
    assert.equal(style("x", "block"), "x");
    delete process.env.NO_COLOR;
  });
  it("colors.* namespace exists for every role", () => {
    for (const k of ["allow", "sanitize", "block", "info", "warning", "error"]) {
      assert.equal(typeof colors[k], "function");
    }
  });
});

describe("events: engine → bus → reducer", () => {
  it("bus delivers typed events and isolates broken listeners", () => {
    const bus = new EventBus();
    const seen = [];
    bus.on(EVENT.POLICY_DECISION, (e) => seen.push(e));
    bus.on(EVENT.POLICY_DECISION, () => { throw new Error("broken UI"); });
    bus.emit(createEvent.policyDecision({ decision: "deny", tool: "t", resource: "r" }));
    assert.equal(seen.length, 1);
    assert.equal(seen[0].type, "POLICY_DECISION");
  });
  it("reducer counts decisions for the status bar", () => {
    let s = initialState();
    s = reduce(s, createEvent.policyDecision({ decision: "allow", tool: "a" }));
    s = reduce(s, createEvent.policyDecision({ decision: "deny", tool: "b" }));
    assert.equal(s.status.requests, 2);
    assert.equal(s.status.allowed, 1);
    assert.equal(s.status.blocked, 1);
  });
  it("evaluation flag clears on decision", () => {
    let s = reduce(initialState(), createEvent.evaluationStarted({}));
    assert.equal(s.evaluating, true);
    s = reduce(s, createEvent.policyDecision({ decision: "allow" }));
    assert.equal(s.evaluating, false);
  });
});

describe("cards: every tool call is a visual object", () => {
  it("policy card names action/risk/policy/identity", () => {
    const out = policyCard({ action: "shell.exec", risk: "medium", policy: "production-deploy", identity: "agent:deploy-bot" });
    assert.match(out, /POLICY DECISION/);
    assert.match(out, /ALLOWED/);
    assert.match(out, /shell\.exec/);
  });
  it("blocked card says what was NOT executed", () => {
    const out = blockedCard({ tool: "filesystem.read", target: "~/.aws/credentials", policy: "credential-protection", reason: "sensitive" });
    assert.match(out, /BLOCKED/);
    assert.match(out, /NOT executed/);
  });
  it("explanations are human sentences, not dumps", () => {
    const out = explainDecision({ decision: "deny", policy: "credential-exfiltration", resource: "https://attacker.example.com/collect", reason: "matches exfil pattern" });
    assert.match(out, /stopped this request/);
    assert.match(out, /No network request was sent/);
  });
});

describe("status bar + activity feed", () => {
  it("wide bar shows mode/requests/latency", () => {
    let s = initialState();
    s.status.requests = 148; s.status.blocked = 21;
    const out = statusBar(s, { width: 100 });
    assert.match(out, /PROTECTED/);
    assert.match(out, /148/);
  });
  it("narrow bar collapses instead of wrapping", () => {
    const out = statusBar(initialState(), { width: 60 });
    assert.ok(out.split("\n").length <= 3);
  });
  it("feed collapses counts, expands rows", () => {
    const mk = (d) => createEvent.policyDecision({ decision: d, tool: "t" });
    const acts = [mk("allow"), mk("deny")];
    assert.match(collapsedFeed(acts, { expanded: false }), /2 actions/);
    assert.match(collapsedFeed(acts, { expanded: true }), /BLOCKED|deny|t/);
  });
});

describe("palette + console", () => {
  it("/pol completes to /policies", () => {
    const names = filterCommands("/pol").map((c) => c.name);
    assert.ok(names.includes("/policies"));
  });
  it("free text maps credential reads to the deny path", () => {
    const p = parseRequest("Read ~/.aws/credentials");
    assert.equal(p.tool, "read_file");
  });
  it("console blocks the credential read end-to-end (real engine)", async () => {
    const { compile } = await import("../src/core/policy-dsl.mjs");
    const { STARTER_POLICY } = await import("../src/commands/init.mjs");
    const rules = compile(STARTER_POLICY, { cwd: process.cwd(), origin: "test" }).rules;
    const app = new ConsoleApp({ rules, write: () => {} });
    const out = await app.runOnce("Read ~/.aws/credentials");
    assert.match(out, /Would block/);
    assert.match(out, /No action executed by preview/);
  });
  it("console /theme rejects unknowns legibly", async () => {
    const app = new ConsoleApp({ rules: [], write: () => {} });
    const out = await app.runSlash("/theme casino");
    assert.match(out, /Unknown theme/);
  });
});
