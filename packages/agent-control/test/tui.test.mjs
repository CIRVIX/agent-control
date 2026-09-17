import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  THEME_NAMES, setTheme, style, colors, roleForDecision, badgeForDecision,
} from "../src/core/theme.mjs";
import { EventBus, createEvent, initialState, reduce, EVENT } from "../src/core/events.mjs";
import { policyCard, blockedCard, explainDecision } from "../src/tui/cards.mjs";
import { statusBar } from "../src/tui/status.mjs";
import { collapsedFeed } from "../src/tui/activity.mjs";
import { filterCommands } from "../src/tui/palette.mjs";
import { ConsoleApp, parseRequest } from "../src/tui/app.mjs";

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
    assert.match(out, /BLOCKED/);
    assert.match(out, /NOT executed/);
  });
  it("console /theme rejects unknowns legibly", async () => {
    const app = new ConsoleApp({ rules: [], write: () => {} });
    const out = await app.runSlash("/theme casino");
    assert.match(out, /Unknown theme/);
  });
});
