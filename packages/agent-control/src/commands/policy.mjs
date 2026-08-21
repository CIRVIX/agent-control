/**
 * `cirvix policy` — check, test, explain, list.
 *
 *   cirvix policy check                    does this file load, and is it sane
 *   cirvix policy test                     run the test cases the file declares
 *   cirvix policy explain --tool …         why would this call be decided that way
 *   cirvix policy list                     the active rules
 *
 * WHY `explain` IS A FIRST-CLASS COMMAND
 *
 * The single most common failure of a policy engine in production is not a
 * wrong decision — it is a rule that everyone believes is protecting them and
 * which has never matched anything. It loads, it validates, it appears in the
 * list, and it is dead. `explain` prints every rule that was considered and
 * whether it matched, so a dead rule is visible the first time somebody looks
 * rather than during the incident it failed to prevent.
 *
 * WHY `test` MATTERS MORE THAN `check`
 *
 * `check` proves the file parses. `test` proves it does what the author meant.
 * Only the second one survives a refactor, and a rule set nobody dares change
 * ossifies until it is bypassed rather than updated.
 */

import { readFile } from "node:fs/promises";

import { evaluate, parseRules, validateRules } from "../core/policy.mjs";
import { compile, toSource, PolicySyntaxError } from "../core/policy-dsl.mjs";
import { DECISION, toDecision } from "../core/decisions.mjs";
import { normalize, policyRequest } from "../core/normalize.mjs";
import { classify } from "../core/risk.mjs";
import { bold, dim, green, red, amber, blue, plural } from "../core/format.mjs";

/* -------------------------------------------------------------------------- */
/*  Loading                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Loads a policy from either format.
 *
 * `.json` is the engine's on-disk shape; anything else is the DSL. Sniffing the
 * content rather than trusting the extension, because a `.policy` file
 * containing JSON should still work — the alternative is a confusing parse
 * error about an unexpected `{`.
 */
export async function loadPolicyFile(path, { cwd = process.cwd() } = {}) {
  const source = await readFile(path, "utf8");
  const looksJson = /^\s*[[{]/.test(source);

  if (looksJson) {
    const rules = parseRules(JSON.parse(source));
    return { rules, tests: [], format: "json", source, path };
  }

  const { rules, tests } = compile(source, { cwd, origin: path });
  return { rules, tests, format: "dsl", source, path };
}

/* -------------------------------------------------------------------------- */
/*  check                                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Parses and validates. Exit code 1 on an error, 0 on warnings only — warnings
 * are things that load and probably should not, and failing CI on them would
 * teach people to stop reading them.
 */
export async function check({ path, cwd = process.cwd(), json = false, strict = false }) {
  let loaded;
  try {
    loaded = await loadPolicyFile(path, { cwd });
  } catch (err) {
    const result = {
      ok: false,
      path,
      errors: [{ rule: null, message: err.message }],
      warnings: [],
      rules: 0,
    };
    return {
      result,
      code: 1,
      output: json
        ? JSON.stringify(result, null, 2)
        : `\n  ${red(bold("policy did not load"))}\n\n  ${err instanceof PolicySyntaxError ? err.message.split("\n").join("\n  ") : err.message}\n\n`,
    };
  }

  const validation = validateRules(loaded.rules);
  const result = {
    ok: validation.ok,
    path,
    format: loaded.format,
    rules: validation.rules,
    tests: loaded.tests.length,
    errors: validation.errors,
    warnings: validation.warnings,
  };

  const code = validation.ok ? (strict && validation.warnings.length ? 1 : 0) : 1;

  if (json) return { result, code, output: JSON.stringify(result, null, 2) };

  const lines = [""];
  if (validation.ok) {
    lines.push(
      `  ${green(bold("policy is valid"))}  ${dim(`${plural(validation.rules, "rule")}, ${plural(loaded.tests.length, "test case")} · ${loaded.format}`)}`,
    );
  } else {
    lines.push(`  ${red(bold("policy is invalid"))}  ${dim(`${plural(validation.errors.length, "error")}`)}`);
  }
  lines.push("");

  for (const e of validation.errors) {
    lines.push(`  ${red("error")}    ${e.rule ? bold(e.rule) + "  " : ""}${e.message}`);
  }
  for (const w of validation.warnings) {
    lines.push(`  ${amber("warning")}  ${w.rule ? bold(w.rule) + "  " : ""}${dim(w.message)}`);
  }
  if (validation.errors.length || validation.warnings.length) lines.push("");
  if (validation.ok && loaded.tests.length) {
    lines.push(`  ${dim("Run the test cases:")}  ${blue("cirvix policy test")}`);
    lines.push("");
  }

  return { result, code, output: lines.join("\n") };
}

/* -------------------------------------------------------------------------- */
/*  test                                                                       */
/* -------------------------------------------------------------------------- */

/**
 * Runs the `test` blocks declared in the policy file.
 *
 * Every case is evaluated through the same normalization the runtime uses, so a
 * test passing means the *runtime* would decide that way — not that the rule
 * matcher would, given a hand-built request the runtime never constructs.
 */
export async function test({ path, cwd = process.cwd(), json = false, filter = null }) {
  const loaded = await loadPolicyFile(path, { cwd });

  if (!loaded.tests.length) {
    const result = { ok: true, total: 0, passed: 0, failed: 0, cases: [] };
    return {
      result,
      code: 0,
      output: json
        ? JSON.stringify(result, null, 2)
        : `\n  ${amber("no test cases")}  ${dim(`${path} declares no \`test\` blocks.`)}\n\n  ${dim("A policy file that ships its own tests is one you can change safely. Add:")}\n\n${dim('    test "dotenv is not readable":\n      tool = filesystem.read\n      path = .env\n      expect deny')}\n\n`,
    };
  }

  const cases = [];
  for (const t of loaded.tests) {
    if (filter && !t.name.toLowerCase().includes(String(filter).toLowerCase())) continue;

    const call = normalize(
      { tool: t.call.tool, server: t.call.server ?? null, arguments: t.call.arguments },
      { agent: t.call.agent, environment: t.call.environment, cwd },
    );
    const decision = evaluate(policyRequest(call), loaded.rules, { cwd });
    const actual = decision.decision ?? toDecision(decision.verdict);
    const expected = normalizeExpectation(t.expect);

    cases.push({
      name: t.name,
      line: t.line,
      expected,
      actual,
      passed: actual === expected,
      rule: decision.rule,
      risk: call.risk,
      tool: call.tool,
      resource: call.resource,
      reason: decision.reason,
    });
  }

  const passed = cases.filter((c) => c.passed).length;
  const failed = cases.length - passed;
  const result = { ok: failed === 0, total: cases.length, passed, failed, cases };

  if (json) return { result, code: failed ? 1 : 0, output: JSON.stringify(result, null, 2) };

  const lines = ["", `  ${bold(path)}`, ""];
  for (const c of cases) {
    if (c.passed) {
      lines.push(`  ${green("✓")} ${c.name}  ${dim(`→ ${c.actual}${c.rule ? ` (${c.rule})` : ""}`)}`);
    } else {
      lines.push(`  ${red("✗")} ${bold(c.name)}  ${dim(`line ${c.line}`)}`);
      lines.push(`      ${dim("expected")}  ${green(c.expected)}`);
      lines.push(`      ${dim("actual")}    ${red(c.actual)}${c.rule ? dim(`  by ${c.rule}`) : dim("  by default-deny")}`);
      lines.push(`      ${dim("call")}      ${c.tool} ${dim(c.resource || "")}  ${dim(`risk ${String(c.risk).toUpperCase()}`)}`);
      lines.push(`      ${dim(c.reason ?? "")}`);
      lines.push("");
    }
  }
  lines.push("");
  lines.push(
    failed === 0
      ? `  ${green(bold(`${passed} passed`))}`
      : `  ${red(bold(`${failed} failed`))}  ${dim(`${passed} passed`)}`,
  );
  lines.push("");

  return { result, code: failed ? 1 : 0, output: lines.join("\n") };
}

/** `allow`/`permit` are the same expectation; so are `deny`/`forbid`. */
function normalizeExpectation(value) {
  const v = String(value).toLowerCase();
  return (
    {
      allow: DECISION.ALLOW,
      permit: DECISION.ALLOW,
      deny: DECISION.DENY,
      forbid: DECISION.DENY,
      denied: DECISION.DENY,
      hold: DECISION.REQUIRE_APPROVAL,
      require_approval: DECISION.REQUIRE_APPROVAL,
      approval: DECISION.REQUIRE_APPROVAL,
      sanitize: DECISION.SANITIZE,
      audit_only: DECISION.AUDIT_ONLY,
      audit: DECISION.AUDIT_ONLY,
    }[v] ?? v
  );
}

/* -------------------------------------------------------------------------- */
/*  explain                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Why would this call be decided this way?
 *
 * Prints the normalized call, the risk classification with the signals that
 * fired, the decision, and every rule that was considered with whether it
 * matched. The considered-list is the part that finds dead rules.
 */
export async function explain({
  path,
  rules = null,
  cwd = process.cwd(),
  json = false,
  tool,
  args = {},
  agent = "local",
  environment = "local",
}) {
  // `rules` lets this run against the built-in starter set, which has no file.
  const loaded = rules ? { rules } : await loadPolicyFile(path, { cwd });

  const call = normalize({ tool, arguments: args }, { agent, environment, cwd });
  const risk = classify(call);
  call.risk = risk.level;

  const decision = evaluate(policyRequest(call), loaded.rules, { cwd });
  const final = decision.decision ?? toDecision(decision.verdict);

  const result = {
    call: {
      tool: call.tool,
      action: call.action,
      resource: call.resource,
      destination: call.destination,
      command: call.command,
      agent: call.agent,
      environment: call.environment,
      insideWorkspace: call.insideWorkspace,
      egress: call.egress,
    },
    risk: { level: risk.level, signals: risk.signals, reason: risk.reason, posture: risk.posture },
    decision: final,
    rule: decision.rule,
    reason: decision.reason,
    remediation: decision.remediation ?? null,
    approvers: decision.approvers ?? [],
    considered: decision.considered,
  };

  if (json) return { result, code: final === DECISION.DENY ? 1 : 0, output: JSON.stringify(result, null, 2) };

  const tone = { allow: green, sanitize: blue, require_approval: amber, deny: red, audit_only: dim }[final] ?? dim;
  const riskTone = { low: dim, medium: blue, high: amber, critical: red }[risk.level] ?? dim;

  const lines = [
    "",
    `  ${tone(bold(String(final).toUpperCase().replace(/_/g, " ")))}   ${bold(call.tool)}  ${dim(call.resource || call.command || "")}`,
    "",
    `  ${dim("action")}      ${call.action}`,
    `  ${dim("resource")}    ${call.resource || dim("—")}`,
    call.command ? `  ${dim("command")}     ${call.command}` : "",
    call.destination ? `  ${dim("destination")} ${call.destination}` : "",
    `  ${dim("workspace")}   ${call.insideWorkspace ? "inside" : red("outside")}`,
    `  ${dim("egress")}      ${call.egress}`,
    "",
    `  ${dim("risk")}        ${riskTone(bold(risk.level.toUpperCase()))}  ${dim(`default posture: ${risk.posture}`)}`,
    ...risk.signals.map((s) => `    ${dim("·")} ${s.id.padEnd(28)} ${dim(s.why)}`),
    "",
    `  ${dim("rule")}        ${decision.rule ?? dim("— no rule matched (default deny)")}`,
    `  ${dim("reason")}      ${decision.reason}`,
    decision.remediation ? `  ${dim("fix")}         ${blue(decision.remediation)}` : "",
    decision.approvers?.length ? `  ${dim("waits on")}    ${decision.approvers.join(", ")}` : "",
    "",
    `  ${dim("considered")}  ${dim(`${decision.considered.filter((c) => c.matched).length} of ${decision.considered.length} matched`)}`,
    ...decision.considered.map(
      (c) =>
        `    ${c.matched ? bold("→") : dim(" ")} ${dim(String(c.effect).padEnd(11))} ${c.matched ? c.rule : dim(c.rule)}`,
    ),
    "",
  ].filter((l) => l !== "");

  return { result, code: final === DECISION.DENY ? 1 : 0, output: lines.join("\n") + "\n" };
}

/* -------------------------------------------------------------------------- */
/*  list                                                                       */
/* -------------------------------------------------------------------------- */

export function list(rules, { json = false, source = false, cwd = process.cwd() } = {}) {
  if (json) return { output: JSON.stringify(rules, null, 2), code: 0 };
  if (source) return { output: "\n" + toSource(rules, { cwd }) + "\n", code: 0 };

  const tone = { permit: green, forbid: red, hold: amber, sanitize: blue, audit_only: dim };
  const label = { permit: "allow", forbid: "deny", hold: "approval", sanitize: "sanitize", audit_only: "audit" };

  const lines = ["", `  ${bold(plural(rules.length, "rule"))}`, ""];
  for (const r of rules) {
    const paint = tone[r.effect] ?? dim;
    lines.push(`    ${paint((label[r.effect] ?? r.effect).padEnd(9))} ${bold(r.name)}`);
    const scope = [
      r.actions?.length ? r.actions.join(", ") : null,
      r.resources?.length ? r.resources.join(", ") : null,
      r.when?.length ? r.when.map((c) => `${c.path} ${c.op} ${Array.isArray(c.value) ? `[${c.value.join("|")}]` : c.value}`).join(" and ") : null,
    ]
      .filter(Boolean)
      .join("  ·  ");
    if (scope) lines.push(`              ${dim(scope)}`);
    if (r.reason) lines.push(`              ${dim(r.reason)}`);
    lines.push("");
  }

  return { output: lines.join("\n"), code: 0 };
}
