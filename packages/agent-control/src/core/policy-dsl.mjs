/**
 * The policy DSL — the syntax people actually write.
 *
 *   allow:
 *     tool = git.status
 *
 *   allow:
 *     tool = filesystem.read
 *     path = ./src/**
 *
 *   deny:
 *     tool = shell.exec
 *     command = "rm -rf"
 *
 *   deny:
 *     network.destination = 169.254.169.254
 *
 *   require_approval:
 *     tool = database.write
 *
 *   require_approval:
 *     tool = shell.exec
 *     risk >= HIGH
 *
 * This compiles to the JSON rule shape the engine already evaluates. It is a
 * front end, not a second engine — `compile()` produces exactly the objects
 * `parseRules()` validates, and every semantic in this file is expressible in
 * that JSON. That constraint is deliberate: the moment the DSL can say
 * something the JSON cannot, there are two policy languages, and the one the
 * conformance suite checks is no longer the one customers write.
 *
 * DELIBERATELY NOT YAML, AND DELIBERATELY NOT CEDAR
 *
 * Not YAML: the format needs one parser, in the CLI, with no dependencies, and
 * YAML's surface area (anchors, merge keys, the Norway problem, implicit typing
 * that turns `no` into `false`) is a liability in a file that decides whether a
 * credential can be read. This grammar is a hundred lines and has no
 * surprises.
 *
 * Not Cedar: the product's documentation once claimed Cedar and the engine was
 * never Cedar. Rather than adopt a policy language to match old marketing, the
 * docs were corrected. This DSL is what the engine actually does.
 *
 * THREE COMPILATION DECISIONS WORTH READING
 *
 * 1. `risk >= HIGH` compiles to `{path:"risk", op:"in", value:["high","critical"]}`
 *    rather than to a new comparator. The Node and Python engines share a
 *    conformance fixture; adding an operator to one is how they drift. Ordinal
 *    comparison over a four-value enum is exactly an `in` over its tail.
 *
 * 2. `command = "rm -rf"` compiles to a CONTAINS match, not equality. Nobody
 *    writing that line means "the command is exactly the two words rm -rf" —
 *    they mean "this appears in the command". Compiling it to equality would
 *    produce a rule that reads as protective, validates cleanly, and never
 *    fires once.
 *
 * 3. RELATIVE PATHS ARE ANCHORED TO THE WORKSPACE AT COMPILE TIME. Resources
 *    are canonicalized to absolute paths before matching, so a literal
 *    `./src/**` pattern would never match anything. `./src/**` becomes
 *    `<cwd>/src/**`. The source file stays portable; the compiled rule is
 *    specific to the workspace it was loaded in, which is what a
 *    workspace-relative rule means.
 */

import { EFFECT } from "./decisions.mjs";
import { RISK_ORDER, riskRank } from "./risk.mjs";
import { canonicalAction } from "./normalize.mjs";

/** Block headers, and the effect each produces. */
const BLOCKS = {
  allow: EFFECT.PERMIT,
  permit: EFFECT.PERMIT,
  deny: EFFECT.FORBID,
  forbid: EFFECT.FORBID,
  require_approval: EFFECT.HOLD,
  hold: EFFECT.HOLD,
  sanitize: EFFECT.SANITIZE,
  audit_only: EFFECT.AUDIT_ONLY,
  audit: EFFECT.AUDIT_ONLY,
};

/** Attribute → where it lands on the compiled rule. */
const ATTRIBUTES = {
  tool: { kind: "action" },
  action: { kind: "action" },
  agent: { kind: "agent" },
  path: { kind: "resource" },
  file: { kind: "resource" },
  resource: { kind: "resource" },
  url: { kind: "resource" },
  command: { kind: "condition", path: "command", contains: true },
  "network.destination": { kind: "condition", path: "egress.destination", contains: true },
  destination: { kind: "condition", path: "egress.destination", contains: true },
  risk: { kind: "risk" },
  env: { kind: "condition", path: "environment" },
  environment: { kind: "condition", path: "environment" },
  workspace: { kind: "condition", path: "path.insideWorkspace", boolean: true },
  external: { kind: "condition", path: "egress.external", boolean: true },
  allowlisted: { kind: "condition", path: "egress.allowlisted", boolean: true },
  touched_secret: { kind: "condition", path: "session.touchedSecret", boolean: true },
  secrets: { kind: "condition", path: "secrets.detected", numeric: true },
  server: { kind: "condition", path: "mcp.server" },

  // Rule metadata rather than matching.
  name: { kind: "meta", field: "name" },
  reason: { kind: "meta", field: "reason" },
  remediation: { kind: "meta", field: "remediation" },
  approvers: { kind: "meta", field: "approvers", list: true },
  targets: { kind: "sanitize", field: "targets", list: true },
  strategies: { kind: "sanitize", field: "strategies", list: true },
};

const OPERATORS = {
  "=": "eq",
  "==": "eq",
  "!=": "ne",
  ">=": "gte",
  "<=": "lte",
  ">": "gt",
  "<": "lt",
  "~": "matches",
  "~=": "matches",
};

/* -------------------------------------------------------------------------- */
/*  Parsing                                                                    */
/* -------------------------------------------------------------------------- */

export class PolicySyntaxError extends Error {
  constructor(message, line, text) {
    super(`Line ${line}: ${message}${text ? `\n    ${text.trim()}` : ""}`);
    this.name = "PolicySyntaxError";
    this.line = line;
  }
}

/**
 * Splits source into blocks. Structure only — no meaning assigned yet, so a
 * syntax error is reported as a syntax error rather than as a mysterious
 * semantic one three stages later.
 *
 * @returns {{blocks: Array, tests: Array}}
 */
export function parse(source) {
  const lines = String(source ?? "").split(/\r?\n/);
  const blocks = [];
  const tests = [];
  let current = null;

  const closeCurrent = () => {
    if (current) (current.kind === "test" ? tests : blocks).push(current);
    current = null;
  };

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const lineNo = i + 1;

    // Comments and blanks. A `#` inside a quoted value is not a comment, so
    // stripping is only safe on a line that starts with one.
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("//")) continue;

    const indented = /^\s/.test(raw);

    if (!indented) {
      closeCurrent();

      const testHeader = trimmed.match(/^test\s+(?:"([^"]*)"|'([^']*)'|(\S+))\s*:$/i);
      if (testHeader) {
        current = {
          kind: "test",
          name: testHeader[1] ?? testHeader[2] ?? testHeader[3],
          line: lineNo,
          attributes: [],
        };
        continue;
      }

      const header = trimmed.match(/^([a-z_]+)\s*:$/i);
      if (!header) {
        throw new PolicySyntaxError(
          `Expected a block header such as "allow:" or "deny:", got "${trimmed}".`,
          lineNo,
          raw,
        );
      }
      const effect = BLOCKS[header[1].toLowerCase()];
      if (!effect) {
        throw new PolicySyntaxError(
          `Unknown block "${header[1]}". Expected one of: ${Object.keys(BLOCKS).join(", ")}.`,
          lineNo,
          raw,
        );
      }
      current = { kind: "rule", effect, line: lineNo, attributes: [] };
      continue;
    }

    if (!current) {
      throw new PolicySyntaxError("Indented attribute with no block above it.", lineNo, raw);
    }

    // `expect deny` — only inside a test block.
    const expect = trimmed.match(/^expect\s+([a-z_]+)$/i);
    if (expect) {
      if (current.kind !== "test") {
        throw new PolicySyntaxError("`expect` is only valid inside a `test` block.", lineNo, raw);
      }
      current.expect = expect[1].toLowerCase();
      continue;
    }

    const attr = trimmed.match(/^([A-Za-z_][A-Za-z0-9_.]*)\s*(!=|>=|<=|~=|==|=|>|<|~)\s*(.+)$/);
    if (!attr) {
      throw new PolicySyntaxError(
        `Expected "attribute = value", got "${trimmed}".`,
        lineNo,
        raw,
      );
    }

    current.attributes.push({
      key: attr[1].toLowerCase(),
      op: attr[2],
      value: unquote(attr[3].trim()),
      quoted: /^["']/.test(attr[3].trim()),
      line: lineNo,
      raw,
    });
  }

  closeCurrent();
  return { blocks, tests };
}

function unquote(value) {
  const s = String(value).trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  // A trailing comment on an unquoted value.
  return s.replace(/\s+#.*$/, "").trim();
}

/* -------------------------------------------------------------------------- */
/*  Compilation                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Compiles parsed blocks into engine rules.
 *
 * @param {string} source
 * @param {object} [opts]
 * @param {string} [opts.cwd]     workspace root, for anchoring relative paths
 * @param {string} [opts.origin]  file name, used in generated rule names
 * @returns {{rules: Array, tests: Array}}
 */
export function compile(source, { cwd = process.cwd(), origin = "policy" } = {}) {
  const { blocks, tests } = parse(source);
  const rules = [];
  const used = new Set();

  blocks.forEach((block, index) => {
    const rule = {
      name: "",
      effect: block.effect,
      agents: [],
      actions: [],
      resources: [],
      when: [],
    };
    const sanitize = {};
    let explicitName = null;

    for (const attr of block.attributes) {
      const spec = ATTRIBUTES[attr.key];
      if (!spec) {
        throw new PolicySyntaxError(
          `Unknown attribute "${attr.key}". Known: ${Object.keys(ATTRIBUTES).join(", ")}.`,
          attr.line,
          attr.raw,
        );
      }
      const op = OPERATORS[attr.op];
      if (!op) {
        throw new PolicySyntaxError(`Unknown operator "${attr.op}".`, attr.line, attr.raw);
      }

      switch (spec.kind) {
        case "action": {
          requireEquality(attr, "tool");
          // `filesystem.read` and `fs.read` resolve to the same action, so a
          // rule written either way governs the same calls.
          rule.actions.push(canonicalAction(attr.value));
          break;
        }
        case "agent": {
          requireEquality(attr, "agent");
          rule.agents.push(attr.value);
          break;
        }
        case "resource": {
          requireEquality(attr, attr.key);
          rule.resources.push(anchor(attr.value, cwd));
          break;
        }
        case "risk": {
          rule.when.push(riskCondition(attr));
          break;
        }
        case "condition": {
          rule.when.push(condition(spec, attr, op));
          break;
        }
        case "meta": {
          if (spec.field === "name") explicitName = attr.value;
          else if (spec.list) rule[spec.field] = splitList(attr.value);
          else rule[spec.field] = attr.value;
          break;
        }
        case "sanitize": {
          sanitize[spec.field] = splitList(attr.value);
          break;
        }
        default:
          break;
      }
    }

    // A block with no matching attributes at all matches every call. That is
    // almost never intended and is catastrophic on an `allow`, so it is a
    // compile error rather than a warning.
    if (!rule.actions.length && !rule.resources.length && !rule.agents.length && !rule.when.length) {
      throw new PolicySyntaxError(
        `This ${invertEffect(block.effect)} block has no conditions, so it would match every call.`,
        block.line,
        "",
      );
    }

    rule.name = uniqueName(explicitName ?? generateName(block, rule, origin, index), used);
    if (Object.keys(sanitize).length) rule.sanitize = sanitize;

    // Empty arrays mean "match anything" to the engine, which is right, but
    // dropping them keeps the compiled JSON readable when it is printed.
    for (const key of ["agents", "actions", "resources", "when"]) {
      if (Array.isArray(rule[key]) && rule[key].length === 0) delete rule[key];
    }

    if (!rule.reason) rule.reason = describe(block.effect, rule);

    rules.push(rule);
  });

  return { rules, tests: tests.map((t) => compileTest(t, cwd)) };
}

function requireEquality(attr, label) {
  if (attr.op !== "=" && attr.op !== "==" && attr.op !== "~" && attr.op !== "~=") {
    throw new PolicySyntaxError(
      `"${label}" supports = and ~ (glob), not ${attr.op}.`,
      attr.line,
      attr.raw,
    );
  }
}

/**
 * `risk >= HIGH` → `in [high, critical]`.
 *
 * Every comparator is expressed as membership in the matching subset of the
 * four levels, so the engine needs no ordinal knowledge and the two language
 * implementations cannot disagree about what "at least HIGH" means.
 */
function riskCondition(attr) {
  const level = String(attr.value).toLowerCase();
  if (!RISK_ORDER.includes(level)) {
    throw new PolicySyntaxError(
      `Unknown risk level "${attr.value}". Expected one of: ${RISK_ORDER.join(", ")}.`,
      attr.line,
      attr.raw,
    );
  }
  const rank = riskRank(level);
  const keep = {
    ">=": (r) => r >= rank,
    ">": (r) => r > rank,
    "<=": (r) => r <= rank,
    "<": (r) => r < rank,
    "=": (r) => r === rank,
    "==": (r) => r === rank,
    "!=": (r) => r !== rank,
  }[attr.op];

  if (!keep) {
    throw new PolicySyntaxError(`"risk" does not support ${attr.op}.`, attr.line, attr.raw);
  }

  return {
    path: "risk",
    op: "in",
    value: RISK_ORDER.filter((_, i) => keep(i)),
  };
}

function condition(spec, attr, op) {
  if (spec.boolean) {
    const value = /^(true|yes|1|on)$/i.test(attr.value);
    return { path: spec.path, op: op === "ne" ? "ne" : "eq", value };
  }
  if (spec.numeric) {
    const n = Number(attr.value);
    if (!Number.isFinite(n)) {
      throw new PolicySyntaxError(`"${attr.key}" needs a number, got "${attr.value}".`, attr.line, attr.raw);
    }
    return { path: spec.path, op, value: n };
  }
  // `command = "rm -rf"` means contains. See the header.
  //
  // `**` and not `*`: a single star does not cross `/`, and the two things this
  // ever wraps are shell commands and URLs — both of which are mostly slashes.
  // Compiled with `*`, `command = "rm -rf"` matched `rm -rf` and did NOT match
  // `rm -rf /`, so the rule protecting against the canonical destructive
  // command was the one case it let through.
  if (spec.contains && (op === "eq" || op === "matches")) {
    const pattern = /[*?]/.test(attr.value) ? attr.value : `**${attr.value}**`;
    return { path: spec.path, op: "matches", value: pattern };
  }
  return { path: spec.path, op, value: attr.value };
}

function splitList(value) {
  return String(value)
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Anchors a workspace-relative pattern to an absolute one.
 *
 * `./src/**` → `<cwd>/src/**`. Already-absolute paths, `**`-prefixed patterns,
 * and URLs are left exactly as written.
 */
export function anchor(pattern, cwd) {
  const p = String(pattern).replace(/\\/g, "/");
  if (p.startsWith("**") || p.startsWith("*") || p === "*") return p;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(p)) return p;
  if (p.startsWith("/") || /^[A-Za-z]:\//.test(p)) return p;
  if (p.startsWith("~/")) return p.replace(/^~\//, "**/");
  const root = String(cwd).replace(/\\/g, "/").replace(/\/+$/, "");
  return `${root}/${p.replace(/^\.\//, "")}`;
}

function generateName(block, rule, origin, index) {
  const verb = { permit: "allow", forbid: "deny", hold: "approve", sanitize: "sanitize", audit_only: "audit" }[block.effect];
  const subject =
    rule.actions[0] ??
    rule.resources[0]?.split("/").filter(Boolean).pop() ??
    rule.when[0]?.path ??
    `rule-${index + 1}`;
  return `${verb}-${String(subject).replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "").toLowerCase()}`;
}

function uniqueName(base, used) {
  let name = base;
  let n = 2;
  while (used.has(name)) name = `${base}-${n++}`;
  used.add(name);
  return name;
}

function invertEffect(effect) {
  return { permit: "allow", forbid: "deny", hold: "require_approval", sanitize: "sanitize", audit_only: "audit_only" }[effect] ?? effect;
}

function describe(effect, rule) {
  const what = rule.actions?.length ? rule.actions.join(", ") : "matching calls";
  const where = rule.resources?.length ? ` on ${rule.resources.join(", ")}` : "";
  return {
    permit: `Permitted: ${what}${where}.`,
    forbid: `Denied: ${what}${where}.`,
    hold: `Held for approval: ${what}${where}.`,
    sanitize: `Sanitized before forwarding: ${what}${where}.`,
    audit_only: `Observed, not enforced: ${what}${where}.`,
  }[effect];
}

/* -------------------------------------------------------------------------- */
/*  Tests                                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Compiles a `test` block into a case the runner can execute.
 *
 *   test "denies reading .env":
 *     tool = filesystem.read
 *     path = .env
 *     expect deny
 *
 * A policy file that ships its own tests is one an operator can change safely,
 * which is the difference between a rule set that evolves and one nobody dares
 * touch after the author leaves.
 */
function compileTest(block, cwd) {
  const call = { tool: null, arguments: {}, agent: "test", environment: "local" };
  let expected = block.expect ?? null;

  for (const attr of block.attributes) {
    switch (attr.key) {
      case "tool":
      case "action":
        call.tool = attr.value;
        break;
      case "path":
      case "file":
      case "resource":
        call.arguments.path = anchorForTest(attr.value, cwd);
        break;
      case "url":
      case "destination":
      case "network.destination":
        call.arguments.url = attr.value;
        break;
      case "command":
        call.arguments.command = attr.value;
        break;
      case "agent":
        call.agent = attr.value;
        break;
      case "env":
      case "environment":
        call.environment = attr.value;
        break;
      case "server":
        call.server = attr.value;
        break;
      case "expect":
        expected = attr.value;
        break;
      default:
        throw new PolicySyntaxError(
          `"${attr.key}" is not something a test case can set.`,
          attr.line,
          attr.raw,
        );
    }
  }

  if (!expected) {
    throw new PolicySyntaxError(`Test "${block.name}" has no \`expect\` line.`, block.line, "");
  }

  return { name: block.name, call, expect: expected, line: block.line };
}

/** Test paths stay relative unless the author wrote them absolute. */
function anchorForTest(value, cwd) {
  const p = String(value).replace(/\\/g, "/");
  if (p.startsWith("/") || /^[A-Za-z]:\//.test(p) || /^[a-z]+:\/\//i.test(p)) return p;
  if (p.startsWith("~/")) return p;
  return `${String(cwd).replace(/\\/g, "/").replace(/\/+$/, "")}/${p.replace(/^\.\//, "")}`;
}

/* -------------------------------------------------------------------------- */
/*  Serialization                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Renders engine rules back as DSL source.
 *
 * Used by `cirvix policy explain` and by `init` when writing a starter file, so
 * the rules a user sees are in the syntax they would edit rather than in JSON
 * they then have to translate.
 */
export function toSource(rules, { cwd = process.cwd() } = {}) {
  const relative = (p) => {
    const root = String(cwd).replace(/\\/g, "/").replace(/\/+$/, "");
    const s = String(p).replace(/\\/g, "/");
    return s.startsWith(root + "/") ? `./${s.slice(root.length + 1)}` : s;
  };

  const out = [];
  for (const rule of rules) {
    const header = invertEffect(rule.effect);
    out.push(`# ${rule.reason ?? rule.name}`);
    out.push(`${header}:`);
    out.push(`  name = ${rule.name}`);
    for (const a of rule.agents ?? []) out.push(`  agent = ${a}`);
    for (const a of rule.actions ?? []) out.push(`  tool = ${a}`);
    for (const r of rule.resources ?? []) out.push(`  path = ${relative(r)}`);
    for (const c of rule.when ?? []) out.push(`  ${sourceCondition(c)}`);
    for (const a of rule.approvers ?? []) out.push(`  approvers = ${a}`);
    out.push("");
  }
  return out.join("\n");
}

function sourceCondition(cond) {
  if (cond.path === "risk" && cond.op === "in" && Array.isArray(cond.value)) {
    const lowest = cond.value.map(riskRank).sort((a, b) => a - b)[0] ?? 0;
    return `risk >= ${RISK_ORDER[lowest].toUpperCase()}`;
  }
  const key =
    Object.entries(ATTRIBUTES).find(([, s]) => s.kind === "condition" && s.path === cond.path)?.[0] ??
    cond.path;
  const op = Object.entries(OPERATORS).find(([, o]) => o === cond.op)?.[0] ?? "=";
  const value = Array.isArray(cond.value) ? cond.value.join(", ") : cond.value;
  return `${key} ${op} ${typeof value === "string" && /\s/.test(value) ? JSON.stringify(value) : value}`;
}
