/**
 * The policy engine.
 *
 * A deterministic evaluator over an ordered rule set. Given a request
 * (agent, action, resource, context) it returns a decision with the rule that
 * produced it — the explanation is a first-class output, not a log line,
 * because a refusal an agent cannot read is a refusal it cannot recover from.
 *
 * Three properties are load-bearing and tested:
 *
 *   1. FORBID ALWAYS WINS. A `forbid` match cannot be overridden by any
 *      `permit`, regardless of order or specificity. This is what makes a
 *      rule set safe to extend: adding a permissive rule can never silently
 *      punch a hole through an existing prohibition.
 *
 *   2. DEFAULT DENY. A request that matches nothing is denied. Fail-open is
 *      how a control plane becomes decorative the first time a rule file
 *      fails to parse.
 *
 *   3. RESOURCES ARE CANONICALIZED BEFORE MATCHING. `./x/../.env`,
 *      `.env`, and an absolute path to the same file are one resource. Rules
 *      that match on raw strings are bypassed by the first attacker who tries
 *      a traversal, and by the first agent that happens to use a relative
 *      path.
 *
 *   4. AN OBSERVATION IS NOT AN AUTHORIZATION. `audit_only` rules match, get
 *      recorded, and contribute nothing to the verdict — so adding one can
 *      never punch a hole through a `forbid`. See `./decisions.mjs`.
 */

import { homedir } from "node:os";

import { canonicalUrl, expandHome, foldPath } from "./canonical.mjs";
import {
  DECISION,
  EFFECT,
  VERDICT,
  effectRank,
  toDecision,
} from "./decisions.mjs";

/** @typedef {"permit"|"forbid"|"hold"|"sanitize"|"audit_only"} Effect */

// Re-exported rather than redefined: two definitions of "what is a forbid" is
// two policy engines. Importers of `policy.mjs` keep working unchanged.
export { EFFECT, VERDICT, DECISION };

/* -------------------------------------------------------------------------- */
/*  Matching                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * Glob matching for tool and resource patterns.
 *
 * `*` matches within a segment, `**` matches across segments, `?` matches one
 * character that is not a separator. Matching is case-insensitive, and every
 * other character is a literal — a `.` in a rule means a dot, not "any
 * character", or `deny **\/.env` would also match `xenv`.
 *
 * DELIBERATELY NOT A REGULAR EXPRESSION.
 *
 * The obvious implementation compiles the glob to a RegExp, and it is what
 * this was. It is also exponential: `*a*a*a*a*b` against a long run of `a`
 * makes the engine explore every way of splitting the input between the
 * wildcards, and JavaScript's backtracking matcher will sit there for minutes.
 * That matters here more than it does in most places, because the pattern
 * comes from a policy rule and the *input* comes from whatever resource an
 * agent named — so a caller on the far side of the enforcement boundary picks
 * the input that triggers it, and a hung evaluator is a hung gateway.
 *
 * This is the standard two-pointer wildcard match instead: it remembers the
 * most recent wildcard and resumes there on a mismatch, which is O(n·m) in the
 * worst case and has no pathological input at all.
 */
export function matchGlob(pattern, value) {
  if (pattern === "*" || pattern === "**") return true;

  const p = String(pattern).toLowerCase();
  const v = String(value).toLowerCase();

  /*
   * Tokenized and matched with dynamic programming, NOT with the two-pointer
   * algorithm this used to use.
   *
   * The two-pointer match remembers exactly one star position, which is correct
   * when every star has the same semantics. Here they do not: `**` crosses `/`
   * and `*` does not. Once the matcher committed to an inner `*`, it had
   * forgotten the outer `**` and could never backtrack far enough — so
   * `matchGlob("**\/*", "/workspace/src/app.ts")` returned FALSE.
   *
   * That is a fail-open bug, not a cosmetic one. A rule written
   * `path = **\/*` — the natural way to say "any file at all" — loaded,
   * validated, appeared in `cirvix policy list`, and matched nothing. The
   * delegation tests found it.
   *
   * The DP is O(n·m) in time and O(m) in space, with no pathological input:
   * the same complexity guarantee the two-pointer version was chosen for, and
   * unlike a backtracking regex there is nothing an attacker can pick to make
   * it explore exponentially.
   */
  const tokens = [];
  for (let i = 0; i < p.length; i++) {
    if (p[i] === "*") {
      const doubled = p[i + 1] === "*";
      tokens.push(doubled ? "**" : "*");
      if (doubled) i++;
    } else if (p[i] === "?") tokens.push("?");
    else tokens.push(p[i]);
  }

  const T = tokens.length;
  const isStar = (t) => t === "*" || t === "**";

  // dp[t] — the first `t` tokens match the value consumed so far.
  let dp = new Array(T + 1).fill(false);
  dp[0] = true;
  // A star may match nothing, so it passes the mark straight through.
  for (let t = 0; t < T; t++) if (dp[t] && isStar(tokens[t])) dp[t + 1] = true;

  for (let i = 0; i < v.length; i++) {
    const c = v[i];
    const next = new Array(T + 1).fill(false);

    for (let t = 0; t < T; t++) {
      const token = tokens[t];
      if (token === "**") {
        // Open here, or already open and consuming another character.
        if (dp[t] || dp[t + 1]) next[t + 1] = true;
      } else if (token === "*") {
        if ((dp[t] || dp[t + 1]) && c !== "/") next[t + 1] = true;
      } else if (token === "?") {
        if (dp[t] && c !== "/") next[t + 1] = true;
      } else if (dp[t] && c === token) {
        next[t + 1] = true;
      }
    }

    // Stars that matched nothing at this position.
    for (let t = 0; t < T; t++) if (next[t] && isStar(tokens[t])) next[t + 1] = true;

    dp = next;
  }

  return dp[T];
}

function matchAny(patterns, value) {
  if (patterns === undefined || patterns === "*") return true;
  const list = Array.isArray(patterns) ? patterns : [patterns];
  if (list.length === 0) return true;
  return list.some((p) => matchGlob(p, value));
}

/**
 * Canonicalizes a resource so equivalent references collapse to one string.
 * Filesystem paths resolve against `cwd`; URLs normalize host and lowercase.
 */
export function canonicalizeResource(resource, cwd = process.cwd()) {
  if (typeof resource !== "string" || resource.length === 0) return "";

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(resource)) {
    // Delegated so URLs canonicalize identically everywhere: alternate IPv4
    // spellings, IPv4-mapped IPv6, trailing dots, and userinfo all collapse.
    // Hand-rolled URL handling here is how `169.254.169.254` and
    // `http://2852039166/` became two different resources to the same rule.
    return canonicalUrl(resource) ?? resource;
  }

  /*
   * Fold before resolving.
   *
   * `~%2F.aws%2Fcredentials` contains no literal separator, so without this it
   * fell through every branch below, stayed a bare token, was judged "inside
   * the workspace" because it had no path to escape it, and a workspace-read
   * rule permitted a credential read. Percent-encoding, Unicode homoglyph
   * separators, and zero-width characters are all normalized here so the rule
   * sees the path the tool will actually open.
   */
  const folded = expandHome(foldPath(resource));
  if (folded !== resource) {
    // Re-entered once with the folded form. One level only: `foldPath` is
    // idempotent by construction, so a second pass cannot change the answer and
    // an unbounded recursion on attacker-controlled input would be its own bug.
    return canonicalizeResource(folded, cwd);
  }

  // `~` is a real path, and agents write it constantly.
  //
  // Left unexpanded it resolved against the WORKSPACE — `~/.aws/credentials`
  // became `<cwd>/~/.aws/credentials`, a directory that does not exist. A rule
  // written against the absolute home path then failed to match the single most
  // common way an agent names a credential file. The glob rules happened to
  // catch it; the exact-path rules did not, which is the worse half of a
  // near-miss.
  if (resource === "~" || resource.startsWith("~/") || resource.startsWith("~\\")) {
    const home = homedir().replace(/\\/g, "/").replace(/\/+$/, "");
    return resolvePath(home + resource.slice(1).replace(/\\/g, "/"), cwd);
  }

  // Anything else that looks like a path gets resolved.
  if (/[/\\]/.test(resource) || resource.startsWith(".")) {
    return resolvePath(resource, cwd);
  }

  return resource;
}

/**
 * Resolves a path the same way on every platform.
 *
 * DELIBERATELY NOT `path.resolve`. That function is platform-aware, and on
 * Windows it prepends the current drive to a drive-less absolute path — so
 * `/etc/passwd` canonicalized to `C:/etc/passwd` there and `/etc/passwd`
 * everywhere else. The consequence is not cosmetic: a rule written
 * `resources: ["/etc/**"]` matched on a Linux runner and silently did not
 * match on a developer's Windows laptop, which is the machine the rule was
 * most likely written to protect.
 *
 * The conformance suite caught this. It is exactly the class of bug two
 * implementations would have disagreed about forever.
 */
function resolvePath(resource, cwd) {
  const norm = (value) => String(value ?? "").replace(/\\/g, "/");
  const target = norm(resource);

  const isAbsolute = target.startsWith("/") || /^[A-Za-z]:\//.test(target);
  const combined = isAbsolute ? target : `${norm(cwd).replace(/\/+$/, "")}/${target}`;

  // A drive letter is carried through untouched rather than invented.
  const drive = combined.match(/^([A-Za-z]:)(\/.*)$/);
  const body = drive ? drive[2] : combined;

  const parts = [];
  for (const segment of body.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      parts.pop();
      continue;
    }
    parts.push(segment);
  }

  return (drive ? drive[1] : "") + (body.startsWith("/") ? "/" : "") + parts.join("/");
}

/* -------------------------------------------------------------------------- */
/*  Conditions                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Conditions are plain data, never expressions.
 *
 * Deliberately NOT `eval` or `new Function`: a policy file is exactly the kind
 * of thing that gets templated by a script, and turning it into an execution
 * surface would make the security product the vulnerability. Comparators are
 * an explicit, closed set.
 */
const COMPARATORS = {
  eq: (a, b) => a === b,
  ne: (a, b) => a !== b,
  in: (a, b) => Array.isArray(b) && b.includes(a),
  nin: (a, b) => Array.isArray(b) && !b.includes(a),
  gt: (a, b) => typeof a === "number" && a > b,
  gte: (a, b) => typeof a === "number" && a >= b,
  lt: (a, b) => typeof a === "number" && a < b,
  lte: (a, b) => typeof a === "number" && a <= b,
  matches: (a, b) => typeof a === "string" && matchGlob(String(b), a),
  exists: (a, b) => (b ? a !== undefined && a !== null : a === undefined || a === null),
  contains: (a, b) => Array.isArray(a) && a.includes(b),
  supersetOf: (a, b) =>
    Array.isArray(a) && Array.isArray(b) && b.every((x) => a.includes(x)),
};

function readPath(obj, path) {
  return path.split(".").reduce((acc, key) => (acc == null ? undefined : acc[key]), obj);
}

/** Every condition must hold. Unknown comparators fail closed. */
function conditionsHold(conditions, context) {
  if (!conditions || conditions.length === 0) return true;
  return conditions.every((cond) => {
    const cmp = COMPARATORS[cond.op];
    if (!cmp) return false;
    return cmp(readPath(context, cond.path), cond.value);
  });
}

/* -------------------------------------------------------------------------- */
/*  Evaluation                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Evaluate a request against a rule set.
 *
 * @returns {{
 *   verdict: "permit"|"deny"|"hold",
 *   rule: string|null,
 *   reason: string,
 *   remediation?: string,
 *   approvers?: string[],
 *   considered: Array<{rule: string, effect: string, matched: boolean}>,
 *   resource: string
 * }}
 */
export function evaluate(request, rules, options = {}) {
  const cwd = options.cwd ?? process.cwd();
  const resource = canonicalizeResource(request.resource, cwd);
  const context = { ...request.context, agent: request.agent, action: request.action };

  const considered = [];
  let firstPermit = null;
  let firstHold = null;
  /** Every matching sanitize rule, not just the first — sanitizers compose. */
  const sanitizers = [];
  /** Matching `audit_only` rules. Recorded, never authorizing. */
  const observed = [];

  /*
   * `rules ?? []`, not `rules`.
   *
   * A missing rule set must default-deny, not throw. It throwing was a real
   * defect: a policy that failed to load, a caller that passed `undefined`, or
   * a config path that resolved to nothing all produced a TypeError inside the
   * decision path rather than a refusal — and an exception in an enforcement
   * hot path is a denial of service against the control plane at best, and an
   * accidental allow at worst, depending on which caller catches it.
   *
   * The Python engine already read `rules or []`. This is also the two engines
   * agreeing again.
   */
  for (const rule of rules ?? []) {
    if (!rule || typeof rule !== "object") continue;

    const matched =
      matchAny(rule.agents, request.agent) &&
      matchAny(rule.actions, request.action) &&
      matchAny(rule.resources, resource) &&
      conditionsHold(rule.when, context);

    considered.push({ rule: rule.name, effect: rule.effect, matched });

    if (!matched) continue;

    // forbid short-circuits — nothing after it can change the outcome.
    if (rule.effect === EFFECT.FORBID) {
      return finish({
        verdict: VERDICT.DENY,
        decision: DECISION.DENY,
        rule: rule.name,
        reason: rule.reason ?? `Denied by ${rule.name}.`,
        remediation: rule.remediation,
        explicit: true,
        considered,
        resource,
        observed,
      });
    }
    if (rule.effect === EFFECT.HOLD && !firstHold) firstHold = rule;
    if (rule.effect === EFFECT.SANITIZE) sanitizers.push(rule);
    if (rule.effect === EFFECT.PERMIT && !firstPermit) firstPermit = rule;
    // `audit_only` lands here and nowhere else: it is recorded and contributes
    // nothing. A matching observation must not be able to authorize a call.
    if (rule.effect === EFFECT.AUDIT_ONLY) {
      observed.push({ rule: rule.name, reason: rule.reason ?? null });
    }
  }

  // A hold outranks a permit: if any rule says a human must see this, the
  // presence of some other permissive rule must not quietly skip them.
  if (firstHold) {
    return finish({
      verdict: VERDICT.HOLD,
      decision: DECISION.REQUIRE_APPROVAL,
      rule: firstHold.name,
      reason: firstHold.reason ?? `Held by ${firstHold.name} pending approval.`,
      approvers: firstHold.approvers ?? [],
      explicit: true,
      considered,
      resource,
      observed,
    });
  }

  // Sanitize outranks permit for the reason given in decisions.mjs: a rule
  // saying "clean this first" must not be skipped because some other rule also
  // said the call was fine. It still requires the call to be permitted at all —
  // a sanitizer alone is not an authorization, so a lone sanitize rule with no
  // permit falls through to default-deny below.
  if (sanitizers.length && firstPermit) {
    return finish({
      verdict: VERDICT.PERMIT,
      decision: DECISION.SANITIZE,
      rule: sanitizers[0].name,
      reason:
        sanitizers[0].reason ??
        `Permitted by ${firstPermit.name}, with sanitization required by ${sanitizers[0].name}.`,
      explicit: true,
      sanitize: sanitizers.map((r) => ({
        rule: r.name,
        /** What to clean: `arguments`, `result`, or both. Defaults to both. */
        targets: normalizeTargets(r.sanitize?.targets),
        /** Which sanitizer families to run. Empty means "all applicable". */
        strategies: Array.isArray(r.sanitize?.strategies) ? r.sanitize.strategies : [],
        reason: r.reason ?? null,
      })),
      permittedBy: firstPermit.name,
      considered,
      resource,
      observed,
    });
  }

  if (firstPermit) {
    return finish({
      verdict: VERDICT.PERMIT,
      decision: DECISION.ALLOW,
      rule: firstPermit.name,
      reason: firstPermit.reason ?? `Permitted by ${firstPermit.name}.`,
      explicit: true,
      considered,
      resource,
      observed,
    });
  }

  return finish({
    verdict: VERDICT.DENY,
    decision: DECISION.DENY,
    rule: null,
    reason:
      sanitizers.length > 0
        ? `No rule permits this call. ${sanitizers[0].name} would have sanitized it, but a sanitizer cleans an authorized call — it does not authorize one.`
        : "No rule permits this call. The policy set is default-deny: an action must be explicitly allowed.",
    remediation:
      "Add a permit rule for this action, or run the engine in audit mode to log without enforcing.",
    // Not explicit: nothing named this call, so the risk floor may escalate it.
    explicit: false,
    considered,
    resource,
    observed,
  });
}

/** Drops empty optional fields so a decision record stays legible. */
function finish(decision) {
  if (!decision.observed?.length) delete decision.observed;
  return decision;
}

function normalizeTargets(targets) {
  const all = ["arguments", "result"];
  if (!targets) return all;
  const list = (Array.isArray(targets) ? targets : [targets]).filter((t) => all.includes(t));
  return list.length ? list : all;
}

/* -------------------------------------------------------------------------- */
/*  Starter policy                                                             */
/* -------------------------------------------------------------------------- */

/**
 * The default rule set — what you get with no `--policy`. Chosen so that a
 * developer working normally is not interrupted, while the handful of actions
 * that actually cause incidents are stopped or held.
 *
 * Ordering is irrelevant to correctness (forbid always wins, hold outranks
 * permit) but rules are grouped for readability.
 */
export const STARTER_RULES = [
  {
    name: "deny-dotenv-read",
    effect: EFFECT.FORBID,
    actions: ["fs.read", "fs.*"],
    resources: ["**/.env", "**/.env.*"],
    reason:
      "Reading .env files is denied outside an approved secrets flow. This is the single most common path from a prompt injection to a live credential.",
    remediation: 'Request the value as a handle: secrets.get("STRIPE_KEY")',
  },
  {
    name: "deny-credential-files",
    effect: EFFECT.FORBID,
    actions: ["fs.read", "fs.*"],
    resources: [
      "**/.aws/**",
      "**/.ssh/**",
      "**/.kube/config",
      "**/.npmrc",
      "**/.netrc",
      "**/.docker/config.json",
    ],
    reason: "Cloud, SSH, and registry credentials are never readable by an agent.",
    remediation: "Use a scoped secret handle instead of the credential file.",
  },
  {
    name: "deny-workspace-escape",
    effect: EFFECT.FORBID,
    actions: ["fs.*"],
    resources: ["*"],
    when: [{ path: "path.insideWorkspace", op: "eq", value: false }],
    reason:
      "The resolved path is outside the workspace root. Traversal and symlinks are resolved before this check.",
  },
  {
    name: "require-approval-destructive",
    effect: EFFECT.HOLD,
    actions: ["fs.delete", "db.write", "db.migrate", "k8s.apply", "shell.exec"],
    resources: ["*"],
    when: [{ path: "environment", op: "in", value: ["production", "prod"] }],
    approvers: ["platform-oncall"],
    reason:
      "Destructive or state-changing action in production. Held for a named human; the call waits rather than failing.",
  },
  {
    name: "deny-external-egress-after-secret",
    effect: EFFECT.FORBID,
    actions: ["http.request", "net.*"],
    resources: ["*"],
    when: [
      { path: "egress.external", op: "eq", value: true },
      { path: "session.touchedSecret", op: "eq", value: true },
    ],
    reason:
      "This session read secret material, so outbound requests to external destinations are blocked for the remainder of it.",
  },
  {
    name: "allow-workspace-read",
    effect: EFFECT.PERMIT,
    actions: ["fs.read", "fs.list", "fs.stat"],
    resources: ["*"],
    when: [{ path: "path.insideWorkspace", op: "eq", value: true }],
    reason: "Read inside the workspace root.",
  },
  {
    name: "allow-workspace-write",
    effect: EFFECT.PERMIT,
    actions: ["fs.write"],
    resources: ["*"],
    when: [{ path: "path.insideWorkspace", op: "eq", value: true }],
    reason: "Write inside the workspace root.",
  },
  {
    name: "allow-allowlisted-egress",
    effect: EFFECT.PERMIT,
    actions: ["http.request", "net.*"],
    resources: ["*"],
    when: [{ path: "egress.allowlisted", op: "eq", value: true }],
    reason: "Destination is on the egress allowlist.",
  },
  {
    name: "allow-read-only-tools",
    effect: EFFECT.PERMIT,
    actions: ["*.read", "*.list", "*.search", "*.get", "*.query"],
    resources: ["*"],
    reason: "Read-only tool call.",
  },
];

/** Rules serialize to JSON — the on-disk format is `cirvix.policy.json`. */
export function parseRules(json) {
  const rules = Array.isArray(json) ? json : json?.rules;
  if (!Array.isArray(rules)) {
    throw new Error("Policy file must be an array of rules, or { rules: [...] }.");
  }
  for (const rule of rules) {
    if (!rule.name) throw new Error("Every rule needs a name.");
    if (!Object.values(EFFECT).includes(rule.effect)) {
      throw new Error(
        `Rule "${rule.name}" has effect "${rule.effect}"; expected ${Object.values(EFFECT).join(", ")}.`,
      );
    }
    for (const cond of rule.when ?? []) {
      if (!COMPARATORS[cond.op]) {
        throw new Error(`Rule "${rule.name}" uses unknown operator "${cond.op}".`);
      }
    }
  }
  return rules;
}

/* -------------------------------------------------------------------------- */
/*  Validation                                                                 */
/* -------------------------------------------------------------------------- */

/**
 * Structured validation for `cirvix policy check`.
 *
 * Distinct from `parseRules`, which throws on the first structural problem
 * because it is the load path and a half-parsed rule set must never reach the
 * engine. This returns everything at once, including things that parse fine but
 * are probably a mistake — an operator fixing a policy file wants the whole
 * list, not one error per run.
 *
 * The severity split is the point: `error` means the file will not load or the
 * rule cannot match; `warning` means it loads and does something the author
 * likely did not intend.
 *
 * @returns {{ok:boolean, errors:Array, warnings:Array, rules:number}}
 */
export function validateRules(json) {
  const errors = [];
  const warnings = [];
  const at = (rule, i) => rule?.name ?? `rule #${i + 1}`;

  const rules = Array.isArray(json) ? json : json?.rules;
  if (!Array.isArray(rules)) {
    return {
      ok: false,
      rules: 0,
      errors: [{ rule: null, message: "Policy must be an array of rules, or { rules: [...] }." }],
      warnings: [],
    };
  }

  const seen = new Map();

  rules.forEach((rule, i) => {
    const where = at(rule, i);

    if (!rule || typeof rule !== "object") {
      errors.push({ rule: where, message: "Rule is not an object." });
      return;
    }
    if (!rule.name) errors.push({ rule: where, message: "Rule has no name." });
    if (!Object.values(EFFECT).includes(rule.effect)) {
      errors.push({
        rule: where,
        message: `Unknown effect "${rule.effect}". Expected one of: ${Object.values(EFFECT).join(", ")}.`,
      });
    }

    if (rule.name) {
      if (seen.has(rule.name)) {
        errors.push({
          rule: where,
          message: `Duplicate rule name — also defined at position ${seen.get(rule.name) + 1}. Names appear in decision records and must identify one rule.`,
        });
      } else seen.set(rule.name, i);
    }

    for (const cond of rule.when ?? []) {
      if (!cond || typeof cond !== "object") {
        errors.push({ rule: where, message: "Condition is not an object." });
        continue;
      }
      if (!COMPARATORS[cond.op]) {
        errors.push({ rule: where, message: `Unknown operator "${cond.op}".` });
      }
      if (typeof cond.path !== "string" || !cond.path) {
        errors.push({ rule: where, message: "Condition has no path." });
      }
      if (["in", "nin"].includes(cond.op) && !Array.isArray(cond.value)) {
        errors.push({
          rule: where,
          message: `Operator "${cond.op}" needs an array value; got ${typeof cond.value}. It would never match.`,
        });
      }
    }

    // Warnings: loads fine, probably not what was meant.
    if (rule.effect === EFFECT.SANITIZE && !rule.sanitize) {
      warnings.push({
        rule: where,
        message:
          "Sanitize rule declares no `sanitize` block, so it defaults to cleaning both arguments and results with every applicable strategy.",
      });
    }
    if (rule.effect === EFFECT.HOLD && !(rule.approvers ?? []).length) {
      warnings.push({
        rule: where,
        message: "Hold rule names no approvers, so the call waits on nobody in particular.",
      });
    }
    if (rule.effect === EFFECT.PERMIT && isUnbounded(rule)) {
      warnings.push({
        rule: where,
        message:
          "Permit rule matches every agent, action, and resource with no conditions. It makes the rest of the rule set decorative for anything a forbid does not catch.",
      });
    }
    if (rule.effect === EFFECT.AUDIT_ONLY) {
      warnings.push({
        rule: where,
        message:
          "audit_only records matches and never authorizes. If this rule was meant to allow the call, it needs effect `permit`.",
      });
    }
    if (rule.effect === EFFECT.FORBID && rule.approvers?.length) {
      warnings.push({
        rule: where,
        message: "Forbid rule names approvers, but a forbid cannot be approved. Use `hold` instead.",
      });
    }
  });

  // A rule set with no forbid at all is legal and almost never intended.
  if (rules.length && !rules.some((r) => r?.effect === EFFECT.FORBID)) {
    warnings.push({
      rule: null,
      message:
        "No forbid rule in this policy set. Default-deny still applies, but nothing is explicitly prohibited.",
    });
  }

  return { ok: errors.length === 0, errors, warnings, rules: rules.length };
}

function isUnbounded(rule) {
  const wild = (v) => v === undefined || v === "*" || (Array.isArray(v) && (!v.length || v.includes("*")));
  return wild(rule.agents) && wild(rule.actions) && wild(rule.resources) && !(rule.when ?? []).length;
}
