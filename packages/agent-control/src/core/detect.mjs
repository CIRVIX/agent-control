/**
 * Runtime detection.
 *
 * Finds the agent runtimes, MCP server configurations, and credential files
 * that are actually present on this machine. Everything here is READ-ONLY —
 * `scan` must never write, never phone home, and never require an account.
 * That property is the entire reason a developer will run it, so it is
 * enforced structurally: this module imports no network API and opens nothing
 * for writing.
 *
 * Detection is filesystem inspection, not magic. Each probe declares the exact
 * path it looks at so a reader can verify what was touched.
 */

import { readFile, readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve, sep } from "node:path";

/** Best-effort read; a missing or unreadable file is simply "not present". */
async function readJson(path) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    return null;
  }
}

async function exists(path) {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

const HOME = homedir();

/* -------------------------------------------------------------------------- */
/*  Agent runtimes                                                             */
/* -------------------------------------------------------------------------- */

/**
 * Where each runtime keeps its configuration. `mcpKey` names the property that
 * holds MCP server definitions, which differs between tools.
 */
const RUNTIME_PROBES = [
  {
    id: "claude-code",
    label: "Claude Code",
    paths: [join(HOME, ".claude", "settings.json"), join(HOME, ".claude.json")],
    mcpKey: "mcpServers",
  },
  {
    id: "cursor",
    label: "Cursor",
    paths: [join(HOME, ".cursor", "mcp.json")],
    mcpKey: "mcpServers",
  },
  {
    id: "windsurf",
    label: "Windsurf",
    paths: [join(HOME, ".codeium", "windsurf", "mcp_config.json")],
    mcpKey: "mcpServers",
  },
  {
    id: "cline",
    label: "Cline",
    paths: [
      join(HOME, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
      join(HOME, "AppData", "Roaming", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
    ],
    mcpKey: "mcpServers",
  },
  {
    id: "vscode",
    label: "VS Code (MCP)",
    paths: [
      join(HOME, "Library", "Application Support", "Code", "User", "mcp.json"),
      join(HOME, "AppData", "Roaming", "Code", "User", "mcp.json"),
    ],
    mcpKey: "servers",
  },
];

/** Project-level markers that indicate an agent framework in the tree. */
const FRAMEWORK_MARKERS = [
  { id: "langchain", label: "LangChain", deps: ["langchain", "@langchain/core", "langgraph"] },
  { id: "crewai", label: "CrewAI", deps: ["crewai"] },
  { id: "openai-agents", label: "OpenAI Agents SDK", deps: ["@openai/agents", "openai-agents"] },
  { id: "vercel-ai", label: "Vercel AI SDK", deps: ["ai"] },
  { id: "anthropic", label: "Anthropic SDK", deps: ["@anthropic-ai/sdk"] },
  { id: "mcp-sdk", label: "MCP SDK", deps: ["@modelcontextprotocol/sdk"] },
];

export async function detectRuntimes() {
  const found = [];

  for (const probe of RUNTIME_PROBES) {
    // Merge across every config path a runtime uses rather than stopping at
    // the first that exists. Claude Code, for example, has both
    // ~/.claude/settings.json and ~/.claude.json, and MCP servers may live in
    // either — breaking early reports "0 MCP servers" for a machine that has
    // several, which is exactly the false clean bill this tool must not give.
    const paths = [];
    const servers = {};

    for (const path of probe.paths) {
      if (!(await exists(path))) continue;
      paths.push(path);
      const config = await readJson(path);
      Object.assign(servers, config?.[probe.mcpKey] ?? {});
    }

    if (paths.length === 0) continue;

    found.push({
      id: probe.id,
      label: probe.label,
      path: paths[0],
      paths,
      governed: isGoverned(servers),
      serverCount: Object.keys(servers).length,
      servers,
    });
  }

  return found;
}

/** A runtime is governed when its MCP traffic routes through the gateway. */
function isGoverned(servers) {
  return Object.entries(servers).some(
    ([name, def]) =>
      name === "cirvix" ||
      (typeof def?.command === "string" && def.command.includes("cirvix")),
  );
}

/**
 * Detects agent frameworks declared in the project at `cwd`. Reads
 * package.json and requirements.txt / pyproject.toml — declaration files only,
 * never source.
 */
export async function detectFrameworks(cwd) {
  const found = [];

  const pkg = await readJson(join(cwd, "package.json"));
  if (pkg) {
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    for (const marker of FRAMEWORK_MARKERS) {
      const hit = marker.deps.find((d) => d in deps);
      if (hit) found.push({ id: marker.id, label: marker.label, via: `package.json → ${hit}` });
    }
  }

  for (const file of ["requirements.txt", "pyproject.toml"]) {
    const path = join(cwd, file);
    if (!(await exists(path))) continue;
    let text = "";
    try {
      text = await readFile(path, "utf8");
    } catch {
      continue;
    }
    for (const marker of FRAMEWORK_MARKERS) {
      if (found.some((f) => f.id === marker.id)) continue;
      const hit = marker.deps.find((d) => new RegExp(`(^|[\\s"'=])${escapeRe(d)}\\b`, "m").test(text));
      if (hit) found.push({ id: marker.id, label: marker.label, via: `${file} → ${hit}` });
    }
  }

  return found;
}

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/* -------------------------------------------------------------------------- */
/*  MCP servers                                                                */
/* -------------------------------------------------------------------------- */

/**
 * Flattens every MCP server across every detected runtime into one list,
 * deduplicated by name+command. Each entry keeps the runtimes that reference
 * it, because the same server configured in three editors is one trust
 * boundary with three doors.
 */
export function collectMcpServers(runtimes) {
  const byKey = new Map();

  for (const runtime of runtimes) {
    for (const [name, def] of Object.entries(runtime.servers ?? {})) {
      if (name === "cirvix") continue; // the gateway itself
      const transport = def?.url ? "http" : "stdio";
      const command = def?.command ?? def?.url ?? "";
      const key = `${name}::${command}`;
      const existing = byKey.get(key);
      if (existing) {
        existing.runtimes.push(runtime.label);
        continue;
      }
      byKey.set(key, {
        name,
        transport,
        command,
        args: def?.args ?? [],
        runtimes: [runtime.label],
        // Env blocks in MCP config frequently carry raw API keys.
        envKeys: Object.keys(def?.env ?? {}),
        scope: inferScope(def),
      });
    }
  }

  return [...byKey.values()];
}

/**
 * Filesystem-style servers are commonly pointed at a whole home directory or
 * `/`, which grants an agent far more reach than the person configuring it
 * usually intends. Flagging that is one of the scanner's most useful outputs.
 */
function inferScope(def) {
  const args = def?.args ?? [];
  const paths = args.filter((a) => typeof a === "string" && (a.startsWith("/") || /^[A-Za-z]:[\\/]/.test(a)));
  if (paths.length === 0) return null;
  const widest = paths.find((p) => p === "/" || p === HOME || /^[A-Za-z]:[\\/]?$/.test(p));
  return { paths, broad: Boolean(widest), widest: widest ?? null };
}

/* -------------------------------------------------------------------------- */
/*  Credentials reachable from agent context                                   */
/* -------------------------------------------------------------------------- */

/** Files whose presence means an agent with file read can obtain secrets. */
const CREDENTIAL_PROBES = [
  { path: join(HOME, ".aws", "credentials"), label: "AWS credentials", severity: "high" },
  { path: join(HOME, ".ssh", "id_rsa"), label: "SSH private key", severity: "high" },
  { path: join(HOME, ".ssh", "id_ed25519"), label: "SSH private key", severity: "high" },
  { path: join(HOME, ".kube", "config"), label: "Kubernetes config", severity: "high" },
  { path: join(HOME, ".docker", "config.json"), label: "Docker registry auth", severity: "medium" },
  { path: join(HOME, ".npmrc"), label: "npm token", severity: "medium" },
  { path: join(HOME, ".netrc"), label: "netrc credentials", severity: "medium" },
  { path: join(HOME, ".config", "gcloud", "credentials.db"), label: "gcloud credentials", severity: "high" },
];

/** Keys that look like live secret material rather than config. */
const SECRET_KEY_RE =
  /(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|APIKEY|ACCESS_KEY|CLIENT_SECRET|DSN|CREDENTIAL)/i;

/** Values that are obviously placeholders shouldn't be reported as secrets. */
const PLACEHOLDER_RE =
  /^(|x{3,}|\.{3,}|<.*>|\$\{.*\}|your[-_ ]|changeme|placeholder|todo|example|test|dummy|none|null|undefined)$/i;

export async function detectCredentials(cwd) {
  const findings = [];

  for (const probe of CREDENTIAL_PROBES) {
    if (await exists(probe.path)) {
      findings.push({
        kind: "credential-file",
        path: probe.path,
        label: probe.label,
        severity: probe.severity,
        detail: "On disk and readable by any agent with filesystem access",
      });
    }
  }

  // .env files in the working tree — the most common real exposure.
  let entries = [];
  try {
    entries = await readdir(cwd, { withFileTypes: true });
  } catch {
    entries = [];
  }

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (!/^\.env($|\.)/.test(entry.name)) continue;
    if (/\.example$|\.sample$|\.template$/.test(entry.name)) continue;

    const path = join(cwd, entry.name);
    const keys = await readSecretKeys(path);
    if (keys.length === 0) continue;

    findings.push({
      kind: "dotenv",
      path,
      label: entry.name,
      severity: /production|prod/.test(entry.name) ? "high" : "medium",
      // Key NAMES only. The scanner never records, prints, or transmits a
      // secret VALUE — reporting a leak by leaking it would be absurd.
      detail: `${keys.length} secret-shaped ${keys.length === 1 ? "key" : "keys"}: ${keys.slice(0, 4).join(", ")}${keys.length > 4 ? "…" : ""}`,
      keys,
    });
  }

  return findings;
}

async function readSecretKeys(path) {
  let text = "";
  try {
    const info = await stat(path);
    if (info.size > 512 * 1024) return []; // not a real .env
    text = await readFile(path, "utf8");
  } catch {
    return [];
  }

  const keys = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim().replace(/^export\s+/, "");
    const value = trimmed.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
    if (!SECRET_KEY_RE.test(key)) continue;
    if (PLACEHOLDER_RE.test(value)) continue;
    if (value.length < 8) continue;
    keys.push(key);
  }
  return keys;
}

/* -------------------------------------------------------------------------- */

/** True when `child` resolves inside `parent` — used by the path guard. */
export function isInside(parent, child) {
  const p = resolve(parent);
  const c = resolve(child);
  return c === p || c.startsWith(p.endsWith(sep) ? p : p + sep);
}
