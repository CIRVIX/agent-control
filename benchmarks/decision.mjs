#!/usr/bin/env node
/**
 * The decision benchmark.
 *
 *   node benchmarks/decision.mjs                 1k, 10k, 100k
 *   node benchmarks/decision.mjs --n 1000000     add the 1M run
 *   node benchmarks/decision.mjs --json          machine-readable
 *
 * WHAT THIS MEASURES, EXACTLY
 *
 * Wall-clock time inside `Pipeline.submit()`: parse, normalize, secret scan,
 * risk classification, policy evaluation, approval check, argument
 * substitution. Everything Cirvix adds to a tool call and nothing else.
 *
 * WHAT IT DOES NOT MEASURE, AND WHY THAT MATTERS MORE
 *
 * It excludes the upstream tool round trip. A filesystem read is single-digit
 * milliseconds and a hosted MCP call is hundreds; including either would put
 * Cirvix's contribution in the noise and produce a flattering number that
 * describes the network rather than the engine.
 *
 * It also excludes audit-chain writes by default, because the append is an
 * fsync-bound filesystem operation whose cost is a property of the disk. Run
 * with `--audit` to include it — the difference is the honest cost of durable
 * history and it should be reported separately, not folded in.
 *
 * PROCESS-LEVEL HONESTY
 *
 * A JIT-compiled runtime produces a fast first number and a different steady
 * state. There is a warmup phase, it is excluded, and its size is reported. GC
 * pauses are NOT excluded — they are real latency that a real caller
 * experiences, and removing them is how a P99 becomes fiction.
 *
 * Every published figure should carry the platform line this prints. A latency
 * number without a machine is not a measurement.
 */

import { cpus, totalmem, platform, arch, release } from "node:os";
import { existsSync } from "node:fs";

import { Pipeline } from "../packages/agent-control/src/core/pipeline.mjs";
import { compile } from "../packages/agent-control/src/core/policy-dsl.mjs";
import { STARTER_POLICY } from "../packages/agent-control/src/commands/init.mjs";

const CWD = platform() === "win32" ? "C:/workspace" : "/workspace";

/**
 * The workload.
 *
 * Deliberately a realistic mix rather than the cheapest call repeated. A
 * benchmark of `git.status` alone measures the fast path and reports it as the
 * product's latency; real traffic includes credential denials, secret scans
 * over request bodies, and risk classification over shell commands, all of
 * which cost more. The mix is weighted toward reads because real agent traffic
 * is.
 */
const WORKLOAD = [
  { weight: 30, call: { tool: "read_file", arguments: { path: `${CWD}/src/app.ts` } } },
  { weight: 15, call: { tool: "git_status", arguments: {} } },
  { weight: 10, call: { tool: "list_files", arguments: { path: `${CWD}/src` } } },
  { weight: 10, call: { tool: "write_file", arguments: { path: `${CWD}/src/out.ts` } } },
  { weight: 8, call: { tool: "shell_exec", arguments: { command: "npm test" } } },
  { weight: 7, call: { tool: "grep_search", arguments: { path: `${CWD}/src` } } },
  {
    weight: 6,
    call: {
      tool: "http_request",
      arguments: { url: "https://api.example.com/v1/items", body: '{"id":42,"name":"widget"}' },
    },
  },
  { weight: 5, call: { tool: "read_file", arguments: { path: "~/.aws/credentials" } } },
  { weight: 4, call: { tool: "shell_exec", arguments: { command: "rm -rf /tmp/x" } } },
  {
    weight: 3,
    call: {
      tool: "http_request",
      arguments: {
        url: "https://api.example.com/log",
        headers: { authorization: "Bearer ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
      },
    },
  },
  { weight: 2, call: { tool: "db_write", arguments: { sql: "UPDATE users SET x=1" } } },
];

/** Expands the weights into a flat array sampled round-robin. */
function buildSequence() {
  const seq = [];
  for (const entry of WORKLOAD) {
    for (let i = 0; i < entry.weight; i++) seq.push(entry.call);
  }
  return seq;
}

function percentile(sorted, q) {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.ceil(q * sorted.length) - 1);
  return sorted[Math.max(0, idx)];
}

async function measure(n, { rules, includeAudit }) {
  const pipeline = new Pipeline({
    rules,
    cwd: CWD,
    agent: "bench",
    audit: includeAudit ? await makeAudit() : null,
  });

  const sequence = buildSequence();

  // Warmup: enough to get the JIT past the interpreter and the inline caches
  // populated, capped so a 1k run does not spend most of its time warming up.
  const warmup = Math.min(2000, Math.max(200, Math.floor(n / 10)));
  for (let i = 0; i < warmup; i++) {
    await pipeline.submit(sequence[i % sequence.length]);
  }

  // Preallocated: growing an array mid-measurement is itself measurable.
  const samples = new Float64Array(n);

  const startedAt = process.hrtime.bigint();
  for (let i = 0; i < n; i++) {
    const t0 = process.hrtime.bigint();
    await pipeline.submit(sequence[i % sequence.length]);
    samples[i] = Number(process.hrtime.bigint() - t0) / 1e6;
  }
  const wall = Number(process.hrtime.bigint() - startedAt) / 1e6;

  const sorted = Array.from(samples).sort((a, b) => a - b);
  const mean = sorted.reduce((s, v) => s + v, 0) / sorted.length;

  return {
    n,
    warmup,
    wallMs: Number(wall.toFixed(1)),
    throughput: Math.round(n / (wall / 1000)),
    mean: Number(mean.toFixed(4)),
    p50: Number(percentile(sorted, 0.5).toFixed(4)),
    p90: Number(percentile(sorted, 0.9).toFixed(4)),
    p95: Number(percentile(sorted, 0.95).toFixed(4)),
    p99: Number(percentile(sorted, 0.99).toFixed(4)),
    p999: Number(percentile(sorted, 0.999).toFixed(4)),
    max: Number(sorted[sorted.length - 1].toFixed(4)),
    min: Number(sorted[0].toFixed(4)),
  };
}

async function makeAudit() {
  const { AuditChain } = await import("../packages/agent-control/src/core/audit.mjs");
  const { mkdtemp } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "cirvix-bench-"));
  return new AuditChain(join(dir, "audit.jsonl")).open();
}

/* -------------------------------------------------------------------------- */

function platformLine() {
  const cpu = cpus()[0];
  return {
    node: process.version,
    platform: `${platform()} ${release()} ${arch()}`,
    cpu: cpu ? `${cpu.model.trim()} × ${cpus().length}` : "unknown",
    memoryGb: Math.round(totalmem() / 1024 ** 3),
  };
}

/**
 * A stable identifier for the machine a result was measured on.
 *
 * Results are keyed by this so `results.json` accumulates one row per platform
 * rather than overwriting whichever ran last. Containers report themselves
 * separately from the host kernel they share, because a Docker number and a
 * bare-metal Linux number are different measurements.
 */
function platformKey() {
  const os = platform();
  const cpuArch = arch();
  const containerized =
    process.env.CIRVIX_BENCH_ENV === "docker" ||
    existsSync("/.dockerenv") ||
    (os === "linux" && existsSync("/run/.containerenv"));

  const base =
    os === "darwin" ? "macos" : os === "win32" ? "windows" : os === "linux" ? "linux" : os;
  const cpu = cpuArch === "x64" ? "x86_64" : cpuArch;
  return containerized ? `docker-${base}-${cpu}` : `${base}-${cpu}`;
}

/** The matrix the project intends to cover. Missing rows are reported, not hidden. */
const TARGET_PLATFORMS = [
  "linux-x86_64",
  "linux-arm64",
  "macos-arm64",
  "docker-linux-x86_64",
  "windows-x86_64",
];

const RESULTS_PATH = new URL("./results.json", import.meta.url);

async function loadResults() {
  try {
    const { readFile } = await import("node:fs/promises");
    return JSON.parse(await readFile(RESULTS_PATH, "utf8"));
  } catch {
    return { $comment: "Accumulated benchmark results, one entry per platform. Written by decision.mjs --record.", platforms: {} };
  }
}

async function main() {
  const args = process.argv.slice(2);
  const json = args.includes("--json");
  const includeAudit = args.includes("--audit");
  const record = args.includes("--record");
  const full = args.includes("--full");
  const matrix = args.includes("--matrix");
  const nFlag = args.indexOf("--n");
  const extra = nFlag !== -1 ? Number(args[nFlag + 1]) : null;

  // `--matrix` prints the coverage table and exits. It is the honest answer to
  // "what have you measured", including the rows that say "not run here".
  if (matrix) {
    const stored = await loadResults();
    process.stdout.write("\n  CIRVIX BENCHMARK MATRIX\n\n");
    const width = Math.max(...TARGET_PLATFORMS.map((p) => p.length));
    for (const target of TARGET_PLATFORMS) {
      const entry = stored.platforms?.[target];
      if (!entry) {
        process.stdout.write(`  ${target.padEnd(width)}   not measured\n`);
        continue;
      }
      const largest = entry.runs[entry.runs.length - 1];
      process.stdout.write(
        `  ${target.padEnd(width)}   P99 ${String(largest.p99).padStart(7)}ms   ` +
          `over ${largest.n.toLocaleString("en-US").padStart(9)} decisions   ${entry.recordedAt}\n`,
      );
    }
    process.stdout.write(
      `\n  Rows marked "not measured" have not been run on this project's hardware.\n` +
        `  They are absent rather than estimated, because an estimated latency row\n` +
        `  is indistinguishable from a measured one once it is in a table.\n\n` +
        `  To fill one in, run on that machine:  node benchmarks/decision.mjs --record\n\n`,
    );
    return;
  }

  const { rules } = compile(STARTER_POLICY, { cwd: CWD, origin: "bench" });

  // 1M is opt-in: it takes minutes, and a benchmark nobody runs because it is
  // slow is a benchmark that stops catching regressions.
  const sizes = full ? [1_000, 10_000, 100_000, 1_000_000] : [1_000, 10_000, 100_000];
  if (extra && !sizes.includes(extra)) sizes.push(extra);

  const env = platformLine();
  const runs = [];

  if (!json) {
    process.stdout.write("\n  CIRVIX DECISION BENCHMARK\n\n");
    process.stdout.write(`  node       ${env.node}\n`);
    process.stdout.write(`  platform   ${env.platform}\n`);
    process.stdout.write(`  cpu        ${env.cpu}\n`);
    process.stdout.write(`  memory     ${env.memoryGb} GB\n`);
    process.stdout.write(`  rules      ${rules.length}\n`);
    process.stdout.write(`  audit      ${includeAudit ? "included (fsync-bound)" : "excluded"}\n`);
    process.stdout.write("\n");
    process.stdout.write(
      "  " +
        ["calls", "wall", "ops/s", "mean", "p50", "p95", "p99", "p99.9", "max"]
          .map((h, i) => h.padStart(i === 0 ? 9 : 10))
          .join("") +
        "\n",
    );
    process.stdout.write("  " + "─".repeat(89) + "\n");
  }

  for (const n of sizes) {
    const result = await measure(n, { rules, includeAudit });
    runs.push(result);
    if (json) continue;
    process.stdout.write(
      "  " +
        [
          n.toLocaleString("en-US"),
          `${(result.wallMs / 1000).toFixed(2)}s`,
          result.throughput.toLocaleString("en-US"),
          `${result.mean}ms`,
          `${result.p50}ms`,
          `${result.p95}ms`,
          `${result.p99}ms`,
          `${result.p999}ms`,
          `${result.max}ms`,
        ]
          .map((v, i) => String(v).padStart(i === 0 ? 9 : 10))
          .join("") +
        "\n",
    );
  }

  // `--record` accumulates into results.json, keyed by platform, so running the
  // harness on a second machine adds a row instead of replacing the first.
  if (record) {
    const { writeFile } = await import("node:fs/promises");
    const stored = await loadResults();
    const key = platformKey();
    stored.platforms = stored.platforms ?? {};
    stored.platforms[key] = {
      environment: env,
      rules: rules.length,
      includeAudit,
      // Stamped from the clock at write time; the runs themselves carry no
      // timestamps, so a re-run replaces the row rather than appending noise.
      recordedAt: new Date().toISOString().slice(0, 10),
      runs,
    };
    await writeFile(RESULTS_PATH, JSON.stringify(stored, null, 2) + "\n", "utf8");
    if (!json) process.stdout.write(`\n  recorded as "${key}" in benchmarks/results.json\n`);
  }

  if (json) {
    process.stdout.write(
      JSON.stringify({ platform: platformKey(), environment: env, rules: rules.length, includeAudit, runs }, null, 2) + "\n",
    );
    return;
  }

  const largest = runs[runs.length - 1];
  process.stdout.write("\n");
  process.stdout.write(
    `  P99 ${largest.p99}ms over ${largest.n.toLocaleString("en-US")} decisions on this machine.\n\n`,
  );
  process.stdout.write("  This measures the decision path only: parse, normalize, secret scan, risk,\n");
  process.stdout.write("  policy, approval, substitution. It excludes the upstream tool round trip,\n");
  process.stdout.write(`  which is orders of magnitude larger${includeAudit ? "" : ", and the audit append, which is disk-bound"}.\n`);
  process.stdout.write("\n");
  process.stdout.write("  Quote this number with the platform line above it. A latency figure with no\n");
  process.stdout.write("  machine attached is not a measurement.\n\n");
}

main().catch((err) => {
  process.stderr.write(`\n  benchmark failed: ${err.stack}\n\n`);
  process.exit(1);
});
