#!/usr/bin/env node
/** Reproducible startup, steady-state, memory, and audit-overhead benchmark. */
import { spawnSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { Pipeline } from "../packages/agent-control/src/core/pipeline.mjs";
import { AuditChain } from "../packages/agent-control/src/core/audit.mjs";
import { STARTER_RULES } from "../packages/agent-control/src/core/policy.mjs";

const root = fileURLToPath(new URL("../", import.meta.url));
const cwd = process.platform === "win32" ? "C:/workspace" : "/workspace";
const nIndex = process.argv.indexOf("--n");
const n = nIndex >= 0 ? Number(process.argv[nIndex + 1]) || 5000 : 5000;
const json = process.argv.includes("--json");
const percentile = (values, q) => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.ceil(q * sorted.length) - 1)];
};
const call = { tool: "read_file", arguments: { path: `${cwd}/src/app.ts` } };

function startup() {
  const values = [];
  for (let i = 0; i < 5; i++) {
    const started = performance.now();
    const result = spawnSync(process.execPath, ["-e", "import('./packages/agent-control/src/core/pipeline.mjs')"], { cwd: root, windowsHide: true });
    if (result.status !== 0) throw new Error(result.stderr?.toString() || "startup child failed");
    values.push(performance.now() - started);
  }
  return { samples: values.length, p50_ms: percentile(values, 0.5), p95_ms: percentile(values, 0.95), p99_ms: percentile(values, 0.99) };
}

async function decisions({ audit }) {
  const state = await mkdtemp(join(tmpdir(), "cirvix-system-bench-"));
  try {
    const chain = audit ? await new AuditChain(join(state, "audit.jsonl")).open() : null;
    const pipeline = new Pipeline({ rules: STARTER_RULES, cwd, agent: "bench", audit: chain });
    for (let i = 0; i < 500; i++) await pipeline.submit(call);
    const values = [];
    const started = performance.now();
    for (let i = 0; i < n; i++) {
      const t0 = performance.now();
      await pipeline.submit(call);
      values.push(performance.now() - t0);
    }
    const wall = performance.now() - started;
    return { n, wall_ms: Number(wall.toFixed(3)), decisions_per_sec: Math.round(n / (wall / 1000)), memory_rss_mb: Number((process.memoryUsage().rss / 1024 / 1024).toFixed(2)), p50_ms: Number(percentile(values, 0.5).toFixed(4)), p95_ms: Number(percentile(values, 0.95).toFixed(4)), p99_ms: Number(percentile(values, 0.99).toFixed(4)) };
  } finally {
    await rm(state, { recursive: true, force: true });
  }
}

const result = {
  generated_at: new Date().toISOString(),
  node: process.version,
  platform: `${process.platform} ${process.arch}`,
  startup: startup(),
  decisions: await decisions({ audit: false }),
  audit: await decisions({ audit: true }),
};
result.audit_overhead_ms_per_decision = Number((result.audit.p50_ms - result.decisions.p50_ms).toFixed(4));
if (json) process.stdout.write(JSON.stringify(result, null, 2) + "\n");
else console.log(`CIRVIX SYSTEM BENCHMARK\n${JSON.stringify(result, null, 2)}`);
