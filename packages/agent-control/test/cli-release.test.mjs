import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, readdir, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { BaseAgentAdapter } from "../src/adapters/base.mjs";

const exec = promisify(execFile);
const cli = fileURLToPath(new URL("../bin/cirvix.mjs", import.meta.url));

async function workspace(t) {
  const cwd = await mkdtemp(join(tmpdir(), "cirvix-cli-regression-"));
  t.after(() => rm(cwd, { recursive: true, force: true }));
  return cwd;
}

async function run(cwd, args) {
  const env = { ...process.env, HOME: cwd, USERPROFILE: cwd, NO_COLOR: "1", CI: "1" };
  delete env.CIRVIX_API_URL;
  delete env.CIRVIX_API_KEY;
  try {
    return { ...(await exec(process.execPath, [cli, ...args], { cwd, env, timeout: 20000 })), code: 0 };
  } catch (error) {
    if (typeof error.code !== "number") throw error;
    return { stdout: error.stdout, stderr: error.stderr, code: error.code };
  }
}

test("boolean flags do not consume commands and help has no side effects", async (t) => {
  const cwd = await workspace(t);
  const result = await run(cwd, ["--json", "version"]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /^\d+\.\d+\.\d+\s*$/);
  const help = await run(cwd, ["init", "--help"]);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /USAGE/);
  assert.deepEqual(await readdir(cwd), []);
});

test("missing option values fail instead of selecting defaults", async (t) => {
  const cwd = await workspace(t);
  const result = await run(cwd, ["policy", "list", "--policy"]);
  assert.equal(result.code, 2);
  assert.match(result.stderr, /--policy requires a value/);
});

test("repeated arguments survive CLI parsing", async (t) => {
  const cwd = await workspace(t);
  await writeFile(join(cwd, "policy.json"), JSON.stringify([{ name: "both", effect: "permit", actions: ["fs.read"], when: [{ path: "arguments.first", op: "eq", value: "one" }, { path: "arguments.second", op: "eq", value: "two" }] }]));
  const result = await run(cwd, ["policy", "explain", "--json", "--policy=policy.json", "--tool", "read_file", "--path", "document.txt", "--arg", "first=one", "--arg", "second=two"]);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).rule, "both");
});

test("audit verify honors explicit state rather than process state", async (t) => {
  const cwd = await workspace(t);
  const state = join(cwd, "custom-state");
  await mkdir(state);
  await writeFile(join(state, "audit.jsonl"), "invalid-record\n");
  const result = await run(cwd, ["audit", "verify", "--state", state, "--json"]);
  assert.equal(result.code, 1);
  assert.equal(JSON.parse(result.stdout).ok, false);
});

test("init dry run writes nothing and rejects conflicting apply", async (t) => {
  const cwd = await workspace(t);
  const result = await run(cwd, ["init", "--dry-run", "--json"]);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).dryRun, true);
  assert.deepEqual(await readdir(cwd), []);
  const conflict = await run(cwd, ["init", "--dry-run", "--apply", "--json"]);
  assert.equal(conflict.code, 1);
  assert.deepEqual(await readdir(cwd), []);
});

test("reinitialization preserves the existing runtime token", async (t) => {
  const cwd = await workspace(t);
  assert.equal((await run(cwd, ["init", "--json"])).code, 0);
  const token = join(cwd, ".cirvix", "socket.token");
  const before = await readFile(token, "utf8");
  assert.equal((await run(cwd, ["init", "--json"])).code, 0);
  assert.equal(await readFile(token, "utf8"), before);
});

test("adapter detection requires an actual gateway command", () => {
  const adapter = new BaseAgentAdapter({ id: "test", label: "test", type: "generic" });
  assert.equal(adapter.isCirvixServer("cirvix", { command: "unrelated" }), false);
  assert.equal(adapter.isCirvixServer("files", { command: "node", args: ["C:/work/cirvix/server.mjs"] }), false);
  assert.equal(adapter.isCirvixServer("gateway", { command: "cirvix.cmd", args: ["gateway", "--servers", "upstreams.json"] }), true);
  assert.equal(adapter.isCirvixServer("gateway", { command: "npx", args: ["-y", "@cirvix_ai/agent-control@0.1.5", "gateway"] }), true);
  // A version-agnostic spelling must also be recognized: pinning is good
  // practice, but the adapter must not depend on one pinned number.
  assert.equal(adapter.isCirvixServer("gateway", { command: "npx", args: ["-y", "@cirvix_ai/agent-control@0.2.1", "gateway"] }), true);
});
