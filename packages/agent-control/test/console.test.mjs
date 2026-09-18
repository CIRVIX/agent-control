import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { consolePreview, parseEvalInput } from "../src/commands/console.mjs";

const exec = promisify(execFile);
const cli = fileURLToPath(new URL("../bin/cirvix.mjs", import.meta.url));

async function workspace(t) {
  const cwd = await mkdtemp(join(tmpdir(), "cirvix-console-"));
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

test("console preview evaluates a hypothetical without executing", async (t) => {
  const cwd = await workspace(t);
  const denied = await run(cwd, ["console", "--eval", "fs.read .env.production"]);
  assert.equal(denied.code, 0);
  assert.match(denied.stdout, /DENY/);
  assert.match(denied.stdout, /nothing executed, nothing recorded/);
  assert.deepEqual(await readdir(cwd), []);
});

test("console preview agrees with check on the same call", async (t) => {
  const cwd = await workspace(t);
  const preview = await run(cwd, ["console", "--eval", "fs.read .env.production", "--json"]);
  assert.equal(preview.code, 0);
  const decision = JSON.parse(preview.stdout).decision;
  assert.equal(decision.verdict, "deny");
  assert.equal(decision.rule, "deny-dotenv-read");
});

test("console preview accepts key=value and cannot be confused into a subcommand", async (t) => {
  const cwd = await workspace(t);
  const kv = await run(cwd, ["console", "--eval", "tool=fs.read resource=.env.production"]);
  assert.equal(kv.code, 0);
  assert.match(kv.stdout, /DENY/);
  const bad = await run(cwd, ["console", "nonsense"]);
  assert.equal(bad.code, 2);
  assert.match(bad.stdout, /USAGE/);
  const incomplete = await run(cwd, ["console", "--eval", "only-a-tool"]);
  assert.equal(incomplete.code, 2);
  assert.match(incomplete.stderr, /tool.*resource/);
});

test("bare --eval previews without launching the terminal", async (t) => {
  const cwd = await workspace(t);
  const result = await run(cwd, ["--eval", "fs.read .env.production"]);
  assert.equal(result.code, 0);
  assert.match(result.stdout, /CONSOLE PREVIEW/);
  assert.deepEqual(await readdir(cwd), []);
});

test("eval input parser rejects malformed shapes", () => {
  assert.equal(parseEvalInput("").ok, false);
  assert.equal(parseEvalInput("just-a-tool").ok, false);
  assert.equal(parseEvalInput("{not json").ok, false);
  assert.equal(parseEvalInput('{"tool":"fs.read"}').ok, false);
});
