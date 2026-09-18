import test from "node:test";
import assert from "node:assert/strict";
import https from "node:https";
import os from "node:os";
import { EventEmitter } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { login } from "../src/commands/login.mjs";

test("rejected login preserves credentials and emits only failure", async (t) => {
  const home = await mkdtemp(join(os.tmpdir(), "cirvix-login-"));
  const file = join(home, ".cirvix", "credentials.json");
  await mkdir(join(home, ".cirvix"));
  const original = JSON.stringify({ apiKey: "dummy-existing", controlPlaneUrl: "https://example.com" });
  await writeFile(file, original);
  let output = "";
  t.mock.method(os, "homedir", () => home);
  syncBuiltinESMExports();
  t.mock.method(process.stdout, "write", (text) => { output += text; return true; });
  t.mock.method(https, "get", (target, options, callback) => {
    assert.equal(target.protocol, "https:");
    assert.equal(target.port, "9443");
    assert.equal(target.pathname, "/control/v1/me");
    assert.equal(options.timeout, 6000);
    const request = new EventEmitter();
    queueMicrotask(() => {
      const response = new EventEmitter();
      response.statusCode = 401;
      callback(response);
      response.emit("data", '{"error":"rejected"}');
      response.emit("end");
    });
    return request;
  });
  syncBuiltinESMExports();
  try {
    assert.equal(await login({ key: "dummy-rejected", url: "https://example.com:9443/control", json: true }), 1);
    assert.equal(await readFile(file, "utf8"), original);
    assert.equal(JSON.parse(output).ok, false);
    assert.match(JSON.parse(output).error, /rejected/);
    assert.equal(https.get.mock.callCount(), 1);
    assert.doesNotMatch(output, /dummy-existing|dummy-rejected|Linked/);
  } finally {
    t.mock.restoreAll();
    syncBuiltinESMExports();
    await rm(home, { recursive: true, force: true });
  }
});
test("a successful login returns 0, stores the key, and never terminates its host", async (t) => {
  const home = await mkdtemp(join(os.tmpdir(), "cirvix-login-ok-"));
  const file = join(home, ".cirvix", "credentials.json");
  await mkdir(join(home, ".cirvix"));
  let out = "";
  t.mock.method(os, "homedir", () => home);
  syncBuiltinESMExports();
  t.mock.method(process.stdout, "write", (text) => { out += text; return true; });
  // `login()` is called in-process by the dashboard as well as by the CLI. A
  // hard exit inside it is a killed host, so the count must stay zero.
  t.mock.method(process, "exit", () => {});
  t.mock.method(https, "get", (target, options, callback) => {
    const request = new EventEmitter();
    queueMicrotask(() => {
      const response = new EventEmitter();
      response.statusCode = 200;
      callback(response);
      response.emit("data", '{"org":{"name":"acme"}}');
      response.emit("end");
    });
    return request;
  });
  syncBuiltinESMExports();
  try {
    assert.equal(await login({ key: "cak_placeholder_not_a_real_key", url: "https://api.example.com", json: true }), 0);
    assert.deepEqual(JSON.parse(out), { ok: true, controlPlaneUrl: "https://api.example.com", org: "acme" });
    const stored = JSON.parse(await readFile(file, "utf8"));
    assert.equal(stored.apiKey, "cak_placeholder_not_a_real_key");
    assert.equal(stored.controlPlaneUrl, "https://api.example.com");
    assert.equal(process.exit.mock.callCount(), 0, "login must never terminate its host process");
  } finally {
    t.mock.restoreAll();
    syncBuiltinESMExports();
    await rm(home, { recursive: true, force: true });
  }
});
