import test from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { Gateway } from "../src/core/gateway.mjs";
import { HttpGatewayServer } from "../src/core/http-transport.mjs";
import { STARTER_RULES } from "../src/core/policy.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const MOCK = join(HERE, "fixtures", "mock-mcp-server.mjs");

function createTestHarness(port, rules = [{ name: "allow-all", effect: "permit", actions: ["*"], resources: ["*"] }]) {
  const stdioMessages = [];
  const gw = new Gateway({
    servers: {
      files: {
        command: process.execPath,
        args: [MOCK],
      },
    },
    rules,
    cwd: process.cwd(),
    log: () => {},
  });

  gw.start((msg) => {
    stdioMessages.push(msg);
  });

  let server;
  return {
    gw,
    stdioMessages,
    async startServer() {
      server = await new HttpGatewayServer({
        gateway: gw,
        host: "127.0.0.1",
        port,
        log: () => {},
      }).start();
      return server;
    },
    async stop() {
      if (server) await server.stop();
      gw.stop();
    },
  };
}

test("HTTP transport: concurrent requests receive strictly their own responses", async () => {
  const harness = createTestHarness(8994);
  await harness.startServer();

  try {
    // Populate tools list first
    await fetch("http://127.0.0.1:8994", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: "init-1", method: "tools/list", params: {} }),
    });

    // Send 10 concurrent requests with different IDs and different targets
    const count = 10;
    const requests = Array.from({ length: count }, (_, i) => {
      const id = `client-${i}`;
      return fetch("http://127.0.0.1:8994", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id,
          method: "tools/call",
          params: {
            name: "files__read_file",
            arguments: { path: `test-path-${i}.txt` },
          },
        }),
      }).then(async (r) => {
        const json = await r.json();
        return { expectedId: id, actual: json };
      });
    });

    const results = await Promise.all(requests);
    for (const { expectedId, actual } of results) {
      assert.equal(actual.id, expectedId, `Response id ${actual.id} must match expected id ${expectedId}`);
      assert.ok(actual.result, "Must return tool result");
      assert.match(actual.result.content[0].text, new RegExp(expectedId.replace("client-", "test-path-")));
    }

    // stdio write sink must NOT have received any HTTP tool call results
    assert.equal(harness.stdioMessages.length, 0);
  } finally {
    await harness.stop();
  }
});

test("HTTP transport: stdio and HTTP messages are strictly isolated", async () => {
  const harness = createTestHarness(8995);
  await harness.startServer();

  try {
    // Stdio ping
    await harness.gw.handleClientMessage({ jsonrpc: "2.0", id: "stdio-ping", method: "ping" });
    assert.equal(harness.stdioMessages.length, 1);
    assert.equal(harness.stdioMessages[0].id, "stdio-ping");

    // HTTP ping
    const res = await fetch("http://127.0.0.1:8995", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: "http-ping", method: "ping" }),
    }).then((r) => r.json());

    assert.equal(res.id, "http-ping");

    // Stdio sink still only has 1 message
    assert.equal(harness.stdioMessages.length, 1);
    assert.equal(harness.stdioMessages[0].id, "stdio-ping");
  } finally {
    await harness.stop();
  }
});

test("HTTP transport: late upstream reply on disconnected socket drops safely", async () => {
  const harness = createTestHarness(8996);
  await harness.startServer();

  try {
    const controller = new AbortController();
    const req = fetch("http://127.0.0.1:8996", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: "aborted-client",
        method: "tools/call",
        params: { name: "files__read_file", arguments: { path: "package.json" } },
      }),
      signal: controller.signal,
    }).catch(() => "aborted");

    // Immediately abort request
    controller.abort();
    await req;

    // Upstream will respond asynchronously; verify gateway and server remain completely stable
    await new Promise((r) => setTimeout(r, 100));

    // A subsequent request must work cleanly
    const followUp = await fetch("http://127.0.0.1:8996", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: "follow-up", method: "ping" }),
    }).then((r) => r.json());

    assert.equal(followUp.id, "follow-up");
  } finally {
    await harness.stop();
  }
});
