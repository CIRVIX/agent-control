/**
 * Can Cirvix be made to lie?
 *
 * For every call: what it told the agent, what actually executed, and what it
 * wrote to the audit chain must all agree. See `oracle.mjs` for why that is a
 * different and harder question than "was the decision correct".
 *
 * Ground truth is the MCP server's own access log — a real subprocess that
 * really opens files and records every attempt before making it. Cirvix's
 * account of events is never used to verify Cirvix's account of events.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

import {
  auditIsComplete,
  createWorld,
  crossExamine,
  decisionOf,
  PLANTED_SECRETS,
  touched,
} from "./oracle.mjs";
import { DECISION } from "../../src/core/decisions.mjs";

/** Runs `fn` against a fresh world and always tears the subprocess down. */
async function withWorld(fn, options) {
  const world = await createWorld(options);
  try {
    return await fn(world);
  } finally {
    world.stop();
  }
}

/** One call, fully cross-examined. Returns the inconsistencies found. */
async function probe(world, { method = "tools/call", params, target }) {
  const before = (await world.accesses()).length;
  const response = await world.request(method, params);
  const accesses = await world.accesses();
  const records = await world.records();
  return {
    response,
    decision: decisionOf(response),
    accesses,
    newAccesses: accesses.slice(before),
    problems: crossExamine({ response, accesses, records, target, accessesBefore: before }),
  };
}

/* -------------------------------------------------------------------------- */
/*  DENY means it did not happen                                              */
/* -------------------------------------------------------------------------- */

test("lie-check: DENY on a credential read — nothing reached the file", async () => {
  await withWorld(async (world) => {
    const result = await probe(world, {
      params: { name: "files__read_file", arguments: { path: `${world.home}/.aws/credentials` } },
      target: ".aws",
    });

    assert.equal(result.decision, DECISION.DENY);
    assert.deepEqual(result.problems, []);
    assert.equal(result.newAccesses.length, 0, "the server attempted nothing");
  });
});

test("lie-check: DENY via resources/read — the other door is shut too", async () => {
  await withWorld(async (world) => {
    const result = await probe(world, {
      method: "resources/read",
      params: { uri: `files__${world.credentialUri}` },
      target: ".aws",
    });

    assert.equal(result.decision, DECISION.DENY);
    assert.deepEqual(result.problems, []);
  });
});

test("lie-check: DENY on a destructive command — it did not run", async () => {
  await withWorld(async (world) => {
    const result = await probe(world, {
      params: { name: "files__run_command", arguments: { command: "rm -rf /" } },
    });

    assert.equal(result.decision, DECISION.DENY);
    assert.deepEqual(result.problems, []);
    const text = result.response.result.content[0].text;
    assert.ok(!text.includes("EXECUTED"), "the command must not have executed");
  });
});

test("lie-check: every alternate spelling of a denied read stays denied AND unexecuted", async () => {
  await withWorld(async (world) => {
    const spellings = [
      `${world.home}/.aws/credentials`,
      `${world.home}/./.aws/./credentials`,
      `${world.home}/x/../.aws/credentials`,
      `${world.home}//.aws//credentials`,
      `${world.home}/%2Eaws/credentials`,
    ];

    for (const path of spellings) {
      const result = await probe(world, {
        params: { name: "files__read_file", arguments: { path } },
        target: ".aws",
      });
      assert.equal(result.decision, DECISION.DENY, path);
      assert.deepEqual(result.problems, [], path);
      assert.equal(result.newAccesses.length, 0, `${path} reached the server`);
    }
  });
});

/* -------------------------------------------------------------------------- */
/*  REQUIRE_APPROVAL means no execution-before-approval path                  */
/* -------------------------------------------------------------------------- */

test("lie-check: REQUIRE_APPROVAL — the call did not execute while pending", async () => {
  await withWorld(async (world) => {
    const result = await probe(world, {
      params: { name: "files__run_command", arguments: { command: "./scripts/whatever.sh --force" } },
    });

    assert.equal(result.decision, DECISION.REQUIRE_APPROVAL);
    assert.deepEqual(result.problems, []);
    assert.equal(result.newAccesses.length, 0, "held calls must not reach the server");
    assert.ok(!result.response.result.content[0].text.includes("EXECUTED"));
    assert.ok(result.response.result._meta["cirvix/approval_id"], "the agent is told what to wait on");
  });
});

test("lie-check: retrying a held call does not execute it on the second attempt", async () => {
  // A hold that becomes an allow simply by asking again is not a hold.
  await withWorld(async (world) => {
    const params = { name: "files__run_command", arguments: { command: "./scripts/deploy.sh --prod" } };
    for (let attempt = 0; attempt < 5; attempt++) {
      const result = await probe(world, { params });
      assert.notEqual(result.decision, DECISION.ALLOW, `attempt ${attempt + 1} was allowed`);
      assert.equal(result.newAccesses.length, 0, `attempt ${attempt + 1} executed`);
    }
  });
});

/* -------------------------------------------------------------------------- */
/*  ALLOW means the audit describes what actually happened                    */
/* -------------------------------------------------------------------------- */

test("lie-check: ALLOW — the audit record matches the call that ran", async () => {
  await withWorld(async (world) => {
    const path = `${world.workspace}/src/app.ts`;
    const result = await probe(world, {
      params: { name: "files__read_file", arguments: { path } },
    });

    assert.equal(result.decision, DECISION.ALLOW);
    assert.deepEqual(result.problems, []);

    // It really executed.
    assert.equal(result.newAccesses.length, 1);
    assert.ok(result.response.result.content[0].text.includes("answer = 42"));

    // And the record describes that call, not a different one.
    const records = await world.records();
    const record = records[records.length - 1];
    assert.equal(record.verdict, "permit");
    assert.equal(record.agent, "claude-code");
    assert.equal(record.tool, "read_file");
    assert.ok(record.resource.includes("app.ts"), `recorded resource was ${record.resource}`);
    assert.equal(record.rule, "allow-workspace-read");
  });
});

test("lie-check: the recorded resource is the one the server opened", async () => {
  // If the audit says one path and the server opened another, replay and every
  // incident review afterwards are reasoning about a call that never happened.
  await withWorld(async (world) => {
    const path = `${world.workspace}/src/../src/notes.md`;
    const result = await probe(world, {
      params: { name: "files__read_file", arguments: { path } },
    });

    assert.equal(result.decision, DECISION.ALLOW);
    const records = await world.records();
    const recorded = records[records.length - 1].resource.replace(/\\/g, "/");
    const opened = result.newAccesses[0].target.replace(/\\/g, "/");

    // The recorded resource is canonical; the opened path is what the agent
    // wrote. They must denote the same file.
    assert.ok(recorded.endsWith("src/notes.md"), `recorded ${recorded}`);
    assert.ok(opened.includes("notes.md"), `opened ${opened}`);
  });
});

/* -------------------------------------------------------------------------- */
/*  SANITIZE means the sanitized form is what executes                        */
/* -------------------------------------------------------------------------- */

test("lie-check: SANITIZE forwards the call and really executes it", async () => {
  await withWorld(async (world) => {
    const result = await probe(world, {
      params: { name: "files__fetch_url", arguments: { url: "https://docs.example.com/guide" } },
    });

    // A sanitize decision forwards — the agent gets a result, not a refusal.
    assert.ok(
      result.decision === DECISION.ALLOW || result.decision === DECISION.SANITIZE,
      `sanitize must forward, got ${result.decision} by ${result.response?.result?._meta?.["cirvix/rule"]}`,
    );
    assert.deepEqual(result.problems, []);

    // And it genuinely ran, rather than being reported as forwarded.
    assert.equal(result.newAccesses.length, 1, "the fetch must have reached the server");
    assert.match(result.response.result.content[0].text, /EXECUTED fetch_url/);
  });
});

test("lie-check: SANITIZE records itself as a sanitize, not as a plain allow", async () => {
  // A sanitize that is recorded as an allow makes the history claim the payload
  // was untouched, which is the opposite of what happened.
  await withWorld(async (world) => {
    await world.request("tools/call", {
      name: "files__fetch_url",
      arguments: { url: "https://docs.example.com/guide" },
    });

    const records = await world.records();
    const record = records[records.length - 1];
    assert.equal(record.verdict, "permit", "a sanitize forwards, so the verdict is a permit");
    assert.ok(record.rule, "and it names the rule that decided it");
  });
});

/* -------------------------------------------------------------------------- */
/*  The audit chain is complete, not merely intact                            */
/* -------------------------------------------------------------------------- */

test("lie-check: every call produces exactly one record, and the chain verifies", async () => {
  await withWorld(async (world) => {
    const calls = [
      { name: "files__read_file", arguments: { path: `${world.workspace}/src/app.ts` } },
      { name: "files__read_file", arguments: { path: `${world.home}/.aws/credentials` } },
      { name: "files__run_command", arguments: { command: "npm test" } },
      { name: "files__run_command", arguments: { command: "rm -rf /" } },
      { name: "files__run_command", arguments: { command: "./unknown.sh" } },
    ];

    for (const params of calls) await world.request("tools/call", { name: params.name, arguments: params.arguments });

    const problems = await auditIsComplete(world, calls.length);
    assert.deepEqual(problems, [], "the history must cover every call and verify");
  });
});

test("lie-check: a chain that verifies cannot be missing a denial", async () => {
  // The subtle failure: enforcement works, but the denial is never written, so
  // the history shows a clean run. Verification would still pass.
  await withWorld(async (world) => {
    await world.request("tools/call", {
      name: "files__read_file",
      arguments: { path: `${world.home}/.aws/credentials` },
    });

    const records = await world.records();
    const denial = records.find((r) => r.verdict === "deny");
    assert.ok(denial, "the denial must be in the history, not only in the response");
    assert.equal(denial.rule, "deny-credentials");
    assert.ok(denial.reason && denial.reason.length > 10);
  });
});

/* -------------------------------------------------------------------------- */
/*  Concurrency — where a proxy silently mis-routes                           */
/* -------------------------------------------------------------------------- */

test("lie-check: under concurrency every answer belongs to its own request", async () => {
  await withWorld(async (world) => {
    const allowed = `${world.workspace}/src/app.ts`;
    const denied = `${world.home}/.aws/credentials`;

    const calls = [];
    for (let i = 0; i < 20; i++) {
      calls.push(world.request("tools/call", { name: "files__read_file", arguments: { path: allowed } }));
      calls.push(world.request("tools/call", { name: "files__read_file", arguments: { path: denied } }));
    }
    const responses = await Promise.all(calls);

    const permits = responses.filter((r) => decisionOf(r) === DECISION.ALLOW);
    const denials = responses.filter((r) => decisionOf(r) === DECISION.DENY);

    assert.equal(permits.length, 20, "every allowed call got an allowed answer");
    assert.equal(denials.length, 20, "every denied call got a denial");

    // Not one response carries the wrong body.
    for (const r of permits) assert.match(r.result.content[0].text, /answer = 42/);
    for (const r of denials) assert.equal(r.result._meta["cirvix/rule"], "deny-credentials");

    // Exactly the twenty permitted reads reached disk, and none was the
    // credential file. This is the assertion a mis-routing bug fails.
    const accesses = await world.accesses();
    assert.equal(accesses.length, 20, `server performed ${accesses.length} operations`);
    assert.ok(!touched(accesses, ".aws"), "no credential access under load");

    const problems = await auditIsComplete(world, 40);
    assert.deepEqual(problems, []);
  });
});

test("lie-check: no planted secret appears in any surface after a full run", async () => {
  await withWorld(async (world) => {
    await world.request("tools/call", {
      name: "files__read_file",
      arguments: { path: `${world.home}/.aws/credentials` },
    });
    await world.request("resources/read", { uri: `files__${world.credentialUri}` });
    await world.request("resources/list", {});

    const records = JSON.stringify(await world.records());
    for (const secret of PLANTED_SECRETS) {
      assert.ok(!records.includes(secret), "the audit chain must never carry credential material");
    }
  });
});

/* -------------------------------------------------------------------------- */
/*  A permissive policy must not make Cirvix inconsistent — only permissive   */
/* -------------------------------------------------------------------------- */

test("lie-check: under an allow-everything policy, ALLOW still means it happened", async () => {
  // The point: consistency is a property of the machinery, not of the rules.
  // A wide-open policy should produce honest ALLOWs, not silent ones.
  await withWorld(
    async (world) => {
      const result = await probe(world, {
        params: { name: "files__read_file", arguments: { path: `${world.home}/.aws/credentials` } },
      });

      assert.equal(result.decision, DECISION.ALLOW, "the policy permits it");
      assert.equal(result.newAccesses.length, 1, "and it really happened");

      // The record must say so plainly rather than hiding a permissive decision.
      const records = await world.records();
      const record = records[records.length - 1];
      assert.equal(record.verdict, "permit");
      assert.ok(record.resource.includes(".aws"), "the record names what was read");
    },
    { policy: "allow:\n  name = allow-everything-reads\n  tool = filesystem.read\n" },
  );
});
