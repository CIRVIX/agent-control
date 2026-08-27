/**
 * SARIF 2.1.0 output for `cirvix scan`.
 *
 * The point is not the file format. It is that a finding uploaded as SARIF
 * lands in GitHub's Security tab and on the pull request diff, where somebody
 * will see it — rather than in a CI log, where a red X means "the build broke"
 * and gets retried. A security tool whose findings only appear in logs is a
 * security tool people learn to ignore.
 *
 * TWO THINGS THAT MAKE THE UPLOAD BEHAVE
 *
 * 1. `partialFingerprints` is stable across runs. Without it, GitHub treats
 *    every scan as a fresh set of findings, so an issue somebody triaged and
 *    dismissed reappears on the next push and the whole feature becomes noise.
 *    The fingerprint is over the rule and the subject, not over the message,
 *    so rewording a `detail` string does not resurrect a dismissal.
 *
 * 2. Paths are repository-relative. SARIF's `uri` is resolved against the
 *    checkout root, and an absolute path from the scanning machine points at
 *    nothing on GitHub's side — the finding uploads successfully and then
 *    appears attached to no file at all.
 */

import { createHash } from "node:crypto";
import { relative } from "node:path";

const VERSION = "0.1.0";

/** SARIF has three levels; ours has three severities. They do not line up 1:1. */
const LEVEL = { high: "error", medium: "warning", low: "note" };

/**
 * GitHub sorts and filters on `security-severity`, a CVSS-like number, and
 * shows nothing useful without it.
 */
const SECURITY_SEVERITY = { high: "8.0", medium: "5.0", low: "3.0" };

const HELP = {
  "runtime-ungoverned":
    "This agent runtime routes tool calls directly to MCP servers. Point it at `cirvix gateway` so every call is evaluated against policy first.",
  "framework-unguarded":
    "This framework's tool boundary has no guard on it. Wrap the executor with `guard.wrap()` from `@cirvix_ai/agent-control`.",
  "server-broad-scope":
    "This MCP server is configured with a scope far wider than a workspace. Narrow it, or add a policy rule bounding what an agent may reach through it.",
  "server-inline-secrets":
    "Credentials sit in a plaintext MCP configuration file. Move them behind a secret handle so the agent never holds the value.",
  "server-duplicated":
    "The same server is configured independently in several runtimes, so a change in one leaves the others behind.",
  "env-readable":
    "A .env file is readable by any agent with filesystem access. This is the most common path from a prompt injection to a live credential.",
  "credential-readable":
    "Cloud, SSH, or registry credentials are readable from agent context. Deny reads of this path and broker the value instead.",
};

/**
 * Converts a scan result to a SARIF log.
 *
 * @param {object} result the object `scan()` returns
 * @param {object} [opts]
 * @param {string} [opts.root] repository root, for relative paths
 */
export function toSarif(result, { root = process.cwd() } = {}) {
  const findings = result.findings ?? [];

  // One rule per code, not per finding — SARIF's model is "rules produce
  // results", and emitting a rule per result makes GitHub's rule filter
  // useless.
  const codes = [...new Set(findings.map((f) => f.code))];
  const rules = codes.map((code) => ({
    id: code,
    name: code.replace(/(^|-)(\w)/g, (_, dash, c) => (dash ? "" : "") + c.toUpperCase()),
    shortDescription: { text: describe(code) },
    fullDescription: { text: HELP[code] ?? describe(code) },
    help: { text: HELP[code] ?? describe(code) },
    defaultConfiguration: {
      level: LEVEL[severityOf(findings, code)] ?? "warning",
    },
    properties: {
      tags: ["security", "ai-agents", "cirvix"],
      "security-severity": SECURITY_SEVERITY[severityOf(findings, code)] ?? "5.0",
    },
  }));

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Cirvix AgentControl",
            informationUri: "https://www.cirvix.com",
            version: VERSION,
            semanticVersion: VERSION,
            rules,
          },
        },
        // A scan of a developer machine finds things outside the repository —
        // an SSH key, a globally configured MCP server. Those are real
        // findings and they are reported, but they cannot be attached to a
        // line of code, so they are anchored at the repository root rather
        // than at a path GitHub cannot resolve.
        results: findings.map((finding) => ({
          ruleId: finding.code,
          level: LEVEL[finding.severity] ?? "warning",
          message: { text: `${finding.subject}: ${finding.detail}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: locationFor(finding, root) },
                region: { startLine: 1 },
              },
            },
          ],
          partialFingerprints: {
            cirvixFindingV1: fingerprint(finding),
          },
          properties: {
            severity: finding.severity,
            remediation: finding.fix ?? null,
          },
        })),
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: result.scannedAt,
          },
        ],
      },
    ],
  };
}

/**
 * Stable across runs, so a dismissal sticks.
 *
 * Over the rule and the subject only — rewording a `detail` string must not
 * resurrect something a human already triaged.
 */
function fingerprint(finding) {
  return createHash("sha256")
    .update(`${finding.code}\u0000${finding.subject}`)
    .digest("hex")
    .slice(0, 32);
}

function locationFor(finding, root) {
  const raw = finding.path ?? finding.file ?? null;
  if (!raw) return ".";
  const rel = relative(root, raw).split("\\").join("/");
  // A path outside the checkout resolves to nothing on GitHub's side, and a
  // result attached to nothing is worse than one attached to the root.
  return rel && !rel.startsWith("..") ? rel : ".";
}

function severityOf(findings, code) {
  const order = { high: 0, medium: 1, low: 2 };
  return findings
    .filter((f) => f.code === code)
    .map((f) => f.severity)
    .sort((a, b) => order[a] - order[b])[0];
}

function describe(code) {
  return (
    {
      "runtime-ungoverned": "An agent runtime is not routed through a control plane",
      "framework-unguarded": "An agent framework has no guard on its tool boundary",
      "server-broad-scope": "An MCP server is configured with a scope wider than a workspace",
      "server-inline-secrets": "An MCP configuration carries credentials inline",
      "server-duplicated": "One MCP server is configured independently in several runtimes",
      "env-readable": "A .env file is readable from agent context",
      "credential-readable": "Cloud or SSH credentials are readable from agent context",
    }[code] ?? code
  );
}
