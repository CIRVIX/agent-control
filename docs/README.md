# Cirvix documentation

Runtime governance for AI agents. Every tool call an agent makes is evaluated
against policy before it executes, and the decision is recorded in a
tamper-evident chain.

**This directory is derived from the code and is the canonical documentation
set.** Where a published page and a document here disagree, this one is right —
these files are reviewed in the same pull request as the change they describe.

## Start here

| If you want to | Read |
|---|---|
| See it work in five minutes | [Quickstart](./quickstart.md) |
| Understand how the pieces fit | [Architecture](./architecture.md) |
| Write rules | [Policy reference](./policy.md) |
| Run a command | [CLI reference](./cli.md) |
| Call the control plane | [API reference](./api.md) |
| Govern a Node agent | [Node SDK](./sdk-node.md) |
| Govern a Python agent | [Python SDK](./sdk-python.md) |
| Let one agent act for another | [Delegation](./delegation.md) |
| Stand up a server | [Deployment](./deployment.md) |
| Administer a tenant | [Administrator guide](./administration.md) |
| Keep it running | [Operations](./operations.md) |
| Take a payment | Paddle setup (in the private operator runbook) |
| Fix something | [Troubleshooting](./troubleshooting.md) |
| Work on Cirvix itself | [Developer guide](./developer.md) |
| Add a third engine | [Conformance](./conformance.md) |
| Know what it does and does not defend | [Security and threat model](./security.md) |
| Copy something that runs | [Examples](./examples/) |

## The shape of the system

Three components, deployable independently:

- **`@cirvix/agent-control`** — a zero-dependency Node package containing the
  policy engine, the MCP gateway, the endpoint daemon, the audit chain, the
  secret client, the scanner, and the `cirvix` CLI.
- **`cirvix`** (PyPI) — a zero-dependency Python package containing a second
  implementation of the same policy engine, and `guard.wrap` for Python agents.
- **`@cirvix/control-plane`** — a zero-dependency multi-tenant HTTP API:
  policy distribution, fleet inventory, telemetry, approvals, secret brokering,
  audit, SSO, SCIM, compliance evidence.

Enforcement does not require the control plane. The gateway and both SDKs
evaluate locally against a rule set on disk; the control plane distributes
rules and collects what happened. That split is deliberate — a control plane
outage must not become an enforcement outage.

## What holds the two engines together

The Node and Python evaluators are separate implementations. They are kept in
agreement by [`packages/conformance/policy-conformance.json`](../packages/conformance/policy-conformance.json):
82 policy cases every engine must pass, plus 24 delegation cases required of
engines that implement delegation. Both suites load the same file. Neither
language is allowed a private copy, because the entire value of the fixture is
that a case cannot be made to pass in one engine and quietly skipped in the
other.

The fixture declares which engine implements which layer, and each suite asserts
its own declaration against reality — so an engine cannot gain a security layer
without also gaining its conformance cases.

Adding an engine means making that file pass, and [Conformance](./conformance.md)
is the contract. Read the section on what passing it does *not* prove: every
bypass found in this codebase so far has been a wiring failure between correct
components rather than a wrong answer from one.

## Maturity

Version `0.1.0` across all three packages. The test suites are real and are the
basis for every claim here:

| Suite | Count | Command |
|---|---|---|
| Node — `agent-control` | 688 (2 skipped on Windows) | `cd packages/agent-control && npm test` |
| Node — `control-plane` | 322 | `cd packages/control-plane && npm test` |
| Python | 108 | `cd packages/cirvix-python && python -m unittest discover -s tests` |
| Shared conformance | 106 cases | included in the above |
| Adversarial verification | 11,629 attack cases, 405 suite tests | `cd packages/agent-control && npm run verify:adversarial` |

The adversarial run is the one to look at. It reports zero-tolerance counters —
policy bypasses, secret leaks, approval bypasses, audit inconsistencies,
fail-open violations, authority escalations — each derived from a suite rather
than asserted, so the report cannot claim a zero that no test established.

No SOC 2, ISO 27001, or FedRAMP certification exists. Cirvix produces
[evidence reports](./administration.md#compliance-evidence) for those audits; it
does not assert an outcome, and the report vocabulary has no word for "pass" —
enforced by a test.
