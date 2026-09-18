# Cirvix documentation

> **Public checkout scope:** the Node runtime/CLI, Python SDK, tests and local tooling are available here. Control-plane API, console, SSO/SCIM, billing and hosted services are not shipped or verified. Historical private-product claims are not release evidence.

Cirvix evaluates tool calls routed through configured enforcement boundaries. Audit persistence and optional controls depend on the actual entry point and supplied stores; installation alone does not govern an agent.

## Start here

| Goal | Guide |
|---|---|
| Run a local wrapper and policy test | [Quickstart](./quickstart.md) |
| Understand components and feature wiring | [Architecture](./architecture.md) |
| Write rules | [Policy reference](./policy.md) |
| Run local commands | [CLI reference](./cli.md) |
| Integrate Node or Python | [Node SDK](./sdk-node.md), [Python SDK](./sdk-python.md) |
| Route MCP traffic | [MCP](./guides/mcp.md), [Claude Code](./guides/claude-code.md), [Cursor](./guides/cursor.md) |
| Integrate an in-process agent | [Local agents](./guides/local-agent.md) |
| Narrow delegated authority | [Delegation](./delegation.md) |
| Launch local components | [Deployment](./deployment.md) |
| Understand persistence and recovery | [Operations](./operations.md) |
| Diagnose local behavior | [Troubleshooting](./troubleshooting.md) |
| Verify a release candidate | [Developer guide](./developer.md) |
| Understand evaluator parity | [Conformance](./conformance.md) |
| Understand security boundaries | [Security](./security.md) |
| Review fixture examples | [Examples](./examples/) |

## Available product

- `@cirvix_ai/agent-control`: zero-runtime-dependency Node ESM engine, Guard, Pipeline, MCP gateway, local socket, local stores, optional feature modules, adapters, scanner, CLI, external API client daemon and scan action.
- `cirvix`: zero-runtime-dependency Python evaluator/wrapper/testing helpers. No Node-equivalent audit sink, broker or delegation layer.
- Shared fixtures: 82 policy cases and 24 Node delegation cases in `packages/conformance/policy-conformance.json`. Passing them does not demonstrate that every transport enables every control.
- Repository-only tools, demos, benchmarks and tests are distinct from shipped package files.

Version metadata currently declares `0.1.5`; package availability in external registries is not established by that declaration. No SaaS API, web frontend, auth/RBAC server, billing processor integration, tenant database, SSO/SCIM or deployment templates are present. The control-plane directory contains ignored artifacts, not a runnable server.

## Historical documents

[API](./api.md) and [Administration](./administration.md) retain external/private-product contracts, not implemented endpoints or verified tenant guarantees. Historical portions of [Operations](./operations.md), [Troubleshooting](./troubleshooting.md), [Commercial readiness](./COMMERCIAL-READINESS-REPORT.md), [Demo runbook](./DEMO-RUNBOOK.md) and launch notes must not be presented as current release proof. They may refer to absent files, routes, historical metrics or unpublished products. Prefer current source and explicit local limitations over those claims.

No certification, performance SLA, zero-bypass guarantee or commercial release approval follows from this documentation. See [Developer guide](./developer.md) for current verification commands and remaining boundaries. Final test and artifact results belong in the main agent's final report; historical counts are not release approval.
