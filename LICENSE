Cirvix — licensing
Copyright 2026 Umang Kumar, trading as Cirvix

This repository is split across two licences on purpose. Which one applies
depends on which package the file is in.

  packages/agent-control    Apache License 2.0    packages/agent-control/LICENSE
  packages/cirvix-python    Apache License 2.0    packages/cirvix-python/LICENSE
  packages/conformance      Apache License 2.0    (shared fixture; engine terms)

  packages/control-plane    Proprietary           packages/control-plane/LICENSE
  src/                      Proprietary           the website, docs and console

THE ENFORCEMENT ENGINE IS APACHE 2.0

`agent-control` and `cirvix-python` are two implementations of the same engine:
policy evaluation, risk classification, secret detection and handle
substitution, the local control socket, the MCP gateway, the audit chain, the
scanner, and the CLI.

That is the part that decides whether a tool call is allowed to run. A security
control you cannot read is one you are asked to take on faith, and asking a
security engineer to do that is how you get ignored. It is Apache 2.0 — with
the patent grant, which matters here — so it can be read, forked, audited, and
run in production without payment or permission.

The free tier is this engine. It is not a crippled build of something else, and
it does not phone home. It is the whole enforcement path, running locally.

THE CONTROL PLANE IS NOT

`control-plane` is the commercial product: multi-tenant policy distribution,
the team vault, SSO and SCIM, the approvals workflow, hosted audit retention
and export, compliance evidence reporting, fleet telemetry, and billing. It is
proprietary and is not published to any registry.

The business is coordination between people and machines, not the act of
deciding a single call. Those are different problems, and only the second one
needs to be secret.

A NOTE ON THE QUOTA COUNTER

The engine's free-tier decision counter lives in a file on the user's own
machine. Under Apache 2.0 they may modify it, and this file does not pretend
otherwise. It is honour-system metering, the source says so in as many words,
and the features that genuinely cannot be faked locally — shared policy, team
approvals, the org vault, hosted audit — are enforced server-side where the
licence is not the thing doing the work.

THIRD-PARTY CODE

There is none in either engine package. Both have zero runtime dependencies,
deliberately and permanently.
