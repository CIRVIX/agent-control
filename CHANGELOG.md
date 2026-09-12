# Changelog

## v0.1.3 — 2026-09-13

Audit-chain signing (repudiation gap closed), honest verification, CLI gates:

- `AuditChain` signs every record's hash with Ed25519 when a signer is
  configured; `verify()` checks signatures and reports
  `signed/signaturesVerified/unsigned` — a forged chain with every hash
  recomputed now fails on the signature, where before it verified clean.
- `cirvix audit verify --keygen <dir>` writes a private key plus a
  publishable public key; `--verify-key <pem>` checks signatures; a gateway
  booting in a state directory holding `audit-key.pem` signs from the next
  append. Publish the public key and a full-disk compromise cannot backdate
  authority.
- Unsigned chains are unchanged, byte-identical; adoption mid-chain is
  supported (the honest limit — attribution to the key, not a third party —
  is stated in the source, same contract as proof.mjs).
- `cirvix redteam --policy <file>` attacks the caller's own rule set (was
  silently the built-in benchmark rules); `--min-integrity <pct>` fails the
  run below the floor — a CI gate that cannot be silently disabled (NaN and
  out-of-range are loud refusals).

No breaking changes. Repro: `npm test`, `npm run verify:adversarial`,
`npm run verify:license`.

## v0.1.2 — 2026-09-11

Enforcement boundary (gateway is now authoritative for routed traffic):

- Unmodeled MCP methods default-deny as `mcp.<method>`; `prompts/get` and
  `completion/complete` evaluated before forwarding; stray notifications
  dropped with an audit record. Previously all three forwarded unevaluated.
- Python SDK: shared tool taxonomy with Node (`classify_tool`), canonical
  destinations, `wrap([fn])` silent-bypass fix, malformed rules skip
  (default-deny preserved).
- Demo (`node docs/examples/pr-title-injection.mjs`) runs the attack through
  `guard.wrap` AND a real gateway, with dual audit chains: PROMPT INJECTION
  OCCURRED, malicious actions denied, ATTACK STOPPED.
- Docs state the exact boundary: wrap covers wrapped paths, gateway covers
  routed traffic, direct servers / builtins / subprocesses / raw sockets are
  routes around it; Python is decision-only, not parity.

No breaking changes. Engine 809/0, Python 117/117, bypass suite 12/12.
Repro: `npm test`, `npm run verify:adversarial`, `npm run example`.

## v0.1.1 — 2026-09-09

Security (see `SECURITY.md` and the 2026-09-09 hostile review):

- No new authority model; no privilege widening on any path probed
  (200k-pair delegation fuzz clean, escape benchmark 44/44 contained).
- Docs: README positioning rewrite (runtime tool-call authorization,
  ALLOW/DENY/APPROVAL, 5-minute quickstart).

No breaking changes. Repro: `npm test`, `npm run verify:adversarial`,
`node benchmarks/decision.mjs`.

## v0.1.0 — 2026-08-27

Initial public release: `@cirvix_ai/agent-control` (npm) + `cirvix` (PyPI).
Known incident: v0.1.0 published to PyPI while npm skipped silently
(outputs-mapping bug); fixed in `release.yml` via `needs.build.outputs.creds`.
