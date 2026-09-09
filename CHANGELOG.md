# Changelog

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
