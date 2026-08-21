# Contributing

Two rules that are not negotiable, and one that saves you time.

## Zero runtime dependencies

Both engines have none, permanently. A security tool that drags in a transitive
dependency tree is asking to become the supply-chain incident it exists to
prevent. A pull request that adds a runtime dependency will be declined
regardless of how good it is; dev dependencies are a separate conversation.

## The conformance fixture changes first

`packages/conformance` holds the cases both the Node and Python engines must
answer identically. If you are changing engine behaviour, change the fixture in
the same pull request and *before* the implementation, so the diff shows the
decision being made rather than the tests being adjusted to match.

## Run this before opening a PR

```bash
cd packages/agent-control && npm test && npm run verify:adversarial
cd ../cirvix-python && python -m unittest discover -s tests
```

The adversarial suite is the one that matters. It runs an 11,629-case corpus
plus a consistency oracle that compares each decision against what a real MCP
subprocess actually did. A change that passes the unit tests and fails the
oracle is a change that is wrong in the way this codebase has been wrong before.

## Security issues

Do not open a public issue. Use the address in
<https://www.cirvix.com/.well-known/security.txt>.
