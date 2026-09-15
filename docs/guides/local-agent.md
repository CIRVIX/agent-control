# Generic local agent

For a hand-rolled loop, LangChain executor, or another local agent that does
not speak MCP, use `guard.wrap`. It governs the tools you pass to it; direct
calls outside the wrapped object are outside this integration's coverage.

## Install → init → connect

```bash
npm install @cirvix_ai/agent-control
cirvix init
```

```js
import { guard, STARTER_RULES, CirvixDenied } from "@cirvix_ai/agent-control";

const tools = guard.wrap(myTools, { agent: "local-agent", rules: STARTER_RULES });
try {
  await tools.read_file({ path: ".env.production" });
} catch (error) {
  if (error instanceof CirvixDenied) console.log(error.policy, error.remediation, error.decisionId);
  throw error;
}
```

## Policy → test → verify

Load a checked-in policy with `parseRules`, run its declared cases with
`cirvix policy test`, then exercise one allowed and one denied call. Verify the
local chain with `cirvix audit verify`. Python uses the same flow through
`pip install cirvix` and `cirvix.guard.wrap`.
