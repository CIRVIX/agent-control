/**
 * Cirvix event model — the contract between the engine and every UI.
 *
 * The policy engine never prints. It emits typed events on an EventBus.
 * Every UI (CLI cards, the interactive console, a future web dashboard or
 * desktop app, CI reporters) is a renderer over this event stream:
 *
 *   Policy engine → Event → State reducer → Component
 *
 * Event types:
 *   SESSION_STARTED / SESSION_ENDED
 *   USER_MESSAGE            the human typed something into the console
 *   AGENT_MESSAGE           a text answer to show in the conversation pane
 *   POLICY_EVALUATION_STARTED
 *   POLICY_DECISION         one tool call decided (carries the audit event)
 *   TOOL_STARTED / TOOL_OUTPUT / TOOL_FINISHED
 *   APPROVAL_REQUESTED / APPROVAL_GRANTED / APPROVAL_DENIED
 *   AUDIT_COMPLETED
 *   RUNTIME_ERROR
 *   STATUS_SNAPSHOT       rolling counters for the status bar
 *
 * Zero dependencies. Serializable (JSON-safe) by construction so the same
 * events can cross the UDS socket or be recorded in tests.
 */

export const EVENT = {
  SESSION_STARTED: "SESSION_STARTED",
  SESSION_ENDED: "SESSION_ENDED",
  USER_MESSAGE: "USER_MESSAGE",
  AGENT_MESSAGE: "AGENT_MESSAGE",
  POLICY_EVALUATION_STARTED: "POLICY_EVALUATION_STARTED",
  POLICY_DECISION: "POLICY_DECISION",
  TOOL_STARTED: "TOOL_STARTED",
  TOOL_OUTPUT: "TOOL_OUTPUT",
  TOOL_FINISHED: "TOOL_FINISHED",
  APPROVAL_REQUESTED: "APPROVAL_REQUESTED",
  APPROVAL_GRANTED: "APPROVAL_GRANTED",
  APPROVAL_DENIED: "APPROVAL_DENIED",
  AUDIT_COMPLETED: "AUDIT_COMPLETED",
  RUNTIME_ERROR: "RUNTIME_ERROR",
  STATUS_SNAPSHOT: "STATUS_SNAPSHOT",
};

let seq = 0;

function base(type, payload = {}) {
  return {
    type,
    id: `evt_${Date.now().toString(36)}_${(seq++).toString(36)}`,
    ts: new Date().toISOString(),
    ...payload,
  };
}

export const createEvent = {
  sessionStarted: (p = {}) => base(EVENT.SESSION_STARTED, p),
  sessionEnded: (p = {}) => base(EVENT.SESSION_ENDED, p),
  userMessage: (text, p = {}) => base(EVENT.USER_MESSAGE, { text, ...p }),
  agentMessage: (text, p = {}) => base(EVENT.AGENT_MESSAGE, { text, ...p }),
  evaluationStarted: (p = {}) => base(EVENT.POLICY_EVALUATION_STARTED, p),
  policyDecision: (decision, p = {}) =>
    base(EVENT.POLICY_DECISION, {
      decision: decision?.decision ?? decision?.verdict ?? "deny",
      tool: decision?.tool ?? decision?.action ?? "unknown",
      resource: decision?.resource ?? "",
      risk: decision?.risk ?? "low",
      policy: decision?.policy ?? decision?.rule ?? null,
      reason: decision?.reason ?? "",
      latency_ms: decision?.latency_ms ?? 0,
      raw: decision,
      ...p,
    }),
  toolStarted: (tool, p = {}) => base(EVENT.TOOL_STARTED, { tool, ...p }),
  toolOutput: (text, p = {}) => base(EVENT.TOOL_OUTPUT, { text, ...p }),
  toolFinished: (tool, p = {}) => base(EVENT.TOOL_FINISHED, { tool, ...p }),
  approvalRequested: (p = {}) => base(EVENT.APPROVAL_REQUESTED, p),
  approvalGranted: (p = {}) => base(EVENT.APPROVAL_GRANTED, p),
  approvalDenied: (p = {}) => base(EVENT.APPROVAL_DENIED, p),
  auditCompleted: (p = {}) => base(EVENT.AUDIT_COMPLETED, p),
  runtimeError: (message, p = {}) => base(EVENT.RUNTIME_ERROR, { message, ...p }),
  statusSnapshot: (p = {}) => base(EVENT.STATUS_SNAPSHOT, p),
};

/**
 * Minimal pub/sub bus. Sync dispatch (the engine is sync-per-decision);
 * subscribers never throw into the engine — a broken UI listener is
 * isolated and reported via `onListenerError`.
 */
export class EventBus {
  constructor({ onListenerError = () => {} } = {}) {
    this.listeners = new Map();
    this.onListenerError = onListenerError;
    this.history = [];
    this.capped = 2000;
  }

  on(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(fn);
    return () => this.listeners.get(type)?.delete(fn);
  }

  onAny(fn) {
    return this.on("*", fn);
  }

  emit(event) {
    this.history.push(event);
    if (this.history.length > this.capped) this.history.shift();
    const targets = [
      ...(this.listeners.get(event.type) ?? []),
      ...(this.listeners.get("*") ?? []),
    ];
    for (const fn of targets) {
      try {
        fn(event);
      } catch (err) {
        this.onListenerError(err, event);
      }
    }
    return event;
  }

  replay(types, fn) {
    for (const e of this.history) {
      if (!types || types.includes(e.type)) fn(e);
    }
  }
}

/**
 * Adapt a live Pipeline to the bus: wraps `onEvent` so every decision the
 * engine makes also becomes a POLICY_DECISION (+ approval/tool) event.
 * Returns an unsubscribe function.
 */
export function attachPipeline(pipeline, bus) {
  const prev = pipeline.onEvent;
  pipeline.onEvent = (e) => {
    try {
      if (e?.kind === "decision") {
        bus.emit(createEvent.policyDecision(e));
        if (e.decision === "require_approval") {
          bus.emit(createEvent.approvalRequested({ approval_id: e.approval_id, tool: e.tool, resource: e.resource }));
        }
      } else if (e?.kind === "scrub") {
        bus.emit(createEvent.toolOutput(`scrubbed ${e.findings?.length ?? 0} finding(s)`, { findings: e.findings }));
      }
    } catch {
      // event translation must never break enforcement
    }
    return prev?.(e);
  };
  return () => {
    pipeline.onEvent = prev;
  };
}

/* ------------------------------------------------------------------ */
/*  Reducer — event stream → renderable UI state                       */
/* ------------------------------------------------------------------ */

export function initialState() {
  return {
    session: null,
    messages: [], // { role: 'user'|'cirvix', text, ts }
    activity: [], // POLICY_DECISION payloads, newest last
    approvals: [], // pending approval requests
    errors: [],
    status: {
      mode: "enforce",
      requests: 0,
      allowed: 0,
      sanitized: 0,
      blocked: 0,
      held: 0,
      latencies: [],
    },
    evaluating: false,
  };
}

export function reduce(state, event) {
  switch (event.type) {
    case EVENT.SESSION_STARTED:
      return { ...state, session: { id: event.sessionId ?? event.id, startedAt: event.ts, agent: event.agent ?? "local" } };
    case EVENT.SESSION_ENDED:
      return { ...state, session: state.session ? { ...state.session, endedAt: event.ts } : null, evaluating: false };
    case EVENT.USER_MESSAGE:
      return { ...state, messages: [...state.messages, { role: "user", text: event.text, ts: event.ts }] };
    case EVENT.AGENT_MESSAGE:
      return { ...state, messages: [...state.messages, { role: "cirvix", text: event.text, ts: event.ts }] };
    case EVENT.POLICY_EVALUATION_STARTED:
      return { ...state, evaluating: true };
    case EVENT.POLICY_DECISION: {
      const d = event.decision;
      const status = { ...state.status, requests: state.status.requests + 1 };
      if (d === "allow") status.allowed++;
      else if (d === "sanitize") status.sanitized++;
      else if (d === "deny") status.blocked++;
      else if (d === "require_approval") status.held++;
      if (typeof event.latency_ms === "number") {
        status.latencies = [...status.latencies.slice(-999), event.latency_ms];
      }
      return {
        ...state,
        evaluating: false,
        activity: [...state.activity.slice(-499), event],
        status,
      };
    }
    case EVENT.APPROVAL_REQUESTED:
      return { ...state, approvals: [...state.approvals, event] };
    case EVENT.APPROVAL_GRANTED:
    case EVENT.APPROVAL_DENIED:
      return {
        ...state,
        approvals: state.approvals.filter((a) => a.approval_id !== event.approval_id),
      };
    case EVENT.RUNTIME_ERROR:
      return { ...state, evaluating: false, errors: [...state.errors.slice(-49), event] };
    case EVENT.STATUS_SNAPSHOT:
      return { ...state, status: { ...state.status, ...event.snapshot } };
    default:
      return state;
  }
}

/** P50/P95 over the reducer's latency window. */
export function latencyStats(latencies) {
  if (!latencies?.length) return { p50: 0, p95: 0, samples: 0 };
  const s = [...latencies].sort((a, b) => a - b);
  const at = (q) => s[Math.min(s.length - 1, Math.floor(q * s.length))];
  return { p50: Number(at(0.5).toFixed(2)), p95: Number(at(0.95).toFixed(2)), samples: s.length };
}
