/**
 * When a commercial notice is shown, and to which stream.
 *
 * WHY THIS FILE EXISTS
 *
 * `prompts.mjs` had the copy — quota reached, agent limit reached, the one
 * soft nudge — written carefully, tested, and imported by nothing. `Meter`
 * had `shouldNudge()`, called by nothing. So the wording that the whole
 * conversion argument depends on was never shown to anybody.
 *
 * `prompts.mjs` deliberately decides nothing: it is strings, and it says so.
 * This file is the missing half — the decision about when to speak — kept out
 * of the CLI so it can be tested without a terminal.
 *
 * STDERR, ALWAYS
 *
 * The gateway's stdout carries MCP protocol frames. A notice written there
 * corrupts the wire and the agent fails in a way nobody will attribute to a
 * marketing line. Every notice goes to stderr, on every path, so there is no
 * per-call-site judgement to get wrong.
 *
 * AT MOST ONCE EACH
 *
 * The limit notice fires on the transition into the limit, not on every
 * refused call after it — a process that keeps calling past its quota would
 * otherwise print the same paragraph hundreds of times. The nudge is once per
 * day and `Meter` owns that flag. The domain-signal prompt is once per
 * process, on the first egress-class denial: the story it offers to share is
 * worth telling once, not every time an agent reaches for a credential file.
 */

import {
  agentLimitReached,
  domainSignal,
  quotaReached,
  softNudge,
  EGRESS_DENY_RULES,
} from "./prompts.mjs";

/**
 * Builds the per-decision notice hook.
 *
 * @param {object} opts
 * @param {object|null} opts.licence
 * @param {object|null} opts.meter
 * @param {(s:string)=>void} opts.write  receives an already-formatted block
 * @returns {(decision:object)=>void}
 */
export function commercialNotices({ licence, meter, write }) {
  if (!licence || !meter) return () => {};

  let saidQuota = false;
  let saidAgents = false;
  let saidDomain = false;

  return function notice(decision) {
    if (!decision) return;

    // The two cores name the deciding rule differently on the way out: a
    // Guard decision carries `rule`, a Pipeline audit event renames it to
    // `policy`. Accepting both is cheaper than making either caller remember,
    // and getting it wrong here fails silently — which is the failure mode
    // this whole file exists to correct.
    const rule = decision.rule ?? decision.policy;

    if (decision.verdict === "deny" && EGRESS_DENY_RULES.has(rule)) {
      if (saidDomain) return;
      saidDomain = true;
      const text = domainSignal(licence, {
        rule,
        destination: decision.destination ?? "",
      });
      if (text) write(`\n${text}\n`);
      return;
    }

    if (rule === "quota-exhausted") {
      if (saidQuota) return;
      saidQuota = true;
      const text = quotaReached(licence);
      if (text) write(`\n${text}\n`);
      return;
    }

    if (rule === "agent-limit") {
      if (saidAgents) return;
      saidAgents = true;
      const text = agentLimitReached(licence);
      if (text) write(`\n${text}\n`);
      return;
    }

    // A permitted call. Ask the meter whether today's single nudge is still
    // owed; `shouldNudge` marks it shown in the same call, so two callers
    // cannot both decide to print it.
    const used = meter.used();
    const text = softNudge(licence, used);
    if (text && meter.shouldNudge()) write(`\n${text}\n`);
  };
}
