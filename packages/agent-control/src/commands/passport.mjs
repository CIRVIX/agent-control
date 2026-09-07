/**
 * `cirvix passport [agent]` — who this agent is, by what it has done.
 *
 * Reads the local audit chain and renders the passport. Optionally signs it
 * with the same proof machinery, so a passport can be handed to someone else
 * and checked with `cirvix verify`.
 */

import { join } from "node:path";
import { writeFile } from "node:fs/promises";

import { AuditChain } from "../core/audit.mjs";
import { buildPassport, signPassport, badgeSvg, MIN_DECISIONS_TO_SCORE } from "../core/passport.mjs";
import { canonical } from "../core/proof.mjs";
import { createHash } from "node:crypto";
import { loadOrCreateKey } from "./prove.mjs";
import { bold, dim, green, red, amber, gray } from "../core/format.mjs";
import { panel } from "../core/ui/primitives.mjs";

export async function passport({
  agentId = null,
  cwd = process.cwd(),
  stateDir = join(cwd, ".cirvix"),
  policy = null,
  json = false,
  sign = false,
  out = null,
  badge = false,
  badgeOut = null,
  write = (s) => process.stdout.write(s),
} = {}) {
  const chain = new AuditChain(join(stateDir, "audit.jsonl"));
  const records = await chain.read();

  if (!records.length) {
    const err = { error: "no_audit_records", message: "There is no audit chain in this workspace yet." };
    if (json) return { result: err, output: JSON.stringify(err, null, 2), exitCode: 1 };
    write(`\n  ${red("No audit chain in this workspace.")}\n  ${dim("Run `cirvix protect` or `cirvix runtime` first.")}\n\n`);
    return { result: err, exitCode: 1 };
  }

  const doc = buildPassport({ agentId, records, policy });

  let signed = null;
  if (sign) {
    /* A passport is about ONE agent. Without an id, buildPassport() returns the
       aggregate view of the workspace, which is a useful thing to read and a
       meaningless thing to sign — it would attest to "some agents, collectively".
       Refuse with the fix in the message rather than signing a document about
       nobody. */
    if (!doc.agent) {
      return {
        output: `
  ${red("error")}  Signing needs one agent, and this workspace view covers all of them.
` +
                `         Name the agent:  ${bold("cirvix passport <agent-id> --sign")}
` +
                `         List them with:  ${bold("cirvix passport")}
`,
        exitCode: 1,
      };
    }
    const key = await loadOrCreateKey(stateDir);
    /*
     * Sign the PASSPORT, not a proof of the last decision.
     *
     * This used to call buildProof(), which produced a perfectly valid
     * artifact describing one decision and its chain segment — and none of
     * the passport. Anyone handed the output of `cirvix passport --sign` and
     * told "here is my agent's passport" received a document with no
     * identity, no tools and no trust score in it. The command name promised
     * one artifact and the file was another.
     *
     * The policy hash is bound here rather than left to the caller: a
     * passport that names a policy version without pinning its content
     * attests to a moving target, and signPassport() refuses that case.
     */
    const policyHash = policy
      ? "sha256:" + createHash("sha256").update(canonical(policy.rules ?? [])).digest("hex")
      : null;
    const built = signPassport({
      passport: doc,
      privateKey: key.privateKey,
      keyId: key.keyId,
      issuer: "local",
      policyHash,
    });
    signed = built.token;
    if (out) await writeFile(out, built.token + "\n", "utf8");
  }

  /* A README badge, rendered from the passport that was just built. */
  if (badge) {
    const svg = badgeSvg(doc);
    if (badgeOut) await writeFile(badgeOut, svg + "\n", "utf8");
    else write(svg + "\n");
  }

  const result = { ...doc, ...(signed ? { proof: signed, writtenTo: out ?? null } : {}) };
  if (json) return { result, output: JSON.stringify(result, null, 2), exitCode: 0 };

  /* ------------------------------------------------------------- render */
  write(`\n  ${bold("AGENT PASSPORT")}  ${dim(doc.agent ?? "all agents in this workspace")}\n\n`);
  write(
    panel({
      lines: [
        `${"First seen".padEnd(13)} ${doc.identity.firstSeen ?? "—"}`,
        `${"Last seen".padEnd(13)} ${doc.identity.lastSeen ?? "—"}`,
        `${"Tools used".padEnd(13)} ${doc.identity.tools.length ? doc.identity.tools.join(", ") : "—"}`,
        ``,
        `${"Decisions".padEnd(13)} ${doc.behaviour.decisions}`,
        `${"Allowed".padEnd(13)} ${doc.behaviour.allowed}`,
        `${"Denied".padEnd(13)} ${doc.behaviour.denied}`,
        `${"Held".padEnd(13)} ${doc.behaviour.heldForApproval}`,
        `${"Critical".padEnd(13)} ${doc.behaviour.criticalAttempts}`,
        `${"Retries".padEnd(13)} ${doc.behaviour.repeatedRefusals}`,
      ],
      width: 62,
    }) + "\n",
  );

  write(`\n  ${bold("TRUST")}\n\n`);
  if (doc.trust.score === null) {
    /* No number at all. Printing a provisional score here would be the exact
       failure this module exists to avoid — it would be quoted, and it would
       be quoted without the caveat. */
    write(`    ${amber("Not enough evidence to score.")}\n`);
    write(`    ${dim(doc.trust.reason)}\n\n`);
    return { result, exitCode: 0 };
  }

  const tone = doc.trust.score >= 85 ? green : doc.trust.score >= 60 ? amber : red;
  write(`    ${tone(bold(String(doc.trust.score)))} ${dim("/ " + doc.trust.outOf)}   ${dim(doc.trust.confidence)}\n\n`);
  for (const c of doc.trust.components) {
    write(`      ${String(c.points).padStart(5)} / ${String(c.weight).padEnd(3)} ${dim(c.label)}\n`);
  }
  /* The bound travels with the number, every time. */
  write(`\n    ${dim(doc.trust.meaning)}\n`);

  if (signed) {
    write(`\n  ${green("✓")} signed${out ? ` → ${bold(out)}` : ""}\n`);
    if (!out) write(`\n${gray(signed)}\n`);
    write(`  ${dim("Check it:")} ${bold(`cirvix verify ${out ?? "<passport>"}`)}\n`);
  }
  write("\n");
  return { result, exitCode: 0 };
}

export { MIN_DECISIONS_TO_SCORE };
