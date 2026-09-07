/**
 * Continuous Red Teaming CLI Command.
 *
 * Runs automated adversarial security attacks against the active policy set.
 */

import { Pipeline } from "../core/pipeline.mjs";
import { runRedTeamSuite } from "../core/redteam/index.mjs";
import { bold, dim, green, red, amber, cyan } from "../core/format.mjs";

export async function executeRedTeamCommand({
  rules = [],
  plugins = null,
  json = false,
  cwd = process.cwd(),
} = {}) {
  const pipeline = new Pipeline({ rules, cwd });
  const report = await runRedTeamSuite(pipeline, { plugins });

  if (json) return { output: JSON.stringify(report, null, 2), code: report.testsBypassed > 0 ? 1 : 0 };

  const tone = report.resilienceScore >= 90 ? green : report.resilienceScore >= 70 ? amber : red;

  const lines = [
    "",
    `  ${bold("CIRVIX CONTINUOUS RED TEAMING REPORT")}`,
    `  ${dim(`Execution timestamp: ${report.ranAt}`)}`,
    "",
    `  ${bold("Resilience Score:")} ${tone(bold(`${report.resilienceScore} / 100`))}`,
    `  ${dim("Tests Passed / Blocked:")} ${green(`${report.testsBlocked}`)} / ${report.totalTests}`,
    `  ${dim("Security Bypasses:")}     ${report.testsBypassed > 0 ? red(`${report.testsBypassed}`) : green("0")}`,
    "",
    `  ${bold("Attack Findings:")}`,
    ...report.findings.map((f) => {
      const statusIcon = f.blocked ? green("✓ BLOCKED") : red("✗ BYPASS");
      return `    ${statusIcon} ${bold(f.vector)} — ${dim(f.decision ?? "ALLOW")} ${f.ruleTriggered ? dim(`(${f.ruleTriggered})`) : ""}`;
    }),
  ];

  if (report.policyRecommendations?.length > 0) {
    lines.push("");
    lines.push(`  ${amber(bold("Recommended Remediation Policies:"))}`);
    for (const rec of report.policyRecommendations) {
      lines.push(`    ${cyan("+")} ${rec}`);
    }
  }

  lines.push("");

  return { output: lines.join("\n"), code: report.testsBypassed > 0 ? 1 : 0 };
}
