#!/usr/bin/env node
/**
 * Turns a scan result into things a reviewer will actually see.
 *
 * Three surfaces, because a CI log is not one of them: a job summary somebody
 * reads without expanding a step, inline annotations on the pull request, and
 * step outputs so a workflow can branch on the numbers.
 *
 * Zero dependencies, like everything else that ships. An action that pulls a
 * markdown library to build a table is an action with a supply chain.
 */

import { appendFile, readFile, writeFile } from "node:fs/promises";

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };
const GATE = { high: ["high"], medium: ["high", "medium"], low: ["high", "medium", "low"] };
const ICON = { high: "🔴", medium: "🟠", low: "🟡" };

const [, , resultPath] = process.argv;

const result = JSON.parse(await readFile(resultPath ?? "cirvix-scan.json", "utf8"));
const findings = [...(result.findings ?? [])].sort(
  (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
);
const counts = result.counts ?? {};
const high = counts.high ?? 0;
const medium = counts.medium ?? 0;
const low = counts.low ?? 0;

const failOn = (process.env.CIRVIX_FAIL_ON ?? "high").toLowerCase();
const watched = GATE[failOn] ?? [];
const blocking = watched.reduce((n, level) => n + (counts[level] ?? 0), 0);
const passed = failOn === "never" || blocking === 0;

/* -- annotations ----------------------------------------------------------- */

// Only the blocking ones. Annotating every low finding on every pull request
// is how a team learns to scroll past the annotations, which costs more than
// the low findings were worth.
for (const finding of findings.filter((f) => watched.includes(f.severity))) {
  const level = finding.severity === "high" ? "error" : "warning";
  const title = `Cirvix: ${finding.subject}`;
  const body = `${finding.detail}${finding.fix ? `  Fix: ${finding.fix}` : ""}`;
  // GitHub's annotation format takes no newlines; %0A is the documented escape.
  process.stdout.write(
    `::${level} title=${escapeProperty(title)}::${escapeData(body)}\n`,
  );
}

/* -- summary --------------------------------------------------------------- */

const verdict = passed
  ? high + medium + low === 0
    ? "Nothing ungoverned found."
    : `No findings at or above **${failOn}**.`
  : `**${blocking}** finding${blocking === 1 ? "" : "s"} at or above **${failOn}**.`;

const lines = [
  "## Cirvix AgentControl",
  "",
  verdict,
  "",
  `| ${ICON.high} High | ${ICON.medium} Medium | ${ICON.low} Low |`,
  "|---|---|---|",
  `| ${high} | ${medium} | ${low} |`,
  "",
];

if (findings.length) {
  lines.push(
    "| | Finding | What it means | Fix |",
    "|---|---|---|---|",
    ...findings
      .slice(0, 40)
      .map(
        (f) =>
          `| ${ICON[f.severity] ?? ""} | \`${escapeCell(f.subject)}\` | ${escapeCell(f.detail)} | ${
            f.fix ? `\`${escapeCell(f.fix)}\`` : "—"
          } |`,
      ),
  );
  // Silence about truncation reads as "that was all of them".
  if (findings.length > 40) {
    lines.push("", `_${findings.length - 40} further findings are in the SARIF upload._`);
  }
} else {
  lines.push(
    "No agent runtime, MCP server, or reachable credential in this repository is currently ungoverned.",
  );
}

lines.push(
  "",
  `<sub>Scanned ${result.cwd ?? "."} at ${result.scannedAt ?? "unknown time"}. `,
  "Findings describe what an agent *could* reach, not what one has done. ",
  "Nothing was executed and no code was sent anywhere.</sub>",
);

const summary = lines.join("\n");

if (process.env.GITHUB_STEP_SUMMARY) {
  await appendFile(process.env.GITHUB_STEP_SUMMARY, summary + "\n", "utf8");
}
// Written unconditionally so the pull-request comment step has it whether or
// not a summary file exists — a local run of this script is a supported way to
// see what CI would say.
await writeFile("cirvix-summary.md", summary + "\n", "utf8");

/* -- outputs --------------------------------------------------------------- */

await setOutput("high", String(high));
await setOutput("medium", String(medium));
await setOutput("low", String(low));
await setOutput("passed", String(passed));
await setOutput("findings", JSON.stringify(result));

process.stdout.write(`\n${verdict.replace(/\*\*/g, "")}\n`);

/* -------------------------------------------------------------------------- */

async function setOutput(name, value) {
  if (!process.env.GITHUB_OUTPUT) return;
  // A multi-line value has to use the delimiter form, and the delimiter has to
  // be one the value cannot contain — otherwise a finding containing the
  // delimiter string can inject arbitrary outputs into the workflow.
  const delimiter = `cirvix_${Math.random().toString(36).slice(2)}_${Date.now().toString(36)}`;
  await appendFile(
    process.env.GITHUB_OUTPUT,
    `${name}<<${delimiter}\n${value}\n${delimiter}\n`,
    "utf8",
  );
}

function escapeData(value) {
  return String(value).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
}

function escapeProperty(value) {
  return escapeData(value).replace(/:/g, "%3A").replace(/,/g, "%2C");
}

function escapeCell(value) {
  return String(value).replace(/\|/g, "\\|").replace(/\n/g, " ");
}
