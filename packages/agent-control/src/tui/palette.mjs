/**
 * Command palette — `/` shows everything. No memorized single letters.
 *
 * Each entry: { name, hint, run }. Filtering is prefix + substring so
 * `/pol` matches `/policies`, `/policy test`, `/policy explain`.
 */

export const COMMANDS = [
  { name: "/audit", hint: "View security audit", run: "audit" },
  { name: "/policies", hint: "Inspect policies", run: "policies" },
  { name: "/policy test", hint: "Run policy test cases", run: "policy-test" },
  { name: "/policy explain", hint: "Why would this call be decided that way", run: "policy-explain" },
  { name: "/logs", hint: "View runtime logs", run: "logs" },
  { name: "/sessions", hint: "Manage sessions", run: "sessions" },
  { name: "/approvals", hint: "Calls waiting on a human", run: "approvals" },
  { name: "/theme", hint: "Change appearance (dark/light/midnight/high-contrast)", run: "theme" },
  { name: "/config", hint: "Configure Cirvix", run: "config" },
  { name: "/doctor", hint: "Diagnose runtime", run: "doctor" },
  { name: "/demo", hint: "Run the live interception demo", run: "demo" },
  { name: "/expand", hint: "Expand activity feed", run: "expand" },
  { name: "/collapse", hint: "Collapse activity feed", run: "collapse" },
  { name: "/clear", hint: "Clear the screen", run: "clear" },
  { name: "/help", hint: "Show commands", run: "help" },
  { name: "/quit", hint: "Leave the console", run: "quit" },
];

export function filterCommands(input) {
  const q = String(input ?? "").trim().toLowerCase();
  if (!q || q === "/") return COMMANDS;
  const needle = q.startsWith("/") ? q : `/${q}`;
  const bare = needle.slice(1);
  return COMMANDS.filter(
    (c) => c.name.toLowerCase().startsWith(needle) || c.name.toLowerCase().includes(bare),
  );
}

export function paletteBox(input) {
  const matches = filterCommands(input);
  const lines = [
    `╭─ Commands ─${"─".repeat(24)}╮`,
    `│ > ${(input ?? "").padEnd(32)} │`,
    `│${" ".repeat(36)}│`,
    ...matches.slice(0, 8).map((c) => `│  ${(c.name.padEnd(14))} ${c.hint.slice(0, 18).padEnd(18)} │`),
    ...(matches.length === 0 ? [`│  (no match)${" ".repeat(24)} │`] : []),
    `╰${"─".repeat(36)}╯`,
  ];
  return lines.join("\n");
}
