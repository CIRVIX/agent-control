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

export function paletteBox(input, { width = process.stdout.columns ?? 80, selected = 0 } = {}) {
  const matches = filterCommands(input);
  const size = Math.max(1, Math.min(76, Math.floor(width)));
  const inner = Math.max(0, size - 4);
  const fit = (text, limit = inner) => Array.from(String(text).replace(/[\x00-\x1f\x7f]/g, " ")).slice(0, limit).join("");
  const row = (text) => size < 4 ? fit(text, size) : `│ ${fit(text).padEnd(inner)} │`;
  const start = Math.max(0, selected - 7);
  const rows = [
    "Commands",
    `> ${input ?? ""}`,
    ...matches.slice(start, start + 8).map((c, i) => `${start + i === selected ? ">" : " "} ${c.name.padEnd(16)} ${c.hint}`),
    ...(matches.length ? [] : ["(no match)"]),
    "↑↓ select · Enter run · Esc close",
  ];
  if (size < 4) return rows.map(row).join("\n");
  return [`╭${"─".repeat(size - 2)}╮`, ...rows.map(row), `╰${"─".repeat(size - 2)}╯`].join("\n");
}
