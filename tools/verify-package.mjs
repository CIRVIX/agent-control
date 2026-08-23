#!/usr/bin/env node
/** Pack the Node package and exercise the tarball in a fresh npm project. */
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const packageDir = join(root, "packages", "agent-control");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";

// Node >= 18.20 refuses to spawn .cmd/.bat shims without a shell (CVE-2024-27980).
// When we must go through the shell, quote every argument ourselves: with
// shell:true, Node joins argv verbatim, so unquoted paths with spaces break.
function needsShell(command) {
  return process.platform === "win32" && /\.(cmd|bat)$/i.test(command);
}
function quoteArg(arg) {
  return /[\s"^&|<>]/.test(arg) ? `"${arg.replace(/"/g, '\\"')}"` : arg;
}
function run(command, args, cwd, expected = 0) {
  const useShell = needsShell(command);
  const finalCommand = useShell ? command : command;
  const finalArgs = useShell ? [] : args;
  const options = {
    cwd,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
    ...(useShell ? { shell: true } : {}),
  };
  const commandLine = useShell ? [command, ...args].map(quoteArg).join(" ") : undefined;
  return new Promise((resolve, reject) => {
    const child = useShell
      ? spawn(commandLine, options)
      : spawn(finalCommand, finalArgs, options);
    let stdout = ""; let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code) => code === expected ? resolve(stdout) : reject(new Error(`${command} ${args.join(" ")} exited ${code}, expected ${expected}\n${stderr}`)));
  });
}

const temp = await mkdtemp(join(tmpdir(), "cirvix-package-"));
try {
  const packJson = JSON.parse(await run(npm, ["pack", "--ignore-scripts", "--json", "--pack-destination", temp], packageDir));
  const tarball = packJson[0]?.filename;
  if (!tarball) throw new Error("npm pack returned no tarball");
  const archive = join(temp, tarball);
  const manifest = JSON.parse(await readFile(join(packageDir, "package.json"), "utf8"));
  await run(npm, ["init", "-y"], temp);
  await run(npm, ["install", "--ignore-scripts", "--no-audit", "--no-fund", archive], temp);
  const binName = process.platform === "win32" ? "cirvix.cmd" : "cirvix";
  const cli = join(temp, "node_modules", ".bin", binName);
  const version = (await run(cli, ["--version"], temp)).trim();
  if (version !== manifest.version) throw new Error(`installed CLI reported ${version}, package is ${manifest.version}`);
  await run(cli, ["init", "--cwd", temp], temp);
  await run(cli, ["policy", "check", "--cwd", temp], temp);
  await run(cli, ["check", "--action", "fs.read", "--resource", ".env.production", "--cwd", temp], temp, 1);
  await run(cli, ["check", "--action", "fs.read", "--resource", "src/index.mjs", "--cwd", temp], temp, 0);
  const smoke = join(temp, "smoke.mjs");
  await writeFile(smoke, "import { guard, STARTER_RULES } from '@cirvix/agent-control';\nconst t = guard.wrap({ read_file: async () => 'ok' }, { rules: STARTER_RULES });\nawait t.read_file({ path: 'src/index.mjs' });\nconsole.log('first decision ok');\n", "utf8");
  await run(process.execPath, [smoke], temp);
  console.log(`package verification passed: ${tarball}, version ${version}`);
} finally {
  await rm(temp, { recursive: true, force: true });
}
