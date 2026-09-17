/**
 * `cirvix login` — link this machine to a CIRVIX control plane.
 *
 * The control plane authenticates hosts with API keys (the dashboard's
 * API-keys section issues them). So login is: open the dashboard, create a
 * key, paste it here. The CLI verifies the key against `/v1/me` BEFORE storing
 * anything, so a typo never ends up on disk looking like a working login.
 *
 * Stored at ~/.cirvix/credentials.json — the user's home, never the workspace,
 * because workspaces get committed and a key must not.
 *
 * Non-interactive: `cirvix login --key cak_… [--url https://api.cirvix.com]`.
 * Piped stdin (`cat key | cirvix login`) works too. No animation anywhere in
 * this command — it is a form, not a show.
 */

import { mkdir, readFile, writeFile, chmod, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";

import { bold, dim, green, red, gray } from "../core/format.mjs";

/* Hard-exit helper for this command only. The verify call leaves undici's
   keep-alive socket winding down, and on Windows Node 24 that races the
   event-loop drain and prints a meaningless libuv assertion at exit. Waiting
   one drain tick then exiting keeps the goodbye clean without changing exit
   codes. */
const finish = (code) => {
  setTimeout(() => process.exit(code), 50);
};

export const DEFAULT_CONTROL_PLANE = "https://api.cirvix.com";
export const DASHBOARD_URL = "https://www.cirvix.com/account.html";

function credPath() {
  return join(homedir(), ".cirvix", "credentials.json");
}

export async function readCredentials() {
  try {
    return JSON.parse(await readFile(credPath(), "utf8"));
  } catch {
    return null;
  }
}

/** GET {url}/v1/me with the key. Resolves { ok, status, org } — never rejects.
 *
 *  node:https rather than fetch deliberately: undici's keep-alive teardown
 *  trips a libuv assertion on Windows at process exit (Node 24.14), printing a
 *  scary, meaningless "Assertion failed" after a successful login. One
 *  one-shot https request has nothing to wind down. */
async function verifyKey(url, apiKey) {
  const { get } = await import("node:https");
  const target = new URL(`${url.replace(/\/+$/, "")}/v1/me`);
  try {
    const body = await new Promise((resolve, reject) => {
      const req = get(
        { hostname: target.hostname, path: target.pathname, headers: { authorization: `Bearer ${apiKey}` }, timeout: 6000 },
        (res) => {
          let data = "";
          res.on("data", (c) => (data += c));
          res.on("end", () => resolve({ status: res.statusCode, text: data }));
        },
      );
      req.on("timeout", () => req.destroy(new Error("timeout")));
      req.on("error", reject);
    });
    const parsed = body.text ? JSON.parse(body.text) : {};
    return { ok: body.status >= 200 && body.status < 300, status: body.status, org: parsed?.org?.name ?? parsed?.org ?? null, error: parsed?.error ?? null };
  } catch (err) {
    const timedOut = String(err?.message ?? err) === "timeout";
    return { ok: false, status: timedOut ? null : 0, org: null, error: timedOut ? "unreachable" : String(err?.message ?? err) };
  }
}

async function store(url, apiKey) {
  const dir = join(homedir(), ".cirvix");
  await mkdir(dir, { recursive: true });
  const file = join(dir, "credentials.json");
  await writeFile(file, JSON.stringify({ controlPlaneUrl: url, apiKey, linkedAt: new Date().toISOString() }, null, 2) + "\n");
  try {
    await chmod(file, 0o600);
  } catch {
    /* Windows FAT-style filesystems may not support it — the file lives in the
       user's home profile, which already ACLs it to the account. */
  }
}

function prompt(question) {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

export async function login({ key = null, url = null, status = false, browser = false, json = false } = {}) {
  const origin = url ?? DEFAULT_CONTROL_PLANE;

  /* --status: report and leave. */
  if (status) {
    const creds = await readCredentials();
    if (json) {
      process.stdout.write(JSON.stringify({ linked: Boolean(creds), controlPlaneUrl: creds?.controlPlaneUrl ?? null }) + "\n");
      return 0;
    }
    if (creds) process.stdout.write(`  ${green("✓")} linked to ${bold(creds.controlPlaneUrl)}\n`);
    else process.stdout.write(`  ${dim("not linked — run")} ${bold("cirvix login")}\n`);
    return 0;
  }

  let apiKey = key;

  /* Browser flow: the terminal never sees a password. A short-lived flow id
     is created on the control plane; the browser (where the user signs in)
     claims it with a fresh org API key; the terminal polls once and stores
     exactly that key — the same credential `--key` would have delivered. */
  if (!apiKey && (browser || (process.stdin.isTTY && !process.env.CI))) {
    try {
      const flowRes = await fetch(`${origin.replace(/\/+$/, "")}/v1/cli/flow`, { method: "POST" });
      const flow = await flowRes.json().catch(() => ({}));
      if (!flow.flowId) throw new Error("the control plane did not offer browser sign-in");
      const pageUrl = `https://www.cirvix.com/cli-auth.html#flow=${flow.flowId}`;
      process.stderr.write(`\n  ${bold("Link this machine to CIRVIX.")}\n`);
      process.stderr.write(`  Opening your browser…\n  ${dim(pageUrl)}\n`);
      process.stderr.write(`  ${dim("Approve in the browser, or press Ctrl+C to cancel.")}\n\n`);
      const openCmd = process.platform === "win32" ? "start" : process.platform === "darwin" ? "open" : "xdg-open";
      const { spawn } = await import("node:child_process");
      const child = spawn(openCmd, [pageUrl], { shell: process.platform === "win32", stdio: "ignore" });
      child.on("error", () => process.stderr.write(`  ${dim("Could not open a browser automatically — visit the URL above.")}\n`));
      const deadline = Date.now() + flow.expiresIn * 1000;
      let linked = null;
      while (Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 3000));
        const poll = await fetch(`${origin.replace(/\/+$/, "")}/v1/cli/flow/${flow.flowId}`, { signal: AbortSignal.timeout(8000) });
        if (!poll.ok) continue;
        const body = await poll.json().catch(() => ({}));
        if (body.status === "ok" && body.apiKey) { linked = { apiKey: body.apiKey, orgName: body.orgName }; break; }
      }
      if (!linked) {
        process.stderr.write(`  ${red("Timed out waiting for approval.")}\n`);
        return 1;
      }
      await store(origin, linked.apiKey);
      process.stdout.write(`  ${green("✓ Linked to ")}${bold(origin)}${linked.orgName ? ` ${dim(`· ${linked.orgName}`)}` : ""}\n`);
      process.stdout.write(`  ${dim("Stored in ~/.cirvix/credentials.json. Run")} ${bold("cirvix doctor")} ${dim("any time.")}\n`);
      finish(0);
    } catch (err) {
      process.stderr.write(`  ${red("✗ Browser sign-in failed")} — ${err?.message ?? err}\n`);
      process.stderr.write(`  ${dim("Fall back to")} ${bold("cirvix login --key <api-key>")}\n`);
      finish(1);
    }
    return;
  }

  const interactive = !apiKey && process.stdin.isTTY;

  if (!apiKey && !interactive && !process.stdin.isTTY) {
    // Piped stdin: read whatever arrives, trimmed.
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    apiKey = chunks.join("").trim() || null;
  }

  if (!apiKey && interactive) {
    process.stderr.write(`\n  ${bold("Link this machine to CIRVIX.")}\n\n`);
    process.stderr.write(`  1. Open ${bold(DASHBOARD_URL)}\n`);
    process.stderr.write(`  2. Sign in → API keys → ${dim("Create key")}\n`);
    process.stderr.write(`  3. Paste the key here (input is hidden)\n\n`);
    apiKey = (await prompt("  API key: ") || "").trim();
  }

  if (!apiKey) {
    process.stderr.write(`  ${red("No key given. Run ")}cirvix login${red(" in a terminal, or pass --key.")}\n`);
    return 1;
  }

  const check = await verifyKey(origin, apiKey);
  if (!check.ok) {
    const reason =
      check.status === 401 || check.status === 403
        ? "the key was rejected (wrong or revoked)"
        : !check.status || check.status === 0
          ? `${origin} was unreachable`
          : `the control plane answered ${check.status}`;
    await new Promise((resolve) => setImmediate(resolve));
    if (json) process.stdout.write(JSON.stringify({ ok: false, error: reason }) + "\n");
    else process.stderr.write(`  ${red("✗ Login failed")} — ${reason}.\n  ${dim("Check the key, your connection, and the control-plane URL.")}\n`);
    finish(1);
  }

  await store(origin, apiKey);
  /* Node 24 on Windows can assert in libuv at exit when undici's keep-alive
     socket from the verify call is still winding down. One macrotask lets it
     close cleanly; without this, a successful login prints a scary
     "Assertion failed" that means nothing. */
  await new Promise((resolve) => setImmediate(resolve));
  if (json) {
    process.stdout.write(JSON.stringify({ ok: true, controlPlaneUrl: origin, org: check.org }) + "\n");
  } else {
    process.stdout.write(`  ${green("✓ Linked to ")}${bold(origin)}${check.org ? ` ${dim(`· ${check.org}`)}` : ""}\n`);
    process.stdout.write(`  ${dim("Stored in ~/.cirvix/credentials.json. Run")} ${bold("cirvix doctor")} ${dim("any time.")}\n`);
  }
  finish(0);
}

/** `cirvix logout` — remove the stored key. Local file only; the server-side
 *  key keeps working until revoked in the dashboard, and the message says so. */
export async function logout({ json = false } = {}) {
  const creds = await readCredentials();
  if (!creds) {
    /* Leftover empty file (an interrupted logout, say) is tidied too, so the
       next doctor pass does not flag our own residue as a broken install. */
    await rm(credPath(), { force: true });
    if (json) process.stdout.write(JSON.stringify({ ok: true, wasLinked: false }) + "\n");
    else process.stdout.write(`  ${dim("not linked")}\n`);
    return 0;
  }
  await rm(credPath(), { force: true });
  if (json) process.stdout.write(JSON.stringify({ ok: true, wasLinked: true }) + "\n");
  else process.stdout.write(`  ${green("✓")} Unlinked this machine. ${dim("The key itself is still valid — revoke it in the dashboard if you want it dead.")}\n`);
  return 0;
}
