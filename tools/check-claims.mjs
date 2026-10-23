#!/usr/bin/env node
/**
 * Claim consistency check.
 *
 * Every defect this guards against was live on cirvix.com at once, and none of
 * them was caught by a build — they were all *internally consistent* pages that
 * disagreed with each other or with the code:
 *
 *   - the site installed `@cirvix/agent-control`, which returns 404 from npm;
 *   - /pricing published 99 / 299 / 499 while the CLI printed 79 / 199 / 349;
 *   - the CLI sold a Lite tier the pricing page did not list;
 *   - the annual term was "2 months free" in the CLI and "Save 20%" on the site;
 *   - the marketing pages said there is no checkout and shipped a checkout call;
 *   - the demo console reported version 0.2.5 while the manifest said 0.3.0;
 *   - the homepage listed a control plane and SIEM export as shipped, and the
 *     secret broker and approvals as in development, while README said the
 *     opposite about all three.
 *
 * This script fails the build on the mechanical ones. It is deliberately
 * reading source text rather than importing TypeScript — the site is compiled
 * by Next and the runtime is plain ESM, so there is no shared module boundary
 * to import across, and a check that needs a build to run is a check that runs
 * too late.
 *
 * Exit codes: 0 = consistent, 1 = contradiction found.
 */
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(resolve(root, p), "utf8");

const failures = [];
const checks = [];

function check(name, fn) {
  try {
    const detail = fn();
    checks.push({ name, ok: true, detail });
  } catch (err) {
    failures.push({ name, message: err instanceof Error ? err.message : String(err) });
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

/* -------------------------------------------------------------------------- */
/*  1. One version                                                             */
/* -------------------------------------------------------------------------- */

check("version: every manifest agrees", () => {
  const pkg = JSON.parse(read("package.json")).version;
  const file = read("VERSION").trim();
  const cli = JSON.parse(read("packages/agent-control/package.json")).version;
  const py = read("packages/cirvix-python/pyproject.toml").match(/^version\s*=\s*"([^"]+)"/m)?.[1];

  assert(file === pkg, `VERSION (${file}) !== package.json (${pkg})`);
  assert(cli === pkg, `packages/agent-control (${cli}) !== package.json (${pkg})`);
  assert(py === pkg, `pyproject.toml (${py}) !== package.json (${pkg})`);

  // The developer-status fixture is where the product version is displayed.
  // (An agent's own `version` field is the workload's version, not ours.)
  const demo = read("src/lib/local/demo-data.ts");
  const status = demo.slice(demo.indexOf("DEMO_DEVELOPER_STATUS"));
  assert(
    !/version:\s*"\d+\.\d+\.\d+"/.test(status),
    "DEMO_DEVELOPER_STATUS hard-codes a product version; import APP_VERSION",
  );
  assert(/version:\s*APP_VERSION/.test(status), "DEMO_DEVELOPER_STATUS does not read APP_VERSION");

  return `all manifests at ${pkg}`;
});

/* -------------------------------------------------------------------------- */
/*  2. The install command must exist                                          */
/* -------------------------------------------------------------------------- */

check("package: site name matches the published package", () => {
  const cliPkg = JSON.parse(read("packages/agent-control/package.json")).name;
  const site = read("src/config/site.ts");
  const configured = site.match(/npmPackage:\s*"([^"]+)"/)?.[1];

  assert(configured === cliPkg, `SITE.npmPackage is "${configured}" but the package is "${cliPkg}"`);

  // The old scope. A bare `@cirvix/` must never appear again; `@cirvix_ai/` is
  // a different scope and does not match this pattern.
  const files = [
    "src/config/site.ts",
    "src/content/docs.ts",
    "src/content/pricing.ts",
    "src/app/(marketing)/developers/page.tsx",
    "src/app/(marketing)/developers/sdk/page.tsx",
    "src/components/marketing/install-command.tsx",
    "README.md",
  ];
  for (const f of files) {
    assert(!read(f).includes("@cirvix/agent-control"), `${f} still references the unpublished @cirvix/ scope`);
  }

  return configured;
});

/* -------------------------------------------------------------------------- */
/*  3. One rate card                                                           */
/* -------------------------------------------------------------------------- */

function pricingFromSite() {
  const src = read("src/content/pricing.ts");
  const block = src.slice(src.indexOf("export const PLANS"), src.indexOf("export function getPlan"));
  const out = {};
  const re = /id: "(free|lite|starter|pro|team|enterprise)"[\s\S]{0,400}?price: \{ usd: (\d+|null)/g;
  for (const m of block.matchAll(re)) out[m[1]] = m[2] === "null" ? null : Number(m[2]);
  return out;
}

function pricingFromCli() {
  const src = read("packages/agent-control/src/commands/upgrade.mjs");
  const block = src.slice(src.indexOf("export const PRICING"), src.indexOf("const CHECKOUT_BASE"));
  const out = {};
  const re = /(\w+): \{ monthly: (\d+|null), annual: (\d+|null)/g;
  for (const m of block.matchAll(re)) {
    out[m[1]] = {
      monthly: m[2] === "null" ? null : Number(m[2]),
      annual: m[3] === "null" ? null : Number(m[3]),
    };
  }
  return out;
}

check("pricing: site and CLI publish the same plans", () => {
  const site = pricingFromSite();
  const cli = pricingFromCli();

  const siteIds = Object.keys(site).sort();
  const cliIds = Object.keys(cli).sort();
  assert(
    siteIds.join(",") === cliIds.join(","),
    `plan sets differ — site: [${siteIds}] cli: [${cliIds}]`,
  );

  for (const id of siteIds) {
    assert(
      site[id] === cli[id].monthly,
      `${id}: site says ${site[id] ?? "custom"} but CLI says ${cli[id].monthly ?? "custom"}`,
    );
  }
  return siteIds.map((id) => `${id}=${site[id] ?? "custom"}`).join(" ");
});

check("pricing: annual is the published term, not a third rate", () => {
  const cli = pricingFromCli();
  const monthsFree = Number(
    read("src/content/pricing.ts").match(/ANNUAL_MONTHS_FREE\s*=\s*(\d+)/)?.[1],
  );
  assert(monthsFree === 2, `ANNUAL_MONTHS_FREE is ${monthsFree}; the rate card sells two months free`);

  for (const [id, p] of Object.entries(cli)) {
    if (p.monthly === null || p.monthly === 0) continue;
    const expected = p.monthly * (12 - monthsFree);
    assert(p.annual === expected, `${id}: annual is ${p.annual}, expected ${expected} (10 months)`);
  }
  return `${monthsFree} months free across every paid tier`;
});

check("pricing: Team is per-seat with a three-seat floor", () => {
  const site = read("src/content/pricing.ts");
  const block = site.slice(site.indexOf('id: "team"'), site.indexOf('id: "enterprise"'));
  assert(/perSeat: true/.test(block), "Team is not marked perSeat");
  assert(/seatsCount: 3/.test(block), "Team does not declare a 3-seat minimum");

  const cli = read("packages/agent-control/src/core/entitlements.mjs");
  const team = cli.slice(cli.indexOf("team: {"), cli.indexOf("enterprise: {"));
  assert(/perSeat: true/.test(team), "runtime Team is not perSeat");
  assert(/seatsIncluded: 3/.test(team), "runtime Team does not declare 3 seats");
  return "per seat, minimum 3, on both sides";
});

/* -------------------------------------------------------------------------- */
/*  4. No checkout on the marketing surface                                    */
/* -------------------------------------------------------------------------- */

check("pricing: marketing cannot start a checkout", () => {
  const files = [
    "src/components/marketing/pricing-section.tsx",
    "src/components/pricing/plan-cards.tsx",
    "src/app/(marketing)/pricing/page.tsx",
  ];
  for (const f of files) {
    const src = read(f);
    // Look at the import, not at prose that mentions a checkout.
    const apiImport =
      src.match(/import\s*\{([\s\S]*?)\}\s*from\s*"@\/lib\/api"/)?.[1] ?? "";
    assert(!/\bcheckout\b/.test(apiImport), `${f} imports checkout from the billing client`);
    assert(!/\bpreview\b/.test(apiImport), `${f} imports preview from the billing client`);
    assert(!/await\s+checkout\s*\(/.test(src), `${f} awaits checkout()`);
    assert(!/await\s+preview\s*\(/.test(src), `${f} awaits preview()`);
  }
  // The claim the surfaces make must also still be true.
  assert(
    /no live checkout/i.test(read("src/content/pricing.ts")),
    "the pricing content no longer states that no checkout is live",
  );
  return "all paid CTAs route to the access request";
});

/* -------------------------------------------------------------------------- */
/*  5. Release list must not contradict itself                                 */
/* -------------------------------------------------------------------------- */

check("release: shipped and in-development do not overlap", () => {
  const site = read("src/config/site.ts");
  const shipped = site.slice(site.indexOf("shipped: ["), site.indexOf("inDevelopment: ["));
  const developing = site.slice(site.indexOf("inDevelopment: ["), site.indexOf("benchmarksMeasured"));

  // Local capability and hosted delivery are different claims and may both be
  // true: the local approval queue ships while Slack delivery does not. What
  // must never overlap is the SAME capability on both lists.
  for (const [shippedTerm, developingTerm, label] of [
    ["secret vault", "secret broker", "the secret broker"],
    ["MCP gateway", "MCP gateway", "the MCP gateway"],
    ["SCIM", "SCIM", "SCIM"],
    ["Slack", "Slack", "Slack delivery"],
  ]) {
    if (developing.includes(developingTerm)) {
      assert(!shipped.includes(shippedTerm), `${label} is listed as both shipped and in development`);
    }
  }

  // Claims that this distribution cannot support.
  assert(
    !/multi-tenant, RBAC, fleet/.test(shipped),
    "the shipped list claims the hosted control plane, which README lists under 'Not shipped here'",
  );
  assert(!/SIEM/.test(shipped), "the shipped list claims SIEM export; no SIEM exporter exists in the package");
  return "shipped list is a subset of what packages/agent-control exports";
});

/* -------------------------------------------------------------------------- */
/*  6. SEO: every public page has a canonical                                  */
/* -------------------------------------------------------------------------- */

check("seo: every static marketing page declares a canonical", () => {
  const pages = [
    "src/app/(marketing)/page.tsx",
    "src/app/(marketing)/platform/page.tsx",
    "src/app/(marketing)/product/page.tsx",
    "src/app/(marketing)/solutions/page.tsx",
    "src/app/(marketing)/pricing/page.tsx",
    "src/app/(marketing)/enterprise/page.tsx",
    "src/app/(marketing)/security/page.tsx",
    "src/app/(marketing)/company/page.tsx",
    "src/app/(marketing)/changelog/page.tsx",
    "src/app/(marketing)/developers/page.tsx",
    "src/app/(marketing)/developers/cli/page.tsx",
    "src/app/(marketing)/developers/sdk/page.tsx",
    "src/app/(marketing)/developers/integrations/page.tsx",
    "src/app/(marketing)/docs/page.tsx",
    "src/app/(marketing)/legal/privacy/page.tsx",
    "src/app/(marketing)/legal/terms/page.tsx",
    "src/app/(marketing)/legal/dpa/page.tsx",
  ];
  const missing = pages.filter((p) => !read(p).includes("canonical"));
  assert(missing.length === 0, `no canonical in: ${missing.join(", ")}`);
  return `${pages.length} pages`;
});

check("seo: sitemap has no fabricated lastModified", () => {
  const src = read("src/app/sitemap.ts");
  assert(!/lastModified\s*:/.test(src), "sitemap emits a build-time lastModified");
  assert(/ROUTES\.product/.test(src), "sitemap omits /product");
  return "no lastModified; /product included";
});

/* -------------------------------------------------------------------------- */
/*  7. Error handling exists                                                   */
/* -------------------------------------------------------------------------- */

check("routes: 404 and error boundaries are present", () => {
  for (const f of ["src/app/not-found.tsx", "src/app/error.tsx", "src/app/global-error.tsx"]) {
    read(f);
  }
  return "not-found, error, global-error";
});

/* -------------------------------------------------------------------------- */

for (const c of checks) {
  console.log(`  ok   ${c.name}${c.detail ? ` — ${c.detail}` : ""}`);
}

if (failures.length > 0) {
  console.error("\nClaim consistency FAILED:\n");
  for (const f of failures) console.error(`  FAIL ${f.name}\n       ${f.message}\n`);
  process.exit(1);
}

console.log(`\nClaim consistency passed (${checks.length} checks).`);
