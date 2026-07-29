#!/usr/bin/env bun
// Entry point for the `tenants-serve` binary.
//
//   tenants-serve [--port N] [--host H]   start the HTTP API
//   tenants-serve migrate [--dry-run]     apply schema migrations + seed
//   tenants-serve --version | --help

import { createTenantsDatabase, runTenantsMigrations } from "../db.js";
import { TENANTS_DATA_BACKEND } from "../storage.js";
import { getPackageVersion } from "../version.js";
import { startServer } from "./serve.js";
import { seedAndBackfill } from "../idp/backfill.js";
import { API_KEYS_TABLE } from "../migrations.js";

function argValue(name: string): string | undefined {
  const idx = process.argv.findIndex((a) => a === name || a.startsWith(`${name}=`));
  if (idx === -1) return undefined;
  const arg = process.argv[idx]!;
  if (arg.includes("=")) return arg.split("=").slice(1).join("=");
  return process.argv[idx + 1];
}

function printHelp(): void {
  console.log(`tenants-serve — @hasna/tenants HTTP API

Usage:
  tenants-serve [options]           Start the HTTP API
  tenants-serve migrate [--dry-run] Apply schema migrations + seed, then exit
  tenants-serve --version           Print the package version
  tenants-serve --help              Show this help

Options:
  --port <port>   Port to bind (default: $PORT or 15460)
  --host <host>   Host to bind (default: $HOST or 0.0.0.0)

Environment:
  HASNA_TENANTS_DATABASE_URL=postgres://...   Required — the PostgreSQL backend
  HASNA_TENANTS_API_SIGNING_KEY=<hmac>        Required (or HASNA_API_SIGNING_KEY)
  HASNA_TENANTS_ALLOWED_EMAIL_DOMAINS=<list>  Exact domains; unset denies all auth
  HASNA_TENANTS_DISABLE_EMAIL_ALLOWLIST=1     Explicit local/dev opt-out
  HASNA_TENANTS_REQUIRE_EMAIL_CONFIRMATION=0  Disable confirmation gate
  HASNA_TENANTS_EMAIL_ENABLED=1               Enable direct Amazon SES delivery
  HASNA_TENANTS_MAIL_FROM=<sender>            Required when email is enabled
  HASNA_TENANTS_CONFIRM_URL_BASE=<url>         Required when email is enabled
  HASNA_TENANTS_JWT_SIGNING_KEY=<private-jwk>  Optional JSON/base64url Ed25519 JWK

See docs/configuration.md for SES, AWS credentials, TLS, and developer settings.`);
}

async function migrate(): Promise<void> {
  const dryRun = process.argv.includes("--dry-run");
  const db = createTenantsDatabase({ applicationName: "tenants-migrate" });
  try {
    const result = await runTenantsMigrations(db.client, { dryRun });
    const appliedIds = new Set(result.applied.map((a) => a.id));
    const pending = result.plan
      .filter((p) => p.state === "pending" && !appliedIds.has(p.migration.id))
      .map((p) => p.migration.id);
    const justApplied = dryRun
      ? []
      : result.plan.filter((p) => p.state === "pending").map((p) => p.migration.id);

    // Seed tenants + ensure a signing key + stamp legacy keys (additive,
    // idempotent). Skipped on dry-run. This is the ONLY place the fixed
    // root-tenant UUID is written (never per-request).
    let backfill: unknown = { skipped: "dry-run" };
    if (!dryRun) {
      backfill = await seedAndBackfill(db.client, API_KEYS_TABLE);
    }

    console.log(
      JSON.stringify({
        dryRun,
        applied: result.applied.map((a) => a.id),
        justApplied,
        pending,
        backfill,
      }, null, 2),
    );
  } finally {
    await db.close();
  }
}

async function main(): Promise<void> {
  if (process.argv.includes("--version") || process.argv.includes("-V")) {
    console.log(getPackageVersion());
    return;
  }
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    printHelp();
    return;
  }
  if (process.argv[2] === "migrate") {
    await migrate();
    return;
  }

  const portArg = argValue("--port");
  const server = await startServer({
    ...(portArg ? { port: Number(portArg) } : {}),
    ...(argValue("--host") ? { host: argValue("--host")! } : {}),
    audit: (e) => {
      try {
        console.log(JSON.stringify({ log: "api_auth", ...(e as object) }));
      } catch {
        // never break the request path on a logging failure
      }
    },
  });
  console.log(
    `tenants-serve listening on http://${server.hostname}:${server.port} (backend=${TENANTS_DATA_BACKEND})`,
  );
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
