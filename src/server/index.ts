#!/usr/bin/env bun
// Entry point for the `tenants-serve` binary.
//
//   tenants-serve [--port N] [--host H]   start the HTTP API (cloud mode)
//   tenants-serve migrate [--dry-run]     apply cloud schema migrations + seed
//   tenants-serve --version | --help

import { createCloudClient, runTenantsMigrations } from "../db.js";
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
  console.log(`tenants-serve — @hasna/tenants cloud HTTP API

Usage:
  tenants-serve [options]           Start the HTTP API (PURE REMOTE cloud mode)
  tenants-serve migrate [--dry-run] Apply cloud schema migrations + seed, then exit
  tenants-serve --version           Print the package version
  tenants-serve --help              Show this help

Options:
  --port <port>   Port to bind (default: $PORT or 15460)
  --host <host>   Host to bind (default: $HOST or 0.0.0.0)

Environment:
  HASNA_TENANTS_STORAGE_MODE=cloud        Required (PURE REMOTE)
  HASNA_TENANTS_DATABASE_URL=postgres://  Required in cloud mode
  HASNA_TENANTS_API_SIGNING_KEY=<hmac>    API-key signing secret (or HASNA_API_SIGNING_KEY)`);
}

async function migrate(): Promise<void> {
  const dryRun = process.argv.includes("--dry-run");
  const cloud = createCloudClient({ applicationName: "tenants-migrate" });
  try {
    const result = await runTenantsMigrations(cloud.client, { dryRun });
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
      backfill = await seedAndBackfill(cloud.client, API_KEYS_TABLE);
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
    await cloud.close();
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
  console.log(`tenants-serve listening on http://${server.hostname}:${server.port} (mode=cloud)`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
