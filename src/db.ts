// PostgreSQL client provider for @hasna/tenants.
//
// Every read/write hits the server's PostgreSQL database directly through the
// vendored storage kit. Unlike the agent-identity registry, there is NO JSONB
// document store and NO IdentityStore here — the tenancy tables are the source of
// truth and are accessed via the IdpStore (src/idp/store.ts) on top of the raw
// TypedQueryClient this module hands out.
//
// One backend, no deployment modes. The pool is built from the kit's mode-free
// primitives (createPgPool + createQueryClient) and the target is resolved by
// src/storage.ts; see that file for why the kit's mode-resolving pool factory is
// deliberately not used.

import {
  MigrationLedger,
  checkHealth,
  checkReady,
  createPgPool,
  createQueryClient,
  type HealthResult,
  type PoolQueryClient,
  type ReadyResult,
  type TypedQueryClient,
} from "./generated/storage-kit/index.js";
import { tenantsMigrations } from "./migrations.js";
import { resolveTenantsDatabase, type Env } from "./storage.js";

/** App name this package reports to PostgreSQL and uses to build its env keys. */
export const TENANTS_APP_NAME = "tenants";

export interface TenantsDatabase {
  client: PoolQueryClient;
  /** Env key the connection string came from — never the value. */
  connectionSource: string;
  close: () => Promise<void>;
}

export interface CreateTenantsDatabaseOptions {
  applicationName?: string;
  /** Environment to read (tests). Defaults to `process.env`. */
  env?: Env;
}

/**
 * Build a PostgreSQL client from the environment.
 *
 * Reads `HASNA_TENANTS_DATABASE_URL`. Throws when the connection string is
 * missing, and throws naming the fix when a retired deployment-mode variable
 * (`HASNA_TENANTS_STORAGE_MODE`) is still set.
 */
export function createTenantsDatabase(
  options: CreateTenantsDatabaseOptions = {},
): TenantsDatabase {
  const env = options.env ?? (process.env as Env);
  const target = resolveTenantsDatabase(env);
  const pool = createPgPool({
    connectionString: target.connectionString,
    env,
    applicationName: options.applicationName ?? "tenants-serve",
  });
  const client = createQueryClient(pool);
  return {
    client,
    connectionSource: target.connectionSource,
    close: async () => {
      await client.close();
    },
  };
}

/** Apply all pending schema migrations (api_keys + tenancy/IdP layer). */
export async function runTenantsMigrations(
  client: TypedQueryClient,
  opts: { dryRun?: boolean } = {},
) {
  const ledger = new MigrationLedger(client, tenantsMigrations());
  return ledger.migrate(opts);
}

export async function databaseHealth(client: TypedQueryClient): Promise<HealthResult> {
  return checkHealth(client);
}

export async function databaseReady(client: TypedQueryClient): Promise<ReadyResult> {
  return checkReady(client, tenantsMigrations());
}
