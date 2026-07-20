// Cloud (Postgres) client provider for @hasna/tenants.
//
// PURE REMOTE: every read/write hits the shared cloud Postgres directly through
// the vendored storage kit. Unlike the agent-identity registry, there is NO
// JSONB document store and NO IdentityStore here — the tenancy tables are the
// source of truth and are accessed via the IdpStore (src/idp/store.ts) on top of
// the raw TypedQueryClient this module hands out.

import {
  MigrationLedger,
  checkHealth,
  checkReady,
  createCloudPoolFromEnv,
  type HealthResult,
  type PoolQueryClient,
  type ReadyResult,
  type TypedQueryClient,
} from "./generated/storage-kit/index.js";
import { tenantsMigrations } from "./migrations.js";

/** App name used to resolve env keys: HASNA_TENANTS_STORAGE_MODE / _DATABASE_URL. */
export const TENANTS_APP_NAME = "tenants";

export interface TenantsCloud {
  client: PoolQueryClient;
  connectionSource: string;
  close: () => Promise<void>;
}

/**
 * Build a cloud Postgres client from the environment. Throws when storage mode
 * is not `cloud` or the database URL is missing (see the storage-kit contract).
 * Reads `HASNA_TENANTS_STORAGE_MODE=cloud` + `HASNA_TENANTS_DATABASE_URL`.
 */
export function createCloudClient(options: { applicationName?: string } = {}): TenantsCloud {
  const { client, connectionSource } = createCloudPoolFromEnv(TENANTS_APP_NAME, {
    applicationName: options.applicationName ?? "tenants-serve",
  });
  return {
    client,
    connectionSource,
    close: async () => {
      await client.close();
    },
  };
}

/** Apply all pending cloud migrations (api_keys + tenancy/IdP layer). */
export async function runTenantsMigrations(
  client: TypedQueryClient,
  opts: { dryRun?: boolean } = {},
) {
  const ledger = new MigrationLedger(client, tenantsMigrations());
  return ledger.migrate(opts);
}

export async function cloudHealth(client: TypedQueryClient): Promise<HealthResult> {
  return checkHealth(client);
}

export async function cloudReady(client: TypedQueryClient): Promise<ReadyResult> {
  return checkReady(client, tenantsMigrations());
}
