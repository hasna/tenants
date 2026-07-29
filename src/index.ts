// Public library surface of @hasna/tenants — the Hasna fleet tenant-auth / IdP.
//
// This is DISTINCT from @hasna/identities (the agent-identity registry). Here you
// get: tenants / users / memberships / service principals, sessions + OTP login,
// EdDSA fleet-token issuance with a published JWKS, the email login front door,
// the database client + migrations, and the HTTP serve/handler + OpenAPI document.

// ── IdP domain ────────────────────────────────────────────────────────────────
export * from "./idp/service.js";
export * from "./idp/store.js";
export * from "./idp/tokens.js";
export * from "./idp/ids.js";
export * from "./idp/passwords.js";
export * from "./idp/policy.js";
export * from "./idp/mailer.js";
export * from "./idp/backfill.js";
export * from "./idp/migrations.js";

// ── Persistence / migrations ───────────────────────────────────────────────────
export { API_KEYS_TABLE, tenantsMigrations } from "./migrations.js";
export {
  TENANTS_APP_NAME,
  createTenantsDatabase,
  runTenantsMigrations,
  databaseHealth,
  databaseReady,
} from "./db.js";
export type { TenantsDatabase, CreateTenantsDatabaseOptions } from "./db.js";
export {
  TENANTS_DATA_BACKEND,
  DATABASE_URL_ENV_KEYS,
  RETIRED_MODE_ENV_KEYS,
  RETIRED_MODE_VALUES,
  assertNoDeploymentModeEnv,
  resolveTenantsDatabase,
} from "./storage.js";
export type { TenantsDataBackend, TenantsDatabaseTarget } from "./storage.js";
export type { TypedQueryClient, PoolQueryClient } from "./generated/storage-kit/index.js";

// ── HTTP surface ────────────────────────────────────────────────────────────────
export { buildOpenApiDocument } from "./server/openapi.js";
export type { TenantsOpenApiDocument } from "./server/openapi.js";
export {
  TENANTS_SERVE_APP,
  buildHandler,
  createFetchHandler,
  startServer,
} from "./server/serve.js";
export type { ServeOptions, RunningServer } from "./server/serve.js";

// ── Misc ────────────────────────────────────────────────────────────────────────
export { getPackageVersion } from "./version.js";
