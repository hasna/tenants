// Data-backend resolution for @hasna/tenants.
//
// There are NO deployment modes here. `tenants-serve` has exactly ONE server
// data backend — PostgreSQL — selected by the presence of a connection string in
// HASNA_TENANTS_DATABASE_URL. Nothing in this package branches on where the
// process runs or who operates it.
//
// WHY THIS FILE EXISTS instead of a call to the vendored kit's
// `createCloudPoolFromEnv`: that entry point resolves a storage MODE
// (`local | cloud`, with `remote`, `hybrid` and `self_hosted` accepted as
// aliases) and refuses to start unless the answer is `cloud`. Two defects follow
// from that, and both are the reason the mode axis is gone:
//
//   1. An UNSET mode resolves to `local` — a backend this service has never
//      implemented — so a missing connection string surfaces as "storage mode is
//      not 'cloud'" instead of "set HASNA_TENANTS_DATABASE_URL".
//   2. `self_hosted`, `self-hosted`, `remote` and `hybrid` are rewritten to
//      `cloud` WITHOUT ERROR. Silent normalization is the actual defect; the
//      vocabulary was only its symptom. A stale deployment keeps booting and the
//      retired words survive another release.
//
// So the retired variable is REFUSED here, loudly, naming the replacement
// variable and the one-line fix — rather than normalized, warned about, or
// ignored.
//
// The kit under src/generated/storage-kit is @generated and sha256-pinned (see
// .storage-kit-manifest.json; CI verifies it with `contracts vendor-kit --check`),
// so it is not edited. This package simply stops consuming its mode surface and
// builds the pool from the kit's mode-free primitives.

/** The one server data backend. There is no second value and no switch. */
export const TENANTS_DATA_BACKEND = "postgresql" as const;
export type TenantsDataBackend = typeof TENANTS_DATA_BACKEND;

/**
 * Env keys that used to select a deployment mode. Setting any of them is now an
 * error: they no longer select anything, and honouring them would keep the
 * three-way concept alive in operator configuration.
 */
export const RETIRED_MODE_ENV_KEYS = [
  "HASNA_TENANTS_STORAGE_MODE",
  "TENANTS_STORAGE_MODE",
] as const;

/**
 * Values the retired variable used to accept, including the aliases the kit
 * normalized silently. Recognizing them lets the error name what the operator
 * set without echoing an arbitrary (possibly sensitive) env value.
 */
export const RETIRED_MODE_VALUES = [
  "local",
  "cloud",
  "self_hosted",
  "self-hosted",
  "selfhosted",
  "remote",
  "hybrid",
] as const;

/** Canonical connection-string key first; the unprefixed alias is still read. */
export const DATABASE_URL_ENV_KEYS = [
  "HASNA_TENANTS_DATABASE_URL",
  "TENANTS_DATABASE_URL",
] as const;

export type Env = Record<string, string | undefined>;

function firstSet(env: Env, keys: readonly string[]): { key: string; value: string } | null {
  for (const key of keys) {
    const value = env[key]?.trim();
    if (value) return { key, value };
  }
  return null;
}

/**
 * Refuse a retired deployment-mode variable instead of normalizing it.
 *
 * Throws when `HASNA_TENANTS_STORAGE_MODE` (or the `TENANTS_STORAGE_MODE` alias)
 * is set to anything, naming the replacement variable and the fix. Returns
 * silently when neither is set — which is now the only correct configuration.
 *
 * The env VALUE is never echoed unless it is one of the known retired mode words,
 * so a misconfigured variable cannot leak a connection string into a log line.
 */
export function assertNoDeploymentModeEnv(env: Env = process.env): void {
  const hit = firstSet(env, RETIRED_MODE_ENV_KEYS);
  if (!hit) return;

  const value = hit.value.toLowerCase();
  const recognized = (RETIRED_MODE_VALUES as readonly string[]).includes(value);
  const setTo = recognized ? ` (set to '${value}')` : "";

  throw new Error(
    `${hit.key} is removed${setTo}: @hasna/tenants has no deployment modes. ` +
      `The server data backend is ${TENANTS_DATA_BACKEND}, selected by ` +
      `${DATABASE_URL_ENV_KEYS[0]}. Fix: unset ${hit.key} and set ` +
      `${DATABASE_URL_ENV_KEYS[0]}=postgres://…`,
  );
}

export interface TenantsDatabaseTarget {
  backend: TenantsDataBackend;
  /** The PostgreSQL connection string. Never log this. */
  connectionString: string;
  /** Env key the connection string came from — safe to log, unlike the value. */
  connectionSource: string;
}

/**
 * Resolve the server's PostgreSQL target from the environment.
 *
 * Order matters: a retired mode variable is refused BEFORE the connection string
 * is looked at, so an operator carrying stale config gets the mode error (which
 * tells them what to delete) rather than a downstream connection error.
 */
export function resolveTenantsDatabase(env: Env = process.env): TenantsDatabaseTarget {
  assertNoDeploymentModeEnv(env);

  const hit = firstSet(env, DATABASE_URL_ENV_KEYS);
  if (!hit) {
    throw new Error(
      `@hasna/tenants needs a ${TENANTS_DATA_BACKEND} connection string. Set ` +
        `${DATABASE_URL_ENV_KEYS[0]}=postgres://… (the alias ` +
        `${DATABASE_URL_ENV_KEYS[1]} is also read).`,
    );
  }

  return {
    backend: TENANTS_DATA_BACKEND,
    connectionString: hit.value,
    connectionSource: hit.key,
  };
}
