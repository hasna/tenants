// Idempotent bootstrap for a fresh @hasna/tenants database.
//
// Runs in the one-shot `tenants-serve migrate` task (never on web boot). It:
//   1) seeds the root tenant + brand children (fixed UUIDs),
//   2) ensures an active EdDSA signing key exists so JWKS is live immediately,
//   3) stamps any legacy api_keys row with the root tenant (single-tenant compat),
//   4) grandfathers pre-existing enrollment users as email-confirmed so the
//      confirmation gate never locks out already-provisioned principals.
//
// It is additive + safe to re-run. Unlike the agent-identity registry, this does
// NOT read any identity_store JSONB document — @hasna/tenants owns only the
// tenancy tables and has no coupling to the agent registry's store.

import type { TypedQueryClient } from "../generated/storage-kit/index.js";
import { IdpStore } from "./store.js";
import { ROOT_TENANT_ID } from "./ids.js";
import { USERS_TABLE } from "./migrations.js";

export interface BackfillResult {
  tenantsSeeded: number;
  apiKeysBackfilled: number;
  usersGrandfatheredVerified: number;
}

/**
 * Seed tenants + ensure a signing key + stamp legacy api_keys to the root tenant.
 * @param client       live cloud Postgres client
 * @param apiKeysTable the api_keys table name (from @hasna/contracts auth kit)
 */
export async function seedAndBackfill(
  client: TypedQueryClient,
  apiKeysTable: string,
): Promise<BackfillResult> {
  const store = new IdpStore(client);

  // 1) Seed tenants (root + brand children) — fixed UUIDs, idempotent.
  await store.seedTenants();

  // 2) Ensure a signing key exists so JWKS is live right after migrate.
  await store.getOrCreateActiveDbKey();

  // 3) Stamp legacy api_keys with the root tenant (single-tenant compat).
  //    A bounded UPDATE of only NULL rows; a no-op on a fresh database.
  await client.execute(
    `UPDATE ${apiKeysTable} SET tenant_id = $1 WHERE tenant_id IS NULL`,
    [ROOT_TENANT_ID],
  );
  const counted = await client.get<{ n: string }>(
    `SELECT count(*)::text AS n FROM ${apiKeysTable} WHERE tenant_id = $1`,
    [ROOT_TENANT_ID],
  );

  // 4) Grandfather pre-existing FLEET users (auth_method='enrollment') as
  //    email-confirmed. Interactive signups ('password'/'otp') are NEVER
  //    auto-verified here, so a fresh unconfirmed signup stays unconfirmed.
  const grandfathered = await client.get<{ n: string }>(
    `WITH upd AS (
       UPDATE ${USERS_TABLE} SET email_verified_at = now(), updated_at = now()
         WHERE email_verified_at IS NULL AND auth_method = 'enrollment'
       RETURNING 1
     ) SELECT count(*)::text AS n FROM upd`,
  );

  return {
    tenantsSeeded: 4,
    apiKeysBackfilled: counted ? Number(counted.n) : 0,
    usersGrandfatheredVerified: grandfathered ? Number(grandfathered.n) : 0,
  };
}
