// Ordered, checksum-guarded schema migrations for @hasna/tenants (cloud Postgres).
//
// The set is: the canonical @hasna/contracts api_keys table, then the additive
// tenancy/IdP layer (tenants, users, service_principals, memberships, sessions,
// auth_challenges, jwt_signing_keys + api_keys bridge columns).
//
// There is deliberately NO identity_store / identity_audit here — that JSONB
// document store belongs to @hasna/identities (the agent registry), a separate
// package. @hasna/tenants owns only the tenancy/IdP schema.

import { defineMigration, type Migration } from "./generated/storage-kit/index.js";
import { apiKeyMigrations } from "@hasna/contracts/auth";
import { idpMigrations } from "./idp/migrations.js";

export const API_KEYS_TABLE = "api_keys";

export function tenantsMigrations(): Migration[] {
  return [
    ...apiKeyMigrations(API_KEYS_TABLE).map((m) => defineMigration(m.id, m.sql)),
    ...idpMigrations(API_KEYS_TABLE),
  ];
}
