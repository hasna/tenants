// Tenancy / IdP schema for @hasna/tenants (the fleet tenant-auth authority).
//
// This is the SOLE schema for the tenants service: tenants, users, service
// principals, memberships, sessions, auth challenges (OTP), and the EdDSA
// signing-key set. It also gains tenant/user bridge columns on the api_keys
// table owned by the canonical @hasna/contracts auth kit.
//
// NOTE: this package is DISTINCT from @hasna/identities (the agent-identity
// registry). There is no identity_store / identity_audit JSONB document here —
// those belong to the agent registry and were intentionally left out.

import { defineMigration, type Migration } from "../generated/storage-kit/index.js";

export const TENANTS_TABLE = "tenants";
export const USERS_TABLE = "users";
export const SERVICE_PRINCIPALS_TABLE = "service_principals";
export const MEMBERSHIPS_TABLE = "memberships";
export const SESSIONS_TABLE = "sessions";
export const AUTH_CHALLENGES_TABLE = "auth_challenges";
export const JWT_SIGNING_KEYS_TABLE = "jwt_signing_keys";

/** Ordered, additive tenancy/IdP migrations. */
export function idpMigrations(apiKeysTable: string): Migration[] {
  return [
    defineMigration(
      "tenants_0001_tenants",
      `CREATE TABLE IF NOT EXISTS ${TENANTS_TABLE} (
         id          UUID PRIMARY KEY,
         slug        TEXT UNIQUE NOT NULL,
         name        TEXT NOT NULL,
         kind        TEXT NOT NULL DEFAULT 'org',
         parent_id   UUID REFERENCES ${TENANTS_TABLE}(id),
         status      TEXT NOT NULL DEFAULT 'active',
         identity_id TEXT,
         metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
         created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
         updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
       )`,
    ),
    defineMigration(
      "tenants_0002_users",
      `CREATE TABLE IF NOT EXISTS ${USERS_TABLE} (
         id            UUID PRIMARY KEY,
         kind          TEXT NOT NULL,
         email         TEXT UNIQUE,
         display_name  TEXT,
         identity_id   TEXT,
         home_tenant_id UUID REFERENCES ${TENANTS_TABLE}(id),
         auth_method   TEXT,
         password_hash TEXT,
         status        TEXT NOT NULL DEFAULT 'active',
         metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
         created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
         updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
         email_verified_at TIMESTAMPTZ
       )`,
    ),
    defineMigration(
      "tenants_0003_service_principals",
      `CREATE TABLE IF NOT EXISTS ${SERVICE_PRINCIPALS_TABLE} (
         id            UUID PRIMARY KEY,
         tenant_id     UUID NOT NULL REFERENCES ${TENANTS_TABLE}(id),
         kind          TEXT NOT NULL DEFAULT 'machine',
         display_name  TEXT,
         identity_id   TEXT,
         enrollment_secret_ref TEXT,
         status        TEXT NOT NULL DEFAULT 'active',
         metadata      JSONB NOT NULL DEFAULT '{}'::jsonb,
         created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
         last_seen_at  TIMESTAMPTZ
       )`,
    ),
    defineMigration(
      "tenants_0004_memberships",
      `CREATE TABLE IF NOT EXISTS ${MEMBERSHIPS_TABLE} (
         id             BIGSERIAL PRIMARY KEY,
         tenant_id      UUID NOT NULL REFERENCES ${TENANTS_TABLE}(id),
         principal_id   UUID NOT NULL,
         principal_type TEXT NOT NULL,
         role           TEXT NOT NULL,
         scopes         JSONB NOT NULL DEFAULT '[]'::jsonb,
         status         TEXT NOT NULL DEFAULT 'active',
         created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
         UNIQUE (tenant_id, principal_id, principal_type)
       )`,
    ),
    defineMigration(
      "tenants_0005_sessions",
      `CREATE TABLE IF NOT EXISTS ${SESSIONS_TABLE} (
         id         UUID PRIMARY KEY,
         user_id    UUID REFERENCES ${USERS_TABLE}(id),
         tenant_id  UUID REFERENCES ${TENANTS_TABLE}(id),
         token_hash TEXT UNIQUE NOT NULL,
         method     TEXT,
         issued_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
         expires_at TIMESTAMPTZ,
         revoked_at TIMESTAMPTZ,
         ip         TEXT,
         user_agent TEXT
       )`,
    ),
    defineMigration(
      "tenants_0006_auth_challenges",
      `CREATE TABLE IF NOT EXISTS ${AUTH_CHALLENGES_TABLE} (
         id          UUID PRIMARY KEY,
         email       TEXT NOT NULL,
         code_hash   TEXT NOT NULL,
         purpose     TEXT NOT NULL,
         expires_at  TIMESTAMPTZ NOT NULL,
         consumed_at TIMESTAMPTZ,
         attempts    INT NOT NULL DEFAULT 0,
         created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
       )`,
    ),
    defineMigration(
      "tenants_0007_auth_challenges_email_idx",
      `CREATE INDEX IF NOT EXISTS ${AUTH_CHALLENGES_TABLE}_email_idx
         ON ${AUTH_CHALLENGES_TABLE} (email, purpose, created_at DESC)`,
    ),
    defineMigration(
      "tenants_0008_jwt_signing_keys",
      `CREATE TABLE IF NOT EXISTS ${JWT_SIGNING_KEYS_TABLE} (
         kid         TEXT PRIMARY KEY,
         alg         TEXT NOT NULL DEFAULT 'EdDSA',
         public_jwk  JSONB NOT NULL,
         private_jwk JSONB NOT NULL,
         status      TEXT NOT NULL DEFAULT 'active',
         created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
         retired_at  TIMESTAMPTZ
       )`,
    ),
    defineMigration(
      "tenants_0009_memberships_principal_idx",
      `CREATE INDEX IF NOT EXISTS ${MEMBERSHIPS_TABLE}_principal_idx
         ON ${MEMBERSHIPS_TABLE} (principal_id, principal_type)`,
    ),
    // Bridge columns on the @hasna/contracts api_keys table: bind an issued key
    // to a tenant / user / principal type. Additive + nullable (online-safe).
    defineMigration(
      "tenants_0010_api_keys_tenant",
      `ALTER TABLE ${apiKeysTable} ADD COLUMN IF NOT EXISTS tenant_id UUID;
       ALTER TABLE ${apiKeysTable} ADD COLUMN IF NOT EXISTS user_id UUID;
       ALTER TABLE ${apiKeysTable} ADD COLUMN IF NOT EXISTS principal_type TEXT;`,
    ),
    defineMigration(
      "tenants_0011_api_keys_tenant_idx",
      `CREATE INDEX IF NOT EXISTS ${apiKeysTable}_tenant_idx ON ${apiKeysTable} (tenant_id)`,
    ),
  ];
}
