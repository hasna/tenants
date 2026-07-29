// IdP data-access layer: tenants, users, memberships, service_principals,
// sessions, auth challenges, and the EdDSA signing-key set. Framework-agnostic;
// takes a storage-kit TypedQueryClient (raw Postgres access, no document store).
//
// Signing-key custody: the private Ed25519 key is read from env
// HASNA_TENANTS_JWT_SIGNING_KEY when set (the Secrets-Manager path —
// `hasna/internalapps/tenants/jwt-signing-key`), otherwise generated once and
// persisted in the app's own RDS (jwt_signing_keys) so JWKS is stable and shared
// across instances without a task-def change. Moving custody fully to Secrets
// Manager is a gated hardening step.

import { generateKeyPairSync } from "node:crypto";
import type { TypedQueryClient } from "../generated/storage-kit/index.js";
import {
  ISSUED_ACCESS_TOKENS_TABLE,
  JWT_SIGNING_KEYS_TABLE,
  MEMBERSHIPS_TABLE,
  SERVICE_PRINCIPALS_TABLE,
  SESSIONS_TABLE,
  AUTH_CHALLENGES_TABLE,
  TENANTS_TABLE,
  USERS_TABLE,
} from "./migrations.js";
import { newId, ROOT_TENANT_ID, SEED_TENANTS } from "./ids.js";
import { signingKeyFromPrivateJwk, type JwkPublic, type SigningKey } from "./tokens.js";

export const JWT_SIGNING_KEY_ENV = "HASNA_TENANTS_JWT_SIGNING_KEY";
export const JWT_KID_ENV = "HASNA_TENANTS_JWT_KID";

export interface TenantRow {
  id: string;
  slug: string;
  name: string;
  kind: string;
  parent_id: string | null;
  status: string;
  identity_id: string | null;
}

export interface UserRow {
  id: string;
  kind: string;
  email: string | null;
  display_name: string | null;
  identity_id: string | null;
  home_tenant_id: string | null;
  auth_method: string | null;
  password_hash: string | null;
  status: string;
  email_verified_at: string | null;
}

export interface MembershipRow {
  id: string;
  tenant_id: string;
  principal_id: string;
  principal_type: string;
  role: string;
  scopes: unknown;
  status: string;
}

export interface ServicePrincipalRow {
  id: string;
  tenant_id: string;
  kind: string;
  display_name: string | null;
  identity_id: string | null;
  enrollment_secret_ref: string | null;
  status: string;
  last_seen_at: string | null;
}

export interface SessionRow {
  id: string;
  user_id: string | null;
  tenant_id: string | null;
  token_hash: string;
  method: string | null;
  issued_at: string;
  expires_at: string | null;
  revoked_at: string | null;
}

export interface SigningKeyRow {
  kid: string;
  alg: string;
  public_jwk: unknown;
  private_jwk: unknown;
  status: string;
}

function asJwk(value: unknown): Record<string, unknown> {
  return (typeof value === "string" ? JSON.parse(value) : value) as Record<string, unknown>;
}

/** The subset of IdpStore the AuthService depends on (enables fakes in tests). */
export interface IdpStoreApi {
  listPublicJwks(): Promise<JwkPublic[]>;
  getSigningKeyForMinting(): Promise<SigningKey>;
  getTenantBySlug(slug: string): Promise<TenantRow | null>;
  createTenant(input: { slug: string; name: string; kind?: string; parentId?: string | null }): Promise<TenantRow>;
  getUserByEmail(email: string): Promise<UserRow | null>;
  getUserById(id: string): Promise<UserRow | null>;
  markEmailVerified(userId: string): Promise<void>;
  createUser(input: {
    kind: string; email?: string | null; displayName?: string | null; identityId?: string | null;
    homeTenantId: string; authMethod?: string | null; passwordHash?: string | null;
  }): Promise<UserRow>;
  createMembership(input: { tenantId: string; principalId: string; principalType: "user" | "service"; role: string; scopes?: string[] }): Promise<void>;
  listMembershipsForPrincipal(principalId: string, principalType: "user" | "service"): Promise<MembershipRow[]>;
  createServicePrincipal(input: {
    id?: string; tenantId: string; kind?: string; displayName?: string | null;
    identityId?: string | null; enrollmentSecretRef: string;
  }): Promise<ServicePrincipalRow>;
  getServicePrincipalById(id: string): Promise<ServicePrincipalRow | null>;
  getServicePrincipalByEnrollmentSecretRef(enrollmentSecretRef: string): Promise<ServicePrincipalRow | null>;
  markServicePrincipalSeen(id: string): Promise<void>;
  disableServicePrincipal(id: string, tenantId: string): Promise<boolean>;
  createSession(input: { userId: string; tenantId: string; tokenHash: string; method?: string; expiresAt: Date; ip?: string | null; userAgent?: string | null }): Promise<string>;
  getSessionByTokenHash(tokenHash: string): Promise<SessionRow | null>;
  createChallenge(input: { email: string; codeHash: string; purpose: string; expiresAt: Date }): Promise<string>;
  findActiveChallenge(email: string, purpose: string): Promise<{ id: string; code_hash: string; attempts: number } | null>;
  consumeChallenge(id: string): Promise<void>;
  bumpChallengeAttempts(id: string): Promise<void>;
  recordApiKeyBinding(apiKeysTable: string, input: { kid: string; tenantId: string; userId: string | null; principalType: "user" | "service" }): Promise<void>;
  lookupApiKeyBinding(apiKeysTable: string, kid: string): Promise<{ tenant_id: string | null; user_id: string | null; principal_type: string | null } | null>;
  recordIssuedAccessToken(input: { jti: string; userId: string | null; tenantId: string | null; aud: string; expiresAt: Date }): Promise<void>;
  /** Stamp revoked_at on the caller's OWN token. Returns false when no owned, un-revoked row matches. */
  revokeIssuedAccessToken(jti: string, userId: string): Promise<boolean>;
  isAccessTokenRevoked(jti: string): Promise<boolean>;
}

export class IdpStore implements IdpStoreApi {
  constructor(private readonly client: TypedQueryClient) {}

  // ── Signing keys ───────────────────────────────────────────────────────────

  /** Env-injected signing key (Secrets Manager path), or null. */
  loadEnvSigningKey(env: NodeJS.ProcessEnv = process.env): SigningKey | null {
    const raw = env[JWT_SIGNING_KEY_ENV]?.trim();
    if (!raw) return null;
    let jwk: Record<string, unknown>;
    try {
      jwk = JSON.parse(raw);
    } catch {
      try {
        jwk = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
      } catch {
        throw new Error(`${JWT_SIGNING_KEY_ENV} must be a private Ed25519 JWK (JSON or base64url JSON).`);
      }
    }
    const kid = env[JWT_KID_ENV]?.trim() || String(jwk["kid"] ?? "env");
    return signingKeyFromPrivateJwk(kid, jwk);
  }

  /** The active DB signing key, generating + persisting one if none exists. */
  async getOrCreateActiveDbKey(): Promise<SigningKey> {
    const existing = await this.client.get<SigningKeyRow>(
      `SELECT kid, alg, public_jwk, private_jwk, status FROM ${JWT_SIGNING_KEYS_TABLE}
         WHERE status = 'active' ORDER BY created_at ASC LIMIT 1`,
    );
    if (existing) {
      return signingKeyFromPrivateJwk(existing.kid, asJwk(existing.private_jwk));
    }
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const kid = `ed25519_${newId().replace(/-/g, "").slice(0, 16)}`;
    const publicJwk = publicKey.export({ format: "jwk" });
    const privateJwk = privateKey.export({ format: "jwk" });
    await this.client.execute(
      `INSERT INTO ${JWT_SIGNING_KEYS_TABLE} (kid, alg, public_jwk, private_jwk, status)
         VALUES ($1, 'EdDSA', $2::jsonb, $3::jsonb, 'active')
       ON CONFLICT (kid) DO NOTHING`,
      [kid, JSON.stringify(publicJwk), JSON.stringify(privateJwk)],
    );
    // Re-read to converge if another instance inserted a different key first.
    const active = await this.client.get<SigningKeyRow>(
      `SELECT kid, alg, public_jwk, private_jwk, status FROM ${JWT_SIGNING_KEYS_TABLE}
         WHERE status = 'active' ORDER BY created_at ASC LIMIT 1`,
    );
    if (!active) throw new Error("Failed to persist an active signing key.");
    return signingKeyFromPrivateJwk(active.kid, asJwk(active.private_jwk));
  }

  /** The key used to MINT new tokens (env wins, else the active DB key). */
  async getSigningKeyForMinting(): Promise<SigningKey> {
    return this.loadEnvSigningKey() ?? (await this.getOrCreateActiveDbKey());
  }

  /** All public JWKs to publish/verify against (env + every active DB key). */
  async listPublicJwks(): Promise<JwkPublic[]> {
    const keys: JwkPublic[] = [];
    const env = this.loadEnvSigningKey();
    if (env) keys.push(env.publicJwk);
    const rows = await this.client.many<SigningKeyRow>(
      `SELECT kid, alg, public_jwk, private_jwk, status FROM ${JWT_SIGNING_KEYS_TABLE}
         WHERE status = 'active' ORDER BY created_at ASC`,
    );
    for (const row of rows) {
      const jwk = asJwk(row.public_jwk) as unknown as JwkPublic;
      keys.push({ kty: "OKP", crv: "Ed25519", x: String(jwk.x), kid: row.kid, use: "sig", alg: "EdDSA" });
    }
    return keys;
  }

  // ── Tenants ──────────────────────────────────────────────────────────────

  /** Idempotently seed the root tenant + brand children (fixed UUIDs). */
  async seedTenants(): Promise<void> {
    for (const t of SEED_TENANTS) {
      await this.client.execute(
        `INSERT INTO ${TENANTS_TABLE} (id, slug, name, kind, parent_id)
           VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (id) DO NOTHING`,
        [t.id, t.slug, t.name, t.kind, t.parentId],
      );
    }
  }

  async getTenantById(id: string): Promise<TenantRow | null> {
    return this.client.get<TenantRow>(
      `SELECT id, slug, name, kind, parent_id, status, identity_id FROM ${TENANTS_TABLE} WHERE id = $1`,
      [id],
    );
  }

  async getTenantBySlug(slug: string): Promise<TenantRow | null> {
    return this.client.get<TenantRow>(
      `SELECT id, slug, name, kind, parent_id, status, identity_id FROM ${TENANTS_TABLE} WHERE slug = $1`,
      [slug],
    );
  }

  async createTenant(input: { slug: string; name: string; kind?: string; parentId?: string | null }): Promise<TenantRow> {
    const id = newId();
    await this.client.execute(
      `INSERT INTO ${TENANTS_TABLE} (id, slug, name, kind, parent_id)
         VALUES ($1, $2, $3, $4, $5)`,
      [id, input.slug, input.name, input.kind ?? "org", input.parentId ?? ROOT_TENANT_ID],
    );
    const row = await this.getTenantById(id);
    if (!row) throw new Error("Failed to create tenant.");
    return row;
  }

  // ── Users ────────────────────────────────────────────────────────────────

  async getUserByEmail(email: string): Promise<UserRow | null> {
    return this.client.get<UserRow>(
      `SELECT id, kind, email, display_name, identity_id, home_tenant_id, auth_method, password_hash, status, email_verified_at
         FROM ${USERS_TABLE} WHERE lower(email) = lower($1)`,
      [email],
    );
  }

  async getUserById(id: string): Promise<UserRow | null> {
    return this.client.get<UserRow>(
      `SELECT id, kind, email, display_name, identity_id, home_tenant_id, auth_method, password_hash, status, email_verified_at
         FROM ${USERS_TABLE} WHERE id = $1`,
      [id],
    );
  }

  /** Mark a user's email confirmed (idempotent; only stamps the first time). */
  async markEmailVerified(userId: string): Promise<void> {
    await this.client.execute(
      `UPDATE ${USERS_TABLE} SET email_verified_at = now(), updated_at = now()
         WHERE id = $1 AND email_verified_at IS NULL`,
      [userId],
    );
  }

  async createUser(input: {
    kind: string;
    email?: string | null;
    displayName?: string | null;
    identityId?: string | null;
    homeTenantId: string;
    authMethod?: string | null;
    passwordHash?: string | null;
  }): Promise<UserRow> {
    const id = newId();
    await this.client.execute(
      `INSERT INTO ${USERS_TABLE} (id, kind, email, display_name, identity_id, home_tenant_id, auth_method, password_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [id, input.kind, input.email ?? null, input.displayName ?? null, input.identityId ?? null,
        input.homeTenantId, input.authMethod ?? null, input.passwordHash ?? null],
    );
    const row = await this.getUserById(id);
    if (!row) throw new Error("Failed to create user.");
    return row;
  }

  async setUserPassword(id: string, passwordHash: string): Promise<void> {
    await this.client.execute(
      `UPDATE ${USERS_TABLE} SET password_hash = $2, auth_method = 'password', updated_at = now() WHERE id = $1`,
      [id, passwordHash],
    );
  }

  // ── Memberships ──────────────────────────────────────────────────────────

  async createMembership(input: {
    tenantId: string;
    principalId: string;
    principalType: "user" | "service";
    role: string;
    scopes?: string[];
  }): Promise<void> {
    await this.client.execute(
      `INSERT INTO ${MEMBERSHIPS_TABLE} (tenant_id, principal_id, principal_type, role, scopes)
         VALUES ($1, $2, $3, $4, $5::jsonb)
       ON CONFLICT (tenant_id, principal_id, principal_type) DO NOTHING`,
      [input.tenantId, input.principalId, input.principalType, input.role, JSON.stringify(input.scopes ?? [])],
    );
  }

  async listMembershipsForPrincipal(principalId: string, principalType: "user" | "service"): Promise<MembershipRow[]> {
    return this.client.many<MembershipRow>(
      `SELECT id, tenant_id, principal_id, principal_type, role, scopes, status
         FROM ${MEMBERSHIPS_TABLE} WHERE principal_id = $1 AND principal_type = $2 AND status = 'active'`,
      [principalId, principalType],
    );
  }

  // ── Service principals ───────────────────────────────────────────────────

  async createServicePrincipal(input: {
    id?: string;
    tenantId: string;
    kind?: string;
    displayName?: string | null;
    identityId?: string | null;
    enrollmentSecretRef: string;
  }): Promise<ServicePrincipalRow> {
    const id = input.id ?? newId();
    await this.client.execute(
      `INSERT INTO ${SERVICE_PRINCIPALS_TABLE} (id, tenant_id, kind, display_name, identity_id, enrollment_secret_ref)
         VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (id) DO NOTHING`,
      [id, input.tenantId, input.kind ?? "machine", input.displayName ?? null, input.identityId ?? null,
        input.enrollmentSecretRef],
    );
    const row = await this.getServicePrincipalById(id);
    if (!row) throw new Error("Failed to create service principal.");
    return row;
  }

  async getServicePrincipalById(id: string): Promise<ServicePrincipalRow | null> {
    return this.client.get<ServicePrincipalRow>(
      `SELECT id, tenant_id, kind, display_name, identity_id, enrollment_secret_ref, status, last_seen_at
         FROM ${SERVICE_PRINCIPALS_TABLE} WHERE id = $1`,
      [id],
    );
  }

  async getServicePrincipalByEnrollmentSecretRef(enrollmentSecretRef: string): Promise<ServicePrincipalRow | null> {
    return this.client.get<ServicePrincipalRow>(
      `SELECT id, tenant_id, kind, display_name, identity_id, enrollment_secret_ref, status, last_seen_at
         FROM ${SERVICE_PRINCIPALS_TABLE}
        WHERE enrollment_secret_ref = $1 AND status = 'active'`,
      [enrollmentSecretRef],
    );
  }

  async markServicePrincipalSeen(id: string): Promise<void> {
    await this.client.execute(
      `UPDATE ${SERVICE_PRINCIPALS_TABLE} SET last_seen_at = now() WHERE id = $1 AND status = 'active'`,
      [id],
    );
  }

  async disableServicePrincipal(id: string, tenantId: string): Promise<boolean> {
    const row = await this.client.get<{ id: string }>(
      `UPDATE ${SERVICE_PRINCIPALS_TABLE}
          SET status = 'disabled', enrollment_secret_ref = NULL
        WHERE id = $1 AND tenant_id = $2 AND status = 'active'
      RETURNING id`,
      [id, tenantId],
    );
    if (!row) return false;
    await this.client.execute(
      `UPDATE ${MEMBERSHIPS_TABLE} SET status = 'disabled'
        WHERE principal_id = $1 AND principal_type = 'service' AND tenant_id = $2 AND status = 'active'`,
      [id, tenantId],
    );
    return true;
  }

  // ── Sessions ─────────────────────────────────────────────────────────────

  async createSession(input: {
    userId: string;
    tenantId: string;
    tokenHash: string;
    method?: string;
    expiresAt: Date;
    ip?: string | null;
    userAgent?: string | null;
  }): Promise<string> {
    const id = newId();
    await this.client.execute(
      `INSERT INTO ${SESSIONS_TABLE} (id, user_id, tenant_id, token_hash, method, expires_at, ip, user_agent)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [id, input.userId, input.tenantId, input.tokenHash, input.method ?? "password",
        input.expiresAt.toISOString(), input.ip ?? null, input.userAgent ?? null],
    );
    return id;
  }

  async getSessionByTokenHash(tokenHash: string): Promise<SessionRow | null> {
    return this.client.get<SessionRow>(
      `SELECT id, user_id, tenant_id, token_hash, method, issued_at, expires_at, revoked_at
         FROM ${SESSIONS_TABLE} WHERE token_hash = $1`,
      [tokenHash],
    );
  }

  async revokeSession(tokenHash: string): Promise<void> {
    await this.client.execute(
      `UPDATE ${SESSIONS_TABLE} SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`,
      [tokenHash],
    );
  }

  // ── Auth challenges (OTP) ────────────────────────────────────────────────

  async createChallenge(input: { email: string; codeHash: string; purpose: string; expiresAt: Date }): Promise<string> {
    const id = newId();
    await this.client.execute(
      `INSERT INTO ${AUTH_CHALLENGES_TABLE} (id, email, code_hash, purpose, expires_at)
         VALUES ($1, $2, $3, $4, $5)`,
      [id, input.email, input.codeHash, input.purpose, input.expiresAt.toISOString()],
    );
    return id;
  }

  async findActiveChallenge(email: string, purpose: string): Promise<{ id: string; code_hash: string; attempts: number } | null> {
    return this.client.get<{ id: string; code_hash: string; attempts: number }>(
      `SELECT id, code_hash, attempts FROM ${AUTH_CHALLENGES_TABLE}
         WHERE lower(email) = lower($1) AND purpose = $2 AND consumed_at IS NULL AND expires_at > now()
         ORDER BY created_at DESC LIMIT 1`,
      [email, purpose],
    );
  }

  async consumeChallenge(id: string): Promise<void> {
    await this.client.execute(
      `UPDATE ${AUTH_CHALLENGES_TABLE} SET consumed_at = now() WHERE id = $1`,
      [id],
    );
  }

  async bumpChallengeAttempts(id: string): Promise<void> {
    await this.client.execute(
      `UPDATE ${AUTH_CHALLENGES_TABLE} SET attempts = attempts + 1 WHERE id = $1`,
      [id],
    );
  }

  // ── API-key bridge (§2.2) ────────────────────────────────────────────────

  /** Record an issued v1 HMAC key's tenant/user/principal binding at mint time. */
  async recordApiKeyBinding(apiKeysTable: string, input: {
    kid: string;
    tenantId: string;
    userId: string | null;
    principalType: "user" | "service";
  }): Promise<void> {
    await this.client.execute(
      `UPDATE ${apiKeysTable} SET tenant_id = $2, user_id = $3, principal_type = $4 WHERE kid = $1`,
      [input.kid, input.tenantId, input.userId, input.principalType],
    );
  }

  /** Resolve a kid to its tenant binding (bridge lookup for v1 tokens). */
  async lookupApiKeyBinding(apiKeysTable: string, kid: string): Promise<{ tenant_id: string | null; user_id: string | null; principal_type: string | null } | null> {
    return this.client.get<{ tenant_id: string | null; user_id: string | null; principal_type: string | null }>(
      `SELECT tenant_id, user_id, principal_type FROM ${apiKeysTable} WHERE kid = $1`,
      [kid],
    );
  }

  // ── Issued access tokens (revocation registry) ──────────────────────────

  /** Record a minted EdDSA token's jti so it can be revoked before exp. */
  async recordIssuedAccessToken(input: { jti: string; userId: string | null; tenantId: string | null; aud: string; expiresAt: Date }): Promise<void> {
    await this.client.execute(
      `INSERT INTO ${ISSUED_ACCESS_TOKENS_TABLE} (jti, user_id, tenant_id, aud, expires_at)
         VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (jti) DO NOTHING`,
      [input.jti, input.userId, input.tenantId, input.aud, input.expiresAt.toISOString()],
    );
  }

  /** Revoke a token the caller OWNS (fail-closed: someone else's jti is untouched). */
  async revokeIssuedAccessToken(jti: string, userId: string): Promise<boolean> {
    const row = await this.client.get<{ jti: string }>(
      `UPDATE ${ISSUED_ACCESS_TOKENS_TABLE} SET revoked_at = now()
         WHERE jti = $1 AND user_id = $2 AND revoked_at IS NULL
       RETURNING jti`,
      [jti, userId],
    );
    return row !== null;
  }

  /** Denylist check consulted on every verify of a tenants-audience token. */
  async isAccessTokenRevoked(jti: string): Promise<boolean> {
    const row = await this.client.get<{ jti: string }>(
      `SELECT jti FROM ${ISSUED_ACCESS_TOKENS_TABLE} WHERE jti = $1 AND revoked_at IS NOT NULL`,
      [jti],
    );
    return row !== null;
  }
}
