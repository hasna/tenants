// Test-only IdP fixtures: an in-memory IdpStore and a Postgres client shim, so a
// REAL `createFetchHandler` can be exercised without a database.
//
// This lives in one module because two suites need the same server: the HTTP
// route tests (src/server/auth-routes.test.ts) and the CLI contract tests
// (src/cli.test.ts), which drive `runCli` against this handler rather than a
// hand-written fetch stub. A stub answers whatever the test wants; only the real
// handler can prove a command is not dead against the actual server.
//
// Excluded from tsconfig (like every *.test.ts) so it never reaches dist/.

import { generateKeyPairSync } from "node:crypto";
import { AuthService } from "../idp/service.js";
import { UNRESTRICTED_EMAIL_POLICY } from "../idp/policy.js";
import type { IdpStoreApi, MembershipRow, SessionRow, TenantRow, UserRow } from "../idp/store.js";
import { signingKeyFromPrivateJwk, type JwkPublic, type SigningKey } from "../idp/tokens.js";
import { ROOT_TENANT_ID, newId } from "../idp/ids.js";
import { createFetchHandler } from "../server/serve.js";
import type { PoolQueryClient } from "../generated/storage-kit/index.js";

export const TEST_SIGNING_SECRET = "test-signing-secret-for-auth-routes";

/** In-memory IdpStore so the HTTP surface is exercised without a database. */
export class FakeIdpStore implements IdpStoreApi {
  users = new Map<string, UserRow>();
  memberships: MembershipRow[] = [];
  sessions = new Map<string, SessionRow>();
  challenges: Array<{ id: string; email: string; code_hash: string; purpose: string; consumed: boolean; attempts: number; expiresAt: number }> = [];
  bindings = new Map<string, { tenant_id: string | null; user_id: string | null; principal_type: string | null }>();
  key: SigningKey;
  constructor() {
    const { privateKey } = generateKeyPairSync("ed25519");
    this.key = signingKeyFromPrivateJwk("routes-kid", privateKey.export({ format: "jwk" }) as Record<string, unknown>);
  }
  async listPublicJwks(): Promise<JwkPublic[]> { return [this.key.publicJwk]; }
  async getSigningKeyForMinting(): Promise<SigningKey> { return this.key; }
  async getTenantBySlug(): Promise<TenantRow | null> { return null; }
  async createTenant(input: any): Promise<TenantRow> { return { id: newId(), slug: input.slug, name: input.name, kind: "org", parent_id: ROOT_TENANT_ID, status: "active", identity_id: null }; }
  async getUserByEmail(email: string): Promise<UserRow | null> { return [...this.users.values()].find((u) => u.email?.toLowerCase() === email.toLowerCase()) ?? null; }
  async getUserById(id: string): Promise<UserRow | null> { return this.users.get(id) ?? null; }
  async createUser(input: any): Promise<UserRow> {
    const row: UserRow = { id: newId(), kind: input.kind, email: input.email ?? null, display_name: input.displayName ?? null, identity_id: null, home_tenant_id: input.homeTenantId, auth_method: input.authMethod ?? null, password_hash: input.passwordHash ?? null, status: "active", email_verified_at: null };
    this.users.set(row.id, row); return row;
  }
  async markEmailVerified(userId: string): Promise<void> { const u = this.users.get(userId); if (u && !u.email_verified_at) u.email_verified_at = new Date().toISOString(); }
  async createMembership(input: any): Promise<void> { this.memberships.push({ id: String(this.memberships.length + 1), tenant_id: input.tenantId, principal_id: input.principalId, principal_type: input.principalType, role: input.role, scopes: [], status: "active" }); }
  async listMembershipsForPrincipal(principalId: string, principalType: "user" | "service"): Promise<MembershipRow[]> { return this.memberships.filter((m) => m.principal_id === principalId && m.principal_type === principalType); }
  async createSession(input: any): Promise<string> { const id = newId(); this.sessions.set(input.tokenHash, { id, user_id: input.userId, tenant_id: input.tenantId, token_hash: input.tokenHash, method: null, issued_at: new Date().toISOString(), expires_at: input.expiresAt.toISOString(), revoked_at: null }); return id; }
  async getSessionByTokenHash(h: string): Promise<SessionRow | null> { return this.sessions.get(h) ?? null; }
  async createChallenge(input: any): Promise<string> { const id = newId(); this.challenges.push({ id, email: input.email, code_hash: input.codeHash, purpose: input.purpose, consumed: false, attempts: 0, expiresAt: input.expiresAt.getTime() }); return id; }
  async findActiveChallenge(email: string, purpose: string) { const c = [...this.challenges].reverse().find((x) => x.email.toLowerCase() === email.toLowerCase() && x.purpose === purpose && !x.consumed && x.expiresAt > Date.now()); return c ? { id: c.id, code_hash: c.code_hash, attempts: c.attempts } : null; }
  async consumeChallenge(id: string): Promise<void> { const c = this.challenges.find((x) => x.id === id); if (c) c.consumed = true; }
  async bumpChallengeAttempts(id: string): Promise<void> { const c = this.challenges.find((x) => x.id === id); if (c) c.attempts += 1; }
  async recordApiKeyBinding(_t: string, input: any): Promise<void> { this.bindings.set(input.kid, { tenant_id: input.tenantId, user_id: input.userId, principal_type: input.principalType }); }
  async lookupApiKeyBinding(_t: string, kid: string) { return this.bindings.get(kid) ?? null; }
  issued = new Map<string, { user_id: string | null; tenant_id: string | null; aud: string; expiresAt: number; revokedAt: number | null }>();
  async recordIssuedAccessToken(input: { jti: string; userId: string | null; tenantId: string | null; aud: string; expiresAt: Date }): Promise<void> {
    this.issued.set(input.jti, { user_id: input.userId, tenant_id: input.tenantId, aud: input.aud, expiresAt: input.expiresAt.getTime(), revokedAt: null });
  }
  async revokeIssuedAccessToken(jti: string, userId: string): Promise<boolean> {
    const t = this.issued.get(jti);
    if (!t || t.user_id !== userId || t.revokedAt !== null) return false;
    t.revokedAt = Date.now();
    return true;
  }
  async isAccessTokenRevoked(jti: string): Promise<boolean> { return (this.issued.get(jti)?.revokedAt ?? null) !== null; }
  async isAccessTokenActive(jti: string, now: Date): Promise<boolean> {
    const token = this.issued.get(jti);
    return token !== undefined && token.revokedAt === null && token.expiresAt > now.getTime();
  }
}

/**
 * A do-nothing Postgres client shim: the auth path uses the FakeIdpStore, so no
 * SQL is executed here (the v1 HMAC verifier's isRevoked is never hit on the v2
 * EdDSA token path these tests use).
 */
export const shimClient = {
  async query() { return { rows: [] as any[], rowCount: 0 }; },
  async many() { return [] as any[]; },
  async get() { return null as any; },
  async one() { throw new Error("no rows"); },
  async execute() {},
  pool: {} as any,
  async transaction<T>(fn: (c: any) => Promise<T>): Promise<T> { return fn(shimClient); },
  async close() {},
} as unknown as PoolQueryClient;

/**
 * Build a real fetch handler over an in-memory store. The front door is
 * explicitly unrestricted (the AuthService constructor default denies every
 * address), so route/CLI tests can sign up without configuring an allowlist.
 */
export async function createTestFetchHandler(
  store: FakeIdpStore = new FakeIdpStore(),
): Promise<{ fetch: (req: Request) => Promise<Response>; store: FakeIdpStore }> {
  const auth = new AuthService({
    store,
    signingSecret: TEST_SIGNING_SECRET,
    apiKeysTable: "api_keys",
    otpEcho: true,
    emailPolicy: UNRESTRICTED_EMAIL_POLICY,
  });
  const built = await createFetchHandler({ client: shimClient, signingSecret: TEST_SIGNING_SECRET, auth });
  return { fetch: built.fetch, store };
}
