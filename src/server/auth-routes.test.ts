import { beforeAll, describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { AuthService } from "../idp/service.js";
import type { IdpStoreApi, MembershipRow, SessionRow, TenantRow, UserRow } from "../idp/store.js";
import { signingKeyFromPrivateJwk, type JwkPublic, type SigningKey } from "../idp/tokens.js";
import { ROOT_TENANT_ID, newId } from "../idp/ids.js";
import { createFetchHandler } from "./serve.js";
import type { PoolQueryClient } from "../generated/storage-kit/index.js";

const SIGNING_SECRET = "test-signing-secret-for-auth-routes";

// In-memory IdpStore so the HTTP surface is exercised without a database.
class FakeIdpStore implements IdpStoreApi {
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
}

// A do-nothing Postgres client shim: the auth path uses the FakeIdpStore, so no
// SQL is executed here (the v1 HMAC verifier's isRevoked is never hit on the v2
// EdDSA token path these tests use).
const shimClient = {
  async query() { return { rows: [] as any[], rowCount: 0 }; },
  async many() { return [] as any[]; },
  async get() { return null as any; },
  async one() { throw new Error("no rows"); },
  async execute() {},
  pool: {} as any,
  async transaction<T>(fn: (c: any) => Promise<T>): Promise<T> { return fn(shimClient); },
  async close() {},
} as unknown as PoolQueryClient;

describe("Tenants IdP HTTP routes", () => {
  let fetchHandler: (req: Request) => Promise<Response>;

  beforeAll(async () => {
    const fakeStore = new FakeIdpStore();
    const auth = new AuthService({ store: fakeStore, signingSecret: SIGNING_SECRET, apiKeysTable: "api_keys", otpEcho: true });
    const built = await createFetchHandler({ client: shimClient, signingSecret: SIGNING_SECRET, auth });
    fetchHandler = built.fetch;
  });

  test("GET /jwks is public and returns an EdDSA key", async () => {
    const res = await fetchHandler(new Request("http://x/jwks"));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.keys[0].kty).toBe("OKP");
    expect(body.keys[0].alg).toBe("EdDSA");
  });

  test("GET /v1/.well-known/jwks.json is also public", async () => {
    const res = await fetchHandler(new Request("http://x/v1/.well-known/jwks.json"));
    expect(res.status).toBe(200);
    expect((await res.json()).keys.length).toBeGreaterThan(0);
  });

  test("signup(password) → token(tenants) → the minted v2 token authenticates /v1/introspect", async () => {
    const signupRes = await fetchHandler(new Request("http://x/signup", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "route@example.com", name: "R", password: "pw-pw-pw-pw" }),
    }));
    expect(signupRes.status).toBe(201);
    const session = (await signupRes.json()).session as string;
    expect(session).toBeTruthy();

    const tokenRes = await fetchHandler(new Request("http://x/v1/auth/token", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${session}` },
      body: JSON.stringify({ app: "tenants", scopes: ["tenants:read"] }),
    }));
    expect(tokenRes.status).toBe(200);
    const tokenBody = await tokenRes.json();
    expect(tokenBody.aud).toBe("tenants");
    const access = tokenBody.access_token as string;

    // The v2 EdDSA token authenticates the /v1 gate (aud=tenants) via JWKS.
    const introspectRes = await fetchHandler(new Request("http://x/v1/introspect?kid=some-kid", {
      headers: { authorization: `Bearer ${access}` },
    }));
    expect(introspectRes.status).toBe(200);
    expect((await introspectRes.json()).active).toBe(false);
  });

  test("a write-scope route rejects a read-only token (403)", async () => {
    // Sign in and mint a read-only token, then hit an unknown /v1 mutation path
    // (POST → requires tenants:write) to prove scope enforcement on the v2 path.
    const s = await fetchHandler(new Request("http://x/login", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "route@example.com", password: "pw-pw-pw-pw" }),
    }));
    const session = (await s.json()).session as string;
    const tokenRes = await fetchHandler(new Request("http://x/v1/auth/token", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${session}` },
      body: JSON.stringify({ app: "tenants", scopes: ["tenants:read"] }),
    }));
    const access = (await tokenRes.json()).access_token as string;
    const writeRes = await fetchHandler(new Request("http://x/v1/introspect", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${access}` },
      body: JSON.stringify({}),
    }));
    expect(writeRes.status).toBe(403);
  });

  test("whoami requires a session and reflects the principal", async () => {
    const s = await fetchHandler(new Request("http://x/login", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "route@example.com", password: "pw-pw-pw-pw" }),
    }));
    const session = (await s.json()).session as string;
    const who = await fetchHandler(new Request("http://x/v1/auth/whoami", { headers: { authorization: `Bearer ${session}` } }));
    expect(who.status).toBe(200);
    expect((await who.json()).principal.email).toBe("route@example.com");
  });

  test("/v1 still rejects an anonymous request (401)", async () => {
    const res = await fetchHandler(new Request("http://x/v1/introspect?kid=x"));
    expect(res.status).toBe(401);
  });
});
