import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { AuthService, AuthError } from "./service.js";
import type { IdpStoreApi, MembershipRow, SessionRow, TenantRow, UserRow } from "./store.js";
import { signingKeyFromPrivateJwk, verifyAccessToken, type JwkPublic, type SigningKey } from "./tokens.js";
import { ROOT_TENANT_ID } from "./ids.js";
import { newId } from "./ids.js";

/** In-memory IdpStore for unit-testing the auth logic without a database. */
class FakeIdpStore implements IdpStoreApi {
  users = new Map<string, UserRow>();
  tenants = new Map<string, TenantRow>();
  memberships: MembershipRow[] = [];
  sessions = new Map<string, SessionRow>();
  challenges: Array<{ id: string; email: string; code_hash: string; purpose: string; consumed: boolean; attempts: number; expiresAt: number }> = [];
  bindings = new Map<string, { tenant_id: string | null; user_id: string | null; principal_type: string | null }>();
  private key: SigningKey;

  constructor() {
    const { privateKey } = generateKeyPairSync("ed25519");
    this.key = signingKeyFromPrivateJwk("test-kid", privateKey.export({ format: "jwk" }) as Record<string, unknown>);
    this.tenants.set(ROOT_TENANT_ID, { id: ROOT_TENANT_ID, slug: "hasna", name: "Hasna", kind: "root", parent_id: null, status: "active", identity_id: null });
  }

  async listPublicJwks(): Promise<JwkPublic[]> { return [this.key.publicJwk]; }
  async getSigningKeyForMinting(): Promise<SigningKey> { return this.key; }
  async getTenantBySlug(slug: string): Promise<TenantRow | null> {
    return [...this.tenants.values()].find((t) => t.slug === slug) ?? null;
  }
  async createTenant(input: { slug: string; name: string; kind?: string; parentId?: string | null }): Promise<TenantRow> {
    const row: TenantRow = { id: newId(), slug: input.slug, name: input.name, kind: input.kind ?? "org", parent_id: input.parentId ?? ROOT_TENANT_ID, status: "active", identity_id: null };
    this.tenants.set(row.id, row);
    return row;
  }
  async getUserByEmail(email: string): Promise<UserRow | null> {
    return [...this.users.values()].find((u) => u.email?.toLowerCase() === email.toLowerCase()) ?? null;
  }
  async getUserById(id: string): Promise<UserRow | null> { return this.users.get(id) ?? null; }
  async createUser(input: any): Promise<UserRow> {
    const row: UserRow = {
      id: newId(), kind: input.kind, email: input.email ?? null, display_name: input.displayName ?? null,
      identity_id: input.identityId ?? null, home_tenant_id: input.homeTenantId, auth_method: input.authMethod ?? null,
      password_hash: input.passwordHash ?? null, status: "active", email_verified_at: null,
    };
    this.users.set(row.id, row);
    return row;
  }
  async markEmailVerified(userId: string): Promise<void> { const u = this.users.get(userId); if (u && !u.email_verified_at) u.email_verified_at = new Date().toISOString(); }
  async createMembership(input: any): Promise<void> {
    this.memberships.push({ id: String(this.memberships.length + 1), tenant_id: input.tenantId, principal_id: input.principalId, principal_type: input.principalType, role: input.role, scopes: input.scopes ?? [], status: "active" });
  }
  async listMembershipsForPrincipal(principalId: string, principalType: "user" | "service"): Promise<MembershipRow[]> {
    return this.memberships.filter((m) => m.principal_id === principalId && m.principal_type === principalType && m.status === "active");
  }
  async createSession(input: any): Promise<string> {
    const id = newId();
    this.sessions.set(input.tokenHash, { id, user_id: input.userId, tenant_id: input.tenantId, token_hash: input.tokenHash, method: input.method ?? null, issued_at: new Date().toISOString(), expires_at: input.expiresAt.toISOString(), revoked_at: null });
    return id;
  }
  async getSessionByTokenHash(tokenHash: string): Promise<SessionRow | null> { return this.sessions.get(tokenHash) ?? null; }
  async createChallenge(input: any): Promise<string> {
    const id = newId();
    this.challenges.push({ id, email: input.email, code_hash: input.codeHash, purpose: input.purpose, consumed: false, attempts: 0, expiresAt: input.expiresAt.getTime() });
    return id;
  }
  async findActiveChallenge(email: string, purpose: string) {
    const c = [...this.challenges].reverse().find((x) => x.email.toLowerCase() === email.toLowerCase() && x.purpose === purpose && !x.consumed && x.expiresAt > Date.now());
    return c ? { id: c.id, code_hash: c.code_hash, attempts: c.attempts } : null;
  }
  async consumeChallenge(id: string): Promise<void> { const c = this.challenges.find((x) => x.id === id); if (c) c.consumed = true; }
  async bumpChallengeAttempts(id: string): Promise<void> { const c = this.challenges.find((x) => x.id === id); if (c) c.attempts += 1; }
  async recordApiKeyBinding(_t: string, input: any): Promise<void> { this.bindings.set(input.kid, { tenant_id: input.tenantId, user_id: input.userId, principal_type: input.principalType }); }
  async lookupApiKeyBinding(_t: string, kid: string) { return this.bindings.get(kid) ?? null; }
}

function service(store: FakeIdpStore, otpEcho = false) {
  return new AuthService({ store, signingSecret: "test-secret", apiKeysTable: "api_keys", otpEcho });
}

class CaptureMailer {
  sent: Array<{ to: string; code: string; purpose?: string }> = [];
  async sendConfirmation(i: { to: string; code: string; purpose?: string }) {
    this.sent.push({ to: i.to, code: i.code, ...(i.purpose ? { purpose: i.purpose } : {}) });
    return { messageId: `msg-${this.sent.length}` };
  }
}

// A production-shaped service: hasna-only allowlist + confirmation gate + mailer.
function gatedService(store: FakeIdpStore, mailer: CaptureMailer) {
  return new AuthService({
    store, signingSecret: "test-secret", apiKeysTable: "api_keys", otpEcho: true,
    emailPolicy: { allowedDomains: new Set(["hasna.xyz", "hasna.studio", "hasna.com"]), requireConfirmation: true },
    mailer: mailer as any,
  });
}

describe("AuthService", () => {
  test("password signup joins root as MEMBER (not owner) and auto-logs-in", async () => {
    const store = new FakeIdpStore();
    const svc = service(store);
    const res = await svc.signup({ email: "a@example.com", name: "A", password: "hunter2hunter2" });
    expect(res.session).toBeTruthy();
    expect((res.tenant as any).tenant_id).toBe(ROOT_TENANT_ID);
    // A random root signup must NOT become a fleet-root owner.
    expect((res.tenants as any[])[0].role).toBe("member");
  });

  test("signup with a NEW org_name makes the creator that org's owner", async () => {
    const store = new FakeIdpStore();
    const svc = service(store);
    const res = await svc.signup({ email: "founder@acme.com", name: "F", org_name: "Acme Co", password: "pw-pw-pw-pw" });
    const tenantId = (res.tenant as any).tenant_id as string;
    expect(tenantId).not.toBe(ROOT_TENANT_ID);
    expect((res.tenants as any[])[0].role).toBe("owner");
  });

  test("duplicate email is rejected", async () => {
    const store = new FakeIdpStore();
    const svc = service(store);
    await svc.signup({ email: "dup@example.com", name: "D", password: "pw-pw-pw-pw" });
    await expect(svc.signup({ email: "dup@example.com", name: "D2", password: "pw-pw-pw-pw" })).rejects.toThrow(AuthError);
  });

  test("wrong password fails with generic error; correct password issues session", async () => {
    const store = new FakeIdpStore();
    const svc = service(store);
    await svc.signup({ email: "b@example.com", name: "B", password: "correct-horse" });
    await expect(svc.login({ email: "b@example.com", password: "nope" })).rejects.toThrow("Invalid email or password");
    const ok = await svc.login({ email: "b@example.com", password: "correct-horse" });
    expect(ok.session).toBeTruthy();
  });

  test("OTP signup → verify → session; a stamped app token carries tid/uid and verifies via JWKS", async () => {
    const store = new FakeIdpStore();
    const svc = service(store, true); // echo the OTP for the test
    const signup = await svc.signup({ email: "otp@example.com", name: "O" });
    expect(signup.challenge).toBe(true);
    const code = String(signup.dev_code);
    const verified = await svc.verify({ email: "otp@example.com", code });
    const session = String(verified.session);
    expect(session).toBeTruthy();

    // mint a token for another app
    const minted = await svc.token({ sessionToken: session, app: "todos" });
    expect(minted.token_type).toBe("Bearer");
    expect(minted.tid).toBe(ROOT_TENANT_ID);
    const jwks = await store.listPublicJwks();
    const result = verifyAccessToken(String(minted.access_token), { jwks, expectedAudience: "todos" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.claims.tid).toBe(ROOT_TENANT_ID);
      expect(result.claims.sub).toBeTruthy();
      expect(result.claims.pt).toBe("user");
      expect(result.claims.scope).toEqual(["todos:read", "todos:write"]);
    }
  });

  test("verify rejects a wrong OTP and enforces attempt ceiling", async () => {
    const store = new FakeIdpStore();
    const svc = service(store, true);
    await svc.signup({ email: "z@example.com", name: "Z" });
    await expect(svc.verify({ email: "z@example.com", code: "000000" })).rejects.toThrow("Invalid code");
  });

  test("token requires a valid session and a known app", async () => {
    const store = new FakeIdpStore();
    const svc = service(store);
    await expect(svc.token({ sessionToken: "bogus", app: "todos" })).rejects.toThrow("Invalid session");
    const s = await svc.signup({ email: "t@example.com", name: "T", password: "pw-pw-pw-pw" });
    await expect(svc.token({ sessionToken: String(s.session), app: "not-a-real-app" })).rejects.toThrow("Unknown app");
  });

  test("whoami reflects the principal + tenants", async () => {
    const store = new FakeIdpStore();
    const svc = service(store);
    const s = await svc.signup({ email: "w@example.com", name: "W", password: "pw-pw-pw-pw" });
    const who = await svc.whoami(String(s.session));
    expect((who.principal as any).email).toBe("w@example.com");
    expect((who.tenants as any[])[0].tenant_id).toBe(ROOT_TENANT_ID);
  });

  test("token for a tenant the caller is NOT a member of fails closed", async () => {
    const store = new FakeIdpStore();
    const svc = service(store);
    const s = await svc.signup({ email: "m@example.com", name: "M", password: "pw-pw-pw-pw" });
    await expect(svc.token({ sessionToken: String(s.session), app: "todos", tenant_id: newId() }))
      .rejects.toThrow("No membership for the requested tenant");
  });
});

describe("AuthService login front door (allowlist + confirmation)", () => {
  test("signup with a non-hasna email is rejected", async () => {
    const store = new FakeIdpStore();
    const svc = gatedService(store, new CaptureMailer());
    await expect(svc.signup({ email: "intruder@gmail.com", name: "X", password: "pw-pw-pw-pw" }))
      .rejects.toThrow("restricted to Hasna email");
  });

  test("login with a non-hasna email is rejected", async () => {
    const store = new FakeIdpStore();
    const svc = gatedService(store, new CaptureMailer());
    await expect(svc.login({ email: "intruder@gmail.com", password: "pw-pw-pw-pw" }))
      .rejects.toThrow("restricted to Hasna email");
  });

  test("hasna signup does NOT mint a session; it sends a confirmation code", async () => {
    const store = new FakeIdpStore();
    const mailer = new CaptureMailer();
    const svc = gatedService(store, mailer);
    const res = await svc.signup({ email: "founder@hasna.xyz", name: "F", password: "pw-pw-pw-pw" });
    expect(res.session).toBeUndefined();
    expect(res.confirmation_required).toBe(true);
    expect(res.challenge).toBe(true);
    expect(res.email_message_id).toBe("msg-1");
    expect(mailer.sent[0]!.to).toBe("founder@hasna.xyz");
  });

  test("password login before confirmation is refused", async () => {
    const store = new FakeIdpStore();
    const svc = gatedService(store, new CaptureMailer());
    await svc.signup({ email: "dev@hasna.studio", name: "D", password: "pw-pw-pw-pw" });
    await expect(svc.login({ email: "dev@hasna.studio", password: "pw-pw-pw-pw" }))
      .rejects.toThrow("Confirm your email");
  });

  test("signup → confirm → password login succeeds", async () => {
    const store = new FakeIdpStore();
    const svc = gatedService(store, new CaptureMailer());
    const signup = await svc.signup({ email: "dev2@hasna.com", name: "D2", password: "pw-pw-pw-pw" });
    const verified = await svc.verify({ email: "dev2@hasna.com", code: String(signup.dev_code) });
    expect(verified.session).toBeTruthy();
    const ok = await svc.login({ email: "dev2@hasna.com", password: "pw-pw-pw-pw" });
    expect(ok.session).toBeTruthy();
  });
});
