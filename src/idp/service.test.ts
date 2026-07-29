import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { AuthService, AuthError } from "./service.js";
import { UNRESTRICTED_EMAIL_POLICY } from "./policy.js";
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
    this.tenants.set(ROOT_TENANT_ID, { id: ROOT_TENANT_ID, slug: "root", name: "Root", kind: "root", parent_id: null, status: "active", identity_id: null });
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

function service(store: FakeIdpStore, otpEcho = false) {
  // No front-door gate: this helper exercises the non-policy paths. The
  // unrestricted policy must be passed EXPLICITLY — the constructor default
  // denies every address.
  return new AuthService({ store, signingSecret: "test-secret", apiKeysTable: "api_keys", otpEcho, emailPolicy: UNRESTRICTED_EMAIL_POLICY });
}

class CaptureMailer {
  sent: Array<{ to: string; code: string; purpose?: string }> = [];
  async sendConfirmation(i: { to: string; code: string; purpose?: string }) {
    this.sent.push({ to: i.to, code: i.code, ...(i.purpose ? { purpose: i.purpose } : {}) });
    return { messageId: `msg-${this.sent.length}` };
  }
}

// A production-shaped service: configured allowlist + confirmation gate + mailer.
function gatedService(store: FakeIdpStore, mailer: CaptureMailer) {
  return new AuthService({
    store, signingSecret: "test-secret", apiKeysTable: "api_keys", otpEcho: true,
    emailPolicy: { allowedDomains: new Set(["example.com", "example.net", "example.org"]), requireConfirmation: true },
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

  test("a caller-requested 10-year TTL is clamped to the 24h ceiling", async () => {
    const store = new FakeIdpStore();
    const svc = service(store);
    const s = await svc.signup({ email: "ttl@example.com", name: "T", password: "pw-pw-pw-pw" });
    const minted = await svc.token({ sessionToken: String(s.session), app: "todos", ttlSeconds: 315_360_000 });
    expect(minted.expires_in).toBe(24 * 60 * 60);
  });

  test("non-positive / non-integer TTLs are rejected with invalid_ttl (400)", async () => {
    const store = new FakeIdpStore();
    const svc = service(store);
    const s = await svc.signup({ email: "ttl2@example.com", name: "T2", password: "pw-pw-pw-pw" });
    for (const bad of [0, -1, 1.5]) {
      await expect(svc.token({ sessionToken: String(s.session), app: "todos", ttlSeconds: bad }))
        .rejects.toThrow("ttlSeconds must be a positive integer");
    }
  });

  test("a minted token is registered by jti and revocable by its owner", async () => {
    const store = new FakeIdpStore();
    const svc = service(store);
    const s = await svc.signup({ email: "rev@example.com", name: "R", password: "pw-pw-pw-pw" });
    const minted = await svc.token({ sessionToken: String(s.session), app: "todos" });
    const jti = String(minted.jti);
    expect(jti).toBeTruthy();
    expect(await svc.isTokenRevoked(jti)).toBe(false);
    const res = await svc.revokeToken({ sessionToken: String(s.session), jti });
    expect(res.revoked).toBe(true);
    expect(await svc.isTokenRevoked(jti)).toBe(true);
  });

  test("access-token introspection fails closed for revoked, expired, and unknown jtis", async () => {
    const store = new FakeIdpStore();
    const svc = service(store);
    const s = await svc.signup({ email: "status@example.com", name: "S", password: "pw-pw-pw-pw" });

    const live = await svc.token({ sessionToken: String(s.session), app: "todos", ttlSeconds: 60 });
    expect(await svc.introspectAccessToken({ jti: String(live.jti) }))
      .toEqual({ active: true, jti: live.jti });

    await svc.revokeToken({ sessionToken: String(s.session), jti: String(live.jti) });
    expect(await svc.introspectAccessToken({ jti: String(live.jti) }))
      .toEqual({ active: false, jti: live.jti });

    const expired = await svc.token({ sessionToken: String(s.session), app: "todos", ttlSeconds: 60 });
    store.issued.get(String(expired.jti))!.expiresAt = Date.now() - 1;
    expect(await svc.introspectAccessToken({ jti: String(expired.jti) }))
      .toEqual({ active: false, jti: expired.jti });

    const unknown = newId();
    expect(await svc.introspectAccessToken({ jti: unknown }))
      .toEqual({ active: false, jti: unknown });
  });

  test("a principal cannot revoke ANOTHER user's token (owner-scoped, no leak)", async () => {
    const store = new FakeIdpStore();
    const svc = service(store);
    const owner = await svc.signup({ email: "owner@example.com", name: "O", password: "pw-pw-pw-pw" });
    const other = await svc.signup({ email: "other@example.com", name: "X", password: "pw-pw-pw-pw" });
    const minted = await svc.token({ sessionToken: String(owner.session), app: "todos" });
    const res = await svc.revokeToken({ sessionToken: String(other.session), jti: String(minted.jti) });
    expect(res.revoked).toBe(false);
    expect(await svc.isTokenRevoked(String(minted.jti))).toBe(false);
  });

  test("revoke rejects a non-UUID jti with a clean 400 invalid_request (guard fires before the store)", async () => {
    const store = new FakeIdpStore();
    const svc = service(store);
    const s = await svc.signup({ email: "badjti@example.com", name: "B", password: "pw-pw-pw-pw" });
    for (const bad of ["not-a-uuid", "1234", "'; DROP TABLE x; --", "aaaaaaaa-bbbb-cccc-dddd"]) {
      const err = await svc.revokeToken({ sessionToken: String(s.session), jti: bad }).then(
        () => { throw new Error(`revokeToken must reject non-UUID jti ${JSON.stringify(bad)}`); },
        (e) => e,
      );
      // A typed AuthError — the HTTP layer maps it to 400 invalid_request —
      // NOT a raw Postgres "invalid input syntax for type uuid" leak.
      expect(err).toBeInstanceOf(AuthError);
      expect((err as AuthError).status).toBe(400);
      expect((err as AuthError).code).toBe("invalid_request");
    }
  });

  test("introspect is tenant-scoped: foreign or unresolvable callers see active:false", async () => {
    const store = new FakeIdpStore();
    const svc = service(store);
    store.bindings.set("kid-a", { tenant_id: "tenant-a", user_id: "u1", principal_type: "user" });
    // Same tenant → full binding.
    const same = await svc.introspect("kid-a", "tenant-a");
    expect(same.active).toBe(true);
    expect(same.tenant_id).toBe("tenant-a");
    // Foreign tenant → fails closed without revealing the binding.
    const foreign = await svc.introspect("kid-a", "tenant-b");
    expect(foreign).toEqual({ active: false, kid: "kid-a" });
    // Unresolvable caller tenant → fails closed.
    const unknown = await svc.introspect("kid-a", null);
    expect(unknown).toEqual({ active: false, kid: "kid-a" });
  });
});

describe("AuthService login front door (allowlist + confirmation)", () => {
  test("signup with an off-allowlist email is rejected", async () => {
    const store = new FakeIdpStore();
    const svc = gatedService(store, new CaptureMailer());
    await expect(svc.signup({ email: "intruder@notallowed.test", name: "X", password: "pw-pw-pw-pw" }))
      .rejects.toThrow("not permitted to sign up or sign in");
  });

  test("login with an off-allowlist email is rejected", async () => {
    const store = new FakeIdpStore();
    const svc = gatedService(store, new CaptureMailer());
    await expect(svc.login({ email: "intruder@notallowed.test", password: "pw-pw-pw-pw" }))
      .rejects.toThrow("not permitted to sign up or sign in");
  });

  test("allowlisted signup does NOT mint a session; it sends a confirmation code", async () => {
    const store = new FakeIdpStore();
    const mailer = new CaptureMailer();
    const svc = gatedService(store, mailer);
    const res = await svc.signup({ email: "founder@example.com", name: "F", password: "pw-pw-pw-pw" });
    expect(res.session).toBeUndefined();
    expect(res.confirmation_required).toBe(true);
    expect(res.challenge).toBe(true);
    expect(res.email_message_id).toBe("msg-1");
    expect(mailer.sent[0]!.to).toBe("founder@example.com");
  });

  test("password login before confirmation is refused", async () => {
    const store = new FakeIdpStore();
    const svc = gatedService(store, new CaptureMailer());
    await svc.signup({ email: "dev@example.net", name: "D", password: "pw-pw-pw-pw" });
    await expect(svc.login({ email: "dev@example.net", password: "pw-pw-pw-pw" }))
      .rejects.toThrow("Confirm your email");
  });

  // The public shape of resend is the whole security property: if it varies
  // with account state, the route is an unauthenticated enumeration oracle.
  test("resend answers with an identical body for unknown, unconfirmed, and confirmed addresses", async () => {
    const store = new FakeIdpStore();
    const mailer = new CaptureMailer();
    const svc = gatedService(store, mailer);

    // pending@ stays unconfirmed; done@ signs up and then confirms.
    await svc.signup({ email: "pending@example.com", name: "P", password: "pw-pw-pw-pw" });
    const done = await svc.signup({ email: "done@example.com", name: "D", password: "pw-pw-pw-pw" });
    await svc.verify({ email: "done@example.com", code: String(done.dev_code) });

    const unknown = await svc.resend({ email: "nobody@example.com" });
    const unconfirmed = await svc.resend({ email: "pending@example.com" });
    const confirmed = await svc.resend({ email: "done@example.com" });

    // Same keys AND same values — no confirmation_required / email_sent /
    // email_skipped_reason / dev_code leaking the account's state.
    for (const res of [unknown, unconfirmed, confirmed]) {
      expect(Object.keys(res).sort()).toEqual(["challenge", "expires_in", "purpose"]);
    }
    expect(unconfirmed).toEqual(unknown);
    expect(confirmed).toEqual(unknown);

    // …while the side effect still happens for exactly the unconfirmed account.
    expect(mailer.sent.map((m) => m.to)).toEqual(["pending@example.com", "done@example.com", "pending@example.com"]);
    expect(store.challenges.filter((c) => c.email === "nobody@example.com")).toHaveLength(0);
  });

  test("signup → confirm → password login succeeds", async () => {
    const store = new FakeIdpStore();
    const svc = gatedService(store, new CaptureMailer());
    const signup = await svc.signup({ email: "dev2@example.org", name: "D2", password: "pw-pw-pw-pw" });
    const verified = await svc.verify({ email: "dev2@example.org", code: String(signup.dev_code) });
    expect(verified.session).toBeTruthy();
    const ok = await svc.login({ email: "dev2@example.org", password: "pw-pw-pw-pw" });
    expect(ok.session).toBeTruthy();
  });
});

// Every session-minting path is gated, not only the entry points.
describe("front door is re-checked before a session is minted", () => {
  test("a pending challenge is not redeemable after its domain leaves the allowlist", async () => {
    const store = new FakeIdpStore();
    const allowed = new Set(["example.com"]);
    const svc = new AuthService({
      store, signingSecret: "test-secret", apiKeysTable: "api_keys", otpEcho: true,
      emailPolicy: { allowedDomains: allowed, requireConfirmation: true },
    });
    const signup = await svc.signup({ email: "late@example.com", name: "L", password: "pw-pw-pw-pw" });
    expect(signup.confirmation_required).toBe(true);

    // The operator removes the domain while the challenge is still live.
    allowed.delete("example.com");

    await expect(svc.verify({ email: "late@example.com", code: String(signup.dev_code) }))
      .rejects.toThrow(AuthError);
  });
});

describe("session-authenticated paths are gated too", () => {
  test("whoami and token stop working once the allowlist no longer covers the user", async () => {
    const allowed = new Set(["example.com"]);
    const store = new FakeIdpStore();
    const svc = new AuthService({
      store, signingSecret: "test-secret", apiKeysTable: "api_keys", otpEcho: true,
      emailPolicy: { allowedDomains: allowed, requireConfirmation: false },
    });
    const res = await svc.signup({ email: "user@example.com", name: "U", password: "pw-pw-pw-pw" });
    const session = res.session as string;
    expect(await svc.whoami(session)).toBeTruthy();

    // The operator removes the domain — or loses the configuration entirely.
    allowed.clear();

    await expect(svc.whoami(session)).rejects.toThrow(AuthError);
    // token() mints fleet credentials, including long-lived v1 API keys whose
    // expiry is independent of the 24h session.
    await expect(svc.token({ sessionToken: session, app: "tenants" })).rejects.toThrow(AuthError);
  });
});

describe("misconfiguration is not reported as a caller error", () => {
  test("signup and resend answer 503, not 400, when the allowlist is unconfigured", async () => {
    const svc = new AuthService({
      store: new FakeIdpStore(), signingSecret: "test-secret", apiKeysTable: "api_keys",
    });
    for (const call of [
      () => svc.signup({ email: "not-an-email", name: "X" }),
      () => svc.resend({ email: "not-an-email" }),
      () => svc.signup({ email: "", name: "X" }),
    ]) {
      const err = await call().catch((e) => e);
      expect(err).toBeInstanceOf(AuthError);
      expect((err as AuthError).status).toBe(503);
      expect((err as AuthError).code).toBe("email_allowlist_not_configured");
    }
  });
});
