// Fleet IdP auth service: signup / login / verify / token / whoami / introspect.
//
// Framework-agnostic: each handler takes a parsed input object and returns a
// plain response (or throws AuthError with an HTTP status). serve.ts wires these
// to Bun.serve routes. Tokens issued for OTHER apps are v2 EdDSA JWS (verified via
// JWKS — this service holds no other app's secret). For the `tenants` app itself
// a v1 HMAC key may also be minted (transitional) and recorded in api_keys with
// tenant/user/principal bridge columns.

import { mintApiKey, hasScope, type ApiKeyStore } from "@hasna/contracts/auth";
import { randomBytes } from "node:crypto";
import type { IdpStoreApi, MembershipRow, UserRow } from "./store.js";
import { hashPassword, sha256, verifyPassword } from "./passwords.js";
import { isUuid, newId, ROOT_TENANT_ID } from "./ids.js";
import { buildJwks, signAccessToken, MAX_ACCESS_TOKEN_TTL_SECONDS, type JwksDocument } from "./tokens.js";
import { checkEmailDomain, denyAllEmailPolicy, type EmailPolicy } from "./policy.js";
import { NoopMailer, type Mailer } from "./mailer.js";

export const SESSION_TTL_SECONDS = 24 * 60 * 60;
export const OTP_TTL_SECONDS = 10 * 60;
export const OTP_MAX_ATTEMPTS = 5;

/**
 * App slugs the IdP will mint fleet tokens for. `tenants` is this service's own
 * app; the rest are the fleet apps that accept tenants-issued EdDSA tokens
 * (verified offline via the published JWKS). `identities` (the SEPARATE agent
 * registry) is listed as a token AUDIENCE only — this is a cross-service token
 * grant, not a code dependency on that package.
 */
export const FLEET_APPS = [
  "tenants", "identities", "todos", "skills", "conversations", "mementos", "hooks",
  "telephony", "infinity", "sandboxes", "domains", "accounts", "files",
  "sessions", "secrets", "projects", "knowledge",
];

/** This service's own app slug (the only app whose HMAC secret it holds). */
export const SELF_APP = "tenants";

export class AuthError extends Error {
  constructor(public status: number, message: string, public code?: string, public details?: Record<string, unknown>) {
    super(message);
    this.name = "AuthError";
  }
}

export interface AuthServiceOptions {
  store: IdpStoreApi;
  /** This service's own HMAC signing secret (mints self-app v1 keys only). */
  signingSecret: string;
  apiKeysTable: string;
  /** Persists issued v1 HMAC keys (for the self-app token path). */
  apiKeys?: ApiKeyStore;
  /** Echo OTP codes in responses (DEV ONLY; never in prod). */
  otpEcho?: boolean;
  /** Login front-door policy (email allowlist + confirmation gate). */
  emailPolicy?: EmailPolicy;
  /** Sends confirmation / login codes (SES). Defaults to a no-op. */
  mailer?: Mailer;
  /**
   * Public base URL for one-click confirmation links, e.g.
   * `https://auth.example.com`. There is no default: when it is absent the
   * confirmation email carries the code only, with no one-click link.
   */
  confirmUrlBase?: string;
  nowMs?: () => number;
}

function roleScopes(app: string, role: string): string[] {
  switch (role) {
    case "owner":
    case "admin":
      return [`${app}:*`];
    case "member":
    case "agent":
    case "service":
      return [`${app}:read`, `${app}:write`];
    case "viewer":
      return [`${app}:read`];
    default:
      return [`${app}:read`];
  }
}

function generateOtp(): string {
  // 6-digit numeric code.
  return String(randomBytes(4).readUInt32BE(0) % 1_000_000).padStart(6, "0");
}

function newSessionToken(): string {
  return `hst_${randomBytes(32).toString("base64url")}`;
}

export interface PrincipalSummary {
  user_id: string;
  kind: string;
  email: string | null;
  display_name: string | null;
}

export interface TenantMembershipSummary {
  tenant_id: string;
  role: string;
}

export class AuthService {
  private readonly store: IdpStoreApi;
  private readonly signingSecret: string;
  private readonly apiKeysTable: string;
  private readonly apiKeys: ApiKeyStore | undefined;
  private readonly otpEcho: boolean;
  private readonly emailPolicy: EmailPolicy;
  private readonly mailer: Mailer;
  private readonly confirmUrlBase: string | undefined;
  private readonly now: () => number;

  constructor(options: AuthServiceOptions) {
    this.store = options.store;
    this.signingSecret = options.signingSecret;
    this.apiKeysTable = options.apiKeysTable;
    this.apiKeys = options.apiKeys;
    this.otpEcho = options.otpEcho ?? false;
    // FAIL CLOSED: omitting the policy denies every address rather than opening
    // the front door. Call sites that genuinely want no gate (local/dev, tests)
    // must pass `UNRESTRICTED_EMAIL_POLICY` explicitly.
    this.emailPolicy = options.emailPolicy ?? denyAllEmailPolicy();
    this.mailer = options.mailer ?? new NoopMailer();
    this.confirmUrlBase = options.confirmUrlBase?.replace(/\/+$/, "") || undefined;
    this.now = options.nowMs ?? (() => Date.now());
  }

  /**
   * Reject any email whose domain is not on the (config-driven) allowlist.
   * An unconfigured allowlist denies everything — see `policy.ts`.
   */
  private assertEmailAllowed(email: string): void {
    const denial = checkEmailDomain(email, this.emailPolicy);
    if (denial) throw new AuthError(denial.status, denial.message, denial.code);
  }

  async jwks(): Promise<JwksDocument> {
    return buildJwks(await this.store.listPublicJwks());
  }

  // ── signup ─────────────────────────────────────────────────────────────────

  async signup(input: {
    email?: string; name?: string; kind?: string; org_name?: string; password?: string;
    ip?: string | null; userAgent?: string | null;
  }): Promise<Record<string, unknown>> {
    const email = (input.email ?? "").trim().toLowerCase();
    if (!email || !email.includes("@")) throw new AuthError(400, "A valid email is required.", "invalid_email");
    // Login front door: only allowlisted email domains may sign up.
    this.assertEmailAllowed(email);
    const kind = input.kind === "agent" ? "agent" : "human";

    if (await this.store.getUserByEmail(email)) {
      throw new AuthError(409, "An account with that email already exists.", "email_taken");
    }

    // Resolve the home tenant: a NEW org creates a child tenant (its creator is
    // the owner); joining the root tenant grants only `member` — a random signup
    // must NOT become an owner of the fleet root (fail-safe default).
    let homeTenantId = ROOT_TENANT_ID;
    let createdNewOrg = false;
    if (input.org_name && input.org_name.trim()) {
      const slug = input.org_name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
      const existing = slug ? await this.store.getTenantBySlug(slug) : null;
      if (existing) {
        homeTenantId = existing.id;
      } else {
        homeTenantId = (await this.store.createTenant({ slug: slug || `org-${newId().slice(0, 8)}`, name: input.org_name.trim(), kind: "org", parentId: ROOT_TENANT_ID })).id;
        createdNewOrg = true;
      }
    }
    const role = createdNewOrg ? "owner" : "member";

    const passwordHash = input.password ? hashPassword(input.password) : null;
    const user = await this.store.createUser({
      kind, email, displayName: input.name ?? null, homeTenantId,
      authMethod: passwordHash ? "password" : "otp", passwordHash,
    });
    await this.store.createMembership({ tenantId: homeTenantId, principalId: user.id, principalType: "user", role });

    const base = {
      user: this.principalSummary(user),
      tenant: { tenant_id: homeTenantId },
      memberships: [{ tenant_id: homeTenantId, role }],
    };

    // Confirmation gate: a fresh signup must confirm its email before ANY
    // session/token is minted — even when a password was set. We always send a
    // confirmation code (and one-click link) and return a challenge, never a
    // session. (When the gate is disabled — local/dev — a password signup
    // auto-logs-in and a password-less one still gets an OTP challenge.)
    if (this.emailPolicy.requireConfirmation) {
      const challenge = await this.startChallenge(email, "signup");
      return { ...base, ...challenge, confirmation_required: true };
    }

    if (passwordHash) {
      // Gate disabled: auto-login and return a session immediately.
      const session = await this.issueSession(user, homeTenantId, input.ip ?? null, input.userAgent ?? null, "password");
      return { ...base, ...session };
    }
    // No password → OTP challenge to complete signup.
    const challenge = await this.startChallenge(email, "signup");
    return { ...base, ...challenge };
  }

  // ── login ──────────────────────────────────────────────────────────────────

  async login(input: { email?: string; password?: string; ip?: string | null; userAgent?: string | null }): Promise<Record<string, unknown>> {
    const email = (input.email ?? "").trim().toLowerCase();
    if (!email) throw new AuthError(400, "email is required.", "invalid_email");
    // Login front door: only allowlisted email domains may log in.
    this.assertEmailAllowed(email);
    const user = await this.store.getUserByEmail(email);

    if (input.password) {
      // Password path — generic failure to avoid user enumeration.
      if (!user || !user.password_hash || !verifyPassword(input.password, user.password_hash)) {
        throw new AuthError(401, "Invalid email or password.", "invalid_credentials");
      }
      // Correct password but email never confirmed: re-issue a confirmation
      // code and refuse the session until the address is verified.
      if (this.emailPolicy.requireConfirmation && !user.email_verified_at) {
        const challenge = await this.startChallenge(email, "signup");
        throw new AuthError(
          403,
          "Confirm your email before signing in. We just re-sent your confirmation code.",
          "email_not_confirmed",
          challenge,
        );
      }
      const session = await this.issueSession(user, user.home_tenant_id ?? ROOT_TENANT_ID, input.ip ?? null, input.userAgent ?? null, "password");
      return session;
    }

    // OTP path — always return the same shape (don't leak whether the user exists).
    const challenge = await this.startChallenge(email, "login");
    return challenge;
  }

  // ── resend confirmation ──────────────────────────────────────────────────────

  async resend(input: { email?: string }): Promise<Record<string, unknown>> {
    const email = (input.email ?? "").trim().toLowerCase();
    if (!email || !email.includes("@")) throw new AuthError(400, "A valid email is required.", "invalid_email");
    this.assertEmailAllowed(email);
    // Same shape whether or not the account exists / is already confirmed
    // (no enumeration). Only send a fresh code when there is an unconfirmed user.
    const user = await this.store.getUserByEmail(email);
    if (user && !user.email_verified_at) {
      return { ...(await this.startChallenge(email, "signup")), confirmation_required: true };
    }
    return { challenge: true, purpose: "signup", expires_in: OTP_TTL_SECONDS };
  }

  // ── verify (OTP) ─────────────────────────────────────────────────────────────

  async verify(input: { email?: string; code?: string; ip?: string | null; userAgent?: string | null }): Promise<Record<string, unknown>> {
    const email = (input.email ?? "").trim().toLowerCase();
    const code = (input.code ?? "").trim();
    if (!email || !code) throw new AuthError(400, "email and code are required.", "invalid_request");
    // Re-check the front door before the step that actually mints a session: a
    // challenge issued while a domain was allowed must not still be redeemable
    // after that domain is removed from the allowlist (or the allowlist is
    // unconfigured). Every session-minting path is gated, not just the entry.
    this.assertEmailAllowed(email);

    // Try login then signup challenges.
    for (const purpose of ["login", "signup"] as const) {
      const challenge = await this.store.findActiveChallenge(email, purpose);
      if (!challenge) continue;
      if (challenge.attempts >= OTP_MAX_ATTEMPTS) throw new AuthError(429, "Too many attempts; request a new code.", "too_many_attempts");
      if (sha256(code) !== challenge.code_hash) {
        await this.store.bumpChallengeAttempts(challenge.id);
        throw new AuthError(401, "Invalid code.", "invalid_code");
      }
      await this.store.consumeChallenge(challenge.id);
      const user = await this.store.getUserByEmail(email);
      if (!user) throw new AuthError(404, "No account for that email.", "no_user");
      // A verified OTP proves control of the address → confirm it.
      if (!user.email_verified_at) await this.store.markEmailVerified(user.id);
      return this.issueSession(user, user.home_tenant_id ?? ROOT_TENANT_ID, input.ip ?? null, input.userAgent ?? null, "otp");
    }
    throw new AuthError(401, "No active challenge; request a new code.", "no_challenge");
  }

  // ── token (mint per-app credential from a session) ───────────────────────────

  async token(input: { sessionToken: string; app?: string; scopes?: string[]; tenant_id?: string; ttlSeconds?: number }): Promise<Record<string, unknown>> {
    const { user } = await this.resolveSession(input.sessionToken);
    const app = (input.app ?? "").trim();
    if (!app) throw new AuthError(400, "app is required.", "invalid_request");
    if (!FLEET_APPS.includes(app)) throw new AuthError(400, `Unknown app: ${app}`, "unknown_app");

    const memberships = await this.store.listMembershipsForPrincipal(user.id, "user");
    // Tenant is server-derived from a real membership row (never trusted from
    // the body). When the caller names a tenant they don't belong to, fail
    // closed — do NOT silently fall back to another tenant.
    let membership: MembershipRow | undefined;
    if (input.tenant_id) {
      membership = memberships.find((m) => m.tenant_id === input.tenant_id);
      if (!membership) throw new AuthError(403, "No membership for the requested tenant.", "no_membership");
    } else {
      const home = user.home_tenant_id ?? ROOT_TENANT_ID;
      membership = memberships.find((m) => m.tenant_id === home) ?? memberships[0];
    }
    if (!membership) throw new AuthError(403, "No tenant membership for this principal.", "no_membership");

    // Role grants the ceiling; a caller may only NARROW (least privilege), never
    // widen. Requested scopes must each be covered by the role-granted set.
    const granted = roleScopes(app, membership.role);
    let scope: string[];
    if (input.scopes && input.scopes.length > 0) {
      const overreach = input.scopes.filter((s) => !hasScope(granted, s));
      if (overreach.length > 0) {
        throw new AuthError(403, `Requested scopes exceed this membership's grants: ${overreach.join(", ")}`, "insufficient_scope");
      }
      scope = input.scopes;
    } else {
      scope = granted;
    }

    // TTL is caller-shrinkable but server-bounded: invalid values are rejected
    // here (400) and signAccessToken clamps anything above the 24h ceiling so a
    // caller can never mint an effectively irrevocable long-lived credential.
    if (input.ttlSeconds !== undefined && (!Number.isSafeInteger(input.ttlSeconds) || input.ttlSeconds <= 0)) {
      throw new AuthError(400, "ttlSeconds must be a positive integer.", "invalid_ttl", {
        max_ttl_seconds: MAX_ACCESS_TOKEN_TTL_SECONDS,
      });
    }

    const jti = newId();
    const signingKey = await this.store.getSigningKeyForMinting();
    const { token, claims } = signAccessToken(signingKey, {
      aud: app, sub: user.id, tid: membership.tenant_id, pt: "user", scope,
      ...(input.ttlSeconds !== undefined ? { ttlSeconds: input.ttlSeconds } : {}),
      jti, nowMs: this.now(),
    });
    // Register the jti so the token is revocable before exp (denylist on verify).
    await this.store.recordIssuedAccessToken({
      jti, userId: user.id, tenantId: membership.tenant_id, aud: app,
      expiresAt: new Date(claims.exp * 1000),
    });

    const response: Record<string, unknown> = {
      access_token: token,
      token_type: "Bearer",
      alg: "EdDSA",
      kid: signingKey.kid,
      aud: app,
      tid: membership.tenant_id,
      uid: user.id,
      pt: "user",
      scope,
      expires_in: claims.exp - claims.iat,
      // Token id — pass to POST /v1/auth/revoke to deny-list this token early.
      jti,
    };

    // Transitional: also mint a long-lived v1 HMAC key for this service's own
    // app (the only app whose signing secret it legitimately holds), and record
    // its tenant/user binding in api_keys (bridge).
    if (app === SELF_APP && this.apiKeys) {
      const minted = mintApiKey({ app: SELF_APP, scopes: scope, signingSecret: this.signingSecret, ...(user.email ? { agent: user.email } : {}) });
      await this.apiKeys.insertMinted(minted, user.email ?? undefined);
      await this.store.recordApiKeyBinding(this.apiKeysTable, {
        kid: minted.kid, tenantId: membership.tenant_id, userId: user.id, principalType: "user",
      });
      response["api_key"] = minted.token;
      response["api_key_kid"] = minted.kid;
      response["api_key_expires_at"] = minted.claims.exp ? new Date(minted.claims.exp * 1000).toISOString() : null;
    }

    return response;
  }

  // ── revoke (deny-list an issued access token before exp) ────────────────────

  /**
   * Revoke a previously minted EdDSA access token by jti. Owner-scoped: the
   * session principal may only revoke tokens minted for THEIR user id (a jti
   * belonging to someone else — or an unknown jti — returns revoked:false
   * without leaking whether it exists).
   */
  async revokeToken(input: { sessionToken: string; jti?: string }): Promise<Record<string, unknown>> {
    const { user } = await this.resolveSession(input.sessionToken);
    const jti = (input.jti ?? "").trim();
    if (!jti) throw new AuthError(400, "jti is required.", "invalid_request");
    // Minted jtis are UUIDs (newId) and the registry column is `uuid` — reject
    // any other shape here so it surfaces as a clean 400, not a raw Postgres
    // "invalid input syntax for type uuid" through the generic catch.
    if (!isUuid(jti)) throw new AuthError(400, "jti must be a UUID.", "invalid_request");
    const revoked = await this.store.revokeIssuedAccessToken(jti, user.id);
    return { revoked, jti };
  }

  /** Denylist check used by the serve layer after stateless verification. */
  async isTokenRevoked(jti: string): Promise<boolean> {
    return this.store.isAccessTokenRevoked(jti);
  }

  // ── whoami ───────────────────────────────────────────────────────────────────

  async whoami(sessionToken: string): Promise<Record<string, unknown>> {
    const { user, memberships } = await this.resolveSession(sessionToken);
    return {
      principal: this.principalSummary(user),
      tenants: memberships.map((m) => ({ tenant_id: m.tenant_id, role: m.role })),
      apps: FLEET_APPS,
    };
  }

  // ── introspect (bridge/status) ───────────────────────────────────────────────

  /**
   * Resolve a kid's tenant/user binding — TENANT-SCOPED. The caller's own
   * tenant (derived server-side from their credential, never the request) must
   * match the binding's tenant; anything else (foreign tenant, unknown kid,
   * unbound key, or an unresolvable caller tenant) fails closed as
   * `active:false` so cross-tenant kid probing leaks nothing.
   */
  async introspect(kid: string, callerTenantId: string | null): Promise<Record<string, unknown>> {
    const binding = await this.store.lookupApiKeyBinding(this.apiKeysTable, kid);
    if (!binding || !callerTenantId || binding.tenant_id !== callerTenantId) {
      return { active: false, kid };
    }
    return {
      active: true, kid,
      tenant_id: binding.tenant_id,
      user_id: binding.user_id,
      principal_type: binding.principal_type,
    };
  }

  /** Resolve the tenant a v1 API key (kid) is bound to — serve-layer caller context. */
  async tenantForApiKey(kid: string): Promise<string | null> {
    const binding = await this.store.lookupApiKeyBinding(this.apiKeysTable, kid);
    return binding?.tenant_id ?? null;
  }

  // ── internals ────────────────────────────────────────────────────────────────

  private principalSummary(user: UserRow): PrincipalSummary {
    return { user_id: user.id, kind: user.kind, email: user.email, display_name: user.display_name };
  }

  private async startChallenge(email: string, purpose: "signup" | "login"): Promise<Record<string, unknown>> {
    const code = generateOtp();
    await this.store.createChallenge({
      email, codeHash: sha256(code), purpose,
      expiresAt: new Date(this.now() + OTP_TTL_SECONDS * 1000),
    });
    const out: Record<string, unknown> = { challenge: true, purpose, expires_in: OTP_TTL_SECONDS };

    // Deliver the code + (when a public base URL is configured) a one-click
    // confirmation link over email. A mail failure must not 500 the request —
    // the code is still valid and the client can resend — so we record delivery
    // status and keep going.
    const link = this.confirmUrlBase
      ? `${this.confirmUrlBase}/v1/auth/confirm?email=${encodeURIComponent(email)}&code=${code}`
      : undefined;
    try {
      const sent = await this.mailer.sendConfirmation({
        to: email, code, ...(link ? { link } : {}), expiresMinutes: Math.round(OTP_TTL_SECONDS / 60), purpose,
      });
      if (sent.messageId) out["email_message_id"] = sent.messageId;
      out["email_sent"] = !sent.skipped;
      if (sent.skipped) out["email_skipped_reason"] = sent.reason ?? "disabled";
    } catch (error) {
      out["email_sent"] = false;
      out["email_error"] = error instanceof Error ? error.message : String(error);
    }

    if (this.otpEcho) out["dev_code"] = code; // DEV ONLY
    return out;
  }

  private async issueSession(user: UserRow, tenantId: string, ip: string | null, userAgent: string | null, method: string): Promise<Record<string, unknown>> {
    const token = newSessionToken();
    await this.store.createSession({
      userId: user.id, tenantId, tokenHash: sha256(token), method,
      expiresAt: new Date(this.now() + SESSION_TTL_SECONDS * 1000), ip, userAgent,
    });
    const memberships = await this.store.listMembershipsForPrincipal(user.id, "user");
    return {
      session: token,
      session_expires_in: SESSION_TTL_SECONDS,
      principal: this.principalSummary(user),
      tenants: memberships.map((m) => ({ tenant_id: m.tenant_id, role: m.role })),
      apps: FLEET_APPS,
    };
  }

  private async resolveSession(sessionToken: string): Promise<{ user: UserRow; memberships: MembershipRow[] }> {
    if (!sessionToken) throw new AuthError(401, "Missing session token.", "missing_session");
    const row = await this.store.getSessionByTokenHash(sha256(sessionToken));
    if (!row) throw new AuthError(401, "Invalid session.", "invalid_session");
    if (row.revoked_at) throw new AuthError(401, "Session revoked.", "revoked_session");
    if (row.expires_at && new Date(row.expires_at).getTime() < this.now()) throw new AuthError(401, "Session expired.", "expired_session");
    const user = row.user_id ? await this.store.getUserById(row.user_id) : null;
    if (!user) throw new AuthError(401, "Session principal not found.", "invalid_session");
    const memberships = await this.store.listMembershipsForPrincipal(user.id, "user");
    return { user, memberships };
  }
}
