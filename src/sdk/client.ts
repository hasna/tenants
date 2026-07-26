// Typed client for the @hasna/tenants HTTP API (the tenant-auth / IdP surface).
// Mirrors the OpenAPI document in src/server/openapi.ts.

export interface ErrorResponse { "error": string; "reason"?: string }

export interface SignupInput { "email": string; "name"?: string; "kind"?: "human" | "agent"; "org_name"?: string; "password"?: string }

export interface LoginInput { "email": string; "password"?: string }

export interface VerifyInput { "email": string; "code": string }

export interface ResendInput { "email": string }

/** ttlSeconds is server-bounded: values above the 24h ceiling are clamped; non-positive/non-integer values are rejected. */
export interface TokenInput { "app": string; "scopes"?: Array<string>; "tenant_id"?: string; "ttlSeconds"?: number }

export interface RevokeInput { "jti": string; "session"?: string }

export interface RevokeResponse { "revoked": boolean; "jti": string }

export interface AuthResponse { "session"?: string; "session_expires_in"?: number; "challenge"?: boolean; "purpose"?: string; "expires_in"?: number; "confirmation_required"?: boolean; "email_sent"?: boolean; "email_message_id"?: string; "principal"?: Record<string, unknown>; "tenants"?: Array<Record<string, unknown>>; "apps"?: Array<string> }

export interface TokenResponse { "access_token"?: string; "token_type"?: string; "alg"?: string; "kid"?: string; "aud"?: string; "tid"?: string; "uid"?: string; "pt"?: string; "scope"?: Array<string>; "expires_in"?: number; "jti"?: string; "api_key"?: string }

export interface WhoamiResponse { "principal"?: Record<string, unknown>; "tenants"?: Array<Record<string, unknown>>; "apps"?: Array<string> }

export interface IntrospectResponse { "active"?: boolean; "kid"?: string; "tenant_id"?: string; "user_id"?: string; "principal_type"?: string }

export interface Jwks { "keys": Array<Record<string, unknown>> }

export interface TenantsClientOptions {
  /** Base URL, e.g. process.env.HASNA_TENANTS_API_URL. */
  baseUrl: string;
  /** API key, e.g. process.env.HASNA_TENANTS_API_KEY. Sent as the 'x-api-key' header. */
  apiKey?: string;
  /** Custom fetch (defaults to global fetch). */
  fetch?: typeof fetch;
  /** Extra headers merged into every request. */
  headers?: Record<string, string>;
}

export class ApiError extends Error {
  constructor(readonly status: number, message: string, readonly body: unknown) {
    super(message);
    this.name = "ApiError";
  }
}

export class TenantsClient {
  private readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly fetchImpl: typeof fetch;
  private readonly baseHeaders: Record<string, string>;

  constructor(options: TenantsClientOptions) {
    if (!options.baseUrl) throw new Error("TenantsClient requires a baseUrl.");
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.apiKey = options.apiKey;
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    this.baseHeaders = options.headers ?? {};
  }

  private async request<T>(method: string, path: string, opts: { body?: unknown; query?: Record<string, unknown>; init?: RequestInit }): Promise<T> {
    const url = new URL(this.baseUrl + path);
    if (opts.query) {
      for (const [key, value] of Object.entries(opts.query)) {
        if (value !== undefined && value !== null) url.searchParams.set(key, String(value));
      }
    }
    const headers: Record<string, string> = { Accept: "application/json", ...this.baseHeaders, ...(opts.init?.headers as Record<string, string> | undefined) };
    if (this.apiKey) headers["x-api-key"] = this.apiKey;
    let payload: BodyInit | undefined;
    if (opts.body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(opts.body);
    }
    const response = await this.fetchImpl(url.toString(), { ...opts.init, method, headers, body: payload });
    const text = await response.text();
    const data = text ? (() => { try { return JSON.parse(text); } catch { return text; } })() : undefined;
    if (!response.ok) {
      throw new ApiError(response.status, `${method} ${path} failed: ${response.status}`, data);
    }
    return data as T;
  }

  /** Public JWKS (EdDSA) for verifying tenants-issued fleet tokens. */
  async getJwks(init?: RequestInit): Promise<Jwks> {
    return this.request("GET", `/v1/.well-known/jwks.json`, { body: undefined, query: undefined, init });
  }

  /** Create a tenant/user (allowlisted email domains only) and send an email confirmation code. */
  async signup(body: SignupInput, init?: RequestInit): Promise<AuthResponse> {
    return this.request("POST", `/v1/auth/signup`, { body, query: undefined, init });
  }

  /** Log in with password (session) or request an OTP challenge. */
  async login(body: LoginInput, init?: RequestInit): Promise<AuthResponse> {
    return this.request("POST", `/v1/auth/login`, { body, query: undefined, init });
  }

  /** Verify an OTP code and open a session. */
  async verifyOtp(body: VerifyInput, init?: RequestInit): Promise<AuthResponse> {
    return this.request("POST", `/v1/auth/verify`, { body, query: undefined, init });
  }

  /** Confirm an email via the one-click link (email + code) and open a session. */
  async confirm(query?: { "email": string; "code": string }, init?: RequestInit): Promise<AuthResponse> {
    return this.request("GET", `/v1/auth/confirm`, { body: undefined, query, init });
  }

  /** Re-send the email confirmation code for an unconfirmed account. */
  async resendConfirmation(body: ResendInput, init?: RequestInit): Promise<AuthResponse> {
    return this.request("POST", `/v1/auth/resend`, { body, query: undefined, init });
  }

  /** Mint a per-app fleet access token from a session (Bearer session). */
  async issueToken(body: TokenInput, init?: RequestInit): Promise<TokenResponse> {
    return this.request("POST", `/v1/auth/token`, { body, query: undefined, init });
  }

  /** Revoke an issued access token by jti before its expiry (Bearer session; owner-scoped). */
  async revokeToken(body: RevokeInput, init?: RequestInit): Promise<RevokeResponse> {
    return this.request("POST", `/v1/auth/revoke`, { body, query: undefined, init });
  }

  /** Resolve the session principal + tenant memberships. */
  async whoami(init?: RequestInit): Promise<WhoamiResponse> {
    return this.request("GET", `/v1/auth/whoami`, { body: undefined, query: undefined, init });
  }

  /** Introspect an issued key by kid (tenant/user binding + status). Tenant-scoped: bindings outside the caller's tenant report active:false. */
  async introspect(query?: { "kid": string }, init?: RequestInit): Promise<IntrospectResponse> {
    return this.request("GET", `/v1/introspect`, { body: undefined, query, init });
  }
}
