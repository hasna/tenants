// HTTP API for @hasna/tenants (cloud / PURE REMOTE).
//
// Surfaces:
//   GET  /health                    liveness (process up)
//   GET  /ready                     readiness (DB reachable + schema migrated)
//   GET  /version                   { status, version, mode }
//   GET  /openapi.json              the OpenAPI document backing the generated SDK
//   POST /signup|/login             public login front door (aliases of /v1/auth/*)
//   /v1/auth/*                      public IdP: signup/login/verify/confirm/resend/token/revoke/whoami
//   GET  /jwks, /v1/.well-known/... public JWKS (EdDSA) for offline token verification
//   GET  /v1/introspect            authenticated, TENANT-SCOPED tenant/user binding lookup
//
// Auth uses the canonical @hasna/contracts API-key kit (verifyApiKey) plus the
// service's own EdDSA access tokens (verified via JWKS), so the serve process is
// framework-agnostic and runs on Bun.serve directly.

import { ApiKeyStore, extractToken, hasAllScopes, verifyApiKey, type ApiKeyVerifier } from "@hasna/contracts/auth";
import type { PoolQueryClient } from "../generated/storage-kit/index.js";
import { createCloudClient, cloudHealth, cloudReady } from "../db.js";
import { getPackageVersion } from "../version.js";
import { buildOpenApiDocument } from "./openapi.js";
import { IdpStore } from "../idp/store.js";
import { AuthService, AuthError } from "../idp/service.js";
import { verifyAccessToken, looksLikeAccessToken, type JwkPublic } from "../idp/tokens.js";
import { API_KEYS_TABLE } from "../migrations.js";
import { emailPolicyFromEnv } from "../idp/policy.js";
import { createMailerFromEnv, confirmUrlBaseFromEnv } from "../idp/mailer.js";

export const TENANTS_SERVE_APP = "tenants";
const DEFAULT_PORT = 15460;
const JWKS_CACHE_TTL_MS = 60_000;

export interface ServeOptions {
  port?: number;
  host?: string;
  /** Provide a pre-built cloud client (tests). Otherwise built from env. */
  client?: PoolQueryClient;
  /** Called on process close to release the pool (tests may omit). */
  close?: () => Promise<void>;
  /** Override the HMAC signing secret. Defaults to env. */
  signingSecret?: string;
  /** Called on each auth decision for the AUDIT trail. */
  audit?: (event: unknown) => void;
  /** Provide a pre-built IdP auth service (tests). Otherwise built from env. */
  auth?: AuthService;
}

export interface RunningServer {
  port: number;
  hostname: string;
  stop: () => Promise<void>;
}

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function resolveSigningSecret(explicit?: string): string {
  const secret =
    explicit ||
    process.env["HASNA_TENANTS_API_SIGNING_KEY"] ||
    process.env["HASNA_API_SIGNING_KEY"];
  if (!secret) {
    throw new Error(
      "Missing API signing secret. Set HASNA_TENANTS_API_SIGNING_KEY (or HASNA_API_SIGNING_KEY).",
    );
  }
  return secret;
}

interface Handler {
  client: PoolQueryClient;
  close: () => Promise<void>;
  verifier: ApiKeyVerifier;
  keys: ApiKeyStore;
  auth: AuthService;
  /** Cached JWKS public keys for token verification (short TTL). */
  getJwks: () => Promise<JwkPublic[]>;
  version: string;
}

async function readJsonBody(req: Request): Promise<any> {
  const text = await req.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(400, "Invalid JSON body");
  }
}

class HttpError extends Error {
  constructor(public status: number, message: string, public reason?: string) {
    super(message);
  }
}

/** The authenticated caller, as derived server-side from their credential. */
interface CallerContext {
  /** Tenant the caller's credential is bound to (null when unresolvable). */
  tenantId: string | null;
}

type AuthOutcome = { failure: Response; caller?: never } | { failure?: never; caller: CallerContext };

async function authenticate(h: Handler, req: Request, requiredScopes: string[]): Promise<AuthOutcome> {
  const url = new URL(req.url);

  // v2 (end state): a tenants-signed EdDSA access token verified via JWKS.
  const raw = extractToken(req.headers);
  if (raw && looksLikeAccessToken(raw)) {
    const jwks = await h.getJwks();
    const result = verifyAccessToken(raw, { jwks, expectedAudience: TENANTS_SERVE_APP });
    if (!result.ok) return { failure: json({ error: `access token ${result.reason}`, reason: result.reason }, 401) };
    // Revocation denylist: a signature-valid, unexpired token that was revoked
    // (POST /v1/auth/revoke) must be refused — exp alone is not the boundary.
    if (result.claims.jti && (await h.auth.isTokenRevoked(result.claims.jti))) {
      return { failure: json({ error: "access token revoked", reason: "revoked" }, 401) };
    }
    if (requiredScopes.length > 0 && !hasAllScopes(result.claims.scope ?? [], requiredScopes)) {
      return { failure: json({ error: "insufficient_scope", reason: "insufficient_scope" }, 403) };
    }
    return { caller: { tenantId: result.claims.tid ?? null } };
  }

  // v1 (transition): the LOCKED @hasna/contracts per-app HMAC token.
  const decision = await h.verifier.authenticate(req.headers, {
    method: req.method,
    path: url.pathname,
    requiredScopes,
  });
  if (decision.ok) {
    // Tenant context comes from the key's recorded binding (api_keys bridge).
    return { caller: { tenantId: await h.auth.tenantForApiKey(decision.principal.kid) } };
  }
  return { failure: json({ error: decision.message, reason: decision.reason }, decision.status) };
}

/** Authenticated tenant-admin surface (currently: key introspection). */
async function handleV1(h: Handler, req: Request, url: URL): Promise<Response> {
  const method = req.method.toUpperCase();
  const segments = url.pathname.split("/").filter(Boolean); // ["v1", "introspect", ...]
  const resource = segments[1];

  const scope = method === "GET" ? "tenants:read" : "tenants:write";
  const outcome = await authenticate(h, req, [scope]);
  if (outcome.failure) return outcome.failure;

  try {
    if (resource === "introspect" && segments.length === 2 && method === "GET") {
      const kid = url.searchParams.get("kid");
      if (!kid) throw new HttpError(400, "kid query parameter is required", "invalid_request");
      // Tenant-scoped: the binding is only revealed inside the caller's tenant.
      return json(await h.auth.introspect(kid, outcome.caller.tenantId));
    }
    throw new HttpError(404, `No route for ${method} ${url.pathname}`, "not_found");
  } catch (error) {
    if (error instanceof HttpError) {
      return json({ error: error.message, reason: error.reason }, error.status);
    }
    const message = error instanceof Error ? error.message : String(error);
    return json({ error: message }, 400);
  }
}

function sessionTokenFrom(req: Request, body: any): string {
  const authz = req.headers.get("authorization");
  if (authz && /^Bearer\s+/i.test(authz)) {
    const token = authz.replace(/^Bearer\s+/i, "").trim();
    // Only treat it as a session token (not an app access token / api key).
    if (token.startsWith("hst_")) return token;
  }
  if (body && typeof body.session === "string") return body.session;
  return "";
}

/**
 * Public IdP surface (unauthenticated signup/login/verify + JWKS; session-bearer
 * token/whoami). Returns null when the request is not an auth/JWKS route.
 */
async function handleAuth(h: Handler, req: Request, url: URL): Promise<Response | null> {
  const path = url.pathname;
  const method = req.method.toUpperCase();

  // JWKS — always public (apps fetch public keys to verify tokens offline).
  if (method === "GET" && (path === "/jwks" || path === "/.well-known/jwks.json" || path === "/v1/.well-known/jwks.json")) {
    const jwks = await h.auth.jwks();
    return json(jwks, 200, { "cache-control": "public, max-age=600" });
  }

  const isAuthRoute =
    path === "/signup" || path === "/login" ||
    path.startsWith("/v1/auth/");
  if (!isAuthRoute) return null;

  try {
    if (method === "POST" && (path === "/signup" || path === "/v1/auth/signup")) {
      const body = await readJsonBody(req);
      return json(await h.auth.signup({ ...body, ip: null, userAgent: req.headers.get("user-agent") }), 201);
    }
    if (method === "POST" && (path === "/login" || path === "/v1/auth/login")) {
      const body = await readJsonBody(req);
      return json(await h.auth.login({ ...body, ip: null, userAgent: req.headers.get("user-agent") }));
    }
    if (method === "POST" && path === "/v1/auth/verify") {
      const body = await readJsonBody(req);
      return json(await h.auth.verify({ ...body, ip: null, userAgent: req.headers.get("user-agent") }));
    }
    // One-click confirmation link target (GET) — confirms the email and opens a
    // session, same as POST /v1/auth/verify but from the email link.
    if (method === "GET" && path === "/v1/auth/confirm") {
      const email = url.searchParams.get("email") ?? undefined;
      const code = url.searchParams.get("code") ?? undefined;
      return json(await h.auth.verify({ email, code, ip: null, userAgent: req.headers.get("user-agent") }));
    }
    if (method === "POST" && path === "/v1/auth/resend") {
      const body = await readJsonBody(req);
      return json(await h.auth.resend({ email: body.email }));
    }
    if (method === "POST" && path === "/v1/auth/token") {
      const body = await readJsonBody(req);
      return json(await h.auth.token({ ...body, sessionToken: sessionTokenFrom(req, body) }));
    }
    // Revoke an issued access token by jti (owner-scoped, session-authenticated).
    if (method === "POST" && path === "/v1/auth/revoke") {
      const body = await readJsonBody(req);
      return json(await h.auth.revokeToken({ jti: body.jti, sessionToken: sessionTokenFrom(req, body) }));
    }
    if (method === "GET" && path === "/v1/auth/whoami") {
      return json(await h.auth.whoami(sessionTokenFrom(req, null)));
    }
    return json({ error: `No auth route for ${method} ${path}`, reason: "not_found" }, 404);
  } catch (error) {
    if (error instanceof AuthError) {
      return json({ error: error.message, reason: error.code, ...(error.details ?? {}) }, error.status);
    }
    if (error instanceof HttpError) {
      return json({ error: error.message, reason: error.reason }, error.status);
    }
    const message = error instanceof Error ? error.message : String(error);
    return json({ error: message }, 400);
  }
}

export async function buildHandler(options: ServeOptions = {}): Promise<Handler> {
  let client: PoolQueryClient;
  let close: () => Promise<void>;
  if (options.client) {
    client = options.client;
    close = options.close ?? (async () => undefined);
  } else {
    const cloud = createCloudClient();
    client = cloud.client;
    close = cloud.close;
  }
  const signingSecret = resolveSigningSecret(options.signingSecret);
  const keys = new ApiKeyStore(client);
  const verifier = verifyApiKey({
    app: TENANTS_SERVE_APP,
    signingSecret,
    isRevoked: keys.isRevoked,
    ...(options.audit ? { audit: options.audit as any } : {}),
  });

  const idpStore = new IdpStore(client);
  const auth = options.auth ?? new AuthService({
    store: idpStore,
    signingSecret,
    apiKeysTable: API_KEYS_TABLE,
    apiKeys: keys,
    otpEcho: process.env["HASNA_TENANTS_OTP_ECHO"] === "1",
    // Login front door: email allowlist + confirmation gate + SES delivery.
    emailPolicy: emailPolicyFromEnv(),
    mailer: createMailerFromEnv(),
    confirmUrlBase: confirmUrlBaseFromEnv(),
  });

  // Short-TTL JWKS cache so verification is a hot-path memory read, not a DB hit
  // per request (honors `kid` rotation on the next refresh).
  let cached: { keys: JwkPublic[]; at: number } | null = null;
  const getJwks = async (): Promise<JwkPublic[]> => {
    const now = Date.now();
    if (cached && now - cached.at < JWKS_CACHE_TTL_MS) return cached.keys;
    const fresh = (await auth.jwks()).keys;
    cached = { keys: fresh, at: now };
    return fresh;
  };

  return { client, close, verifier, keys, auth, getJwks, version: getPackageVersion() };
}

export async function createFetchHandler(options: ServeOptions = {}): Promise<{
  handler: Handler;
  fetch: (req: Request) => Promise<Response>;
}> {
  const handler = await buildHandler(options);
  const openapi = buildOpenApiDocument(handler.version);

  const fetch = async (req: Request): Promise<Response> => {
    const url = new URL(req.url);
    const path = url.pathname;

    if (path === "/health") {
      return json({ status: "ok", version: handler.version, mode: "cloud" });
    }
    if (path === "/version") {
      return json({ status: "ok", version: handler.version, mode: "cloud" });
    }
    if (path === "/ready") {
      const ready = await cloudReady(handler.client);
      return json(
        {
          status: ready.ok ? "ok" : "degraded",
          version: handler.version,
          mode: "cloud",
          latencyMs: ready.latencyMs,
          pendingMigrations: ready.pendingMigrations,
          ...(ready.error ? { error: ready.error } : {}),
        },
        ready.ok ? 200 : 503,
      );
    }
    if (path === "/openapi.json") {
      return json(openapi);
    }
    if (path === "/") {
      return json({ name: "@hasna/tenants", status: "ok", version: handler.version, mode: "cloud" });
    }
    // Public IdP surface (signup/login/verify/token/whoami + JWKS) — handled
    // before the authenticated /v1 gate.
    const authResponse = await handleAuth(handler, req, url);
    if (authResponse) return authResponse;
    if (path.startsWith("/v1/") || path === "/v1") {
      return handleV1(handler, req, url);
    }
    return json({ error: `Not found: ${path}` }, 404);
  };

  return { handler, fetch };
}

export async function startServer(options: ServeOptions = {}): Promise<RunningServer> {
  const port = options.port ?? (Number(process.env["PORT"]) || DEFAULT_PORT);
  const host = options.host ?? process.env["HOST"] ?? "0.0.0.0";
  const { fetch, handler } = await createFetchHandler(options);

  const server = Bun.serve({ port, hostname: host, fetch });
  // Prove the DB path early (does not block liveness).
  cloudHealth(handler.client).catch(() => undefined);

  return {
    port: server.port ?? port,
    hostname: host,
    stop: async () => {
      server.stop(true);
      await handler.close().catch(() => undefined);
    },
  };
}
