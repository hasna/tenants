// OpenAPI 3.1 description of the @hasna/tenants HTTP API. This is the
// single source of truth for both the running server routes and the generated
// SDK. It describes ONLY the tenant-auth / IdP surface: signup / login / verify /
// confirm / resend / token / whoami / JWKS / introspection. (The agent-identity CRUD
// surface lives in the separate @hasna/identities package and is NOT here.)

import { MAX_ACCESS_TOKEN_TTL_SECONDS } from "../idp/tokens.js";

export function buildOpenApiDocument(version: string) {
  return {
    openapi: "3.1.0",
    info: {
      title: "Tenants API",
      version,
      description:
        "Hasna fleet tenant auth / IdP: tenants, users, memberships, service principals, sessions, and asymmetric (EdDSA) fleet token issuance with a published JWKS. All reads and writes hit the service PostgreSQL database directly.",
    },
    servers: [{ url: "/" }],
    components: {
      securitySchemes: {
        SessionBearer: {
          type: "http",
          scheme: "bearer",
          description: "Opaque hst_ session returned by login or OTP verification.",
        },
        FleetAccessToken: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description: "EdDSA access token with aud=tenants and the required tenants scope.",
        },
        ApiKeyAuth: {
          type: "apiKey",
          in: "header",
          name: "x-api-key",
          description: "Transitional HMAC API key with the required tenants scope.",
        },
      },
      schemas: {
        ErrorResponse: {
          type: "object",
          properties: { error: { type: "string" }, reason: { type: "string" } },
          required: ["error"],
        },
        SignupInput: {
          type: "object",
          additionalProperties: true,
          properties: {
            email: { type: "string" },
            name: { type: "string" },
            kind: { type: "string", enum: ["human", "agent"] },
            org_name: { type: "string" },
            password: { type: "string" },
          },
          required: ["email"],
        },
        LoginInput: {
          type: "object",
          additionalProperties: true,
          properties: { email: { type: "string" }, password: { type: "string" } },
          required: ["email"],
        },
        VerifyInput: {
          type: "object",
          properties: { email: { type: "string" }, code: { type: "string" } },
          required: ["email", "code"],
        },
        ResendInput: {
          type: "object",
          properties: { email: { type: "string" } },
          required: ["email"],
        },
        TokenInput: {
          type: "object",
          additionalProperties: true,
          properties: {
            app: { type: "string" },
            scopes: { type: "array", items: { type: "string" } },
            tenant_id: { type: "string" },
            ttlSeconds: {
              type: "integer",
              minimum: 1,
              maximum: MAX_ACCESS_TOKEN_TTL_SECONDS,
              description:
                `Requested token lifetime in seconds. Server-bounded: values above the ceiling (${MAX_ACCESS_TOKEN_TTL_SECONDS}s = 24h) are clamped; non-positive/non-integer values are rejected (invalid_ttl).`,
            },
          },
          required: ["app"],
        },
        RevokeInput: {
          type: "object",
          properties: { jti: { type: "string" }, session: { type: "string" } },
          required: ["jti"],
        },
        RevokeResponse: {
          type: "object",
          properties: { revoked: { type: "boolean" }, jti: { type: "string" } },
          required: ["revoked", "jti"],
        },
        TokenIntrospectionInput: {
          type: "object",
          properties: { jti: { type: "string", format: "uuid" } },
          required: ["jti"],
        },
        TokenIntrospectionResponse: {
          type: "object",
          properties: { active: { type: "boolean" }, jti: { type: "string", format: "uuid" } },
          required: ["active", "jti"],
        },
        AuthResponse: {
          type: "object",
          additionalProperties: true,
          properties: {
            session: { type: "string" },
            session_expires_in: { type: "integer" },
            challenge: { type: "boolean" },
            purpose: { type: "string" },
            expires_in: { type: "integer" },
            confirmation_required: { type: "boolean" },
            email_sent: { type: "boolean" },
            email_message_id: { type: "string" },
            email_skipped_reason: { type: "string" },
            email_error: { type: "string" },
            dev_code: { type: "string", description: "Present only when HASNA_TENANTS_OTP_ECHO=1 (development only)." },
            user: { type: "object", additionalProperties: true },
            tenant: { type: "object", additionalProperties: true },
            memberships: { type: "array", items: { type: "object", additionalProperties: true } },
            principal: { type: "object", additionalProperties: true },
            tenants: { type: "array", items: { type: "object", additionalProperties: true } },
            apps: { type: "array", items: { type: "string" } },
          },
        },
        TokenResponse: {
          type: "object",
          additionalProperties: true,
          properties: {
            access_token: { type: "string" },
            token_type: { type: "string" },
            alg: { type: "string" },
            kid: { type: "string" },
            aud: { type: "string" },
            tid: { type: "string" },
            uid: { type: "string" },
            pt: { type: "string" },
            scope: { type: "array", items: { type: "string" } },
            expires_in: { type: "integer" },
            jti: { type: "string", description: "Token id — pass to POST /v1/auth/revoke to deny-list the token before exp." },
            api_key: { type: "string" },
            api_key_kid: { type: "string" },
            api_key_expires_at: { type: ["string", "null"] },
          },
        },
        WhoamiResponse: {
          type: "object",
          additionalProperties: true,
          properties: {
            principal: { type: "object", additionalProperties: true },
            tenants: { type: "array", items: { type: "object", additionalProperties: true } },
            apps: { type: "array", items: { type: "string" } },
          },
        },
        IntrospectResponse: {
          type: "object",
          additionalProperties: true,
          properties: {
            active: { type: "boolean" },
            kid: { type: "string" },
            tenant_id: { type: "string" },
            user_id: { type: "string" },
            principal_type: { type: "string" },
          },
        },
        Jwks: {
          type: "object",
          properties: { keys: { type: "array", items: { type: "object", additionalProperties: true } } },
          required: ["keys"],
        },
      },
    },
    paths: {
      "/v1/.well-known/jwks.json": {
        get: {
          operationId: "getJwks",
          summary: "Public JWKS (EdDSA) for verifying tenants-issued fleet tokens",
          security: [],
          responses: {
            "200": { description: "OK", content: { "application/json": { schema: { $ref: "#/components/schemas/Jwks" } } } },
          },
        },
      },
      "/v1/auth/signup": {
        post: {
          operationId: "signup",
          summary: "Create a tenant/user (allowlisted email domains only) and send an email confirmation code",
          security: [],
          requestBody: jsonBody("SignupInput"),
          responses: jsonResponse("AuthResponse", "201"),
        },
      },
      "/v1/auth/login": {
        post: {
          operationId: "login",
          summary: "Log in with password (session) or request an OTP challenge",
          security: [],
          requestBody: jsonBody("LoginInput"),
          responses: jsonResponse("AuthResponse"),
        },
      },
      "/v1/auth/verify": {
        post: {
          operationId: "verifyOtp",
          summary: "Verify an OTP code and open a session",
          security: [],
          requestBody: jsonBody("VerifyInput"),
          responses: jsonResponse("AuthResponse"),
        },
      },
      "/v1/auth/confirm": {
        get: {
          operationId: "confirm",
          summary: "Confirm an email via the one-click link (email + code) and open a session",
          security: [],
          parameters: [
            { name: "email", in: "query", required: true, schema: { type: "string" } },
            { name: "code", in: "query", required: true, schema: { type: "string" } },
          ],
          responses: jsonResponse("AuthResponse"),
        },
      },
      "/v1/auth/resend": {
        post: {
          operationId: "resendConfirmation",
          summary: "Re-send the email confirmation code for an unconfirmed account",
          security: [],
          requestBody: jsonBody("ResendInput"),
          responses: jsonResponse("AuthResponse"),
        },
      },
      "/v1/auth/token": {
        post: {
          operationId: "issueToken",
          summary: "Mint a per-app fleet access token from a session (Bearer session)",
          security: [{ SessionBearer: [] }],
          requestBody: jsonBody("TokenInput"),
          responses: jsonResponse("TokenResponse"),
        },
      },
      "/v1/auth/revoke": {
        post: {
          operationId: "revokeToken",
          summary:
            "Revoke an issued access token by jti before its expiry (Bearer session; owner-scoped)",
          security: [{ SessionBearer: [] }],
          requestBody: jsonBody("RevokeInput"),
          responses: jsonResponse("RevokeResponse"),
        },
      },
      "/v1/auth/introspect": {
        post: {
          operationId: "introspectAccessToken",
          summary:
            "Check whether a locally verified access-token jti is registered, unexpired, and not revoked",
          description:
            "Public revocation-status lookup for JWKS verifiers. This does not verify a token or authenticate a caller; verify signature, issuer, audience, and claims locally before submitting the verified jti. Unknown, expired, and revoked ids all return active:false.",
          security: [],
          requestBody: jsonBody("TokenIntrospectionInput"),
          responses: jsonResponse("TokenIntrospectionResponse"),
        },
      },
      "/v1/auth/whoami": {
        get: {
          operationId: "whoami",
          summary: "Resolve the session principal + tenant memberships",
          security: [{ SessionBearer: [] }],
          responses: jsonResponse("WhoamiResponse"),
        },
      },
      "/v1/introspect": {
        get: {
          operationId: "introspect",
          summary:
            "Introspect an issued key by kid (tenant/user binding + status). Tenant-scoped: bindings outside the caller's own tenant report active:false.",
          security: [{ FleetAccessToken: [] }, { ApiKeyAuth: [] }],
          parameters: [{ name: "kid", in: "query", required: true, schema: { type: "string" } }],
          responses: jsonResponse("IntrospectResponse"),
        },
      },
    },
  };
}

function jsonBody(schema: string) {
  return {
    required: true,
    content: { "application/json": { schema: { $ref: `#/components/schemas/${schema}` } } },
  };
}

function jsonResponse(schema: string, status = "200") {
  return {
    [status]: {
      description: "OK",
      content: { "application/json": { schema: { $ref: `#/components/schemas/${schema}` } } },
    },
    "400": errorResponse(),
    "401": errorResponse(),
    "403": errorResponse(),
    "404": errorResponse(),
  };
}

function errorResponse() {
  return {
    description: "Error",
    content: { "application/json": { schema: { $ref: "#/components/schemas/ErrorResponse" } } },
  };
}

export type TenantsOpenApiDocument = ReturnType<typeof buildOpenApiDocument>;
