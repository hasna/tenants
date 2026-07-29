# HTTP API

The service uses JSON request and response bodies and runs directly on
`Bun.serve`. `/openapi.json` describes the canonical application routes; health
routes and compatibility aliases are documented here.

## Operational Routes

| Method and path | Behavior |
| --- | --- |
| `GET /` | Service name, status, version, and `backend: "postgresql"` |
| `GET /health` | Process liveness; does not wait for a database probe |
| `GET /ready` | Database/schema readiness, latency, and pending migration IDs; returns 503 when degraded |
| `GET /version` | Status, package version, and data backend |
| `GET /openapi.json` | OpenAPI 3.1 document |

## Authentication

- **Public:** JWKS, signup, login, verify, confirm, resend, and service-principal
  enrollment-secret exchange.
- **Session:** token, revoke, and whoami accept `Authorization: Bearer hst_…`.
  Token and revoke also accept a `session` property in the JSON body, but bearer
  authentication is preferred and is what the CLI sends.
- **Fleet credential:** `/v1/introspect` accepts either a `tenants`-audience
  EdDSA access token in `Authorization: Bearer …` or a transitional HMAC API key
  accepted by the contracts auth kit (including `x-api-key`). It requires
  `tenants:read` for GET requests.
- **Fleet credential:** creating and disabling service principals use the same
  gate with `tenants:write`; the principal is always scoped to the caller's
  tenant.

All `/v1` access tokens are verified for EdDSA signature, fixed issuer,
`aud=tenants`, timestamps, required scopes, non-empty `jti`, and local revocation
status. HMAC keys are checked by the canonical API-key verifier and revocation
store.

## Public Auth Routes

### `POST /v1/auth/signup`

Compatibility alias: `POST /signup`.

```json
{
  "email": "user@example.com",
  "name": "Example User",
  "kind": "human",
  "org_name": "Example Org",
  "password": "optional password"
}
```

Only `email` is required. `kind` is `agent` only when explicitly set to that
value; all other values become `human`. A new normalized organization slug
creates a child tenant and an owner membership. Existing organizations and the
root tenant grant `member`.

The default confirmation policy returns HTTP 201 with user/tenant/membership
details plus a 10-minute signup challenge. It never returns a session until the
email is verified.

### `POST /v1/auth/login`

Compatibility alias: `POST /login`.

```json
{ "email": "user@example.com", "password": "optional" }
```

A valid password for a confirmed user returns a 24-hour session. Without a
password, the route always returns a generic login challenge so account
existence is not disclosed. Correct credentials for an unconfirmed user return
403 `email_not_confirmed` and issue a fresh signup challenge.

### `POST /v1/auth/verify`

```json
{ "email": "user@example.com", "code": "123456" }
```

Consumes the newest active login or signup challenge, marks the email verified,
and opens a session. Codes are six digits, expire after 10 minutes, and permit
five failed attempts.

### `GET /v1/auth/confirm`

Query parameters: required `email` and `code`. This is the one-click-link form
of verify and returns the same session response.

### `POST /v1/auth/resend`

```json
{ "email": "user@example.com" }
```

Creates a new signup challenge — and sends the email — only for an existing
unconfirmed account. That is a side effect: the response body is the fixed
constant below, byte-identical for unknown, already-confirmed, and unconfirmed
addresses, so this unauthenticated route reveals no account state. Unlike
`signup`, it never returns `confirmation_required`, `email_sent`,
`email_skipped_reason`, or `dev_code`.

```json
{ "challenge": true, "purpose": "signup", "expires_in": 600 }
```

## Session Routes

### `POST /v1/auth/token`

```json
{
  "app": "todos",
  "scopes": ["todos:read"],
  "tenant_id": "optional membership UUID",
  "ttlSeconds": 3600
}
```

`app` must be one of the fleet app slugs listed by `whoami`. The tenant is
resolved from active membership, never trusted from the request. Requested
scopes may narrow but not exceed role grants. TTL defaults to and is capped at
86,400 seconds; non-positive or non-integer values return 400 `invalid_ttl`.

The response includes a bearer access token and these claims/metadata:

```json
{
  "access_token": "…",
  "token_type": "Bearer",
  "alg": "EdDSA",
  "kid": "…",
  "aud": "todos",
  "tid": "tenant UUID",
  "uid": "user UUID",
  "pt": "user",
  "scope": ["todos:read"],
  "expires_in": 3600,
  "jti": "token UUID"
}
```

For `app: "tenants"`, the response can additionally contain `api_key`,
`api_key_kid`, and `api_key_expires_at` when the service has an API-key store.

### `POST /v1/auth/revoke`

```json
{ "jti": "token UUID" }
```

Returns `{ "revoked": true|false, "jti": "…" }`. The caller can revoke only
their own registered token; unknown or foreign IDs do not reveal existence.
Malformed non-UUID IDs return 400 `invalid_request`.

Revocation is enforced by this service when a token is used on its `/v1`
surface. Offline consumers cannot query the denylist and continue to rely on the
token's bounded expiry.

### `GET /v1/auth/whoami`

Returns the session principal, active memberships, and supported fleet app
slugs.

## Service Principals

### `POST /v1/principals`

Requires a `tenants`-audience access token or API key with `tenants:write`.
Creates a service principal and `service` membership in the authenticated
credential's tenant. An optional `tenant_id` is only an assertion and must match
that tenant.

```json
{ "display_name": "Build agent", "kind": "machine", "identity_id": "optional external id" }
```

The response returns an `hse_…` `enrollment_secret` once. The database stores
only its SHA-256 digest in `enrollment_secret_ref`; callers must put the returned
secret in their credential store.

### `POST /v1/principals/token`

```json
{
  "enrollment_secret": "hse_…",
  "app": "todos",
  "scopes": ["todos:read"],
  "ttlSeconds": 3600
}
```

Exchanges an active principal's enrollment secret for an EdDSA token whose
claims contain the service-principal ID as `sub` and `pt: "service"`. Scope and
TTL narrowing follows the user token rules. No session or fleet credential is
required in addition to the enrollment secret.

### `POST /v1/principals/{principalId}/disable`

Requires `tenants:write` and only affects a principal in the caller's tenant.
It sets the principal and membership to disabled and destroys the stored
enrollment-secret digest. Existing service tokens are immediately rejected on
this service's stateful `/v1` gate; offline JWKS consumers may accept them until
their bounded expiry.

## JWKS and Introspection

### `GET /v1/.well-known/jwks.json`

Compatibility aliases: `GET /jwks` and `GET /.well-known/jwks.json`.

Returns `{ "keys": [...] }` and `Cache-Control: public, max-age=600`. Keys are
Ed25519 OKP JWKs with `use: "sig"` and `alg: "EdDSA"`.

### `GET /v1/introspect?kid=…`

Looks up the tenant/user binding for a transitional HMAC API key `kid`. This is
not OAuth token introspection and does not accept a session or `jti`.

The binding is returned only when its tenant equals the authenticated caller's
tenant:

```json
{
  "active": true,
  "kid": "…",
  "tenant_id": "…",
  "user_id": "…",
  "principal_type": "user"
}
```

Unknown, unbound, foreign-tenant, or unresolvable bindings return
`{ "active": false, "kid": "…" }` without leaking binding details.

## Errors

Errors are JSON with at least `error` and usually a stable `reason`:

```json
{ "error": "Invalid session.", "reason": "invalid_session" }
```

Auth routes map `AuthError` statuses directly. Malformed JSON returns 400.
Unknown auth routes return 404, and authenticated `/v1` routes enforce read
scopes for GET and write scopes for other methods before route dispatch.
