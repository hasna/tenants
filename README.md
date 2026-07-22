# @hasna/tenants

**Hasna fleet tenant auth / IdP.** The login front door and identity provider for
the Hasna fleet: **tenants, users, memberships, service principals, sessions +
OTP/password login**, and asymmetric **EdDSA fleet-token issuance** with a
published **JWKS**. Apps across the fleet verify tenants-issued access tokens
offline against that JWKS.

> **Not to be confused with [`@hasna/identities`](https://www.npmjs.com/package/@hasna/identities).**
> `@hasna/identities` (a.k.a. *open-identities*) is the separate, healthy
> **agent-identity registry** (identity records for humans/agents, personas,
> roster, browser-plan slots). **`@hasna/tenants` is the tenant-auth / IdP
> service** and shares no code with the registry — the two domains are
> intentionally decoupled. This package was extracted from the tenant-auth work
> that had been built as a fork of the registry.

## What it does

- **Tenancy** — a fixed root tenant plus brand children (deterministic UUIDs),
  and org tenants created on signup.
- **Users & principals** — human/agent users and machine service principals,
  each with tenant memberships and roles.
- **Login front door** — signup / login restricted to hasna-branded email
  domains, with an email-confirmation gate (OTP + one-click link) delivered via
  Amazon SES.
- **Sessions & tokens** — password/OTP sessions, and per-app fleet access tokens
  (EdDSA JWS) minted from a session, scoped by membership role. Token TTL is
  server-bounded (24h ceiling — callers can only shorten it), and every minted
  `jti` is registered so a token can be revoked before its expiry
  (`POST /v1/auth/revoke`; the serve layer checks the denylist on verify).
- **JWKS** — a published `/.well-known/jwks.json` so every app verifies tokens
  offline. Keys are generated + persisted in the app's own Postgres (or injected
  via Secrets Manager).
- **API-key bridge** — issued keys are bound to a tenant/user and introspectable
  by `kid`. Introspection is tenant-scoped: bindings outside the caller's own
  tenant read as `active:false`.

## Surfaces

| Surface | Entry |
| --- | --- |
| HTTP API | `tenants-serve` (`src/server/index.ts`) — Bun.serve, cloud/PURE REMOTE |
| CLI | `tenants` (`src/cli.ts`) — thin client over the HTTP API |
| SDK | `@hasna/tenants/sdk` (`TenantsClient`) |
| Library | `@hasna/tenants` (`AuthService`, `IdpStore`, tokens, migrations, …) |

### HTTP routes

```
GET  /health | /version | /ready | /openapi.json
GET  /jwks | /v1/.well-known/jwks.json          (public)
POST /signup | /v1/auth/signup                  (public)
POST /login  | /v1/auth/login                   (public)
POST /v1/auth/verify | /v1/auth/resend          (public)
GET  /v1/auth/confirm                            (public, one-click)
POST /v1/auth/token                              (Bearer session)
POST /v1/auth/revoke                             (Bearer session, owner-scoped)
GET  /v1/auth/whoami                             (Bearer session)
GET  /v1/introspect?kid=…                        (API-key / access-token auth, tenant-scoped)
```

## Configuration (cloud mode)

| Env | Purpose |
| --- | --- |
| `HASNA_TENANTS_STORAGE_MODE=cloud` | Required (PURE REMOTE) |
| `HASNA_TENANTS_DATABASE_URL` | Postgres connection string |
| `HASNA_TENANTS_API_SIGNING_KEY` | HMAC signing secret (or `HASNA_API_SIGNING_KEY`) |
| `HASNA_TENANTS_JWT_SIGNING_KEY` / `_JWT_KID` | Optional EdDSA private JWK (Secrets Manager path) |
| `HASNA_TENANTS_ALLOWED_EMAIL_DOMAINS` | Override the hasna email allowlist |
| `HASNA_TENANTS_EMAIL_ENABLED=1` | Enable SES confirmation email |
| `HASNA_TENANTS_API_URL` | Base URL used by the `tenants` CLI |

## Develop

```bash
bun install
bun test          # unit tests (no live deps required)
bun run build     # bundle + type declarations
```

Applying the schema against a real database:

```bash
HASNA_TENANTS_STORAGE_MODE=cloud HASNA_TENANTS_DATABASE_URL=postgres://… \
  bun run src/server/index.ts migrate --dry-run
```

## License

Apache-2.0
