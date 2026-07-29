# @hasna/tenants

**Hasna fleet tenant auth / IdP.** This package owns tenants, users,
memberships, service principals, sessions, OTP/password login, Ed25519 access
tokens, and the public JWKS used to verify those tokens.

It is separate from `@hasna/identities`, the agent-identity registry. Tenants is
the authentication and tenancy authority; it does not contain the identities
document store or identity CRUD API.

## What It Does

- Seeds a deterministic fleet root tenant and brand tenants; signup can create
  or join an organization tenant.
- Restricts signup, login, OTP verification, and session-authenticated actions
  to an exact-match email-domain allowlist that fails closed when unconfigured.
- Requires email confirmation by default and can deliver signup/login OTPs and
  one-click links directly through Amazon SES.
- Issues 24-hour sessions and per-app EdDSA access tokens. Membership roles set
  the scope ceiling, while callers may request narrower scopes and shorter TTLs.
- Publishes Ed25519 public keys as JWKS. Signing keys can be injected through the
  environment or generated once and persisted in Postgres.
- Registers every access-token `jti` for owner-scoped early revocation. The
  tenants HTTP service checks this denylist; offline JWKS consumers cannot see
  revocations and may accept a revoked token until its bounded expiry.
- Optionally returns a transitional HMAC API key when minting a token for the
  `tenants` audience. Those keys carry tenant/user bindings that can be queried
  through tenant-scoped introspection.

## Install

```bash
bun add @hasna/tenants
```

The package requires Bun 1.0 or newer. Running the service also requires a
PostgreSQL database, configured with `HASNA_TENANTS_DATABASE_URL`. PostgreSQL is
the only data backend this package implements; there is no SQLite implementation
and no deployment-mode variable to set.

## Surfaces

| Surface | Entry |
| --- | --- |
| HTTP API | `tenants-serve` — Bun HTTP service over PostgreSQL |
| CLI | `tenants` — thin client over the HTTP API |
| SDK | `@hasna/tenants/sdk` — `TenantsClient` |
| Library | `@hasna/tenants` — auth service, store, tokens, server helpers, and migrations |
| Database | `@hasna/tenants/db` and `@hasna/tenants/migrations` |

## Quick Start

Apply migrations and the idempotent seed/backfill:

```bash
export HASNA_TENANTS_DATABASE_URL='postgres://user:password@localhost:5432/tenants'
export HASNA_TENANTS_API_SIGNING_KEY="$(openssl rand -hex 32)"
export HASNA_TENANTS_ALLOWED_EMAIL_DOMAINS='example.com'
export HASNA_TENANTS_OTP_ECHO=1 # development only; returns dev_code

tenants-serve migrate
tenants-serve --port 15460
```

In another shell, point the client at the service:

```bash
export HASNA_TENANTS_API_URL='http://127.0.0.1:15460'

tenants auth signup --email user@example.com --password 'choose-a-password'
tenants auth verify --email user@example.com --code 123456
tenants auth token --session hst_… --app todos --scope todos:read
```

Signup returns a challenge rather than a session while confirmation is enabled.
Use the development-only `dev_code` (or the code received by email when SES is
configured) with `auth verify`; `auth confirm` calls the same verification flow
through the one-click-link GET route. Never enable OTP echo in production.

## CLI

```text
tenants [--json] <command>

tenants auth signup --email <e> [--name <n>] [--org <org>] [--password <pw>]
tenants auth login --email <e> [--password <pw>]
tenants auth verify --email <e> --code <code>
tenants auth confirm --email <e> --code <code>
tenants auth resend --email <e>
tenants auth token --session <s> --app <app> [--scope <scope>]... [--tenant <id>] [--ttl <seconds>]
tenants auth revoke --session <s> --jti <jti>
tenants auth whoami --session <s>
tenants auth jwks
tenants auth introspect --kid <kid> --key <access-token-or-api-key>
tenants version
```

`auth introspect` does not accept a session. Mint a `tenants`-audience access
token first, then pass its `access_token` as `--key`. See [CLI usage](docs/cli.md)
for command behavior, output, and examples.

## HTTP API

Canonical application routes:

```text
GET  /v1/.well-known/jwks.json                    public
POST /v1/auth/signup                             public
POST /v1/auth/login                              public
POST /v1/auth/verify                             public
GET  /v1/auth/confirm?email=…&code=…              public
POST /v1/auth/resend                             public
POST /v1/auth/token                              Bearer session
POST /v1/auth/revoke                             Bearer session
GET  /v1/auth/whoami                             Bearer session
GET  /v1/introspect?kid=…                        access token or API key
```

The service also exposes `/`, `/health`, `/ready`, `/version`, and
`/openapi.json`. Compatibility aliases are available for `/signup`, `/login`,
`/jwks`, and `/.well-known/jwks.json`. See [HTTP API](docs/http-api.md) for
request shapes, authentication, roles, token behavior, and errors.

## Configuration

The minimum service configuration is:

| Environment variable | Purpose |
| --- | --- |
| `HASNA_TENANTS_DATABASE_URL` | PostgreSQL connection string — the only backend selector |
| `HASNA_TENANTS_API_SIGNING_KEY` | HMAC secret; `HASNA_API_SIGNING_KEY` is the fallback |
| `HASNA_TENANTS_ALLOWED_EMAIL_DOMAINS` | Comma-separated exact domains; unset or empty denies all front-door activity |

Email delivery, signing-key injection, TLS, developer switches, port/host, and
CLI settings are documented in [Configuration](docs/configuration.md).

The allowlist is exact and case-insensitive. Listing `example.com` does not
permit `mail.example.com`. If both an allowlist and
`HASNA_TENANTS_DISABLE_EMAIL_ALLOWLIST=1` are set, the configured allowlist wins.

## Library and SDK

```ts
import { TenantsClient } from "@hasna/tenants/sdk";

const client = new TenantsClient({
  baseUrl: process.env.HASNA_TENANTS_API_URL!,
});

const jwks = await client.getJwks();
```

See [Library and SDK](docs/library.md) for package exports, custom fetch/header
configuration, server embedding, migration helpers, and stateless token
verification.

## Develop

```bash
bun install
bun run typecheck
bun test
bun run build
```

Run the complete release gate with:

```bash
bun run verify:release
```

The release gate typechecks, tests, builds, and scans the actual npm packed file
set for private infrastructure, domain, and credential literals. The same scan
runs from `prepack`; publishing with `--ignore-scripts` bypasses lifecycle hooks,
so releases should use `bun run verify:release` first.

## License

Apache-2.0
