# Library and SDK

## Package Exports

| Import | Main exports |
| --- | --- |
| `@hasna/tenants` | `AuthService`, `IdpStore`, policy/mailer/token helpers, IDs, migrations, database helpers, OpenAPI, and embeddable server handlers |
| `@hasna/tenants/sdk` | `TenantsClient`, request/response interfaces, and `ApiError` |
| `@hasna/tenants/db` | PostgreSQL client, health/readiness, and migration runner |
| `@hasna/tenants/migrations` | `API_KEYS_TABLE` and the ordered migration set |

The root package intentionally exports low-level domain and storage APIs for
services that embed the IdP rather than running the binaries.

## SDK Client

```ts
import { TenantsClient } from "@hasna/tenants/sdk";

const client = new TenantsClient({
  baseUrl: "https://auth.example.com",
  headers: { "x-request-source": "example" },
});

const challenge = await client.login({ email: "user@example.com" });
const session = await client.verifyOtp({
  email: "user@example.com",
  code: "123456",
});
```

Constructor options:

- `baseUrl` is required and has one trailing slash removed.
- `apiKey` adds an `x-api-key` header to every request; use a separate client
  instance for key-authenticated introspection.
- `fetch` replaces global `fetch`, which is useful for tests or instrumentation.
- `headers` adds base headers; per-call `RequestInit.headers` overrides them.

Every method accepts an optional `RequestInit`. Session routes need an explicit
bearer header:

```ts
const init = {
  headers: { Authorization: `Bearer ${session.session}` },
};

const token = await client.issueToken(
  { app: "todos", scopes: ["todos:read"], ttlSeconds: 3600 },
  init,
);
```

For non-2xx responses, the SDK throws `ApiError` with `status`, a method/path
message, and `body`. Bodies are parsed as JSON when possible and retained as text
otherwise.

## Introspection Client

```ts
const introspection = new TenantsClient({
  baseUrl: "https://auth.example.com",
  apiKey: token.access_token,
});

const binding = await introspection.introspect({ kid: "api-key-kid" });
```

The provided credential must be a `tenants`-audience access token with
`tenants:read` or a transitional HMAC API key. A session is not valid.

## Stateless Token Verification

```ts
import { verifyAccessToken } from "@hasna/tenants";

const result = verifyAccessToken(token.access_token!, {
  jwks: jwks.keys,
  expectedAudience: "todos",
});

if (!result.ok) throw new Error(result.reason);
```

`verifyAccessToken` checks compact-JWS shape, EdDSA algorithm/signature, key ID,
the fixed fleet issuer, optional audience, expiry, and issued-at time. It is
stateless by itself. A verifier that needs prompt revocation can add the IdP
lookup after a successful local check:

```ts
if (result.ok) {
  const status = await client.introspectAccessToken({ jti: result.claims.jti });
  if (!status.active) throw new Error("token inactive");
}
```

The status endpoint returns `active:false` for unknown, expired, or revoked
IDs and is marked `no-store`. It does not replace signature, issuer, or audience
verification. Consumers that stay fully offline may still accept a revoked
token until its maximum 24-hour expiry.

## Embedding the HTTP Handler

```ts
import { createFetchHandler } from "@hasna/tenants";

const { fetch, handler } = await createFetchHandler();
const server = Bun.serve({ port: 15460, fetch });

// During shutdown:
server.stop(true);
await handler.close();
```

`createFetchHandler` builds Postgres, auth, API-key verification, and the route
handler from the environment. Tests can inject `client`, `close`, `signingSecret`,
`audit`, or a pre-built `AuthService`. `startServer` wraps the same handler and
returns `{ port, hostname, stop }`.

## Database and Migrations

```ts
import {
  createTenantsDatabase,
  runTenantsMigrations,
  databaseReady,
} from "@hasna/tenants/db";

const db = createTenantsDatabase({ applicationName: "example-service" });
try {
  await runTenantsMigrations(db.client);
  const ready = await databaseReady(db.client);
  if (!ready.ok) throw new Error("tenant schema is not ready");
} finally {
  await db.close();
}
```

`runTenantsMigrations` applies schema only. The binary's `migrate` command also
runs `seedAndBackfill`; embedders that need identical bootstrap behavior should
call that exported helper after a non-dry-run migration.
