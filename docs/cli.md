# CLI

The `tenants` binary is a thin HTTP client. Every auth command requires
`HASNA_TENANTS_API_URL`; local help and version output do not.

## Global Usage

```text
tenants [--json] <command>
tenants help
tenants --help
tenants version
tenants --version
tenants auth help
```

`--json` formats help as a JSON string, version output as `{ "version": "…" }`,
and errors as `{ "error": "…" }`. Successful API responses are always printed
as formatted JSON. A failed command exits with status 1; success exits with 0.

Flags use `--name value` syntax. Repeating `--scope` builds a scope array. The
parser does not support short flags or `--name=value`.

## Authentication Flow

### Sign Up

```text
tenants auth signup --email <e> [--name <n>] [--org <org>] [--password <pw>]
```

`--org` maps to the API's `org_name`. A new organization slug creates a child
tenant and gives its creator the `owner` role. An existing organization is
joined as `member`; signup without `--org` joins the fleet root as `member`.

With confirmation enabled (the default), signup always returns a signup
challenge and no session, even when a password was supplied.

### Verify or Confirm

```text
tenants auth verify --email <e> --code <code>
tenants auth confirm --email <e> --code <code>
tenants auth resend --email <e>
```

`verify` posts the OTP. `confirm` sends the same email/code pair to the GET route
used by one-click email links. A successful verification confirms the address
and returns a 24-hour `hst_…` session. Codes expire after 10 minutes and allow at
most five failed attempts. `resend` deliberately prints the same fixed body —
`{"challenge":true,"purpose":"signup","expires_in":600}` — for unknown,
already-confirmed, and unconfirmed addresses to avoid enumeration, so it never
echoes a `dev_code` even when OTP echo is on.

### Log In

```text
tenants auth login --email <e> [--password <pw>]
```

With a password, a confirmed account receives a session immediately. Without a
password, login creates an OTP challenge and `verify` completes the flow. An
unconfirmed password login is rejected and sends a fresh signup-confirmation
challenge.

## Session Commands

### Mint a Token

```text
tenants auth token --session <s> --app <app> \
  [--scope <scope>]... [--tenant <id>] [--ttl <seconds>]
```

Supported app slugs are `tenants`, `identities`, `todos`, `skills`,
`conversations`, `mementos`, `hooks`, `telephony`, `infinity`, `sandboxes`,
`domains`, `accounts`, `files`, `sessions`, `secrets`, `projects`, and
`knowledge`.

If `--tenant` is omitted, the user's home membership is preferred. A named
tenant must match an active membership. Role grants are:

| Role | Default scopes for app `APP` |
| --- | --- |
| `owner`, `admin` | `APP:*` |
| `member`, `agent`, `service` | `APP:read`, `APP:write` |
| `viewer` or unknown | `APP:read` |

Requested scopes can only narrow those grants. `--ttl` must be a positive
integer; the server honors shorter values and clamps larger values to 86,400
seconds. The response includes the EdDSA `access_token`, its claims, expiry, and
revocable UUID `jti`. For `--app tenants`, it can also include a transitional
`api_key`, `api_key_kid`, and `api_key_expires_at`.

### Revoke a Token

```text
tenants auth revoke --session <s> --jti <jti>
```

The `jti` must be a UUID. Revocation is owner-scoped: another user's or an
unknown token returns `revoked:false`. The tenants service rejects a revoked
access token on its own authenticated `/v1` routes. Apps doing offline JWKS-only
verification do not consult this denylist and may accept it until expiry.

### Inspect the Session

```text
tenants auth whoami --session <s>
```

Returns the principal, active tenant memberships, and supported fleet app slugs.
Session-authenticated calls re-check the current email allowlist, so removing a
domain immediately prevents existing users from using `whoami`, minting tokens,
or revoking tokens through that session.

## Keys and Introspection

```text
tenants auth jwks
tenants auth introspect --kid <kid> --key <access-token-or-api-key>
```

`jwks` is public but still needs the configured API base URL in the CLI.

`introspect` authenticates with either a `tenants`-audience EdDSA access token or
a transitional HMAC API key. A session is never accepted. The caller needs
`tenants:read`; mint a suitable credential with:

```bash
tenants auth token --session hst_… --app tenants --scope tenants:read
```

Introspection looks up a transitional API-key binding by `kid`. It is not JWT
introspection and does not query a token `jti`. A binding is returned only when
its tenant matches the authenticated caller; foreign, unknown, or unbound keys
return `{ "active": false, "kid": "…" }`.

## Service Principals

```text
tenants principals create --key <access-token-or-api-key> \
  [--tenant <id>] [--name <name>] [--kind <kind>] [--identity <id>]
tenants principals token --enrollment-secret <secret> --app <app> \
  [--scope <scope>]... [--ttl <seconds>]
tenants principals disable --id <principal-id> --key <access-token-or-api-key>
```

`create` and `disable` require a `tenants:write` credential. `create` scopes the
principal to the credential's tenant and prints its enrollment secret once;
store that value securely. `token` exchanges the secret for a bounded EdDSA
access token carrying `pt: "service"`. `disable` destroys the enrollment
credential so it cannot mint another token.

## Error Output

The CLI includes the server's JSON error/reason or non-JSON proxy body after the
HTTP status. Response details are capped at 500 characters. Use `--json` when a
caller needs a stable machine-readable error envelope.
