# Configuration

## Service Requirements

`tenants-serve` always opens cloud Postgres. Although the vendored storage kit
understands a generic `local` mode, this package does not implement local SQLite
storage and refuses to start unless the resolved mode is `cloud`.

| Environment variable | Required | Behavior |
| --- | --- | --- |
| `HASNA_TENANTS_STORAGE_MODE` | Yes | Must be `cloud`; deprecated `remote`, `hybrid`, and `self_hosted` values normalize to `cloud` |
| `HASNA_TENANTS_DATABASE_URL` | Yes | Postgres connection string; `TENANTS_DATABASE_URL` is a lower-priority compatibility alias |
| `HASNA_TENANTS_API_SIGNING_KEY` | Yes | HMAC secret for transitional `tenants` API keys |
| `HASNA_API_SIGNING_KEY` | Fallback | Used only when the tenants-specific signing key is absent |
| `PORT` | No | Server port, default `15460`; `--port` overrides it |
| `HOST` | No | Bind host, default `0.0.0.0`; `--host` overrides it |

The storage-mode alias `TENANTS_STORAGE_MODE` is also recognized after the
canonical variable. Omitting storage mode resolves to generic `local`, which the
service then rejects.

## Email Front Door

| Environment variable | Default | Behavior |
| --- | --- | --- |
| `HASNA_TENANTS_ALLOWED_EMAIL_DOMAINS` | Empty | Comma-separated exact domains; empty denies all signup, login, verification, resend, and session-authenticated activity |
| `HASNA_TENANTS_DISABLE_EMAIL_ALLOWLIST` | Off | Exactly `1` accepts every domain only when no allowlist is configured |
| `HASNA_TENANTS_REQUIRE_EMAIL_CONFIRMATION` | On | Exactly `0` disables the confirmation gate |
| `HASNA_TENANTS_OTP_ECHO` | Off | Exactly `1` adds `dev_code` to challenge responses; development only |

Domains are trimmed, lowercased, and matched exactly. Subdomains are not
implied. If both an allowlist and the disable switch are present, the allowlist
wins so a stale development override cannot silently open a configured service.

With confirmation disabled, password signup returns a session immediately;
passwordless signup still creates an OTP challenge. Disabling confirmation does
not disable the allowlist.

## SES Delivery

Email is inert unless explicitly enabled. Challenges remain valid when delivery
is disabled or an SES send fails; the response reports `email_sent:false` and a
skip/error detail.

| Environment variable | Required | Behavior |
| --- | --- | --- |
| `HASNA_TENANTS_EMAIL_ENABLED` | No | Exactly `1` enables direct SESv2 delivery |
| `HASNA_TENANTS_MAIL_FROM` | With email | DKIM-verified envelope sender |
| `HASNA_TENANTS_CONFIRM_URL_BASE` | With email | Public deployment base URL used for one-click links; trailing slashes are removed |
| `HASNA_TENANTS_SES_REGION` | No | SES region; falls back to `AWS_REGION`, then `us-east-1` |
| `HASNA_TENANTS_SES_FROM_ARN` | No | Cross-account SES sender identity ARN |

AWS credentials resolve from `AWS_ACCESS_KEY_ID` plus
`AWS_SECRET_ACCESS_KEY` (and optional `AWS_SESSION_TOKEN`), or from ECS container
credentials using `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or
`AWS_CONTAINER_CREDENTIALS_FULL_URI`. The optional
`AWS_CONTAINER_AUTHORIZATION_TOKEN` is forwarded to that credentials endpoint.

Enabling email without either the sender or confirmation URL causes startup to
fail before the server accepts requests.

## EdDSA Signing Keys

| Environment variable | Default | Behavior |
| --- | --- | --- |
| `HASNA_TENANTS_JWT_SIGNING_KEY` | None | Private Ed25519 JWK as JSON or base64url-encoded JSON; wins for minting |
| `HASNA_TENANTS_JWT_KID` | JWK `kid` or `env` | Published `kid` for the injected key |

Without an injected key, migration creates an active Ed25519 key in
`jwt_signing_keys`; runtime also creates one on demand if needed. JWKS publishes
the injected public key plus every active database public key, which supports a
rotation overlap. Database-backed private keys are currently stored as JWK JSON.

## Postgres TLS

TLS follows connection-string `sslmode` semantics:

| `sslmode` | Behavior |
| --- | --- |
| absent, `disable`, `prefer` | No explicit forced TLS configuration |
| `require` | Encrypt without certificate verification |
| `verify-ca`, `verify-full` | Encrypt and verify against a required CA bundle |

For verification, provide the CA inline when embedding the library, by path via
`PGSSLROOTCERT`, or through `NODE_EXTRA_CA_CERTS`. `ssl=true` is treated as
`sslmode=require`.

## CLI

| Environment variable | Required | Behavior |
| --- | --- | --- |
| `HASNA_TENANTS_API_URL` | For auth commands | Base URL for all `tenants auth …` HTTP requests; trailing slashes are removed |

The CLI has no implicit localhost default.

## Migration Command

```bash
tenants-serve migrate
tenants-serve migrate --dry-run
```

Migration uses a checksum-guarded `schema_migrations` ledger. A normal run
applies pending schema changes, seeds deterministic root/brand tenants, ensures
an active database signing key, binds legacy API keys to the root tenant, and
marks legacy enrollment users as email-confirmed. `--dry-run` reports the plan
and skips seed/backfill, but it may create the migration ledger table while
reading the plan.
