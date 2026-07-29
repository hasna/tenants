#!/usr/bin/env bun
// CLI for @hasna/tenants — a thin client over the tenant-auth / IdP HTTP API.
//
// Every command talks directly to the HTTP API at HASNA_TENANTS_API_URL.
// signup/login/verify/resend/jwks are unauthenticated; token/revoke/whoami use
// the returned session as a Bearer credential. introspect is the exception: the
// /v1 gate authenticates an access token or an API key, never a session.

import { getPackageVersion } from "./version.js";
import {
  ApiError,
  TenantsClient,
  type LoginInput,
  type ServicePrincipalCreateInput,
  type ServicePrincipalTokenInput,
  type SignupInput,
  type TokenInput,
} from "./sdk/client.js";

interface ParsedArgs {
  positionals: string[];
  flags: Map<string, string[]>;
}

const version = getPackageVersion();

const booleanFlags = new Set(["json", "help", "h", "version"]);

const helpText = `tenants — @hasna/tenants fleet tenant-auth / IdP client

Usage:
  tenants [--json] <command>
  tenants help | --help
  tenants version | --version

Commands:
  auth signup --email <e> [--name <n>] [--org <org>] [--password <pw>]
  auth login  --email <e> [--password <pw>]        (no password -> OTP challenge)
  auth verify --email <e> --code <code>            (confirm signup / complete an OTP challenge)
  auth confirm --email <e> --code <code>           (confirm signup via the one-click-link API route)
  auth resend --email <e>                          (re-send an email confirmation code)
  auth token  --session <s> --app <app> [--scope a --scope b] [--tenant <id>] [--ttl <seconds>]
  auth revoke --session <s> --jti <jti>            (deny-list an issued token before its expiry)
  auth whoami --session <s>
  auth jwks
  auth introspect --kid <kid> --key <accessToken|apiKey>
  principals create --key <accessToken|apiKey> [--tenant <id>] [--name <n>] [--kind <kind>] [--identity <id>]
  principals token --enrollment-secret <secret> --app <app> [--scope a --scope b] [--ttl <seconds>]
  principals disable --id <principalId> --key <accessToken|apiKey>
  version

Options:
  --json     Print help, version, and errors as JSON (API responses are always JSON)
  --help     Show this help
  --version  Print the package version

Sign-up and login are limited to the email domains the server allows; signup requires
email confirmation. Requires HASNA_TENANTS_API_URL (the tenants API base URL). Session
tokens are returned by verify/login (after confirmation).

introspect does NOT take a session: /v1/introspect authenticates an access token or an
API key. Exchange a session first —
  tenants auth token --session <s> --app tenants   (then pass access_token as --key)
`;

const principalsHelpText = `tenants principals — service-principal enrollment and tokens

Usage:
  tenants principals <command>

  principals create --key <accessToken|apiKey> [--tenant <id>] [--name <n>] [--kind <kind>] [--identity <id>]
  principals token --enrollment-secret <secret> --app <app> [--scope a --scope b] [--ttl <seconds>]
  principals disable --id <principalId> --key <accessToken|apiKey>

create and disable require a tenants:write fleet credential. create returns the
enrollment secret once; store it securely. token exchanges that secret for a
short-lived fleet access token with pt=service.`;

const authHelpText = `tenants auth — fleet tenant-auth / IdP client

Usage:
  tenants auth <command>

  auth signup --email <e> [--name <n>] [--org <org>] [--password <pw>]
  auth login  --email <e> [--password <pw>]        (no password -> OTP challenge)
  auth verify --email <e> --code <code>            (confirm signup / complete an OTP challenge)
  auth confirm --email <e> --code <code>           (confirm signup via the one-click-link API route)
  auth resend --email <e>                          (re-send an email confirmation code)
  auth token  --session <s> --app <app> [--scope a --scope b] [--tenant <id>] [--ttl <seconds>]
  auth revoke --session <s> --jti <jti>            (deny-list an issued token before its expiry)
  auth whoami --session <s>
  auth jwks
  auth introspect --kid <kid> --key <accessToken|apiKey>

Run \`tenants auth help\` to show this page without contacting the API.

Sign-up and login are limited to the email domains the server allows; signup requires
email confirmation. Requires HASNA_TENANTS_API_URL. Session tokens are returned by
verify/login (after confirmation).

introspect does NOT take a session: /v1/introspect authenticates an access token or an
API key. Exchange a session first —
  tenants auth token --session <s> --app tenants   (then pass access_token as --key)`;

/** Refusal for `auth introspect --session`: the server can never honour it. */
const SESSION_NOT_ACCEPTED =
  "auth introspect does not accept --session: /v1/introspect authenticates an access token or an API key. " +
  "Mint one with `tenants auth token --session <s> --app tenants`, then pass its access_token as --key.";

/**
 * Run one CLI invocation and RETURN its exit code (0 ok, 1 failed).
 *
 * The status is returned rather than written to `process.exitCode` so a caller —
 * notably the test suite — never has to mutate global process state. Bun ignores
 * `process.exitCode = undefined`, so a single leaked 1 would otherwise persist
 * for the whole run and fail `bun test` with no reported failure.
 */
export async function runCli(argv = process.argv.slice(2)): Promise<number> {
  const parsed = parseArgs(argv);
  const json = hasFlag(parsed, "json");
  try {
    await dispatch(parsed, json);
  } catch (error) {
    if (json) {
      console.log(JSON.stringify({ error: errorMessage(error) }, null, 2));
    } else {
      console.error(errorMessage(error));
    }
    return 1;
  }
  return 0;
}

async function dispatch(parsed: ParsedArgs, json: boolean): Promise<void> {
  const [command, ...rest] = parsed.positionals;

  if (command === "version" || hasFlag(parsed, "version")) {
    if (json) output({ version }, true);
    else console.log(version);
    return;
  }

  if (!command || command === "help" || hasFlag(parsed, "help") || hasFlag(parsed, "h")) {
    output(helpText, json);
    return;
  }

  if (command === "auth") {
    await dispatchAuth(rest, parsed, json);
    return;
  }

  if (command === "principals") {
    await dispatchPrincipals(rest, parsed, json);
    return;
  }

  throw new Error(`Unknown command: ${command}`);
}

async function dispatchPrincipals(rest: string[], parsed: ParsedArgs, json: boolean): Promise<void> {
  const [subcommand] = rest;
  if (!subcommand || subcommand === "help") {
    output(principalsHelpText, json);
    return;
  }

  const apiUrl = (process.env["HASNA_TENANTS_API_URL"] ?? "").replace(/\/+$/, "");
  if (!apiUrl) {
    throw new Error("Set HASNA_TENANTS_API_URL to the tenants API base URL (e.g. https://auth.example.com).");
  }

  if (subcommand === "create") {
    const key = required(flagValue(parsed, "key"), "principals create requires --key <accessToken|apiKey>");
    const body: ServicePrincipalCreateInput = {};
    if (flagValue(parsed, "tenant")) body["tenant_id"] = flagValue(parsed, "tenant");
    if (flagValue(parsed, "name")) body["display_name"] = flagValue(parsed, "name");
    if (flagValue(parsed, "kind")) body["kind"] = flagValue(parsed, "kind");
    if (flagValue(parsed, "identity")) body["identity_id"] = flagValue(parsed, "identity");
    output(await new TenantsClient({ baseUrl: apiUrl, apiKey: key }).createServicePrincipal(body), true);
    return;
  }
  if (subcommand === "token") {
    const body: ServicePrincipalTokenInput = {
      enrollment_secret: required(
        flagValue(parsed, "enrollment-secret"),
        "principals token requires --enrollment-secret",
      ),
      app: required(flagValue(parsed, "app"), "principals token requires --app"),
    };
    const scopes = flagValues(parsed, "scope");
    if (scopes.length > 0) body["scopes"] = scopes;
    if (flagValue(parsed, "ttl")) body["ttlSeconds"] = Number(flagValue(parsed, "ttl"));
    output(await new TenantsClient({ baseUrl: apiUrl }).issueServicePrincipalToken(body), true);
    return;
  }
  if (subcommand === "disable") {
    const principalId = required(flagValue(parsed, "id"), "principals disable requires --id");
    const key = required(flagValue(parsed, "key"), "principals disable requires --key <accessToken|apiKey>");
    output(await new TenantsClient({ baseUrl: apiUrl, apiKey: key }).disableServicePrincipal(principalId), true);
    return;
  }
  throw new Error(`Unknown principals command: ${subcommand}`);
}

async function dispatchAuth(rest: string[], parsed: ParsedArgs, json: boolean): Promise<void> {
  const [subcommand] = rest;
  if (!subcommand || subcommand === "help") {
    output(authHelpText, json);
    return;
  }

  const apiUrl = (process.env["HASNA_TENANTS_API_URL"] ?? "").replace(/\/+$/, "");
  if (!apiUrl) {
    throw new Error("Set HASNA_TENANTS_API_URL to the tenants API base URL (e.g. https://auth.example.com).");
  }
  const client = new TenantsClient({ baseUrl: apiUrl });
  const bearer = (token: string): RequestInit => ({ headers: { Authorization: `Bearer ${token}` } });

  if (subcommand === "jwks") {
    output(await client.getJwks(), true);
    return;
  }
  if (subcommand === "signup") {
    const body: SignupInput = { email: required(flagValue(parsed, "email"), "auth signup requires --email") };
    if (flagValue(parsed, "name")) body["name"] = flagValue(parsed, "name");
    if (flagValue(parsed, "org")) body["org_name"] = flagValue(parsed, "org");
    if (flagValue(parsed, "password")) body["password"] = flagValue(parsed, "password");
    output(await client.signup(body), true);
    return;
  }
  if (subcommand === "login") {
    const body: LoginInput = { email: required(flagValue(parsed, "email"), "auth login requires --email") };
    if (flagValue(parsed, "password")) body["password"] = flagValue(parsed, "password");
    output(await client.login(body), true);
    return;
  }
  if (subcommand === "verify") {
    const body = {
      email: required(flagValue(parsed, "email"), "auth verify requires --email"),
      code: required(flagValue(parsed, "code"), "auth verify requires --code"),
    };
    output(await client.verifyOtp(body), true);
    return;
  }
  if (subcommand === "confirm") {
    const query = {
      email: required(flagValue(parsed, "email"), "auth confirm requires --email"),
      code: required(flagValue(parsed, "code"), "auth confirm requires --code"),
    };
    output(await client.confirm(query), true);
    return;
  }
  if (subcommand === "resend") {
    const body = { email: required(flagValue(parsed, "email"), "auth resend requires --email") };
    output(await client.resendConfirmation(body), true);
    return;
  }
  if (subcommand === "token") {
    const session = required(flagValue(parsed, "session"), "auth token requires --session");
    const body: TokenInput = { app: required(flagValue(parsed, "app"), "auth token requires --app") };
    const scopes = flagValues(parsed, "scope");
    if (scopes.length > 0) body["scopes"] = scopes;
    if (flagValue(parsed, "tenant")) body["tenant_id"] = flagValue(parsed, "tenant");
    // Server-bounded: values above the 24h ceiling are clamped by the API.
    if (flagValue(parsed, "ttl")) body["ttlSeconds"] = Number(flagValue(parsed, "ttl"));
    output(await client.issueToken(body, bearer(session)), true);
    return;
  }
  if (subcommand === "revoke") {
    const session = required(flagValue(parsed, "session"), "auth revoke requires --session");
    const body = { jti: required(flagValue(parsed, "jti"), "auth revoke requires --jti") };
    output(await client.revokeToken(body, bearer(session)), true);
    return;
  }
  if (subcommand === "whoami") {
    const session = required(flagValue(parsed, "session"), "auth whoami requires --session");
    output(await client.whoami(bearer(session)), true);
    return;
  }
  if (subcommand === "introspect") {
    const kid = required(flagValue(parsed, "kid"), "auth introspect requires --kid");
    // The /v1 gate authenticates an EdDSA access token or an HMAC API key only.
    // A session token (hst_…) is neither, so the server refuses it outright —
    // offering --session here would advertise a request that can only ever 401.
    if (flagValue(parsed, "session")) throw new Error(SESSION_NOT_ACCEPTED);
    const key = required(flagValue(parsed, "key"), "auth introspect requires --key <accessToken|apiKey>");
    const introspectClient = new TenantsClient({ baseUrl: apiUrl, apiKey: key });
    output(await introspectClient.introspect({ kid }), true);
    return;
  }
  throw new Error(`Unknown auth command: ${subcommand}`);
}

// ── arg parsing / output helpers ─────────────────────────────────────────────

function parseArgs(args: string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags = new Map<string, string[]>();
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]!;
    if (!arg.startsWith("--")) {
      positionals.push(arg);
      continue;
    }
    const key = arg.slice(2);
    if (booleanFlags.has(key)) {
      flags.set(key, [...(flags.get(key) ?? []), "true"]);
      continue;
    }
    const next = args[index + 1];
    if (!next || next.startsWith("--")) throw new Error(`Missing value for --${key}`);
    index += 1;
    flags.set(key, [...(flags.get(key) ?? []), next]);
  }
  return { positionals, flags };
}

function hasFlag(args: ParsedArgs, key: string): boolean {
  return args.flags.has(key);
}

function flagValue(args: ParsedArgs, key: string): string | undefined {
  const value = args.flags.get(key)?.[0];
  return value === "true" ? undefined : value;
}

function flagValues(args: ParsedArgs, key: string): string[] {
  return (args.flags.get(key) ?? []).filter((value) => value !== "true");
}

function required<T>(value: T | undefined, message: string): T {
  if (value === undefined || value === "") throw new Error(message);
  return value;
}

function output(data: unknown, json: boolean): void {
  if (json || typeof data !== "string") console.log(JSON.stringify(data, null, 2));
  else console.log(data);
}

/** Cap on server-supplied detail: enough to diagnose, not a whole error page. */
const MAX_ERROR_DETAIL = 500;

function truncate(value: string): string {
  return value.length > MAX_ERROR_DETAIL ? `${value.slice(0, MAX_ERROR_DETAIL)}… (truncated)` : value;
}

/**
 * Render whatever the server sent alongside a non-2xx status.
 *
 * The body is NEVER discarded: an ALB, Cloudflare or nginx in front of the API
 * answers with HTML, and a rate limiter may answer with JSON carrying no `error`
 * key at all. Dropping those leaves an operator with a bare status code and no
 * diagnostics, which is the one thing this CLI exists to surface.
 */
function errorDetail(body: unknown): string | undefined {
  if (body === undefined || body === null) return undefined;
  if (typeof body === "string") return truncate(body.trim()) || undefined;
  if (typeof body === "object") {
    const record = body as Record<string, unknown>;
    if (typeof record["error"] === "string") {
      const reason = typeof record["reason"] === "string" ? ` (${record["reason"]})` : "";
      return truncate(`${record["error"]}${reason}`);
    }
    return truncate(JSON.stringify(body));
  }
  return truncate(String(body));
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    const detail = errorDetail(error.body);
    return detail ? `${error.message}: ${detail}` : error.message;
  }
  return error instanceof Error ? error.message : String(error);
}

if (import.meta.main) {
  process.exitCode = await runCli();
}
