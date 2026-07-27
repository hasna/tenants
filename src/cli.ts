#!/usr/bin/env bun
// CLI for @hasna/tenants — a thin client over the tenant-auth / IdP HTTP API.
//
// Every command talks directly to the HTTP API at HASNA_TENANTS_API_URL.
// signup/login/verify/resend/jwks are unauthenticated; token/whoami/introspect
// use the returned session as a Bearer credential or an API key as x-api-key.

import { getPackageVersion } from "./version.js";
import { ApiError, TenantsClient, type LoginInput, type SignupInput, type TokenInput } from "./sdk/client.js";

interface ParsedArgs {
  positionals: string[];
  flags: Map<string, string[]>;
}

const version = getPackageVersion();

const booleanFlags = new Set(["json", "help", "h", "version"]);

const helpText = `tenants — @hasna/tenants fleet tenant-auth / IdP client

Usage:
  tenants [--json] <command>

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
  auth introspect --kid <kid> --session <s>|--key <apiKey>
  version

Sign-up and login are limited to the email domains the server allows; signup requires
email confirmation. Requires HASNA_TENANTS_API_URL (the tenants API base URL). Session
tokens are returned by verify/login (after confirmation).
`;

const authHelpText = `tenants auth — fleet tenant-auth / IdP client

  auth signup --email <e> [--name <n>] [--org <org>] [--password <pw>]
  auth login  --email <e> [--password <pw>]        (no password -> OTP challenge)
  auth verify --email <e> --code <code>            (confirm signup / complete an OTP challenge)
  auth confirm --email <e> --code <code>           (confirm signup via the one-click-link API route)
  auth resend --email <e>                          (re-send an email confirmation code)
  auth token  --session <s> --app <app> [--scope a --scope b] [--tenant <id>] [--ttl <seconds>]
  auth revoke --session <s> --jti <jti>            (deny-list an issued token before its expiry)
  auth whoami --session <s>
  auth jwks
  auth introspect --kid <kid> --session <s>|--key <apiKey>

Sign-up and login are limited to the email domains the server allows; signup requires
email confirmation. Requires HASNA_TENANTS_API_URL. Session tokens are returned by
verify/login (after confirmation).`;

export async function runCli(argv = process.argv.slice(2)): Promise<void> {
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
    process.exitCode = 1;
  }
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

  throw new Error(`Unknown command: ${command}`);
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
    const session = flagValue(parsed, "session");
    const key = flagValue(parsed, "key");
    if (!session && !key) throw new Error("auth introspect requires --session or --key");
    if (session && key) throw new Error("auth introspect accepts only one of --session or --key");
    const introspectClient = key ? new TenantsClient({ baseUrl: apiUrl, apiKey: key }) : client;
    output(await introspectClient.introspect({ kid }, session ? bearer(session) : undefined), true);
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

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    const body = error.body;
    if (body && typeof body === "object" && "error" in body) {
      return `${error.message}: ${String((body as any).error)}`;
    }
  }
  return error instanceof Error ? error.message : String(error);
}

if (import.meta.main) {
  await runCli();
}
