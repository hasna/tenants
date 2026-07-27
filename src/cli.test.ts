import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { runCli } from "./cli.js";

interface CapturedRequest {
  method: string;
  url: URL;
  headers: Headers;
  body: string | undefined;
}

const originalFetch = globalThis.fetch;
const originalLog = console.log;
const originalError = console.error;
const originalApiUrl = process.env["HASNA_TENANTS_API_URL"];

let logs: string[];
let errors: string[];

beforeEach(() => {
  logs = [];
  errors = [];
  process.exitCode = undefined;
  console.log = (...args: unknown[]) => {
    logs.push(args.map(String).join(" "));
  };
  console.error = (...args: unknown[]) => {
    errors.push(args.map(String).join(" "));
  };
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  console.log = originalLog;
  console.error = originalError;
  process.exitCode = undefined;
  if (originalApiUrl === undefined) delete process.env["HASNA_TENANTS_API_URL"];
  else process.env["HASNA_TENANTS_API_URL"] = originalApiUrl;
});

function installFetch(body: unknown = { ok: true }): CapturedRequest[] {
  const requests: CapturedRequest[] = [];
  globalThis.fetch = async (input: URL | RequestInfo, init?: RequestInit) => {
    const request = input instanceof Request ? input : null;
    const url = new URL(request ? request.url : String(input));
    const headers = new Headers(init?.headers ?? request?.headers);
    requests.push({
      method: init?.method ?? request?.method ?? "GET",
      url,
      headers,
      body: init?.body === undefined ? undefined : String(init.body),
    });
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  return requests;
}

async function runWithApiUrl(args: string[], apiUrl = "https://tenants.example.com"): Promise<void> {
  process.env["HASNA_TENANTS_API_URL"] = apiUrl;
  await runCli(args);
  expect(process.exitCode).toBeUndefined();
  expect(errors).toEqual([]);
}

function parsedBody(request: CapturedRequest): unknown {
  return request.body ? JSON.parse(request.body) : undefined;
}

describe("tenants CLI", () => {
  test("auth group help is local-only text and does not require HASNA_TENANTS_API_URL", async () => {
    delete process.env["HASNA_TENANTS_API_URL"];

    await runCli(["auth"]);

    expect(process.exitCode).toBeUndefined();
    expect(errors).toEqual([]);
    expect(logs.join("\n")).toContain("tenants auth");
    expect(logs.join("\n")).toContain("auth confirm");
  });

  test("visible auth commands route through the documented HTTP API", async () => {
    const cases: Array<{
      name: string;
      args: string[];
      method: string;
      path: string;
      query?: Record<string, string>;
      body?: unknown;
      authorization?: string;
      apiKey?: string;
    }> = [
      {
        name: "jwks",
        args: ["auth", "jwks"],
        method: "GET",
        path: "/v1/.well-known/jwks.json",
      },
      {
        name: "signup",
        args: ["auth", "signup", "--email", "a@example.com", "--name", "A", "--org", "Acme", "--password", "pw"],
        method: "POST",
        path: "/v1/auth/signup",
        body: { email: "a@example.com", name: "A", org_name: "Acme", password: "pw" },
      },
      {
        name: "login",
        args: ["auth", "login", "--email", "a@example.com", "--password", "pw"],
        method: "POST",
        path: "/v1/auth/login",
        body: { email: "a@example.com", password: "pw" },
      },
      {
        name: "verify",
        args: ["auth", "verify", "--email", "a@example.com", "--code", "123456"],
        method: "POST",
        path: "/v1/auth/verify",
        body: { email: "a@example.com", code: "123456" },
      },
      {
        name: "confirm",
        args: ["auth", "confirm", "--email", "a@example.com", "--code", "123456"],
        method: "GET",
        path: "/v1/auth/confirm",
        query: { email: "a@example.com", code: "123456" },
      },
      {
        name: "resend",
        args: ["auth", "resend", "--email", "a@example.com"],
        method: "POST",
        path: "/v1/auth/resend",
        body: { email: "a@example.com" },
      },
      {
        name: "token",
        args: ["auth", "token", "--session", "hst_session", "--app", "todos", "--scope", "todos:read", "--ttl", "60"],
        method: "POST",
        path: "/v1/auth/token",
        body: { app: "todos", scopes: ["todos:read"], ttlSeconds: 60 },
        authorization: "Bearer hst_session",
      },
      {
        name: "revoke",
        args: ["auth", "revoke", "--session", "hst_session", "--jti", "00000000-0000-4000-8000-000000000000"],
        method: "POST",
        path: "/v1/auth/revoke",
        body: { jti: "00000000-0000-4000-8000-000000000000" },
        authorization: "Bearer hst_session",
      },
      {
        name: "whoami",
        args: ["auth", "whoami", "--session", "hst_session"],
        method: "GET",
        path: "/v1/auth/whoami",
        authorization: "Bearer hst_session",
      },
      {
        name: "introspect session",
        args: ["auth", "introspect", "--kid", "kid-session", "--session", "hst_session"],
        method: "GET",
        path: "/v1/introspect",
        query: { kid: "kid-session" },
        authorization: "Bearer hst_session",
      },
      {
        name: "introspect API key",
        args: ["auth", "introspect", "--kid", "kid-api", "--key", "hsk_api"],
        method: "GET",
        path: "/v1/introspect",
        query: { kid: "kid-api" },
        apiKey: "hsk_api",
      },
    ];

    for (const item of cases) {
      logs = [];
      errors = [];
      process.exitCode = undefined;
      const requests = installFetch({ command: item.name });

      await runWithApiUrl(item.args);

      expect(requests).toHaveLength(1);
      const [request] = requests;
      expect(request.method).toBe(item.method);
      expect(request.url.pathname).toBe(item.path);
      if (item.query) {
        expect(Object.fromEntries(request.url.searchParams.entries())).toEqual(item.query);
      } else {
        expect(request.url.search).toBe("");
      }
      expect(parsedBody(request)).toEqual(item.body);
      expect(request.headers.get("authorization")).toBe(item.authorization ?? null);
      expect(request.headers.get("x-api-key")).toBe(item.apiKey ?? null);
      if (item.body) expect(request.headers.get("content-type")).toBe("application/json");
      expect(JSON.parse(logs[0] ?? "{}")).toEqual({ command: item.name });
    }
  });

  test("loopback and remote API URLs produce the same command request shape", async () => {
    const capture = async (apiUrl: string) => {
      const requests = installFetch({ ok: true });
      await runWithApiUrl(["auth", "token", "--session", "hst_session", "--app", "todos", "--scope", "todos:read"], apiUrl);
      const [request] = requests;
      return {
        method: request.method,
        path: request.url.pathname,
        search: request.url.search,
        body: parsedBody(request),
        authorization: request.headers.get("authorization"),
      };
    };

    expect(await capture("http://127.0.0.1:15460/")).toEqual(
      await capture("https://tenants.example.com/"),
    );
  });
});
