import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { runCli } from "./cli.js";
import { createTestFetchHandler } from "./testing/fake-idp.js";

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

// `process.exitCode` is deliberately never touched here: Bun ignores
// `process.exitCode = undefined`, so a single leaked 1 would survive to the end
// of the run and make `bun test` exit non-zero with no reported failure. runCli
// RETURNS its status instead, so every assertion below is on a local value.
beforeEach(() => {
  logs = [];
  errors = [];
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

/** Answer every request with one fixed non-2xx response (error-rendering tests). */
function installFailingFetch(status: number, body: string, contentType: string): CapturedRequest[] {
  const requests: CapturedRequest[] = [];
  globalThis.fetch = async (input: URL | RequestInfo, init?: RequestInit) => {
    requests.push({
      method: init?.method ?? "GET",
      url: new URL(String(input)),
      headers: new Headers(init?.headers),
      body: init?.body === undefined ? undefined : String(init.body),
    });
    return new Response(body, { status, headers: { "content-type": contentType } });
  };
  return requests;
}

/** Route the CLI's fetch into a REAL tenants fetch handler (no stubbing). */
function installServerFetch(handler: (req: Request) => Promise<Response>): void {
  globalThis.fetch = async (input: URL | RequestInfo, init?: RequestInit) =>
    handler(new Request(String(input), init));
}

async function runWithApiUrl(args: string[], apiUrl = "https://tenants.example.com"): Promise<void> {
  process.env["HASNA_TENANTS_API_URL"] = apiUrl;
  expect(await runCli(args)).toBe(0);
  expect(errors).toEqual([]);
}

async function runExpectingFailure(args: string[], apiUrl = "https://tenants.example.com"): Promise<string> {
  process.env["HASNA_TENANTS_API_URL"] = apiUrl;
  expect(await runCli(args)).toBe(1);
  return errors.join("\n");
}

function parsedBody(request: CapturedRequest): unknown {
  return request.body ? JSON.parse(request.body) : undefined;
}

describe("tenants CLI", () => {
  test("auth group help is local-only text and does not require HASNA_TENANTS_API_URL", async () => {
    delete process.env["HASNA_TENANTS_API_URL"];

    expect(await runCli(["auth"])).toBe(0);

    expect(errors).toEqual([]);
    expect(logs.join("\n")).toContain("tenants auth");
    expect(logs.join("\n")).toContain("auth confirm");
  });

  test("principals group help is local-only text", async () => {
    delete process.env["HASNA_TENANTS_API_URL"];
    expect(await runCli(["principals", "help"])).toBe(0);
    expect(errors).toEqual([]);
    expect(logs.join("\n")).toContain("principals create");
    expect(logs.join("\n")).toContain("principals token");
    expect(logs.join("\n")).toContain("principals disable");
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
        name: "introspect API key",
        args: ["auth", "introspect", "--kid", "kid-api", "--key", "hsk_api"],
        method: "GET",
        path: "/v1/introspect",
        query: { kid: "kid-api" },
        apiKey: "hsk_api",
      },
      {
        name: "principal create",
        args: ["principals", "create", "--key", "admin-key", "--tenant", "tenant-1", "--name", "Agent", "--kind", "agent", "--identity", "identity-1"],
        method: "POST",
        path: "/v1/principals",
        body: { tenant_id: "tenant-1", display_name: "Agent", kind: "agent", identity_id: "identity-1" },
        apiKey: "admin-key",
      },
      {
        name: "principal token",
        args: ["principals", "token", "--enrollment-secret", "hse_secret", "--app", "todos", "--scope", "todos:read", "--ttl", "60"],
        method: "POST",
        path: "/v1/principals/token",
        body: { enrollment_secret: "hse_secret", app: "todos", scopes: ["todos:read"], ttlSeconds: 60 },
      },
      {
        name: "principal disable",
        args: ["principals", "disable", "--id", "00000000-0000-4000-8000-000000000000", "--key", "admin-key"],
        method: "POST",
        path: "/v1/principals/00000000-0000-4000-8000-000000000000/disable",
        body: {},
        apiKey: "admin-key",
      },
    ];

    for (const item of cases) {
      logs = [];
      errors = [];
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

// A stubbed fetch answers whatever the test wants, so it can bless a command
// that the real server would refuse. These drive `runCli` against an ACTUAL
// `createFetchHandler`, which is the only thing that proves a command is live.
describe("tenants CLI against a real tenants server", () => {
  test("service-principal create, token, and disable commands are live end to end", async () => {
    const { fetch: handler } = await createTestFetchHandler();
    installServerFetch(handler);

    await runWithApiUrl(["auth", "signup", "--email", "principal-cli@example.com", "--password", "pw-pw-pw-pw"]);
    const session = (JSON.parse(logs[0]!) as { session: string }).session;
    logs = [];
    await runWithApiUrl(["auth", "token", "--session", session, "--app", "tenants", "--scope", "tenants:write"]);
    const adminToken = (JSON.parse(logs[0]!) as { access_token: string }).access_token;

    logs = [];
    await runWithApiUrl(["principals", "create", "--key", adminToken, "--name", "CLI agent"]);
    const created = JSON.parse(logs[0]!) as {
      principal: { service_principal_id: string };
      enrollment_secret: string;
    };
    expect(created.enrollment_secret).toStartWith("hse_");

    logs = [];
    await runWithApiUrl([
      "principals", "token", "--enrollment-secret", created.enrollment_secret,
      "--app", "todos", "--scope", "todos:read", "--ttl", "60",
    ]);
    expect(JSON.parse(logs[0]!)).toMatchObject({
      pt: "service",
      service_principal_id: created.principal.service_principal_id,
      expires_in: 60,
    });

    logs = [];
    await runWithApiUrl(["principals", "disable", "--id", created.principal.service_principal_id, "--key", adminToken]);
    expect(JSON.parse(logs[0]!)).toEqual({ disabled: true, service_principal_id: created.principal.service_principal_id });

    logs = [];
    const error = await runExpectingFailure([
      "principals", "token", "--enrollment-secret", created.enrollment_secret, "--app", "todos",
    ]);
    expect(error).toContain("Invalid enrollment secret");
  });

  test("introspect authenticates with an access token, and the server refuses a session", async () => {
    const { fetch: handler } = await createTestFetchHandler();
    installServerFetch(handler);

    // Sign up to get a session, then exchange it for a tenants-audience token.
    await runWithApiUrl(["auth", "signup", "--email", "cli@example.com", "--name", "C", "--password", "pw-pw-pw-pw"]);
    const session = (JSON.parse(logs[0]!) as { session: string }).session;
    expect(session).toStartWith("hst_");

    logs = [];
    await runWithApiUrl(["auth", "token", "--session", session, "--app", "tenants", "--scope", "tenants:read"]);
    const accessToken = (JSON.parse(logs[0]!) as { access_token: string }).access_token;
    expect(accessToken).toBeTruthy();

    // --key with that access token is a LIVE command end to end.
    logs = [];
    await runWithApiUrl(["auth", "introspect", "--kid", "some-kid", "--key", accessToken]);
    expect(JSON.parse(logs[0]!)).toEqual({ active: false, kid: "some-kid" });

    // Ground truth for dropping --session: the server rejects a session token on
    // /v1/introspect outright, so no CLI flag could ever make it work.
    const direct = await handler(new Request("http://x/v1/introspect?kid=some-kid", {
      headers: { authorization: `Bearer ${session}` },
    }));
    expect(direct.status).toBe(401);
  });

  test("introspect --session fails fast with the exchange recipe and issues no request", async () => {
    const { fetch: handler } = await createTestFetchHandler();
    const seen: string[] = [];
    installServerFetch(async (req) => {
      seen.push(req.url);
      return handler(req);
    });

    const message = await runExpectingFailure(["auth", "introspect", "--kid", "k", "--session", "hst_whatever"]);

    expect(message).toContain("does not accept --session");
    expect(message).toContain("auth token --session <s> --app tenants");
    expect(seen).toEqual([]);
  });

  test("introspect without a credential is refused locally", async () => {
    installServerFetch(async () => new Response("{}", { status: 200 }));

    const message = await runExpectingFailure(["auth", "introspect", "--kid", "k"]);

    expect(message).toContain("auth introspect requires --key");
  });
});

// A bare status code is not a diagnostic. Everything the server said about the
// failure has to reach the operator — including bodies from a proxy in front of
// the API, which are never the well-formed `{error: …}` shape.
describe("tenants CLI error output", () => {
  test("a non-JSON gateway body is reported verbatim, not swallowed", async () => {
    installFailingFetch(502, "<html><body>502 Bad Gateway - upstream tenants pod is down</body></html>", "text/html");

    const message = await runExpectingFailure(["auth", "whoami", "--session", "hst_session"]);

    expect(message).toContain("GET /v1/auth/whoami failed: 502");
    expect(message).toContain("upstream tenants pod is down");
  });

  test("a JSON body with no `error` key is still reported", async () => {
    installFailingFetch(429, JSON.stringify({ reason: "rate_limited", retry_after: 30 }), "application/json");

    const message = await runExpectingFailure(["auth", "whoami", "--session", "hst_session"]);

    expect(message).toContain("failed: 429");
    expect(message).toContain("rate_limited");
    expect(message).toContain("30");
  });

  test("a well-formed error body reports both `error` and `reason`", async () => {
    installFailingFetch(401, JSON.stringify({ error: "access token revoked", reason: "revoked" }), "application/json");

    const message = await runExpectingFailure(["auth", "whoami", "--session", "hst_session"]);

    expect(message).toContain("access token revoked");
    expect(message).toContain("(revoked)");
  });

  test("--json carries the same detail into the machine-readable error", async () => {
    installFailingFetch(500, "plain text failure", "text/plain");

    process.env["HASNA_TENANTS_API_URL"] = "https://tenants.example.com";
    expect(await runCli(["--json", "auth", "whoami", "--session", "hst_session"])).toBe(1);

    expect(JSON.parse(logs.join("\n"))).toEqual({
      error: "GET /v1/auth/whoami failed: 500: plain text failure",
    });
  });

  test("an oversized body is truncated rather than dumped whole", async () => {
    installFailingFetch(500, "x".repeat(5000), "text/plain");

    const message = await runExpectingFailure(["auth", "whoami", "--session", "hst_session"]);

    expect(message).toContain("(truncated)");
    expect(message.length).toBeLessThan(700);
  });
});
