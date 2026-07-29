import { afterEach, describe, expect, test } from "bun:test";
import { AuthService } from "../idp/service.js";
import { UNRESTRICTED_EMAIL_POLICY } from "../idp/policy.js";
import { API_KEYS_TABLE } from "../migrations.js";
import {
  FakeIdpStore,
  TEST_SIGNING_SECRET,
  createTestFetchHandler,
  shimClient,
} from "../testing/fake-idp.js";
import type { PoolQueryClient } from "../generated/storage-kit/index.js";
import { buildHandler, createFetchHandler, startServer } from "./serve.js";

const signingEnvKeys = ["HASNA_TENANTS_API_SIGNING_KEY", "HASNA_API_SIGNING_KEY"] as const;
const originalSigningEnv = Object.fromEntries(
  signingEnvKeys.map((key) => [key, process.env[key]]),
) as Record<(typeof signingEnvKeys)[number], string | undefined>;

afterEach(() => {
  for (const key of signingEnvKeys) {
    const original = originalSigningEnv[key];
    if (original === undefined) delete process.env[key];
    else process.env[key] = original;
  }
});

function authFor(store: FakeIdpStore = new FakeIdpStore()): AuthService {
  return new AuthService({
    store,
    signingSecret: TEST_SIGNING_SECRET,
    apiKeysTable: API_KEYS_TABLE,
    otpEcho: true,
    emailPolicy: UNRESTRICTED_EMAIL_POLICY,
  });
}

describe("buildHandler", () => {
  test("requires a signing secret when neither an option nor environment fallback exists", async () => {
    for (const key of signingEnvKeys) delete process.env[key];
    await expect(buildHandler({ client: shimClient, auth: authFor() })).rejects.toThrow(
      "Missing API signing secret. Set HASNA_TENANTS_API_SIGNING_KEY",
    );
  });

  test("accepts the legacy environment fallback", async () => {
    delete process.env["HASNA_TENANTS_API_SIGNING_KEY"];
    process.env["HASNA_API_SIGNING_KEY"] = "legacy-secret";

    const handler = await buildHandler({ client: shimClient, auth: authFor() });
    expect(handler.client).toBe(shimClient);
    expect(handler.version).toMatch(/^\d+\.\d+\.\d+/);
    await expect(handler.close()).resolves.toBeUndefined();
  });

  test("uses the supplied dependencies and caches JWKS reads", async () => {
    class CountingStore extends FakeIdpStore {
      reads = 0;
      override async listPublicJwks() {
        this.reads += 1;
        return super.listPublicJwks();
      }
    }
    const store = new CountingStore();
    const auth = authFor(store);
    let closed = 0;
    const handler = await buildHandler({
      client: shimClient,
      auth,
      signingSecret: TEST_SIGNING_SECRET,
      close: async () => { closed += 1; },
    });

    const first = await handler.getJwks();
    const second = await handler.getJwks();
    expect(first).toBe(second);
    expect(first[0]?.kid).toBe("routes-kid");
    expect(store.reads).toBe(1);
    await handler.close();
    expect(closed).toBe(1);
  });
});

describe("createFetchHandler", () => {
  test("serves metadata and a concrete JSON 404", async () => {
    const { fetch } = await createTestFetchHandler();

    const health = await fetch(new Request("http://tenants.test/health"));
    expect(health.status).toBe(200);
    expect(health.headers.get("content-type")).toBe("application/json");
    expect(await health.json()).toMatchObject({ status: "ok", backend: "postgresql" });

    const missing = await fetch(new Request("http://tenants.test/not-here"));
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({ error: "Not found: /not-here" });
  });

  test("rejects malformed and empty signup bodies with distinct client errors", async () => {
    const { fetch } = await createTestFetchHandler();

    const malformed = await fetch(new Request("http://tenants.test/signup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not-json",
    }));
    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toEqual({ error: "Invalid JSON body" });

    const empty = await fetch(new Request("http://tenants.test/signup", { method: "POST" }));
    expect(empty.status).toBe(400);
    expect(await empty.json()).toMatchObject({ reason: "invalid_email" });
  });

  test("returns route-specific 404s and keeps JWKS public and cacheable", async () => {
    const { fetch } = await createTestFetchHandler();

    const wrongMethod = await fetch(new Request("http://tenants.test/v1/auth/whoami", { method: "POST" }));
    expect(wrongMethod.status).toBe(404);
    expect(await wrongMethod.json()).toEqual({
      error: "No auth route for POST /v1/auth/whoami",
      reason: "not_found",
    });

    const jwks = await fetch(new Request("http://tenants.test/.well-known/jwks.json"));
    expect(jwks.status).toBe(200);
    expect(jwks.headers.get("cache-control")).toBe("public, max-age=600");
    expect((await jwks.json()).keys[0]).toMatchObject({ kid: "routes-kid", alg: "EdDSA" });
  });

  test("accepts a session token from the JSON body and refuses a non-session bearer", async () => {
    const { fetch } = await createTestFetchHandler();
    const signup = await fetch(new Request("http://tenants.test/signup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "body-session@example.com", name: "Body", password: "long-enough-password" }),
    }));
    expect(signup.status).toBe(201);
    const session = (await signup.json()).session as string;

    const token = await fetch(new Request("http://tenants.test/v1/auth/token", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer not-a-session" },
      body: JSON.stringify({ app: "todos", session }),
    }));
    expect(token.status).toBe(200);
    expect(await token.json()).toMatchObject({ token_type: "Bearer", aud: "todos" });

    const refused = await fetch(new Request("http://tenants.test/v1/auth/whoami", {
      headers: { authorization: "Bearer not-a-session" },
    }));
    expect(refused.status).toBe(401);
    expect(await refused.json()).toMatchObject({ reason: "missing_session" });
  });

  test("reports readiness failures as a degraded 503 without throwing", async () => {
    const failingClient = {
      ...shimClient,
      async execute() { throw new Error("ledger unavailable"); },
    } as PoolQueryClient;
    const { fetch } = await createFetchHandler({
      client: failingClient,
      auth: authFor(),
      signingSecret: TEST_SIGNING_SECRET,
    });

    const response = await fetch(new Request("http://tenants.test/ready"));
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({
      status: "degraded",
      backend: "postgresql",
      pendingMigrations: [],
      error: "ledger unavailable",
    });
  });

  test("authenticates before validating an introspection query", async () => {
    const { fetch } = await createTestFetchHandler();
    const response = await fetch(new Request("http://tenants.test/v1/introspect"));
    expect(response.status).toBe(401);
    expect((await response.json()).reason).toBeTruthy();
  });
});

describe("startServer", () => {
  test("listens on an ephemeral port and stops even when pool cleanup fails", async () => {
    let closeCalls = 0;
    const server = await startServer({
      port: 0,
      host: "127.0.0.1",
      client: shimClient,
      auth: authFor(),
      signingSecret: TEST_SIGNING_SECRET,
      close: async () => {
        closeCalls += 1;
        throw new Error("close failed");
      },
    });

    try {
      expect(server.port).toBeGreaterThan(0);
      expect(server.hostname).toBe("127.0.0.1");
      const response = await fetch(`http://127.0.0.1:${server.port}/version`);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ status: "ok", backend: "postgresql" });
    } finally {
      await expect(server.stop()).resolves.toBeUndefined();
    }
    expect(closeCalls).toBe(1);
  });
});
