import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import type { TypedQueryClient } from "../generated/storage-kit/index.js";
import { ROOT_TENANT_ID, SEED_TENANTS } from "./ids.js";
import {
  IdpStore,
  JWT_KID_ENV,
  JWT_SIGNING_KEY_ENV,
  type MembershipRow,
  type SessionRow,
  type SigningKeyRow,
  type TenantRow,
  type UserRow,
} from "./store.js";

interface QueryCall {
  operation: "execute" | "get" | "many";
  sql: string;
  params?: readonly unknown[];
}

class RecordingClient {
  calls: QueryCall[] = [];
  getResults: unknown[] = [];
  manyResults: unknown[][] = [];
  executeError: Error | null = null;

  async query<T>(): Promise<{ rows: T[]; rowCount: number }> {
    return { rows: [], rowCount: 0 };
  }

  async many<T>(sql: string, params?: readonly unknown[]): Promise<T[]> {
    this.calls.push({ operation: "many", sql, ...(params ? { params } : {}) });
    return (this.manyResults.shift() ?? []) as T[];
  }

  async get<T>(sql: string, params?: readonly unknown[]): Promise<T | null> {
    this.calls.push({ operation: "get", sql, ...(params ? { params } : {}) });
    const result = this.getResults.shift();
    if (result instanceof Error) throw result;
    return (result ?? null) as T | null;
  }

  async one<T>(): Promise<T> {
    throw new Error("one() is not used by IdpStore");
  }

  async execute(sql: string, params?: readonly unknown[]): Promise<void> {
    this.calls.push({ operation: "execute", sql, ...(params ? { params } : {}) });
    if (this.executeError) throw this.executeError;
  }
}

function setup(): { client: RecordingClient; store: IdpStore } {
  const client = new RecordingClient();
  return { client, store: new IdpStore(client as unknown as TypedQueryClient) };
}

function privateJwk(kid?: string): Record<string, unknown> {
  const { privateKey } = generateKeyPairSync("ed25519");
  return { ...privateKey.export({ format: "jwk" }), ...(kid ? { kid } : {}) };
}

function publicJwk(): Record<string, unknown> {
  const { publicKey } = generateKeyPairSync("ed25519");
  return publicKey.export({ format: "jwk" });
}

const tenant: TenantRow = {
  id: "00000000-0000-4000-8000-000000000001",
  slug: "acme",
  name: "Acme",
  kind: "org",
  parent_id: ROOT_TENANT_ID,
  status: "active",
  identity_id: null,
};

const user: UserRow = {
  id: "00000000-0000-4000-8000-000000000002",
  kind: "human",
  email: "person@example.com",
  display_name: "Person",
  identity_id: null,
  home_tenant_id: tenant.id,
  auth_method: "password",
  password_hash: "hash",
  status: "active",
  email_verified_at: null,
};

const originalSigningKey = process.env[JWT_SIGNING_KEY_ENV];
const originalKid = process.env[JWT_KID_ENV];

beforeEach(() => {
  delete process.env[JWT_SIGNING_KEY_ENV];
  delete process.env[JWT_KID_ENV];
});

afterEach(() => {
  if (originalSigningKey === undefined) delete process.env[JWT_SIGNING_KEY_ENV];
  else process.env[JWT_SIGNING_KEY_ENV] = originalSigningKey;
  if (originalKid === undefined) delete process.env[JWT_KID_ENV];
  else process.env[JWT_KID_ENV] = originalKid;
});

describe("IdpStore signing keys", () => {
  test("loads JSON and base64url private JWKs, with explicit kid precedence", () => {
    const { store } = setup();
    const jwk = privateJwk("embedded-kid");

    expect(store.loadEnvSigningKey({})).toBeNull();
    expect(store.loadEnvSigningKey({ [JWT_SIGNING_KEY_ENV]: "   " })).toBeNull();
    expect(store.loadEnvSigningKey({ [JWT_SIGNING_KEY_ENV]: JSON.stringify(jwk) })?.kid).toBe("embedded-kid");
    expect(store.loadEnvSigningKey({
      [JWT_SIGNING_KEY_ENV]: Buffer.from(JSON.stringify(jwk)).toString("base64url"),
      [JWT_KID_ENV]: " configured-kid ",
    })?.kid).toBe("configured-kid");
    expect(store.loadEnvSigningKey({ [JWT_SIGNING_KEY_ENV]: JSON.stringify(privateJwk()) })?.kid).toBe("env");
  });

  test("rejects a signing-key value that is neither JSON nor base64url JSON", () => {
    const { store } = setup();
    expect(() => store.loadEnvSigningKey({ [JWT_SIGNING_KEY_ENV]: "not-a-jwk" }))
      .toThrow(`${JWT_SIGNING_KEY_ENV} must be a private Ed25519 JWK`);
  });

  test("returns an existing DB key without writing", async () => {
    const { client, store } = setup();
    client.getResults.push({
      kid: "db-kid",
      alg: "EdDSA",
      public_jwk: publicJwk(),
      private_jwk: JSON.stringify(privateJwk()),
      status: "active",
    } satisfies SigningKeyRow);

    const key = await store.getOrCreateActiveDbKey();

    expect(key.kid).toBe("db-kid");
    expect(key.publicJwk.alg).toBe("EdDSA");
    expect(client.calls.map((call) => call.operation)).toEqual(["get"]);
  });

  test("generates, persists, and re-reads a key when the DB has none", async () => {
    const { client, store } = setup();
    const persisted = privateJwk();
    client.getResults.push(null, {
      kid: "winner-kid",
      alg: "EdDSA",
      public_jwk: publicJwk(),
      private_jwk: persisted,
      status: "active",
    } satisfies SigningKeyRow);

    const key = await store.getOrCreateActiveDbKey();

    expect(key.kid).toBe("winner-kid");
    const insert = client.calls.find((call) => call.operation === "execute");
    expect(insert?.sql).toContain("INSERT INTO jwt_signing_keys");
    expect(String(insert?.params?.[0])).toMatch(/^ed25519_[0-9a-f]{16}$/);
    expect(JSON.parse(String(insert?.params?.[1]))).toMatchObject({ kty: "OKP", crv: "Ed25519" });
    expect(JSON.parse(String(insert?.params?.[2]))).toMatchObject({ kty: "OKP", crv: "Ed25519" });
  });

  test("fails if no active key exists after the generated key is inserted", async () => {
    const { client, store } = setup();
    client.getResults.push(null, null);
    await expect(store.getOrCreateActiveDbKey()).rejects.toThrow("Failed to persist an active signing key.");
  });

  test("prefers the environment key for minting and falls back to the DB", async () => {
    const envJwk = privateJwk();
    process.env[JWT_SIGNING_KEY_ENV] = JSON.stringify(envJwk);
    process.env[JWT_KID_ENV] = "env-wins";
    const envSetup = setup();

    expect((await envSetup.store.getSigningKeyForMinting()).kid).toBe("env-wins");
    expect(envSetup.client.calls).toEqual([]);

    delete process.env[JWT_SIGNING_KEY_ENV];
    delete process.env[JWT_KID_ENV];
    const dbSetup = setup();
    dbSetup.client.getResults.push({
      kid: "db-fallback",
      alg: "EdDSA",
      public_jwk: publicJwk(),
      private_jwk: privateJwk(),
      status: "active",
    } satisfies SigningKeyRow);
    expect((await dbSetup.store.getSigningKeyForMinting()).kid).toBe("db-fallback");
  });

  test("publishes environment and DB public keys in order and handles an empty set", async () => {
    process.env[JWT_SIGNING_KEY_ENV] = JSON.stringify(privateJwk());
    process.env[JWT_KID_ENV] = "env-kid";
    const { client, store } = setup();
    const dbPublic = publicJwk();
    client.manyResults.push([{
      kid: "db-kid",
      alg: "EdDSA",
      public_jwk: JSON.stringify(dbPublic),
      private_jwk: {},
      status: "active",
    }]);

    const keys = await store.listPublicJwks();
    expect(keys.map((key) => key.kid)).toEqual(["env-kid", "db-kid"]);
    expect(keys[1]).toEqual({
      kty: "OKP", crv: "Ed25519", x: dbPublic["x"], kid: "db-kid", use: "sig", alg: "EdDSA",
    });

    delete process.env[JWT_SIGNING_KEY_ENV];
    const empty = setup();
    empty.client.manyResults.push([]);
    expect(await empty.store.listPublicJwks()).toEqual([]);
  });
});

describe("IdpStore data access", () => {
  test("seeds every fixed tenant idempotently", async () => {
    const { client, store } = setup();
    await store.seedTenants();

    expect(client.calls).toHaveLength(SEED_TENANTS.length);
    expect(client.calls.every((call) => call.sql.includes("ON CONFLICT (id) DO NOTHING"))).toBe(true);
    expect(client.calls.map((call) => call.params)).toEqual(
      SEED_TENANTS.map((item) => [item.id, item.slug, item.name, item.kind, item.parentId]),
    );
  });

  test("looks up tenants by id and slug, including a missing row", async () => {
    const { client, store } = setup();
    client.getResults.push(tenant, null);

    expect(await store.getTenantById(tenant.id)).toEqual(tenant);
    expect(await store.getTenantBySlug("missing")).toBeNull();
    expect(client.calls.map((call) => call.params)).toEqual([[tenant.id], ["missing"]]);
  });

  test("creates a tenant with defaults and rejects a missing post-insert row", async () => {
    const { client, store } = setup();
    client.getResults.push(tenant);

    expect(await store.createTenant({ slug: "acme", name: "Acme" })).toEqual(tenant);
    const insert = client.calls[0]!;
    expect(String(insert.params?.[0])).toMatch(/^[0-9a-f-]{36}$/);
    expect(insert.params?.slice(1)).toEqual(["acme", "Acme", "org", ROOT_TENANT_ID]);

    const failed = setup();
    failed.client.getResults.push(null);
    await expect(failed.store.createTenant({ slug: "lost", name: "Lost", kind: "brand", parentId: null }))
      .rejects.toThrow("Failed to create tenant.");
    expect(failed.client.calls[0]?.params?.slice(1)).toEqual(["lost", "Lost", "brand", ROOT_TENANT_ID]);
  });

  test("looks up and updates users with the supplied identifiers", async () => {
    const { client, store } = setup();
    client.getResults.push(user, null);

    expect(await store.getUserByEmail("PERSON@example.com")).toEqual(user);
    expect(await store.getUserById("missing")).toBeNull();
    await store.markEmailVerified(user.id);
    await store.setUserPassword(user.id, "new-hash");

    expect(client.calls[0]?.sql).toContain("lower(email) = lower($1)");
    expect(client.calls[2]).toMatchObject({ operation: "execute", params: [user.id] });
    expect(client.calls[3]).toMatchObject({ operation: "execute", params: [user.id, "new-hash"] });
  });

  test("creates users with nullable defaults and returns the persisted row", async () => {
    const { client, store } = setup();
    client.getResults.push(user);

    const result = await store.createUser({ kind: "human", homeTenantId: tenant.id });

    expect(result).toEqual(user);
    expect(client.calls[0]?.params?.slice(1)).toEqual([
      "human", null, null, null, tenant.id, null, null,
    ]);

    const failed = setup();
    failed.client.getResults.push(null);
    await expect(failed.store.createUser({
      kind: "human",
      email: "x@example.com",
      displayName: "X",
      identityId: "identity-x",
      homeTenantId: tenant.id,
      authMethod: "password",
      passwordHash: "hash-x",
    })).rejects.toThrow("Failed to create user.");
    expect(failed.client.calls[0]?.params?.slice(1)).toEqual([
      "human", "x@example.com", "X", "identity-x", tenant.id, "password", "hash-x",
    ]);
  });

  test("creates and lists memberships, defaulting an omitted scope list", async () => {
    const { client, store } = setup();
    const membership: MembershipRow = {
      id: "1", tenant_id: tenant.id, principal_id: user.id, principal_type: "user",
      role: "member", scopes: ["todos:read"], status: "active",
    };
    client.manyResults.push([membership], []);

    await store.createMembership({ tenantId: tenant.id, principalId: user.id, principalType: "user", role: "member" });
    await store.createMembership({
      tenantId: tenant.id, principalId: "service-1", principalType: "service", role: "admin", scopes: ["*"],
    });
    expect(await store.listMembershipsForPrincipal(user.id, "user")).toEqual([membership]);
    expect(await store.listMembershipsForPrincipal("missing", "service")).toEqual([]);

    expect(client.calls[0]?.params?.[4]).toBe("[]");
    expect(client.calls[1]?.params?.[4]).toBe('["*"]');
    expect(client.calls[2]?.params).toEqual([user.id, "user"]);
  });

  test("creates service principals with generated defaults or explicit values", async () => {
    const { client, store } = setup();
    const generated = await store.createServicePrincipal({ tenantId: tenant.id });
    const explicit = await store.createServicePrincipal({
      id: "service-fixed", tenantId: tenant.id, kind: "agent", displayName: "Bot", identityId: "identity-bot",
    });

    expect(generated).toMatch(/^[0-9a-f-]{36}$/);
    expect(client.calls[0]?.params).toEqual([generated, tenant.id, "machine", null, null]);
    expect(explicit).toBe("service-fixed");
    expect(client.calls[1]?.params).toEqual(["service-fixed", tenant.id, "agent", "Bot", "identity-bot"]);
  });

  test("creates, reads, and revokes sessions with normalized optional values", async () => {
    const { client, store } = setup();
    const expiresAt = new Date("2030-01-02T03:04:05.000Z");
    const session: SessionRow = {
      id: "session-1", user_id: user.id, tenant_id: tenant.id, token_hash: "token-hash",
      method: "password", issued_at: "2029-01-01T00:00:00.000Z", expires_at: expiresAt.toISOString(), revoked_at: null,
    };
    client.getResults.push(session, null);

    const id = await store.createSession({ userId: user.id, tenantId: tenant.id, tokenHash: "token-hash", expiresAt });
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    expect(client.calls[0]?.params).toEqual([
      id, user.id, tenant.id, "token-hash", "password", expiresAt.toISOString(), null, null,
    ]);
    expect(await store.getSessionByTokenHash("token-hash")).toEqual(session);
    expect(await store.getSessionByTokenHash("missing")).toBeNull();
    await store.revokeSession("token-hash");
    expect(client.calls.at(-1)?.params).toEqual(["token-hash"]);
  });

  test("creates, finds, consumes, and bumps OTP challenges", async () => {
    const { client, store } = setup();
    const expiresAt = new Date("2030-02-03T04:05:06.000Z");
    const challenge = { id: "challenge-1", code_hash: "code-hash", attempts: 2 };
    client.getResults.push(challenge, null);

    const id = await store.createChallenge({
      email: "person@example.com", codeHash: "code-hash", purpose: "signup", expiresAt,
    });
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
    expect(client.calls[0]?.params).toEqual([
      id, "person@example.com", "code-hash", "signup", expiresAt.toISOString(),
    ]);
    expect(await store.findActiveChallenge("PERSON@example.com", "signup")).toEqual(challenge);
    expect(await store.findActiveChallenge("missing@example.com", "login")).toBeNull();
    await store.consumeChallenge(id);
    await store.bumpChallengeAttempts(id);
    expect(client.calls.slice(-2).map((call) => call.params)).toEqual([[id], [id]]);
  });

  test("records and looks up API-key bindings, including no binding", async () => {
    const { client, store } = setup();
    const binding = { tenant_id: tenant.id, user_id: user.id, principal_type: "user" };
    client.getResults.push(binding, null);

    await store.recordApiKeyBinding("custom_api_keys", {
      kid: "kid-1", tenantId: tenant.id, userId: user.id, principalType: "user",
    });
    expect(client.calls[0]?.sql).toContain("UPDATE custom_api_keys");
    expect(client.calls[0]?.params).toEqual(["kid-1", tenant.id, user.id, "user"]);
    expect(await store.lookupApiKeyBinding("custom_api_keys", "kid-1")).toEqual(binding);
    expect(await store.lookupApiKeyBinding("custom_api_keys", "missing")).toBeNull();
  });

  test("records access-token expiry and reports both revocation outcomes", async () => {
    const { client, store } = setup();
    const expiresAt = new Date("2030-03-04T05:06:07.000Z");
    client.getResults.push({ jti: "jti-1" }, null, { jti: "jti-1" }, null);

    await store.recordIssuedAccessToken({
      jti: "jti-1", userId: user.id, tenantId: tenant.id, aud: "todos", expiresAt,
    });
    expect(client.calls[0]?.params).toEqual([
      "jti-1", user.id, tenant.id, "todos", expiresAt.toISOString(),
    ]);
    expect(await store.revokeIssuedAccessToken("jti-1", user.id)).toBe(true);
    expect(await store.revokeIssuedAccessToken("foreign-jti", user.id)).toBe(false);
    expect(await store.isAccessTokenRevoked("jti-1")).toBe(true);
    expect(await store.isAccessTokenRevoked("unknown")).toBe(false);
  });

  test("propagates database write failures", async () => {
    const { client, store } = setup();
    client.executeError = new Error("database unavailable");
    await expect(store.markEmailVerified(user.id)).rejects.toThrow("database unavailable");
  });
});
