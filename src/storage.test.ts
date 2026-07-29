import { describe, expect, test } from "bun:test";
import { createTenantsDatabase } from "./db.js";
import {
  DATABASE_URL_ENV_KEYS,
  RETIRED_MODE_ENV_KEYS,
  RETIRED_MODE_VALUES,
  TENANTS_DATA_BACKEND,
  assertNoDeploymentModeEnv,
  resolveTenantsDatabase,
  type Env,
} from "./storage.js";

// Every case passes an explicit `env` object, so nothing here depends on (or
// mutates) the ambient process environment — a test that mutated process.env
// would leak into the suites that read it.
const DB_URL = "postgres://u:p@db.example.test:5432/tenants";

describe("deployment modes are removed, not normalized", () => {
  // The defect being fixed: the vendored kit mapped `self_hosted`, `self-hosted`,
  // `remote` and `hybrid` to `cloud` SILENTLY, and resolved an unset value to
  // `local` — a backend this service never implemented. Both behaviours let a
  // stale deployment boot and let the retired vocabulary survive.
  //
  // These cases separate two behaviours: (a) a retired mode value is ACCEPTED
  // and quietly rewritten, versus (b) it throws. Before this change, every value
  // below except an unknown string was accepted, so the inputs could produce the
  // failure this asserts against.
  for (const value of RETIRED_MODE_VALUES) {
    test(`HASNA_TENANTS_STORAGE_MODE=${value} is refused`, () => {
      const env: Env = { [RETIRED_MODE_ENV_KEYS[0]]: value, [DATABASE_URL_ENV_KEYS[0]]: DB_URL };
      expect(() => assertNoDeploymentModeEnv(env)).toThrow(/is removed/);
      expect(() => assertNoDeploymentModeEnv(env)).toThrow(new RegExp(`set to '${value}'`));
    });
  }

  test("the refusal names the replacement variable, the backend, and the fix", () => {
    const env: Env = { HASNA_TENANTS_STORAGE_MODE: "self_hosted" };
    let message = "";
    try {
      assertNoDeploymentModeEnv(env);
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toContain("HASNA_TENANTS_STORAGE_MODE is removed");
    expect(message).toContain("no deployment modes");
    // Naming the replacement variable is the whole point of erroring rather than
    // ignoring: the operator must be told what to set instead.
    expect(message).toContain("HASNA_TENANTS_DATABASE_URL");
    expect(message).toContain("Fix: unset HASNA_TENANTS_STORAGE_MODE");
    expect(message).toContain(TENANTS_DATA_BACKEND);
  });

  test("the unprefixed TENANTS_STORAGE_MODE alias is refused too", () => {
    // A single grep for the canonical key misses this one, which is exactly how
    // the alias survived the previous pass.
    expect(() => assertNoDeploymentModeEnv({ TENANTS_STORAGE_MODE: "cloud" })).toThrow(
      /TENANTS_STORAGE_MODE is removed/,
    );
  });

  test("an unrecognized value is refused without echoing it", () => {
    // The value is not echoed unless it is a known retired mode word, so a
    // misconfigured variable cannot leak a connection string into a log line.
    let message = "";
    try {
      assertNoDeploymentModeEnv({ HASNA_TENANTS_STORAGE_MODE: "postgres://u:secret@h/db" });
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toContain("is removed");
    expect(message).not.toContain("secret");
    expect(message).not.toContain("set to '");
  });

  test("an empty or whitespace-only value is not treated as set", () => {
    expect(() => assertNoDeploymentModeEnv({ HASNA_TENANTS_STORAGE_MODE: "" })).not.toThrow();
    expect(() => assertNoDeploymentModeEnv({ HASNA_TENANTS_STORAGE_MODE: "   " })).not.toThrow();
  });

  test("no mode variable set is the correct configuration", () => {
    expect(() => assertNoDeploymentModeEnv({})).not.toThrow();
  });
});

describe("resolveTenantsDatabase", () => {
  test("resolves the one backend from the canonical connection-string key", () => {
    const target = resolveTenantsDatabase({ [DATABASE_URL_ENV_KEYS[0]]: DB_URL });
    expect(target.backend).toBe("postgresql");
    expect(target.connectionString).toBe(DB_URL);
    expect(target.connectionSource).toBe("HASNA_TENANTS_DATABASE_URL");
  });

  test("honours the unprefixed alias when the canonical key is unset", () => {
    const target = resolveTenantsDatabase({ TENANTS_DATABASE_URL: DB_URL });
    expect(target.connectionSource).toBe("TENANTS_DATABASE_URL");
  });

  test("the canonical key wins over the alias", () => {
    const target = resolveTenantsDatabase({
      HASNA_TENANTS_DATABASE_URL: DB_URL,
      TENANTS_DATABASE_URL: "postgres://wrong@h/db",
    });
    expect(target.connectionString).toBe(DB_URL);
  });

  test("a missing connection string names the variable to set, not a mode", () => {
    // Behaviour change worth asserting: the old failure for this input was
    // "requires tenants storage mode 'cloud', got 'local'", which pointed the
    // operator at the wrong variable entirely.
    let message = "";
    try {
      resolveTenantsDatabase({});
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    expect(message).toContain("HASNA_TENANTS_DATABASE_URL");
    expect(message).not.toContain("mode");
  });

  test("a retired mode variable is refused BEFORE the connection string is missing", () => {
    // Ordering matters: an operator carrying stale config must be told what to
    // delete, not sent chasing a connection error.
    expect(() => resolveTenantsDatabase({ HASNA_TENANTS_STORAGE_MODE: "cloud" })).toThrow(
      /HASNA_TENANTS_STORAGE_MODE is removed/,
    );
  });
});

describe("createTenantsDatabase", () => {
  test("refuses a retired mode variable before opening a pool", () => {
    // No pool is created and nothing is closed, so a throw here proves the guard
    // runs ahead of any connection attempt.
    expect(() =>
      createTenantsDatabase({
        env: { HASNA_TENANTS_STORAGE_MODE: "self-hosted", HASNA_TENANTS_DATABASE_URL: DB_URL },
      }),
    ).toThrow(/HASNA_TENANTS_STORAGE_MODE is removed/);
  });

  test("builds a client from a connection string alone — no mode variable needed", async () => {
    // The pg Pool is lazy: constructing it does not dial the server, so this
    // exercises the real factory without a database. Previously this exact env
    // THREW, because an unset mode resolved to `local`.
    const db = createTenantsDatabase({
      env: { HASNA_TENANTS_DATABASE_URL: DB_URL },
      applicationName: "storage-test",
    });
    try {
      expect(db.connectionSource).toBe("HASNA_TENANTS_DATABASE_URL");
      expect(typeof db.client.query).toBe("function");
    } finally {
      await db.close();
    }
  });

  test("reports the env key it used, never the connection string", async () => {
    const db = createTenantsDatabase({ env: { TENANTS_DATABASE_URL: DB_URL } });
    try {
      expect(db.connectionSource).toBe("TENANTS_DATABASE_URL");
      expect(db.connectionSource).not.toContain("postgres://");
    } finally {
      await db.close();
    }
  });
});
