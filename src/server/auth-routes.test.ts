import { beforeAll, describe, expect, test } from "bun:test";
import { sign as edSign } from "node:crypto";
import { AuthService } from "../idp/service.js";
import { TOKEN_ALG, TOKEN_ISSUER, TOKEN_TYPE } from "../idp/tokens.js";
import { ROOT_TENANT_ID, newId } from "../idp/ids.js";
import { TENANTS_SERVE_APP, createFetchHandler } from "./serve.js";
import { FakeIdpStore, TEST_SIGNING_SECRET as SIGNING_SECRET, createTestFetchHandler, shimClient } from "../testing/fake-idp.js";

describe("Tenants IdP HTTP routes", () => {
  let fetchHandler: (req: Request) => Promise<Response>;
  let fakeStore: FakeIdpStore;

  beforeAll(async () => {
    ({ fetch: fetchHandler, store: fakeStore } = await createTestFetchHandler());
  });

  test("GET /jwks is public and returns an EdDSA key", async () => {
    const res = await fetchHandler(new Request("http://x/jwks"));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.keys[0].kty).toBe("OKP");
    expect(body.keys[0].alg).toBe("EdDSA");
  });

  test("GET /v1/.well-known/jwks.json is also public", async () => {
    const res = await fetchHandler(new Request("http://x/v1/.well-known/jwks.json"));
    expect(res.status).toBe(200);
    expect((await res.json()).keys.length).toBeGreaterThan(0);
  });

  test("signup(password) → token(tenants) → the minted v2 token authenticates /v1/introspect", async () => {
    const signupRes = await fetchHandler(new Request("http://x/signup", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "route@example.com", name: "R", password: "pw-pw-pw-pw" }),
    }));
    expect(signupRes.status).toBe(201);
    const session = (await signupRes.json()).session as string;
    expect(session).toBeTruthy();

    const tokenRes = await fetchHandler(new Request("http://x/v1/auth/token", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${session}` },
      body: JSON.stringify({ app: "tenants", scopes: ["tenants:read"] }),
    }));
    expect(tokenRes.status).toBe(200);
    const tokenBody = await tokenRes.json();
    expect(tokenBody.aud).toBe("tenants");
    const access = tokenBody.access_token as string;

    // The v2 EdDSA token authenticates the /v1 gate (aud=tenants) via JWKS.
    const introspectRes = await fetchHandler(new Request("http://x/v1/introspect?kid=some-kid", {
      headers: { authorization: `Bearer ${access}` },
    }));
    expect(introspectRes.status).toBe(200);
    expect((await introspectRes.json()).active).toBe(false);
  });

  test("a write-scope route rejects a read-only token (403)", async () => {
    // Sign in and mint a read-only token, then hit an unknown /v1 mutation path
    // (POST → requires tenants:write) to prove scope enforcement on the v2 path.
    const s = await fetchHandler(new Request("http://x/login", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "route@example.com", password: "pw-pw-pw-pw" }),
    }));
    const session = (await s.json()).session as string;
    const tokenRes = await fetchHandler(new Request("http://x/v1/auth/token", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${session}` },
      body: JSON.stringify({ app: "tenants", scopes: ["tenants:read"] }),
    }));
    const access = (await tokenRes.json()).access_token as string;
    const writeRes = await fetchHandler(new Request("http://x/v1/introspect", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${access}` },
      body: JSON.stringify({}),
    }));
    expect(writeRes.status).toBe(403);
  });

  test("whoami requires a session and reflects the principal", async () => {
    const s = await fetchHandler(new Request("http://x/login", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "route@example.com", password: "pw-pw-pw-pw" }),
    }));
    const session = (await s.json()).session as string;
    const who = await fetchHandler(new Request("http://x/v1/auth/whoami", { headers: { authorization: `Bearer ${session}` } }));
    expect(who.status).toBe(200);
    expect((await who.json()).principal.email).toBe("route@example.com");
  });

  test("/v1 still rejects an anonymous request (401)", async () => {
    const res = await fetchHandler(new Request("http://x/v1/introspect?kid=x"));
    expect(res.status).toBe(401);
  });

  test("a REVOKED access token is refused on verify (401 revoked) even before exp", async () => {
    const s = await fetchHandler(new Request("http://x/login", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "route@example.com", password: "pw-pw-pw-pw" }),
    }));
    const session = (await s.json()).session as string;
    const tokenRes = await fetchHandler(new Request("http://x/v1/auth/token", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${session}` },
      body: JSON.stringify({ app: "tenants" }),
    }));
    const tokenBody = await tokenRes.json();
    const access = tokenBody.access_token as string;
    const jti = tokenBody.jti as string;
    expect(jti).toBeTruthy();

    // Token works before revocation…
    const before = await fetchHandler(new Request("http://x/v1/introspect?kid=nope", { headers: { authorization: `Bearer ${access}` } }));
    expect(before.status).toBe(200);

    // …then the owner revokes it by jti…
    const revoke = await fetchHandler(new Request("http://x/v1/auth/revoke", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${session}` },
      body: JSON.stringify({ jti }),
    }));
    expect(revoke.status).toBe(200);
    expect((await revoke.json()).revoked).toBe(true);

    // …and the SAME signature-valid, unexpired token is now refused.
    const after = await fetchHandler(new Request("http://x/v1/introspect?kid=nope", { headers: { authorization: `Bearer ${access}` } }));
    expect(after.status).toBe(401);
    expect((await after.json()).reason).toBe("revoked");
  });

  test("public jti introspection lets a JWKS verifier observe revocation", async () => {
    const s = await fetchHandler(new Request("http://x/login", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "route@example.com", password: "pw-pw-pw-pw" }),
    }));
    const session = (await s.json()).session as string;
    const tokenRes = await fetchHandler(new Request("http://x/v1/auth/token", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${session}` },
      // A non-tenants audience proves this is usable by an external JWKS verifier.
      body: JSON.stringify({ app: "todos" }),
    }));
    const jti = String((await tokenRes.json()).jti);

    const status = () => fetchHandler(new Request("http://x/v1/auth/introspect", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ jti }),
    }));

    const before = await status();
    expect(before.status).toBe(200);
    expect(before.headers.get("cache-control")).toBe("no-store");
    expect(await before.json()).toEqual({ active: true, jti });

    const revoke = await fetchHandler(new Request("http://x/v1/auth/revoke", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${session}` },
      body: JSON.stringify({ jti }),
    }));
    expect(revoke.status).toBe(200);

    const after = await status();
    expect(after.status).toBe(200);
    expect(await after.json()).toEqual({ active: false, jti });
  });

  test("a valid-signature tenants token WITHOUT a jti is refused (401 missing_jti), never skipping the denylist", async () => {
    // Craft a JWS with the store's REAL signing key so signature/iss/aud/exp all
    // pass — only the jti claim is absent. Fail-closed means this must be 401.
    const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
    const craft = (claims: Record<string, unknown>): string => {
      const header = { alg: TOKEN_ALG, kid: fakeStore.key.kid, typ: TOKEN_TYPE };
      const signingInput = `${enc(header)}.${enc(claims)}`;
      const signature = edSign(null, Buffer.from(signingInput), fakeStore.key.privateKey);
      return `${signingInput}.${signature.toString("base64url")}`;
    };
    const nowSec = Math.floor(Date.now() / 1000);
    const baseClaims = {
      iss: TOKEN_ISSUER, aud: TENANTS_SERVE_APP, sub: newId(), tid: ROOT_TENANT_ID,
      pt: "user", scope: ["tenants:read"], iat: nowSec, exp: nowSec + 3600,
    };

    // Control: the SAME crafted claims WITH a jti authenticate — so the failure
    // below is attributable to the missing jti, not the crafting harness.
    const withJti = await fetchHandler(new Request("http://x/v1/introspect?kid=nope", {
      headers: { authorization: `Bearer ${craft({ ...baseClaims, jti: newId() })}` },
    }));
    expect(withJti.status).toBe(200);

    // No jti → rejected outright (the denylist can never vouch for this token).
    const res = await fetchHandler(new Request("http://x/v1/introspect?kid=nope", {
      headers: { authorization: `Bearer ${craft(baseClaims)}` },
    }));
    expect(res.status).toBe(401);
    expect((await res.json()).reason).toBe("missing_jti");

    // An empty-string jti is equally unverifiable against the denylist.
    const empty = await fetchHandler(new Request("http://x/v1/introspect?kid=nope", {
      headers: { authorization: `Bearer ${craft({ ...baseClaims, jti: "" })}` },
    }));
    expect(empty.status).toBe(401);
    expect((await empty.json()).reason).toBe("missing_jti");
  });

  test("revoke with a non-UUID jti returns a clean 400 invalid_request (no raw DB error leak)", async () => {
    // Self-contained principal (no dependence on earlier tests' signups).
    const s = await fetchHandler(new Request("http://x/signup", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "revoke-badjti@example.com", name: "RB", password: "pw-pw-pw-pw" }),
    }));
    expect(s.status).toBe(201);
    const session = (await s.json()).session as string;
    const res = await fetchHandler(new Request("http://x/v1/auth/revoke", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${session}` },
      body: JSON.stringify({ jti: "not-a-uuid" }),
    }));
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.reason).toBe("invalid_request");
    expect(body.error).toBe("jti must be a UUID.");
    expect(JSON.stringify(body)).not.toContain("invalid input syntax");
  });

  test("a caller-requested 10-year TTL comes back clamped to 24h over HTTP", async () => {
    const s = await fetchHandler(new Request("http://x/login", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "route@example.com", password: "pw-pw-pw-pw" }),
    }));
    const session = (await s.json()).session as string;
    const tokenRes = await fetchHandler(new Request("http://x/v1/auth/token", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${session}` },
      body: JSON.stringify({ app: "tenants", ttlSeconds: 315360000 }),
    }));
    expect(tokenRes.status).toBe(200);
    expect((await tokenRes.json()).expires_in).toBe(24 * 60 * 60);

    const badRes = await fetchHandler(new Request("http://x/v1/auth/token", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${session}` },
      body: JSON.stringify({ app: "tenants", ttlSeconds: -1 }),
    }));
    expect(badRes.status).toBe(400);
    expect((await badRes.json()).reason).toBe("invalid_ttl");
  });

  test("/v1/introspect is tenant-scoped: a foreign tenant's kid reads active:false", async () => {
    const s = await fetchHandler(new Request("http://x/login", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "route@example.com", password: "pw-pw-pw-pw" }),
    }));
    const session = (await s.json()).session as string;
    const tokenRes = await fetchHandler(new Request("http://x/v1/auth/token", {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${session}` },
      body: JSON.stringify({ app: "tenants", scopes: ["tenants:read"] }),
    }));
    const tokenBody = await tokenRes.json();
    const access = tokenBody.access_token as string;
    const callerTid = tokenBody.tid as string;

    // A key bound INSIDE the caller's tenant is visible…
    fakeStore.bindings.set("kid-same-tenant", { tenant_id: callerTid, user_id: "u-same", principal_type: "user" });
    const same = await fetchHandler(new Request("http://x/v1/introspect?kid=kid-same-tenant", { headers: { authorization: `Bearer ${access}` } }));
    expect(same.status).toBe(200);
    expect(await same.json()).toMatchObject({ active: true, tenant_id: callerTid, user_id: "u-same" });

    // …a key bound to ANOTHER tenant fails closed (no binding leak).
    fakeStore.bindings.set("kid-foreign-tenant", { tenant_id: newId(), user_id: "u-foreign", principal_type: "user" });
    const foreign = await fetchHandler(new Request("http://x/v1/introspect?kid=kid-foreign-tenant", { headers: { authorization: `Bearer ${access}` } }));
    expect(foreign.status).toBe(200);
    const foreignBody = await foreign.json();
    expect(foreignBody).toEqual({ active: false, kid: "kid-foreign-tenant" });
    expect(foreignBody.user_id).toBeUndefined();
  });
});

// The front door must fail CLOSED at the HTTP boundary: a deployment that never
// configured HASNA_TENANTS_ALLOWED_EMAIL_DOMAINS rejects everyone rather than
// admitting everyone. This is the regression test for the allowlist default.
describe("unconfigured allowlist fails closed over HTTP", () => {
  let fetchHandler: (req: Request) => Promise<Response>;

  beforeAll(async () => {
    // No `emailPolicy` at all — exactly what an unconfigured deployment gets.
    const auth = new AuthService({
      store: new FakeIdpStore(), signingSecret: SIGNING_SECRET, apiKeysTable: "api_keys", otpEcho: true,
    });
    fetchHandler = (await createFetchHandler({ client: shimClient, signingSecret: SIGNING_SECRET, auth })).fetch;
  });

  const post = (path: string, body: unknown) =>
    fetchHandler(new Request(`http://x${path}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
    }));

  test("POST /signup is refused with a message naming the env var", async () => {
    const res = await post("/signup", { email: "anyone@example.com", name: "A", password: "pw-pw-pw-pw" });
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.reason).toBe("email_allowlist_not_configured");
    expect(body.error).toContain("HASNA_TENANTS_ALLOWED_EMAIL_DOMAINS");
    expect(body.session).toBeUndefined();
  });

  test("POST /login is refused too (no fail-open on the login path)", async () => {
    const res = await post("/login", { email: "anyone@example.com", password: "pw-pw-pw-pw" });
    expect(res.status).toBe(503);
    expect((await res.json()).reason).toBe("email_allowlist_not_configured");
  });

  test("no address gets in — not even one that looks internal", async () => {
    for (const email of ["a@example.com", "b@sub.example.net", "c@localhost.test"]) {
      const res = await post("/signup", { email, name: "X", password: "pw-pw-pw-pw" });
      expect(res.status).toBe(503);
    }
  });
});
