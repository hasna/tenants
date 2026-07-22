import { describe, expect, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import {
  boundedTtlSeconds,
  buildJwks,
  DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
  looksLikeAccessToken,
  MAX_ACCESS_TOKEN_TTL_SECONDS,
  signAccessToken,
  signingKeyFromPrivateJwk,
  verifyAccessToken,
} from "./tokens.js";

function freshKey(kid = "k1") {
  const { privateKey } = generateKeyPairSync("ed25519");
  const jwk = privateKey.export({ format: "jwk" }) as Record<string, unknown>;
  return signingKeyFromPrivateJwk(kid, jwk);
}

describe("EdDSA access tokens", () => {
  test("sign then verify round-trips with claims and JWKS", () => {
    const key = freshKey("kid-abc");
    const { token, claims } = signAccessToken(key, {
      aud: "todos", sub: "u1", tid: "t1", pt: "user", scope: ["todos:*"], jti: "j1",
    });
    expect(claims.iss).toBe("identities");
    expect(claims.aud).toBe("todos");
    const jwks = buildJwks([key.publicJwk]);
    const result = verifyAccessToken(token, { jwks: jwks.keys, expectedAudience: "todos" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.claims.sub).toBe("u1");
      expect(result.claims.tid).toBe("t1");
      expect(result.kid).toBe("kid-abc");
    }
  });

  test("rejects a wrong audience", () => {
    const key = freshKey();
    const { token } = signAccessToken(key, { aud: "todos", sub: "u", tid: "t", pt: "user", scope: [], jti: "j" });
    const result = verifyAccessToken(token, { jwks: [key.publicJwk], expectedAudience: "mementos" });
    expect(result).toEqual({ ok: false, reason: "audience_mismatch" });
  });

  test("rejects an expired token", () => {
    const key = freshKey();
    const { token } = signAccessToken(key, {
      aud: "todos", sub: "u", tid: "t", pt: "user", scope: [], jti: "j",
      ttlSeconds: 60, nowMs: Date.now() - 3600_000,
    });
    const result = verifyAccessToken(token, { jwks: [key.publicJwk], expectedAudience: "todos" });
    expect(result).toEqual({ ok: false, reason: "expired" });
  });

  test("rejects a token signed by an unknown key (forgery / rotation gap)", () => {
    const signer = freshKey("real");
    const attacker = freshKey("real"); // same kid, different key material
    const { token } = signAccessToken(attacker, { aud: "todos", sub: "u", tid: "t", pt: "user", scope: [], jti: "j" });
    const result = verifyAccessToken(token, { jwks: [signer.publicJwk] });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("bad_signature");
  });

  test("rejects a tampered payload", () => {
    const key = freshKey();
    const { token } = signAccessToken(key, { aud: "todos", sub: "u", tid: "t", pt: "user", scope: ["todos:read"], jti: "j" });
    const [h, , s] = token.split(".");
    const forgedPayload = Buffer.from(JSON.stringify({ iss: "identities", aud: "todos", sub: "u", tid: "EVIL", pt: "user", scope: ["*"], iat: 1, exp: 9999999999, jti: "j" })).toString("base64url");
    const forged = `${h}.${forgedPayload}.${s}`;
    const result = verifyAccessToken(forged, { jwks: [key.publicJwk] });
    expect(result.ok).toBe(false);
  });

  test("caller-requested TTL above the ceiling is CLAMPED, never honored", () => {
    const key = freshKey();
    const tenYears = 315_360_000;
    const { claims } = signAccessToken(key, {
      aud: "todos", sub: "u", tid: "t", pt: "user", scope: [], jti: "j",
      ttlSeconds: tenYears,
    });
    expect(claims.exp - claims.iat).toBe(MAX_ACCESS_TOKEN_TTL_SECONDS);
  });

  test("a shorter TTL is honored; omitted TTL uses the default", () => {
    const key = freshKey();
    const short = signAccessToken(key, { aud: "todos", sub: "u", tid: "t", pt: "user", scope: [], jti: "j", ttlSeconds: 60 });
    expect(short.claims.exp - short.claims.iat).toBe(60);
    const dflt = signAccessToken(key, { aud: "todos", sub: "u", tid: "t", pt: "user", scope: [], jti: "j" });
    expect(dflt.claims.exp - dflt.claims.iat).toBe(DEFAULT_ACCESS_TOKEN_TTL_SECONDS);
  });

  test("non-positive / non-integer TTLs are rejected", () => {
    const key = freshKey();
    for (const bad of [0, -5, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => signAccessToken(key, { aud: "x", sub: "u", tid: "t", pt: "user", scope: [], jti: "j", ttlSeconds: bad }))
        .toThrow("ttlSeconds must be a positive integer");
    }
    expect(boundedTtlSeconds(undefined)).toBe(DEFAULT_ACCESS_TOKEN_TTL_SECONDS);
  });

  test("looksLikeAccessToken distinguishes JWS from HMAC keys", () => {
    const key = freshKey();
    const { token } = signAccessToken(key, { aud: "x", sub: "u", tid: "t", pt: "user", scope: [], jti: "j" });
    expect(looksLikeAccessToken(token)).toBe(true);
    expect(looksLikeAccessToken("hasna_identities_abc.def")).toBe(false);
    expect(looksLikeAccessToken("garbage")).toBe(false);
  });
});
