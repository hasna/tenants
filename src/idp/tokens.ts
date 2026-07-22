// v2 asymmetric (EdDSA / Ed25519) access tokens for the fleet IdP.
//
// The IdP holds a PRIVATE Ed25519 signing key and mints compact JWS access tokens
// that carry the tenancy claims {iss, aud, sub, tid, pt, scope, iat, exp, jti}.
// Every other app verifies with the PUBLIC key published at the JWKS endpoint —
// so the IdP never holds any app's HMAC secret and a compromise cannot forge
// another app's keys.
//
// WIRE CONTRACT: `iss` is the fixed fleet issuer string `identities` (see
// TOKEN_ISSUER). This is the value every verifying app currently pins; it is a
// cross-fleet contract, NOT a code dependency on the @hasna/identities agent
// registry. Renaming it to `tenants` is a coordinated fleet-wide change (all
// verifiers must update together) and is intentionally out of scope here.
//
// This module is transport/DB-agnostic: it turns a private-key JWK into signed
// tokens and a set of public-key JWKs into a JWKS document. Key persistence lives
// in idp/store.ts; the transitional per-app HMAC path stays in @hasna/contracts.

import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";

export const TOKEN_TYPE = "at+jwt";
export const TOKEN_ALG = "EdDSA";
/**
 * Fixed fleet issuer string embedded in every access token's `iss` claim and
 * enforced on verify. This is a cross-fleet WIRE CONTRACT value pinned by all
 * verifying apps — not a dependency on the @hasna/identities agent registry.
 * Changing it requires a coordinated fleet-wide rollout.
 */
export const TOKEN_ISSUER = "identities";
/** Default access-token TTL (24h) per standard §1.3 (v2 access tokens ≤24h). */
export const DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 24 * 60 * 60;
/**
 * Hard server-side ceiling on any caller-requested TTL (24h per standard §1.3).
 * A caller may only SHORTEN a token's life, never extend it: requests above the
 * ceiling are clamped so no one can mint an effectively irrevocable credential.
 */
export const MAX_ACCESS_TOKEN_TTL_SECONDS = DEFAULT_ACCESS_TOKEN_TTL_SECONDS;

/**
 * Validate + bound a caller-supplied TTL. Non-integer / non-positive values are
 * rejected (throws); values above MAX_ACCESS_TOKEN_TTL_SECONDS are clamped.
 */
export function boundedTtlSeconds(ttlSeconds: number | undefined): number {
  if (ttlSeconds === undefined) return DEFAULT_ACCESS_TOKEN_TTL_SECONDS;
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds <= 0) {
    throw new Error(`ttlSeconds must be a positive integer (got ${String(ttlSeconds)}).`);
  }
  return Math.min(ttlSeconds, MAX_ACCESS_TOKEN_TTL_SECONDS);
}

export interface AccessTokenClaims {
  /** Issuer — the fixed fleet issuer string (see TOKEN_ISSUER). */
  iss: string;
  /** Audience — the app slug the token is for. */
  aud: string;
  /** Subject — principal id (users.id or service_principals.id). */
  sub: string;
  /** Tenant UUID (the isolation boundary). */
  tid: string;
  /** Principal type: user | service. */
  pt: "user" | "service";
  /** Granted scopes (`<app>:<action>` / `<app>:*` / `*`). */
  scope: string[];
  /** Issued-at, epoch seconds. */
  iat: number;
  /** Expiry, epoch seconds. */
  exp: number;
  /** Token id (revocation / audit). */
  jti: string;
}

export interface JwkPublic {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  kid: string;
  use: "sig";
  alg: "EdDSA";
}

export interface JwksDocument {
  keys: JwkPublic[];
}

/** A resolved signing key: private KeyObject + published public JWK + kid. */
export interface SigningKey {
  kid: string;
  privateKey: KeyObject;
  publicJwk: JwkPublic;
}

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

function b64urlJson(value: unknown): string {
  return b64url(JSON.stringify(value));
}

/** Build a SigningKey from a private Ed25519 JWK (as stored / injected). */
export function signingKeyFromPrivateJwk(kid: string, privateJwk: Record<string, unknown>): SigningKey {
  const privateKey = createPrivateKey({ key: privateJwk as any, format: "jwk" });
  const publicKey = createPublicKey(privateKey);
  const pub = publicKey.export({ format: "jwk" }) as { crv?: string; x?: string };
  if (pub.crv !== "Ed25519" || !pub.x) {
    throw new Error("Signing key must be an Ed25519 (OKP) key.");
  }
  return {
    kid,
    privateKey,
    publicJwk: { kty: "OKP", crv: "Ed25519", x: pub.x, kid, use: "sig", alg: "EdDSA" },
  };
}

/** Assemble a JWKS document from one or more public JWKs. */
export function buildJwks(publicJwks: JwkPublic[]): JwksDocument {
  return { keys: publicJwks };
}

export interface SignAccessTokenInput {
  aud: string;
  sub: string;
  tid: string;
  pt: "user" | "service";
  scope: string[];
  /**
   * Requested lifetime. Validated + clamped by boundedTtlSeconds: must be a
   * positive integer, and is capped at MAX_ACCESS_TOKEN_TTL_SECONDS.
   */
  ttlSeconds?: number;
  jti: string;
  nowMs?: number;
}

/** Mint a signed EdDSA access token. TTL is server-bounded (never caller-extended). */
export function signAccessToken(key: SigningKey, input: SignAccessTokenInput): { token: string; claims: AccessTokenClaims } {
  const nowSec = Math.floor((input.nowMs ?? Date.now()) / 1000);
  const ttl = boundedTtlSeconds(input.ttlSeconds);
  const claims: AccessTokenClaims = {
    iss: TOKEN_ISSUER,
    aud: input.aud,
    sub: input.sub,
    tid: input.tid,
    pt: input.pt,
    scope: input.scope,
    iat: nowSec,
    exp: nowSec + ttl,
    jti: input.jti,
  };
  const header = { alg: TOKEN_ALG, kid: key.kid, typ: TOKEN_TYPE };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(claims)}`;
  const signature = edSign(null, Buffer.from(signingInput), key.privateKey);
  return { token: `${signingInput}.${b64url(signature)}`, claims };
}

export type VerifyAccessTokenResult =
  | { ok: true; claims: AccessTokenClaims; kid: string }
  | { ok: false; reason: string };

export interface VerifyAccessTokenOptions {
  /** Public JWKs to verify against (from a JWKS fetch / local key set). */
  jwks: JwkPublic[];
  /** Expected audience (this app slug). Enforced when set. */
  expectedAudience?: string;
  /** Clock-skew leeway in seconds. Default 0. */
  leewaySeconds?: number;
  nowMs?: number;
}

/**
 * Fully verify an EdDSA access token: signature, issuer, audience, expiry.
 *
 * NOTE: this is the STATELESS check (usable offline by any app holding the
 * JWKS) — it cannot see revocations. The tenants service itself additionally
 * consults the issued-token denylist (store.isAccessTokenRevoked / the
 * /v1/auth/revoke surface) after this succeeds; other apps may call
 * /v1/introspect for the same defense-in-depth.
 */
export function verifyAccessToken(token: string, options: VerifyAccessTokenOptions): VerifyAccessTokenResult {
  const parts = token.split(".");
  if (parts.length !== 3) return { ok: false, reason: "malformed" };
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string];
  let header: { alg?: string; kid?: string; typ?: string };
  let claims: AccessTokenClaims;
  try {
    header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
    claims = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  } catch {
    return { ok: false, reason: "malformed" };
  }
  if (header.alg !== TOKEN_ALG) return { ok: false, reason: "unsupported_alg" };
  if (!header.kid) return { ok: false, reason: "missing_kid" };
  const jwk = options.jwks.find((k) => k.kid === header.kid);
  if (!jwk) return { ok: false, reason: "unknown_kid" };

  let verified = false;
  try {
    const publicKey = createPublicKey({ key: jwk as any, format: "jwk" });
    verified = edVerify(null, Buffer.from(`${headerB64}.${payloadB64}`), publicKey, Buffer.from(sigB64, "base64url"));
  } catch {
    return { ok: false, reason: "bad_signature" };
  }
  if (!verified) return { ok: false, reason: "bad_signature" };

  if (claims.iss !== TOKEN_ISSUER) return { ok: false, reason: "issuer_mismatch" };
  if (options.expectedAudience && claims.aud !== options.expectedAudience) {
    return { ok: false, reason: "audience_mismatch" };
  }
  const nowSec = Math.floor((options.nowMs ?? Date.now()) / 1000);
  const leeway = options.leewaySeconds ?? 0;
  if (typeof claims.exp === "number" && nowSec > claims.exp + leeway) {
    return { ok: false, reason: "expired" };
  }
  if (typeof claims.iat === "number" && claims.iat - leeway > nowSec) {
    return { ok: false, reason: "not_yet_valid" };
  }
  return { ok: true, claims, kid: header.kid };
}

/** Structural parse (no signature check) — used to route v1 HMAC vs v2 JWS. */
export function looksLikeAccessToken(token: string): boolean {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  try {
    const header = JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8"));
    return header?.typ === TOKEN_TYPE || header?.alg === TOKEN_ALG;
  } catch {
    return false;
  }
}
