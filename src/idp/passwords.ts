// Password hashing for IdP human/agent users. Uses node:crypto scrypt (portable,
// no runtime coupling) with a random per-hash salt and constant-time compare.
// Stored format: `scrypt$N$saltB64url$hashB64url`. OTP codes are hashed with the
// same primitive so no plaintext credential is ever persisted.

import { randomBytes, scryptSync, timingSafeEqual, createHash } from "node:crypto";

const SCRYPT_COST = 16384; // N; keep in the stored string so it can evolve.
const KEY_LEN = 32;

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const derived = scryptSync(password, salt, KEY_LEN, { N: SCRYPT_COST });
  return `scrypt$${SCRYPT_COST}$${salt.toString("base64url")}$${derived.toString("base64url")}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "scrypt") return false;
  const cost = Number(parts[1]);
  if (!Number.isInteger(cost) || cost < 2) return false;
  let salt: Buffer;
  let expected: Buffer;
  try {
    salt = Buffer.from(parts[2]!, "base64url");
    expected = Buffer.from(parts[3]!, "base64url");
  } catch {
    return false;
  }
  const derived = scryptSync(password, salt, expected.length, { N: cost });
  return derived.length === expected.length && timingSafeEqual(derived, expected);
}

/** sha256 hex — used for OTP codes and opaque session tokens at rest. */
export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
