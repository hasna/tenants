// Deterministic tenant identifiers for the fleet IdP.
//
// The fleet auth/tenancy standard (v2) fixes ONE canonical root-tenant UUID that
// every app backfills pre-existing rows to, derived as
//   uuidv5( TENANT_NAMESPACE, "tenant:hasna:root" )
// and it MUST equal the constant below. Brand children are derived the same way
// so their ids are stable across every seed run and every machine.
//
// TENANT_NAMESPACE itself is a FIXED, opaque UUIDv5 frozen by the standard. It
// is stored as a literal rather than recomputed from a seed string: the value is
// what matters, and changing it — or the derivation that produced it — would
// silently repoint every tenant id in every deployment.

import { createHash, randomUUID } from "node:crypto";

/** RFC 4122 v5 (SHA-1) UUID from a name under a 16-byte namespace. */
export function uuidv5(name: string, namespace: Buffer): string {
  const hash = createHash("sha1");
  hash.update(namespace);
  hash.update(Buffer.from(name, "utf8"));
  const bytes = hash.digest().subarray(0, 16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x50; // version 5
  bytes[8] = (bytes[8]! & 0x3f) | 0x80; // RFC 4122 variant
  const hex = Buffer.from(bytes).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function parseUuid(uuid: string): Buffer {
  return Buffer.from(uuid.replace(/-/g, ""), "hex");
}

/**
 * Fixed namespace UUID under which every tenant id is derived. Frozen by the
 * fleet auth/tenancy standard v2 — never regenerate it.
 */
export const HASNA_TENANT_NAMESPACE = "709cdf8b-c278-5052-91e1-cc919d35b9e9";

/** Derive a stable tenant UUID from `tenant:<slug>:<kind>`. */
export function deriveTenantId(slug: string, kind: string): string {
  return uuidv5(`tenant:${slug}:${kind}`, parseUuid(HASNA_TENANT_NAMESPACE));
}

/**
 * The FIXED canonical root-tenant UUID (slug `hasna`, kind `root`) from the
 * fleet auth/tenancy standard v2. Every app backfills pre-existing rows to this
 * exact UUID. Verified in tests to equal the derived value.
 */
export const ROOT_TENANT_ID = "adfd95c7-ee8b-52cb-ae47-4ae65dae3313";
export const ROOT_TENANT_SLUG = "hasna";

export interface SeedTenant {
  id: string;
  slug: string;
  name: string;
  kind: string;
  parentId: string | null;
}

/** The root tenant + its brand children, all with fixed derived UUIDs. */
export const SEED_TENANTS: SeedTenant[] = [
  { id: ROOT_TENANT_ID, slug: ROOT_TENANT_SLUG, name: "Hasna", kind: "root", parentId: null },
  { id: deriveTenantId("hasnastudio", "brand"), slug: "hasnastudio", name: "Hasna Studio", kind: "brand", parentId: ROOT_TENANT_ID },
  { id: deriveTenantId("hasnafamily", "brand"), slug: "hasnafamily", name: "Hasna Family", kind: "brand", parentId: ROOT_TENANT_ID },
  { id: deriveTenantId("hasnatools", "brand"), slug: "hasnatools", name: "Hasna Tools", kind: "brand", parentId: ROOT_TENANT_ID },
];

/** Fresh random v4 id (users, sessions, service principals, key ids). */
export function newId(): string {
  return randomUUID();
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * RFC 4122 shape check. Guards caller-supplied ids (e.g. a revoke request's
 * jti) before they reach a Postgres `uuid` column, so malformed input becomes
 * a clean 400 instead of a raw "invalid input syntax for type uuid" error.
 */
export function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}
