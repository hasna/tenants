import { describe, expect, test } from "bun:test";
import {
  DEFAULT_ALLOWED_EMAIL_DOMAINS,
  emailDomain,
  emailPolicyFromEnv,
  isEmailDomainAllowed,
  type EmailPolicy,
} from "./policy.js";

const HASNA: EmailPolicy = { allowedDomains: new Set(DEFAULT_ALLOWED_EMAIL_DOMAINS), requireConfirmation: true };

describe("email domain allowlist", () => {
  test("hasna.xyz is always allowed", () => {
    expect(DEFAULT_ALLOWED_EMAIL_DOMAINS).toContain("hasna.xyz");
    expect(isEmailDomainAllowed("agent@hasna.xyz", HASNA)).toBe(true);
  });

  test("other hasna.<tld> brands are allowed (studio/com/family/tools/ai)", () => {
    for (const d of ["hasna.studio", "hasna.com", "hasna.family", "hasna.tools", "hasna.ai"]) {
      expect(isEmailDomainAllowed(`x@${d}`, HASNA)).toBe(true);
    }
  });

  test("non-hasna domains are rejected", () => {
    for (const e of ["a@gmail.com", "a@hasna.evil.com", "a@notahasna.com", "a@hasnaxyz.com", "a@sub.hasna.xyz.attacker.com"]) {
      expect(isEmailDomainAllowed(e, HASNA)).toBe(false);
    }
  });

  test("case-insensitive + malformed emails rejected", () => {
    expect(isEmailDomainAllowed("A@HASNA.XYZ", HASNA)).toBe(true);
    expect(isEmailDomainAllowed("no-at-sign", HASNA)).toBe(false);
    expect(isEmailDomainAllowed("trailing@", HASNA)).toBe(false);
    expect(emailDomain("x@hasna.xyz")).toBe("hasna.xyz");
    expect(emailDomain("bad")).toBeNull();
  });

  test("null allowlist disables the check (local/dev)", () => {
    const off: EmailPolicy = { allowedDomains: null, requireConfirmation: false };
    expect(isEmailDomainAllowed("anyone@example.com", off)).toBe(true);
  });

  test("env override replaces the default list", () => {
    const p = emailPolicyFromEnv({ HASNA_TENANTS_ALLOWED_EMAIL_DOMAINS: "example.com, Foo.Test" } as any);
    expect(p.allowedDomains?.has("example.com")).toBe(true);
    expect(p.allowedDomains?.has("foo.test")).toBe(true);
    expect(p.allowedDomains?.has("hasna.xyz")).toBe(false);
  });

  test("env can disable allowlist and confirmation", () => {
    const p = emailPolicyFromEnv({ HASNA_TENANTS_DISABLE_EMAIL_ALLOWLIST: "1", HASNA_TENANTS_REQUIRE_EMAIL_CONFIRMATION: "0" } as any);
    expect(p.allowedDomains).toBeNull();
    expect(p.requireConfirmation).toBe(false);
  });

  test("default policy from empty env requires confirmation + uses hasna list", () => {
    const p = emailPolicyFromEnv({} as any);
    expect(p.requireConfirmation).toBe(true);
    expect(p.allowedDomains?.has("hasna.xyz")).toBe(true);
  });
});
