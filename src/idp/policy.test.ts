import { describe, expect, test } from "bun:test";
import * as policyModule from "./policy.js";
import {
  ALLOWED_EMAIL_DOMAINS_ENV,
  checkEmailDomain,
  denyAllEmailPolicy,
  DISABLE_EMAIL_ALLOWLIST_ENV,
  emailDomain,
  emailPolicyFromEnv,
  isEmailDomainAllowed,
  UNRESTRICTED_EMAIL_POLICY,
  type EmailPolicy,
} from "./policy.js";

/** A configured deployment: two exact domains, nothing else. */
const CONFIGURED: EmailPolicy = {
  allowedDomains: new Set(["example.com", "example.net"]),
  requireConfirmation: true,
};

describe("email domain allowlist", () => {
  test("exact configured domains are allowed", () => {
    expect(isEmailDomainAllowed("agent@example.com", CONFIGURED)).toBe(true);
    expect(isEmailDomainAllowed("agent@example.net", CONFIGURED)).toBe(true);
  });

  test("matching is EXACT: no suffix, substring or subdomain bypass", () => {
    for (const email of [
      "a@notexample.com", // suffix-match bypass (`endsWith`)
      "a@example.com.attacker.net", // substring-match bypass (`includes`)
      "a@mail.example.com", // subdomain is not implied by the apex
      "a@example.org", // different TLD
      "a@examplecom", // no dot at all
    ]) {
      expect(isEmailDomainAllowed(email, CONFIGURED)).toBe(false);
    }
  });

  test("case-insensitive matching; malformed addresses rejected", () => {
    expect(isEmailDomainAllowed("A@EXAMPLE.COM", CONFIGURED)).toBe(true);
    expect(isEmailDomainAllowed("no-at-sign", CONFIGURED)).toBe(false);
    expect(isEmailDomainAllowed("trailing@", CONFIGURED)).toBe(false);
    expect(emailDomain("x@example.com")).toBe("example.com");
    expect(emailDomain("bad")).toBeNull();
  });

  test("a rejected domain gets a 403 that does NOT enumerate the allowlist", () => {
    const denial = checkEmailDomain("someone@example.org", CONFIGURED);
    expect(denial?.status).toBe(403);
    expect(denial?.code).toBe("email_domain_not_allowed");
    expect(denial?.message).not.toContain("example.com");
    expect(denial?.message).not.toContain("example.net");
  });
});

// The security property of this module: absent configuration must deny, not allow.
describe("fail closed", () => {
  test("an EMPTY allowlist rejects every address", () => {
    const empty = denyAllEmailPolicy();
    for (const email of ["agent@example.com", "anyone@anywhere.test", "a@b.co"]) {
      expect(isEmailDomainAllowed(email, empty)).toBe(false);
    }
  });

  test("the empty-allowlist denial names the env var to set", () => {
    const denial = checkEmailDomain("agent@example.com", denyAllEmailPolicy());
    expect(denial).not.toBeNull();
    expect(denial?.status).toBe(503);
    expect(denial?.code).toBe("email_allowlist_not_configured");
    expect(denial?.message).toContain(ALLOWED_EMAIL_DOMAINS_ENV);
  });

  test("an unset env yields an empty allowlist, not an open door", () => {
    const p = emailPolicyFromEnv({} as NodeJS.ProcessEnv);
    expect(p.allowedDomains).not.toBeNull();
    expect(p.allowedDomains?.size).toBe(0);
    expect(isEmailDomainAllowed("anyone@example.com", p)).toBe(false);
    expect(p.requireConfirmation).toBe(true);
  });

  test("a blank or separator-only env value still denies", () => {
    for (const value of ["", "   ", ",", " , , "]) {
      const p = emailPolicyFromEnv({ [ALLOWED_EMAIL_DOMAINS_ENV]: value } as NodeJS.ProcessEnv);
      expect(p.allowedDomains?.size).toBe(0);
      expect(isEmailDomainAllowed("anyone@example.com", p)).toBe(false);
    }
  });

  test("the misconfiguration is reported even for a malformed address", () => {
    // Config errors must not be misreported as caller errors.
    expect(checkEmailDomain("not-an-email", denyAllEmailPolicy())?.code)
      .toBe("email_allowlist_not_configured");
  });

  test("denyAllEmailPolicy() returns a fresh Set each call (no shared mutable state)", () => {
    const a = denyAllEmailPolicy();
    a.allowedDomains?.add("attacker.test");
    expect(denyAllEmailPolicy().allowedDomains?.size).toBe(0);
  });

  test("no built-in domain list ships with the package", () => {
    expect("DEFAULT_ALLOWED_EMAIL_DOMAINS" in policyModule).toBe(false);
    const arrays = Object.values(policyModule).filter(Array.isArray);
    expect(arrays).toEqual([]);
  });
});

describe("explicit opt-out", () => {
  test("the check is disabled only by its own env var", () => {
    const p = emailPolicyFromEnv({ [DISABLE_EMAIL_ALLOWLIST_ENV]: "1" } as NodeJS.ProcessEnv);
    expect(p.allowedDomains).toBeNull();
    expect(isEmailDomainAllowed("anyone@anywhere.test", p)).toBe(true);
  });

  test("any value other than exactly \"1\" keeps the gate closed", () => {
    for (const value of ["0", "true", "yes", ""]) {
      const p = emailPolicyFromEnv({ [DISABLE_EMAIL_ALLOWLIST_ENV]: value } as NodeJS.ProcessEnv);
      expect(p.allowedDomains).not.toBeNull();
      expect(isEmailDomainAllowed("anyone@anywhere.test", p)).toBe(false);
    }
  });

  test("UNRESTRICTED_EMAIL_POLICY allows any domain (local/dev escape hatch)", () => {
    expect(isEmailDomainAllowed("anyone@anywhere.test", UNRESTRICTED_EMAIL_POLICY)).toBe(true);
    expect(checkEmailDomain("anyone@anywhere.test", UNRESTRICTED_EMAIL_POLICY)).toBeNull();
  });
});

describe("env configuration", () => {
  test("the env value defines the allowlist, trimmed and lowercased", () => {
    const p = emailPolicyFromEnv({
      [ALLOWED_EMAIL_DOMAINS_ENV]: "example.com, Foo.Test ",
    } as NodeJS.ProcessEnv);
    expect(p.allowedDomains?.has("example.com")).toBe(true);
    expect(p.allowedDomains?.has("foo.test")).toBe(true);
    expect(p.allowedDomains?.size).toBe(2);
  });

  test("confirmation gating is on unless explicitly disabled", () => {
    expect(emailPolicyFromEnv({} as NodeJS.ProcessEnv).requireConfirmation).toBe(true);
    const off = emailPolicyFromEnv({
      HASNA_TENANTS_REQUIRE_EMAIL_CONFIRMATION: "0",
    } as NodeJS.ProcessEnv);
    expect(off.requireConfirmation).toBe(false);
  });
});
