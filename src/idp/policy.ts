// Login front-door policy for the IdP: the email-domain allowlist.
//
// Signup AND login are both gated on the caller's email domain — this is the
// org boundary of a deployment, so an address outside the allowlist can neither
// create an account nor sign in.
//
// The allowlist is CONFIG-DRIVEN and has NO built-in default. Operators supply
// it (comma-separated, exact domains) via `HASNA_TENANTS_ALLOWED_EMAIL_DOMAINS`.
// A built-in default would bake one deployment's domain portfolio into every
// published artifact, so this file ships none.
//
// Two properties this file exists to guarantee:
//
//  1. FAIL CLOSED. An unset or empty allowlist permits NOTHING. It is treated as
//     "the front door is not configured" and every signup/login is rejected with
//     an error naming the env var to set. It must never degrade into "allow
//     everything": an operator who forgets the variable gets an outage, which is
//     noisy and recoverable, instead of an open front door, which is silent and
//     not. Turning the check off is possible, but only through a separate,
//     explicitly-named opt-out (`HASNA_TENANTS_DISABLE_EMAIL_ALLOWLIST=1`) that
//     no one sets by accident.
//
//  2. EXACT match, never a suffix or substring match. Comparing the whole
//     lowercased domain against a Set is the only form with no bypass:
//       - `domain.endsWith("example.com")` also admits `notexample.com` — an
//         attacker just registers a domain whose name ENDS with the allowed one.
//       - `domain.includes("example.com")` also admits
//         `example.com.attacker.net`, a domain the attacker fully controls.
//     Subdomains are likewise not implied: `mail.example.com` is allowed only if
//     it is itself listed.

export const ALLOWED_EMAIL_DOMAINS_ENV = "HASNA_TENANTS_ALLOWED_EMAIL_DOMAINS";
export const DISABLE_EMAIL_ALLOWLIST_ENV = "HASNA_TENANTS_DISABLE_EMAIL_ALLOWLIST";
export const REQUIRE_EMAIL_CONFIRMATION_ENV = "HASNA_TENANTS_REQUIRE_EMAIL_CONFIRMATION";

/**
 * Operator-facing message for the fail-closed state. It names the variable to
 * set but never enumerates configured domains — this text reaches unauthenticated
 * callers of `/signup` and `/login`.
 */
export const ALLOWLIST_NOT_CONFIGURED_MESSAGE =
  `Sign-up and sign-in are disabled: no email-domain allowlist is configured. Set ` +
  `${ALLOWED_EMAIL_DOMAINS_ENV} to a comma-separated list of exact domains (or set ` +
  `${DISABLE_EMAIL_ALLOWLIST_ENV}=1 to deliberately accept every domain).`;

/**
 * Rejection message for a domain that is simply not on the list. Deliberately
 * generic: an unauthenticated caller must not be able to enumerate the allowed
 * domains by probing this endpoint.
 */
export const DOMAIN_NOT_ALLOWED_MESSAGE =
  "This email domain is not permitted to sign up or sign in.";

/** Extract the lowercased domain part of an email, or null when malformed. */
export function emailDomain(email: string): string | null {
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1) return null;
  const domain = email.slice(at + 1).trim().toLowerCase();
  if (!domain || domain.includes("@") || !domain.includes(".")) return null;
  return domain;
}

export interface EmailPolicy {
  /**
   * Exact-match allowlist of permitted email domains.
   * - non-empty Set — only these exact domains may sign up / sign in.
   * - EMPTY Set — nothing is permitted (fail closed: front door unconfigured).
   * - `null` — the check is DISABLED and every domain is accepted. Reachable
   *   only by an explicit opt-out; never the result of missing configuration.
   */
  allowedDomains: Set<string> | null;
  /** Require email confirmation before a session/token is minted. */
  requireConfirmation: boolean;
}

/**
 * The fail-closed default: an empty allowlist, which permits no one. Returned as
 * a fresh object so a caller mutating its Set cannot open the door process-wide.
 */
export function denyAllEmailPolicy(): EmailPolicy {
  return { allowedDomains: new Set<string>(), requireConfirmation: true };
}

/**
 * Explicit "no gate at all" policy for local development and tests. Named so it
 * is obvious in review that a call site has turned the front door off; nothing
 * produces this by default.
 */
export const UNRESTRICTED_EMAIL_POLICY: EmailPolicy = Object.freeze({
  allowedDomains: null,
  requireConfirmation: false,
});

export interface EmailDomainDenial {
  /** HTTP status the caller should receive. */
  status: number;
  code: "email_allowlist_not_configured" | "email_domain_not_allowed" | "invalid_email";
  message: string;
}

/**
 * Build the email policy from the environment.
 * - `HASNA_TENANTS_ALLOWED_EMAIL_DOMAINS` — comma-separated exact domains. Unset
 *   or empty yields an EMPTY allowlist, which denies everything (fail closed).
 * - `HASNA_TENANTS_DISABLE_EMAIL_ALLOWLIST=1` — explicit opt-out; disables the
 *   check entirely (local/dev only).
 * - `HASNA_TENANTS_REQUIRE_EMAIL_CONFIRMATION=0` — disables confirmation gating.
 */
export function emailPolicyFromEnv(env: NodeJS.ProcessEnv = process.env): EmailPolicy {
  const disabled = env[DISABLE_EMAIL_ALLOWLIST_ENV] === "1";
  const configured = (env[ALLOWED_EMAIL_DOMAINS_ENV] ?? "")
    .split(",")
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean);
  return {
    allowedDomains: disabled ? null : new Set(configured),
    requireConfirmation: env[REQUIRE_EMAIL_CONFIRMATION_ENV] !== "0",
  };
}

/**
 * Decide whether `email` may use the front door. Returns `null` when it may, or
 * the denial to surface otherwise.
 *
 * The unconfigured-allowlist case is checked FIRST and independently of the
 * address, so a deployment missing its configuration always reports that fact
 * rather than blaming the caller's email.
 */
export function checkEmailDomain(email: string, policy: EmailPolicy): EmailDomainDenial | null {
  if (policy.allowedDomains === null) return null; // explicitly disabled
  if (policy.allowedDomains.size === 0) {
    return { status: 503, code: "email_allowlist_not_configured", message: ALLOWLIST_NOT_CONFIGURED_MESSAGE };
  }
  const domain = emailDomain(email);
  if (!domain) return { status: 400, code: "invalid_email", message: "A valid email address is required." };
  if (!policy.allowedDomains.has(domain)) {
    return { status: 403, code: "email_domain_not_allowed", message: DOMAIN_NOT_ALLOWED_MESSAGE };
  }
  return null;
}

/** True when `email`'s domain is permitted by the policy (or the policy is off). */
export function isEmailDomainAllowed(email: string, policy: EmailPolicy): boolean {
  return checkEmailDomain(email, policy) === null;
}
