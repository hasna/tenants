// Login front-door policy for the fleet IdP: the email-domain allowlist.
//
// Signup AND login are restricted to the hasna-branded email domains
// (`hasna.xyz` + every `hasna.<tld>` we own). This is the org boundary for the
// internal fleet — a random `@gmail.com` address can neither sign up nor log in.
//
// The allowlist is CONFIG-DRIVEN. Operators override it (comma-separated, exact
// domains) via `HASNA_TENANTS_ALLOWED_EMAIL_DOMAINS`; when that env is unset
// the built-in default below is used. The default was discovered from the live
// domains portfolio (https://domains.hasna.xyz/v1) on 2026-07-13: every ACTIVE
// `hasna.<tld>` apex (177 domains). Matching is EXACT (never a suffix/pattern)
// so `hasna.attacker.com` — a subdomain of someone else's domain — is rejected.

/**
 * Built-in default allowlist: the hasna-branded apex domains from the live
 * domains portfolio (ACTIVE `hasna.<tld>`, snapshot 2026-07-13). `hasna.xyz` is
 * guaranteed present. Refreshable from the domains API; overridable via env.
 */
export const DEFAULT_ALLOWED_EMAIL_DOMAINS: readonly string[] = [
  "hasna.academy", "hasna.agency", "hasna.ai", "hasna.app", "hasna.army", "hasna.art",
  "hasna.asia", "hasna.autos", "hasna.band", "hasna.best", "hasna.bio", "hasna.blog",
  "hasna.builders", "hasna.business", "hasna.cafe", "hasna.camp", "hasna.capital", "hasna.care",
  "hasna.career", "hasna.careers", "hasna.cash", "hasna.cc", "hasna.center", "hasna.charity",
  "hasna.chat", "hasna.city", "hasna.clinic", "hasna.clothing", "hasna.cloud", "hasna.club",
  "hasna.co.uk", "hasna.coach", "hasna.codes", "hasna.coffee", "hasna.com", "hasna.community",
  "hasna.company", "hasna.computer", "hasna.construction", "hasna.consulting", "hasna.contact",
  "hasna.cool", "hasna.day", "hasna.deals", "hasna.delivery", "hasna.dev", "hasna.digital",
  "hasna.dog", "hasna.domains", "hasna.earth", "hasna.eco", "hasna.education", "hasna.email",
  "hasna.energy", "hasna.engineering", "hasna.enterprises", "hasna.estate", "hasna.events",
  "hasna.exchange", "hasna.expert", "hasna.express", "hasna.family", "hasna.fan", "hasna.fans",
  "hasna.farm", "hasna.finance", "hasna.financial", "hasna.fit", "hasna.fitness", "hasna.food",
  "hasna.football", "hasna.foundation", "hasna.fund", "hasna.gallery", "hasna.games",
  "hasna.global", "hasna.gold", "hasna.green", "hasna.group", "hasna.guide", "hasna.guru",
  "hasna.health", "hasna.healthcare", "hasna.holdings", "hasna.homes", "hasna.hospital",
  "hasna.hosting", "hasna.house", "hasna.how", "hasna.industries", "hasna.info", "hasna.ink",
  "hasna.institute", "hasna.international", "hasna.investments", "hasna.irish", "hasna.land",
  "hasna.legal", "hasna.life", "hasna.lifestyle", "hasna.live", "hasna.living", "hasna.llc",
  "hasna.loans", "hasna.love", "hasna.ltd", "hasna.luxury", "hasna.management", "hasna.market",
  "hasna.marketing", "hasna.mba", "hasna.md", "hasna.media", "hasna.mobi", "hasna.money",
  "hasna.net", "hasna.network", "hasna.news", "hasna.ngo", "hasna.ninja", "hasna.one",
  "hasna.ooo", "hasna.page", "hasna.partners", "hasna.place", "hasna.plus", "hasna.pro",
  "hasna.productions", "hasna.properties", "hasna.quest", "hasna.red", "hasna.rentals",
  "hasna.review", "hasna.reviews", "hasna.rocks", "hasna.run", "hasna.sale", "hasna.school",
  "hasna.science", "hasna.services", "hasna.shopping", "hasna.show", "hasna.social",
  "hasna.software", "hasna.solar", "hasna.solutions", "hasna.space", "hasna.store",
  "hasna.studio", "hasna.supply", "hasna.support", "hasna.systems", "hasna.tax", "hasna.team",
  "hasna.tech", "hasna.technology", "hasna.today", "hasna.tools", "hasna.toys", "hasna.trade",
  "hasna.tv", "hasna.university", "hasna.us", "hasna.vc", "hasna.ventures", "hasna.vip",
  "hasna.vision", "hasna.website", "hasna.wiki", "hasna.win", "hasna.work", "hasna.works",
  "hasna.world", "hasna.ws", "hasna.wtf", "hasna.xyz", "hasna.zone",
];

export const ALLOWED_EMAIL_DOMAINS_ENV = "HASNA_TENANTS_ALLOWED_EMAIL_DOMAINS";

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
   * Exact-match allowlist of permitted email domains. `null` DISABLES the check
   * (allow any) — used only by tests/local; production always sets a Set.
   */
  allowedDomains: Set<string> | null;
  /** Require email confirmation before a session/token is minted. */
  requireConfirmation: boolean;
}

/**
 * Build the email policy from the environment.
 * - `HASNA_TENANTS_ALLOWED_EMAIL_DOMAINS` (comma list) overrides the default.
 * - `HASNA_TENANTS_DISABLE_EMAIL_ALLOWLIST=1` fully disables it (escape hatch).
 * - `HASNA_TENANTS_REQUIRE_EMAIL_CONFIRMATION=0` disables confirmation gating.
 */
export function emailPolicyFromEnv(env: NodeJS.ProcessEnv = process.env): EmailPolicy {
  const disabled = env["HASNA_TENANTS_DISABLE_EMAIL_ALLOWLIST"] === "1";
  const override = (env[ALLOWED_EMAIL_DOMAINS_ENV] ?? "").trim();
  const domains = override
    ? override.split(",").map((d) => d.trim().toLowerCase()).filter(Boolean)
    : [...DEFAULT_ALLOWED_EMAIL_DOMAINS];
  return {
    allowedDomains: disabled ? null : new Set(domains),
    requireConfirmation: env["HASNA_TENANTS_REQUIRE_EMAIL_CONFIRMATION"] !== "0",
  };
}

/** True when `email`'s domain is permitted by the policy (or the policy is off). */
export function isEmailDomainAllowed(email: string, policy: EmailPolicy): boolean {
  if (!policy.allowedDomains) return true;
  const domain = emailDomain(email);
  if (!domain) return false;
  return policy.allowedDomains.has(domain);
}
