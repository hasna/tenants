import { describe, expect, test } from "bun:test";
import { BRAND_DOMAIN_LABELS, RULES, scanText } from "./check-packed-artifact.js";

// Fixtures are assembled at runtime so this test file does not itself contain
// the literals the guard exists to keep out of the repository.
const BRAND = BRAND_DOMAIN_LABELS[0];
const apex = (tld: string) => `${BRAND}.${tld}`;
const host = (sub: string, tld: string) => `${sub}.${BRAND}.${tld}`;

function ids(text: string): string[] {
  return [...new Set(scanText(text).map((v) => v.ruleId))].sort();
}

describe("disclosure rules", () => {
  test("catches an owned apex domain literal — the 0.1.0 incident", () => {
    const built = `var DEFAULT_ALLOWED_EMAIL_DOMAINS = ["${apex("xyz")}", "${apex("dev")}"];`;
    const found = scanText(built, "dist/index.js");
    expect(found.length).toBeGreaterThanOrEqual(2);
    expect(found.every((v) => v.file === "dist/index.js")).toBe(true);
    expect(ids(built)).toContain("brand-domain");
  });

  test("catches multi-label apexes and hostnames beneath them", () => {
    expect(ids(`from "https://${host("domains", "xyz")}/v1"`)).toContain("brand-subdomain");
    expect(ids(`"${apex("co.uk")}"`)).toContain("brand-domain");
    expect(scanText(`"${host("tenants", "xyz")}"`).length).toBeGreaterThan(0);
  });

  test("reports the exact line so it can be fixed", () => {
    const found = scanText(`line one\nline two\nconst h = "${apex("app")}";`);
    expect(found[0]?.line).toBe(3);
    expect(found[0]?.excerpt).toBe(apex("app"));
  });

  test("catches private infrastructure hosts and addresses", () => {
    expect(ids("https://db.prod.internal:5432")).toContain("internal-host");
    expect(ids("host: 10.1.2.3")).toContain("private-ip");
    expect(ids("host: 192.168.0.7")).toContain("private-ip");
    expect(ids("host: 100.101.102.103")).toContain("private-ip"); // tailnet CGNAT
    expect(ids("https://box.example.ts.net")).toContain("tailnet-host");
    expect(ids("mydb.c9x.eu-west-1.rds.amazonaws.com")).toContain("aws-resource-endpoint");
    expect(ids("arn:aws:ses:us-east-1:123456789012:identity/x")).toContain("aws-account-id");
    expect(ids("123456789012.dkr.ecr.us-east-1.amazonaws.com/app")).toContain("aws-account-id");
  });
});

describe("credential rules", () => {
  test("catches standard credential shapes", () => {
    expect(ids(`AWS_ACCESS_KEY_ID=AKIA${"A1B2C3D4E5F6G7H8"}`)).toContain("aws-access-key-id");
    expect(ids(`token=ghp_${"a".repeat(36)}`)).toContain("github-token");
    expect(ids(`//registry.npmjs.org/:_authToken=npm_${"b".repeat(36)}`)).toContain("npm-token");
    expect(ids(`xoxb-${"1".repeat(12)}-abcdef`)).toContain("slack-token");
    expect(ids(`key = "sk-${"c".repeat(32)}"`)).toContain("provider-api-key");
    expect(ids("-----BEGIN OPENSSH PRIVATE KEY-----")).toContain("private-key-block");
    expect(ids(`const password = "hunter2-hunter2";`)).toContain("hardcoded-secret");
    expect(ids(`eyJhbGciOiJI.eyJzdWIiOiIx.dBjftJeZ4CV`)).toContain("jwt");
  });

  test("credential matches are redacted, disclosure matches are not", () => {
    const secret = `AKIA${"A1B2C3D4E5F6G7H8"}`;
    const found = scanText(`AWS_ACCESS_KEY_ID=${secret}`);
    const hit = found.find((v) => v.ruleId === "aws-access-key-id")!;
    expect(hit.severity).toBe("credential");
    expect(hit.excerpt).not.toContain(secret);
    expect(hit.excerpt).toContain("<redacted>");

    const disclosed = scanText(`"${apex("xyz")}"`)[0]!;
    expect(disclosed.severity).toBe("disclosure");
    expect(disclosed.excerpt).toBe(apex("xyz"));
  });
});

describe("no false positives on legitimate build output", () => {
  test("scoped package names, env var names and public hosts pass", () => {
    const clean = [
      `import { mintApiKey } from "@${BRAND}/contracts/auth";`,
      `export const ALLOWED_EMAIL_DOMAINS_ENV = "HASNA_TENANTS_ALLOWED_EMAIL_DOMAINS";`,
      `const url = "https://github.com/${BRAND}/tenants";`,
      `const npmDocs = "https://www.npmjs.com/package/@${BRAND}/identities";`,
      `const bundle = "https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem";`,
      `const ecs = "http://169.254.170.2" + relativeUri;`,
      `const dev = "http://localhost:3000";`,
      `const loop = "http://127.0.0.1:5432";`,
      `if (config.internal) return;`,
      `const host = \`email.\${region}.amazonaws.com\`;`,
      `headers["x-amz-security-token"] = creds.sessionToken;`,
      `const signingSecret = options.signingSecret;`,
    ].join("\n");
    expect(scanText(clean)).toEqual([]);
  });
});

describe("rule table", () => {
  test("every rule is global (all occurrences reported, not just the first)", () => {
    for (const rule of RULES) expect(rule.pattern.flags).toContain("g");
  });

  test("rule ids are unique", () => {
    expect(new Set(RULES.map((r) => r.id)).size).toBe(RULES.length);
  });

  test("repeated scans are stable (no leaked regex lastIndex state)", () => {
    const text = `"${apex("xyz")}" and "${apex("dev")}"`;
    expect(scanText(text).length).toBe(scanText(text).length);
    expect(scanText(text).filter((v) => v.ruleId === "brand-domain").length).toBe(2);
  });
});
