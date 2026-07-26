#!/usr/bin/env bun
/**
 * Release guard: scan the ACTUAL PACKED ARTIFACT for disclosure.
 *
 * Why this exists
 * ---------------
 * `@hasna/tenants@0.1.0` shipped the complete list of owned apex domains to the
 * public npm registry. The repository was private, so source review saw nothing;
 * the disclosure existed only in the built `dist/` bundles that npm actually
 * publishes. Any check that reads `src/` is therefore insufficient BY
 * CONSTRUCTION — it inspects a different set of bytes than the ones shipped.
 *
 * So this guard starts from `npm pack --dry-run --json`, which reports exactly
 * the file list npm would publish (honouring `files`, `.npmignore`, and npm's
 * built-in rules), and scans the CONTENT of those files. Whatever npm would
 * upload is what gets read.
 *
 * It runs from two places so it cannot be bypassed:
 *   - `bun run verify:release` — the normal pre-release gate.
 *   - `prepack` — npm's own lifecycle hook, which runs on `npm pack` AND
 *     `npm publish`. Publishing directly, without the verify script, still runs
 *     it. (The nested `npm pack` below passes `--ignore-scripts` so this hook
 *     does not re-enter itself.)
 *
 * Known limits (stated so no one mistakes this for a proof)
 * ---------------------------------------------------------
 * It matches literals in text. A value assembled at runtime (`brand + ".xyz"`),
 * encoded (base64), or fetched from a network service will not be seen. It
 * catches the shape of the incident that happened — a constant compiled into the
 * bundle — and every routine variant of it, not an adversary hiding data on
 * purpose. Binary files are listed but not scanned.
 *
 * `npm publish --ignore-scripts` skips ALL lifecycle hooks, this one included.
 * No package.json setting can defeat that flag; closing it needs a publish path
 * that runs `verify:release` (CI, or a release script). Publish through
 * `bun run verify:release` rather than reaching for `--ignore-scripts`.
 *
 * Exit codes: 0 clean · 1 violations found · 2 the guard could not run.
 */

import { spawnSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

// ── what counts as ours ──────────────────────────────────────────────────────

/**
 * Brand labels whose apex domains must never appear in a published artifact.
 * Add a label here and every `<label>.<tld>` literal becomes a release blocker.
 */
export const BRAND_DOMAIN_LABELS = ["hasna"] as const;

/** Hostname suffixes that only ever name private infrastructure. */
const INTERNAL_TLDS = ["internal", "intranet", "corp", "lan", "local", "localdomain"] as const;

const BRAND_ALTERNATION = BRAND_DOMAIN_LABELS.join("|");

/**
 * Private/carrier-grade IPv4 ranges. Deliberately EXCLUDES 127.0.0.0/8
 * (loopback) and 169.254.0.0/16 (link-local, e.g. the fixed AWS container
 * credentials address): those are well-known constants that identify no
 * deployment of ours, and flagging them would only teach reviewers to add
 * exceptions.
 */
const PRIVATE_IPV4 =
  String.raw`(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}` +
  String.raw`|192\.168\.\d{1,3}\.\d{1,3}` +
  String.raw`|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}` +
  String.raw`|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})`;

export type Severity = "disclosure" | "credential";

export interface Rule {
  id: string;
  severity: Severity;
  description: string;
  pattern: RegExp;
  /** Mask the matched text in output (credentials must never be echoed). */
  redact?: boolean;
}

export const RULES: Rule[] = [
  {
    id: "brand-domain",
    severity: "disclosure",
    description: "Owned apex domain literal (the 0.1.0 incident class)",
    pattern: new RegExp(String.raw`\b(?:${BRAND_ALTERNATION})\.[a-z]{2,24}(?:\.[a-z]{2,24})?\b`, "gi"),
  },
  {
    id: "brand-subdomain",
    severity: "disclosure",
    description: "Hostname under an owned apex domain",
    pattern: new RegExp(String.raw`\b[a-z0-9][a-z0-9-]*\.(?:${BRAND_ALTERNATION})\.[a-z]{2,24}\b`, "gi"),
  },
  {
    id: "internal-host",
    severity: "disclosure",
    description: "Private-infrastructure hostname",
    // Two or more labels before an internal TLD, so ordinary property access
    // such as `config.internal` is not mistaken for a hostname.
    pattern: new RegExp(
      String.raw`\b[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9-]*\.(?:${INTERNAL_TLDS.join("|")})\b`,
      "gi",
    ),
  },
  {
    id: "tailnet-host",
    severity: "disclosure",
    description: "Tailscale tailnet hostname",
    pattern: /\b[a-z0-9][a-z0-9-]*\.ts\.net\b/gi,
  },
  {
    id: "private-ip",
    severity: "disclosure",
    description: "Private / tailnet IPv4 address",
    pattern: new RegExp(String.raw`\b${PRIVATE_IPV4}\b`, "g"),
  },
  {
    id: "aws-resource-endpoint",
    severity: "disclosure",
    description: "Region-scoped AWS resource endpoint (identifies an account's infrastructure)",
    // Matches `name.abc123.us-east-1.rds.amazonaws.com` but not the public,
    // account-independent `truststore.pki.rds.amazonaws.com`.
    pattern: /\b[a-z0-9-]+\.[a-z]{2}-[a-z]+-\d\.(?:rds|elb|es|cache|redshift|execute-api|elasticbeanstalk)\.amazonaws\.com\b/gi,
  },
  {
    id: "aws-account-id",
    severity: "disclosure",
    description: "AWS account id (ARN or ECR registry host)",
    pattern: /(?:arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:\d{12}:|\b\d{12}\.dkr\.ecr\.)/gi,
  },
  {
    id: "aws-access-key-id",
    severity: "credential",
    description: "AWS access key id",
    pattern: /\b(?:AKIA|ASIA|AIDA|AROA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    redact: true,
  },
  {
    id: "private-key-block",
    severity: "credential",
    description: "PEM private key block",
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
    redact: true,
  },
  {
    id: "github-token",
    severity: "credential",
    description: "GitHub token",
    pattern: /\bgh[pousr]_[A-Za-z0-9]{16,}\b/g,
    redact: true,
  },
  {
    id: "npm-token",
    severity: "credential",
    description: "npm access token",
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
    redact: true,
  },
  {
    id: "slack-token",
    severity: "credential",
    description: "Slack token",
    pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g,
    redact: true,
  },
  {
    id: "provider-api-key",
    severity: "credential",
    description: "Provider API key (sk-…, AIza…)",
    pattern: /\b(?:sk-(?:ant-)?[A-Za-z0-9_-]{24,}|AIza[0-9A-Za-z_-]{35})\b/g,
    redact: true,
  },
  {
    id: "jwt",
    severity: "credential",
    description: "Serialized JWT",
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
    redact: true,
  },
  {
    id: "hardcoded-secret",
    severity: "credential",
    description: "Literal assigned to a secret-looking name",
    pattern:
      /\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*["'`][^"'`\n]{8,}["'`]/gi,
    redact: true,
  },
];

export interface Violation {
  file: string;
  line: number;
  ruleId: string;
  severity: Severity;
  description: string;
  excerpt: string;
}

function mask(value: string): string {
  if (value.length <= 6) return "*".repeat(value.length);
  return `${value.slice(0, 4)}${"*".repeat(Math.min(value.length - 4, 20))}<redacted>`;
}

/** Scan one file's text against every rule. Exported for unit tests. */
export function scanText(text: string, file = "<memory>"): Violation[] {
  const violations: Violation[] = [];
  const lines = text.split("\n");
  for (const rule of RULES) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      rule.pattern.lastIndex = 0;
      for (const match of line.matchAll(rule.pattern)) {
        violations.push({
          file,
          line: i + 1,
          ruleId: rule.id,
          severity: rule.severity,
          description: rule.description,
          excerpt: rule.redact ? mask(match[0]) : match[0],
        });
      }
    }
  }
  return violations;
}

// ── packed file list ─────────────────────────────────────────────────────────

export interface PackedFile {
  path: string;
  size: number;
}

/**
 * Ask npm exactly which files it would publish.
 *
 * `--ignore-scripts` is REQUIRED: this guard itself runs from `prepack`, and
 * without it the nested pack would re-enter the guard forever.
 */
export function listPackedFiles(cwd: string): PackedFile[] {
  const result = spawnSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error) throw new Error(`could not run \`npm pack\`: ${result.error.message}`);
  if (result.status !== 0) {
    throw new Error(`\`npm pack --dry-run\` failed (exit ${result.status}):\n${result.stderr ?? ""}`);
  }
  const stdout = (result.stdout ?? "").trim();
  const start = stdout.indexOf("[");
  if (start === -1) throw new Error(`\`npm pack --dry-run --json\` produced no JSON:\n${stdout}`);
  const parsed = JSON.parse(stdout.slice(start)) as Array<{ files?: PackedFile[] }>;
  const files = parsed[0]?.files;
  if (!files?.length) throw new Error("`npm pack --dry-run --json` reported no files");
  return files;
}

/** A NUL byte in the head of a file is a good-enough binary signal. */
function isBinary(buf: Buffer): boolean {
  return buf.subarray(0, 8192).includes(0);
}

export interface ScanReport {
  scanned: string[];
  skipped: string[];
  violations: Violation[];
}

export function scanPackedArtifact(cwd: string): ScanReport {
  const files = listPackedFiles(cwd);
  const report: ScanReport = { scanned: [], skipped: [], violations: [] };
  for (const file of files) {
    const abs = resolve(cwd, file.path);
    if (!existsSync(abs)) {
      throw new Error(`npm would pack \`${file.path}\`, but it is missing from the working tree`);
    }
    const buf = readFileSync(abs);
    if (isBinary(buf)) {
      report.skipped.push(file.path);
      continue;
    }
    report.scanned.push(file.path);
    report.violations.push(...scanText(buf.toString("utf8"), file.path));
  }

  // A guard that scans nothing must never report success: an unbuilt or
  // mis-configured package would otherwise pass silently.
  const builtJs = report.scanned.filter((p) => p.startsWith("dist/") && p.endsWith(".js"));
  if (builtJs.length === 0) {
    throw new Error(
      "no built `dist/**/*.js` files in the packed set — run `bun run build` before packing " +
        "(refusing to report a clean artifact that contains no build output)",
    );
  }
  return report;
}

// ── entry point ──────────────────────────────────────────────────────────────

function main(): number {
  const cwd = process.cwd();
  let report: ScanReport;
  try {
    report = scanPackedArtifact(cwd);
  } catch (error) {
    console.error(`✗ artifact check could not run: ${error instanceof Error ? error.message : String(error)}`);
    return 2;
  }

  if (report.violations.length === 0) {
    console.log(
      `✓ packed artifact clean — ${report.scanned.length} file(s) scanned` +
        `${report.skipped.length ? `, ${report.skipped.length} binary file(s) skipped` : ""}, ` +
        `${RULES.length} rules applied`,
    );
    return 0;
  }

  console.error(`✗ packed artifact would disclose ${report.violations.length} item(s):\n`);
  const byFile = new Map<string, Violation[]>();
  for (const v of report.violations) {
    byFile.set(v.file, [...(byFile.get(v.file) ?? []), v]);
  }
  for (const [file, violations] of byFile) {
    console.error(`  ${file}`);
    for (const v of violations) {
      console.error(`    line ${v.line}  [${v.ruleId}] ${v.description}: ${v.excerpt}`);
    }
    console.error("");
  }
  console.error(
    "These bytes are what npm would publish. Remove them from the SOURCE, rebuild, and re-run.\n" +
      "Configuration belongs in environment variables, not in the package.",
  );
  return 1;
}

if (import.meta.main) {
  // Safety net: if `--ignore-scripts` ever stops suppressing the prepack hook,
  // the nested run exits quietly and the outer run still decides the outcome.
  if (process.env["TENANTS_PACK_GUARD_ACTIVE"] === "1") {
    console.error("… nested artifact check skipped (outer run owns the result)");
    process.exit(0);
  }
  process.env["TENANTS_PACK_GUARD_ACTIVE"] = "1";
  process.exit(main());
}
