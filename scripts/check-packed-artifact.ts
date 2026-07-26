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
 * It runs from two places, so neither the normal gate nor a direct publish
 * misses it (see the residual `--ignore-scripts` gap below):
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
 * purpose. Files that are not plain text are scanned as raw bytes AND as UTF-16,
 * and then FAIL the check rather than being skipped — the guard never calls a
 * file clean that it could not read.
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
  /** Discard a match that the pattern over-approximates. */
  ignoreMatch?: (match: string) => boolean;
}

/**
 * Trailing labels that make a dotted token a FILENAME rather than a hostname.
 * `@hasna/contracts` ships a config file called `hasna.contract.json`, and a
 * guard that fails a release because a doc comment mentions it is a guard that
 * engineers switch off. Only applied when a label FOLLOWS the apex, so a real
 * two-label domain such as `<brand>.md` is still reported.
 */
const FILE_EXTENSION_LABELS = new Set([
  "json", "js", "mjs", "cjs", "ts", "tsx", "jsx", "map", "lock", "txt", "yaml", "yml",
  "toml", "html", "css", "png", "jpg", "jpeg", "svg", "gif", "log", "bak", "tgz", "zip",
  "sh", "py", "rs", "go", "java", "rb", "php", "sql", "csv", "xml", "ini", "cfg", "conf",
]);

/** `<brand>.contract.json` is a filename; `<brand>.co.uk` and `<brand>.md` are not. */
function isFilenameNotDomain(match: string): boolean {
  const labels = match.toLowerCase().split(".");
  return labels.length > 2 && FILE_EXTENSION_LABELS.has(labels[labels.length - 1]!);
}

export const RULES: Rule[] = [
  {
    id: "brand-domain",
    severity: "disclosure",
    description: "Owned apex domain literal (the 0.1.0 incident class)",
    pattern: new RegExp(String.raw`\b(?:${BRAND_ALTERNATION})\.[a-z]{2,24}(?:\.[a-z]{2,24})?\b`, "gi"),
    ignoreMatch: isFilenameNotDomain,
  },
  {
    id: "brand-subdomain",
    severity: "disclosure",
    description: "Hostname under an owned apex domain",
    pattern: new RegExp(String.raw`\b[a-z0-9][a-z0-9-]*\.(?:${BRAND_ALTERNATION})\.[a-z]{2,24}\b`, "gi"),
    ignoreMatch: isFilenameNotDomain,
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
  /** Set when the hit was found by decoding the file as something other than text. */
  encoding?: string;
}

/** An `artifact-check-ignore:` annotation that suppressed a line. */
export interface HonoredIgnore {
  file: string;
  line: number;
  reason: string;
}

/**
 * Per-line escape hatch: `artifact-check-ignore: <reason>` on the same line
 * suppresses that line. It exists so a false positive gets annotated in a
 * reviewable diff instead of someone deleting the `prepack` hook — the usual
 * fate of a guard that cries wolf. Every honoured ignore is PRINTED on every
 * run, pass or fail, and a reason is mandatory.
 */
const IGNORE_MARKER = /artifact-check-ignore:\s*(\S[^\n]*)/;

function mask(value: string): string {
  if (value.length <= 6) return "*".repeat(value.length);
  return `${value.slice(0, 4)}${"*".repeat(Math.min(value.length - 4, 20))}<redacted>`;
}

export interface ScanTextResult {
  violations: Violation[];
  ignored: HonoredIgnore[];
}

/** Scan one file's text against every rule. Exported for unit tests. */
export function scanTextDetailed(text: string, file = "<memory>", encoding?: string): ScanTextResult {
  const violations: Violation[] = [];
  const ignored: HonoredIgnore[] = [];
  // Split on CR as well: a minified bundle is one long line, and generated files
  // may use CRLF — a rule must not lose its line anchor because of either.
  const lines = text.split(/\r\n|\r|\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const ignore = IGNORE_MARKER.exec(line);
    let lineHits = 0;
    for (const rule of RULES) {
      rule.pattern.lastIndex = 0;
      for (const match of line.matchAll(rule.pattern)) {
        if (rule.ignoreMatch?.(match[0])) continue;
        lineHits++;
        if (ignore) continue;
        violations.push({
          file,
          line: i + 1,
          ruleId: rule.id,
          severity: rule.severity,
          description: rule.description,
          excerpt: rule.redact ? mask(match[0]) : match[0],
          ...(encoding ? { encoding } : {}),
        });
      }
    }
    if (ignore && lineHits > 0) ignored.push({ file, line: i + 1, reason: ignore[1]!.trim() });
  }
  return { violations, ignored };
}

/** Thin wrapper returning only the violations. */
export function scanText(text: string, file = "<memory>"): Violation[] {
  return scanTextDetailed(text, file).violations;
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
    // Recursion marker for the CHILD only. If `--ignore-scripts` ever stops
    // suppressing the prepack hook, the nested guard sees this and exits 2 — a
    // loud failure instead of an infinite loop. It is never read from the
    // ambient parent environment, so it cannot serve as a kill switch.
    env: { ...process.env, TENANTS_PACK_GUARD_ACTIVE: "1" },
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

/** A NUL byte anywhere means the file is not plain text. */
function isBinary(buf: Buffer): boolean {
  return buf.includes(0);
}

/**
 * Packed paths permitted to be non-text. EMPTY ON PURPOSE: a file this guard
 * cannot read as text is a file it cannot certify, and "unscannable" must never
 * read as "clean". Adding a path here is a reviewed decision, visible in a diff.
 */
export const ALLOWED_BINARY_PATHS: readonly string[] = [];

export interface ScanReport {
  scanned: string[];
  /** Packed files that are not plain text. Never silently tolerated. */
  binary: string[];
  violations: Violation[];
  ignored: HonoredIgnore[];
}

export function scanPackedArtifact(cwd: string): ScanReport {
  const files = listPackedFiles(cwd);
  const report: ScanReport = { scanned: [], binary: [], violations: [], ignored: [] };
  for (const file of files) {
    const abs = resolve(cwd, file.path);
    if (!existsSync(abs)) {
      throw new Error(`npm would pack \`${file.path}\`, but it is missing from the working tree`);
    }
    const buf = readFileSync(abs);
    report.scanned.push(file.path);

    // latin1 maps bytes 1:1, so ASCII literals are found even in a file that is
    // not valid UTF-8 — a single NUL byte can no longer hide a domain.
    const primary = scanTextDetailed(buf.toString("latin1"), file.path);
    report.violations.push(...primary.violations);
    report.ignored.push(...primary.ignored);

    if (isBinary(buf)) {
      // Also look for UTF-16 encoded literals — the other common way an ASCII
      // string hides inside binary-looking bytes.
      report.violations.push(...scanTextDetailed(buf.toString("utf16le"), file.path, "utf16le").violations);
      if (!ALLOWED_BINARY_PATHS.includes(file.path)) report.binary.push(file.path);
    }
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

  // Suppressions print on every run, pass or fail: an ignore nobody sees is an
  // ignore that outlives its reason.
  for (const i of report.ignored) {
    console.error(`  ! ignored ${i.file}:${i.line} — ${i.reason}`);
  }

  if (report.binary.length > 0) {
    console.error(
      `✗ ${report.binary.length} packed file(s) are not plain text, so their contents cannot be ` +
        `certified:\n${report.binary.map((p) => `    ${p}`).join("\n")}\n\n` +
        "Remove them from the package, or add them to ALLOWED_BINARY_PATHS with a reason.\n" +
        "A file this guard cannot read is a file it must not call clean.",
    );
    return 1;
  }

  if (report.violations.length === 0) {
    console.log(
      `✓ packed artifact clean — ${report.scanned.length} file(s) scanned, ` +
        `${RULES.length} rules applied` +
        `${report.ignored.length ? `, ${report.ignored.length} line(s) ignored by annotation` : ""}`,
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
      const where = v.encoding ? `line ${v.line} (${v.encoding})` : `line ${v.line}`;
      console.error(`    ${where}  [${v.ruleId}] ${v.description}: ${v.excerpt}`);
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
  // Recursion detection must FAIL, never pass. An earlier version exited 0 here,
  // which turned an inherited environment variable into a silent kill switch:
  // `TENANTS_PACK_GUARD_ACTIVE=1 npm publish` would have sailed through with a
  // leak in the tarball. The nested pack passes `--ignore-scripts`, so this is
  // expected to be unreachable — and if it is ever reached, that is a defect to
  // surface, not a reason to skip the scan.
  if (process.env["TENANTS_PACK_GUARD_ACTIVE"] === "1") {
    console.error(
      "✗ artifact check re-entered itself (TENANTS_PACK_GUARD_ACTIVE already set).\n" +
        "  This variable is internal and must not be set by hand.",
    );
    process.exit(2);
  }
  process.exit(main());
}
