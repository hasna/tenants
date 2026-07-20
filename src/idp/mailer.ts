// Confirmation-email sender for the IdP login front door.
//
// Sends the signup confirmation via Amazon SES (SESv2 SendEmail) using a
// DKIM-verified sender identity (default `auth@tenants.hasna.xyz`). It calls SES
// DIRECTLY (SigV4 over HTTPS) — no dependency on the `emails` app and no AWS SDK
// in the bundle.
//
// A cross-account send is supported by passing `FromEmailAddressIdentityArn`
// (HASNA_TENANTS_SES_FROM_ARN) so SES attributes the mail to the authorizing
// identity in the account that owns the verified domain.
//
// Credentials come from the standard AWS chain: explicit env keys (local) or the
// ECS container-credentials endpoint (Fargate task role). No secret is ever
// logged; only the returned SES MessageId is surfaced.

import { createHash, createHmac } from "node:crypto";

export interface ConfirmationEmail {
  to: string;
  code: string;
  /** Fully-formed confirmation link (GET) for one-click confirm. */
  link: string;
  /** Minutes until the code/link expires (for the copy). */
  expiresMinutes: number;
  /** Why the code was issued (drives the subject/copy). Default `signup`. */
  purpose?: "signup" | "login";
}

export interface SendResult {
  messageId?: string;
  skipped?: boolean;
  reason?: string;
}

export interface Mailer {
  sendConfirmation(input: ConfirmationEmail): Promise<SendResult>;
}

/** No-op mailer: used when email is disabled (local/dev). Never throws. */
export class NoopMailer implements Mailer {
  async sendConfirmation(_input: ConfirmationEmail): Promise<SendResult> {
    return { skipped: true, reason: "email_disabled" };
  }
}

interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export interface SesMailerOptions {
  region: string;
  /** Envelope From, e.g. `Hasna Tenants <auth@tenants.hasna.xyz>`. */
  from: string;
  /** Cross-account identity ARN authorizing this sender. */
  fromArn?: string;
  /** Explicit credentials (else resolved from the AWS chain at send time). */
  credentials?: AwsCredentials;
}

function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

function hmac(key: Buffer | string, data: string): Buffer {
  return createHmac("sha256", key).update(data, "utf8").digest();
}

/** Resolve AWS credentials: explicit env keys, then the ECS container endpoint. */
async function resolveAwsCredentials(env: NodeJS.ProcessEnv = process.env): Promise<AwsCredentials> {
  const id = env["AWS_ACCESS_KEY_ID"];
  const secret = env["AWS_SECRET_ACCESS_KEY"];
  if (id && secret) {
    return { accessKeyId: id, secretAccessKey: secret, ...(env["AWS_SESSION_TOKEN"] ? { sessionToken: env["AWS_SESSION_TOKEN"] } : {}) };
  }
  const relative = env["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"];
  const full = env["AWS_CONTAINER_CREDENTIALS_FULL_URI"];
  const url = relative ? `http://169.254.170.2${relative}` : full;
  if (url) {
    const headers: Record<string, string> = {};
    const authToken = env["AWS_CONTAINER_AUTHORIZATION_TOKEN"];
    if (authToken) headers["Authorization"] = authToken;
    const res = await fetch(url, { headers });
    if (!res.ok) throw new Error(`container credentials endpoint returned ${res.status}`);
    const body = (await res.json()) as { AccessKeyId: string; SecretAccessKey: string; Token?: string };
    return { accessKeyId: body.AccessKeyId, secretAccessKey: body.SecretAccessKey, ...(body.Token ? { sessionToken: body.Token } : {}) };
  }
  throw new Error("No AWS credentials available (set AWS_ACCESS_KEY_ID/SECRET or run under an ECS task role).");
}

/** SES (SESv2) sender using raw SigV4 — zero third-party dependencies. */
export class SesMailer implements Mailer {
  constructor(private readonly options: SesMailerOptions) {}

  async sendConfirmation(input: ConfirmationEmail): Promise<SendResult> {
    const creds = this.options.credentials ?? (await resolveAwsCredentials());
    const region = this.options.region;
    const host = `email.${region}.amazonaws.com`;
    const path = "/v2/email/outbound-emails";
    const endpoint = `https://${host}${path}`;

    const login = input.purpose === "login";
    const subject = login ? "Your Hasna login code" : "Confirm your Hasna account";
    const bodyObj: Record<string, unknown> = {
      FromEmailAddress: this.options.from,
      Destination: { ToAddresses: [input.to] },
      Content: {
        Simple: {
          Subject: { Data: subject, Charset: "UTF-8" },
          Body: {
            Text: { Data: confirmationText(input), Charset: "UTF-8" },
            Html: { Data: confirmationHtml(input), Charset: "UTF-8" },
          },
        },
      },
    };
    if (this.options.fromArn) bodyObj["FromEmailAddressIdentityArn"] = this.options.fromArn;
    const body = JSON.stringify(bodyObj);

    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, ""); // YYYYMMDDTHHMMSSZ
    const dateStamp = amzDate.slice(0, 8);
    const payloadHash = sha256Hex(body);

    const canonicalHeaders =
      `content-type:application/json\n` +
      `host:${host}\n` +
      `x-amz-content-sha256:${payloadHash}\n` +
      `x-amz-date:${amzDate}\n` +
      (creds.sessionToken ? `x-amz-security-token:${creds.sessionToken}\n` : "");
    const signedHeaders = creds.sessionToken
      ? "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
      : "content-type;host;x-amz-content-sha256;x-amz-date";

    const canonicalRequest = ["POST", path, "", canonicalHeaders, signedHeaders, payloadHash].join("\n");
    const scope = `${dateStamp}/${region}/ses/aws4_request`;
    const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonicalRequest)].join("\n");

    const kDate = hmac(`AWS4${creds.secretAccessKey}`, dateStamp);
    const kRegion = hmac(kDate, region);
    const kService = hmac(kRegion, "ses");
    const kSigning = hmac(kService, "aws4_request");
    const signature = createHmac("sha256", kSigning).update(stringToSign, "utf8").digest("hex");

    const authorization = `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const headers: Record<string, string> = {
      "content-type": "application/json",
      host,
      "x-amz-content-sha256": payloadHash,
      "x-amz-date": amzDate,
      authorization,
    };
    if (creds.sessionToken) headers["x-amz-security-token"] = creds.sessionToken;

    const res = await fetch(endpoint, { method: "POST", headers, body });
    const text = await res.text();
    if (!res.ok) {
      // Surface SES's error type/message (never a credential) for diagnosis.
      let detail = text;
      try {
        const j = JSON.parse(text);
        detail = j.message || j.Message || j.__type || text;
      } catch { /* keep raw */ }
      throw new Error(`SES send failed (${res.status}): ${detail}`);
    }
    let messageId: string | undefined;
    try {
      messageId = (JSON.parse(text) as { MessageId?: string }).MessageId;
    } catch { /* ignore */ }
    return { ...(messageId ? { messageId } : {}) };
  }
}

function confirmationText(i: ConfirmationEmail): string {
  const login = i.purpose === "login";
  return [
    login ? "Here is your Hasna login code." : "Welcome to Hasna.",
    "",
    `Your ${login ? "login" : "confirmation"} code is: ${i.code}`,
    "",
    `Or ${login ? "sign in" : "confirm"} in one click: ${i.link}`,
    "",
    `This code expires in ${i.expiresMinutes} minutes. If you did not request this, ignore this email.`,
  ].join("\n");
}

function confirmationHtml(i: ConfirmationEmail): string {
  const login = i.purpose === "login";
  const safeLink = i.link.replace(/"/g, "&quot;");
  return [
    `<div style="font-family:system-ui,Segoe UI,Roboto,sans-serif;max-width:480px;margin:0 auto">`,
    `<h2>${login ? "Your Hasna login code" : "Welcome to Hasna"}</h2>`,
    `<p>Your ${login ? "login" : "confirmation"} code is:</p>`,
    `<p style="font-size:28px;font-weight:700;letter-spacing:4px">${i.code}</p>`,
    `<p>Or ${login ? "sign in" : "confirm"} in one click:</p>`,
    `<p><a href="${safeLink}" style="background:#111;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">${login ? "Sign in" : "Confirm my account"}</a></p>`,
    `<p style="color:#666;font-size:13px">This code expires in ${i.expiresMinutes} minutes. If you did not request this, ignore this email.</p>`,
    `</div>`,
  ].join("");
}

export const MAIL_FROM_ENV = "HASNA_TENANTS_MAIL_FROM";
export const MAIL_ENABLED_ENV = "HASNA_TENANTS_EMAIL_ENABLED";
export const SES_REGION_ENV = "HASNA_TENANTS_SES_REGION";
export const SES_FROM_ARN_ENV = "HASNA_TENANTS_SES_FROM_ARN";
export const CONFIRM_URL_BASE_ENV = "HASNA_TENANTS_CONFIRM_URL_BASE";

export const DEFAULT_MAIL_FROM = "Hasna Tenants <auth@tenants.hasna.xyz>";
export const DEFAULT_CONFIRM_URL_BASE = "https://tenants.hasna.xyz";

/** The public base URL used to build one-click confirmation links. */
export function confirmUrlBaseFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  return (env[CONFIRM_URL_BASE_ENV] ?? DEFAULT_CONFIRM_URL_BASE).replace(/\/+$/, "");
}

/**
 * Build a mailer from the environment. Returns a NoopMailer unless
 * `HASNA_TENANTS_EMAIL_ENABLED=1`, so email stays inert in local/dev until
 * explicitly turned on in the deployed service.
 */
export function createMailerFromEnv(env: NodeJS.ProcessEnv = process.env): Mailer {
  if (env[MAIL_ENABLED_ENV] !== "1") return new NoopMailer();
  const region = env[SES_REGION_ENV] || env["AWS_REGION"] || "us-east-1";
  const from = env[MAIL_FROM_ENV] || DEFAULT_MAIL_FROM;
  const fromArn = env[SES_FROM_ARN_ENV];
  return new SesMailer({ region, from, ...(fromArn ? { fromArn } : {}) });
}
