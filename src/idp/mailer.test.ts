import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  CONFIRM_URL_BASE_ENV,
  MAIL_ENABLED_ENV,
  MAIL_FROM_ENV,
  NoopMailer,
  SES_FROM_ARN_ENV,
  SES_REGION_ENV,
  SesMailer,
  confirmUrlBaseFromEnv,
  createMailerFromEnv,
  resolveEmailDeliveryFromEnv,
} from "./mailer.js";

interface CapturedRequest {
  url: string;
  method: string;
  headers: Headers;
  body: string | undefined;
}

const originalFetch = globalThis.fetch;
const credentialEnvKeys = [
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
  "AWS_CONTAINER_CREDENTIALS_FULL_URI",
  "AWS_CONTAINER_AUTHORIZATION_TOKEN",
] as const;
const originalCredentialEnv = Object.fromEntries(
  credentialEnvKeys.map((key) => [key, process.env[key]]),
) as Record<(typeof credentialEnvKeys)[number], string | undefined>;

beforeEach(() => {
  for (const key of credentialEnvKeys) delete process.env[key];
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  for (const key of credentialEnvKeys) {
    const original = originalCredentialEnv[key];
    if (original === undefined) delete process.env[key];
    else process.env[key] = original;
  }
});

function installSesResponse(body: string, status = 200): CapturedRequest[] {
  const requests: CapturedRequest[] = [];
  globalThis.fetch = async (input: URL | RequestInfo, init?: RequestInit) => {
    requests.push({
      url: String(input),
      method: init?.method ?? "GET",
      headers: new Headers(init?.headers),
      body: init?.body === undefined ? undefined : String(init.body),
    });
    return new Response(body, { status });
  };
  return requests;
}

describe("NoopMailer", () => {
  test("reports that delivery was intentionally skipped", async () => {
    const result = await new NoopMailer().sendConfirmation({
      to: "person@example.com", code: "123456", expiresMinutes: 10,
    });
    expect(result).toEqual({ skipped: true, reason: "email_disabled" });
  });
});

describe("SesMailer", () => {
  test("sends a signed signup email and returns the SES message id", async () => {
    const requests = installSesResponse(JSON.stringify({ MessageId: "message-123" }));
    const mailer = new SesMailer({
      region: "eu-west-1",
      from: "Example Auth <auth@example.com>",
      credentials: { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "secret-key" },
    });

    const result = await mailer.sendConfirmation({
      to: "person@example.com",
      code: "123456",
      link: "https://auth.example.com/v1/auth/confirm?code=123456",
      expiresMinutes: 15,
    });

    expect(result).toEqual({ messageId: "message-123" });
    expect(requests).toHaveLength(1);
    const request = requests[0]!;
    expect(request.url).toBe("https://email.eu-west-1.amazonaws.com/v2/email/outbound-emails");
    expect(request.method).toBe("POST");
    const body = JSON.parse(request.body!);
    expect(body).toMatchObject({
      FromEmailAddress: "Example Auth <auth@example.com>",
      Destination: { ToAddresses: ["person@example.com"] },
      Content: { Simple: { Subject: { Data: "Confirm your account", Charset: "UTF-8" } } },
    });
    expect(body.Content.Simple.Body.Text.Data).toContain("confirmation code is: 123456");
    expect(body.Content.Simple.Body.Text.Data).toContain("confirm in one click: https://auth.example.com");
    expect(body.Content.Simple.Body.Html.Data).toContain("Confirm my account");
    expect(body).not.toHaveProperty("FromEmailAddressIdentityArn");

    const payloadHash = createHash("sha256").update(request.body!).digest("hex");
    expect(request.headers.get("x-amz-content-sha256")).toBe(payloadHash);
    expect(request.headers.get("authorization")).toContain("Credential=AKIDEXAMPLE/");
    expect(request.headers.get("authorization")).toContain("/eu-west-1/ses/aws4_request");
    expect(request.headers.get("x-amz-security-token")).toBeNull();
  });

  test("renders login copy, escapes a quote in the link, and signs a session token", async () => {
    const requests = installSesResponse("{}");
    const mailer = new SesMailer({
      region: "us-east-2",
      from: "login@example.com",
      fromArn: "arn:aws:ses:us-east-2:123456789012:identity/example.com",
      credentials: {
        accessKeyId: "SESSIONKEY",
        secretAccessKey: "session-secret",
        sessionToken: "temporary-token",
      },
    });

    expect(await mailer.sendConfirmation({
      to: "person@example.com",
      code: "654321",
      link: 'https://auth.example.com/confirm?next="account"',
      expiresMinutes: 5,
      purpose: "login",
    })).toEqual({});

    const request = requests[0]!;
    const body = JSON.parse(request.body!);
    expect(body.FromEmailAddressIdentityArn).toContain("identity/example.com");
    expect(body.Content.Simple.Subject.Data).toBe("Your login code");
    expect(body.Content.Simple.Body.Text.Data).toContain("Here is your login code.");
    expect(body.Content.Simple.Body.Html.Data).toContain("&quot;account&quot;");
    expect(request.headers.get("x-amz-security-token")).toBe("temporary-token");
    expect(request.headers.get("authorization")).toContain("x-amz-security-token");
  });

  test("uses credentials from the process environment when none are explicit", async () => {
    process.env["AWS_ACCESS_KEY_ID"] = "ENVKEY";
    process.env["AWS_SECRET_ACCESS_KEY"] = "env-secret";
    const requests = installSesResponse("not-json");

    const result = await new SesMailer({ region: "us-west-1", from: "auth@example.com" })
      .sendConfirmation({ to: "person@example.com", code: "111111", expiresMinutes: 10 });

    expect(result).toEqual({});
    expect(requests[0]?.headers.get("authorization")).toContain("Credential=ENVKEY/");
  });

  test("resolves ECS credentials with the authorization token before sending", async () => {
    process.env["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"] = "/v2/credentials/task";
    process.env["AWS_CONTAINER_AUTHORIZATION_TOKEN"] = "container-auth";
    const requests: CapturedRequest[] = [];
    globalThis.fetch = async (input: URL | RequestInfo, init?: RequestInit) => {
      requests.push({
        url: String(input),
        method: init?.method ?? "GET",
        headers: new Headers(init?.headers),
        body: init?.body === undefined ? undefined : String(init.body),
      });
      if (requests.length === 1) {
        return Response.json({ AccessKeyId: "ECSKEY", SecretAccessKey: "ecs-secret", Token: "ecs-token" });
      }
      return Response.json({ MessageId: "ecs-message" });
    };

    const result = await new SesMailer({ region: "ap-southeast-1", from: "auth@example.com" })
      .sendConfirmation({ to: "person@example.com", code: "222222", expiresMinutes: 10 });

    expect(result).toEqual({ messageId: "ecs-message" });
    expect(requests[0]?.url).toBe("http://169.254.170.2/v2/credentials/task");
    expect(requests[0]?.headers.get("authorization")).toBe("container-auth");
    expect(requests[1]?.headers.get("authorization")).toContain("Credential=ECSKEY/");
    expect(requests[1]?.headers.get("x-amz-security-token")).toBe("ecs-token");
  });

  test("rejects unavailable or missing AWS credentials before delivery", async () => {
    process.env["AWS_CONTAINER_CREDENTIALS_FULL_URI"] = "http://credentials.test/task";
    globalThis.fetch = async () => new Response("no role", { status: 503 });
    const endpointMailer = new SesMailer({ region: "us-east-1", from: "auth@example.com" });
    await expect(endpointMailer.sendConfirmation({
      to: "person@example.com", code: "333333", expiresMinutes: 10,
    })).rejects.toThrow("container credentials endpoint returned 503");

    delete process.env["AWS_CONTAINER_CREDENTIALS_FULL_URI"];
    await expect(endpointMailer.sendConfirmation({
      to: "person@example.com", code: "333333", expiresMinutes: 10,
    })).rejects.toThrow("No AWS credentials available");
  });

  test("surfaces parsed and raw SES errors without leaking credentials", async () => {
    const mailer = new SesMailer({
      region: "us-east-1",
      from: "auth@example.com",
      credentials: { accessKeyId: "SAFEKEY", secretAccessKey: "never-print-this" },
    });
    installSesResponse(JSON.stringify({ message: "sender identity is not verified" }), 400);
    await expect(mailer.sendConfirmation({
      to: "person@example.com", code: "444444", expiresMinutes: 10,
    })).rejects.toThrow("SES send failed (400): sender identity is not verified");

    installSesResponse("upstream unavailable", 502);
    await expect(mailer.sendConfirmation({
      to: "person@example.com", code: "444444", expiresMinutes: 10,
    })).rejects.toThrow("SES send failed (502): upstream unavailable");
  });
});

describe("mailer environment configuration", () => {
  test("normalizes the confirmation base URL and treats blank input as missing", () => {
    expect(confirmUrlBaseFromEnv({})).toBeUndefined();
    expect(confirmUrlBaseFromEnv({ [CONFIRM_URL_BASE_ENV]: "  ///  " })).toBeUndefined();
    expect(confirmUrlBaseFromEnv({
      [CONFIRM_URL_BASE_ENV]: "  https://auth.example.com/path///  ",
    })).toBe("https://auth.example.com/path");
  });

  test("keeps mail disabled unless explicitly enabled", async () => {
    const disabled = createMailerFromEnv({
      [MAIL_ENABLED_ENV]: "true",
      [MAIL_FROM_ENV]: "auth@example.com",
    });
    expect(disabled).toBeInstanceOf(NoopMailer);
    expect(await disabled.sendConfirmation({
      to: "person@example.com", code: "123456", expiresMinutes: 10,
    })).toEqual({ skipped: true, reason: "email_disabled" });
  });

  test("requires a nonblank sender when email is enabled", () => {
    expect(() => createMailerFromEnv({ [MAIL_ENABLED_ENV]: "1", [MAIL_FROM_ENV]: "  " }))
      .toThrow(`${MAIL_FROM_ENV} is required when ${MAIL_ENABLED_ENV}=1`);
  });

  test("builds an enabled SES mailer from configured region and identity", async () => {
    process.env["AWS_ACCESS_KEY_ID"] = "CONFIGKEY";
    process.env["AWS_SECRET_ACCESS_KEY"] = "config-secret";
    const requests = installSesResponse(JSON.stringify({ MessageId: "configured-message" }));
    const mailer = createMailerFromEnv({
      [MAIL_ENABLED_ENV]: "1",
      [MAIL_FROM_ENV]: " Auth <auth@example.com> ",
      [SES_REGION_ENV]: "eu-central-1",
      [SES_FROM_ARN_ENV]: "arn:aws:ses:eu-central-1:123:identity/example.com",
    });
    expect(mailer).toBeInstanceOf(SesMailer);
    expect(await mailer.sendConfirmation({
      to: "person@example.com", code: "555555", expiresMinutes: 10,
    })).toEqual({ messageId: "configured-message" });
    expect(requests[0]?.url).toStartWith("https://email.eu-central-1.amazonaws.com/");
    expect(JSON.parse(requests[0]!.body!)).toMatchObject({
      FromEmailAddress: "Auth <auth@example.com>",
      FromEmailAddressIdentityArn: "arn:aws:ses:eu-central-1:123:identity/example.com",
    });
  });

  test("resolves disabled delivery with or without an optional confirmation base", () => {
    const disabled = resolveEmailDeliveryFromEnv({});
    expect(disabled.mailer).toBeInstanceOf(NoopMailer);
    expect(disabled).not.toHaveProperty("confirmUrlBase");

    const local = resolveEmailDeliveryFromEnv({ [CONFIRM_URL_BASE_ENV]: "http://localhost:15460/" });
    expect(local.confirmUrlBase).toBe("http://localhost:15460");
  });

  test("requires the confirmation URL when delivery is enabled", () => {
    expect(() => resolveEmailDeliveryFromEnv({
      [MAIL_ENABLED_ENV]: "1",
      [MAIL_FROM_ENV]: "auth@example.com",
    })).toThrow(`${CONFIRM_URL_BASE_ENV} is required when ${MAIL_ENABLED_ENV}=1`);
  });

  test("returns the complete enabled delivery configuration", () => {
    const delivery = resolveEmailDeliveryFromEnv({
      [MAIL_ENABLED_ENV]: "1",
      [MAIL_FROM_ENV]: "auth@example.com",
      [CONFIRM_URL_BASE_ENV]: "https://auth.example.com///",
    });
    expect(delivery.mailer).toBeInstanceOf(SesMailer);
    expect(delivery.confirmUrlBase).toBe("https://auth.example.com");
  });
});
