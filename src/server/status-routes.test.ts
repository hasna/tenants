import { beforeAll, describe, expect, test } from "bun:test";
import { createTestFetchHandler } from "../testing/fake-idp.js";

// The status surface used to answer `mode: "cloud"` on four routes, which put a
// deployment-mode word in user-facing output. It now reports the data backend.
//
// Each case separates two behaviours: the body carries a `mode` key naming a
// deployment placement, versus a `backend` key naming the storage engine. Before
// this change every assertion below on `backend` failed and every assertion on
// the absence of `mode` failed, so the inputs could produce the failure.
describe("status routes report a data backend, not a deployment mode", () => {
  let fetchHandler: (req: Request) => Promise<Response>;

  beforeAll(async () => {
    ({ fetch: fetchHandler } = await createTestFetchHandler());
  });

  for (const path of ["/health", "/version", "/"]) {
    test(`GET ${path} reports backend=postgresql and no mode key`, async () => {
      const res = await fetchHandler(new Request(`http://x${path}`));
      expect(res.status).toBe(200);
      const body = (await res.json()) as Record<string, unknown>;
      expect(body["backend"]).toBe("postgresql");
      expect(body).not.toHaveProperty("mode");
      expect(JSON.stringify(body)).not.toContain("cloud");
    });
  }

  test("GET /ready reports backend=postgresql and no mode key", async () => {
    const res = await fetchHandler(new Request("http://x/ready"));
    // The shimmed client answers empty rows, so readiness may be ok or degraded;
    // the assertion here is on the shape, not the verdict.
    const body = (await res.json()) as Record<string, unknown>;
    expect(body["backend"]).toBe("postgresql");
    expect(body).not.toHaveProperty("mode");
    expect(JSON.stringify(body)).not.toContain("cloud");
  });

  test("the OpenAPI description carries no deployment-mode vocabulary", async () => {
    const res = await fetchHandler(new Request("http://x/openapi.json"));
    expect(res.status).toBe(200);
    const text = JSON.stringify(await res.json());
    for (const word of ["PURE REMOTE", "Cloud mode", "self_hosted", "self-hosted", "hybrid"]) {
      expect(text).not.toContain(word);
    }
  });
});
