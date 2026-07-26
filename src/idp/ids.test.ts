import { describe, expect, test } from "bun:test";
import { deriveTenantId, HASNA_TENANT_NAMESPACE, ROOT_TENANT_ID, ROOT_TENANT_SLUG, SEED_TENANTS } from "./ids.js";

describe("tenant ids", () => {
  test("the tenant namespace is a frozen constant", () => {
    // Changing this value silently repoints every derived tenant id in every
    // deployment. It is asserted here so it can only change deliberately.
    expect(HASNA_TENANT_NAMESPACE).toBe("709cdf8b-c278-5052-91e1-cc919d35b9e9");
  });

  test("the derived root tenant id equals the FIXED standard constant", () => {
    // The standard fixes ROOT_TENANT_ID = uuidv5(TENANT_NAMESPACE, 'tenant:hasna:root').
    expect(deriveTenantId("hasna", "root")).toBe(ROOT_TENANT_ID);
    expect(ROOT_TENANT_ID).toBe("adfd95c7-ee8b-52cb-ae47-4ae65dae3313");
  });

  test("brand children are stable and parented to root", () => {
    const root = SEED_TENANTS.find((t) => t.slug === ROOT_TENANT_SLUG)!;
    expect(root.parentId).toBeNull();
    expect(root.kind).toBe("root");
    const brands = SEED_TENANTS.filter((t) => t.kind === "brand");
    expect(brands.map((b) => b.slug).sort()).toEqual(["hasnafamily", "hasnastudio", "hasnatools"]);
    for (const brand of brands) {
      expect(brand.parentId).toBe(ROOT_TENANT_ID);
      expect(brand.id).toBe(deriveTenantId(brand.slug, "brand"));
    }
    // All ids unique.
    const ids = new Set(SEED_TENANTS.map((t) => t.id));
    expect(ids.size).toBe(SEED_TENANTS.length);
  });
});
