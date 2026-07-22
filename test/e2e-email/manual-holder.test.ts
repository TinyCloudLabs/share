import { describe, expect, it } from "vitest";
import { createExportableTestHolder, exportExportableTestHolder, importExportableTestHolder } from "./manual-holder.ts";

describe("manual holder material", () => {
  it("round-trips an exportable Ed25519 JWK and did:key", async () => {
    const original = await createExportableTestHolder();
    const jwk = await exportExportableTestHolder(original);
    const imported = await importExportableTestHolder(jwk);
    expect(imported.did).toBe(original.did);
    expect((await exportExportableTestHolder(imported)).x).toBe(jwk.x);
  });

  it("rejects a JWK whose public material does not match its private material", async () => {
    const holder = await createExportableTestHolder();
    const jwk = await exportExportableTestHolder(holder);
    await expect(importExportableTestHolder({ ...jwk, x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" })).rejects.toThrow();
  });
});
