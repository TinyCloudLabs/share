// @vitest-environment node
import { describe, expect, it, vi } from "vitest";
import { generateKey, seal, toBase64Url } from "@tinycloud/share-envelope";
import { LINK_BODY_MAX_BYTES } from "../src/short-links/limits.js";
import { LinkReadError, resolveLink } from "../src/short-links/resolve.js";
import { publishLink } from "../src/short-links/publish.js";
import { ShareTooLargeForLink } from "../src/short-links/errors.js";
import { API_ORIGIN, ISSUER_DID, mockLinks, SHARE_ORIGIN, signWithIssuer, type SealedMaterial } from "./fixtures/link-material.js";

/** A sealed share body of exactly `bytes` bytes (the seal adds 29 bytes to its plaintext). */
async function sealedOfSize(bytes: number): Promise<SealedMaterial> {
  const key = generateKey();
  const base = JSON.stringify({ version: 3, signature: { signerDid: ISSUER_DID, algorithm: "Ed25519", value: "TEST ONLY" }, pad: "" });
  const plaintext = JSON.stringify({ ...JSON.parse(base), pad: "x".repeat(bytes - 29 - base.length) });
  const sealed = await seal(new TextEncoder().encode(plaintext), key);
  expect(sealed.blob.byteLength).toBe(bytes);
  return { sealedEnvelope: toBase64Url(sealed.blob), envelopeKey: toBase64Url(key), shareCid: sealed.cid, bytes: sealed.blob, key };
}

const publish = (material: SealedMaterial, fetchFn: typeof fetch) => publishLink({
  material, expiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString(), signer: { issuerDid: ISSUER_DID, sign: signWithIssuer },
  shareOrigin: SHARE_ORIGIN, apiOrigin: API_ORIGIN, fetchFn,
});

describe("the one stored-link size limit", () => {
  it("is 64 KiB", () => {
    expect(LINK_BODY_MAX_BYTES).toBe(65_536);
  });

  it("sends a body of exactly the limit to the API as a short link", async () => {
    const links = mockLinks();
    const result = await publish(await sealedOfSize(LINK_BODY_MAX_BYTES), links.fetchFn);
    expect(result.form).toBe("short");
    expect(links.api.state.records.size).toBe(1);
  });

  it("creates no link of any form for a body one byte over the limit, and never calls the API", async () => {
    const fetchFn = vi.fn() as unknown as typeof fetch;
    await expect(publish(await sealedOfSize(LINK_BODY_MAX_BYTES + 1), fetchFn)).rejects.toBeInstanceOf(ShareTooLargeForLink);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("opens a full link whose body is exactly the limit, and refuses one a byte over as not found", async () => {
    const links = mockLinks();
    const fetchFn = vi.fn() as unknown as typeof fetch;
    const atLimit = await publishLink({
      material: await sealedOfSize(LINK_BODY_MAX_BYTES), expiresAt: new Date(Date.now() + 40 * 86_400_000).toISOString(), signer: { issuerDid: ISSUER_DID, sign: signWithIssuer },
      shareOrigin: SHARE_ORIGIN, apiOrigin: API_ORIGIN, fetchFn: links.fetchFn,
    });
    expect(atLimit.form).toBe("full");
    await expect(resolveLink(atLimit.url, { trustedOrigins: [SHARE_ORIGIN], apiOrigin: API_ORIGIN, fetchFn })).resolves.toMatchObject({ type: "share" });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("reads a stored body of exactly the limit and refuses one byte over as not found", async () => {
    const links = mockLinks();
    const options = { trustedOrigins: [SHARE_ORIGIN], apiOrigin: API_ORIGIN, fetchFn: links.fetchFn };
    const atLimit = await publish(await sealedOfSize(LINK_BODY_MAX_BYTES), links.fetchFn);
    await expect(resolveLink(atLimit.url, options)).resolves.toMatchObject({ type: "share" });

    // A service that stores more than the viewer reads: the viewer's streaming bound refuses it.
    const [id, record] = [...links.api.state.records.entries()][0]!;
    const { header, signature } = JSON.parse(atob((await links.api.handle({ method: "GET", path: `/v1/links/${id}`, headers: {} })).headers.get("x-link-record")!.replace(/-/g, "+").replace(/_/g, "/")));
    links.api.state.records.set("aaaaaaaaaaaaaaaaaaaaaaaaaa", { ...record, body: new Uint8Array(LINK_BODY_MAX_BYTES + 1), headerJcs: JSON.stringify(header), signature });
    const link = atLimit.url.replace(id, "aaaaaaaaaaaaaaaaaaaaaaaaaa");
    const refused = await resolveLink(link, options).catch((error: unknown) => error);
    expect(refused).toBeInstanceOf(LinkReadError);
    expect((refused as LinkReadError).kind).toBe("not-found");
  });
});
