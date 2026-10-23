// @vitest-environment node
import { describe, expect, it, vi } from "vitest";
import { generateKey, seal, toBase64Url } from "@tinycloud/share-envelope";
import { LINK_BODY_MAX_BYTES } from "../src/short-links/limits.js";
import { LinkReadError, resolveLink } from "../src/short-links/resolve.js";
import { publishLink } from "../src/short-links/publish.js";
import { SHORT_LINK_UNAVAILABLE_NOTICE } from "../src/short-links/strings.js";
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

  it("gives a body one byte over the limit the full link with the notice, without calling the API", async () => {
    const fetchFn = vi.fn() as unknown as typeof fetch;
    const result = await publish(await sealedOfSize(LINK_BODY_MAX_BYTES + 1), fetchFn);
    expect(result.form).toBe("full");
    expect(result.notice).toBe(SHORT_LINK_UNAVAILABLE_NOTICE);
    expect(fetchFn).not.toHaveBeenCalled();
    // The full link opens: it is not stored, so the stored-link limit does not apply to it.
    const opened = await resolveLink(result.url, { trustedOrigins: [SHARE_ORIGIN], apiOrigin: API_ORIGIN, fetchFn });
    expect(opened.sealedBody.byteLength).toBe(LINK_BODY_MAX_BYTES + 1);
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("reads a stored body of exactly the limit and refuses one byte over as not found", async () => {
    const links = mockLinks();
    const options = { trustedOrigins: [SHARE_ORIGIN], apiOrigin: API_ORIGIN, fetchFn: links.fetchFn };
    const atLimit = await publish(await sealedOfSize(LINK_BODY_MAX_BYTES), links.fetchFn);
    await expect(resolveLink(atLimit.url, options)).resolves.toMatchObject({ type: "share" });

    // A service that stores more than the viewer reads: the viewer's streaming bound refuses it.
    const over = await sealedOfSize(LINK_BODY_MAX_BYTES + 1);
    const created = await publish(over, links.fetchFn);
    expect(created.form).toBe("full");
    const [id, record] = [...links.api.state.records.entries()][0]!;
    const { header, signature } = JSON.parse(atob((await links.api.handle({ method: "GET", path: `/v1/links/${id}`, headers: {} })).headers.get("x-link-record")!.replace(/-/g, "+").replace(/_/g, "/")));
    links.api.state.records.set("aaaaaaaaaaaaaaaaaaaaaaaaaa", { ...record, body: new Uint8Array(LINK_BODY_MAX_BYTES + 1), headerJcs: JSON.stringify(header), signature });
    const link = atLimit.url.replace(id, "aaaaaaaaaaaaaaaaaaaaaaaaaa");
    const refused = await resolveLink(link, options).catch((error: unknown) => error);
    expect(refused).toBeInstanceOf(LinkReadError);
    expect((refused as LinkReadError).kind).toBe("not-found");
  });
});
