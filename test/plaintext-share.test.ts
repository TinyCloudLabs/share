import { describe, expect, it } from "vitest";
import { plaintextHistoryRecord, publishPlaintextShare, resolvePlaintextShare } from "../src/share/plaintext-share.js";

describe("greenfield public plaintext shares", () => {
  it.each([false, true])("publishes and opens an integrity-bound %s inline share", async (inline) => {
    const blobs = new Map<string, Uint8Array>();
    const expiresAt = "2030-01-02T00:00:00.000Z";
    const published = await publishPlaintextShare({ bytes: new TextEncoder().encode("# Public"), filename: "public.md", mediaType: "text/markdown", expiresAt, origin: "https://share.example", inline, upload: async (cid, blob) => { blobs.set(cid, blob.slice()); } });
    const resolved = await resolvePlaintextShare(published.url, { expectedOrigin: "https://share.example", registryBaseUrl: "https://registry.example", now: () => Date.parse("2030-01-01T00:00:00.000Z"), fetchFn: async (input) => { const cid = String(input).split("/").at(-1)!; const blob = blobs.get(cid); return blob === undefined ? new Response(null, { status: 404 }) : new Response(blob as BodyInit); } });
    expect(new TextDecoder().decode(resolved!.bytes)).toBe("# Public");
    expect(resolved!.manifest).toMatchObject({ filename: "public.md", contentCid: expect.stringMatching(/^b/) });
  });

  it("produces the canonical bearer record persisted by All shares", () => {
    const record = plaintextHistoryRecord({ cid: "bafyplain", url: "https://share.example/s/bafyplain", filename: "public.md", origin: "https://share.example", registeredAt: "2030-01-01T00:00:00.000Z", expiresAt: "2030-01-02T00:00:00.000Z" });
    expect(record).toMatchObject({ shareId: "bafyplain", targetKind: "bearer", recipientMatcher: { kind: "bearer" }, resource: { kind: "exact", path: "public.md" }, actions: ["tinycloud.kv/get"], link: "https://share.example/s/bafyplain" });
  });

  it("rejects non-canonical, oversized, and tampered public input", async () => {
    const origin = "https://share.example";
    const expiresAt = "2030-01-02T00:00:00.000Z";
    const bytes = new TextEncoder().encode("safe");
    const contentCid = await (await import("@tinycloud/share-envelope")).computeCid(bytes);
    const base = { type: "tinycloud.public-share/v1", filename: "safe.txt", mediaType: "text/plain", byteLength: bytes.byteLength, contentCid, expiresAt, origin } as const;
    const resolveManifest = async (manifest: Record<string, unknown>, content = bytes): Promise<unknown> => {
      const { canonicalize, computeCid } = await import("@tinycloud/share-envelope");
      const blob = new TextEncoder().encode(canonicalize(manifest));
      const cid = await computeCid(blob);
      return resolvePlaintextShare(`${origin}/s/${cid}`, { expectedOrigin: origin, registryBaseUrl: "https://registry.example", now: () => Date.parse("2030-01-01T00:00:00.000Z"), fetchFn: async (input) => String(input).endsWith(cid) ? new Response(blob) : new Response(content) });
    };
    await expect(resolveManifest({ ...base, unexpected: true })).rejects.toThrow(/manifest invalid/);
    await expect(resolveManifest({ ...base, filename: "../unsafe.txt" })).rejects.toThrow(/manifest invalid/);
    await expect(resolveManifest({ ...base, byteLength: 101 * 1024 * 1024 })).rejects.toThrow(/manifest invalid/);
    await expect(resolveManifest(base, new TextEncoder().encode("evil"))).rejects.toThrow(/integrity failure/);
  });
});
