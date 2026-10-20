import { describe, expect, it, vi } from "vitest";
import { composeNativeBearer } from "../src/share/native-bearer.js";
import { senderFailureKind, senderFailureMessage } from "../src/share/sender-failure.js";
import { failIfSpaceNotReady, isSpaceNotFound, SPACE_NOT_READY_CODE } from "../src/share/space-not-ready.js";

const SPACE_ID = "tinycloud:pkh:eip155:1:0xabc:applications";
const unhosted = { ok: false as const, error: { message: 'Failed to put key "xyz.tinycloud.share/shares/a/b.txt": 404 - Space not found', meta: { status: 404 } } };

describe("space-not-found classification of a share write", () => {
  it("accepts only the un-hosted-space 404", () => {
    expect(isSpaceNotFound(unhosted)).toBe(true);
    expect(isSpaceNotFound({ ok: false, error: { message: "KV 404 - Space not found" } })).toBe(true);
    // Other 404s, other statuses, and successes are not remapped.
    expect(isSpaceNotFound({ ok: false, error: { message: "Key not found: a", meta: { status: 404 } } })).toBe(false);
    expect(isSpaceNotFound({ ok: false, error: { message: "Share not found", meta: { status: 404 } } })).toBe(false);
    expect(isSpaceNotFound({ ok: false, error: { message: "Space not found", meta: { status: 500 } } })).toBe(false);
    expect(isSpaceNotFound({ ok: false, error: { message: "Failed to put key: 413 - too large", meta: { status: 413 } } })).toBe(false);
    expect(isSpaceNotFound({ ok: true })).toBe(false);
  });

  it("throws the typed failure, keeps the node's error on cause, and shows copy with no node text", () => {
    const error = (() => { try { failIfSpaceNotReady(unhosted); } catch (caught) { return caught; } })();
    expect(senderFailureKind(error)).toBe("spaceNotReady");
    expect(error).toMatchObject({ code: SPACE_NOT_READY_CODE, cause: unhosted.error });
    expect(senderFailureMessage(error)).toContain("contact support with code SPACE_NOT_READY");
    expect(senderFailureMessage(error)).not.toContain("xyz.tinycloud.share");
  });

  it("leaves every other outcome to the caller", () => {
    expect(() => failIfSpaceNotReady({ ok: true })).not.toThrow();
    expect(() => failIfSpaceNotReady({ ok: false, error: { message: "boom", meta: { status: 503 } } })).not.toThrow();
  });
});

describe("native bearer upload", () => {
  const sharing = {
    generate: vi.fn(async () => ({ ok: true as const, data: { token: "tc1:bearer", delegation: { cid: "bafy-delegation" }, expiresAt: new Date("2030-01-01T00:00:00.000Z") } })),
    decodeLink: () => ({ path: "p", spaceId: SPACE_ID }),
    receive: async () => ({ ok: false as const, error: { message: "unused" } }),
  };
  const input = { path: "xyz.tinycloud.share/shares/a.bin", bytes: new Uint8Array([1, 2]), expiresAt: new Date("2030-01-01T00:00:00Z"), viewerOrigin: "https://viewer.example" };

  it("fails with SPACE_NOT_READY on the first-write 404, once, without creating a delegation", async () => {
    const put = vi.fn(async () => unhosted);
    await expect(composeNativeBearer({ spaceId: SPACE_ID, kvForSpace: () => ({ put }), sharing }, input)).rejects.toMatchObject({ kind: "spaceNotReady", code: SPACE_NOT_READY_CODE });
    expect(put).toHaveBeenCalledTimes(1);
    expect(sharing.generate).not.toHaveBeenCalled();
  });

  it("keeps the generic rejection for other upload failures", async () => {
    const put = vi.fn(async () => ({ ok: false as const, error: { message: "quota", meta: { status: 402 } } }));
    const error = await composeNativeBearer({ spaceId: SPACE_ID, kvForSpace: () => ({ put }), sharing }, input).catch((caught: unknown) => caught);
    expect(senderFailureKind(error)).toBe("internal");
  });
});
