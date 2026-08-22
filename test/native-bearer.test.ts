import { describe, expect, it } from "vitest";
import { composeNativeBearer } from "../src/share/native-bearer.js";
import { receiveNativeBearer } from "../src/viewer/native-bearer.js";

describe("TinyCloud-native bearer happy path", () => {
  it("writes exact bytes, creates one exact read delegation, then reads it through the SDK", async () => {
    const bytes = new Uint8Array([0, 1, 2, 255]);
    const calls: string[] = [];
    const sharing = {
      generate: async (params: { path: string; actions: string[] }) => {
        calls.push(`delegate:${params.path}:${params.actions.join(",")}`);
        return { ok: true as const, data: { token: "tc1:bearer" } };
      },
      receive: async (token: string) => ({ ok: true as const, data: { path: "xyz.tinycloud.share/shares/a.bin", spaceId: "tinycloud:pkh:eip155:1:0xabc:applications", delegation: { expiry: new Date("2030-01-01T00:00:00.000Z") }, kv: { get: async (path: string) => { calls.push(`get:${token}:${path}`); return { ok: true as const, data: { data: bytes } }; } } } }),
    };
    const url = await composeNativeBearer({ kvForSpace: (space) => ({ put: async (path, value) => { calls.push(`put:${space}:${path}:${Array.from(value)}`); return { ok: true }; } }), sharing }, { path: "xyz.tinycloud.share/shares/a.bin", bytes, expiresAt: new Date("2030-01-01T00:00:00Z"), viewerOrigin: "https://viewer.example" });
    await expect(receiveNativeBearer(sharing, url)).resolves.toEqual(bytes);
    expect(calls).toEqual(["put:applications:xyz.tinycloud.share/shares/a.bin:0,1,2,255", "delegate:xyz.tinycloud.share/shares/a.bin:tinycloud.kv/get", "get:tc1:bearer:"]);
  });

  it("surfaces revocation as a denied bearer read", async () => {
    const revoked = {
      receive: async () => ({ ok: false as const, error: { message: "Sharing link has been revoked" } }),
      generate: async () => ({ ok: true as const, data: { token: "unused" } }),
    };
    await expect(receiveNativeBearer(revoked, "https://viewer.example/#tc1=revoked")).rejects.toThrow("revoked");
  });
});
