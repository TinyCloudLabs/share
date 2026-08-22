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
      receive: async (token: string) => ({ ok: true as const, data: { path: "applications/a.bin", kv: { get: async (path: string) => { calls.push(`get:${token}:${path}`); return { ok: true as const, data: { data: bytes } }; } } } }),
    };
    const url = await composeNativeBearer({ kv: { put: async (path, value) => { calls.push(`put:${path}:${Array.from(value)}`); return { ok: true }; } }, sharing }, { path: "applications/a.bin", bytes, expiresAt: new Date("2030-01-01T00:00:00Z"), viewerOrigin: "https://viewer.example" });
    await expect(receiveNativeBearer(sharing, url)).resolves.toEqual(bytes);
    expect(calls).toEqual(["put:applications/a.bin:0,1,2,255", "delegate:applications/a.bin:tinycloud.kv/get", "get:tc1:bearer:applications/a.bin"]);
  });
});
