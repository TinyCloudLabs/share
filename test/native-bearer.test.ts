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
        return { ok: true as const, data: { token: "tc1:bearer", delegation: { cid: "bafy-native-delegation" }, expiresAt: new Date("2030-01-01T00:00:00.000Z") } };
      },
      decodeLink: () => ({ path: "xyz.tinycloud.share/shares/a.bin", spaceId: "tinycloud:pkh:eip155:1:0xabc:applications" }),
      receive: async () => ({ ok: false as const, error: { message: "not used by the browser adapter" } }),
    };
    const share = await composeNativeBearer({ spaceId: "tinycloud:pkh:eip155:1:0xabc:applications", kvForSpace: (space) => ({ put: async (path, value) => { calls.push(`put:${space}:${path}:${Array.from(value)}`); return { ok: true }; } }), sharing }, { path: "xyz.tinycloud.share/shares/a.bin", bytes, expiresAt: new Date("2030-01-01T00:00:00Z"), viewerOrigin: "https://viewer.example" });
    expect(share).toEqual({ url: "https://viewer.example/viewer#tc1=tc1%3Abearer", delegationCid: "bafy-native-delegation", expiresAt: new Date("2030-01-01T00:00:00.000Z"), spaceId: "tinycloud:pkh:eip155:1:0xabc:applications" });
    await expect(receiveNativeBearer(share.url, async (token) => {
      calls.push(`receive:${token}`);
      return { ok: true as const, data: { data: bytes, path: "xyz.tinycloud.share/shares/a.bin", spaceId: "tinycloud:pkh:eip155:1:0xabc:applications", host: "https://owner-node.example", delegation: { expiry: new Date("2030-01-01T00:00:00.000Z") } } };
    })).resolves.toEqual(bytes);
    expect(calls).toEqual(["put:tinycloud:pkh:eip155:1:0xabc:applications:xyz.tinycloud.share/shares/a.bin:0,1,2,255", "delegate:xyz.tinycloud.share/shares/a.bin:tinycloud.kv/get", "receive:tc1:bearer"]);
  });

  it("normalizes a bare tc1 payload (no inner prefix) before the SDK receive", async () => {
    // Links written ~04:50-05:48Z on the post-#194 line carry the share data
    // without the inner 'tc1:' prefix; the receiver must hand web-sdk a
    // prefixed token or the decode fails with 'Expected prefix tc1:'.
    const bytes = new Uint8Array([9, 8, 7]);
    const tokens: string[] = [];
    const received = await receiveNativeBearer("https://viewer.example/viewer#tc1=bearerpayload", async (token) => {
      tokens.push(token);
      return { ok: true as const, data: { data: bytes, path: "xyz.tinycloud.share/shares/b.bin", spaceId: "spc", host: "https://owner-node.example", delegation: { expiry: new Date("2030-01-01T00:00:00.000Z") } } };
    });
    expect(received).toEqual(bytes);
    expect(tokens).toEqual(["tc1:bearerpayload"]);
  });

  it("round-trips a correctly prefixed link unchanged", async () => {
    const bytes = new Uint8Array([5]);
    const tokens: string[] = [];
    await receiveNativeBearer("https://viewer.example/viewer#tc1=tc1%3Aalready", async (token) => {
      tokens.push(token);
      return { ok: true as const, data: { data: bytes, path: "p", spaceId: "s", host: "h", delegation: { expiry: new Date("2030-01-01T00:00:00.000Z") } } };
    });
    expect(tokens).toEqual(["tc1:already"]);
  });

  it("un-encodes a percent-encoded tc1 value before the SDK receive", async () => {
    // A fragment like #tc1=tc1%3AeyJ… arrives double-encoded if the writer
    // encoded the already-encoded fragment again; decode until the payload
    // is a plain tc1: token (base64url never contains '%').
    const bytes = new Uint8Array([3]);
    const tokens: string[] = [];
    await receiveNativeBearer("https://viewer.example/viewer#tc1=tc1%253Aencoded", async (token) => {
      tokens.push(token);
      return { ok: true as const, data: { data: bytes, path: "p", spaceId: "s", host: "h", delegation: { expiry: new Date("2030-01-01T00:00:00.000Z") } } };
    });
    expect(tokens).toEqual(["tc1:encoded"]);
  });

  it("surfaces revocation as a denied bearer read", async () => {
    const revoked = {
      receive: async () => ({ ok: false as const, error: { message: "Sharing link has been revoked" } }),
      generate: async () => ({ ok: true as const, data: { token: "unused", delegation: { cid: "unused" }, expiresAt: new Date("2030-01-01T00:00:00.000Z") } }),
      decodeLink: () => ({ path: "unused", spaceId: "unused" }),
    };
    await expect(receiveNativeBearer("https://viewer.example/viewer#tc1=revoked", async () => revoked.receive())).rejects.toThrow("revoked");
  });

  it("refuses root, legacy-path, query, and mixed native links before receive", async () => {
    let received = 0;
    const sharing = {
      generate: async () => ({ ok: true as const, data: { token: "unused", delegation: { cid: "unused" }, expiresAt: new Date("2030-01-01T00:00:00.000Z") } }),
      decodeLink: () => ({ path: "unused", spaceId: "unused" }),
      receive: async () => { received += 1; return { ok: false as const, error: { message: "unexpected" } }; },
    };
    for (const url of [
      "https://viewer.example/#tc1=token",
      "https://viewer.example/s/token",
      "https://viewer.example/viewer?tc1=token",
      "https://viewer.example/viewer?legacy=1#tc1=token",
      "https://viewer.example/viewer#tc1=token&legacy=1",
    ]) await expect(receiveNativeBearer(url, async () => sharing.receive())).rejects.toThrow();
    expect(received).toBe(0);
  });
});
