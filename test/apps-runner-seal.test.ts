import { Buffer } from "node:buffer";
import * as sdk from "@tinycloud/sdk-core";
import type { NamedKeyEnvelope } from "@tinycloud/node-sdk/encryption-keys";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";

import { createCapabilityBridge, MAX_SEAL_CONTEXT_CHARS, MAX_SEAL_ENVELOPE_BYTES, MAX_SEAL_JSON_BYTES, type AppData } from "../src/apps/bridge.ts";
import type { CatalogEntry } from "../src/apps/catalog.ts";
import { consentFor } from "../src/apps/consent.ts";
import { capGrants, makeAuthorizer } from "../src/apps/grants.ts";
import { signInPlan } from "../src/apps/run.ts";
import { bindSeal, type BoundSeal } from "../src/apps/seal.ts";
import { runnerSealingKey } from "../src/apps/seal-key.ts";
import type { CapOp, CapResult } from "../src/artifact/jsx-runtime/cap-protocol.ts";
import { JSX_BRIDGE_RUNTIME_SCRIPT } from "../src/viewer/jsx-frame.ts";
import { assertManifestInScope, MANIFEST_CHECK_ADDRESS } from "../src/share/manifest-policy.ts";

const appId = "xyz.tinycloud.tinyapps.contacts";
const keyPath = `apps/xyz.tinycloud.share/${appId}/seal-v1`;
const owner = privateKeyToAccount(generatePrivateKey());
const ownerDid = sdk.pkhDid(owner.address, 1);
const networkId = `urn:tinycloud:encryption:${ownerDid}:default`;
const spaceId = `tinycloud:pkh:eip155:1:${owner.address}:applications`;
const context = `${appId}/person/alex-0123abcd`;
const key = { path: keyPath, abilities: ["decrypt", "key.create"] } satisfies NonNullable<sdk.Manifest["keys"]>[number];
const original: sdk.Manifest = {
  app_id: appId, name: "Contacts", defaults: false, space: "applications", includePublicSpace: false,
  permissions: [{ service: "tinycloud.kv", path: "person/", actions: ["get", "put"] }],
};
const manifest: sdk.Manifest = { ...original, keys_app_id: "xyz.tinycloud.share", keys: [key] };
const rawEncryption = (path: string, actions = ["decrypt"]): sdk.PermissionEntry => ({
  service: "tinycloud.encryption", path, actions, skipPrefix: true,
});

describe("one sealing key in the installed manifest", () => {
  it("discloses one key and adds it to the one sign-in with the same KV scope", () => {
    const plan = signInPlan({ ok: true, manifest }, sdk);
    const previous = signInPlan({ ok: true, manifest: original }, sdk);
    expect(plan.manifest.keys).toEqual([key]);
    expect(plan.scope).toEqual({ ...previous.scope, allowedRunnerKeyPath: keyPath });
    expect(plan.manifest.permissions).toEqual(previous.manifest.permissions);
    expect(() => assertManifestInScope(plan.manifest, plan.scope, MANIFEST_CHECK_ADDRESS)).not.toThrow();
    expect(() => assertManifestInScope(plan.manifest, previous.scope, MANIFEST_CHECK_ADDRESS)).toThrow();
    expect(consentFor({ app_id: appId, name: "Contacts" } as CatalogEntry, manifest, []).notices).toContain(
      "Contacts can create one encryption key for its own data and use it to encrypt and open that data. The key stays in your TinyCloud if you remove Contacts.",
    );
    expect(runnerSealingKey(original)).toBeUndefined();
    expect(capGrants(original, manifest, sdk).ok).toBe(true);
    expect(capGrants(manifest, original, sdk)).toMatchObject({ ok: false, refusal: { reason: "widened" } });
  });

  it.each([
    ["a prefix", { ...manifest, keys: [{ prefix: "apps/xyz.tinycloud.share/", abilities: key.abilities }] }],
    ["a second declaration", { ...manifest, keys: [key, key] }],
    ["another app's key", { ...manifest, keys: [{ ...key, path: keyPath.replace(appId, "someone.else") }] }],
    ["a second path under its own key", { ...manifest, keys: [{ ...key, path: `${keyPath}/extra` }] }],
    ["one omitted ability", { ...manifest, keys: [{ ...key, abilities: ["decrypt"] }] }],
    ["one extra ability", { ...manifest, keys: [{ ...key, abilities: [...key.abilities, "key.block"] }] }],
    ["the default network", { ...manifest, permissions: [...original.permissions!, rawEncryption(networkId)] }],
    ["a direct secret key", { ...manifest, permissions: [...original.permissions!, rawEncryption(`${networkId}/secrets/example`)] }],
    ["a direct encryption prefix", { ...manifest, permissions: [...original.permissions!, rawEncryption(`${networkId}/share/`)] }],
  ] satisfies Array<[string, sdk.Manifest]>)("refuses %s in both the installed copy and before sign-in", (_label, bad) => {
    expect(capGrants(bad, manifest, sdk)).toMatchObject({ ok: false });
    expect(() => signInPlan({ ok: true, manifest: bad }, sdk)).toThrow();
    expect(() => assertManifestInScope(bad, signInPlan({ ok: true, manifest }, sdk).scope, MANIFEST_CHECK_ADDRESS)).toThrow();
  });

  it("preserves the runner's KV, SQL, public space and delegation boundaries", () => {
    const plan = signInPlan({ ok: true, manifest }, sdk);
    for (const bad of [
      { ...manifest, includePublicSpace: true },
      { ...manifest, did: "did:key:z6MkwExample" },
      { ...manifest, permissions: [...original.permissions!, { service: "tinycloud.kv", path: "someone-else/", skipPrefix: true, actions: ["put"] }] },
      { ...manifest, permissions: [...original.permissions!, { service: "tinycloud.sql", path: "extra", actions: ["schema"] }] },
    ]) {
      expect(() => assertManifestInScope({ ...plan.manifest, ...bad }, plan.scope, MANIFEST_CHECK_ADDRESS)).toThrow();
    }
    const authorize = makeAuthorizer(manifest, sdk);
    expect(authorize("tinycloud.kv", `${appId}/person/alex`, "put", false)).toBe(true);
    expect(authorize("tinycloud.kv", "other/person/alex", "put", true)).toBe(false);
    expect(authorize("tinycloud.sql", `${appId}/person/alex`, "schema", false)).toBe(false);
  });
});

async function signed(recap: Record<string, unknown>): Promise<sdk.ClientSession> {
  const message = `Resources:\n- urn:recap:${Buffer.from(JSON.stringify({ att: recap })).toString("base64url")}`;
  return {
    address: owner.address, walletAddress: owner.address, chainId: 1, sessionKey: "test",
    siwe: message, signature: await owner.signMessage({ message }),
  };
}
const exact = `${networkId}/${keyPath}`;
const decrypt = "tinycloud.encryption/decrypt";
const create = "tinycloud.encryption/key.create";

describe("binding the signed session's exact key", () => {
  it("does not acquire an SDK client without approval of both unrestricted abilities on that key", async () => {
    const getKeys = vi.fn(() => { throw new Error("should not be called"); });
    for (const att of [
      {},
      { [networkId]: { [decrypt]: [{}], [create]: [{}] } },
      { [`${exact}/`]: { [decrypt]: [{}], [create]: [{}] } },
      { [exact]: { [decrypt]: [{}] } },
      { [exact]: { [decrypt]: [{ condition: true }], [create]: [{}] } },
    ]) expect(await bindSeal(keyPath, spaceId, await signed(att), getKeys)).toBeUndefined();
    const approved = await signed({ [exact]: { [decrypt]: [{}], [create]: [{}] } });
    expect(await bindSeal(keyPath, spaceId, { ...approved, signature: "0x" }, getKeys)).toBeUndefined();
    expect(await bindSeal(keyPath, spaceId, approved, getKeys)).toMatchObject({ keyPath, networkId });
    expect(getKeys).not.toHaveBeenCalled();
  });
});

const data: AppData = {
  kvGet: async () => { throw new Error("unexpected kvGet"); },
  kvPut: async () => { throw new Error("unexpected kvPut"); },
  kvList: async () => { throw new Error("unexpected kvList"); },
  kvDelete: async () => { throw new Error("unexpected kvDelete"); },
  sqlQuery: async () => { throw new Error("unexpected sqlQuery"); },
  sqlExecute: async () => { throw new Error("unexpected sqlExecute"); },
};

function harness(seal?: BoundSeal, isLive = true) {
  let id = 0;
  let reply: (result: CapResult) => void;
  const bridge = createCapabilityBridge({
    appId, authorize: makeAuthorizer(manifest, sdk), data, isLive: () => isLive,
    ...(seal === undefined ? {} : { seal }),
    reply: (_id, result) => reply(result),
  });
  return (op: CapOp, args: Record<string, unknown>) => new Promise<CapResult>((resolve) => {
    reply = resolve;
    bridge.handle({ type: `cap/${op}`, body: { id: String(++id), args } });
  });
}

function sealFixture() {
  const envelope: NamedKeyEnvelope = {
    v: 2, keyPath, networkId, ciphertext: "ciphertext", encryptedSymmetricKey: "wrapped",
    encryptedSymmetricKeyHash: "hash", alg: "algorithm", keyVersion: 1,
  };
  let bytes = new Uint8Array(0);
  const seal: BoundSeal = {
    keyPath, networkId, ownerDid, spaceId,
    encrypt: vi.fn(async (value, aad) => {
      bytes = new Uint8Array(value);
      return { ...envelope, aad: Buffer.from(aad).toString("base64") };
    }),
    decrypt: vi.fn(async () => bytes),
  };
  return { seal, envelope };
}

describe("the sealing bridge", () => {
  it("round-trips plain JSON through the bound SDK port", async () => {
    const { seal } = sealFixture();
    const call = harness(seal);
    const value = { name: "Aléx", answers: [true, null, 4] };
    const encrypted = await call("seal.encrypt", { value, context });
    expect(encrypted).toMatchObject({ ok: true, sealed: expect.any(String) });
    if (!encrypted.ok) return;
    expect(encrypted.sealed).not.toContain(value.name);
    expect(await call("seal.decrypt", { sealed: encrypted.sealed, context })).toEqual({ ok: true, value });
  });

  it("refuses both ops when the manifest or approval is missing and when the session expired", async () => {
    const denied = harness();
    expect(await denied("seal.encrypt", { value: null, context })).toMatchObject({ error: { code: "PERMISSION_DENIED" } });
    expect(await denied("seal.decrypt", { sealed: "{}", context })).toMatchObject({ error: { code: "PERMISSION_DENIED" } });
    const { seal } = sealFixture();
    expect(await harness(seal, false)("seal.encrypt", { value: null, context })).toMatchObject({ error: { code: "NOT_CONNECTED" } });
    expect(seal.encrypt).not.toHaveBeenCalled();
  });

  it("refuses foreign keys or networks before any SDK call", async () => {
    const { seal, envelope } = sealFixture();
    const call = harness(seal);
    expect(await call("seal.encrypt", { value: {}, context, keyPath: "other/key" })).toMatchObject({ error: { code: "BAD_REQUEST" } });
    for (const other of [{ ...envelope, keyPath: "other/key" }, { ...envelope, networkId: `${networkId}-other` }]) {
      expect(await call("seal.decrypt", { sealed: JSON.stringify(other), context })).toMatchObject({ error: { code: "PERMISSION_DENIED" } });
    }
    expect(seal.encrypt).not.toHaveBeenCalled();
    expect(seal.decrypt).not.toHaveBeenCalled();
  });

  it("checks JSON shape and both byte caps before using the SDK", async () => {
    const { seal } = sealFixture();
    const call = harness(seal);
    for (const value of [undefined, { nested: new Uint8Array([1]) }, [undefined]]) {
      expect(await call("seal.encrypt", { value, context })).toMatchObject({ error: { code: "BAD_REQUEST" } });
    }
    expect(await call("seal.decrypt", { sealed: "{", context })).toMatchObject({ error: { code: "BAD_REQUEST" } });
    expect(await call("seal.decrypt", { sealed: JSON.stringify({ v: 1, networkId }), context })).toMatchObject({ error: { code: "BAD_REQUEST" } });
    expect(await call("seal.encrypt", { value: "é".repeat(MAX_SEAL_JSON_BYTES / 2), context })).toMatchObject({ error: { code: "TOO_LARGE" } });
    expect(await call("seal.decrypt", { sealed: "a".repeat(MAX_SEAL_ENVELOPE_BYTES + 1), context })).toMatchObject({ error: { code: "TOO_LARGE" } });
    expect(seal.encrypt).not.toHaveBeenCalled();
    expect(seal.decrypt).not.toHaveBeenCalled();
  });
});

describe("sealing context", () => {
  it("rejects a sealed value from a different record, owner or space before SDK decryption", async () => {
    const { seal } = sealFixture();
    const call = harness(seal);
    const encrypted = await call("seal.encrypt", { value: { name: "Alex" }, context });
    if (!encrypted.ok || typeof encrypted.sealed !== "string") throw new Error("encrypt failed");
    const envelope = JSON.parse(encrypted.sealed);
    expect(JSON.parse(Buffer.from(envelope.aad, "base64").toString("utf8"))).toEqual(
      ["tinycloud.app.seal/v1", ownerDid, spaceId, context],
    );
    expect(await call("seal.decrypt", { sealed: encrypted.sealed, context: `${appId}/person/another` })).toMatchObject({
      error: { code: "CONTEXT_MISMATCH" },
    });
    for (const [wrongOwner, wrongSpace] of [
      [sdk.pkhDid(privateKeyToAccount(generatePrivateKey()).address, 1), spaceId],
      [ownerDid, spaceId.replace(":applications", ":other")],
    ]) {
      const aad = Buffer.from(JSON.stringify(["tinycloud.app.seal/v1", wrongOwner, wrongSpace, context])).toString("base64");
      expect(await call("seal.decrypt", { sealed: JSON.stringify({ ...envelope, aad }), context })).toMatchObject({
        error: { code: "CONTEXT_MISMATCH" },
      });
    }
    expect(seal.decrypt).not.toHaveBeenCalled();

    const anotherContext = `${appId}/person/another`;
    const changedAad = Buffer.from(JSON.stringify(["tinycloud.app.seal/v1", ownerDid, spaceId, anotherContext])).toString("base64");
    const retagged = await call("seal.decrypt", { sealed: JSON.stringify({ ...envelope, aad: changedAad }), context: anotherContext });
    expect(retagged).toMatchObject({ error: { code: "CONTEXT_MISMATCH" } });
    expect(retagged).not.toHaveProperty("value");
    expect(seal.decrypt).toHaveBeenCalledTimes(1);
  });

  it("requires a bounded full record key and rejects page-supplied owner or space", async () => {
    const { seal } = sealFixture();
    const call = harness(seal);
    for (const op of ["seal.encrypt", "seal.decrypt"] as const) {
      const args = op === "seal.encrypt" ? { value: true } : { sealed: "{}" };
      for (const invalid of [undefined, "", "person/example", `/${context}`, `${appId}/../example`, `${appId}/person/white space`]) {
        expect(await call(op, { ...args, context: invalid })).toMatchObject({ error: { code: "BAD_REQUEST" } });
      }
      const long = `${appId}/${"x".repeat(MAX_SEAL_CONTEXT_CHARS)}`;
      expect(await call(op, { ...args, context: long })).toMatchObject({ error: { code: "TOO_LARGE" } });
      for (const override of [{ ownerDid }, { spaceId }]) {
        expect(await call(op, { ...args, context, ...override })).toMatchObject({ error: { code: "BAD_REQUEST" } });
      }
    }
    expect(seal.encrypt).not.toHaveBeenCalled();
    expect(seal.decrypt).not.toHaveBeenCalled();
  });
});

it("scrubs SDK error details for both seal operations", async () => {
  const { seal } = sealFixture();
  const call = harness(seal);
  const encrypted = await call("seal.encrypt", { value: true, context });
  if (!encrypted.ok) throw new Error("encrypt failed");
  const error = Object.assign(new Error("secret plaintext and owner details"), { code: "FORBIDDEN" });
  vi.mocked(seal.encrypt).mockRejectedValueOnce(error);
  vi.mocked(seal.decrypt).mockRejectedValueOnce({ code: "FORBIDDEN", message: error.message });
  const expected = { ok: false, error: { code: "PERMISSION_DENIED", message: "This app's permissions don't allow that." } };
  expect(await call("seal.encrypt", { value: true, context })).toEqual(expected);
  expect(await call("seal.decrypt", { sealed: encrypted.sealed, context })).toEqual(expected);
});

it("forwards and opens a history record with an imported nested address", async () => {
  const { seal: bound } = sealFixture();
  const call = harness(bound);
  const value = {
    prior: {
      v: 1, at: "2026-11-23", by: "owner",
      data: {
        name: "Thistle Tern", added: "2026-11-23",
        private: { addresses: [{ label: "Studio", lines: ["12 Fable Walk", "Sedge"] }] },
      },
    },
  };
  const historyKey = `${appId}/history/2026-11/2026-11-23T1200-thistle-tern-0123abcd`;
  const nonce = "a".repeat(32);
  let receive: (event: { source: unknown; origin?: string; data: unknown }) => void;
  const parent = { postMessage: vi.fn() };
  const child = { postMessage: vi.fn() };
  const frame = { contentWindow: child, setAttribute: vi.fn(), addEventListener: vi.fn() };
  const relayWindow = {
    location: { hash: "#" + nonce, pathname: "/", search: "" },
    parent,
    addEventListener: (_type: string, listener: typeof receive) => { receive = listener; },
  };
  const relayDocument = {
    getElementById: () => null,
    createElement: () => frame,
    body: { replaceChildren: vi.fn() },
  };
  new Function("window", "self", "document", JSX_BRIDGE_RUNTIME_SCRIPT)(relayWindow, { origin: "null" }, relayDocument);
  receive!({ source: parent, data: { v: 1, type: "render", nonce, kind: "jsx", source: "", modules: { runtime: "" }, theme: "system" } });

  async function roundTrip(id: string, op: CapOp, args: Record<string, unknown>) {
    receive({ source: child, origin: "null", data: { v: 1, type: `cap/${op}`, id, args } });
    expect(parent.postMessage).toHaveBeenLastCalledWith({ v: 1, nonce, type: `cap/${op}`, body: { id, args } }, "*");
    const result = await call(op, args);
    receive({ source: parent, data: { v: 1, nonce, type: "cap/result", id, result } });
    expect(child.postMessage).toHaveBeenLastCalledWith({ v: 1, type: "cap/result", id, result }, "*");
    return result;
  }

  const encrypted = await roundTrip("10", "seal.encrypt", { value, context: historyKey });
  expect(encrypted).toMatchObject({ ok: true, sealed: expect.any(String) });
  if (!encrypted.ok) return;
  expect(await roundTrip("11", "seal.decrypt", { sealed: encrypted.sealed, context: historyKey })).toEqual({ ok: true, value });

  receive!({ source: child, origin: "null", data: { v: 1, type: "cap/kv.put", id: "12", args: { key: "k", body: value } } });
  expect(child.postMessage).toHaveBeenLastCalledWith({ v: 1, type: "cap/result", id: "12", result: {
    ok: false, error: { code: "BAD_REQUEST", message: expect.any(String) },
  } }, "*");
});
