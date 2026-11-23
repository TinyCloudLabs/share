import { Buffer } from "node:buffer";
import * as sdk from "@tinycloud/sdk-core";
import type { NamedKeyEnvelope } from "@tinycloud/node-sdk/encryption-keys";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";

import { createCapabilityBridge, MAX_SEAL_ENVELOPE_BYTES, MAX_SEAL_JSON_BYTES, type AppData } from "../src/apps/bridge.ts";
import type { CatalogEntry } from "../src/apps/catalog.ts";
import { consentFor } from "../src/apps/consent.ts";
import { capGrants, makeAuthorizer } from "../src/apps/grants.ts";
import { signInPlan } from "../src/apps/run.ts";
import { bindSeal, type BoundSeal } from "../src/apps/seal.ts";
import { runnerSealingKey } from "../src/apps/seal-key.ts";
import type { CapOp, CapResult } from "../src/artifact/jsx-runtime/cap-protocol.ts";
import { assertManifestInScope, MANIFEST_CHECK_ADDRESS } from "../src/share/manifest-policy.ts";

const appId = "xyz.tinycloud.tinyapps.contacts";
const keyPath = `apps/xyz.tinycloud.share/${appId}/seal-v1`;
const owner = privateKeyToAccount(generatePrivateKey());
const networkId = `urn:tinycloud:encryption:${sdk.pkhDid(owner.address, 1)}:default`;
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
      "Contacts can encrypt and open its own data with one key set aside for it.",
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
    ]) expect(await bindSeal(keyPath, await signed(att), getKeys)).toBeUndefined();
    const approved = await signed({ [exact]: { [decrypt]: [{}], [create]: [{}] } });
    expect(await bindSeal(keyPath, { ...approved, signature: "0x" }, getKeys)).toBeUndefined();
    expect(await bindSeal(keyPath, approved, getKeys)).toMatchObject({ keyPath, networkId });
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
    keyPath, networkId,
    encrypt: vi.fn(async (value) => { bytes = new Uint8Array(value); return envelope; }),
    decrypt: vi.fn(async () => bytes),
  };
  return { seal, envelope };
}

describe("the sealing bridge", () => {
  it("round-trips plain JSON through the bound SDK port", async () => {
    const { seal } = sealFixture();
    const call = harness(seal);
    const value = { name: "Aléx", answers: [true, null, 4] };
    const encrypted = await call("seal.encrypt", { value });
    expect(encrypted).toMatchObject({ ok: true, sealed: expect.any(String) });
    if (!encrypted.ok) return;
    expect(encrypted.sealed).not.toContain(value.name);
    expect(await call("seal.decrypt", { sealed: encrypted.sealed })).toEqual({ ok: true, value });
  });

  it("refuses both ops when the manifest or approval is missing and when the session expired", async () => {
    const denied = harness();
    expect(await denied("seal.encrypt", { value: null })).toMatchObject({ error: { code: "PERMISSION_DENIED" } });
    expect(await denied("seal.decrypt", { sealed: "{}" })).toMatchObject({ error: { code: "PERMISSION_DENIED" } });
    const { seal } = sealFixture();
    expect(await harness(seal, false)("seal.encrypt", { value: null })).toMatchObject({ error: { code: "NOT_CONNECTED" } });
    expect(seal.encrypt).not.toHaveBeenCalled();
  });

  it("refuses foreign keys or networks before any SDK call", async () => {
    const { seal, envelope } = sealFixture();
    const call = harness(seal);
    expect(await call("seal.encrypt", { value: {}, keyPath: "other/key" })).toMatchObject({ error: { code: "BAD_REQUEST" } });
    for (const other of [{ ...envelope, keyPath: "other/key" }, { ...envelope, networkId: `${networkId}-other` }]) {
      expect(await call("seal.decrypt", { sealed: JSON.stringify(other) })).toMatchObject({ error: { code: "PERMISSION_DENIED" } });
    }
    expect(seal.encrypt).not.toHaveBeenCalled();
    expect(seal.decrypt).not.toHaveBeenCalled();
  });

  it("checks JSON shape and both byte caps before using the SDK", async () => {
    const { seal } = sealFixture();
    const call = harness(seal);
    for (const value of [undefined, { nested: new Uint8Array([1]) }, [undefined]]) {
      expect(await call("seal.encrypt", { value })).toMatchObject({ error: { code: "BAD_REQUEST" } });
    }
    expect(await call("seal.decrypt", { sealed: "{" })).toMatchObject({ error: { code: "BAD_REQUEST" } });
    expect(await call("seal.decrypt", { sealed: JSON.stringify({ v: 1, networkId }) })).toMatchObject({ error: { code: "BAD_REQUEST" } });
    expect(await call("seal.encrypt", { value: "é".repeat(MAX_SEAL_JSON_BYTES / 2) })).toMatchObject({ error: { code: "TOO_LARGE" } });
    expect(await call("seal.decrypt", { sealed: "a".repeat(MAX_SEAL_ENVELOPE_BYTES + 1) })).toMatchObject({ error: { code: "TOO_LARGE" } });
    expect(seal.encrypt).not.toHaveBeenCalled();
    expect(seal.decrypt).not.toHaveBeenCalled();
  });
});
