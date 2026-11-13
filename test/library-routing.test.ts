/** Share selects onboarding hosts through the published registry API. Details: TC-2872 */
import { afterEach, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { createInMemoryRegistrySequenceStore, pkhDid, REGISTRY_NOT_FOUND_BODY, resolveFailClosedTinyCloudHosts, signLocationRecord, signLocationRecordV2 } from "@tinycloud/sdk-core";
import type { Config } from "@tinycloud/web-sdk";
import { createTinyCloudClient, reopenOpenKey } from "../src/share/openkey-session.js";
import { createShareReceiverClient } from "../src/share/receiver.js";
import type { SharePublicConfig } from "../src/email-share/config.js";

const capture = vi.hoisted(() => ({ config: undefined as Config | undefined, stop: new Error("config-captured") }));
vi.mock("@tinycloud/web-sdk", () => ({ TinyCloudWeb: class {
  constructor(config: Config) { capture.config = config; throw capture.stop; }
  static async create(config: Config) { capture.config = config; throw capture.stop; }
} }));
vi.mock("@openkey/sdk", () => ({ OpenKey: class {}, OpenKeyProvider: class {} }));
const owner = privateKeyToAccount("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
const registry = "https://registry.routing.test";
const signedHost = "https://owner.routing.test";
const nodeDid = "did:key:z6MkixsGj3MVGKMug2VMC2JbtzX3UjaAcfRs7G1RjbSnZJaH";
const config: SharePublicConfig = { version: "tinycloud.share/config-v2", shareOrigin: "https://share.tinycloud.xyz", senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz", registryOrigin: registry, credentialsOrigin: "https://witness.credentials.org", accountlessReceiverEnabled: true };

afterEach(() => { vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

function capturedConfig(): Config {
  if (!capture.config) throw new Error("missing-config");
  return capture.config;
}

async function selectedConfig(receiver: boolean): Promise<Config> {
  capture.config = undefined;
  if (receiver) await expect(createShareReceiverClient(config)).rejects.toBe(capture.stop);
  else {
    const session = reopenOpenKey({ address: owner.address, keyId: "routing-owner", keyType: "MANAGED" });
    await expect(createTinyCloudClient(session, config, () => undefined)).rejects.toBe(capture.stop);
  }
  const selected = capturedConfig();
  expect(selected).not.toHaveProperty("tinycloudFallbackHosts");
  expect(selected.newUserHost).toBe(receiver ? null : config.senderBootstrapNodeOrigin);
  expect(selected).not.toHaveProperty("tinycloudHosts");
  return selected;
}

async function resolve(receiver: boolean, answer: "v2" | "v1" | "unregistered" | "unavailable") {
  const selected = await selectedConfig(receiver);
  const subject = pkhDid(owner.address, 1);
  const signer = { type: "did:pkh" as const, signMessage: (message: string) => owner.signMessage({ message }) };
  const requests: string[] = [];
  vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
    const url = String(input); requests.push(url);
    if (!url.startsWith(registry + "/")) throw new Error("unexpected host request: " + url);
    if (answer === "unavailable") return new Response("unavailable", { status: 503 });
    if (answer === "v2" && url.includes("/v2/")) return Response.json({ record: await signLocationRecordV2({ version: 2, subject, nodes: [{ did: nodeDid, url: signedHost }], spaces: [], encryptionNode: nodeDid, updated_at: "2026-11-13T00:00:00.000Z", sequence: 1 }, signer) });
    if (answer === "v1" && url.includes("/v1/")) return Response.json({ record: await signLocationRecord({ version: 1, subject, multiaddrs: ["/dns4/legacy.routing.test/tcp/443/https"], updated_at: "2026-11-13T00:00:00.000Z", sequence: 1 }, signer) });
    return new Response(REGISTRY_NOT_FOUND_BODY, { status: 404 });
  });
  const resolution = resolveFailClosedTinyCloudHosts(owner.address, {
    registryUrl: selected.tinycloudRegistryUrl!, newUserHost: selected.newUserHost!, autoDiscoverLocalNode: false,
    sequenceStore: createInMemoryRegistrySequenceStore(),
  });
  return { resolution, requests };
}

for (const receiver of [false, true]) {
  const role = receiver ? "receiver" : "sender";
  it(`${role} selects signed v2 hosts`, async () => {
    const { resolution } = await resolve(receiver, "v2");
    expect((await resolution).hosts).toEqual([signedHost]);
  });
  it(`${role} retains v1 registration without onboarding`, async () => {
    const { resolution } = await resolve(receiver, "v1");
    await expect(resolution).rejects.toThrow();
  });
  it(`${role} handles an unregistered owner`, async () => {
    const { resolution } = await resolve(receiver, "unregistered");
    if (receiver) await expect(resolution).rejects.toThrow();
    else expect((await resolution).hosts).toEqual([config.senderBootstrapNodeOrigin]);
  });
  it(`${role} refuses unavailable registry routing`, async () => {
    const { resolution, requests } = await resolve(receiver, "unavailable");
    await expect(resolution).rejects.toThrow();
    expect(requests.every((url) => url.startsWith(registry + "/"))).toBe(true);
  });
}

it("hermetic sender retains an explicit origin hint with onboarding disabled", async () => {
  vi.stubEnv("VITE_SHARE_HERMETIC", "true");
  const session = reopenOpenKey({ address: owner.address, keyId: "routing-owner", keyType: "MANAGED" });
  await expect(createTinyCloudClient(session, config, () => undefined)).rejects.toBe(capture.stop);
  expect(capture.config?.newUserHost).toBeNull();
  expect(capture.config?.tinycloudHosts).toEqual([window.location.origin]);
  expect(capture.config?.tinycloudRegistryUrl).toBeNull();
});
