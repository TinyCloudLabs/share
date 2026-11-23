import { beforeEach, expect, it, vi } from "vitest";
import { CONFIG_VERSION, type SharePublicConfig } from "../src/email-share/config.js";
import { authenticateWithOpenKey, createTinyCloudClient, saveCopyManifest, SAVE_COPY_MANIFEST_SCOPE, signInWithManifest } from "../src/share/openkey-session.js";
import { shareManifest } from "../src/share/share-manifest.js";

const ADDRESS = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const CONFIG: SharePublicConfig = {
  version: CONFIG_VERSION,
  shareOrigin: "https://share.example",
  senderBootstrapNodeOrigin: "https://node.example",
  registryOrigin: "https://registry.example",
  credentialsOrigin: "https://credentials.example",
  accountlessReceiverEnabled: false,
};
const recap = Buffer.from(JSON.stringify({ att: { "tinycloud:space-a/kv/one": { "tinycloud.kv/get": [] } } })).toString("base64url");
const SIWE = `share.example wants you to sign in with your Ethereum account:\n${ADDRESS}\n\nSign in.\n\nResources:\n- urn:recap:${recap}`;
const authorize = vi.hoisted(() => vi.fn());

vi.mock("@openkey/sdk", () => ({
  OpenKey: class {
    async connect() { return { address: ADDRESS, keyId: "key-1", keyType: "MANAGED" }; }
    authorizeTinyCloud = authorize;
  },
  OpenKeyProvider: class {},
}));

vi.mock("@tinycloud/web-sdk", () => ({
  TinyCloudWeb: class {
    readonly sessionRestoreStatus = "idle";
    constructor(private readonly config: { openkey: { client: { authorizeTinyCloud(request: unknown): Promise<{ signedMessage: string }> } } }) {}
    async signIn() {
      const { signedMessage } = await this.config.openkey.client.authorizeTinyCloud({ protocolVersion: 1, siwe: SIWE, jwk: {} });
      return { address: ADDRESS, siwe: signedMessage };
    }
    async ensureOwnedSpaceHosted(name: string) { return name; }
  },
}));

beforeEach(() => {
  localStorage.clear();
  authorize.mockReset().mockResolvedValue({ address: ADDRESS, signedMessage: SIWE });
});

it("offers renewal without a standing purpose when the library can decrypt", async () => {
  expect(shareManifest.permissions).toContainEqual(expect.objectContaining({
    service: "tinycloud.encryption",
    actions: expect.arrayContaining(["tinycloud.encryption/decrypt"]),
  }));
  const onStatus = () => undefined;
  await createTinyCloudClient(await authenticateWithOpenKey(onStatus), CONFIG, onStatus);
  expect(authorize.mock.calls[0]?.[0].renewal).toEqual({ version: 1, leaseLifetimeSeconds: 90 * 86_400 });
});

it("keeps the standing purpose for a sign-in whose manifest has no sensitive permissions", async () => {
  await signInWithManifest({
    manifest: saveCopyManifest(),
    ...SAVE_COPY_MANIFEST_SCOPE,
    config: CONFIG,
    versionedSignIn: true,
    persistSession: true,
    renewal: true,
  });
  expect(authorize.mock.calls[0]?.[0].renewal).toEqual({ version: 1, leaseLifetimeSeconds: 90 * 86_400, purpose: "standing" });
});
