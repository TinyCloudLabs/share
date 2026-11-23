import { Buffer } from "node:buffer";
import * as sdk from "@tinycloud/sdk-core";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { beforeEach, expect, it, vi } from "vitest";

import { createCapabilityBridge } from "../src/apps/bridge.ts";
import { catalog } from "../src/apps/catalog.ts";
import { installRecordPlan, signInPlan } from "../src/apps/run.ts";
import { createRunPorts } from "../src/apps/run-session.ts";
import type { CapResult } from "../src/artifact/jsx-runtime/cap-protocol.ts";
import { signInWithManifest, type ManifestSignIn } from "../src/share/openkey-session.ts";

vi.mock("../src/share/openkey-session.ts", () => ({ signInWithManifest: vi.fn(), takeWalletApprovalFailure: () => undefined }));
vi.mock("../src/email-share/config.js", () => ({ loadSharePublicConfig: async () => ({ shareOrigin: "https://share.tinycloud.xyz" }) }));
vi.mock("@tinycloud/web-sdk", () => ({
  BrowserSessionStorage: class {
    activeAddressForRenewal() { return undefined; }
  },
}));

const owner = privateKeyToAccount(generatePrivateKey());
const appId = "xyz.tinycloud.tinyapps.contacts";
const keyPath = `apps/xyz.tinycloud.share/${appId}/seal-v1`;
const entry = { ...catalog.apps[0]!, app_id: appId, name: "Contacts" };
const narrowed = installRecordPlan(entry);
const selected = signInPlan({
  ok: true,
  manifest: {
    app_id: appId, name: "Contacts", defaults: false, space: "applications", includePublicSpace: false,
    permissions: [{ service: "tinycloud.kv", path: "person/", actions: ["get", "put"] }],
    keys_app_id: "xyz.tinycloud.share", keys: [{ path: keyPath, abilities: ["decrypt", "key.create"] }],
  },
}, sdk);
const exact = `urn:tinycloud:encryption:${sdk.pkhDid(owner.address, 1)}:default/${keyPath}`;
const expiresAt = Date.now() + 3_600_000;

async function session(sealing: boolean): Promise<ManifestSignIn> {
  const credentials = sealing ? { [exact]: { "tinycloud.encryption/decrypt": [{}], "tinycloud.encryption/key.create": [{}] } } : {};
  const siwe = `Resources:\n- urn:recap:${Buffer.from(JSON.stringify({ att: credentials })).toString("base64url")}`;
  const signed = {
    siwe, address: owner.address, walletAddress: owner.address, chainId: 1, sessionKey: "fixture",
    signature: await owner.signMessage({ message: siwe }),
  };
  const tinycloud = {
    address: () => owner.address,
    session: () => signed,
    space: () => ({ id: `tinycloud:pkh:eip155:1:${owner.address}:applications`, kv: {
      list: async () => ({ ok: true, data: { keys: [] } }),
    } }),
    sqlForSpace: () => ({}),
    hasPermissions: () => true,
    requestPermissions: vi.fn(() => { throw new Error("unexpected permission prompt"); }),
  } as unknown as ManifestSignIn["tinycloud"];
  return {
    tinycloud, session: undefined, spaces: {}, sessionExpiresAt: expiresAt,
    preparePermissionRequest: vi.fn(), dispose: vi.fn(async () => {}), detach: vi.fn(async () => {}),
  };
}

beforeEach(() => {
  vi.mocked(signInWithManifest).mockReset();
  localStorage.clear();
});

it("denies seal calls before the installed version's grants are checked even with a signed key", async () => {
  vi.mocked(signInWithManifest).mockResolvedValueOnce(await session(true));
  const opened = await createRunPorts().signIn(entry, selected, { approval: vi.fn() });
  const bound = opened.runtime.sealFor?.(keyPath);
  expect(bound).toBeUndefined();
  const reply = vi.fn<(id: string, result: CapResult) => void>();
  const bridge = createCapabilityBridge({ appId, authorize: () => false, data: opened.runtime.data, reply });
  bridge.handle({ type: "cap/seal.encrypt", body: { id: "1", args: { value: true, context: `${appId}/person/alex` } } });
  expect(reply).toHaveBeenCalledExactlyOnceWith("1", expect.objectContaining({ error: expect.objectContaining({ code: "PERMISSION_DENIED" }) }));
  await opened.authorize(entry, selected, sdk);
  expect(opened.runtime.sealFor?.(keyPath)).toMatchObject({ keyPath });
  expect(opened.runtime.sealFor?.(`${keyPath}/other`)).toBeUndefined();
});

it("re-signs once with the selected full manifest and renewal when a narrow reopen lacks the key", async () => {
  const old = await session(false);
  const approved = await session(true);
  let approve!: (session: ManifestSignIn) => void;
  const pending = new Promise<ManifestSignIn>((resolve) => { approve = resolve; });
  vi.mocked(signInWithManifest).mockResolvedValueOnce(old).mockReturnValueOnce(pending);
  const opened = await createRunPorts().signIn(entry, narrowed, { approval: vi.fn() });
  expect(signInWithManifest).toHaveBeenNthCalledWith(1, expect.objectContaining({
    manifest: narrowed.manifest, restoreBeforeOpenKey: true, versionedSignIn: false, renewal: false,
  }));
  const authorizing = opened.authorize(entry, selected, sdk);
  await vi.waitFor(() => expect(signInWithManifest).toHaveBeenNthCalledWith(2, expect.objectContaining({
    manifest: selected.manifest, allowedRunnerKeyPath: keyPath,
    restoreBeforeOpenKey: false, versionedSignIn: true, renewal: true,
  })));
  expect(old.dispose).toHaveBeenCalledOnce();
  expect(opened.runtime.sealFor?.(keyPath)).toBeUndefined();
  approve(approved);
  await authorizing;
  expect(opened.runtime.sealFor?.(keyPath)).toMatchObject({ keyPath });
  expect(approved.tinycloud.requestPermissions).not.toHaveBeenCalled();
  expect(signInWithManifest).toHaveBeenCalledTimes(2);
});
