// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { pkhDid, resolveManifestOwner } from "@tinycloud/sdk-core";
import type { Manifest, PermissionEntry } from "@tinycloud/web-sdk";
import { defaultEncryptionNetworkForOwner, pathBoundSessionPermissions } from "@tinycloud/share-sdk";
import { ownerEncryptionNetwork, SHARE_MANIFEST_SCOPE, shareManifest } from "../src/share/openkey-session.js";
import { assertManifestInScope, ManifestRejectedError } from "../src/share/manifest-policy.js";

const OWNER = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");

function withEntry(entry: PermissionEntry): Manifest {
  const manifest = shareManifest;
  return { ...manifest, permissions: [...manifest.permissions!, entry] };
}

describe("Share's sign-in request", () => {
  const permissions = shareManifest.permissions!;

  it("names no decrypt on the whole encryption network", () => {
    expect(permissions.filter((entry) => entry.service === "tinycloud.encryption" && entry.path.toLowerCase() === ownerEncryptionNetwork(OWNER.address))).toEqual([]);
  });

  it("asks for no network creation", () => {
    expect(permissions.filter((entry) => entry.actions.some((action) => action.includes("network.create")))).toEqual([]);
  });

  it("keeps decrypt on the share/ prefix", () => {
    const prefix = pathBoundSessionPermissions({ encryptionNetwork: defaultEncryptionNetworkForOwner({ address: OWNER.address }) });
    expect(prefix.length).toBeGreaterThan(0);
    expect(resolveManifestOwner(shareManifest, pkhDid(OWNER.address, 1)).permissions).toEqual(expect.arrayContaining(prefix));
    expect(prefix.every((entry) => entry.actions.some((action) => action.includes("decrypt")))).toBe(true);
  });

  it("is inside its scope", () => {
    expect(() => assertManifestInScope(shareManifest, SHARE_MANIFEST_SCOPE, OWNER.address)).not.toThrow();
  });
});

describe.each([
  ["the SDK's spelling", defaultEncryptionNetworkForOwner({ address: OWNER.address })],
  ["the lower-case spelling", ownerEncryptionNetwork(OWNER.address)],
])("the sign-in scope, whole network as %s", (_spelling, network) => {
  it("refuses a manifest that adds decrypt on the whole network back", () => {
    const manifest = withEntry({ service: "tinycloud.encryption", path: network, actions: ["decrypt"], skipPrefix: true });
    expect(() => assertManifestInScope(manifest, SHARE_MANIFEST_SCOPE, OWNER.address)).toThrow(ManifestRejectedError);
  });

  it("refuses a manifest that adds network creation back", () => {
    const manifest = withEntry({ service: "tinycloud.encryption", path: network, actions: ["network.create"], skipPrefix: true });
    expect(() => assertManifestInScope(manifest, SHARE_MANIFEST_SCOPE, OWNER.address)).toThrow(ManifestRejectedError);
  });

  it("refuses both together, as the sign-in used to ask", () => {
    const manifest = withEntry({ service: "tinycloud.encryption", path: network, actions: ["decrypt", "network.create"], skipPrefix: true });
    expect(() => assertManifestInScope(manifest, SHARE_MANIFEST_SCOPE, OWNER.address)).toThrow(ManifestRejectedError);
  });
});

describe("the sign-in scope, share/ prefix", () => {
  it("refuses network creation on the share/ prefix", () => {
    const prefix = pathBoundSessionPermissions({ encryptionNetwork: defaultEncryptionNetworkForOwner({ address: OWNER.address }) })[0]!;
    expect(() => assertManifestInScope(withEntry({ ...prefix, actions: ["network.create"] }), SHARE_MANIFEST_SCOPE, OWNER.address)).toThrow(ManifestRejectedError);
  });
});
