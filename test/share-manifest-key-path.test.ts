// Option M: the library signs in once with decrypt and key.create on the default network's share/ prefix, so every share's key can be
// created without a further prompt. The entry comes from the SDK; the sign-in scope guard accepts exactly it and nothing broader.
import { getAddress } from "viem";
import { describe, expect, it } from "vitest";
import { resolveManifest } from "@tinycloud/sdk-core";
import { defaultEncryptionNetworkForOwner, pathBoundSessionPermissions } from "@tinycloud/share-sdk";
import { assertManifestInScope } from "../src/share/manifest-policy.js";
import { ownerEncryptionNetwork, SHARE_MANIFEST_SCOPE, shareManifest } from "../src/share/openkey-session.js";

const ADDRESS = "0x2f9fad83dbbb1e6bf56acb7e651225c070b7774b";
const OTHER_ADDRESS = "0x1111111111111111111111111111111111111111";
const KEY_CREATE = "tinycloud.encryption/key.create";

const keyCreates = (manifest: ReturnType<typeof shareManifest>) => resolveManifest(manifest).resources.filter((resource) => resource.actions.includes(KEY_CREATE));

describe("the library's sign-in manifest", () => {
  it("asks for key creation on the share/ prefix of the account's own default network, exactly as the SDK names it", () => {
    const [entry] = pathBoundSessionPermissions({ encryptionNetwork: defaultEncryptionNetworkForOwner({ address: ADDRESS }) });
    expect(shareManifest(ADDRESS).permissions).toContainEqual(expect.objectContaining({ service: "tinycloud.encryption", path: entry!.path }));
    const created = keyCreates(shareManifest(ADDRESS));
    expect(created).toHaveLength(1);
    expect(created[0]!.path).toBe(`urn:tinycloud:encryption:did:pkh:eip155:1:${getAddress(ADDRESS)}:default/share/`);
  });

  it("stays inside the library's sign-in scope, whatever the case of the address", () => {
    expect(() => assertManifestInScope(shareManifest(ADDRESS), SHARE_MANIFEST_SCOPE, ADDRESS)).not.toThrow();
    expect(() => assertManifestInScope(shareManifest(ADDRESS), SHARE_MANIFEST_SCOPE, getAddress(ADDRESS))).not.toThrow();
  });

  it("refuses key creation anywhere else: the bare network, another account's prefix", () => {
    const bare = shareManifest(ADDRESS);
    bare.permissions = [...bare.permissions!, { service: "tinycloud.encryption", path: ownerEncryptionNetwork(ADDRESS), actions: ["key.create"], skipPrefix: true }];
    expect(() => assertManifestInScope(bare, SHARE_MANIFEST_SCOPE, ADDRESS)).toThrow();
    const foreign = shareManifest(ADDRESS);
    const [other] = pathBoundSessionPermissions({ encryptionNetwork: defaultEncryptionNetworkForOwner({ address: OTHER_ADDRESS }) });
    foreign.permissions = [...foreign.permissions!, { service: "tinycloud.encryption", path: other!.path, actions: ["decrypt", "key.create"], skipPrefix: true }];
    expect(() => assertManifestInScope(foreign, SHARE_MANIFEST_SCOPE, ADDRESS)).toThrow();
  });
});
