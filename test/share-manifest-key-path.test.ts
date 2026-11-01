// Option M: the library signs in once with decrypt and key.create on the default network's share/ prefix, so every share's key can be
// created without a further prompt. The entry comes from the SDK; the sign-in scope guard accepts exactly it and nothing broader.
import { getAddress } from "viem";
import { describe, expect, it } from "vitest";
import { resolveManifest } from "@tinycloud/sdk-core";
import { defaultEncryptionNetworkForOwner, pathBoundSessionPermissions } from "@tinycloud/share-sdk";
import { assertManifestInScope, ManifestRejectedError, type ManifestScope } from "../src/share/manifest-policy.js";
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

  const refusedWith = (permissions: ReturnType<typeof shareManifest>["permissions"]) => {
    const manifest = shareManifest(ADDRESS);
    manifest.permissions = [...manifest.permissions!, ...permissions!];
    try {
      assertManifestInScope(manifest, SHARE_MANIFEST_SCOPE, ADDRESS);
    } catch (error) {
      return (error as { code?: string }).code;
    }
    return "accepted";
  };
  const [other] = pathBoundSessionPermissions({ encryptionNetwork: defaultEncryptionNetworkForOwner({ address: OTHER_ADDRESS }) });
  const [foreignChain] = pathBoundSessionPermissions({ encryptionNetwork: defaultEncryptionNetworkForOwner({ address: ADDRESS }) });

  it.each([
    ["key.create on the bare network", [{ service: "tinycloud.encryption", path: ownerEncryptionNetwork(ADDRESS), actions: ["tinycloud.encryption/key.create"] }], "invalid-manifest"],
    ["another account's prefix", [{ service: "tinycloud.encryption", path: other!.path, actions: ["tinycloud.encryption/decrypt", "tinycloud.encryption/key.create"] }], "path-not-allowed"],
    ["the prefix on another chain", [{ service: "tinycloud.encryption", path: foreignChain!.path.replace(":eip155:1:", ":eip155:10:"), actions: ["tinycloud.encryption/decrypt", "tinycloud.encryption/key.create"] }], "path-not-allowed"],
    ["key.create on a kv path (the bare action must not be a wildcard)", [{ service: "tinycloud.kv", path: "xyz.tinycloud.share/x", actions: ["key.create"] }], "action-not-allowed"],
  ])("refuses %s", (_name, permissions, code) => {
    expect(refusedWith(permissions as never)).toBe(code);
  });
});

describe("a scope without the checksum placeholder", () => {
  it("never parses the address as one, so a malformed address is refused as a manifest, not thrown as an address error", () => {
    const scope: ManifestScope = { allowedSpaces: ["s"], allowedServices: ["kv"], allowedActions: ["get"], allowedPathPrefixes: [{ space: "s", prefix: "app/" }] };
    const manifest = { app_id: "app", permissions: [{ service: "tinycloud.kv", space: "s", path: "app/x", actions: ["get"] }] } as never;
    let thrown: unknown;
    try { assertManifestInScope(manifest, scope, "not-an-address"); } catch (error) { thrown = error; }
    expect(thrown === undefined || thrown instanceof ManifestRejectedError).toBe(true);
  });
});
