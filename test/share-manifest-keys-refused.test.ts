// Share holds no key declarations: a manifest that carries `keys` or `keys_app_id` is refused whatever its scope says.
import { describe, expect, it } from "vitest";
import { assertManifestInScope, ManifestRejectedError, MANIFEST_CHECK_ADDRESS } from "../src/share/manifest-policy.js";
import { SHARE_MANIFEST_SCOPE, shareManifest } from "../src/share/openkey-session.js";

const KEY = { path: "apps/example/key", abilities: ["encrypt", "decrypt"] };

describe("a manifest that declares keys", () => {
  it.each([
    ["keys", { ...shareManifest, keys: [KEY] }],
    ["keys_app_id", { ...shareManifest, keys_app_id: "example" }],
    ["both", { ...shareManifest, keys_app_id: "example", keys: [KEY] }],
  ])("is refused for %s", (_name, manifest) => {
    expect(() => assertManifestInScope(manifest as never, SHARE_MANIFEST_SCOPE, MANIFEST_CHECK_ADDRESS)).toThrow(ManifestRejectedError);
  });

  it("leaves the library's own manifest accepted", () => {
    expect(() => assertManifestInScope(shareManifest, SHARE_MANIFEST_SCOPE, MANIFEST_CHECK_ADDRESS)).not.toThrow();
  });
});
