import { afterEach, describe, expect, it, vi } from "vitest";
import { OWNER_SDK_PRIMITIVES, missingOwnerSdkPrimitives, mountShareComposer } from "../src/share/composer.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";

// The deployment config loader is the one external boundary this file stubs.
// `@tinycloud/web-sdk` is deliberately left alone — it is the subject.
vi.mock("../src/email-share/config.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/email-share/config.js")>();
  return {
    ...actual,
    loadSharePublicConfig: async () => ({
      version: "tinycloud.share-email-claim/config-v1",
      shareOrigin: "https://share.tinycloud.xyz",
      registryOrigin: "https://registry.tinycloud.xyz",
      nodeOrigin: "https://node.tinycloud.xyz",
      credentialsOrigin: "https://credentials.org",
      nodeAudience: "did:web:node.tinycloud.xyz",
      enforcerDid: "did:web:node.tinycloud.xyz",
      nodeEnabled: true,
      issuerDid: "did:web:credentials.org",
      issuerVct: "opencredentials.email/v1",
      issuerEnabled: true,
      nodeInvitationKid: "did:web:node.tinycloud.xyz#invitation-1",
      nodeInvitationPublicKey: "A".repeat(43),
      nodeKeyVersion: 1,
      issuerKeyVersion: 1,
      issuerPublicKey: "A".repeat(43),
    }),
  };
});

/**
 * TC-338 coverage gap.
 *
 * `createOwnerPolicyShare` reaches three module-level owner-share primitives in
 * `@tinycloud/web-sdk`, and `@tinycloud/web-sdk@2.9.0` exports none of them, so
 * the shipped browser fails on the first call. No test caught it because the
 * only suite that drives the owner path (`composer-expiry.test.ts`) installs
 * those primitives itself:
 *
 *     vi.mock("@tinycloud/web-sdk", async (importOriginal) => ({
 *       ...(await importOriginal()), createDelegatedShareKey: ..., ...
 *     }))
 *
 * A stub cannot observe an export the real package does not have, so this file
 * deliberately does NOT mock `@tinycloud/web-sdk`. It loads the package that is
 * actually installed, through the same resolution the browser build uses, and
 * holds the composer's own guard to that surface.
 *
 * This is the only layer below a real browser that can see the drift. It is not
 * a substitute for a browser run of the owner path, which is tracked separately
 * (`test/e2e-sharing`, not owned here).
 */
describe("the owner-share SDK contract is checked against the installed Web SDK", () => {
  it("agrees with the module that actually loads", async () => {
    const sdk = await import("@tinycloud/web-sdk") as unknown as Record<string, unknown>;

    // Computed from the real package, not from a fixture: whatever the installed
    // SDK provides is the truth this guard has to report.
    const actuallyMissing = OWNER_SDK_PRIMITIVES.filter((name) => typeof sdk[name] !== "function");

    expect(missingOwnerSdkPrimitives(sdk)).toEqual(actuallyMissing);
  });

  it("names every primitive the owner path calls, so a new call site cannot go unchecked", async () => {
    // jsdom rewrites `import.meta.url` to an http URL, so this resolves from
    // the vitest root instead.
    const { readFile } = await import("node:fs/promises");
    const { resolve } = await import("node:path");
    const source = await readFile(resolve(process.cwd(), "src/share/composer.ts"), "utf8");

    // Every `sdk.<name>(` call inside composer.ts must be covered by the guard.
    // Adding a fourth primitive without listing it here reintroduces exactly the
    // TC-338 failure mode: an unchecked call on a possibly-absent export.
    const called = [...new Set([...source.matchAll(/\bsdk\.([A-Za-z0-9_$]+)\s*\(/g)].map((match) => match[1]!))].sort();

    expect(called).toEqual([...OWNER_SDK_PRIMITIVES].sort());
  });

  it("reports missing primitives by name instead of throwing an opaque TypeError", () => {
    const empty = missingOwnerSdkPrimitives({});
    expect(empty).toEqual([...OWNER_SDK_PRIMITIVES]);

    const partial = missingOwnerSdkPrimitives({ createDelegatedShareKey: () => undefined, canonicalOwnerSharePolicy: "not a function" });
    expect(partial).toEqual(["canonicalOwnerSharePolicy", "createPolicyEnforcementDelegation"]);

    const complete = Object.fromEntries(OWNER_SDK_PRIMITIVES.map((name) => [name, () => undefined]));
    expect(missingOwnerSdkPrimitives(complete)).toEqual([]);
  });
});

/**
 * The guard above is only worth anything if `createOwnerPolicyShare` actually
 * runs it. This drives the real composer — real DOM controls, real
 * `validateComposerModel` -> `defaultCreate` -> `createPolicyShare` ->
 * `createOwnerPolicyShare` chain — with the REAL `@tinycloud/web-sdk`, and
 * pins the invariant that survives either state of that package: the owner path
 * never reports an unresolved-export TypeError to the sender. Deleting the
 * guard puts `sdk.createDelegatedShareKey is not a function` back on this
 * assertion.
 */
describe("the owner-policy path fails diagnosably against the real Web SDK", () => {
  afterEach(() => { vi.restoreAllMocks(); document.body.replaceChildren(); });

  it("never surfaces an opaque 'is not a function' for an absent owner primitive", async () => {
    const debug = vi.spyOn(console, "debug").mockImplementation(() => undefined);

    const tinycloud = {
      spaceId: "space-1",
      did: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222",
      // Reached only if the SDK guard passes; present so a guard regression
      // fails on the assertion below rather than on missing scaffolding.
      createOwnerDelegation: async () => ({ delegationCid: "bafkreiownerdelegationfake", signedDagCbor: new Uint8Array([1, 2, 3]) }),
      registerOwnerSharePolicy: async () => ({ registration: { registrationCid: "bafkreiregistrationfake" } }),
      kvForSpace: () => ({ put: async () => ({ ok: true }) }),
    } as unknown as ShareTinyCloud;

    const root = document.createElement("div");
    document.body.append(root);
    mountShareComposer(root, {
      openKeyAddress: "0x1234567890abcdef",
      origin: "https://share.tinycloud.xyz",
      onBack: () => undefined,
      session: {} as OpenKeyShareSession,
      tinycloud,
      loadCapabilities: async () => [],
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const recipient = root.querySelector<HTMLInputElement>("input[value=exactEmail]")!;
    recipient.checked = true; recipient.dispatchEvent(new Event("change", { bubbles: true }));
    const value = root.querySelector<HTMLInputElement>("input[name=recipient-value]")!;
    value.value = "reader@example.com"; value.dispatchEvent(new Event("input", { bubbles: true }));
    const format = root.querySelector<HTMLSelectElement>("select[name=format]")!;
    format.value = "inline"; format.dispatchEvent(new Event("change", { bubbles: true }));
    const delivery = root.querySelector<HTMLInputElement>("input[name=delivery-email]")!;
    delivery.value = "reader@example.com"; delivery.dispatchEvent(new Event("input", { bubbles: true }));
    const file = root.querySelector<HTMLInputElement>("input[type=file]")!;
    Object.defineProperty(file, "files", { configurable: true, value: [new File([new Uint8Array([1, 2, 3, 4])], "notes.txt", { type: "text/plain" })] });
    file.dispatchEvent(new Event("change", { bubbles: true }));
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    for (let tick = 0; tick < 60; tick += 1) await new Promise((resolve) => setTimeout(resolve, 5));

    const errors = debug.mock.calls.filter((call) => String(call[0]).includes("sender request failed")).map((call) => String((call[1] as Error | undefined)?.message ?? call[1]));

    // The failure mode TC-338 shipped: an unresolved SDK export called as a
    // function. It must never reach the sender lane, in either SDK state.
    for (const message of errors) expect(message).not.toMatch(/is not a function/i);

    // And when primitives really are absent, the report has to name them.
    const sdk = await import("@tinycloud/web-sdk") as unknown as Record<string, unknown>;
    const missing = missingOwnerSdkPrimitives(sdk);
    if (missing.length > 0) {
      expect(errors.join(" | ")).toContain(missing.join(", "));
      expect(errors.join(" | ")).toContain("@tinycloud/web-sdk");
    }
  });
});
