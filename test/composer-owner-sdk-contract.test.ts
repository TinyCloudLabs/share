// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { mountShareComposer } from "../src/share/composer.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";

function selectAddressedFile(root: HTMLElement): void {
  const recipient = root.querySelector<HTMLInputElement>("input[value=exactEmail]")!;
  recipient.checked = true;
  recipient.dispatchEvent(new Event("change", { bubbles: true }));
  const value = root.querySelector<HTMLInputElement>("input[name=recipient-value]")!;
  value.value = "reader@example.com";
  value.dispatchEvent(new Event("input", { bubbles: true }));
  const file = root.querySelector<HTMLInputElement>("input[type=file]")!;
  Object.defineProperty(file, "files", { configurable: true, value: [new File(["notes"], "notes.txt", { type: "text/plain" })] });
  file.dispatchEvent(new Event("change", { bubbles: true }));
}

describe("the unified owner-share authority boundary", () => {
  afterEach(() => { vi.restoreAllMocks(); document.body.replaceChildren(); });

  it("has no remaining dependency on the retired v2 owner SDK ceremony", async () => {
    const { readFile } = await import("node:fs/promises");
    const { resolve } = await import("node:path");
    const source = await readFile(resolve(process.cwd(), "src/share/composer.ts"), "utf8");
    expect(source).not.toMatch(/\bsdk\.(?:createDelegatedShareKey|canonicalOwnerSharePolicy|createPolicyEnforcementDelegation)\s*\(/u);
    expect(source).not.toMatch(/\btinycloud\.(?:createOwnerDelegation|registerOwnerSharePolicy)\s*\(/u);
    expect(source).toContain("options.createUnifiedOwnerRoot");
    expect(source).toContain("options.signUnifiedPolicy");
  });

  it("fails closed before storage or network use when the owner authority bridge is absent", async () => {
    const debug = vi.spyOn(console, "debug").mockImplementation(() => undefined);
    const put = vi.fn();
    const root = document.createElement("div");
    document.body.append(root);
    mountShareComposer(root, {
      openKeyAddress: "0x1234567890abcdef",
      origin: "https://share.tinycloud.xyz",
      onBack: () => undefined,
      session: {} as OpenKeyShareSession,
      tinycloud: {
        spaceId: "space-1",
        did: "did:pkh:eip155:1:0x2222222222222222222222222222222222222222",
        kvForSpace: () => ({ put }),
      } as unknown as ShareTinyCloud,
      loadCapabilities: async () => [],
    });
    selectAddressedFile(root);
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".composer-status")?.dataset.state).toBe("error-invalid"));
    const failures = debug.mock.calls.map((call) => String((call[1] as Error | undefined)?.message ?? call[1]));
    expect(failures.join(" | ")).toContain("unified v3 owner-share primitives are unavailable");
    expect(put).not.toHaveBeenCalled();
  });
});
