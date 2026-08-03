// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { mountShareComposer } from "../src/share/composer.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";

describe("owner delivery never bypasses unified v3 authority", () => {
  afterEach(() => { vi.restoreAllMocks(); document.body.replaceChildren(); });

  it("does not create or notify a share when the owner-root signer is unavailable", async () => {
    vi.spyOn(console, "debug").mockImplementation(() => undefined);
    const notify = vi.fn();
    const authorizeShareDelivery = vi.fn();
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
        authorizeShareDelivery,
        kvForSpace: () => ({ put: vi.fn() }),
      } as unknown as ShareTinyCloud,
      loadCapabilities: async () => [],
      notify,
    });
    const recipient = root.querySelector<HTMLInputElement>("input[value=exactEmail]")!;
    recipient.checked = true;
    recipient.dispatchEvent(new Event("change", { bubbles: true }));
    const value = root.querySelector<HTMLInputElement>("input[name=recipient-value]")!;
    value.value = "reader@example.com";
    value.dispatchEvent(new Event("input", { bubbles: true }));
    const file = root.querySelector<HTMLInputElement>("input[type=file]")!;
    Object.defineProperty(file, "files", { configurable: true, value: [new File(["notes"], "notes.txt")] });
    file.dispatchEvent(new Event("change", { bubbles: true }));
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".composer-status")?.dataset.state).toBe("error-invalid"));
    expect(root.querySelector(".confirm-notification")).toBeNull();
    expect(authorizeShareDelivery).not.toHaveBeenCalled();
    expect(notify).not.toHaveBeenCalled();
  });
});
