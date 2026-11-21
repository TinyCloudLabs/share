import { afterEach, describe, expect, it, vi } from "vitest";
import { TinyCloudWeb } from "@tinycloud/web-sdk";
import { showRuntimePermissionDialog } from "../src/apps/permission-dialog.ts";

afterEach(() => {
  document.body.replaceChildren();
  localStorage.clear();
});

describe("published SDK permission dialog contract", () => {
  it("shows app names as text and honours Cancel through the real permission request", async () => {
    const appName = "Health Log <img src=x>";
    // Keep the published requestPermissions implementation; only its node backend
    // and constructor state are supplied here, so no wallet, WASM or network is needed.
    const client = Object.create(TinyCloudWeb.prototype) as TinyCloudWeb;
    Object.assign(client, {
      _manifest: { app_id: "xyz.example.permission-dialog", name: appName },
      ensureNode: async () => ({
        did: "did:pkh:eip155:1:0x0000000000000000000000000000000000000001",
        hasRuntimePermissions: () => false,
      }),
      uiClient: { promptScope: undefined },
      _testHooks: { showModal: showRuntimePermissionDialog },
    });
    const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
    if (descriptor?.set === undefined) throw new Error("innerHTML setter unavailable");
    Object.defineProperty(Element.prototype, "innerHTML", {
      ...descriptor,
      set() { throw new TypeError("TrustedHTML required"); },
    });
    try {
      // Attach a rejection handler immediately, including when a changed SDK
      // rejects before it can show the dialog.
      const result = client.requestPermissions([{
        service: "tinycloud.kv",
        space: "applications",
        path: "xyz.example.permission-dialog/settings/",
        actions: ["tinycloud.kv/put"],
      }]).catch((error: unknown) => ({ error }));
      await vi.waitFor(() => {
        expect(document.querySelector("dialog h2")?.textContent).toBe(`${appName} requests additional access`);
      });
      const dialog = document.querySelector("dialog");
      expect(dialog?.querySelector("img")).toBeNull();
      expect(dialog?.textContent).toContain("applications/xyz.example.permission-dialog/settings/");
      expect(dialog?.textContent).toContain("tinycloud.kv/put");
      const cancel = [...(dialog?.querySelectorAll("button") ?? [])].find((button) => button.textContent === "Cancel");
      expect(cancel).toBeDefined();
      cancel?.click();
      await expect(result).resolves.toEqual({ approved: false });
      expect(document.querySelector("dialog")).toBeNull();
    } finally {
      document.querySelector("dialog")?.dispatchEvent(new Event("cancel", { cancelable: true }));
      Object.defineProperty(Element.prototype, "innerHTML", descriptor);
    }
  });
});
