// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { showRuntimePermissionDialog } from "../src/apps/permission-dialog.ts";

describe("runtime permission prompt", () => {
  it("shows only the requested permission when innerHTML requires TrustedHTML", async () => {
    const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, "innerHTML");
    expect(descriptor?.set).toBeTypeOf("function");
    if (descriptor?.set === undefined) throw new Error("innerHTML setter unavailable");
    Object.defineProperty(Element.prototype, "innerHTML", {
      ...descriptor,
      set() { throw new TypeError("TrustedHTML required"); },
    });
    try {
      const result = showRuntimePermissionDialog({
        appName: "Health Log",
        additional: [{ service: "tinycloud.kv", space: "applications", path: "xyz.tinycloud.sample.healthlog/settings/", actions: ["tinycloud.kv/get", "tinycloud.kv/put"] }],
      });
      const dialog = document.querySelector("dialog");
      expect(dialog?.textContent).toContain("Health Log");
      expect(dialog?.textContent).toContain("settings/");
      expect(dialog?.textContent).toContain("tinycloud.kv/get, tinycloud.kv/put");
      expect(dialog?.querySelector("script")).toBeNull();
      dialog?.querySelector<HTMLButtonElement>("[data-permission-allow]")?.click();
      await expect(result).resolves.toEqual({ approved: true });
      expect(document.querySelector("dialog")).toBeNull();
    } finally {
      Object.defineProperty(Element.prototype, "innerHTML", descriptor);
    }
  });

  it("declines when the request is cancelled", async () => {
    const result = showRuntimePermissionDialog({
      appName: "Health Log",
      additional: [{ service: "tinycloud.kv", space: "applications", path: "xyz.tinycloud.sample.healthlog/settings/", actions: ["tinycloud.kv/put"] }],
    });
    document.querySelector("dialog")?.dispatchEvent(new Event("cancel", { cancelable: true }));
    await expect(result).resolves.toEqual({ approved: false });
  });
});
