import { describe, expect, it, vi } from "vitest";

import { canonicalArtifactPath } from "../src/artifact/bundle.js";
import { canonicalShareFilename, hasUnsafeFilenameCodePoint } from "../src/filename-policy.js";
import { validateComposerModel } from "../src/share/composer-model.js";
import { renderSafeContent } from "../src/viewer/content.js";

const SPOOFING_NAMES = [
  "invoice\u202Efdp.exe",
  "invoice\u202Apdf.txt",
  "invoice\u2066pdf.txt",
  "invoice\u2069pdf.txt",
  "line\u2028break.md",
  "paragraph\u2029break.md",
  "zero\u200Bwidth.md",
  "control\u0001.md",
  "surrogate\uD800.md",
] as const;

describe("shared filename policy", () => {
  it.each(SPOOFING_NAMES)("rejects Unicode control/spoofing filename %j at canonicalization", (filename) => {
    expect(hasUnsafeFilenameCodePoint(filename)).toBe(true);
    expect(() => canonicalShareFilename(filename)).toThrow("share filename is unsafe");
    expect(() => canonicalArtifactPath(filename)).toThrow("artifact path is not canonical");
  });

  it.each(SPOOFING_NAMES)("rejects %j before the sender model can be signed", (filename) => {
    expect(() => validateComposerModel({
      content: { kind: "text", text: "safe body", filename },
      recipient: { kind: "bearer" },
      permissions: ["read"],
      expiresAt: "2030-01-01T00:00:00.000Z",
      resource: { kind: "exact", path: filename },
      encryption: true,
      encryptionAcknowledged: false,
    })).toThrow("That file name can't be shared");
  });

  it.each(SPOOFING_NAMES)("rejects %j before viewer render or download allocation", async (filename) => {
    const previous = URL.createObjectURL;
    const createObjectURL = vi.fn(() => "blob:must-not-be-created");
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: createObjectURL });
    const root = document.createElement("main");
    try {
      await expect(renderSafeContent(root, new TextEncoder().encode("safe body"), {
        mediaType: "application/octet-stream",
        filename,
        byteLength: 9,
      })).rejects.toThrow("share filename is unsafe");
      expect(root.childElementCount).toBe(0);
      expect(createObjectURL).not.toHaveBeenCalled();
    } finally {
      if (previous === undefined) Reflect.deleteProperty(URL, "createObjectURL");
      else Object.defineProperty(URL, "createObjectURL", { configurable: true, value: previous });
    }
  });

  it("retains ordinary international filenames after NFC canonicalization", () => {
    expect(canonicalShareFilename("résumé-日本語.md")).toBe("résumé-日本語.md");
  });
});
