import { afterEach, describe, expect, it, vi } from "vitest";
import { defaultComposerModel, emailDomainOf, normalizeEmailDomain, validateComposerModel, type ShareComposerModel } from "../src/share/composer-model.js";
import { mountShareComposer } from "../src/share/composer.js";

afterEach(() => { document.body.replaceChildren(); vi.restoreAllMocks(); });

function readFileBytes(file: File): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

describe("share composer model", () => {
  it("defaults to encrypted compact read-only bearer sharing with no notification", () => {
    expect(defaultComposerModel()).toMatchObject({ linkFormat: "compact", encryption: true, permissions: ["read"], notify: false, recipient: { kind: "bearer" } });
  });

  it("normalizes domain authorization from the input, never from asserted metadata", () => {
    expect(normalizeEmailDomain("MAILINATOR.COM")).toBe("mailinator.com");
    expect(emailDomainOf("Alice@mailinator.com")).toBe("mailinator.com");
    expect(() => validateComposerModel({ ...defaultComposerModel(), recipient: { kind: "emailDomain", value: "mailinator.com" }, encryption: false, encryptionAcknowledged: false })).toThrow();
    expect(validateComposerModel({ ...defaultComposerModel(), recipient: { kind: "emailDomain", value: "MAILINATOR.COM" }, encryption: false, encryptionAcknowledged: true })).toMatchObject({ recipient: { value: "mailinator.com" } });
  });

  it("does not expose notification controls for bearer shares", () => {
    const root = document.createElement("div"); document.body.append(root);
    mountShareComposer(root, { openKeyAddress: "0x1234567890abcdef", origin: "https://share.tinycloud.xyz" });
    const notify = root.querySelector<HTMLInputElement>("input[name=notify]");
    expect(notify?.disabled).toBe(true);
    expect(root.querySelector(".confirm-notification")).toBeNull();
  });

  it.each([
    ["author", "# Notes\n\nHello", "notes.md"],
    ["upload", new Uint8Array([0, 255, 1, 2]), "photo.bin"],
  ] as const)("routes %s content through the canonical create callback", async (mode, content, filename) => {
    const root = document.createElement("div");
    const received: { file?: File; model?: ShareComposerModel } = {};
    mountShareComposer(root, {
      openKeyAddress: "0x1234567890abcdef",
      origin: "https://share.tinycloud.xyz",
      loadCapabilities: async () => [],
      createShare: async ({ file, model }) => { received.file = file; received.model = model; return { url: "https://share.tinycloud.xyz/s/example", cid: "cid", format: model.linkFormat }; },
    });
    const modeInput = root.querySelector<HTMLSelectElement>("select[name=content-mode]")!;
    modeInput.value = mode;
    modeInput.dispatchEvent(new Event("change", { bubbles: true }));
    if (mode === "author") {
      const author = root.querySelector<HTMLTextAreaElement>("textarea[name=author-content]")!;
      author.value = String(content);
    } else {
      const input = root.querySelector<HTMLInputElement>("input[name=document]")!;
      Object.defineProperty(input, "files", { configurable: true, value: [new File([content], filename, { type: "application/octet-stream" })] });
      input.dispatchEvent(new Event("change", { bubbles: true }));
    }
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(received.file).toBeDefined();
    expect(Array.from(await readFileBytes(received.file!))).toEqual(Array.from(mode === "author" ? new TextEncoder().encode(String(content)) : content));
    expect(received.model?.permissions).toEqual(["read"]);
  });

  it("selects a real authenticated KV source and preserves the canonical source boundary", async () => {
    const root = document.createElement("div");
    let selected: ShareComposerModel | undefined;
    const capability = { capabilityId: "cap-1", scope: {}, source: { kind: "kv" as const, space: "space-1", path: "docs/readme.md", action: "tinycloud.kv/get" as const }, policy: {} as never };
    mountShareComposer(root, { openKeyAddress: "0x1234567890abcdef", origin: "https://share.tinycloud.xyz", loadCapabilities: async () => [capability], createShare: async ({ model }) => { selected = model; return { url: "https://share.tinycloud.xyz/s/example", cid: "cid", format: model.linkFormat }; } });
    await new Promise((resolve) => setTimeout(resolve, 0));
    const mode = root.querySelector<HTMLSelectElement>("select[name=content-mode]")!; mode.value = "kv"; mode.dispatchEvent(new Event("change", { bubbles: true }));
    const file = root.querySelector<HTMLInputElement>("input[name=document]")!; Object.defineProperty(file, "files", { configurable: true, value: [new File([new Uint8Array([1, 2])], "draft.bin")] });
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(selected?.source).toEqual(capability.source);
    expect(selected?.resource).toEqual({ kind: "exact", path: capability.source.path });
  });

  it("keeps a selected KV folder as a segment-boundary prefix", async () => {
    const root = document.createElement("div");
    let selected: ShareComposerModel | undefined;
    const capability = { capabilityId: "cap-folder", scope: { prefixes: ["docs"] }, source: { kind: "kv" as const, space: "space-1", path: "docs/readme.md", action: "tinycloud.kv/get" as const }, policy: {} as never };
    mountShareComposer(root, { openKeyAddress: "0x1234567890abcdef", origin: "https://share.tinycloud.xyz", loadCapabilities: async () => [capability], createShare: async ({ model }) => { selected = model; return { url: "https://share.tinycloud.xyz/s/example", cid: "cid", format: model.linkFormat }; } });
    await new Promise((resolve) => setTimeout(resolve, 0));
    const mode = root.querySelector<HTMLSelectElement>("select[name=content-mode]")!; mode.value = "kv"; mode.dispatchEvent(new Event("change", { bubbles: true }));
    const source = root.querySelector<HTMLSelectElement>("select[name=kv-source]")!; source.value = "docs/";
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(selected?.resource).toEqual({ kind: "prefix", path: "docs/" });
    expect(selected?.source).toEqual(capability.source);
  });

  it("rejects unsafe plaintext attempts and never permits bearer plaintext", () => {
    expect(() => validateComposerModel({ ...defaultComposerModel(), encryption: false })).toThrow(/must stay encrypted/i);
    expect(() => validateComposerModel({ ...defaultComposerModel(), recipient: { kind: "emailDomain", value: "MAILINATOR.COM" }, encryption: false, encryptionAcknowledged: false })).toThrow(/acknowledge/i);
    expect(validateComposerModel({ ...defaultComposerModel(), recipient: { kind: "emailDomain", value: "MAILINATOR.COM" }, encryption: false, encryptionAcknowledged: true, resource: { kind: "prefix", path: "docs" } })).toMatchObject({ recipient: { value: "mailinator.com" }, resource: { kind: "prefix", path: "docs/" } });
  });
});
