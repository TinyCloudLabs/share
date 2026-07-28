import { afterEach, describe, expect, it, vi } from "vitest";
import {
  clampExpiry,
  contentFile,
  contentFilename,
  contentMediaType,
  contentMode,
  defaultComposerModel,
  emailDomainOf,
  expiryFromChoice,
  normalizeEmailDomain,
  validateComposerModel,
  type ComposerContent,
  type ShareComposerModel,
} from "../src/share/composer-model.js";
import { mountShareComposer } from "../src/share/composer.js";
import { LinkOnlyShareError } from "../src/share/link-only.js";
import { fail, SENDER_FAILURE, senderFailureMessage } from "../src/share/sender-failure.js";

afterEach(() => { document.body.replaceChildren(); vi.restoreAllMocks(); });

function readFileBytes(file: File): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(file);
  });
}

/** A model is only valid with content; tests supply it explicitly. */
function modelWith(content: ComposerContent, overrides: Partial<ShareComposerModel> = {}): ShareComposerModel {
  const resource = content.kind === "library" ? content.resource : { kind: "exact" as const, path: contentFilename(content) };
  return { ...defaultComposerModel(), content, resource, ...overrides };
}

const textContent: ComposerContent = { kind: "text", text: "# Notes", filename: "notes.md" };

function paste(target: Element, value: { readonly text?: string; readonly file?: File }): void {
  const event = new Event("paste", { bubbles: true, cancelable: true });
  Object.defineProperty(event, "clipboardData", {
    value: { files: value.file === undefined ? [] : [value.file], getData: (type: string) => type === "text/plain" ? value.text ?? "" : "" },
  });
  target.dispatchEvent(event);
}

function dropFile(target: Element, file: File): void {
  const event = new Event("drop", { bubbles: true, cancelable: true });
  Object.defineProperty(event, "dataTransfer", { value: { files: [file] } });
  target.dispatchEvent(event);
}

function baseOptions(): { openKeyAddress: string; origin: string; onBack: () => void } {
  return { openKeyAddress: "0x1234567890abcdef", origin: "https://share.tinycloud.xyz", onBack: () => undefined };
}

describe("share composer model", () => {
  it("defaults to an encrypted, short, read-only, link-only share expiring in 7 days", () => {
    const defaults = defaultComposerModel(Date.parse("2026-07-27T00:00:00.000Z"));
    expect(defaults).toMatchObject({ linkFormat: "compact", encryption: true, permissions: ["read"], recipient: { kind: "bearer" } });
    expect(defaults.expiresAt).toBe("2026-08-03T00:00:00.000Z");
    expect(defaults).not.toHaveProperty("notify");
  });

  it("describes every content kind through one union, so no mode has to be recorded by hand", async () => {
    const file = new File([new Uint8Array([1, 2, 3])], "photo.bin", { type: "image/png" });
    expect(contentFilename({ kind: "file", file })).toBe("photo.bin");
    expect(contentMediaType({ kind: "file", file })).toBe("image/png");
    expect(contentMode({ kind: "file", file })).toBe("upload");

    const text = contentFile(textContent)!;
    expect(text.name).toBe("notes.md");
    expect(Array.from(await readFileBytes(text))).toEqual(Array.from(new TextEncoder().encode("# Notes")));
    expect(contentMediaType(textContent)).toBe("text/markdown;charset=utf-8");
    expect(contentMode(textContent)).toBe("author");

    const library: ComposerContent = { kind: "library", source: { kind: "kv", space: "space-1", path: "docs/readme.md", action: "tinycloud.kv/get" }, resource: { kind: "exact", path: "docs/readme.md" } };
    expect(contentFile(library)).toBeUndefined();
    expect(contentFilename(library)).toBe("readme.md");
    expect(contentMode(library)).toBe("kv");
  });

  it("clamps the chosen expiry to the signed capability boundary", () => {
    expect(expiryFromChoice("24h", Date.parse("2026-07-27T00:00:00.000Z"))).toBe("2026-07-28T00:00:00.000Z");
    expect(clampExpiry("2026-08-30T00:00:00.000Z", "2026-08-01T00:00:00.000Z")).toBe("2026-08-01T00:00:00.000Z");
    expect(clampExpiry("2026-08-01T00:00:00.000Z", "2026-08-30T00:00:00.000Z")).toBe("2026-08-01T00:00:00.000Z");
    expect(clampExpiry("2026-08-01T00:00:00.000Z")).toBe("2026-08-01T00:00:00.000Z");
  });

  it("normalizes domain authorization from the input, never from asserted metadata", () => {
    expect(normalizeEmailDomain("MAILINATOR.COM")).toBe("mailinator.com");
    expect(emailDomainOf("Alice@mailinator.com")).toBe("mailinator.com");
    expect(() => validateComposerModel(modelWith(textContent, { recipient: { kind: "emailDomain", value: "mailinator.com" }, encryption: false, encryptionAcknowledged: false }))).toThrow();
    expect(validateComposerModel(modelWith(textContent, { recipient: { kind: "emailDomain", value: "MAILINATOR.COM" }, encryption: false, encryptionAcknowledged: true }))).toMatchObject({ recipient: { value: "mailinator.com" } });
  });

  it("rejects unsafe plaintext attempts and never permits bearer plaintext", () => {
    expect(() => validateComposerModel(modelWith(textContent, { encryption: false }))).toThrow(/must stay encrypted/i);
    expect(() => validateComposerModel(modelWith(textContent, { recipient: { kind: "emailDomain", value: "MAILINATOR.COM" }, encryption: false, encryptionAcknowledged: false }))).toThrow(/confirm you understand/i);
    expect(validateComposerModel(modelWith(textContent, { recipient: { kind: "emailDomain", value: "MAILINATOR.COM" }, encryption: false, encryptionAcknowledged: true, resource: { kind: "prefix", path: "docs" } }))).toMatchObject({ recipient: { value: "mailinator.com" }, resource: { kind: "prefix", path: "docs/" } });
  });
});

describe("share composer content picker", () => {
  it("never asks the sender to classify their content", () => {
    const root = document.createElement("div"); document.body.append(root);
    mountShareComposer(root, baseOptions());
    expect(root.querySelector("select[name=content-mode]")).toBeNull();
    expect(root.querySelector("input[name=notify]")).toBeNull();
    expect(root.querySelector(".content-dropzone")).not.toBeNull();
    expect(root.textContent).not.toContain("KV");
  });

  it("turns a pasted block of text into an editable draft in place, with no mode chosen", async () => {
    const root = document.createElement("div"); document.body.append(root);
    let received: { file?: File; model?: ShareComposerModel } = {};
    mountShareComposer(root, { ...baseOptions(), loadCapabilities: async () => [], createShare: async ({ file, model }) => { received = { ...(file === undefined ? {} : { file }), model }; return { url: "https://share.tinycloud.xyz/s/example", cid: "cid", format: model.linkFormat }; } });
    const drop = root.querySelector<HTMLElement>(".content-dropzone")!;
    paste(drop, { text: "# Hermetic sharing\n\nPasted in the browser." });
    const author = root.querySelector<HTMLTextAreaElement>("textarea[name=author-content]")!;
    const chip = root.querySelector<HTMLInputElement>("input[name=content-filename]")!;
    expect(drop.hidden).toBe(true);
    expect(author.value).toBe("# Hermetic sharing\n\nPasted in the browser.");
    expect(chip.value).toBe("Hermetic-sharing.md");
    expect(root.querySelector<HTMLButtonElement>(".use-file-instead")).not.toBeNull();

    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(received.model?.content).toMatchObject({ kind: "text", filename: "Hermetic-sharing.md" });
    expect(Array.from(await readFileBytes(received.file!))).toEqual(Array.from(new TextEncoder().encode("# Hermetic sharing\n\nPasted in the browser.")));
  });

  it("restores the drop zone when the sender decides to use a file instead", () => {
    const root = document.createElement("div"); document.body.append(root);
    mountShareComposer(root, baseOptions());
    const drop = root.querySelector<HTMLElement>(".content-dropzone")!;
    paste(drop, { text: "draft" });
    expect(drop.hidden).toBe(true);
    root.querySelector<HTMLButtonElement>(".use-file-instead")!.click();
    expect(drop.hidden).toBe(false);
    expect(root.querySelector<HTMLElement>(".content-text")!.hidden).toBe(true);
  });

  it.each([
    ["a dropped file", (root: HTMLElement, file: File) => dropFile(root.querySelector<HTMLElement>(".content-dropzone")!, file)],
    ["a pasted file", (root: HTMLElement, file: File) => paste(root.querySelector<HTMLElement>(".content-dropzone")!, { file })],
    ["a chosen file", (root: HTMLElement, file: File) => {
      const input = root.querySelector<HTMLInputElement>("input[name=document]")!;
      Object.defineProperty(input, "files", { configurable: true, value: [file] });
      input.dispatchEvent(new Event("change", { bubbles: true }));
    }],
  ])("infers file content from %s", async (_label, act) => {
    const root = document.createElement("div"); document.body.append(root);
    let received: { file?: File; model?: ShareComposerModel } = {};
    mountShareComposer(root, { ...baseOptions(), loadCapabilities: async () => [], createShare: async ({ file, model }) => { received = { ...(file === undefined ? {} : { file }), model }; return { url: "https://share.tinycloud.xyz/s/example", cid: "cid", format: model.linkFormat }; } });
    const file = new File([new Uint8Array([0, 255, 1, 2])], "photo.bin", { type: "application/octet-stream" });
    act(root, file);
    expect(root.querySelector<HTMLElement>(".content-chosen")!.hidden).toBe(false);
    expect(root.querySelector(".content-chosen-name")?.textContent).toBe("photo.bin");
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(received.model?.content).toMatchObject({ kind: "file" });
    expect(Array.from(await readFileBytes(received.file!))).toEqual([0, 255, 1, 2]);
    expect(received.model?.permissions).toEqual(["read"]);
  });

  it("selects a real library source and preserves the canonical source boundary", async () => {
    const root = document.createElement("div"); document.body.append(root);
    let selected: ShareComposerModel | undefined;
    const capability = { capabilityId: "cap-1", scope: {}, source: { kind: "kv" as const, space: "space-1", path: "docs/readme.md", action: "tinycloud.kv/get" as const }, policy: {} as never };
    mountShareComposer(root, { ...baseOptions(), loadCapabilities: async () => [capability], createShare: async ({ model }) => { selected = model; return { url: "https://share.tinycloud.xyz/s/example", cid: "cid", format: model.linkFormat }; } });
    await new Promise((resolve) => setTimeout(resolve, 0));
    root.querySelector<HTMLButtonElement>(".dropzone-library")!.click();
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(selected?.content).toEqual({ kind: "library", source: capability.source, resource: { kind: "exact", path: capability.source.path } });
    expect(selected?.resource).toEqual({ kind: "exact", path: capability.source.path });
  });

  it("keeps a selected library folder as a segment-boundary prefix", async () => {
    const root = document.createElement("div"); document.body.append(root);
    let selected: ShareComposerModel | undefined;
    const capability = { capabilityId: "cap-folder", scope: { prefixes: ["docs"] }, source: { kind: "kv" as const, space: "space-1", path: "docs/readme.md", action: "tinycloud.kv/get" as const }, policy: {} as never };
    mountShareComposer(root, { ...baseOptions(), loadCapabilities: async () => [capability], createShare: async ({ model }) => { selected = model; return { url: "https://share.tinycloud.xyz/s/example", cid: "cid", format: model.linkFormat }; } });
    await new Promise((resolve) => setTimeout(resolve, 0));
    root.querySelector<HTMLButtonElement>(".dropzone-library")!.click();
    const source = root.querySelector<HTMLSelectElement>("select[name=kv-source]")!; source.value = "docs/";
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(selected?.resource).toEqual({ kind: "prefix", path: "docs/" });
    expect(selected?.content).toMatchObject({ kind: "library", source: capability.source });
  });

  it("refuses to submit with nothing chosen, and says what to do", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const createShare = vi.fn();
    mountShareComposer(root, { ...baseOptions(), loadCapabilities: async () => [], createShare: createShare as never });
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(createShare).not.toHaveBeenCalled();
    expect(root.querySelector(".composer-status")?.textContent).toContain("Drop a file, paste text");
  });
});

describe("share composer access controls", () => {
  it("asks for the expiry it used to hardcode, and states the consequence", async () => {
    const root = document.createElement("div"); document.body.append(root);
    let selected: ShareComposerModel | undefined;
    mountShareComposer(root, { ...baseOptions(), loadCapabilities: async () => [], createShare: async ({ model }) => { selected = model; return { url: "https://share.tinycloud.xyz/s/example", cid: "cid", format: model.linkFormat }; } });
    const expiry = root.querySelector<HTMLSelectElement>("select[name=expiry]")!;
    expect(expiry.value).toBe("7d");
    expect(Array.from(expiry.options).map((option) => option.value)).toEqual(["24h", "7d", "30d", "90d"]);
    expect(root.querySelector(".composer-note")?.textContent).toContain("can't be revoked early");

    expiry.value = "24h"; expiry.dispatchEvent(new Event("change", { bubbles: true }));
    paste(root.querySelector<HTMLElement>(".content-dropzone")!, { text: "hello" });
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const hours = (Date.parse(selected!.expiresAt) - Date.now()) / (60 * 60 * 1000);
    expect(hours).toBeGreaterThan(23.9);
    expect(hours).toBeLessThan(24.1);
  });

  it("keeps link plumbing and the encryption choice out of the primary form", () => {
    const root = document.createElement("div"); document.body.append(root);
    mountShareComposer(root, baseOptions());
    const advanced = root.querySelector<HTMLDetailsElement>("details.composer-advanced")!;
    expect(advanced.open).toBe(false);
    expect(advanced.contains(root.querySelector("select[name=format]"))).toBe(true);
    expect(advanced.contains(root.querySelector("input[name=encryption]"))).toBe(true);
    expect(advanced.contains(root.querySelector("input[name=delivery-email]"))).toBe(true);
    expect(advanced.contains(root.querySelector("input[value=emailDomain]"))).toBe(true);
    expect(root.querySelector<HTMLSelectElement>("select[name=format]")!.options[0]!.textContent).toBe("Short link (recommended)");
    // Encryption is a real choice only for a domain share.
    expect(root.querySelector<HTMLElement>(".encryption-group")!.hidden).toBe(true);
    root.querySelector<HTMLInputElement>("input[value=emailDomain]")!.checked = true;
    root.querySelector<HTMLInputElement>("input[value=emailDomain]")!.dispatchEvent(new Event("change", { bubbles: true }));
    expect(root.querySelector<HTMLElement>(".encryption-group")!.hidden).toBe(false);
  });
});

describe("share composer navigation", () => {
  it("offers a way back to the library from the empty composer and from the result", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const onBack = vi.fn();
    mountShareComposer(root, { ...baseOptions(), onBack, loadCapabilities: async () => [], createShare: async ({ model }) => ({ url: "https://share.tinycloud.xyz/s/example", cid: "cid", format: model.linkFormat }) });
    const back = root.querySelector<HTMLButtonElement>("button.composer-back")!;
    expect(back.textContent).toContain("All shares");
    back.click();
    expect(onBack).toHaveBeenCalledTimes(1);

    paste(root.querySelector<HTMLElement>(".content-dropzone")!, { text: "hello" });
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const actions = [...root.querySelectorAll(".result-actions button")].map((button) => button.textContent);
    expect(actions).toEqual(["Copy link", "Share another", "Done"]);
    expect(root.querySelector(".sender-status-detail")?.textContent).not.toContain("return to All shares");
    root.querySelector<HTMLButtonElement>("button.composer-done")!.click();
    expect(onBack).toHaveBeenCalledTimes(2);
  });
});

describe("share composer sender failures", () => {
  it("never renders raw protocol failure text", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const error = new Error("Node policy bytes is invalid: delegation envelope CID mismatch in the KV registry (bearer capability)");
    const debug = vi.spyOn(console, "debug").mockImplementation(() => undefined);
    mountShareComposer(root, { ...baseOptions(), createShare: async () => { throw error; } });

    paste(root.querySelector<HTMLElement>(".content-dropzone")!, { text: "hello" });
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(root.querySelector(".composer-status .sender-status-detail")?.textContent).toBe("Something went wrong creating this link. Nothing was shared. Try again.");
    expect(root.querySelector(".composer-status")?.textContent).not.toMatch(/capabilit|delegat|\bDID\b|\bspace\b|bearer|policy|envelope|\bCID\b|\bKV\b|registry|matcher|attenuat|nonce|\bclaim\b|credential|epoch|invocation|\bnode\b/i);
    expect(debug).toHaveBeenCalledWith("tinycloud share: sender request failed", error);
  });

  it("maps tagged sender failures without rendering their developer detail", async () => {
    const root = document.createElement("div"); document.body.append(root);
    mountShareComposer(root, { ...baseOptions(), createShare: async () => { throw fail("permission", "node action bounds exceeded"); } });

    paste(root.querySelector<HTMLElement>(".content-dropzone")!, { text: "hello" });
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(root.querySelector(".composer-status .sender-status-detail")?.textContent).toBe("You can't grant more access than you have on that file.");
    expect(root.querySelector(".composer-status")?.textContent).not.toContain("node action bounds exceeded");
  });

  it("classifies untagged, link-only, network, and model-validation failures", () => {
    expect(senderFailureMessage(new Error("delegation envelope CID mismatch"))).toBe(SENDER_FAILURE.internal);
    expect(senderFailureMessage(new LinkOnlyShareError("file", "Choose a .txt, .md, or .markdown file."))).toBe("Choose a .txt, .md, or .markdown file.");
    expect(senderFailureMessage(new TypeError("Failed to fetch"))).toBe(SENDER_FAILURE.offline);

    let validationError: unknown;
    try {
      validateComposerModel(modelWith(textContent, {
        recipient: { kind: "emailDomain", value: "example.com" },
        deliveryEmail: "person@other.example",
      }));
    } catch (error) {
      validationError = error;
    }
    expect(senderFailureMessage(validationError)).toBe("The delivery address must belong to the shared domain.");
  });

  it("keeps tagged form validation copy in the composer status", async () => {
    const root = document.createElement("div"); document.body.append(root);
    mountShareComposer(root, baseOptions());
    const domain = root.querySelector<HTMLInputElement>("input[name=recipient][value=emailDomain]")!;
    domain.checked = true;
    domain.dispatchEvent(new Event("change", { bubbles: true }));
    const recipient = root.querySelector<HTMLInputElement>("input[name=recipient-value]")!;
    recipient.value = "example.com";
    recipient.dispatchEvent(new Event("input", { bubbles: true }));
    const delivery = root.querySelector<HTMLInputElement>("input[name=delivery-email]")!;
    delivery.value = "person@other.example";
    delivery.dispatchEvent(new Event("input", { bubbles: true }));
    paste(root.querySelector<HTMLElement>(".content-dropzone")!, { text: "hello" });
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(root.querySelector(".composer-status .sender-status-detail")?.textContent).toContain("must belong to the shared domain");
  });
});
