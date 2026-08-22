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
import { canonicalUploadFiles, mountShareComposer, selectedFilePath, type ComposerShareResult } from "../src/share/composer.js";
import { createDevRegistry } from "@tinycloud/share-registry/dev-server";
import { LinkOnlyShareError } from "../src/share/link-only.js";
import { fail, SENDER_FAILURE, senderFailureMessage } from "../src/share/sender-failure.js";

/**
 * The approved sender-facing copy, as LITERALS (TC-305).
 *
 * Assertions below compare against these, never against `SENDER_FAILURE.x`.
 * Reading the expectation out of the table under test makes a copy regression
 * undetectable by construction: rewrite the shipped sentence and the assertion
 * rewrites itself with it. The one test that touches the exported table
 * compares the whole of it to this record, so a deliberate copy change lands in
 * exactly one place and has to be re-approved there.
 */
const EXPECTED_SENDER_COPY = {
  session: "Your session expired. Reload and sign in again.",
  content: "Pick the file you want to share.",
  format: "This share can't be made self-contained. Use the short link instead.",
  account: "Your account isn't set up for sharing yet. Contact support.",
  source: "You don't have access to that file any more. Pick another one.",
  rejected: "We couldn't create that link. Try again, or pick a different file.",
  permission: "You can't grant more access than you have on that file.",
  internal: "Something went wrong creating this link. Nothing was shared. Try again.",
  save: "We couldn't save this link. Nothing was shared. Try again.",
  delivery: "Add the email address this should be sent to.",
  storage: "Your TinyCloud storage isn't ready yet. Reload and try again.",
  filename: "That file name can't be shared. Rename it and try again.",
  folder: "Pick the folder from your library to share it.",
  actions: "Choose at least one thing they can do.",
  upload: "Upload didn't go through. Nothing was shared — try again.",
  libraryCopy: "We couldn't copy that from your library. Try again.",
  libraryOpen: "We couldn't open that folder in your library. Try again.",
  offline: "Couldn't reach TinyCloud. Check your connection and try again.",
  emptyFile: "Choose a non-empty document.",
  fileTooLarge: "Choose a document no larger than 100 MB.",
  recipientDomain: "Enter a valid ASCII email domain.",
  recipientEmail: "Enter one exact email address.",
  recipientUnavailable: "That recipient option isn't available yet. Choose one person or anyone with the link.",
  expiry: "Choose when the link should expire.",
  deliveryRecipient: "The delivery address must match the person you're sharing with.",
  deliveryDomain: "The delivery address must belong to the shared domain.",
  plaintext: "Shares must stay encrypted.",
  acknowledgment: "Tick the box to confirm you understand.",
  linkOnlyActions: "Link-only shares are view-only. Share with a specific person to allow editing.",
  linkOnlyFolder: "To share multiple files or a folder, choose a specific person or company domain. Anyone-with-link shares support one file at a time.",
  folderUnsupported: "Folder sharing is temporarily unavailable. Choose one file to share.",
  signIn: "Sign-in could not be completed. Try again.",
  signInService: "TinyCloud is temporarily unavailable. Try signing in again shortly.",
} as const;

const originalClipboardDescriptor = Object.getOwnPropertyDescriptor(navigator, "clipboard");

afterEach(() => {
  document.body.replaceChildren();
  vi.restoreAllMocks();
  if (originalClipboardDescriptor === undefined) Reflect.deleteProperty(navigator, "clipboard");
  else Object.defineProperty(navigator, "clipboard", originalClipboardDescriptor);
});

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

function dropFiles(target: Element, files: readonly File[]): void {
  const event = new Event("drop", { bubbles: true, cancelable: true });
  Object.defineProperty(event, "dataTransfer", { value: { files } });
  target.dispatchEvent(event);
}

function chooseExpiry(root: HTMLElement, value: string): void {
  const input = root.querySelector<HTMLInputElement>(`input[name=expiry][value="${value}"]`)!;
  input.checked = true;
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

function baseOptions(): { openKeyAddress: string; origin: string; nativeHistoryTarget: { origin: string; nodeAudience: string }; onBack: () => void } {
  return { openKeyAddress: "0x1234567890abcdef", origin: "https://share.tinycloud.xyz", nativeHistoryTarget: { origin: "https://node.tinycloud.xyz", nodeAudience: "did:web:node.tinycloud.xyz" }, onBack: () => undefined };
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
    expect(contentFilename({ kind: "files", files: [file, new File(["notes"], "notes.txt")] })).toBe("2 files");
    expect(contentMediaType({ kind: "files", files: [file, new File(["notes"], "notes.txt")] })).toBe("application/x-tinycloud-folder");
    expect(contentMode({ kind: "files", files: [file, new File(["notes"], "notes.txt")] })).toBe("upload");

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

  it("normalizes domain input independently while refusing unsupported recipient modes", () => {
    expect(normalizeEmailDomain("MAILINATOR.COM")).toBe("mailinator.com");
    expect(emailDomainOf("Alice@mailinator.com")).toBe("mailinator.com");
    expect(() => validateComposerModel(modelWith(textContent, { recipient: { kind: "emailDomain", value: "MAILINATOR.COM" } }))).toThrow("That recipient option isn't available yet");
    expect(() => validateComposerModel(modelWith(textContent, { recipient: { kind: "recipientDid", value: "did:key:z6Mkexample" } }))).toThrow("That recipient option isn't available yet");
  });

  it("preserves the sender's encryption choice for every available recipient mode", () => {
    expect(validateComposerModel(modelWith(textContent, { encryption: false }))).toMatchObject({ encryption: false, recipient: { kind: "bearer" } });
    const library: ComposerContent = { kind: "library", source: { kind: "kv", space: "space-1", path: "docs/readme.md", action: "tinycloud.kv/get" }, resource: { kind: "exact", path: "docs/readme.md" } };
    expect(validateComposerModel(modelWith(library, { resource: library.resource, recipient: { kind: "exactEmail", value: "reader@example.com" }, encryption: false, encryptionAcknowledged: true }))).toMatchObject({ encryption: false, recipient: { kind: "exactEmail", value: "reader@example.com" } });
  });

  it("rejects prefix content until the encrypted shared-key contract exists", () => {
    const library: ComposerContent = { kind: "library", source: { kind: "kv", space: "space-1", path: "docs", action: "tinycloud.kv/get" }, resource: { kind: "prefix", path: "docs" } };
    expect(() => validateComposerModel(modelWith(library, { resource: library.resource, recipient: { kind: "exactEmail", value: "reader@example.com" } }))).toThrow(SENDER_FAILURE.folderUnsupported);
  });

  it("rejects ungranted link-only actions while allowing read", () => {
    expect(() => validateComposerModel(modelWith(textContent, { permissions: ["read", "edit"] }))).toThrow("Link-only shares are view-only. Share with a specific person to allow editing.");
    expect(validateComposerModel(modelWith(textContent, { permissions: ["read"] }))).toMatchObject({ recipient: { kind: "bearer" }, permissions: ["read"] });
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

  it("offers a real paste action that reads clipboard text without opening the file picker", async () => {
    const root = document.createElement("div"); document.body.append(root);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { readText: vi.fn().mockResolvedValue("# Pasted with a click") },
    });
    mountShareComposer(root, baseOptions());
    const fileInput = root.querySelector<HTMLInputElement>("input[name=document]")!;
    const filePicker = vi.spyOn(fileInput, "click");
    const pasteButton = root.querySelector<HTMLButtonElement>(".dropzone-paste")!;

    expect(pasteButton).toMatchObject({ type: "button", textContent: "Paste from clipboard" });
    pasteButton.click();

    await vi.waitFor(() => expect(root.querySelector<HTMLTextAreaElement>("textarea[name=author-content]")!.value).toBe("# Pasted with a click"));
    expect(filePicker).not.toHaveBeenCalled();
    expect(root.querySelector<HTMLElement>(".content-dropzone")!.hidden).toBe(true);
  });

  it("uses a clipboard image as file content when the browser exposes clipboard items", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const image = new Blob([new Uint8Array([137, 80, 78, 71])], { type: "image/png" });
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        read: vi.fn().mockResolvedValue([{
          types: ["image/png"],
          getType: vi.fn().mockResolvedValue(image),
        }]),
      },
    });
    mountShareComposer(root, baseOptions());

    root.querySelector<HTMLButtonElement>(".dropzone-paste")!.click();

    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".content-chosen")!.hidden).toBe(false));
    expect(root.querySelector(".content-chosen-name")?.textContent).toBe("pasted-image.png");
  });

  it("explains the ordinary paste fallback when clipboard access is denied", async () => {
    const root = document.createElement("div"); document.body.append(root);
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { readText: vi.fn().mockRejectedValue(new DOMException("Denied", "NotAllowedError")) },
    });
    mountShareComposer(root, baseOptions());

    root.querySelector<HTMLButtonElement>(".dropzone-paste")!.click();

    const pasteStatus = root.querySelector<HTMLElement>(".dropzone-paste-status")!;
    await vi.waitFor(() => expect(pasteStatus.getAttribute("role")).toBe("alert"));
    expect(pasteStatus.textContent).toContain("Command+V or Ctrl+V");
    expect(root.querySelector<HTMLElement>(".content-dropzone")!.hidden).toBe(false);

    paste(root.querySelector<HTMLElement>(".content-dropzone")!, { text: "ordinary paste still works" });
    expect(root.querySelector<HTMLTextAreaElement>("textarea[name=author-content]")!.value).toBe("ordinary paste still works");
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
    expect(received.model?.resource.kind).toBe("exact");
  });

  it("removes folder controls and rejects multi-file drops before share creation", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const createShare = vi.fn();
    mountShareComposer(root, {
      ...baseOptions(),
      loadCapabilities: async () => [],
      createShare: createShare as never,
    });
    expect(root.querySelector<HTMLInputElement>("input[name=document]")!.multiple).toBe(false);
    expect(root.textContent).not.toContain("Choose folder");
    const files = [
      new File(["alpha"], "alpha.txt", { type: "text/plain" }),
      new File(["beta"], "beta.txt", { type: "text/plain" }),
    ];
    dropFiles(root.querySelector<HTMLElement>(".content-dropzone")!, files);
    await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".composer-status")?.dataset.state).toBe("error-file"));
    expect(createShare).not.toHaveBeenCalled();
    expect(root.querySelector(".composer-status")?.textContent).toContain(SENDER_FAILURE.folderUnsupported);
  });

  it("canonicalizes names and rejects unsafe, duplicate, per-file, and aggregate uploads", () => {
    const composed = "café.txt";
    const decomposed = "cafe\u0301.txt";
    const canonical = canonicalUploadFiles([new File(["a"], decomposed), new File(["b"], "other.txt")]);
    expect(canonical[0]?.name).toBe(composed);
    expect(() => canonicalUploadFiles([new File(["a"], composed), new File(["b"], decomposed)])).toThrow(/overwrite/i);
    expect(() => canonicalUploadFiles([new File(["a"], "../unsafe.txt")])).toThrow(/filename|file name/i);
    expect(() => canonicalUploadFiles([{ name: "huge.bin", size: 100 * 1024 * 1024 + 1, type: "", lastModified: 0 } as File])).toThrow(/100 MB/i);
    expect(() => canonicalUploadFiles([
      { name: "a.bin", size: 60 * 1024 * 1024, type: "", lastModified: 0 } as File,
      { name: "b.bin", size: 60 * 1024 * 1024, type: "", lastModified: 0 } as File,
    ])).toThrow(/100 MB/i);
  });

  it("does not expose folder or multi-file artifact controls", () => {
    const root = document.createElement("div"); document.body.append(root);
    mountShareComposer(root, baseOptions());
    expect(root.querySelector("input[name=artifact-folder]")).toBeNull();
    expect(Array.from(root.querySelectorAll<HTMLButtonElement>(".dropzone-actions button")).map((button) => button.textContent)).toEqual(["Choose file", "Paste from clipboard", "Pick from your library"]);
  });

  it("keeps normalized folder paths stable when submit validation runs a second time", () => {
    const first = new File(["a"], "a.txt");
    const second = new File(["b"], "b.txt");
    Object.defineProperty(first, "webkitRelativePath", { value: "demo/assets/a.txt" });
    Object.defineProperty(second, "webkitRelativePath", { value: "demo/assets/b.txt" });
    const canonical = canonicalUploadFiles([first, second]);
    expect(canonical.map(selectedFilePath)).toEqual(["assets/a.txt", "assets/b.txt"]);
    expect(canonicalUploadFiles(canonical).map(selectedFilePath)).toEqual(["assets/a.txt", "assets/b.txt"]);
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

  it("does not offer a library prefix until folder encryption is supported", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const capability = { capabilityId: "cap-folder", scope: { prefixes: ["docs"] }, source: { kind: "kv" as const, space: "space-1", path: "docs/readme.md", action: "tinycloud.kv/get" as const }, policy: {} as never };
    mountShareComposer(root, { ...baseOptions(), loadCapabilities: async () => [capability] });
    await new Promise((resolve) => setTimeout(resolve, 0));
    root.querySelector<HTMLButtonElement>(".dropzone-library")!.click();
    const options = Array.from(root.querySelector<HTMLSelectElement>("select[name=kv-source]")!.options);
    expect(options.some((option) => option.value === "docs/" || option.dataset.resourceKind === "prefix")).toBe(false);
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
  /**
   * FORM-LEVEL ONLY (TC-305). This injects `createShare`, so the last assertion
   * proves the control reaches `model.expiresAt` — and nothing about the
   * lifetime of the link production actually mints. That is precisely how
   * TC-298 survived: choose 24 hours, get 7 days, suite green. Left in place
   * for the control and copy it checks, renamed so it cannot be mistaken for
   * expiry coverage. The real creation paths are covered without injection by
   * "uses the selected 24-hour expiry in the real link-only creation path"
   * below, and by test/composer-expiry.test.ts for the addressed and
   * owner-policy paths.
   */
  it("offers the expiry control it used to hardcode, states the consequence, and carries the choice into the model", async () => {
    const root = document.createElement("div"); document.body.append(root);
    let selected: ShareComposerModel | undefined;
    mountShareComposer(root, { ...baseOptions(), loadCapabilities: async () => [], createShare: async ({ model }) => { selected = model; return { url: "https://share.tinycloud.xyz/s/example", cid: "cid", format: model.linkFormat }; } });
    const expiryFieldset = root.querySelector<HTMLFieldSetElement>("fieldset.expiry-field")!;
    const expiryInputs = Array.from(expiryFieldset.querySelectorAll<HTMLInputElement>("input[name=expiry]"));
    expect(root.querySelector("select[name=expiry]")).toBeNull();
    expect(expiryFieldset.querySelector("legend")?.textContent).toBe("Link expires");
    expect(expiryInputs.map((input) => input.value)).toEqual(["24h", "7d", "30d"]);
    expect(expiryInputs.filter((input) => input.checked).map((input) => input.value)).toEqual(["7d"]);
    expect(root.querySelector(".composer-note")?.textContent).toContain("can't be revoked early");

    chooseExpiry(root, "24h");
    paste(root.querySelector<HTMLElement>(".content-dropzone")!, { text: "hello" });
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    const hours = (Date.parse(selected!.expiresAt) - Date.now()) / (60 * 60 * 1000);
    expect(hours).toBeGreaterThan(23.9);
    expect(hours).toBeLessThan(24.1);
  });

  it("shows unsupported recipient choices as intentionally unavailable and lets the sender turn encryption off", () => {
    const root = document.createElement("div"); document.body.append(root);
    mountShareComposer(root, baseOptions());
    const recipients = root.querySelector<HTMLFieldSetElement>("fieldset.recipient-section")!;
    const advanced = root.querySelector<HTMLDetailsElement>("details.composer-advanced")!;
    const recipientOptions = Array.from(recipients.querySelectorAll<HTMLInputElement>("input[name=recipient]"));

    expect(recipients.querySelector("legend")?.textContent).toBe("Who can open it");
    expect(recipientOptions.map((input) => input.value)).toEqual(["exactEmail", "emailDomain", "recipientDid", "bearer"]);
    expect(recipientOptions.map((input) => input.closest("label")?.textContent)).toEqual([
      "Only this person — they'll confirm their email to open it",
      "Anyone with an email from this domain — not available yet",
      "Only this OpenKey device — not available yet",
      "Anyone with the link — anyone you send it to can open it",
    ]);
    expect(recipientOptions.map((input) => input.disabled)).toEqual([false, true, true, false]);
    expect(recipientOptions.slice(1, 3).map((input) => input.closest("label")?.getAttribute("aria-disabled"))).toEqual(["true", "true"]);
    expect(advanced.open).toBe(false);
    expect(advanced.contains(root.querySelector("select[name=format]"))).toBe(true);
    const encryption = root.querySelector<HTMLInputElement>("input[name=encryption]")!;
    expect(advanced.contains(encryption)).toBe(false);
    expect(encryption.checked).toBe(true);
    expect(encryption.disabled).toBe(false);
    expect(root.querySelector(".encryption-group")?.textContent).toContain("Encrypt this share");
    encryption.click();
    expect(encryption.checked).toBe(false);
    expect(root.querySelector(".encryption-group")?.textContent).toContain("Encryption is off");
    expect(advanced.contains(root.querySelector("input[name=delivery-email]"))).toBe(true);
    expect(advanced.querySelector("input[name=recipient]")).toBeNull();
    expect(advanced.textContent).not.toContain("Anyone with an email from this domain");
    expect(root.querySelector<HTMLSelectElement>("select[name=format]")!.options[0]!.textContent).toBe("Short link (recommended)");
    expect(root.querySelector<HTMLElement>(".encryption-group")!.hidden).toBe(false);
    expect(root.querySelector<HTMLElement>(".encryption-group")!.hidden).toBe(false);
    expect(encryption.checked).toBe(false);
    expect(encryption.disabled).toBe(false);
  });

  it("submits the unchecked encryption choice without changing who can receive it", async () => {
    const root = document.createElement("div"); document.body.append(root);
    const submitted: ShareComposerModel[] = [];
    mountShareComposer(root, {
      ...baseOptions(),
      createShare: async ({ model }) => { submitted.push(model); return { url: "https://share.tinycloud.xyz/s/plain", cid: "plain", format: model.linkFormat }; },
    });
    const input = root.querySelector<HTMLInputElement>("input[name=document]")!;
    Object.defineProperty(input, "files", { configurable: true, value: [new File(["public"], "public.txt", { type: "text/plain" })] });
    input.dispatchEvent(new Event("change", { bubbles: true }));
    root.querySelector<HTMLInputElement>("input[name=encryption]")!.click();
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await vi.waitFor(() => expect(submitted).toHaveLength(1));
    expect(submitted[0]).toMatchObject({ encryption: false, recipient: { kind: "bearer" } });
  });

  it("does not select or submit unavailable domain and device recipients", () => {
    const root = document.createElement("div"); document.body.append(root);
    mountShareComposer(root, baseOptions());

    const domain = root.querySelector<HTMLInputElement>("fieldset.recipient-section input[name=recipient][value=emailDomain]")!;
    const did = root.querySelector<HTMLInputElement>("fieldset.recipient-section input[name=recipient][value=recipientDid]")!;
    domain.closest<HTMLLabelElement>("label")!.click();
    did.closest<HTMLLabelElement>("label")!.click();

    expect(domain.checked).toBe(false);
    expect(did.checked).toBe(false);
    expect(root.querySelector<HTMLInputElement>('input[name="recipient"]:checked')?.value).toBe("bearer");
    expect(root.querySelector<HTMLInputElement>("input[name=recipient-value]")!.hidden).toBe(true);
  });

  it("removes manual folder browsing and restores edit controls for a person", () => {
    const root = document.createElement("div"); document.body.append(root);
    mountShareComposer(root, baseOptions());
    const read = root.querySelector<HTMLInputElement>("input[name=permission][value=read]")!;
    const edit = root.querySelector<HTMLInputElement>("input[name=permission][value=edit]")!;
    const editRow = edit.closest<HTMLLabelElement>("label")!;
    const hint = root.querySelector<HTMLElement>(".composer-access-hint")!;

    expect(read).toMatchObject({ checked: true, disabled: true });
    expect(root.querySelector("input[name=permission][value=list]")).toBeNull();
    expect(root.textContent).not.toContain("Can browse the folder");
    expect(edit).toMatchObject({ checked: false });
    expect(editRow.hidden).toBe(true);
    expect(hint.hidden).toBe(false);

    const person = root.querySelector<HTMLInputElement>("input[name=recipient][value=exactEmail]")!;
    person.checked = true;
    person.dispatchEvent(new Event("change", { bubbles: true }));

    expect(read.disabled).toBe(false);
    expect(editRow.hidden).toBe(false);
    expect(hint.hidden).toBe(true);
  });

  it("persists only read for a plain link-only submit", async () => {
    const root = document.createElement("div"); document.body.append(root);
    let persisted: ShareComposerModel | undefined;
    mountShareComposer(root, {
      ...baseOptions(),
      loadCapabilities: async () => [],
      createShare: async ({ model }) => ({ url: "https://share.tinycloud.xyz/s/example", cid: "cid", format: model.linkFormat }),
      persistShare: async ({ model }) => { persisted = model; },
    });
    const input = root.querySelector<HTMLInputElement>("input[name=document]")!;
    Object.defineProperty(input, "files", {
      configurable: true,
      value: [new File(["read only"], "read.txt", { type: "text/plain" })],
    });
    input.dispatchEvent(new Event("change", { bubbles: true }));
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(persisted).toBeDefined());
    expect(persisted!.permissions).toEqual(["read"]);
  });

  it("uses the selected 24-hour expiry in the real link-only creation path", async () => {
    const fixed = Date.parse("2030-07-27T00:00:00.000Z");
    const expectedExpiry = new Date(fixed + 24 * 60 * 60 * 1000).toISOString();
    vi.spyOn(Date, "now").mockReturnValue(fixed);

    const puts = vi.fn(async () => ({ ok: true }));
    const generate = vi.fn(async () => ({ ok: true as const, data: { token: "delegation", delegation: { cid: "bafy-native-delegation" }, expiresAt: new Date(expectedExpiry) } }));

    const root = document.createElement("div");
    document.body.append(root);
    let captured: { readonly share: ComposerShareResult; readonly model: ShareComposerModel } | undefined;
    mountShareComposer(root, {
      ...baseOptions(),
      now: () => fixed,
      tinycloud: { spaceId: "tinycloud:pkh:eip155:1:0xabc:applications", kvForSpace: () => ({ put: puts }), sharing: { generate, receive: vi.fn() } } as never,
      loadCapabilities: async () => [],
      persistShare: async ({ share, model }) => { captured = { share, model }; },
    });

    const input = root.querySelector<HTMLInputElement>("input[name=document]")!;
    Object.defineProperty(input, "files", {
      configurable: true,
      value: [new File(["selected expiry"], "expiry.txt", { type: "text/plain" })],
    });
    input.dispatchEvent(new Event("change", { bubbles: true }));
    chooseExpiry(root, "24h");
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(captured).toBeDefined(), { timeout: 5_000 });
    expect(captured!.model.expiresAt).toBe(expectedExpiry);
    expect(captured!.share.expiresAt).toBe(expectedExpiry);
    expect(puts).toHaveBeenCalledOnce();
    expect(generate).toHaveBeenCalledWith(expect.objectContaining({ actions: ["tinycloud.kv/get"], expiry: new Date(expectedExpiry) }));
    expect(captured!.share.url).toBe("https://share.tinycloud.xyz/viewer#tc1=delegation");
    expect(captured!.share.record).toMatchObject({ enforcementDelegationCid: "bafy-native-delegation", target: { origin: "https://node.tinycloud.xyz", nodeAudience: "did:web:node.tinycloud.xyz", spaceId: "tinycloud:pkh:eip155:1:0xabc:applications" }, resource: { kind: "exact" }, actions: ["tinycloud.kv/get"], recipientMatcher: { kind: "bearer" }, expiresAt: expectedExpiry, filename: "expiry.txt" });
  });

  it("publishes a non-UTF-8 file through the real link-only creation path", async () => {
    const puts = vi.fn(async (_path: string, bytes: Uint8Array) => ({ ok: true, bytes }));

    const root = document.createElement("div");
    document.body.append(root);
    let captured: { readonly share: ComposerShareResult; readonly model: ShareComposerModel } | undefined;
    mountShareComposer(root, {
      ...baseOptions(),
      tinycloud: { spaceId: "tinycloud:pkh:eip155:1:0xabc:applications", kvForSpace: () => ({ put: puts }), sharing: { generate: async () => ({ ok: true as const, data: { token: "delegation", delegation: { cid: "bafy-native-delegation" }, expiresAt: new Date("2030-01-01T00:00:00.000Z") } }), receive: vi.fn() } } as never,
      loadCapabilities: async () => [],
      persistShare: async ({ share, model }) => { captured = { share, model }; },
    });

    const input = root.querySelector<HTMLInputElement>("input[name=document]")!;
    Object.defineProperty(input, "files", {
      configurable: true,
      value: [new File([new Uint8Array([0, 255, 1])], "proof.bin", { type: "application/octet-stream" })],
    });
    input.dispatchEvent(new Event("change", { bubbles: true }));
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(captured).toBeDefined(), { timeout: 5_000 });
    expect(captured!.model.content).toMatchObject({ kind: "file" });
    expect(puts).toHaveBeenCalledWith(expect.any(String), new Uint8Array([0, 255, 1]), { contentType: "application/octet-stream" });
    expect(captured!.share.url).toBe("https://share.tinycloud.xyz/viewer#tc1=delegation");
  });

  it("a link-only share never persists an ungranted action", async () => {
    const registry = createDevRegistry();
    const authenticatedRegistryFetch: typeof fetch = async (input, init) => {
      const url = new URL(String(input));
      const body = new Uint8Array(await new Response(init?.body).arrayBuffer());
      const target = new URL(
        url.pathname.replace("/api/share/link-only/registry", ""),
        "http://registry.local",
      );
      return registry.handler(new Request(target, {
        ...init,
        body,
        duplex: "half",
      } as RequestInit));
    };

    const root = document.createElement("div");
    document.body.append(root);
    const persisted: Array<{ readonly share: ComposerShareResult; readonly model: ShareComposerModel }> = [];
    mountShareComposer(root, {
      ...baseOptions(),
      fetchFn: authenticatedRegistryFetch,
      loadCapabilities: async () => [],
      persistShare: async ({ share, model }) => { persisted.push({ share, model }); },
    });

    const input = root.querySelector<HTMLInputElement>("input[name=document]")!;
    Object.defineProperty(input, "files", {
      configurable: true,
      value: [new File(["hostile permission"], "hostile.txt", { type: "text/plain" })],
    });
    input.dispatchEvent(new Event("change", { bubbles: true }));
    root.querySelector<HTMLInputElement>("input[name=permission][value=edit]")!.checked = true;
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    await vi.waitFor(() => expect(persisted.length > 0 || root.querySelector<HTMLElement>(".composer-status")?.dataset.state === "error-invalid").toBe(true));
    expect(persisted.some(({ model }) => model.permissions.includes("edit"))).toBe(false);
    // The guard must reach the sender as its own actionable copy. It is the one
    // validateComposerModel throw that the sender-failure table could silently
    // swallow into the generic "internal" message if it were left untagged.
    expect(root.querySelector(".composer-status .sender-status-detail")?.textContent).toBe(EXPECTED_SENDER_COPY.linkOnlyActions);
    expect(root.querySelector(".composer-status .sender-status-detail")?.textContent).not.toBe(EXPECTED_SENDER_COPY.internal);
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
    expect(senderFailureMessage(new Error("delegation envelope CID mismatch"))).toBe(EXPECTED_SENDER_COPY.internal);
    expect(senderFailureMessage(new LinkOnlyShareError("file", "Choose a .txt, .md, or .markdown file."))).toBe("Choose a .txt, .md, or .markdown file.");
    expect(senderFailureMessage(new TypeError("Failed to fetch"))).toBe(EXPECTED_SENDER_COPY.offline);

    let validationError: unknown;
    try {
      validateComposerModel(modelWith(textContent, {
        recipient: { kind: "emailDomain", value: "example.com" },
        deliveryEmail: "person@other.example",
      }));
    } catch (error) {
      validationError = error;
    }
    expect(senderFailureMessage(validationError)).toBe("That recipient option isn't available yet. Choose one person or anyone with the link.");
  });

  /**
   * The one place the shipped table is compared to the approved copy (TC-305).
   * Every other assertion in this file uses the literals, so a copy edit — or a
   * new failure kind appearing with unswept protocol vocabulary in it — lands
   * here and has to be made deliberately.
   */
  it("ships exactly the approved sender copy, and no string a sender can read carries protocol vocabulary", () => {
    expect(SENDER_FAILURE).toEqual(EXPECTED_SENDER_COPY);
    for (const message of Object.values(EXPECTED_SENDER_COPY)) {
      expect(message).not.toMatch(/capabilit|delegat|\bDID\b|bearer|policy|envelope|\bCID\b|\bKV\b|registry|matcher|attenuat|nonce|credential|invocation/i);
    }
  });

  it("keeps unavailable-recipient validation copy in the composer status", async () => {
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

    expect(root.querySelector(".composer-status .sender-status-detail")?.textContent).toBe("That recipient option isn't available yet. Choose one person or anyone with the link.");
  });
});

/**
 * TC-334. The clipboard-denied fallback must not put the complete share URL in
 * the DOM: §6.3 of the UX critique forbids rendering it "as text, an `<a
 * href>`, or any DOM attribute", and TC-297 already removed exactly this
 * exposure from `copyWithFallback`.
 */
describe("share composer clipboard-denied fallback (TC-334)", () => {
  const SHARE_URL = "https://share.tinycloud.xyz/s/bafyexample#k=SECRET-KEY-MATERIAL";

  /** Every way a string can be read back out of the live tree. */
  function exposures(root: HTMLElement, value: string): readonly string[] {
    const found: string[] = [];
    for (const node of [root, ...root.querySelectorAll<HTMLElement>("*")]) {
      if ((node.textContent ?? "").includes(value)) found.push(`${node.nodeName}.textContent`);
      for (const attribute of Array.from(node.attributes ?? [])) {
        if (attribute.value.includes(value)) found.push(`${node.nodeName}[${attribute.name}]`);
      }
      const fieldValue = (node as Partial<HTMLInputElement>).value;
      if (typeof fieldValue === "string" && fieldValue.includes(value)) found.push(`${node.nodeName}.value`);
    }
    return found;
  }

  async function denyClipboard(): Promise<HTMLElement> {
    const root = document.createElement("div"); document.body.append(root);
    mountShareComposer(root, {
      ...baseOptions(),
      loadCapabilities: async () => [],
      createShare: async ({ model }) => ({ url: SHARE_URL, cid: "bafyexample", format: model.linkFormat }),
      copyText: async () => { throw new Error("clipboard unavailable"); },
    });
    paste(root.querySelector<HTMLElement>(".content-dropzone")!, { text: "hello" });
    root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    root.querySelector<HTMLButtonElement>(".result-actions .button-primary")!.click();
    await new Promise((resolve) => setTimeout(resolve, 0));
    return root;
  }

  it("never writes the complete share URL into the DOM when the clipboard is denied", async () => {
    const root = await denyClipboard();
    expect(root.querySelector(".manual-copy-field")).not.toBeNull();
    expect(exposures(root, SHARE_URL)).toEqual([]);
    expect(exposures(document.body, SHARE_URL)).toEqual([]);
  });

  it("still lets the sender copy with their own keystroke, substituting the URL in the copy event", async () => {
    const root = await denyClipboard();
    const target = root.querySelector<HTMLElement>(".manual-copy-target")!;
    expect(target.textContent).not.toContain("tinycloud");

    const selection = document.getSelection()!;
    const range = document.createRange();
    range.selectNodeContents(target);
    selection.removeAllRanges();
    selection.addRange(range);

    let payload: string | undefined;
    const event = new Event("copy", { bubbles: true, cancelable: true });
    Object.defineProperty(event, "clipboardData", { value: { setData: (_type: string, data: string) => { payload = data; } } });
    document.dispatchEvent(event);

    expect(payload).toBe(SHARE_URL);
    expect(event.defaultPrevented).toBe(true);
    expect(root.querySelector(".copy-status")?.textContent).toBe("Link copied.");
  });

  it("does not hijack an unrelated copy elsewhere on the page", async () => {
    const root = await denyClipboard();
    const elsewhere = document.createElement("p"); elsewhere.textContent = "unrelated"; document.body.append(elsewhere);
    const selection = document.getSelection()!;
    const range = document.createRange();
    range.selectNodeContents(elsewhere);
    selection.removeAllRanges();
    selection.addRange(range);

    let payload: string | undefined;
    const event = new Event("copy", { bubbles: true, cancelable: true });
    Object.defineProperty(event, "clipboardData", { value: { setData: (_type: string, data: string) => { payload = data; } } });
    document.dispatchEvent(event);

    expect(payload).toBeUndefined();
    expect(event.defaultPrevented).toBe(false);
  });

  it("disarms the interception once the sender dismisses the affordance", async () => {
    const root = await denyClipboard();
    const target = root.querySelector<HTMLElement>(".manual-copy-target")!;
    const selection = document.getSelection()!;
    const range = document.createRange();
    range.selectNodeContents(target);
    selection.removeAllRanges();
    selection.addRange(range);

    root.querySelector<HTMLButtonElement>(".manual-copy-field .button-secondary")!.click();
    expect(root.querySelector(".manual-copy-field")).toBeNull();

    let payload: string | undefined;
    const event = new Event("copy", { bubbles: true, cancelable: true });
    Object.defineProperty(event, "clipboardData", { value: { setData: (_type: string, data: string) => { payload = data; } } });
    document.dispatchEvent(event);
    expect(payload).toBeUndefined();
  });
});
