import { afterEach, describe, expect, it, vi } from "vitest";
import { mountShareComposer, type ComposerShareResult } from "../src/share/composer.js";
import { APPROVAL_SLOW_AFTER_MS, APPROVAL_SLOW_COPY, APPROVAL_TIMEOUT_AFTER_MS, showApprovalHint } from "../src/share/approval-hint.js";
import { registerWalletApprovalObserver, type ObservedOpenKeyProvider, type OpenKeyShareSession, type ShareTinyCloud } from "../src/share/openkey-session.js";
import { resetWalletApproval, trackWalletApproval } from "../src/share/wallet-approval.js";
import { SENDER_FAILURE } from "../src/share/sender-failure.js";
import { artifactKindOf } from "../src/share/artifact-kind.js";

afterEach(() => { document.body.replaceChildren(); vi.restoreAllMocks(); vi.useRealTimers(); resetWalletApproval(); });

const base = { openKeyAddress: "0x1234567890abcdef", origin: "https://share.tinycloud.xyz", onBack: () => undefined };
const READY: ComposerShareResult = { url: "https://share.tinycloud.xyz/viewer#tc1=opaque", cid: "cid" };

function mount(extra: Partial<Parameters<typeof mountShareComposer>[1]> = {}): HTMLElement {
  const root = document.createElement("div"); document.body.append(root);
  mountShareComposer(root, { ...base, ...extra });
  return root;
}

function drop(root: HTMLElement, file: File): void {
  const event = new Event("drop", { bubbles: true, cancelable: true });
  Object.defineProperty(event, "dataTransfer", { value: { files: [file] } });
  root.querySelector(".content-dropzone")!.dispatchEvent(event);
}

function pickRecipient(root: HTMLElement, kind: string): void {
  const input = root.querySelector<HTMLInputElement>(`input[name=recipient][value="${kind}"]`)!;
  input.checked = true; input.dispatchEvent(new Event("change", { bubbles: true }));
}

const submit = (root: HTMLElement): void => { root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); };
const flush = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));
function deferred<T>(): { readonly promise: Promise<T>; readonly resolve: (value: T) => void; readonly reject: (reason: unknown) => void } {
  let resolve: (value: T) => void = () => undefined; let reject: (reason: unknown) => void = () => undefined;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

describe("TC-1423 composer: Allow re-sharing is shown, not offered", () => {
  it("renders a disabled, unchecked toggle that says it is coming later and explains what that means", () => {
    const root = mount();
    const toggle = root.querySelector<HTMLInputElement>("input[name=reshare]")!;
    expect(toggle.disabled).toBe(true);
    expect(toggle.checked).toBe(false);
    expect(toggle.closest("label")?.textContent).toContain("Allow re-sharing");
    expect(toggle.closest("label")?.textContent).toContain("Coming later");
    expect(root.querySelector(`#${toggle.getAttribute("aria-describedby")}`)?.textContent).toContain("can't pass this on as their own share yet");
    toggle.click();
    expect(toggle.checked).toBe(false);
  });

  it("never lets the toggle reach the share the composer builds", async () => {
    let permissions: readonly string[] = [];
    const root = mount({ createShare: async ({ model }) => { permissions = model.permissions; return READY; } });
    root.querySelector<HTMLElement>(".content-dropzone")!.dispatchEvent(Object.assign(new Event("paste", { bubbles: true, cancelable: true }), { clipboardData: { files: [], getData: () => "hello" } }));
    submit(root); await flush();
    expect(permissions).toEqual(["read"]);
  });
});

describe("TC-1423 composer: expiry says what it does", () => {
  it("offers 24 hours, 7 days and 30 days with 7 days chosen, and states the consequence for the chosen one", () => {
    const root = mount();
    const inputs = Array.from(root.querySelectorAll<HTMLInputElement>("input[name=expiry]"));
    expect(inputs.map((input) => input.value)).toEqual(["24h", "7d", "30d"]);
    expect(inputs.find((input) => input.checked)?.value).toBe("7d");
    const help = root.querySelector(".expiry-help")!;
    expect(help.textContent).toMatch(/^After .+ the link stops working; your stored copy stays in your TinyCloud\./);
    expect(help.textContent).toContain("Revoking the link ends access sooner");
    expect(help.textContent).toContain("keeps their copy");
    const before = help.textContent;
    const day = root.querySelector<HTMLInputElement>("input[name=expiry][value='24h']")!;
    day.checked = true; day.dispatchEvent(new Event("change", { bubbles: true }));
    expect(root.querySelector(".expiry-help")?.textContent).not.toBe(before);
  });

  it("tells the sender when the link actually works until, and what revoking leaves behind, on the result", async () => {
    const root = mount({ createShare: async () => ({ ...READY, expiresAt: "2026-11-03T12:00:00.000Z" }) });
    root.querySelector<HTMLElement>(".content-dropzone")!.dispatchEvent(Object.assign(new Event("paste", { bubbles: true, cancelable: true }), { clipboardData: { files: [], getData: () => "hello" } }));
    submit(root); await flush();
    const detail = root.querySelector(".result-expiry")?.textContent ?? "";
    expect(detail).toMatch(/^Works until /);
    expect(detail).toContain("Revoke it any time from All shares");
    expect(detail).toContain("keeps their copy");
  });
});

describe("TC-1423 composer: artifact files", () => {
  it.each([["page.html", "Artifact · HTML"], ["Page.HTM", "Artifact · HTML"], ["app.jsx", "Artifact · JSX"], ["app.tsx", "Artifact · TSX"]])("badges %s as %s and says what a link recipient gets", (name, label) => {
    const root = mount();
    drop(root, new File(["<p>hi</p>"], name, { type: "" }));
    const badge = root.querySelector<HTMLElement>(".content-chosen-kind")!;
    expect(badge.hidden).toBe(false);
    expect(badge.textContent).toBe(label);
    expect(root.querySelector(".content-chosen-note")?.textContent).toBe("Opens as a page for anyone with the link.");
  });

  it("is honest that named recipients still get a download, and follows the audience choice", () => {
    const root = mount();
    drop(root, new File(["export default () => null"], "app.jsx"));
    pickRecipient(root, "exactEmail");
    expect(root.querySelector(".content-chosen-note")?.textContent).toContain("Named recipients get a download for now");
    pickRecipient(root, "bearer");
    expect(root.querySelector(".content-chosen-note")?.textContent).toBe("Opens as a page for anyone with the link.");
  });

  it("shows no badge for a document, and the picked file reaches the share under its own name", async () => {
    let name = "";
    const root = mount({ createShare: async ({ file }) => { name = file?.name ?? ""; return READY; } });
    drop(root, new File(["# hi"], "notes.md"));
    expect(root.querySelector<HTMLElement>(".content-chosen-kind")!.hidden).toBe(true);
    root.querySelector<HTMLButtonElement>(".content-change")!.click();
    drop(root, new File(["export default () => null"], "chart.tsx"));
    submit(root); await flush();
    expect(name).toBe("chart.tsx");
  });

  it("classifies by extension only", () => {
    expect(artifactKindOf("a.html")).toBe("html");
    expect(artifactKindOf("a.jsx")).toBe("jsx");
    expect(artifactKindOf("a.tsx")).toBe("tsx");
    expect(artifactKindOf("html")).toBeUndefined();
    expect(artifactKindOf("a.html.txt")).toBeUndefined();
    expect(artifactKindOf("a.ts")).toBeUndefined();
  });
});

describe("TC-1583 composer: the OpenKey approval hint", () => {
  const pasteHello = (root: HTMLElement): void => { root.querySelector<HTMLElement>(".content-dropzone")!.dispatchEvent(Object.assign(new Event("paste", { bubbles: true, cancelable: true }), { clipboardData: { files: [], getData: () => "hello" } })); };
  const session = (disconnect: () => void): OpenKeyShareSession => ({ address: "0x1234567890abcdef", openkey: { disconnect } } as unknown as OpenKeyShareSession);

  it("shows one hint while the wallet approval is open, with Cancel, and removes it when the approval closes", async () => {
    const gate = deferred<void>(); const finish = deferred<ComposerShareResult>();
    const disconnect = vi.fn();
    const root = mount({ session: session(disconnect), createShare: async () => { await trackWalletApproval(() => gate.promise); return finish.promise; } });
    pasteHello(root); submit(root); await flush();
    expect(root.querySelectorAll(".sender-approval")).toHaveLength(1);
    expect(root.querySelector(".sender-approval-line")?.textContent).toBe("Approve in the OpenKey window to create your link");
    await vi.waitFor(() => expect(root.querySelector(".sender-announce")?.textContent).toBe("Approve in the OpenKey window to create your link."));
    expect(root.querySelector(".composer-status .sender-approval")).toBeNull();
    root.querySelector<HTMLButtonElement>(".sender-approval-cancel")!.click();
    expect(disconnect).toHaveBeenCalledTimes(1);
    expect(root.querySelector<HTMLButtonElement>(".sender-approval-cancel")!.disabled).toBe(true);
    // The wallet answered; the share is still being finished. The hint must not outlive the approval.
    gate.resolve(); await flush();
    expect(root.querySelector(".sender-approval")).toBeNull();
    finish.resolve(READY); await flush();
    expect(root.querySelector(".composer-status")?.textContent).toContain("Your link is ready");
    expect(root.querySelector(".sender-approval")).toBeNull();
  });

  it("leaves no hint behind when the approval is cancelled, and says nothing was created", async () => {
    const gate = deferred<void>();
    const tinycloud = {} as ShareTinyCloud;
    registerWalletApprovalObserver(tinycloud, { takeFailure: () => "cancelled" } as unknown as ObservedOpenKeyProvider);
    const root = mount({ tinycloud, session: session(() => undefined), createShare: async () => { await trackWalletApproval(() => gate.promise); return READY; } });
    pasteHello(root); submit(root); await flush();
    expect(root.querySelector(".sender-approval")).not.toBeNull();
    gate.reject({ code: "USER_CANCELLED" }); await flush();
    expect(root.querySelector(".sender-approval")).toBeNull();
    expect(root.querySelector(".composer-status")?.textContent).toContain(SENDER_FAILURE.approvalCancelled);
    expect(root.querySelector<HTMLButtonElement>("button[type=submit]")!.disabled).toBe(false);
  });

  it("shows no hint for a create that needs no approval", async () => {
    const root = mount({ createShare: async () => READY });
    pasteHello(root); submit(root); await flush();
    expect(root.querySelector(".sender-approval")).toBeNull();
    expect(root.querySelector(".composer-status")?.textContent).toContain("Your link is ready");
  });
});

describe("TC-1583 approval hint: slow and timeout copy", () => {
  it("adds where the window may be after a while, then says the wait has gone on too long, and disposes cleanly", () => {
    vi.useFakeTimers();
    const parent = document.createElement("div"); document.body.append(parent);
    const hint = showApprovalHint(parent, { text: "Approve it", lineClass: "line", timeoutCopy: "Too long.", onCancel: () => undefined });
    const more = (): HTMLElement => parent.querySelector<HTMLElement>(".sender-approval-more")!;
    expect(more().hidden).toBe(true);
    vi.advanceTimersByTime(APPROVAL_SLOW_AFTER_MS);
    expect(more().hidden).toBe(false);
    expect(more().textContent).toBe(APPROVAL_SLOW_COPY);
    vi.advanceTimersByTime(APPROVAL_TIMEOUT_AFTER_MS - APPROVAL_SLOW_AFTER_MS);
    expect(more().textContent).toBe("Too long.");
    hint.dispose();
    expect(parent.querySelector(".sender-approval")).toBeNull();
  });

  it("does not run its timers after it is disposed", () => {
    vi.useFakeTimers();
    const parent = document.createElement("div"); document.body.append(parent);
    const hint = showApprovalHint(parent, { text: "x", lineClass: "line", timeoutCopy: "late" });
    const more = parent.querySelector<HTMLElement>(".sender-approval-more")!;
    expect(parent.querySelector(".sender-approval-cancel")).toBeNull();
    hint.dispose();
    vi.advanceTimersByTime(APPROVAL_TIMEOUT_AFTER_MS + 1);
    expect(more.textContent).toBe("");
  });
});
