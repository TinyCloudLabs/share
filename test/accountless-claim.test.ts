// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  receive: vi.fn(),
  get: vi.fn(),
  custody: "persistent" as "persistent" | "memory",
  options: undefined as undefined | { interaction: { mountTarget: HTMLElement }; onProgress?: (event: unknown) => void },
}));

function identity() {
  return { kind: "receiver", holderDid: "did:key:z6MkReceiver", custody: state.custody, origin: "https://share.tinycloud.xyz" };
}

vi.mock("../src/share/receiver.js", () => ({
  createShareReceiverClient: async () => ({ share: { receive: (...args: unknown[]) => state.receive(...args) } }),
}));

const config = {
  version: "tinycloud.share/config-v2",
  shareOrigin: "https://share.tinycloud.xyz",
  senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz",
  registryOrigin: "https://registry.tinycloud.xyz",
  credentialsOrigin: "https://credentials.example",
  accountlessReceiverEnabled: true,
} as never;

function credentialError(code: string, details: Record<string, unknown> = {}) {
  return Object.assign(new Error("credential stopped"), { name: "CredentialError", code, details });
}

beforeEach(() => {
  vi.resetModules();
  document.body.innerHTML = '<div id="viewer"></div>';
  state.get.mockReset();
  state.receive.mockReset();
  state.options = undefined;
  state.custody = "persistent";
  state.receive.mockImplementation(async (_url: string, options: typeof state.options) => {
    state.options = options;
    return { identity: identity(), recipient: { kind: "exactEmail", email: "reader@example.com" }, get: (...args: unknown[]) => state.get(...args) };
  });
});

async function start(onComplete = vi.fn(async () => undefined), { requestCode = true } = {}) {
  const { receiveWithSdk } = await import("../src/viewer/sdk-accountless-receiver.js");
  const root = document.getElementById("viewer")!;
  const done = receiveWithSdk({ root, shareUrl: "https://share.tinycloud.xyz/s/inline#v=2&p=test", config, invitation: { filename: "Q3 report.pdf", expiresAt: "2030-01-02T03:04:00Z", actions: ["read"] }, onComplete });
  if (requestCode) {
    await vi.waitFor(() => expect(root.querySelector(".claim-request-code")).not.toBeNull());
    root.querySelector<HTMLButtonElement>(".claim-request-code")!.click();
  }
  return { root, done, onComplete };
}

describe("exact-email claim screen", () => {
  it("requests no code on load and exactly one per click", async () => {
    state.get.mockImplementation(() => new Promise(() => undefined));
    const { root } = await start(undefined, { requestCode: false });
    // The button exists once the claim is waiting for the click; nothing has been requested yet.
    await vi.waitFor(() => expect(root.querySelector(".claim-request-code")).not.toBeNull());
    expect(state.get).not.toHaveBeenCalled();
    const request = root.querySelector<HTMLButtonElement>(".claim-request-code")!;
    expect(request.textContent).toBe("Email me a code");
    expect(request.type).toBe("button");
    expect(document.getElementById(request.getAttribute("aria-describedby")!)?.textContent).toContain("r***@e***.com");
    // Record the status line's text at the moment it is inserted.
    const insertedText: string[] = [];
    const observer = new MutationObserver((records) => {
      for (const record of records) for (const node of record.addedNodes) if (node instanceof HTMLElement && node.matches(".claim-requested")) insertedText.push(node.textContent ?? "");
    });
    observer.observe(root, { childList: true, subtree: true });
    request.focus();
    request.click();
    request.click();
    await vi.waitFor(() => expect(state.get).toHaveBeenCalledTimes(1));
    expect(state.get).toHaveBeenCalledTimes(1);
    const status = root.querySelector<HTMLElement>(".claim-requested[role=status]")!;
    // The clicked button is gone; focus lands on the status line, not the page body.
    expect(document.activeElement).toBe(status);
    await vi.waitFor(() => expect(status.textContent).toBe("Code requested for r***@e***.com. It can take a minute to arrive."));
    observer.disconnect();
    // Screen readers announce a live region's changes, so it is inserted empty.
    expect(insertedText).toEqual([""]);
  });

  it("names the SDK-verified mailbox and signed invitation facts, and mounts the SDK view in the verification slot", async () => {
    let finish!: (value: unknown) => void;
    state.get.mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    const { root, done, onComplete } = await start();
    await vi.waitFor(() => expect(state.get).toHaveBeenCalledTimes(1));

    expect(root.querySelector("h1")?.textContent).toBe("Verify your email to open this file");
    expect(root.querySelector(".claim-mailbox")?.textContent).toBe("reader@example.com");
    const facts = [...root.querySelectorAll(".claim-fact")].map((row) => [row.querySelector("dt")?.textContent, row.querySelector("dd")?.textContent]);
    expect(facts.slice(0, 3)).toEqual([["For", "reader@example.com"], ["File", "Q3 report.pdf"], ["Access", "View"]]);
    expect(root.querySelector("time")?.dateTime).toBe("2030-01-02T03:04:00.000Z");
    expect(root.querySelector(".claim-verify")?.contains(state.options!.interaction.mountTarget)).toBe(true);
    // The mailbox is rendered from the SDK's verified recipient, never from the URL.
    expect(window.location.href).not.toContain("reader");

    state.options!.onProgress?.({ state: "credential-acquisition", status: "completed" });
    expect(root.querySelector(".claim-verify .claim-state-line[role=status]")?.textContent).toBe("Opening the file through the owner’s TinyCloud node…");
    finish({ bytes: new Uint8Array([1]) });
    await done;
    expect(onComplete).toHaveBeenCalledWith({ bytes: new Uint8Array([1]) });
  });

  it.each([
    ["CANCELED", {}, "Verification canceled", "Send a new code"],
    ["REQUEST_EXPIRED", {}, "That code expired", "Send a new code"],
    ["VERIFICATION_FAILED", { state: "proof_attempts_exhausted" }, "Too many incorrect codes", "Send a new code"],
    ["OFFLINE", {}, "Email verification is unavailable", "Try again"],
    ["ISSUER_UNREADY", { state: "rate_limited" }, "Too many codes requested", "Try again"],
  ])("recovers from %s with a fresh acquisition after the resend cooldown", async (code, details, title, action) => {
    vi.useFakeTimers({ toFake: ["setTimeout", "Date"] });
    try {
      state.get.mockRejectedValueOnce(credentialError(code, details)).mockResolvedValueOnce({ bytes: new Uint8Array([7]) });
      const { root, done, onComplete } = await start();
      await vi.waitFor(() => expect(root.querySelector(".claim-state[role=alert]")).not.toBeNull());
      const heading = root.querySelector<HTMLElement>(".claim-state-title")!;
      expect(heading.textContent).toBe(title);
      expect(document.activeElement).toBe(heading);
      const retry = root.querySelector<HTMLButtonElement>(".claim-state button")!;
      expect(retry.textContent).toBe(action);
      expect(retry.disabled).toBe(true);
      expect(root.querySelector(".claim-cooldown")?.textContent).toBe("You can ask for a new code in 30 seconds.");
      retry.click();
      expect(state.get).toHaveBeenCalledTimes(1);
      vi.advanceTimersByTime(30_000);
      expect(retry.disabled).toBe(false);
      retry.click();
      retry.click();
      await done;
      expect(state.get).toHaveBeenCalledTimes(2);
      expect(root.querySelector(".claim-verify")?.contains(state.options!.interaction.mountTarget)).toBe(true);
      expect(onComplete).toHaveBeenCalledWith({ bytes: new Uint8Array([7]) });
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not offer a retry for an invitation or policy failure", async () => {
    state.get.mockRejectedValueOnce(credentialError("REQUEST_SUBSTITUTED"));
    const { done } = await start();
    await expect(done).rejects.toMatchObject({ code: "REQUEST_SUBSTITUTED" });
    state.get.mockRejectedValueOnce(new Error("share invocation rejected (403)"));
    const second = await start();
    await expect(second.done).rejects.toThrow("share invocation rejected (403)");
  });

  it("tells the recipient a reload means verifying again only when the key lives in page memory", async () => {
    state.get.mockImplementation(() => new Promise(() => undefined));
    const persistent = await start(undefined, { requestCode: false });
    await vi.waitFor(() => expect(persistent.root.querySelector(".claim-request-code")).not.toBeNull());
    expect(persistent.root.querySelector(".claim-reload-note")).toBeNull();

    state.custody = "memory";
    const memory = await start(undefined, { requestCode: false });
    await vi.waitFor(() => expect(memory.root.querySelector(".claim-reload-note")).not.toBeNull());
    expect(memory.root.querySelector(".claim-reload-note")?.textContent).toBe("This browser can keep your verification only while this page is open. If you reload or close it, open the link from your email and verify again.");
  });

  it("presents a domain invitation's domain first and the credential-bound mailbox once verified", async () => {
    state.receive.mockImplementationOnce(async (_url: string, options: typeof state.options) => {
      state.options = options;
      return { identity: identity(), recipient: { kind: "emailDomain", domain: "tinycloud.xyz" }, get: (...args: unknown[]) => state.get(...args) };
    });
    let finish!: (value: unknown) => void;
    state.get.mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    // A domain invitation waits for a typed address instead, so it shows no code button.
    const { root, done } = await start(undefined, { requestCode: false });
    await vi.waitFor(() => expect(state.get).toHaveBeenCalledTimes(1));
    expect(root.querySelector(".claim-request-code")).toBeNull();
    expect(root.querySelector(".claim-lede")?.textContent).toBe("This invitation is open to anyone with an email address at @tinycloud.xyz. Confirm an address there to open it — no account needed.");
    expect(root.querySelector(".claim-fact dd")?.textContent).toBe("Anyone at @tinycloud.xyz");
    state.options!.onProgress?.({ state: "credential-acquisition", status: "completed", mailbox: "reader@tinycloud.xyz" });
    expect(root.querySelector(".claim-verified-mailbox")?.textContent).toBe("reader@tinycloud.xyz");
    finish({ bytes: new Uint8Array([1]) });
    await done;
  });

  it("never renders the claim before the SDK has verified the invitation", async () => {
    state.receive.mockRejectedValueOnce(new Error("share credential requirement does not match its policy commitment"));
    const { root, done } = await start(undefined, { requestCode: false });
    await expect(done).rejects.toThrow("policy commitment");
    expect(root.querySelector(".claim")).toBeNull();
  });
});
