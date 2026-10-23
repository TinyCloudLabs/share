// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  receive: vi.fn(),
  get: vi.fn(),
  clients: 0,
  custody: "persistent" as "persistent" | "memory",
  options: undefined as undefined | { interaction: { mountTarget: HTMLElement }; onProgress?: (event: unknown) => void },
}));

function identity() {
  return { kind: "receiver", holderDid: "did:key:z6MkReceiver", custody: state.custody, origin: "https://share.tinycloud.xyz" };
}

vi.mock("../src/share/receiver.js", () => ({
  createShareReceiverClient: async () => { state.clients += 1; return { share: { receive: (...args: unknown[]) => state.receive(...args) } }; },
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
  state.clients = 0;
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
  const done = receiveWithSdk({ root, shareUrl: "https://share.tinycloud.xyz/s/lqdw5iopqq2tkkvjj6gbbi5vbv#v=4&k=key&c=cid", config, invitation: { filename: "Q3 report.pdf", expiresAt: "2030-01-02T03:04:00Z", actions: ["read"] }, onComplete });
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
  ])("recovers from %s with a fresh acquisition after the resend cooldown", async (code, details, title, action) => {
    vi.useFakeTimers({ toFake: ["setTimeout", "setInterval", "clearInterval", "Date"] });
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

  it("keeps retry disabled for the issuer's Retry-After and counts down in minutes", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "setInterval", "clearInterval", "Date"] });
    try {
      let refusedAt = 0;
      state.get
        .mockImplementationOnce(async () => {
          refusedAt = Date.now();
          throw credentialError("ISSUER_UNREADY", { state: "rate_limited", retryAfterMs: 3_448_000 });
        })
        .mockResolvedValueOnce({ bytes: new Uint8Array([7]) });
      const { root, done, onComplete } = await start();
      await vi.waitFor(() => expect(root.querySelector(".claim-state[role=alert]")).not.toBeNull());
      expect(root.querySelector(".claim-state-detail:not(.claim-cooldown)")?.textContent).toBe("Too many verification codes were requested recently. Nothing was opened.");
      const retry = root.querySelector<HTMLButtonElement>(".claim-state button")!;
      expect(retry.disabled).toBe(true);
      expect(root.querySelector(".claim-cooldown")?.textContent).toBe("You can ask for a new code in 58 minutes.");
      // vi.waitFor advances the fake clock while polling, so each step is set from the recorded refusal time.
      vi.advanceTimersByTime(refusedAt + 3_388_000 - Date.now());
      expect(root.querySelector(".claim-cooldown")?.textContent).toBe("You can ask for a new code in 1 minute.");
      vi.advanceTimersByTime(refusedAt + 3_447_999 - Date.now());
      expect(retry.disabled).toBe(true);
      vi.advanceTimersByTime(refusedAt + 3_448_000 - Date.now());
      expect(retry.disabled).toBe(false);
      expect(root.querySelector(".claim-cooldown")?.textContent).toBe("You can ask for a new code now.");
      retry.click();
      await done;
      expect(onComplete).toHaveBeenCalledWith({ bytes: new Uint8Array([7]) });
    } finally {
      vi.useRealTimers();
    }
  });

  it("measures the issuer's Retry-After from when the refusal arrives, not from the click", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "setInterval", "clearInterval", "Date"] });
    try {
      let refusedAt = 0;
      state.get
        .mockImplementationOnce(async () => {
          vi.advanceTimersByTime(2_000);
          refusedAt = Date.now();
          throw credentialError("ISSUER_UNREADY", { state: "rate_limited", retryAfterMs: 3_448_000 });
        })
        .mockResolvedValueOnce({ bytes: new Uint8Array([7]) });
      const { root, done, onComplete } = await start();
      await vi.waitFor(() => expect(root.querySelector(".claim-state[role=alert]")).not.toBeNull());
      const retry = root.querySelector<HTMLButtonElement>(".claim-state button")!;
      vi.advanceTimersByTime(refusedAt + 3_447_999 - Date.now());
      expect(retry.disabled).toBe(true);
      vi.advanceTimersByTime(refusedAt + 3_448_000 - Date.now());
      expect(retry.disabled).toBe(false);
      retry.click();
      await done;
      expect(onComplete).toHaveBeenCalledWith({ bytes: new Uint8Array([7]) });
    } finally {
      vi.useRealTimers();
    }
  });

  it("waits an hour when the issuer rate-limits without a Retry-After", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "setInterval", "clearInterval", "Date"] });
    try {
      let refusedAt = 0;
      state.get
        .mockImplementationOnce(async () => {
          refusedAt = Date.now();
          throw credentialError("ISSUER_UNREADY", { state: "rate_limited" });
        })
        .mockResolvedValueOnce({ bytes: new Uint8Array([7]) });
      const { root, done, onComplete } = await start();
      await vi.waitFor(() => expect(root.querySelector(".claim-state[role=alert]")).not.toBeNull());
      expect(root.querySelector(".claim-state-detail:not(.claim-cooldown)")?.textContent).toBe("Too many verification codes were requested recently. Nothing was opened.");
      const retry = root.querySelector<HTMLButtonElement>(".claim-state button")!;
      expect(root.querySelector(".claim-cooldown")?.textContent).toBe("You can ask for a new code in 60 minutes.");
      vi.advanceTimersByTime(refusedAt + 3_599_999 - Date.now());
      expect(retry.disabled).toBe(true);
      vi.advanceTimersByTime(refusedAt + 3_600_000 - Date.now());
      expect(retry.disabled).toBe(false);
      retry.click();
      await done;
      expect(onComplete).toHaveBeenCalledWith({ bytes: new Uint8Array([7]) });
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps the rate-limit detail fixed while the live countdown runs", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "setInterval", "clearInterval", "Date"] });
    try {
      let refusedAt = 0;
      state.get
        .mockImplementationOnce(async () => {
          refusedAt = Date.now();
          throw credentialError("ISSUER_UNREADY", { state: "rate_limited", retryAfterMs: 3_448_000 });
        })
        .mockResolvedValueOnce({ bytes: new Uint8Array([7]) });
      const { root, done, onComplete } = await start();
      await vi.waitFor(() => expect(root.querySelector(".claim-state[role=alert]")).not.toBeNull());
      const detail = () => root.querySelector(".claim-state-detail:not(.claim-cooldown)")?.textContent;
      const fixed = "Too many verification codes were requested recently. Nothing was opened.";
      expect(detail()).toBe(fixed);
      expect(root.querySelector(".claim-cooldown")?.textContent).toBe("You can ask for a new code in 58 minutes.");
      vi.advanceTimersByTime(refusedAt + 600_000 - Date.now());
      expect(detail()).toBe(fixed);
      expect(root.querySelector(".claim-cooldown")?.textContent).toBe("You can ask for a new code in 48 minutes.");
      vi.advanceTimersByTime(refusedAt + 3_300_000 - Date.now());
      expect(detail()).toBe(fixed);
      expect(root.querySelector(".claim-cooldown")?.textContent).toBe("You can ask for a new code in 3 minutes.");
      const retry = root.querySelector<HTMLButtonElement>(".claim-state button")!;
      vi.advanceTimersByTime(refusedAt + 3_448_000 - Date.now());
      expect(retry.disabled).toBe(false);
      retry.click();
      await done;
      expect(onComplete).toHaveBeenCalledWith({ bytes: new Uint8Array([7]) });
    } finally {
      vi.useRealTimers();
    }
  });

  it("changes the 30-second cooldown line once, when the retry opens", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "setInterval", "clearInterval", "Date"] });
    try {
      let refusedAt = 0;
      state.get
        .mockImplementationOnce(async () => {
          refusedAt = Date.now();
          throw credentialError("OFFLINE", {});
        })
        .mockResolvedValueOnce({ bytes: new Uint8Array([7]) });
      const { root, done, onComplete } = await start();
      await vi.waitFor(() => expect(root.querySelector(".claim-state[role=alert]")).not.toBeNull());
      const cooldown = root.querySelector<HTMLElement>(".claim-cooldown")!;
      const said: string[] = [cooldown.textContent ?? ""];
      const observer = new MutationObserver(() => {});
      observer.observe(cooldown, { childList: true, characterData: true, subtree: true });
      for (let t = 1000; t <= 30_000; t += 1000) {
        vi.advanceTimersByTime(Math.max(0, refusedAt + t - Date.now()));
        if (observer.takeRecords().length > 0) said.push(cooldown.textContent ?? "");
      }
      observer.disconnect();
      expect(said).toEqual(["You can ask for a new code in 30 seconds.", "You can ask for a new code now."]);
      const retry = root.querySelector<HTMLButtonElement>(".claim-state button")!;
      expect(retry.disabled).toBe(false);
      retry.click();
      await done;
      expect(onComplete).toHaveBeenCalledWith({ bytes: new Uint8Array([7]) });
    } finally {
      vi.useRealTimers();
    }
  });

  it("changes the rate-limit line only when the whole-minute count changes", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "setInterval", "clearInterval", "Date"] });
    try {
      let refusedAt = 0;
      state.get
        .mockImplementationOnce(async () => {
          refusedAt = Date.now();
          throw credentialError("ISSUER_UNREADY", { state: "rate_limited", retryAfterMs: 210_000 });
        })
        .mockResolvedValueOnce({ bytes: new Uint8Array([7]) });
      const { root, done, onComplete } = await start();
      await vi.waitFor(() => expect(root.querySelector(".claim-state[role=alert]")).not.toBeNull());
      const cooldown = root.querySelector<HTMLElement>(".claim-cooldown")!;
      const said: string[] = [cooldown.textContent ?? ""];
      const observer = new MutationObserver(() => {});
      observer.observe(cooldown, { childList: true, characterData: true, subtree: true });
      for (let t = 1000; t <= 210_000; t += 1000) {
        vi.advanceTimersByTime(Math.max(0, refusedAt + t - Date.now()));
        if (observer.takeRecords().length > 0) said.push(cooldown.textContent ?? "");
      }
      observer.disconnect();
      expect(said).toEqual([
        "You can ask for a new code in 4 minutes.",
        "You can ask for a new code in 3 minutes.",
        "You can ask for a new code in 2 minutes.",
        "You can ask for a new code in 1 minute.",
        "You can ask for a new code now.",
      ]);
      const retry = root.querySelector<HTMLButtonElement>(".claim-state button")!;
      expect(retry.disabled).toBe(false);
      retry.click();
      await done;
      expect(onComplete).toHaveBeenCalledWith({ bytes: new Uint8Array([7]) });
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps retry disabled for a Retry-After beyond setTimeout's range, then enables it when the wait ends", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "setInterval", "clearInterval", "Date"] });
    try {
      const thirtyDays = 2_592_000_000;
      let refusedAt = 0;
      state.get
        .mockImplementationOnce(async () => {
          refusedAt = Date.now();
          throw credentialError("ISSUER_UNREADY", { state: "rate_limited", retryAfterMs: thirtyDays });
        })
        .mockResolvedValueOnce({ bytes: new Uint8Array([7]) });
      const { root, done, onComplete } = await start();
      await vi.waitFor(() => expect(root.querySelector(".claim-state[role=alert]")).not.toBeNull());
      const retry = root.querySelector<HTMLButtonElement>(".claim-state button")!;
      expect(retry.disabled).toBe(true);
      vi.advanceTimersByTime(Math.max(0, refusedAt + 25 * 86_400_000 - Date.now()));
      expect(retry.disabled).toBe(true);
      vi.advanceTimersByTime(Math.max(0, refusedAt + thirtyDays - 1 - Date.now()));
      expect(retry.disabled).toBe(true);
      vi.advanceTimersByTime(Math.max(0, refusedAt + thirtyDays - Date.now()));
      expect(retry.disabled).toBe(false);
      retry.click();
      await done;
      expect(onComplete).toHaveBeenCalledWith({ bytes: new Uint8Array([7]) });
    } finally {
      vi.useRealTimers();
    }
  });

  it.each([
    ["CANCELED", {}],
    ["REQUEST_EXPIRED", {}],
    ["VERIFICATION_FAILED", { state: "proof_attempts_exhausted" }],
    ["OFFLINE", {}],
  ])("offers %s's retry at once when the refusal arrives after the resend cooldown", async (code, details) => {
    vi.useFakeTimers({ toFake: ["setTimeout", "setInterval", "clearInterval", "Date"] });
    try {
      state.get
        .mockImplementationOnce(async () => {
          vi.advanceTimersByTime(120_000);
          throw credentialError(code, details);
        })
        .mockResolvedValueOnce({ bytes: new Uint8Array([7]) });
      const { root, done, onComplete } = await start();
      await vi.waitFor(() => expect(root.querySelector(".claim-state[role=alert]")).not.toBeNull());
      const retry = root.querySelector<HTMLButtonElement>(".claim-state button")!;
      expect(root.querySelector(".claim-cooldown")).toBeNull();
      expect(retry.disabled).toBe(false);
      retry.click();
      await done;
      expect(onComplete).toHaveBeenCalledWith({ bytes: new Uint8Array([7]) });
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps the retry disabled until the resend cooldown ends when the refusal arrives inside it", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "setInterval", "clearInterval", "Date"] });
    try {
      let refusedAt = 0;
      state.get
        .mockImplementationOnce(async () => {
          refusedAt = Date.now();
          vi.advanceTimersByTime(10_000);
          throw credentialError("OFFLINE");
        })
        .mockResolvedValueOnce({ bytes: new Uint8Array([7]) });
      const { root, done, onComplete } = await start();
      await vi.waitFor(() => expect(root.querySelector(".claim-state[role=alert]")).not.toBeNull());
      const retry = root.querySelector<HTMLButtonElement>(".claim-state button")!;
      expect(root.querySelector(".claim-cooldown")?.textContent).toBe("You can ask for a new code in 20 seconds.");
      // The cooldown runs from the request, so it ends 30 s after refusedAt, not 30 s after the refusal.
      vi.advanceTimersByTime(refusedAt + 29_999 - Date.now());
      expect(retry.disabled).toBe(true);
      vi.advanceTimersByTime(refusedAt + 30_000 - Date.now());
      expect(retry.disabled).toBe(false);
      retry.click();
      await done;
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

describe("share availability before a code is offered or sent", () => {
  const NODE = "https://tee.node.tinycloud.xyz";
  const availability = { nodeOrigin: NODE, rootCids: ["bafyPolicyRoot", "bafyEnforcementRoot"] };
  const live = { value: "active" as "active" | "revoked", freshUntil: "2030-01-01T00:00:00Z", fail: false };
  const statusFetch = vi.fn(async (input: RequestInfo | URL) => {
    if (live.fail) throw new TypeError("Failed to fetch");
    const rootCid = decodeURIComponent(new URL(String(input)).pathname.split("/").at(-1)!);
    return Response.json({ rootCid, state: live.value, checkpoint: { state: live.value, freshUntil: live.freshUntil } });
  });

  beforeEach(() => {
    live.value = "active";
    live.freshUntil = "2030-01-01T00:00:00Z";
    live.fail = false;
    statusFetch.mockClear();
    vi.stubGlobal("fetch", statusFetch);
    state.get.mockImplementation(() => new Promise(() => undefined));
  });
  afterEach(() => { vi.unstubAllGlobals(); });

  async function begin(extra: { availability?: typeof availability } = { availability }) {
    const { receiveWithSdk } = await import("../src/viewer/sdk-accountless-receiver.js");
    const root = document.getElementById("viewer")!;
    const onComplete = vi.fn(async () => undefined);
    const done = receiveWithSdk({ root, shareUrl: "https://share.tinycloud.xyz/s/lqdw5iopqq2tkkvjj6gbbi5vbv#v=4&k=key&c=cid", config, invitation: { filename: "Q3 report.pdf" }, onComplete, ...extra });
    return { root, done, onComplete };
  }

  it("shows the unavailable screen for a revoked share and never makes a key, offers a button or requests a code", async () => {
    live.value = "revoked";
    const { root, done, onComplete } = await begin();
    await done;
    expect(root.querySelector("h1")?.textContent).toBe("This share is no longer available");
    expect(root.querySelector(".recipient-detail")?.textContent).toBe("The sender may have revoked it, or it has expired.");
    expect(root.querySelector(".recipient-unavailable")?.getAttribute("role")).toBe("alert");
    expect(root.querySelector(".claim-request-code")).toBeNull();
    expect(root.textContent).not.toContain("Verify your email");
    expect(root.textContent).not.toContain("reader@example.com");
    expect(document.activeElement).toBe(root);
    expect(state.clients).toBe(0);
    expect(state.receive).not.toHaveBeenCalled();
    expect(state.get).not.toHaveBeenCalled();
    expect(onComplete).not.toHaveBeenCalled();
  });

  it("says expired for a root whose lifetime is over, without requesting a code", async () => {
    live.freshUntil = "2020-01-01T00:00:00Z";
    const { root, done } = await begin();
    await done;
    expect(root.querySelector("h1")?.textContent).toBe("This share has expired");
    expect(root.querySelector(".claim-request-code")).toBeNull();
    expect(state.get).not.toHaveBeenCalled();
  });

  it.each([
    ["the node is unreachable", () => { live.fail = true; }],
    ["the node knows nothing of the root", () => { statusFetch.mockImplementationOnce(async () => new Response("policy-root-missing", { status: 404 })).mockImplementationOnce(async () => new Response("policy-root-missing", { status: 404 })); }],
    ["the pre-check has no target", () => undefined],
  ])("runs the normal flow unchanged when %s", async (name, arrange) => {
    arrange();
    const { root } = await begin(name === "the pre-check has no target" ? {} : { availability });
    await vi.waitFor(() => expect(root.querySelector(".claim-request-code")).not.toBeNull());
    expect(root.querySelector("h1")?.textContent).toBe("Verify your email to open this file");
    expect(state.get).not.toHaveBeenCalled();
    root.querySelector<HTMLButtonElement>(".claim-request-code")!.click();
    await vi.waitFor(() => expect(state.get).toHaveBeenCalledTimes(1));
  });

  it("checks again after the click, so a share revoked while the page was open sends no code", async () => {
    const { root, done } = await begin();
    await vi.waitFor(() => expect(root.querySelector(".claim-request-code")).not.toBeNull());
    expect(statusFetch).toHaveBeenCalledTimes(2);
    live.value = "revoked";
    root.querySelector<HTMLButtonElement>(".claim-request-code")!.click();
    await done;
    expect(statusFetch).toHaveBeenCalledTimes(4);
    expect(state.get).not.toHaveBeenCalled();
    expect(root.querySelector("h1")?.textContent).toBe("This share is no longer available");
    expect(root.querySelector(".claim-requested")).toBeNull();
  });

  it("checks again before a new code is requested after a recovery", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "setInterval", "clearInterval", "Date"] });
    try {
      state.get.mockRejectedValueOnce(credentialError("REQUEST_EXPIRED"));
      const { root, done } = await begin();
      await vi.waitFor(() => expect(root.querySelector(".claim-request-code")).not.toBeNull());
      root.querySelector<HTMLButtonElement>(".claim-request-code")!.click();
      await vi.waitFor(() => expect(root.querySelector(".claim-state[role=alert]")).not.toBeNull());
      expect(state.get).toHaveBeenCalledTimes(1);
      live.value = "revoked";
      vi.advanceTimersByTime(30_000);
      root.querySelector<HTMLButtonElement>(".claim-state button")!.click();
      await done;
      expect(state.get).toHaveBeenCalledTimes(1);
      expect(root.querySelector("h1")?.textContent).toBe("This share is no longer available");
    } finally {
      vi.useRealTimers();
    }
  });
});
