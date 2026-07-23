import { describe, expect, it, vi } from "vitest";
import { renderRecipientState, type RecipientFacts } from "../../src/email-share/view.js";

function actions() {
  return { onOpen: vi.fn(), onRetry: vi.fn(), onUseOtp: vi.fn(), onOtp: vi.fn(), onResend: vi.fn(), onForget: vi.fn() };
}

const facts = {
  envelope: { display: { senderName: "TinyCloud sender", filename: "plan.md" } },
  share: {
    shareId: "share-id", shareCid: "bafkrei" + "a".repeat(52), policyCid: "b" + "a".repeat(58),
    recipientEmail: "recipient@example.com", recipientHint: "r***@example.com", expiry: "2099-01-01T00:00:00.000Z",
    nodeOrigin: "https://node.example", nodeAudience: "did:web:node.example", requestOrigin: "https://share.tinycloud.xyz",
    delegationCid: "b" + "a".repeat(58), authorityMaterialHandle: "amh_kv_001", authorityMaterialDigest: "A".repeat(43),
    contentSource: { kind: "kv", space: "space", path: "plan.md", action: "tinycloud.kv/get" }, contentSourceDigest: "A".repeat(43),
    action: "tinycloud.kv/get", resource: "plan.md", trustedNode: { targetOrigin: "https://node.example", nodeAudience: "did:web:node.example", invitationKid: "did:web:node.example#invitation-key-1", invitationPublicKey: new Uint8Array(32), keyVersion: 1, enabled: true },
  },
} as unknown as RecipientFacts;

function render(state: Parameters<typeof renderRecipientState>[2]): { root: HTMLElement; callbacks: ReturnType<typeof actions> } {
  const root = document.createElement("div");
  const callbacks = actions();
  renderRecipientState(root, facts, state, callbacks);
  return { root, callbacks };
}

describe("shipping exact-email recipient UI contract", () => {
  it("keeps a verified invitation inert and gives the recipient one explicit action", () => {
    const { root, callbacks } = render({ state: "ready", emailHint: "r***@example.com" });
    const status = root.querySelector<HTMLElement>("[role=status]");
    const open = root.querySelector<HTMLButtonElement>("button.recipient-primary-action");
    const otp = root.querySelector<HTMLButtonElement>("button.recipient-secondary-action");
    expect(status?.getAttribute("aria-live")).toBe("polite");
    expect(status?.getAttribute("aria-atomic")).toBe("true");
    expect(open?.textContent).toBe("Open document");
    expect(otp?.textContent).toBe("Use email code instead");
    expect(root.querySelector(".viewer-content")).toBeNull();
    expect(root.textContent).toContain("does not redeem it");
    expect(root.textContent).not.toMatch(/wallet|openkey|sign in|account/i);
    open?.click(); otp?.click();
    expect(callbacks.onOpen).toHaveBeenCalledTimes(1);
    expect(callbacks.onUseOtp).toHaveBeenCalledTimes(1);
  });

  it("exposes OTP, cooldown semantics, and labelled controls", () => {
    const { root, callbacks } = render({ state: "otp", emailHint: "r***@example.com", message: "Enter the six-digit code from the invitation email.", retryAfterSeconds: 20 });
    const input = root.querySelector<HTMLInputElement>("#recipient-code");
    const form = root.querySelector<HTMLFormElement>("form");
    const resend = root.querySelector<HTMLButtonElement>("button.recipient-secondary-action");
    const cooldown = root.querySelector<HTMLElement>("#recipient-cooldown");
    expect(input?.getAttribute("aria-describedby")).toBe("recipient-cooldown");
    expect(input?.autocomplete).toBe("one-time-code");
    expect(input?.inputMode).toBe("numeric");
    expect(input?.pattern).toBe("[0-9]{6}");
    expect(input?.maxLength).toBe(6);
    expect(resend?.disabled).toBe(true);
    expect(resend?.getAttribute("aria-disabled")).toBe("true");
    expect(cooldown?.getAttribute("aria-live")).toBe("polite");
    input!.value = "042731";
    form!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    expect(callbacks.onOtp).toHaveBeenCalledWith("042731");
  });

  it("makes recovery truthful and keeps terminal states free of document sinks", () => {
    const retry = render({ state: "error", code: "offline", retryable: true });
    expect(retry.root.querySelector("button.recipient-primary-action")?.textContent).toBe("Retry");
    expect(retry.root.querySelector("[role=alert]")?.textContent).toContain("No document bytes were requested");
    retry.root.querySelector<HTMLButtonElement>("button.recipient-primary-action")?.click();
    expect(retry.callbacks.onRetry).toHaveBeenCalledTimes(1);
    for (const state of ["used", "expired", "revoked", "denied"] as const) {
      const { root } = render({ state, message: "Ask the sender for a fresh invitation.", retryable: false });
      expect(root.querySelector(".viewer-content")).toBeNull();
      expect(root.querySelectorAll("button")).toHaveLength(0);
      expect(root.querySelector("[role=alert]")?.textContent).toContain("Ask the sender");
    }
  });

  it("labels the forget action and explains tab-only key lifetime", () => {
    const { root, callbacks } = render({ state: "claimed", claim: { holder: { did: "did:key:z6Mkholder", privateKey: {} as CryptoKey }, credential: "credential", expiresAt: "2099-01-01T00:00:00.000Z", persisted: false } });
    const forget = root.querySelector<HTMLButtonElement>("button.recipient-secondary-action");
    expect(forget?.getAttribute("aria-label")).toBe("Forget the private browser key for this share");
    expect(root.textContent).toContain("stays in this tab");
    forget?.click();
    expect(callbacks.onForget).toHaveBeenCalledTimes(1);
  });
});
