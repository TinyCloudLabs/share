import type { ShareEnvelope } from "@tinycloud/share-envelope";
import type { ClaimState } from "./claim.js";
import type { VerifiedExactEmailShare } from "./verified-share.js";
import { copyWithFallback } from "../share/link-only.js";

function element<K extends keyof HTMLElementTagNameMap>(doc: Document, tag: K, className: string, text?: string): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag); node.className = className; if (text !== undefined) node.textContent = text; return node;
}

export interface RecipientFacts {
  readonly envelope: ShareEnvelope;
  readonly share: VerifiedExactEmailShare;
  /** Complete launch URL held only in memory; never rendered as text or href. */
  readonly shareUrl?: string;
}

export interface RecipientViewActions {
  readonly onOpen: () => void;
  readonly onRetry: () => void;
  readonly onUseOtp: () => void;
  readonly onOtp: (code: string) => void;
  readonly onResend: () => void;
  readonly onForget: () => void;
}

function formatExpiry(value: string): string {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return "the stated expiry";
  return new Date(time).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function documentName(facts: RecipientFacts): string {
  const name = facts.envelope.display.filename;
  if (typeof name === "string" && name.length > 0) return name;
  return facts.share.resource.split("/").at(-1) ?? "shared document";
}

function recipientCopy(state: ClaimState): { readonly title: string; readonly detail: string; readonly alert: boolean } {
  switch (state.state) {
    case "verifying": return { title: "Verifying invitation", detail: "Checking the signed invitation before anything is claimed.", alert: false };
    case "ready": return { title: "Open this document", detail: "The invitation is verified for this browser. Select Open document to continue; visiting the link alone does not redeem it.", alert: false };
    case "activation": return { title: "Confirming invitation", detail: "The one-use invitation is being activated after your confirmation.", alert: false };
    case "challenge": return { title: "Checking invitation", detail: "The service is checking the invitation scope.", alert: false };
    case "redeeming": return { title: "Verifying email proof", detail: "The browser is establishing a private holder key for this share.", alert: false };
    case "otp": return { title: "Enter the email code", detail: state.message ?? "Enter the six-digit code from the invitation email.", alert: false };
    case "resending": return { title: "Requesting a new code", detail: "The delivery service is processing the resend request.", alert: false };
    case "claimed": return { title: "Claim verified", detail: "The browser is ready to authorize one read of this document. The non-extractable key stays in this tab; reopening requires a fresh invitation.", alert: false };
    case "session": return { title: "Authorizing one read", detail: "The node is checking the holder-bound access session.", alert: false };
    case "reading": return { title: "Reading document", detail: "The signed read is being checked before the document is shown.", alert: false };
    case "forgotten": return { title: "Browser key forgotten", detail: "The private browser key and claim material were removed. Ask the sender for a fresh invitation to start again.", alert: false };
    case "used": return { title: "Invitation already used", detail: state.message, alert: true };
    case "expired": return { title: "Invitation expired", detail: state.message, alert: true };
    case "revoked": return { title: "Invitation unavailable", detail: state.message, alert: true };
    case "denied": return { title: "Access not authorized", detail: state.message, alert: true };
    case "error": {
      const details: Record<string, string> = {
        "unsupported-browser": "This browser cannot create the private key required for a claim. Try a current browser with WebCrypto support.",
        offline: "You appear to be offline. Reconnect, then retry. No document bytes were requested.",
        "capability-unavailable": "The trusted claim service is unavailable. No credential or document request was completed.",
        "delivery-failed": "The invitation service did not accept the request. Retry when the service is available.",
        invalid: "This invitation could not be verified. Ask the sender for a fresh invitation.",
        "missing-secret": "This invitation is incomplete. Ask the sender to resend it.",
      };
      return { title: "We couldn't finish the invitation", detail: details[state.code] ?? (state.retryable ? "The service is temporarily unavailable. Retry when you are connected." : "Ask the sender for a fresh invitation."), alert: true };
    }
  }
}

export function renderRecipientLoading(root: HTMLElement, message = "Verifying invitation…"): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const main = element(doc, "main", "recipient-shell recipient-message");
  main.append(element(doc, "p", "recipient-brand", "TinyCloud sharing"), element(doc, "h1", "recipient-title", message), element(doc, "p", "recipient-detail", "The invitation is checked before any access request can begin."));
  root.append(main);
}

export function renderRecipientInvalid(root: HTMLElement, message: string): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const main = element(doc, "main", "recipient-shell recipient-message recipient-shell-error");
  main.setAttribute("role", "alert");
  main.append(element(doc, "p", "recipient-brand", "TinyCloud sharing"), element(doc, "h1", "recipient-title", "This invitation cannot be opened"), element(doc, "p", "recipient-detail", message));
  root.append(main);
}

export function renderRecipientState(root: HTMLElement, facts: RecipientFacts, state: ClaimState, actions: RecipientViewActions): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const copy = recipientCopy(state);
  const main = element(doc, "main", "recipient-shell");
  const header = element(doc, "header", "recipient-header");
  header.append(element(doc, "p", "recipient-brand", "TinyCloud sharing"), element(doc, "h1", "recipient-title", documentName(facts)), element(doc, "p", "recipient-detail", "A read-only document shared with you."));
  const factsList = element(doc, "dl", "recipient-facts");
  const addFact = (label: string, value: string): void => { factsList.append(element(doc, "dt", "recipient-fact-label", label), element(doc, "dd", "recipient-fact-value", value)); };
  addFact("Shared by", facts.envelope.display.senderName?.trim() || "TinyCloud sender");
  addFact("Shared with", facts.share.recipientHint);
  addFact("Access", "Read-only");
  addFact("Available until", formatExpiry(facts.share.expiry));
  header.append(factsList);
  const status = element(doc, "section", "recipient-status");
  status.setAttribute("role", copy.alert ? "alert" : "status");
  status.setAttribute("aria-live", copy.alert ? "assertive" : "polite");
  status.setAttribute("aria-atomic", "true");
  status.append(element(doc, "h2", "recipient-status-title", copy.title), element(doc, "p", "recipient-status-detail", copy.detail));
  if (state.state === "ready" || state.state === "verifying") {
    const open = element(doc, "button", "recipient-primary-action", "Open document"); open.type = "button"; open.addEventListener("click", actions.onOpen); status.append(open);
    const otp = element(doc, "button", "recipient-secondary-action", "Use email code instead"); otp.type = "button"; otp.addEventListener("click", actions.onUseOtp); status.append(otp);
  }
  if (state.state === "error" && state.retryable) {
    const retry = element(doc, "button", "recipient-primary-action", "Retry"); retry.type = "button"; retry.addEventListener("click", actions.onRetry); status.append(retry);
  }
  if (state.state === "otp") {
    const form = element(doc, "form", "recipient-otp-form") as HTMLFormElement;
    const label = element(doc, "label", "recipient-field-label", "Six-digit code");
    const input = element(doc, "input", "recipient-code") as HTMLInputElement; input.type = "text"; input.inputMode = "numeric"; input.autocomplete = "one-time-code"; input.pattern = "[0-9]{6}"; input.maxLength = 6; input.required = true; input.id = "recipient-code"; input.setAttribute("aria-describedby", "recipient-cooldown"); label.htmlFor = input.id; label.append(input);
    const submit = element(doc, "button", "recipient-primary-action", "Verify code"); submit.type = "submit"; form.append(label, submit); form.addEventListener("submit", (event) => { event.preventDefault(); actions.onOtp(input.value); }); status.append(form);
    const cooldown = element(doc, "p", "recipient-cooldown", state.retryAfterSeconds !== undefined && state.retryAfterSeconds > 0 ? `You can request another code in ${state.retryAfterSeconds} seconds.` : "You can request a new code if it does not arrive."); cooldown.id = "recipient-cooldown"; cooldown.setAttribute("aria-live", "polite"); status.append(cooldown);
    const resend = element(doc, "button", "recipient-secondary-action", "Resend email"); resend.type = "button"; resend.disabled = (state.retryAfterSeconds ?? 0) > 0; resend.setAttribute("aria-disabled", String(resend.disabled)); resend.addEventListener("click", actions.onResend); status.append(resend);
  }
  if (state.state === "claimed" || state.state === "session" || state.state === "reading") {
    const forget = element(doc, "button", "recipient-secondary-action", "Forget this browser key"); forget.type = "button"; forget.setAttribute("aria-label", "Forget the private browser key for this share"); forget.addEventListener("click", actions.onForget); status.append(forget);
  }
  if (facts.shareUrl !== undefined) {
    const copy = element(doc, "button", "recipient-secondary-action", "Copy link"); copy.type = "button";
    copy.setAttribute("aria-describedby", "recipient-copy-status");
    const copyStatus = element(doc, "span", "recipient-copy-status", ""); copyStatus.id = "recipient-copy-status"; copyStatus.setAttribute("role", "status"); copyStatus.setAttribute("aria-live", "polite");
    copy.addEventListener("click", () => { void copyWithFallback(facts.shareUrl!).then(() => { copyStatus.removeAttribute("role"); copyStatus.textContent = "Link copied."; }).catch(() => { copyStatus.setAttribute("role", "alert"); copyStatus.textContent = "Copy failed. Allow clipboard access and try again."; }); });
    status.append(copy, copyStatus);
  }
  main.append(header, status);
  root.append(main);
}

export function appendRecipientForgetAction(root: HTMLElement, onForget: () => void): void {
  root.querySelector("[data-recipient-forget]")?.remove();
  const footer = root.querySelector(".viewer-footer") ?? root;
  const button = element(root.ownerDocument, "button", "recipient-secondary-action") as HTMLButtonElement;
  button.type = "button"; button.dataset.recipientForget = "true"; button.textContent = "Forget this browser key"; button.addEventListener("click", onForget, { once: true }); footer.append(button);
}
