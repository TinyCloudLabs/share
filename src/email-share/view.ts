import type { ShareEnvelope } from "@tinycloud/share-envelope";
import type { ClaimState } from "./claim.js";
import type { VerifiedExactEmailShare } from "./verified-share.js";
import { copyWithFallback } from "../share/link-only.js";
import { focusViewerRoot } from "../viewer/focus.js";

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

interface Mounted {
  readonly main: HTMLElement;
  readonly statusSection: HTMLElement;
  readonly liveRegion: HTMLElement;
  readonly title: HTMLElement;
  readonly detail: HTMLElement;
  readonly actionsHost: HTMLElement;
  lastState: ClaimState["state"];
}

const mountedRecipientViews = new WeakMap<HTMLElement, Mounted>();

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

function recipientCopy(state: ClaimState, senderName: string): { readonly title: string; readonly detail: string; readonly alert: boolean } {
  switch (state.state) {
    case "verifying": return { title: "Checking this link…", detail: "", alert: false };
    case "ready": return { title: "Open this document", detail: `${senderName} shared this with you.`, alert: false };
    case "activation": return { title: "Confirming your email…", detail: "", alert: false };
    case "challenge": return { title: "Checking…", detail: "", alert: false };
    case "redeeming": return { title: "Confirming your email…", detail: "", alert: false };
    case "otp": return { title: "Enter the email code", detail: state.message ?? "Enter the six-digit code from the invitation email.", alert: false };
    case "resending": return { title: "Requesting a new code", detail: "The delivery service is processing the resend request.", alert: false };
    case "claimed": return { title: "Verified", detail: "Opening your document…", alert: false };
    case "session": return { title: "Opening…", detail: "", alert: false };
    case "reading": return { title: "Opening…", detail: "", alert: false };
    case "forgotten": return { title: "Signed out of this share", detail: "Open the original link again to get back in.", alert: false };
    case "used": return { title: "Invitation already used", detail: state.message, alert: true };
    case "expired": return { title: "Invitation expired", detail: state.message, alert: true };
    case "revoked": return { title: "Invitation unavailable", detail: state.message, alert: true };
    case "denied": return { title: "Access not authorized", detail: state.message, alert: true };
    case "error": {
      const details: Record<string, string> = {
        "unsupported-browser": "This browser is too old to open secure shares. Try a current version of Chrome, Safari, Edge, or Firefox.",
        offline: "You appear to be offline. Reconnect, then retry. No document bytes were requested.",
        "capability-unavailable": "TinyCloud is temporarily unavailable. Nothing was opened — try again shortly.",
        "delivery-failed": "The invitation service did not accept the request. Retry when the service is available.",
        invalid: "This invitation could not be verified. Ask the sender for a fresh invitation.",
        "missing-secret": "This invitation is incomplete. Ask the sender to resend it.",
      };
      return { title: "We couldn't finish the invitation", detail: details[state.code] ?? (state.retryable ? "The service is temporarily unavailable. Retry when you are connected." : "Ask the sender for a fresh invitation."), alert: true };
    }
  }
}

export function renderRecipientLoading(root: HTMLElement, message = "Checking this link…"): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const main = element(doc, "main", "recipient-shell recipient-message");
  main.append(element(doc, "p", "recipient-brand", "TinyCloud sharing"), element(doc, "h1", "recipient-title", message));
  root.append(main);
}

export function renderRecipientInvalid(root: HTMLElement, message: string): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const main = element(doc, "main", "recipient-shell recipient-message recipient-shell-error");
  main.setAttribute("role", "alert");
  main.append(element(doc, "p", "recipient-brand", "TinyCloud sharing"), element(doc, "h1", "recipient-title", "This invitation cannot be opened"), element(doc, "p", "recipient-detail", message));
  root.append(main);
  focusViewerRoot(root);
}

function cooldownCopy(state: Extract<ClaimState, { readonly state: "otp" }>): string {
  return state.retryAfterSeconds !== undefined && state.retryAfterSeconds > 0
    ? `You can request another code in ${state.retryAfterSeconds} seconds.`
    : "You can request a new code if it does not arrive.";
}

function buildActions(doc: Document, facts: RecipientFacts, state: ClaimState, actions: RecipientViewActions): DocumentFragment {
  const fragment = doc.createDocumentFragment();
  if (state.state === "ready" || state.state === "verifying") {
    const open = element(doc, "button", "recipient-primary-action", "Open document"); open.type = "button"; open.addEventListener("click", actions.onOpen); fragment.append(open);
    const otp = element(doc, "button", "recipient-secondary-action", "Use email code instead"); otp.type = "button"; otp.addEventListener("click", actions.onUseOtp); fragment.append(otp);
  }
  if (state.state === "error" && state.retryable) {
    const retry = element(doc, "button", "recipient-primary-action", "Retry"); retry.type = "button"; retry.addEventListener("click", actions.onRetry); fragment.append(retry);
  }
  if (state.state === "otp") {
    const form = element(doc, "form", "recipient-otp-form") as HTMLFormElement;
    const label = element(doc, "label", "recipient-field-label", "Six-digit code");
    const input = element(doc, "input", "recipient-code") as HTMLInputElement; input.type = "text"; input.inputMode = "numeric"; input.autocomplete = "one-time-code"; input.pattern = "[0-9]{6}"; input.maxLength = 6; input.required = true; input.id = "recipient-code"; input.setAttribute("aria-describedby", "recipient-cooldown"); label.htmlFor = input.id; label.append(input);
    const submit = element(doc, "button", "recipient-primary-action", "Verify code"); submit.type = "submit"; form.append(label, submit); form.addEventListener("submit", (event) => { event.preventDefault(); actions.onOtp(input.value); }); fragment.append(form);
    const cooldown = element(doc, "p", "recipient-cooldown", cooldownCopy(state)); cooldown.id = "recipient-cooldown"; cooldown.setAttribute("aria-live", "polite"); fragment.append(cooldown);
    const resend = element(doc, "button", "recipient-secondary-action", "Resend email"); resend.type = "button"; resend.disabled = (state.retryAfterSeconds ?? 0) > 0; resend.setAttribute("aria-disabled", String(resend.disabled)); resend.addEventListener("click", actions.onResend); fragment.append(resend);
  }
  if (state.state === "claimed" || state.state === "session" || state.state === "reading") {
    const forget = element(doc, "button", "recipient-secondary-action", "Sign out of this share"); forget.type = "button"; forget.addEventListener("click", actions.onForget); fragment.append(forget);
  }
  if (facts.shareUrl !== undefined) {
    const shareUrl = facts.shareUrl;
    const copy = element(doc, "button", "recipient-secondary-action", "Copy link"); copy.type = "button";
    copy.setAttribute("aria-describedby", "recipient-copy-status");
    const copyStatus = element(doc, "span", "recipient-copy-status", ""); copyStatus.id = "recipient-copy-status"; copyStatus.setAttribute("role", "status"); copyStatus.setAttribute("aria-live", "polite");
    copy.addEventListener("click", () => { void copyWithFallback(shareUrl).then(() => { copyStatus.removeAttribute("role"); copyStatus.textContent = "Link copied."; }).catch(() => { copyStatus.setAttribute("role", "alert"); copyStatus.textContent = "Copy failed. Allow clipboard access and try again."; }); });
    fragment.append(copy, copyStatus);
  }
  return fragment;
}

function updateLiveRegion(mounted: Mounted, copy: ReturnType<typeof recipientCopy>): void {
  mounted.liveRegion.setAttribute("role", copy.alert ? "alert" : "status");
  mounted.liveRegion.setAttribute("aria-live", copy.alert ? "assertive" : "polite");
  mounted.statusSection.classList.toggle("recipient-status-alert", copy.alert);
}

function updateStatusCopy(mounted: Mounted, copy: ReturnType<typeof recipientCopy>): void {
  if (mounted.title.textContent !== copy.title) mounted.title.textContent = copy.title;
  if (mounted.detail.textContent !== copy.detail) mounted.detail.textContent = copy.detail;
  const detailHidden = copy.detail === "";
  if (mounted.detail.hidden !== detailHidden) mounted.detail.hidden = detailHidden;
}

function updateOtpControls(actionsHost: HTMLElement, state: Extract<ClaimState, { readonly state: "otp" }>): void {
  const cooldown = actionsHost.querySelector<HTMLElement>("#recipient-cooldown");
  const cooldownText = cooldownCopy(state);
  if (cooldown?.textContent !== cooldownText) cooldown!.textContent = cooldownText;
  const resend = actionsHost.querySelector<HTMLButtonElement>("button.recipient-secondary-action");
  if (resend !== null) {
    const disabled = (state.retryAfterSeconds ?? 0) > 0;
    if (resend.disabled !== disabled) resend.disabled = disabled;
    if (resend.getAttribute("aria-disabled") !== String(disabled)) resend.setAttribute("aria-disabled", String(disabled));
  }
}

export function renderRecipientState(root: HTMLElement, facts: RecipientFacts, state: ClaimState, actions: RecipientViewActions): void {
  const senderName = facts.envelope.display.senderName?.trim() || "Someone";
  const copy = recipientCopy(state, senderName);
  let mounted = mountedRecipientViews.get(root);

  if (mounted === undefined || mounted.main.parentNode !== root) {
    const doc = root.ownerDocument;
    const main = element(doc, "main", "recipient-shell");
    const header = element(doc, "header", "recipient-header");
    header.append(element(doc, "p", "recipient-brand", "TinyCloud sharing"), element(doc, "h1", "recipient-title", documentName(facts)), element(doc, "p", "recipient-detail", "A read-only document shared with you."));
    const factsList = element(doc, "dl", "recipient-facts");
    const addFact = (label: string, value: string): void => { factsList.append(element(doc, "dt", "recipient-fact-label", label), element(doc, "dd", "recipient-fact-value", value)); };
    addFact("Shared by", senderName);
    addFact("Shared with", facts.share.recipientHint);
    addFact("Access", "Read-only");
    addFact("Available until", formatExpiry(facts.share.expiry));
    header.append(factsList);
    const statusSection = element(doc, "section", "recipient-status");
    const liveRegion = element(doc, "div", "recipient-status-live");
    liveRegion.setAttribute("aria-atomic", "true");
    const title = element(doc, "h2", "recipient-status-title", copy.title);
    const detail = element(doc, "p", "recipient-status-detail", copy.detail);
    detail.hidden = copy.detail === "";
    liveRegion.append(title, detail);
    const actionsHost = element(doc, "div", "recipient-actions");
    actionsHost.append(buildActions(doc, facts, state, actions));
    statusSection.append(liveRegion, actionsHost);
    main.append(header, statusSection);
    root.replaceChildren(main);
    mounted = { main, statusSection, liveRegion, title, detail, actionsHost, lastState: state.state };
    mountedRecipientViews.set(root, mounted);
    updateLiveRegion(mounted, copy);
    updateStatusCopy(mounted, copy);
    focusViewerRoot(root);
    return;
  }

  if (mounted.lastState !== state.state) {
    mounted.actionsHost.replaceChildren(buildActions(root.ownerDocument, facts, state, actions));
    updateLiveRegion(mounted, copy);
    updateStatusCopy(mounted, copy);
    mounted.lastState = state.state;
    focusViewerRoot(root);
    return;
  }

  updateStatusCopy(mounted, copy);
  if (state.state === "otp") updateOtpControls(mounted.actionsHost, state);
}

export function appendRecipientForgetAction(root: HTMLElement, onForget: () => void): void {
  root.querySelector("[data-recipient-forget]")?.remove();
  const footer = root.querySelector(".viewer-footer") ?? root;
  const button = element(root.ownerDocument, "button", "recipient-secondary-action") as HTMLButtonElement;
  button.type = "button"; button.dataset.recipientForget = "true"; button.textContent = "Sign out of this share"; button.addEventListener("click", onForget, { once: true }); footer.append(button);
}
