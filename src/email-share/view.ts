import { focusViewerRoot } from "../viewer/focus.js";

function element<K extends keyof HTMLElementTagNameMap>(doc: Document, tag: K, className: string, text?: string): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag);
  node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function checkIcon(doc: Document): SVGSVGElement {
  const ns = "http://www.w3.org/2000/svg";
  const icon = doc.createElementNS(ns, "svg");
  for (const [name, value] of Object.entries({ class: "claim-check", viewBox: "0 0 24 24", width: "18", height: "18", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", focusable: "false" })) icon.setAttribute(name, value);
  const path = doc.createElementNS(ns, "path");
  path.setAttribute("d", "m5 12.5 4.5 4.5L19 7.5");
  icon.append(path);
  return icon;
}

function spinner(doc: Document): HTMLSpanElement {
  const node = element(doc, "span", "claim-spinner");
  node.setAttribute("aria-hidden", "true");
  return node;
}

export function renderRecipientLoading(root: HTMLElement, message = "Checking this link…"): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const main = element(doc, "main", "recipient-shell claim claim-loading");
  main.setAttribute("aria-busy", "true");
  const status = element(doc, "p", "claim-lede claim-progress");
  status.setAttribute("role", "status");
  status.append(spinner(doc), "Verifying it before anything opens.");
  main.append(element(doc, "h1", "claim-title", message), status);
  root.append(main);
}

export function renderRecipientInvalid(root: HTMLElement, message: string): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const main = element(doc, "main", "recipient-shell recipient-message recipient-shell-error");
  main.setAttribute("role", "alert");
  main.append(element(doc, "h1", "recipient-title", "This invitation cannot be opened"), element(doc, "p", "recipient-detail", message));
  root.append(main);
  focusViewerRoot(root);
}

/** Facts from the owner-signed invitation, shown before any credential is requested. */
export interface RecipientClaimInvitation {
  /** The recipient the SDK bound to the signed policy commitment. */
  readonly recipient: { readonly kind: "exactEmail"; readonly email: string } | { readonly kind: "emailDomain"; readonly domain: string };
  readonly filename?: string;
  readonly expiresAt?: string;
  readonly actions?: readonly string[];
}

export interface RecipientClaimView {
  /** Container the SDK mounts its credential view into. */
  readonly verify: HTMLElement;
}

const ACTION_LABELS: ReadonlyMap<string, string> = new Map([["read", "View"], ["list", "List folder"], ["edit", "Edit"]]);

function expiryText(value: string | undefined): { readonly text: string; readonly datetime: string } | undefined {
  if (value === undefined) return undefined;
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return undefined;
  return { text: new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date), datetime: date.toISOString() };
}

export function renderRecipientClaim(root: HTMLElement, invitation: RecipientClaimInvitation): RecipientClaimView {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const main = element(doc, "main", "recipient-shell claim");
  main.setAttribute("aria-labelledby", "claim-title");
  const title = element(doc, "h1", "claim-title", "Verify your email to open this file");
  title.id = "claim-title";
  const lede = element(doc, "p", "claim-lede");
  const recipient = invitation.recipient;
  if (recipient.kind === "exactEmail") {
    lede.append("This invitation was sent to ", element(doc, "strong", "claim-mailbox", recipient.email), ". Only someone who can read that inbox can open it — no account needed.");
  } else {
    lede.append("This invitation is open to anyone with an email address at ", element(doc, "strong", "claim-mailbox", `@${recipient.domain}`), ". Confirm an address there to open it — no account needed.");
  }
  const intro = element(doc, "header", "claim-intro");
  intro.append(title, lede);

  const verify = element(doc, "section", "claim-verify");
  verify.setAttribute("aria-label", "Email verification");

  const details = element(doc, "aside", "claim-details");
  details.setAttribute("aria-label", "Invitation details");
  const facts = element(doc, "dl", "claim-facts");
  const fact = (label: string, value: Node | string) => {
    const row = element(doc, "div", "claim-fact");
    const dd = element(doc, "dd", "");
    dd.append(value);
    row.append(element(doc, "dt", "", label), dd);
    facts.append(row);
  };
  fact("For", recipient.kind === "exactEmail" ? recipient.email : `Anyone at @${recipient.domain}`);
  if (invitation.filename !== undefined) fact("File", invitation.filename);
  const actions = (invitation.actions ?? []).map((action) => ACTION_LABELS.get(action)).filter((label): label is string => label !== undefined);
  if (actions.length > 0) fact("Access", actions.join(", "));
  const expiry = expiryText(invitation.expiresAt);
  if (expiry !== undefined) {
    const time = doc.createElement("time");
    time.dateTime = expiry.datetime;
    time.textContent = expiry.text;
    fact("Expires", time);
  }
  const note = element(doc, "p", "claim-note", recipient.kind === "exactEmail"
    ? "The emailed code proves you control this mailbox. The owner’s TinyCloud node checks that proof before it releases the encrypted file, which is decrypted in this browser."
    : "The emailed code proves you control an address at this domain. The owner’s TinyCloud node checks that proof, and sees the address you verify, before it releases the encrypted file, which is decrypted in this browser.");
  details.append(facts, note);

  const layout = element(doc, "div", "claim-layout");
  layout.append(verify, details);
  main.append(intro, layout);
  root.append(main);
  return { verify };
}

/** Replaces the verification slot once the mailbox credential is in hand. */
export function renderRecipientClaimProgress(view: RecipientClaimView, message: string, mailbox?: string): void {
  const doc = view.verify.ownerDocument;
  const panel = element(doc, "div", "claim-state");
  const status = element(doc, "p", "claim-state-line");
  status.setAttribute("role", "status");
  status.append(spinner(doc), message);
  const verified = element(doc, "p", "claim-state-title claim-verified");
  verified.append(checkIcon(doc), "Email verified");
  panel.append(verified);
  // The mailbox comes from the verified credential, not from anything typed.
  if (mailbox !== undefined) panel.append(element(doc, "p", "claim-state-detail claim-verified-mailbox", mailbox));
  panel.append(status);
  view.verify.replaceChildren(panel);
}

/** `reader@example.com` -> `r***@e***.com`, for status lines that confirm where a code went. */
export function maskedMailbox(email: string): string {
  const at = email.lastIndexOf("@");
  const domain = email.slice(at + 1);
  const tld = domain.lastIndexOf(".");
  return `${email.slice(0, 1)}***@${domain.slice(0, 1)}***${tld > 0 ? domain.slice(tld) : ""}`;
}

/**
 * Waits for the recipient to ask for a code. Mail scanners open links and run
 * their scripts, so a code is only ever requested by this click, never on load.
 */
export function renderRecipientCodeRequest(view: RecipientClaimView, email: string, onRequest: () => void): void {
  const doc = view.verify.ownerDocument;
  const panel = element(doc, "div", "claim-state claim-request");
  const detail = element(doc, "p", "claim-state-detail", `We’ll email a one-time code to ${maskedMailbox(email)}. Enter it here to open the file.`);
  detail.id = "claim-request-detail";
  const request = element(doc, "button", "recipient-primary-action claim-request-code", "Email me a code");
  request.type = "button";
  request.setAttribute("aria-describedby", detail.id);
  request.addEventListener("click", () => { request.disabled = true; onRequest(); }, { once: true });
  panel.append(element(doc, "h2", "claim-state-title", "Get a code by email"), detail, request);
  view.verify.replaceChildren(panel);
}

/**
 * Shows, above the code entry, where the requested code was sent. The clicked
 * button is gone, so focus moves to this line instead of falling to the page
 * body; its text is set after insertion so screen readers announce it.
 */
export function renderRecipientCodeRequested(view: RecipientClaimView, email: string, codeEntry: HTMLElement): void {
  const line = element(view.verify.ownerDocument, "p", "claim-state-detail claim-requested");
  line.setAttribute("role", "status");
  line.tabIndex = -1;
  view.verify.replaceChildren(line, codeEntry);
  line.focus();
  setTimeout(() => { line.textContent = `Code requested for ${maskedMailbox(email)}. It can take a minute to arrive.`; }, 0);
}

export interface RecipientClaimRecovery {
  readonly title: string;
  readonly detail: string;
  readonly action: string;
}

/**
 * A recoverable stop: nothing was opened and a fresh code can be requested.
 * Until `availableAt` (epoch ms) the button stays disabled, so a recipient
 * cannot burn the issuer's code budget by retrying in a burst.
 */
export function renderRecipientClaimRecovery(view: RecipientClaimView, recovery: RecipientClaimRecovery, onRetry: () => void, availableAt = 0): void {
  const doc = view.verify.ownerDocument;
  const panel = element(doc, "div", "claim-state");
  panel.dataset.tone = "alert";
  panel.setAttribute("role", "alert");
  const title = element(doc, "h2", "claim-state-title", recovery.title);
  title.tabIndex = -1;
  const retry = element(doc, "button", "recipient-primary-action", recovery.action);
  retry.type = "button";
  retry.addEventListener("click", () => { retry.disabled = true; onRetry(); }, { once: true });
  panel.append(title, element(doc, "p", "claim-state-detail", recovery.detail), retry);
  const wait = availableAt - Date.now();
  if (wait > 0) {
    retry.disabled = true;
    const cooldown = element(doc, "p", "claim-state-detail claim-cooldown", `You can ask for a new code in ${Math.ceil(wait / 1000)} seconds.`);
    cooldown.setAttribute("aria-live", "polite");
    panel.append(cooldown);
    setTimeout(() => { retry.disabled = false; cooldown.textContent = "You can ask for a new code now."; }, wait);
  }
  view.verify.replaceChildren(panel);
  title.focus();
}
