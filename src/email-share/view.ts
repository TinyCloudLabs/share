import type { ShareEnvelope } from "@tinycloud/share-envelope";
import type { ClaimState } from "./claim.js";
import type { ContentSource, SenderScope } from "./protocol.js";
import { createSenderController, type SenderPolicy, type SenderState } from "./sender.js";
import type { ShareTransport } from "./transport.js";
import type { VerifiedExactEmailShare } from "./verified-share.js";

export interface SenderMountOptions {
  readonly capabilities: readonly { readonly scope: SenderScope; readonly source: ContentSource; readonly policy: SenderPolicy }[];
  readonly transport: ShareTransport;
  readonly uploadContent: (file: File, capability: { readonly scope: SenderScope; readonly source: ContentSource; readonly policy: SenderPolicy }) => Promise<void>;
  readonly uploadEnvelope: (cid: string, blob: Uint8Array, deleteAfter: string) => Promise<void>;
  readonly publishBinding?: (binding: Record<string, unknown>) => Promise<void>;
  readonly openKeyAddress: string;
}

function element<K extends keyof HTMLElementTagNameMap>(doc: Document, tag: K, className: string, text?: string): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag); node.className = className; if (text !== undefined) node.textContent = text; return node;
}

function sourceFromForm(form: HTMLFormElement): ContentSource {
  const kind = new FormData(form).get("source-kind");
  const space = String(new FormData(form).get("space") ?? "").trim();
  const path = String(new FormData(form).get("path") ?? "").trim();
  if (kind === "sql") {
    const database = String(new FormData(form).get("database") ?? "").trim();
    const statement = String(new FormData(form).get("statement") ?? "").trim();
    const argsText = String(new FormData(form).get("arguments") ?? "{}");
    const args = JSON.parse(argsText) as Record<string, number>;
    return { kind: "sql", space, database, path, statement, arguments: args, argumentsDigest: "adapter-supplied", action: "tinycloud.sql/read" };
  }
  return { kind: "kv", space, path, action: "tinycloud.kv/get" };
}

function sourceSummary(source: ContentSource): string {
  return source.kind === "kv"
    ? `Resource: ${source.space}/${source.path}\nAction: ${source.action}`
    : `Resource: ${source.space}/${source.database}/${source.path}\nAction: ${source.action}\nNamed statement: ${source.statement}\nArguments: ${JSON.stringify(source.arguments)}`;
}

function renderState(root: HTMLElement, state: SenderState, submit?: () => void): void {
  const status = root.querySelector<HTMLElement>("[data-sender-status]");
  if (status === null) return;
  status.replaceChildren();
  status.dataset.state = state.state;
  status.setAttribute("role", state.state === "delivery-failed" || state.state === "invalid" ? "alert" : "status");
  const copy: Record<SenderState["state"], string> = {
    editing: "Ready when you are.", authorizing: "Checking the selected policy with TinyCloud…", requesting: "Invitation requested. Waiting for delivery service acceptance…",
    requested: "Invitation requested. The delivery service accepted the request; this does not claim that an email has arrived.", "delivery-failed": "Delivery failed before the service accepted the request.", unavailable: "Exact-email sharing is unavailable until the trusted node and delivery capability are ready.", invalid: "Check the highlighted details and try again.",
  };
  const title = element(root.ownerDocument, "strong", "sender-status-title", state.state === "requested" ? "Invitation requested" : state.state === "delivery-failed" ? "Delivery failed" : state.state === "authorizing" || state.state === "requesting" ? "Working securely" : "Share status");
  const detail = element(root.ownerDocument, "span", "sender-status-detail", state.state === "invalid" ? state.message : copy[state.state]);
  status.append(title, detail);
  if (state.state === "requested") {
    const link = element(root.ownerDocument, "a", "share-result-link", state.shareUrl) as HTMLAnchorElement;
    link.href = state.shareUrl; link.target = "_blank"; link.rel = "noopener noreferrer";
    const copy = element(root.ownerDocument, "button", "button button-secondary", "Copy link"); copy.type = "button";
    copy.addEventListener("click", () => { void navigator.clipboard.writeText(state.shareUrl).then(() => { copy.textContent = "Copied"; }); });
    status.append(link, copy);
  }
  if (state.state === "delivery-failed" && state.retryable && submit !== undefined) {
    const retry = element(root.ownerDocument, "button", "button button-secondary", "Retry"); retry.type = "button"; retry.addEventListener("click", submit); status.append(retry);
  }
}

export function mountSender(root: HTMLElement, options: SenderMountOptions): void {
  const doc = root.ownerDocument;
  root.replaceChildren();
  const shell = element(doc, "main", "sender-shell");
  const header = element(doc, "header", "sender-header");
  header.append(element(doc, "p", "sender-kicker", `OpenKey connected · ${options.openKeyAddress.slice(0, 6)}…${options.openKeyAddress.slice(-4)}`), element(doc, "h1", "sender-title", "Upload. Choose who. Share."), element(doc, "p", "sender-lede", "Your document is written to your TinyCloud space first. Then an exact-email policy controls who can open the link."));
  shell.append(header);
  const form = element(doc, "form", "sender-form") as HTMLFormElement;
  form.noValidate = true;
  const capabilities = options.capabilities.filter((candidate) => candidate.source.kind === "kv");
  if (capabilities.length === 0) { renderState(root, { state: "unavailable", code: "capability-unavailable" }); return; }
  const progress = element(doc, "ol", "share-progress");
  for (const [number, label, state] of [["01", "Signed in", "complete"], ["02", "Upload", "current"], ["03", "Share", "upcoming"]] as const) {
    const item = element(doc, "li", ""); item.dataset.state = state; item.append(element(doc, "span", "", number), doc.createTextNode(label)); progress.append(item);
  }
  const fileLabel = element(doc, "label", "upload-field");
  const fileTitle = element(doc, "strong", "upload-title", "Choose a document");
  const fileHelp = element(doc, "span", "upload-help", "Markdown or text · up to 1 MB");
  const fileInput = element(doc, "input", "upload-input") as HTMLInputElement; fileInput.type = "file"; fileInput.name = "document"; fileInput.accept = ".md,.markdown,.txt,text/markdown,text/plain"; fileInput.required = true;
  const fileMeta = element(doc, "span", "upload-meta", "No file selected");
  fileLabel.append(fileTitle, fileHelp, fileInput, fileMeta);
  fileInput.addEventListener("change", () => {
    const selectedFile = fileInput.files?.[0];
    fileMeta.textContent = selectedFile === undefined ? "No file selected" : `${selectedFile.name} · ${selectedFile.size < 1024 ? `${selectedFile.size} B` : `${(selectedFile.size / 1024).toFixed(1)} KB`}`;
    fileLabel.dataset.selected = String(selectedFile !== undefined);
  });
  const emailLabel = element(doc, "label", "field-label", "Recipient email");
  const email = element(doc, "input", "field-input") as HTMLInputElement; email.type = "email"; email.name = "email"; email.autocomplete = "email"; email.required = true; email.placeholder = "name@example.com"; emailLabel.append(email);
  const capabilityLabel = element(doc, "label", "field-label technical-field", "Policy-bound storage destination");
  const capabilitySelect = element(doc, "select", "field-input") as HTMLSelectElement; capabilitySelect.name = "capability";
  capabilities.forEach((candidate, index) => capabilitySelect.append(new Option(sourceSummary(candidate.source), String(index)))); capabilityLabel.append(capabilitySelect);
  const kindLabel = element(doc, "label", "field-label technical-field", "Source");
  const kind = element(doc, "select", "field-input") as HTMLSelectElement; kind.name = "source-kind"; kind.append(new Option("TinyCloud KV · exact path", "kv"), new Option("Named SQL · one constrained statement", "sql")); kindLabel.append(kind);
  const spaceLabel = element(doc, "label", "field-label technical-field", "Space"); const space = element(doc, "input", "field-input") as HTMLInputElement; space.name = "space"; space.required = true; space.readOnly = true; space.placeholder = "did:pkh:…"; spaceLabel.append(space);
  const pathLabel = element(doc, "label", "field-label technical-field", "Resource path"); const path = element(doc, "input", "field-input") as HTMLInputElement; path.name = "path"; path.required = true; path.placeholder = "documents/plan.md"; pathLabel.append(path);
  const sqlFields = element(doc, "fieldset", "sql-fields"); sqlFields.hidden = true; sqlFields.append(element(doc, "legend", "field-legend", "Named SQL scope"));
  const database = element(doc, "label", "field-label", "Database"); const databaseInput = element(doc, "input", "field-input") as HTMLInputElement; databaseInput.name = "database"; databaseInput.placeholder = "documents"; database.append(databaseInput);
  const statement = element(doc, "label", "field-label", "Statement name"); const statementInput = element(doc, "input", "field-input") as HTMLInputElement; statementInput.name = "statement"; statementInput.placeholder = "shared_document_by_id"; statement.append(statementInput);
  const args = element(doc, "label", "field-label", "Fixed arguments (JSON integers only)"); const argsInput = element(doc, "textarea", "field-input") as HTMLTextAreaElement; argsInput.name = "arguments"; argsInput.value = "{}"; argsInput.rows = 2; args.append(argsInput); sqlFields.append(database, statement, args);
  kind.addEventListener("change", () => { sqlFields.hidden = kind.value !== "sql"; });
  const expiryLabel = element(doc, "label", "field-label", "Access ends"); const expiry = element(doc, "input", "field-input") as HTMLInputElement; expiry.type = "datetime-local"; expiry.step = "0.001"; expiry.name = "expiry"; expiry.required = true; expiryLabel.append(expiry);
  const scopeNote = element(doc, "p", "scope-note", "Read-only. No raw SQL, folder listing, downloads, or write access are available in v1.");
  const exactScope = element(doc, "pre", "scope-note");
  const submit = element(doc, "button", "button button-primary", "Create and send share"); submit.type = "submit";
  const status = element(doc, "div", "sender-status"); status.dataset.senderStatus = "true";
  form.append(progress, fileLabel, emailLabel, expiryLabel, exactScope, capabilityLabel, kindLabel, spaceLabel, pathLabel, sqlFields, scopeNote, submit, status);
  shell.append(form);
  const explainer = element(doc, "section", "sender-explainer"); explainer.append(element(doc, "h2", "What happens next"), element(doc, "p", "sender-explainer-copy", "A signed envelope binds the exact email, source, method, node, and expiry. OpenCredentials only sends after TinyCloud authorizes that exact bundle. The recipient then explicitly opens the document before the one-use claim is redeemed."));
  const diagram = element(doc, "div", "sender-diagram"); diagram.setAttribute("aria-live", "polite"); const fallback = element(doc, "ol", "sender-diagram-fallback"); ["Verify scope locally", "Authorize with TinyCloud", "Request OpenCredentials delivery", "Recipient confirms and reads once"].forEach((item) => fallback.append(element(doc, "li", "", item))); diagram.append(fallback); explainer.append(diagram); shell.append(explainer); root.append(shell);
  const controller = createSenderController({ transport: options.transport, uploadEnvelope: options.uploadEnvelope, ...(options.publishBinding === undefined ? {} : { publishBinding: options.publishBinding }) });
  let lastRequest: { readonly email: string; readonly source: ContentSource; readonly scope: SenderScope; readonly shareId: string; readonly expiresAt: string; readonly policy: SenderPolicy } | undefined;
  const render = (state: SenderState): void => {
    const retryRequest = lastRequest;
    renderState(root, state, retryRequest === undefined ? undefined : () => { void controller.request(retryRequest); });
  };
  controller.subscribe(render);
  renderState(root, controller.state);
  const selected = (): { readonly scope: SenderScope; readonly source: ContentSource; readonly policy: SenderPolicy } => capabilities[Number(capabilitySelect.value)]!;
  const localDateTime = (value: string): string => new Date(Date.parse(value) - new Date(value).getTimezoneOffset() * 60_000).toISOString().slice(0, 23);
  const renderSelection = (): void => {
    const candidate = selected(); const source = candidate.source;
    kind.value = source.kind; space.value = source.space; path.value = source.path;
    kind.disabled = false; path.readOnly = true; sqlFields.hidden = source.kind !== "sql";
    if (source.kind === "sql") { databaseInput.value = source.database; statementInput.value = source.statement; argsInput.value = JSON.stringify(source.arguments); databaseInput.readOnly = true; statementInput.readOnly = true; argsInput.readOnly = true; }
    const max = candidate.scope.expiryMax ?? candidate.scope.expiresAt; const defaultExpiry = candidate.scope.expiryDefault ?? max;
    if (candidate.scope.expiryMin !== undefined) expiry.min = localDateTime(candidate.scope.expiryMin); else expiry.removeAttribute("min");
    if (max !== undefined) expiry.max = localDateTime(max); else expiry.removeAttribute("max");
    if (defaultExpiry !== undefined && expiry.value === "") expiry.value = localDateTime(defaultExpiry);
    exactScope.textContent = `Recipient: ${email.value || "(enter one exact email)"}\nAccess: Read-only until ${expiry.value || "(choose a bounded expiry)"}\nStorage: Your encrypted TinyCloud space`;
  };
  capabilitySelect.addEventListener("change", renderSelection);
  email.addEventListener("input", () => {
    const match = capabilities.findIndex((candidate) => candidate.policy.recipientEmail.toLowerCase() === email.value.trim().toLowerCase());
    if (match >= 0) capabilitySelect.value = String(match);
    renderSelection();
  }); expiry.addEventListener("input", renderSelection); expiry.addEventListener("change", renderSelection);
  renderSelection();
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    void (async () => {
      const candidate = selected();
      try {
      const file = fileInput.files?.[0];
      if (file === undefined) throw new TypeError("Choose a document to upload.");
      if (candidate.policy.recipientEmail.toLowerCase() !== email.value.trim().toLowerCase()) throw new TypeError("No policy is ready for that recipient yet.");
      const source = sourceFromForm(form); const expiryValue = String(new FormData(form).get("expiry") ?? ""); const expiresAt = new Date(expiryValue).toISOString();
      const request = { email: email.value, source, scope: candidate.scope, shareId: `share-${crypto.randomUUID()}`, expiresAt, policy: candidate.policy };
      submit.disabled = true;
      status.dataset.state = "uploading"; status.replaceChildren(element(doc, "strong", "sender-status-title", "Uploading securely"), element(doc, "span", "sender-status-detail", `Writing ${file.name} to your TinyCloud space…`));
      await options.uploadContent(file, candidate);
      progress.children[1]?.setAttribute("data-state", "complete"); progress.children[2]?.setAttribute("data-state", "current");
      lastRequest = request; await controller.request(request);
    } catch (error) { renderState(root, { state: "invalid", message: error instanceof Error ? error.message : "Check the document, email, and access details." }); }
    finally { submit.disabled = false; }
    })();
  });
}

export interface RecipientFacts {
  readonly envelope: ShareEnvelope;
  readonly share: VerifiedExactEmailShare;
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
  const main = element(doc, "main", "recipient-shell");
  main.append(element(doc, "p", "recipient-brand", "TinyCloud sharing"), element(doc, "h1", "recipient-title", message), element(doc, "p", "recipient-detail", "The invitation is checked before any access request can begin."));
  root.append(main);
}

export function renderRecipientInvalid(root: HTMLElement, message: string): void {
  root.replaceChildren();
  const doc = root.ownerDocument;
  const main = element(doc, "main", "recipient-shell recipient-shell-error");
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
  main.append(header, status);
  root.append(main);
}

export function appendRecipientForgetAction(root: HTMLElement, onForget: () => void): void {
  root.querySelector("[data-recipient-forget]")?.remove();
  const footer = root.querySelector(".viewer-footer") ?? root;
  const button = element(root.ownerDocument, "button", "recipient-secondary-action") as HTMLButtonElement;
  button.type = "button"; button.dataset.recipientForget = "true"; button.textContent = "Forget this browser key"; button.addEventListener("click", onForget, { once: true }); footer.append(button);
}
