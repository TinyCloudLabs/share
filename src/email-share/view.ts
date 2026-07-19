import { createMermaidSandbox } from "../viewer/mermaid-sandbox.js";
import { sanitizeSvg } from "../viewer/render.js";
import type { ContentSource, SenderScope } from "./protocol.js";
import { createSenderController, type SenderState } from "./sender.js";
import type { ShareTransport } from "./transport.js";

export interface SenderMountOptions {
  readonly scope?: SenderScope;
  readonly transport: ShareTransport;
  readonly uploadEnvelope: (cid: string, blob: Uint8Array) => Promise<void>;
  readonly defaultSource?: ContentSource;
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
  const detail = element(root.ownerDocument, "span", "sender-status-detail", copy[state.state]);
  status.append(title, detail);
  if (state.state === "delivery-failed" && state.retryable && submit !== undefined) {
    const retry = element(root.ownerDocument, "button", "button button-secondary", "Retry"); retry.type = "button"; retry.addEventListener("click", submit); status.append(retry);
  }
}

export function mountSender(root: HTMLElement, options: SenderMountOptions): void {
  const doc = root.ownerDocument;
  root.replaceChildren();
  const shell = element(doc, "main", "sender-shell");
  const header = element(doc, "header", "sender-header");
  header.append(element(doc, "p", "sender-kicker", "TinyCloud sharing"), element(doc, "h1", "sender-title", "Share one document with one person."), element(doc, "p", "sender-lede", "The recipient’s email is part of the policy. TinyCloud and OpenCredentials verify the scope before any delivery request is accepted."));
  shell.append(header);
  const form = element(doc, "form", "sender-form") as HTMLFormElement;
  form.noValidate = true;
  const emailLabel = element(doc, "label", "field-label", "Recipient email");
  const email = element(doc, "input", "field-input") as HTMLInputElement; email.type = "email"; email.name = "email"; email.autocomplete = "email"; email.required = true; email.placeholder = "name@example.com"; emailLabel.append(email);
  const kindLabel = element(doc, "label", "field-label", "Source");
  const kind = element(doc, "select", "field-input") as HTMLSelectElement; kind.name = "source-kind"; kind.append(new Option("TinyCloud KV · exact path", "kv"), new Option("Named SQL · one constrained statement", "sql")); kindLabel.append(kind);
  const spaceLabel = element(doc, "label", "field-label", "Space"); const space = element(doc, "input", "field-input") as HTMLInputElement; space.name = "space"; space.required = true; space.placeholder = "did:pkh:…"; spaceLabel.append(space);
  const pathLabel = element(doc, "label", "field-label", "Resource path"); const path = element(doc, "input", "field-input") as HTMLInputElement; path.name = "path"; path.required = true; path.placeholder = "documents/plan.md"; pathLabel.append(path);
  const sqlFields = element(doc, "fieldset", "sql-fields"); sqlFields.hidden = true; sqlFields.append(element(doc, "legend", "field-legend", "Named SQL scope"));
  const database = element(doc, "label", "field-label", "Database"); const databaseInput = element(doc, "input", "field-input") as HTMLInputElement; databaseInput.name = "database"; databaseInput.placeholder = "documents"; database.append(databaseInput);
  const statement = element(doc, "label", "field-label", "Statement name"); const statementInput = element(doc, "input", "field-input") as HTMLInputElement; statementInput.name = "statement"; statementInput.placeholder = "shared_document_by_id"; statement.append(statementInput);
  const args = element(doc, "label", "field-label", "Fixed arguments (JSON integers only)"); const argsInput = element(doc, "textarea", "field-input") as HTMLTextAreaElement; argsInput.name = "arguments"; argsInput.value = "{}"; argsInput.rows = 2; args.append(argsInput); sqlFields.append(database, statement, args);
  kind.addEventListener("change", () => { sqlFields.hidden = kind.value !== "sql"; });
  const expiryLabel = element(doc, "label", "field-label", "Access ends"); const expiry = element(doc, "input", "field-input") as HTMLInputElement; expiry.type = "datetime-local"; expiry.name = "expiry"; expiry.required = true; expiryLabel.append(expiry);
  const scopeNote = element(doc, "p", "scope-note", "Read-only. No raw SQL, folder listing, downloads, or write access are available in v1.");
  const submit = element(doc, "button", "button button-primary", "Request invitation"); submit.type = "submit";
  const status = element(doc, "div", "sender-status"); status.dataset.senderStatus = "true";
  form.append(emailLabel, kindLabel, spaceLabel, pathLabel, sqlFields, expiryLabel, scopeNote, submit, status);
  shell.append(form);
  const explainer = element(doc, "section", "sender-explainer"); explainer.append(element(doc, "h2", "What happens next"), element(doc, "p", "sender-explainer-copy", "A signed envelope binds the exact email, source, method, node, and expiry. OpenCredentials only sends after TinyCloud authorizes that exact bundle. The recipient then explicitly opens the document before the one-use claim is redeemed."));
  const diagram = element(doc, "div", "sender-diagram"); diagram.setAttribute("aria-live", "polite"); const fallback = element(doc, "ol", "sender-diagram-fallback"); ["Verify scope locally", "Authorize with TinyCloud", "Request OpenCredentials delivery", "Recipient confirms and reads once"].forEach((item) => fallback.append(element(doc, "li", "", item))); diagram.append(fallback); explainer.append(diagram); shell.append(explainer); root.append(shell);
  const controller = createSenderController({ transport: options.transport, uploadEnvelope: options.uploadEnvelope });
  let lastRequest: { readonly email: string; readonly source: ContentSource; readonly scope: SenderScope; readonly shareId: string; readonly expiresAt: string } | undefined;
  const render = (state: SenderState): void => renderState(root, state, lastRequest === undefined ? undefined : () => { void controller.request(lastRequest as never); });
  controller.subscribe(render);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (options.scope === undefined) { renderState(root, { state: "unavailable", code: "capability-unavailable" }); return; }
    try {
      const source = sourceFromForm(form); const expiryValue = String(new FormData(form).get("expiry") ?? ""); const expiresAt = new Date(expiryValue).toISOString();
      const request = { email: email.value, source, scope: options.scope, shareId: `share-${crypto.randomUUID()}`, expiresAt };
      lastRequest = request; void controller.request(request);
    } catch { renderState(root, { state: "invalid", message: "Check the email and resource details, then try again." }); }
  });
  if (typeof document !== "undefined") {
    void (async () => { try { const sandbox = createMermaidSandbox(doc); const raw = await sandbox.render("flowchart LR\nA[Verify scope] --> B[Authorize node]\nB --> C[Request delivery]\nC --> D[Explicit open]"); sandbox.destroy(); const safe = sanitizeSvg(raw); const parsed = new DOMParser().parseFromString(safe, "image/svg+xml").documentElement; if (parsed !== null && parsed.nodeName.toLowerCase() === "svg") { diagram.replaceChildren(parsed); } } catch { /* the accessible ordered-list fallback stays visible */ } })();
  }
}
