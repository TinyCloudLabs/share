import type { ShareComposerModel } from "./composer-model.js";
import { mountShareComposer, type ComposerShareResult, type ShareComposerOptions } from "./composer.js";
import { copyWithFallback } from "./link-only.js";
import { createSenderHistoryRecord, SenderHistoryRepository, type SenderHistoryItem } from "./sender-history.js";
import type { OpenKeyShareSession, ShareTinyCloud, UploadCapability } from "./openkey-session.js";

interface SenderHomeOptions {
  readonly session: OpenKeyShareSession;
  readonly tinycloud: ShareTinyCloud;
  readonly history: SenderHistoryRepository;
  readonly capabilities: readonly UploadCapability[];
  readonly composer: Omit<ShareComposerOptions, "openKeyAddress" | "session" | "tinycloud" | "persistShare" | "loadCapabilities">;
}

function node<K extends keyof HTMLElementTagNameMap>(doc: Document, tag: K, className: string, text?: string): HTMLElementTagNameMap[K] {
  const item = doc.createElement(tag);
  item.className = className;
  if (text !== undefined) item.textContent = text;
  return item;
}

function safeName(record: Extract<SenderHistoryItem, { state: "ready" | "expired" }> ["record"]): string {
  return record.name.length > 80 ? `${record.name.slice(0, 77)}…` : record.name;
}

function recipientSummary(item: Extract<SenderHistoryItem, { state: "ready" | "expired" }>): string {
  if (item.record.recipient.kind === "bearer") return "Anyone with link";
  if (item.record.recipient.kind === "emailDomain") return `Email domain · ${item.record.recipient.value}`;
  const [local, domain] = item.record.recipient.value.split("@");
  return `Exact email · ${(local?.slice(0, 1) ?? "•")}***@${domain ?? "…"}`;
}

function actionsSummary(actions: readonly string[]): string {
  return actions.map((action) => action === "list" ? "List" : action[0]!.toUpperCase() + action.slice(1)).join(" / ");
}

export function mountSenderHome(root: HTMLElement, options: SenderHomeOptions): void {
  const doc = root.ownerDocument;
  root.removeAttribute("aria-busy");
  root.replaceChildren();
  const shell = node(doc, "main", "sender-shell sender-home");
  const header = node(doc, "header", "sender-header sender-home-header");
  header.append(node(doc, "p", "sender-kicker", "OpenKey connected"), node(doc, "h1", "sender-title", "Shared by me."), node(doc, "p", "sender-lede", "Your encrypted share library, scoped to this sender account. Links stay private until you choose to copy or open them."));
  const toolbar = node(doc, "div", "sender-home-toolbar");
  const newShare = node(doc, "button", "button button-primary", "New share") as HTMLButtonElement; newShare.type = "button";
  const account = node(doc, "span", "sender-account", options.session.address.length > 12 ? `${options.session.address.slice(0, 6)}…${options.session.address.slice(-4)}` : options.session.address);
  toolbar.append(newShare, account);
  const live = node(doc, "p", "sender-live"); live.setAttribute("role", "status"); live.setAttribute("aria-live", "polite");
  const content = node(doc, "section", "sender-library"); content.setAttribute("aria-labelledby", "sender-library-title");
  const title = node(doc, "h2", "sender-library-title", "All shares");
  const table = node(doc, "table", "sender-history-table");
  const caption = node(doc, "caption", "sr-only", "Shares created by this sender");
  const head = node(doc, "thead", ""); const row = node(doc, "tr", "");
  for (const label of ["Item", "Recipient", "Access", "Expires / status", "Created", "Actions"]) row.append(node(doc, "th", "", label));
  head.append(row); table.append(caption, head);
  const body = node(doc, "tbody", ""); table.append(body);
  const more = node(doc, "button", "button button-secondary sender-load-more", "Load more") as HTMLButtonElement; more.type = "button"; more.hidden = true;
  const error = node(doc, "div", "sender-status"); error.hidden = true; error.setAttribute("role", "alert");
  content.append(title, table, more, error); shell.append(header, toolbar, live, content); root.append(shell);

  const pageRows: HTMLElement[] = [];
  let cursor: string | undefined;
  let loading = false;
  let initialLoadRetries = 0;
  const renderSkeleton = (): void => {
    body.replaceChildren();
    for (let index = 0; index < 4; index += 1) { const skeleton = node(doc, "tr", "sender-skeleton-row"); for (let column = 0; column < 6; column += 1) skeleton.append(node(doc, "td", "sender-skeleton-cell", "Loading")); body.append(skeleton); }
  };
  const openImport = (): void => {
    const dialog = node(doc, "dialog", "sender-import-dialog") as HTMLDialogElement;
    const form = node(doc, "form", "sender-form") as HTMLFormElement; form.method = "dialog";
    const heading = node(doc, "h2", "", "Import an existing link");
    const help = node(doc, "p", "sender-status-detail", "Paste a complete link you still possess. It is validated and encrypted in this browser before it is saved.");
    const label = node(doc, "label", "field-label", "Complete share link"); const input = node(doc, "input", "field-input") as HTMLInputElement; input.type = "url"; input.required = true; input.autocomplete = "off"; label.append(input);
    const save = node(doc, "button", "button button-primary", "Save encrypted link") as HTMLButtonElement; save.type = "submit";
    const cancel = node(doc, "button", "button button-secondary", "Cancel") as HTMLButtonElement; cancel.type = "button"; cancel.addEventListener("click", () => dialog.close());
    const message = node(doc, "p", "sender-live"); form.append(heading, help, label, save, cancel, message); dialog.append(form); root.append(dialog); dialog.showModal(); input.focus();
    form.addEventListener("submit", (event) => { event.preventDefault(); const value = input.value.trim(); try { const parsed = new URL(value); if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.username || parsed.password || (!parsed.hash && parsed.pathname !== "/s/inline")) throw new Error("invalid"); const recordPromise = createSenderHistoryRecord({ id: crypto.randomUUID().replace(/-/g, ""), url: value, cid: parsed.pathname.split("/").at(-1) ?? "inline", format: parsed.pathname === "/s/inline" ? "inline" : "compact", createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), name: "Imported share", mediaType: "application/octet-stream", sourceKind: "upload", recipient: { kind: "bearer" }, actions: ["read"] }); void recordPromise.then((record) => options.history.save(record)).then(() => { dialog.close(); dialog.remove(); void load(false); }).catch(() => { message.textContent = "That link could not be validated or saved."; }); } catch { message.textContent = "Enter a complete share link with its fragment."; } });
  };
  const renderEmpty = (): void => {
    const empty = node(doc, "tr", "sender-empty-row"); const cell = node(doc, "td", "sender-empty-state"); cell.colSpan = 6; cell.append(node(doc, "strong", "", "No shares yet"), node(doc, "span", "", "Create your first encrypted share or import a link you still possess.")); const importButton = node(doc, "button", "button button-secondary", "Import existing link") as HTMLButtonElement; importButton.type = "button"; importButton.addEventListener("click", openImport); cell.append(importButton); empty.append(cell); body.append(empty); };
  const renderItem = (item: SenderHistoryItem): void => {
    const row = node(doc, "tr", "sender-history-row");
    if (item.state === "needs-attention") {
      const cell = node(doc, "td", "sender-history-attention"); cell.colSpan = 5; cell.append(node(doc, "strong", "", "Needs attention"), node(doc, "span", "", "This saved share could not be decrypted or validated.")); const retry = node(doc, "button", "button button-secondary", "Retry") as HTMLButtonElement; retry.type = "button"; retry.addEventListener("click", () => { void load(false); }); const remove = node(doc, "button", "button button-secondary", "Remove saved entry") as HTMLButtonElement; remove.type = "button"; remove.addEventListener("click", () => { if (!window.confirm("Remove this saved entry?")) return; remove.disabled = true; void options.history.remove(item.key).then(() => load(false)).catch(() => { remove.disabled = false; live.textContent = "The saved entry could not be removed. Try again."; }); }); cell.append(retry, remove); row.append(cell, node(doc, "td", "", "—")); body.append(row); return;
    }
    const itemCell = node(doc, "td", "sender-item-cell"); itemCell.append(node(doc, "strong", "", safeName(item.record)), node(doc, "span", "sender-item-type", item.record.mediaType));
    const recipient = node(doc, "td", "", recipientSummary(item)); recipient.dataset.label = "Recipient";
    const access = node(doc, "td", "", actionsSummary(item.record.actions)); access.dataset.label = "Access";
    const status = node(doc, "td", `sender-status-text ${item.state}`); status.dataset.label = "Expires / status"; status.append(node(doc, "span", "status-label", item.state === "expired" ? "Expired" : "Ready"), node(doc, "span", "status-expiry", new Date(item.record.expiresAt).toLocaleDateString()));
    const created = node(doc, "td", "", new Date(item.record.createdAt).toLocaleDateString()); created.dataset.label = "Created";
    const controls = node(doc, "td", "sender-row-actions");
    const copy = node(doc, "button", "button button-secondary", "Copy link") as HTMLButtonElement; copy.type = "button"; copy.setAttribute("aria-label", `Copy link for ${safeName(item.record)}`); copy.addEventListener("click", () => { void copyWithFallback(item.record.url).then(() => { live.textContent = "Link copied."; }).catch(() => { live.textContent = "Copy failed. Try again after allowing clipboard access."; }); });
    const open = node(doc, "button", "button button-secondary", "Open") as HTMLButtonElement; open.type = "button"; open.setAttribute("aria-label", `Open ${safeName(item.record)}`); open.addEventListener("click", () => openSenderViewer(item.record.url, live));
    itemCell.dataset.label = "Item"; controls.dataset.label = "Actions"; row.tabIndex = -1; controls.append(open, copy); row.append(itemCell, recipient, access, status, created, controls); body.append(row); pageRows.push(row);
  };
  const load = async (append: boolean): Promise<void> => {
    if (loading) return;
    loading = true; error.hidden = true; table.setAttribute("aria-busy", "true"); if (!append) { cursor = undefined; pageRows.length = 0; renderSkeleton(); }
    try {
      const page = await options.history.page(cursor);
      if (!append) body.replaceChildren();
      if (page.items.length === 0 && !append) renderEmpty();
      page.items.forEach(renderItem); cursor = page.nextCursor; more.hidden = !page.truncated; if (page.items.length > 0) live.textContent = append ? `${page.items.length} more shares loaded.` : `${page.items.length} shares loaded.`;
    } catch (caught) {
      if (import.meta.env.VITE_SHARE_HERMETIC === "true") (window as Window & { __tinycloudSenderHistoryError?: string }).__tinycloudSenderHistoryError = caught instanceof Error ? caught.message : String(caught);
      if (!append && initialLoadRetries < 3) {
        initialLoadRetries += 1;
        live.textContent = "Reconnecting to your encrypted share library…";
        window.setTimeout(() => { void load(false); }, 250);
        return;
      }
      error.hidden = false; error.replaceChildren(node(doc, "strong", "sender-status-title", "Could not load shares"), node(doc, "span", "sender-status-detail", "Your encrypted library could not be reached. Try again.")); const retry = node(doc, "button", "button button-secondary", "Retry") as HTMLButtonElement; retry.type = "button"; retry.addEventListener("click", () => { void load(false); }); error.append(retry);
    } finally { table.removeAttribute("aria-busy"); loading = false; }
  };
  const openComposer = (): void => {
    const composerOptions: ShareComposerOptions = { ...options.composer, openKeyAddress: options.session.address, session: options.session, tinycloud: options.tinycloud, loadCapabilities: async () => options.capabilities.map((candidate) => ({ capabilityId: candidate.capabilityId ?? "", scope: candidate.scope as unknown as Record<string, unknown>, source: candidate.source, policy: candidate.policy as never })), persistShare: async ({ share, model, file }) => {
      const expiresAt = share.expiresAt ?? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
      const recipient = model.recipient.kind === "bearer" ? { kind: "bearer" as const } : { kind: model.recipient.kind, value: model.recipient.value! };
      const record = await createSenderHistoryRecord({ id: crypto.randomUUID().replace(/-/g, ""), url: share.url, cid: share.cid, format: share.format, createdAt: new Date().toISOString(), expiresAt, name: model.filename ?? file.name, mediaType: (model.mediaType ?? file.type) || "application/octet-stream", sourceKind: model.contentMode ?? "upload", recipient, actions: model.permissions });
      await options.history.save(record);
      await load(false);
    } };
    mountShareComposer(root, composerOptions);
  };
  newShare.addEventListener("click", openComposer); more.addEventListener("click", () => { const firstNew = pageRows.length; void load(true).then(() => pageRows[firstNew]?.focus?.()); });
  void load(false);
}

function openSenderViewer(url: string, live: HTMLElement): void {
  const child = window.open("/viewer?sender-launch=1", "_blank", "noreferrer");
  if (child === null) { live.textContent = "The viewer window was blocked. Allow pop-ups and try again."; return; }
  const channel = new MessageChannel();
  let delivered = false;
  const timeout = window.setTimeout(() => { if (!delivered) { channel.port1.close(); live.textContent = "The viewer did not accept the private launch."; } }, 10_000);
  channel.port1.onmessage = (event): void => {
    if (delivered || event.data?.type !== "tinycloud-sender-ready") return;
    delivered = true;
    window.clearTimeout(timeout);
    try { channel.port1.postMessage({ type: "tinycloud-sender-launch", url }); child.opener = null; } catch { live.textContent = "The viewer could not be opened."; }
  };
  try { child.postMessage({ type: "tinycloud-sender-channel" }, window.location.origin, [channel.port2]); } catch { window.clearTimeout(timeout); channel.port1.close(); live.textContent = "The viewer could not be opened."; }
}
