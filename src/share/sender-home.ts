import { copyWithFallback } from "./clipboard.js";
import { importSenderHistoryRecord, SenderHistoryRepository, type SenderHistoryItem } from "./sender-history.js";
import type { OpenKeyShareSession, ShareTinyCloud } from "./openkey-session.js";
import { revokeShare } from "@tinycloud/share-sdk";

export interface SenderHomeOptions {
  readonly session: OpenKeyShareSession;
  readonly tinycloud: ShareTinyCloud;
  readonly history: SenderHistoryRepository;
  /** Hands control back to the router. The library never mounts another screen itself (P0-1). */
  readonly onNavigate: (route: string) => void;
}

function node<K extends keyof HTMLElementTagNameMap>(doc: Document, tag: K, className: string, text?: string): HTMLElementTagNameMap[K] {
  const item = doc.createElement(tag);
  item.className = className;
  if (text !== undefined) item.textContent = text;
  return item;
}

function safeName(record: Extract<SenderHistoryItem, { state: "ready" | "expired" | "revoked" }> ["record"]): string {
  const name = record.filename ?? record.resource.path.replace(/\/+$/, "").split("/").at(-1) ?? "Shared document";
  return name.length > 80 ? `${name.slice(0, 77)}…` : name;
}

function recipientSummary(item: Extract<SenderHistoryItem, { state: "ready" | "expired" | "revoked" }>): string {
  const matcher = item.record.recipientMatcher;
  if (matcher.kind === "bearer") return "Anyone with link";
  if (matcher.kind === "recipientDid") return "OpenKey recipient";
  if (matcher.kind === "emailDomain") return `Anyone at ${matcher.value}`;
  const [local, domain] = matcher.value.split("@");
  return `Only ${(local?.slice(0, 1) ?? "•")}***@${domain ?? "…"}`;
}

function actionsSummary(actions: readonly string[]): string {
  return actions.map((action) => action.includes("list") ? "Browse" : action.includes("put") ? "Edit" : "View").join(" / ");
}

export function mountSenderHome(root: HTMLElement, options: SenderHomeOptions): void {
  const doc = root.ownerDocument;
  root.removeAttribute("aria-busy");
  root.replaceChildren();
  const shell = node(doc, "main", "sender-shell sender-home");
  const header = node(doc, "header", "sender-header sender-home-header");
  header.append(node(doc, "p", "sender-kicker", "Signed in"), node(doc, "h1", "sender-title", "Shared by me."), node(doc, "p", "sender-lede", "Everything you've shared. Links stay private until you copy them."));
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
  const empty = node(doc, "div", "sender-empty-state"); empty.hidden = true;
  const more = node(doc, "button", "button button-secondary sender-load-more", "Load more") as HTMLButtonElement; more.type = "button"; more.hidden = true;
  const error = node(doc, "div", "sender-status"); error.hidden = true; error.setAttribute("role", "alert");
  content.append(title, table, empty, more, error); shell.append(header, toolbar, live, content); root.append(shell);

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
    const help = node(doc, "p", "sender-status-detail", "Paste a share link you already have. It's checked and encrypted here before it's saved.");
    const label = node(doc, "label", "field-label", "Complete share link"); const input = node(doc, "input", "field-input") as HTMLInputElement; input.type = "url"; input.required = true; input.autocomplete = "off"; label.append(input);
    const save = node(doc, "button", "button button-primary", "Save encrypted link") as HTMLButtonElement; save.type = "submit";
    const cancel = node(doc, "button", "button button-secondary", "Cancel") as HTMLButtonElement; cancel.type = "button"; cancel.addEventListener("click", () => dialog.close());
    const message = node(doc, "p", "sender-live"); form.append(heading, help, label, save, cancel, message); dialog.append(form); root.append(dialog); dialog.showModal(); input.focus();
    form.addEventListener("submit", (event) => { event.preventDefault(); const value = input.value.trim(); try { const parsed = new URL(value); const fragment = new URLSearchParams(parsed.hash.slice(1)); if ((parsed.protocol !== "https:" && parsed.protocol !== "http:") || parsed.username || parsed.password || parsed.pathname !== "/viewer" || parsed.search !== "" || fragment.size !== 1 || !fragment.get("tc1")) throw new Error("invalid"); const record = importSenderHistoryRecord(value); void options.history.save(record).then(() => { dialog.close(); dialog.remove(); void load(false); }).catch(() => { message.textContent = "That link could not be validated or saved."; }); } catch { message.textContent = "Enter a complete TinyCloud bearer link."; } });
  };
  // A first run is not a table row. The table and its six column headers stay
  // out of the way entirely until there is something to put in them (P1-8).
  const renderEmpty = (): void => {
    table.hidden = true; empty.hidden = false;
    empty.replaceChildren(node(doc, "h3", "sender-empty-title", "No shares yet"), node(doc, "p", "sender-empty-copy", "Upload a file and get a private link in about ten seconds."));
    const share = node(doc, "button", "button button-primary", "Share a file") as HTMLButtonElement; share.type = "button"; share.addEventListener("click", () => options.onNavigate("#/new"));
    const importLink = node(doc, "button", "sender-empty-import", "Import a link you already have") as HTMLButtonElement; importLink.type = "button"; importLink.addEventListener("click", openImport);
    empty.append(share, importLink);
  };
  const renderItem = (item: SenderHistoryItem): void => {
    const row = node(doc, "tr", "sender-history-row");
    if (item.state === "needs-attention") {
      const cell = node(doc, "td", "sender-history-attention"); cell.colSpan = 5; cell.append(node(doc, "strong", "", "Needs attention"), node(doc, "span", "", "We couldn't read this saved entry.")); const retry = node(doc, "button", "button button-secondary", "Retry") as HTMLButtonElement; retry.type = "button"; retry.addEventListener("click", () => { void load(false); }); const remove = node(doc, "button", "button button-secondary", "Remove saved entry") as HTMLButtonElement; remove.type = "button"; remove.addEventListener("click", () => { if (!window.confirm("Remove this saved entry?")) return; remove.disabled = true; void options.history.remove(item.key).then(() => load(false)).catch(() => { remove.disabled = false; live.textContent = "The saved entry could not be removed. Try again."; }); }); cell.append(retry, remove); row.append(cell, node(doc, "td", "", "—")); body.append(row); return;
    }
    const itemCell = node(doc, "td", "sender-item-cell"); itemCell.append(node(doc, "strong", "", safeName(item.record)), node(doc, "span", "sender-item-type", item.record.resource.kind === "prefix" ? "Folder" : "File"));
    const recipient = node(doc, "td", "", recipientSummary(item)); recipient.dataset.label = "Recipient";
    const access = node(doc, "td", "", actionsSummary(item.record.actions)); access.dataset.label = "Access";
    const statusLabel = item.state === "revoked" ? "Revoked" : item.state === "expired" ? "Expired" : "Ready";
    const status = node(doc, "td", `sender-status-text ${item.state}`); status.dataset.label = "Expires / status"; status.append(node(doc, "span", "status-label", statusLabel), node(doc, "span", "status-expiry", new Date(item.record.expiresAt).toLocaleDateString()));
    const created = node(doc, "td", "", new Date(item.record.registeredAt).toLocaleDateString()); created.dataset.label = "Created";
    const controls = node(doc, "td", "sender-row-actions");
    const copy = node(doc, "button", "button button-secondary", "Copy link") as HTMLButtonElement; copy.type = "button"; copy.setAttribute("aria-label", `Copy link for ${safeName(item.record)}`); copy.addEventListener("click", () => { copy.disabled = true; void options.history.show(item.record.shareId, true).then((view) => { if (view.link === undefined) throw new Error("share-link-unavailable"); return copyWithFallback(view.link); }).then(() => { live.textContent = "Link copied."; }).catch(() => { live.textContent = "Copy failed. Try again after allowing clipboard access."; }).finally(() => { copy.disabled = false; }); });
    const open = node(doc, "button", "button button-secondary", "Open") as HTMLButtonElement; open.type = "button"; open.setAttribute("aria-label", `Open ${safeName(item.record)}`); open.addEventListener("click", () => { open.disabled = true; void options.history.show(item.record.shareId, true).then((view) => { if (view.link === undefined) throw new Error("share-link-unavailable"); openSenderViewer(view.link, live); }).catch(() => { live.textContent = "The share link could not be opened. Try again."; }).finally(() => { open.disabled = false; }); });
    itemCell.dataset.label = "Item"; controls.dataset.label = "Actions"; row.tabIndex = -1; controls.append(open, copy);
    if (item.state !== "revoked") {
      const revoke = node(doc, "button", "button button-secondary sender-revoke", "Revoke") as HTMLButtonElement; revoke.type = "button"; revoke.setAttribute("aria-label", `Revoke ${safeName(item.record)}`);
      if (item.record.enforcementDelegationCid === undefined && item.record.ownerDelegationCid === undefined) {
        // Imported bearer links may not have a revocation authority.
        revoke.disabled = true;
        revoke.title = "This saved link can't be revoked because its revocation authority is missing.";
        revoke.classList.add("sender-revoke-unavailable");
      } else {
        revoke.addEventListener("click", () => {
          if (!window.confirm("Revoke this share? Everyone who has the link loses access immediately, including anyone they passed it to. This can't be undone.")) return;
          revoke.disabled = true; live.textContent = "Revoking…";
          void revokeShare({
            record: item.record,
            records: options.history.records,
            adapter: {
              revokeDelegation: async ({ delegationCid }) => {
                const result = await options.tinycloud.revokeDelegation(delegationCid);
                if (!result.ok) throw new Error("revoke-rejected");
              },
            },
          }).then((result) => {
            if (result.state !== "revoked") throw new Error("revoke-unsupported");
          }).then(() => { live.textContent = "Share revoked."; return load(false); }).catch(() => { revoke.disabled = false; live.textContent = "Revoke didn't go through — the share is still active. Try again."; });
        });
      }
      controls.append(revoke);
    }
    row.append(itemCell, recipient, access, status, created, controls); body.append(row); pageRows.push(row);
  };
  const load = async (append: boolean): Promise<void> => {
    if (loading) return;
    loading = true; error.hidden = true; table.setAttribute("aria-busy", "true"); if (!append) { cursor = undefined; pageRows.length = 0; table.hidden = false; empty.hidden = true; renderSkeleton(); }
    try {
      const page = await options.history.page(cursor);
      if (!append) body.replaceChildren();
      if (page.items.length === 0 && !append) renderEmpty();
      page.items.forEach(renderItem); cursor = page.nextCursor; more.hidden = !page.truncated; if (page.items.length > 0) live.textContent = append ? `${page.items.length} more shares loaded.` : `${page.items.length} shares loaded.`;
    } catch (caught) {
      if (import.meta.env.VITE_SHARE_HERMETIC === "true") (window as Window & { __tinycloudSenderHistoryError?: string }).__tinycloudSenderHistoryError = caught instanceof Error ? caught.message : String(caught);
      if (!append && initialLoadRetries < 3) {
        initialLoadRetries += 1;
        live.textContent = "Loading your shares…";
        window.setTimeout(() => { void load(false); }, 250);
        return;
      }
      error.hidden = false; error.replaceChildren(node(doc, "strong", "sender-status-title", "Could not load shares"), node(doc, "span", "sender-status-detail", "Couldn't load your shares. Try again.")); const retry = node(doc, "button", "button button-secondary", "Retry") as HTMLButtonElement; retry.type = "button"; retry.addEventListener("click", () => { void load(false); }); error.append(retry);
    } finally { table.removeAttribute("aria-busy"); loading = false; }
  };
  newShare.addEventListener("click", () => options.onNavigate("#/new"));
  more.addEventListener("click", () => { const firstNew = pageRows.length; void load(true).then(() => pageRows[firstNew]?.focus?.()); });
  void load(false);
}

function openSenderViewer(url: string, live: HTMLElement): void {
  try { window.open(url, "_self", "noreferrer"); } catch { live.textContent = "The viewer could not be opened."; }
}
