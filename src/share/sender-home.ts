import { copyWithFallback } from "./clipboard.js";
import { importSenderHistoryRecord, SenderHistoryRepository, type SenderHistoryItem } from "./sender-history.js";
import { takeWalletApprovalFailure, type OpenKeyShareSession, type ShareTinyCloud } from "./openkey-session.js";
import { revokeShare, type SenderShareRecord } from "@tinycloud/share-sdk";
import { getPolicyRootStatusV3, revokePolicyRootV3 } from "@tinycloud/sdk-core";
import { httpStatusOf, revokeFailureMessage } from "./sender-failure.js";
import { verifyShareRootOnNode, type ShareRootKind } from "./owner-revoke.js";

/** The owner wallet's revocation request is valid for this long from the moment the approval is asked for. */
const APPROVAL_WINDOW_MS = 60_000;

export interface SenderHomeOptions {
  readonly session: OpenKeyShareSession;
  readonly tinycloud: ShareTinyCloud;
  readonly history: SenderHistoryRepository;
  /** Hands control back to the router. The library never mounts another screen itself (P0-1). */
  readonly onNavigate: (route: string) => void;
}

/**
 * TC-601. sdk-core 3.0.0-beta.19 stamps a policy root revocation with
 * `toISOString()`, and the Node refuses a time it can't reproduce exactly:
 * its RFC 3339 formatter drops trailing zeros, so `.120Z` came back as
 * `.12Z` and about one Revoke in ten failed with 403. A millisecond that
 * doesn't end in 0 round-trips, so nudge those forward by one. Harmless and
 * removable once Share uses sdk-core 3.1.0-beta.3 or later, which stamps
 * whole seconds.
 */
export function nodeReproducibleRevocationTime(now: Date = new Date()): Date {
  return now.getUTCMilliseconds() % 10 === 0 ? new Date(now.getTime() + 1) : now;
}

function node<K extends keyof HTMLElementTagNameMap>(doc: Document, tag: K, className: string, text?: string): HTMLElementTagNameMap[K] {
  const item = doc.createElement(tag);
  item.className = className;
  if (text !== undefined) item.textContent = text;
  return item;
}

export const REVOKE_CONFIRM_TITLE = "Revoke this share?";
export const REVOKE_CONFIRM_BODY = "Everyone who has the link loses access immediately, including anyone they passed it to. This can't be undone.";
export const REVOKE_CONFIRM_CAVEAT = "Anyone holding a share link can also revoke it.";

/** In-page confirmation. Resolves true only on the explicit "Revoke share" press; Esc, Cancel and the backdrop resolve false. */
function confirmRevoke(root: HTMLElement, name: string, opener: HTMLElement, onConfirm: () => void): Promise<boolean> {
  const doc = root.ownerDocument;
  return new Promise((resolve) => {
    const dialog = node(doc, "dialog", "sender-confirm-dialog") as HTMLDialogElement;
    const titleId = `sender-confirm-title-${Math.random().toString(36).slice(2, 8)}`;
    dialog.setAttribute("aria-labelledby", titleId); dialog.setAttribute("role", "alertdialog");
    const heading = node(doc, "h2", "sender-confirm-title", REVOKE_CONFIRM_TITLE); heading.id = titleId;
    const subject = node(doc, "p", "sender-confirm-subject", name);
    const body = node(doc, "p", "sender-status-detail", REVOKE_CONFIRM_BODY);
    const caveat = node(doc, "p", "sender-status-detail", REVOKE_CONFIRM_CAVEAT);
    const actions = node(doc, "div", "sender-confirm-actions");
    const cancel = node(doc, "button", "button button-secondary", "Cancel") as HTMLButtonElement; cancel.type = "button";
    const confirm = node(doc, "button", "button button-danger sender-confirm-revoke", "Revoke share") as HTMLButtonElement; confirm.type = "button";
    actions.append(cancel, confirm); dialog.append(heading, subject, body, caveat, actions);
    const finish = (result: boolean): void => { if (result) onConfirm(); dialog.remove(); if (opener.isConnected) opener.focus(); resolve(result); };
    cancel.addEventListener("click", () => finish(false));
    confirm.addEventListener("click", () => finish(true));
    dialog.addEventListener("cancel", (event) => { event.preventDefault(); finish(false); });
    dialog.addEventListener("click", (event) => { if (event.target === dialog) finish(false); });
    root.append(dialog);
    // Engines without <dialog> modal support still show it, open in place.
    if (typeof dialog.showModal === "function") dialog.showModal(); else dialog.setAttribute("open", "");
    cancel.focus();
  });
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
  type LibraryItem = Extract<SenderHistoryItem, { state: "ready" | "expired" | "revoked" }>;
  /** Shares with a revoke open, from the confirmation to the answer. One per share, whatever rebuilds the rows. */
  const revoking = new Set<string>();
  /**
   * TC-721. Revoke is confirmed in the page, never with `window.confirm`: a
   * native dialog is dismissed without a trace by automation, embedded
   * webviews and a browser's "block further dialogs", and the handler then
   * returned before showing anything, so Revoke looked dead. Every outcome
   * after the click is visible on the row: pending, revoked, or the reason.
   */
  const revokeRow = async (item: LibraryItem, revoke: HTMLButtonElement, status: HTMLElement, controls: HTMLElement): Promise<void> => {
    const shareId = item.record.shareId;
    // One revoke per share, and one confirmation at a time: a second click or Enter never starts a second revoke (a second wallet request).
    if (revoking.has(shareId) || root.querySelector(".sender-confirm-dialog") !== null) return;
    let hint: HTMLElement | undefined;
    let owned = false;
    try {
      const name = safeName(item.record);
      controls.querySelector(".sender-row-error")?.remove();
      if (!(await confirmRevoke(root, name, revoke, () => { revoking.add(shareId); owned = true; }))) return;
      const label = status.querySelector(".status-label");
      const priorLabel = label?.textContent ?? "";
      revoke.disabled = true; revoke.textContent = "Revoking…"; revoke.setAttribute("aria-busy", "true");
      status.classList.add("pending"); if (label) label.textContent = "Revoking…";
      live.textContent = "Revoking…";
      /**
       * The creating session is gone, or this is a link-only share: the
       * owner's wallet revokes that one delegation, with one approval. The
       * saved record only names the CID; the node must first show it is a
       * share root of this account, or nothing is signed.
       */
      const revokeWithOwnerWallet = async (current: SenderShareRecord, cid: string | undefined, kind: ShareRootKind, activeNode: { readonly origin: string; readonly nodeDid: string }): Promise<void> => {
        const state = await verifyShareRootOnNode({ tinycloud: options.tinycloud, address: options.session.address, node: activeNode, record: current, cid, kind });
        // The node already has it revoked (another tab, an earlier attempt): nothing to sign.
        if (state === "revoked" || cid === undefined) return;
        hint = node(doc, "p", "sender-row-hint", "Approve in the OpenKey window to revoke"); hint.setAttribute("role", "status");
        controls.append(hint);
        // A failure left by an earlier approval is not this one's.
        takeWalletApprovalFailure(options.tinycloud);
        const started = Date.now();
        const outcome = await options.tinycloud.revokeDelegation(cid);
        if (outcome.ok) return;
        // The OpenKey window's own answer: a cancel is the sender's choice, not a node refusal.
        const approval = takeWalletApprovalFailure(options.tinycloud);
        if (approval !== undefined) throw new Error(`revoke-approval-${approval}`);
        // A lost race or a retry after a lost response: ask the node, never the policy-status route, which disagrees with itself after a wallet revocation.
        const after = await options.tinycloud.delegations.status(cid).catch(() => undefined);
        if (after?.ok === true && after.data.status === "revoked") return;
        const code = httpStatusOf(outcome) ?? (outcome.error.code === "NOT_FOUND" ? 404 : undefined);
        // The wallet signs a request that is good for 60 seconds from the moment the approval was asked for.
        if ((code === 401 || code === 403) && Date.now() - started >= APPROVAL_WINDOW_MS - 5_000) throw new Error("revoke-approval-expired");
        throw Object.assign(new Error("revoke-rejected"), { status: code });
      };
      let revoked = false;
      try {
        // The row holds display fields only; read the full record (with delivery material) when the owner confirms.
        const current = await options.history.records.get(item.record.shareId);
        if (current === undefined) throw new Error("share-not-found");
        const result = await revokeShare({
          record: current,
          records: options.history.records,
          adapter: {
            revokeDelegation: async ({ delegationCid, record }) => {
              await revokeWithOwnerWallet(record, delegationCid, "bearer", await options.tinycloud.activeNodeIdentity());
            },
            revokePolicyRoot: async (request) => {
              const activeNode = await options.tinycloud.activeNodeIdentity();
              // Sender history is encrypted client state, not authority. Bind
              // its root identifiers to the currently authenticated owner node
              // before signing a generic Policy/v3 revocation.
              if (request.nodeOrigin !== activeNode.origin || request.nodeAudience !== activeNode.nodeDid) throw new Error("revoke-unbound-policy-root");
              // Signed by an earlier session key of this sign-in's account: only the owner's wallet can revoke it now.
              if (request.ownerDid !== options.tinycloud.credentialHolderDid) {
                await revokeWithOwnerWallet(current, current.ownerDelegationCid, "policy-root", activeNode);
                return;
              }
              try {
                await revokePolicyRootV3({
                  nodeOrigin: activeNode.origin,
                  rootCid: request.rootCid,
                  targetRole: request.targetRole,
                  ownerDid: options.tinycloud.credentialHolderDid,
                  issuerDid: options.tinycloud.credentialHolderDid,
                  nodeAudience: activeNode.nodeDid,
                  reason: "share revoked",
                  now: nodeReproducibleRevocationTime(),
                  sign: (digest) => options.tinycloud.signSessionBytes(digest),
                });
              } catch (caught) {
                // TC-657. A retry after a lost response signs a new
                // `revokedAt`, and the Node, already holding the first
                // revocation, answers 409 root-revocation-irreversible.
                // Ask the Node whether the root is revoked before calling
                // the revoke a failure.
                if (httpStatusOf(caught) !== 409) throw caught;
                const state = await getPolicyRootStatusV3({ nodeOrigin: activeNode.origin, rootCid: request.rootCid, expectedNodeAudience: activeNode.nodeDid }).catch(() => undefined);
                if (state?.state !== "revoked") throw caught;
              }
            },
          },
        });
        if (result.state !== "revoked") throw new Error("revoke-unsupported");
        revoked = true;
      } catch (caught) {
        // Only a status code or a fixed reason is shown; the error text can carry a response body.
        status.classList.remove("pending"); if (label) label.textContent = priorLabel;
        revoke.disabled = false; revoke.textContent = "Revoke"; revoke.removeAttribute("aria-busy");
        const message = revokeFailureMessage(caught);
        const detail = node(doc, "p", "sender-row-error", message); detail.setAttribute("role", "alert");
        controls.append(detail);
        live.textContent = "";
      }
      if (revoked) {
        status.classList.remove("pending", "ready", "expired"); status.classList.add("revoked");
        if (label) label.textContent = "Revoked";
        revoke.remove();
        live.textContent = "Share revoked.";
      }
    } finally {
      if (owned) revoking.delete(shareId);
      hint?.remove();
    }
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
        revoke.addEventListener("click", () => { void revokeRow(item, revoke, status, controls); });
      }
      controls.append(revoke);
    }
    row.append(itemCell, recipient, access, status, created, controls); body.append(row); pageRows.push(row);
  };
  const load = async (append: boolean): Promise<void> => {
    if (loading) return;
    loading = true; error.hidden = true; table.setAttribute("aria-busy", "true"); if (!append) { cursor = undefined; pageRows.length = 0; table.hidden = false; empty.hidden = true; more.hidden = true; renderSkeleton(); }
    // True while an automatic retry is scheduled: the load is still pending, so the busy state must not drop in between.
    let retryScheduled = false;
    try {
      const page = await options.history.page(cursor);
      if (!append) body.replaceChildren();
      if (page.items.length === 0 && !append) renderEmpty();
      page.items.forEach(renderItem); cursor = page.nextCursor; more.hidden = !page.truncated; if (page.items.length > 0) live.textContent = append ? `${page.items.length} more shares loaded.` : `${page.items.length} shares loaded.`;
    } catch (caught) {
      if (import.meta.env.VITE_SHARE_HERMETIC === "true") (window as Window & { __tinycloudSenderHistoryError?: string }).__tinycloudSenderHistoryError = caught instanceof Error ? caught.message : String(caught);
      if (!append && initialLoadRetries < 3) {
        initialLoadRetries += 1; retryScheduled = true;
        live.textContent = "Loading your shares…";
        window.setTimeout(() => { void load(false); }, 250);
        return;
      }
      // A failed first load leaves nothing to show: drop the loading placeholders and the table so the error stands alone.
      if (!append) { body.replaceChildren(); table.hidden = true; more.hidden = true; }
      live.textContent = "";
      error.hidden = false; error.replaceChildren(node(doc, "strong", "sender-status-title", "Could not load shares"), node(doc, "span", "sender-status-detail", "Couldn't load your shares. Try again.")); const retry = node(doc, "button", "button button-secondary", "Retry") as HTMLButtonElement; retry.type = "button"; retry.addEventListener("click", () => { live.textContent = "Loading your shares…"; void load(false); }); error.append(retry);
    } finally { if (!retryScheduled) table.removeAttribute("aria-busy"); loading = false; }
  };
  newShare.addEventListener("click", () => options.onNavigate("#/new"));
  more.addEventListener("click", () => { const firstNew = pageRows.length; void load(true).then(() => pageRows[firstNew]?.focus?.()); });
  void load(false);
}

function openSenderViewer(url: string, live: HTMLElement): void {
  try { window.open(url, "_self", "noreferrer"); } catch { live.textContent = "The viewer could not be opened."; }
}
