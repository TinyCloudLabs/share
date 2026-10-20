import { copyWithFallback } from "./clipboard.js";
import { importSenderHistoryRecord, SenderHistoryRepository, type SenderHistoryItem } from "./sender-history.js";
import { takeWalletApprovalFailure, type OpenKeyShareSession, type ShareTinyCloud } from "./openkey-session.js";
import { revokeShare, type SenderShareRecord } from "@tinycloud/share-sdk";
import { getPolicyRootStatusV3, revokePolicyRootV3 } from "@tinycloud/sdk-core";
import { httpStatusOf, revokeFailureMessage, revokeOutcomeIsNeutral } from "./sender-failure.js";
import { activeFlight, APPROVAL_WINDOW_MS, flightKey, RevokeFlight, withWalletApproval } from "./revoke-flight.js";
import { verifyShareRootOnNode, type ShareRootKind } from "./owner-revoke.js";
import { confirmDialog } from "./confirm-dialog.js";
import { showApprovalHint, type ApprovalHint } from "./approval-hint.js";
import { artifactKindOf, ARTIFACT_KIND_LABEL } from "./artifact-kind.js";
import type { NodeShareStatus, NodeStatusReader } from "./node-status.js";

const APPROVAL_HINT = "Approve in the OpenKey window to revoke";

export interface SenderHomeOptions {
  readonly session: OpenKeyShareSession;
  readonly tinycloud: ShareTinyCloud;
  readonly history: SenderHistoryRepository;
  /** Hands control back to the router. The library never mounts another screen itself (P0-1). */
  readonly onNavigate: (route: string) => void;
  /** TC-1584. Asks the owner's node for each share's state. Without it the library shows only what was saved here. */
  readonly statusReader?: NodeStatusReader;
}

/** Back in the tab after this long, statuses are asked for again. */
const FOCUS_RECHECK_MS = 15_000;
/** The focus and visibility listeners of the mounted library; mounting again ends the earlier ones. */
let libraryScope: AbortController | undefined;

/** Sign-out: the mounted library stops listening and an open status check is abandoned. */
export function endSenderLibrary(): void {
  libraryScope?.abort();
  libraryScope = undefined;
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
/** True for a link: every holder of it, and anyone it was passed on to, holds the one delegation that is revoked. */
export const REVOKE_CONFIRM_BODY = "Everyone who has the link loses access right away, including anyone they passed it to. This can't be undone.";
export const REVOKE_CONFIRM_BODY_ADDRESSED = "The people you shared it with lose access right away. This can't be undone.";
/** The app's session cannot delete (`del` is not in its grant), so a stored copy outlives a revoke. */
export const REVOKE_CONFIRM_STORED = "Revoking stops access. The encrypted copy stays in your TinyCloud until you delete it, and Share can't delete it yet. Anyone who already downloaded or copied the content keeps their copy.";
export const REVOKE_CONFIRM_CAVEAT = "Anyone holding a share link can also revoke it.";
export const REVOKE_APPROVAL_TIMEOUT_COPY = "OpenKey is still waiting for you. The share is still active. Cancel and try again.";

export const FRESHNESS_CHECKING = "Checking each share with TinyCloud…";
export const FRESHNESS_UNCONFIRMED = "Couldn't confirm every share with TinyCloud, so statuses may be out of date: a share revoked or expired elsewhere can still show as Ready.";
export const FRESHNESS_TIMEOUT = "TinyCloud didn't answer in time, so statuses may be out of date: a share revoked or expired elsewhere can still show as Ready.";
export const CHECK_STATUS_LABEL = "Check status";
export const CHECK_AGAIN_LABEL = "Check again";
/** How long one status check waits for the node before the statuses are called unconfirmed. */
export const STATUS_CHECK_TIMEOUT_MS = 4_000;
export function freshnessConfirmed(at: Date): string {
  return `Statuses confirmed with TinyCloud at ${at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}.`;
}

type RowKind = "ready" | "pending" | "expired" | "revoked";
const TONE: Record<RowKind, string> = { ready: "success", pending: "info", expired: "warning", revoked: "danger" };
const KIND_LABEL: Record<RowKind, string> = { ready: "Ready", pending: "Revoking…", expired: "Expired", revoked: "Revoked" };

/** One place that decides how a row's status reads: the label, its tone, and the line under it. */
function paintStatus(status: HTMLElement, kind: RowKind, expiresAt: string, endedOn?: string | null): void {
  status.classList.remove("ready", "pending", "expired", "revoked"); status.classList.add(kind);
  status.dataset.kind = kind; status.dataset.expiresAt = expiresAt;
  // `endedOn` is only for a share the node reports expired: undefined = the saved expiry, null = the node gave no date, so none is shown.
  if (endedOn !== undefined) status.dataset.endedOn = endedOn === null ? "none" : endedOn;
  const label = status.querySelector(".status-label"); const detail = status.querySelector(".status-expiry");
  if (label !== null) { label.className = `status-label tc-status tc-status--${TONE[kind]}`; label.textContent = KIND_LABEL[kind]; }
  const ended = status.dataset.endedOn;
  const expiredText = ended === "none" ? "Expired" : `Expired ${new Date(ended ?? expiresAt).toLocaleDateString()}`;
  if (detail !== null) detail.textContent = kind === "revoked" ? "Access ended" : kind === "expired" ? expiredText : `Expires ${new Date(expiresAt).toLocaleDateString()}`;
}

/** The earlier of what the node says and what was saved; no date at all when the node said none (a later saved expiry would read as a wrong end). */
function earlierEnd(nodeEnd: string | undefined, saved: string): string | null {
  if (nodeEnd === undefined) return null;
  const node = Date.parse(nodeEnd); const recorded = Date.parse(saved);
  return Number.isFinite(recorded) && recorded < node ? saved : nodeEnd;
}

interface RowHandle {
  readonly item: Extract<SenderHistoryItem, { state: "ready" | "expired" | "revoked" }>;
  readonly status: HTMLElement;
  readonly controls: HTMLElement;
  revoke?: HTMLButtonElement;
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
  const newShare = node(doc, "button", "button button-primary tc-button tc-button--primary", "New share") as HTMLButtonElement; newShare.type = "button";
  const recheck = node(doc, "button", "button button-secondary tc-button tc-button--compact sender-recheck", CHECK_STATUS_LABEL) as HTMLButtonElement; recheck.type = "button"; recheck.hidden = options.statusReader === undefined;
  toolbar.append(newShare, recheck);
  const freshness = node(doc, "p", "sender-freshness tc-help"); freshness.hidden = true; freshness.setAttribute("role", "status"); freshness.setAttribute("aria-live", "polite");
  libraryScope?.abort();
  const scope = new AbortController(); libraryScope = scope;
  const live = node(doc, "p", "sender-live"); live.setAttribute("role", "status"); live.setAttribute("aria-live", "polite");
  // Spoken only: the row already shows the approval hint and the notes, so the visible live line must not repeat them.
  const announce = node(doc, "p", "sr-only sender-announce"); announce.setAttribute("role", "status"); announce.setAttribute("aria-live", "polite");
  /** A region is announced when its text changes after it exists, so clear it and set the text a moment later (also right after a mount). */
  const say = (text: string): void => { announce.textContent = ""; window.setTimeout(() => { announce.textContent = text; }, 100); };
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
  content.append(title, table, empty, more, error); shell.append(header, toolbar, freshness, live, announce, content); root.append(shell);
  const rows = new Map<string, RowHandle>();

  const pageRows: HTMLElement[] = [];
  let cursor: string | undefined;
  let loading = false;
  let initialLoadRetries = 0;
  const renderSkeleton = (): void => {
    body.replaceChildren(); rows.clear();
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
  /**
   * Paints one row as revoking and follows the flight to its end: Revoked, or
   * the reason. The row that started the revoke and a row mounted later (the
   * sender left the library and came back) follow the same flight.
   */
  const followFlight = (flight: RevokeFlight, revoke: HTMLButtonElement, status: HTMLElement, controls: HTMLElement): void => {
    const prior = { kind: (status.dataset.kind ?? "ready") as RowKind, expiresAt: status.dataset.expiresAt ?? "" };
    // The visible text changes to "Revoking…", so the accessible name does too (it must contain the visible text).
    const idleLabel = revoke.getAttribute("aria-label");
    revoke.disabled = true; revoke.textContent = "Revoking…"; revoke.setAttribute("aria-busy", "true");
    if (idleLabel !== null) revoke.setAttribute("aria-label", idleLabel.replace(/^Revoke /, "Revoking "));
    paintStatus(status, "pending", prior.expiresAt);
    live.textContent = "Revoking…";
    let hint: ApprovalHint | undefined;
    // The hint lives exactly as long as the wallet approval: it is removed the moment the approval closes, not when the whole revoke ends.
    const repaint = (): void => {
      if (flight.approval && hint === undefined) {
        hint = showApprovalHint(controls, { text: APPROVAL_HINT, lineClass: "sender-row-hint", timeoutCopy: REVOKE_APPROVAL_TIMEOUT_COPY, onCancel: () => options.session.openkey.disconnect() });
        // The inserted node is not announced reliably; the persistent spoken region is, also for a row mounted while the approval is open.
        say(`${APPROVAL_HINT}.`);
      } else if (!flight.approval && hint !== undefined) {
        hint.dispose(); hint = undefined;
      }
    };
    flight.subscribers.add(repaint); repaint();
    void flight.done.then((outcome) => {
      flight.subscribers.delete(repaint); hint?.dispose(); hint = undefined;
      if (outcome.revoked) {
        paintStatus(status, "revoked", prior.expiresAt);
        revoke.remove();
        live.textContent = "Share revoked.";
        return;
      }
      // Only a status code or a fixed reason is shown; the error text can carry a response body.
      paintStatus(status, prior.kind, prior.expiresAt);
      revoke.disabled = false; revoke.textContent = "Revoke"; revoke.removeAttribute("aria-busy");
      if (idleLabel !== null) revoke.setAttribute("aria-label", idleLabel);
      const message = revokeFailureMessage(outcome.failure);
      // A cancel, or another approval still open, is not an error: a quiet note, not an alert.
      if (revokeOutcomeIsNeutral(outcome.failure)) {
        controls.append(node(doc, "p", "sender-row-note", message));
        live.textContent = "";
        say(message);
        return;
      }
      const detail = node(doc, "p", "sender-row-error", message); detail.setAttribute("role", "alert");
      controls.append(detail);
      live.textContent = "";
    });
  };
  /** The revoke itself: no DOM, so it can finish while the library is not on screen. */
  const performRevoke = async (shareId: string, flight: RevokeFlight): Promise<void> => {
    /**
     * The creating session is gone, or this is a link-only share: the owner's
     * wallet revokes that one delegation, with one approval. The saved record
     * only names the CID; the node must first show it is a share root of this
     * account, or nothing is signed.
     */
    const revokeWithOwnerWallet = async (current: SenderShareRecord, cid: string | undefined, kind: ShareRootKind, activeNode: { readonly origin: string; readonly nodeDid: string }): Promise<void> => {
      const state = await verifyShareRootOnNode({ tinycloud: options.tinycloud, address: options.session.address, node: activeNode, record: current, cid, kind });
      // The node already has it revoked (another tab, an earlier attempt): nothing to sign.
      if (state === "revoked" || cid === undefined) return;
      let started = Date.now();
      // One OpenKey approval at a time, so the window's answer is read for the request that asked.
      const { outcome, approval } = await withWalletApproval(flight, async (current) => {
        // A failure left by an earlier approval is not this one's.
        takeWalletApprovalFailure(options.tinycloud);
        started = Date.now();
        const result = await options.tinycloud.revokeDelegation(cid);
        // The OpenKey window's own answer: a cancel is the sender's choice, not a node refusal. A request already given up on must not consume a newer attempt's answer.
        return { outcome: result, approval: result.ok || !current() ? undefined : takeWalletApprovalFailure(options.tinycloud) };
      });
      if (outcome.ok) return;
      if (approval !== undefined) throw new Error(`revoke-approval-${approval}`);
      // A lost race or a retry after a lost response: ask the node, never the policy-status route, which disagrees with itself after a wallet revocation.
      const after = await options.tinycloud.delegations.status(cid).catch(() => undefined);
      if (after?.ok === true && after.data.status === "revoked") return;
      const code = httpStatusOf(outcome) ?? (outcome.error.code === "NOT_FOUND" ? 404 : undefined);
      // The wallet signs a request that is good for 60 seconds from the moment the approval was asked for.
      if ((code === 401 || code === 403) && Date.now() - started >= APPROVAL_WINDOW_MS - 5_000) throw new Error("revoke-approval-expired");
      throw Object.assign(new Error("revoke-rejected"), { status: code });
    };
    // The row holds display fields only; read the full record (with delivery material) when the owner confirms.
    const current = await options.history.records.get(shareId);
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
  };
  /**
   * TC-721. Revoke is confirmed in the page, never with `window.confirm`: a
   * native dialog is dismissed without a trace by automation, embedded
   * webviews and a browser's "block further dialogs", and the handler then
   * returned before showing anything, so Revoke looked dead. Every outcome
   * after the click is visible on the row: pending, revoked, or the reason.
   */
  const revokeRow = async (item: LibraryItem, revoke: HTMLButtonElement, status: HTMLElement, controls: HTMLElement): Promise<void> => {
    const shareId = item.record.shareId;
    const key = flightKey(options.session.address, shareId);
    // One revoke per share for the whole page session, and one confirmation at a time: a second click, Enter or re-mounted row never starts a second revoke (a second wallet request).
    if (activeFlight(key) !== undefined || root.querySelector(".sender-confirm-dialog") !== null) return;
    controls.querySelector(".sender-row-error, .sender-row-note")?.remove();
    const started: { flight?: RevokeFlight } = {};
    const bearer = item.record.recipientMatcher.kind === "bearer";
    const confirmed = await confirmDialog(root, {
      title: REVOKE_CONFIRM_TITLE, subject: safeName(item.record), confirmLabel: "Revoke share", danger: true, opener: revoke,
      paragraphs: bearer ? [REVOKE_CONFIRM_BODY, REVOKE_CONFIRM_STORED, REVOKE_CONFIRM_CAVEAT] : [REVOKE_CONFIRM_BODY_ADDRESSED, REVOKE_CONFIRM_STORED],
      onConfirm: () => { started.flight = new RevokeFlight(key, (flight) => performRevoke(shareId, flight)); },
    });
    if (confirmed && started.flight !== undefined) followFlight(started.flight, revoke, status, controls);
  };
  const renderItem = (item: SenderHistoryItem): void => {
    const row = node(doc, "tr", "sender-history-row");
    if (item.state === "needs-attention") {
      const cell = node(doc, "td", "sender-history-attention"); cell.colSpan = 5; cell.append(node(doc, "strong", "", "Needs attention"), node(doc, "span", "", "We couldn't read this saved entry.")); const retry = node(doc, "button", "button button-secondary", "Retry") as HTMLButtonElement; retry.type = "button"; retry.addEventListener("click", () => { void load(false); }); const remove = node(doc, "button", "button button-secondary", "Remove saved entry") as HTMLButtonElement; remove.type = "button"; remove.addEventListener("click", () => { if (!window.confirm("Remove this saved entry?")) return; remove.disabled = true; void options.history.remove(item.key).then(() => load(false)).catch(() => { remove.disabled = false; live.textContent = "The saved entry could not be removed. Try again."; }); }); cell.append(retry, remove); row.append(cell, node(doc, "td", "", "—")); body.append(row); return;
    }
    const rawName = item.record.filename ?? item.record.resource.path.replace(/\/+$/, "").split("/").at(-1) ?? "";
    const artifact = item.record.resource.kind === "prefix" ? undefined : artifactKindOf(rawName);
    const itemCell = node(doc, "td", "sender-item-cell"); itemCell.append(node(doc, "strong", "", safeName(item.record)), node(doc, "span", artifact === undefined ? "sender-item-type" : "sender-item-type sender-item-artifact tc-badge", artifact === undefined ? (item.record.resource.kind === "prefix" ? "Folder" : "File") : ARTIFACT_KIND_LABEL[artifact]));
    const recipient = node(doc, "td", ""); recipient.dataset.label = "Recipient"; recipient.append(node(doc, "span", `sender-audience tc-badge sender-audience-${item.record.recipientMatcher.kind}`, recipientSummary(item)));
    const access = node(doc, "td", "", actionsSummary(item.record.actions)); access.dataset.label = "Access";
    const status = node(doc, "td", "sender-status-text"); status.dataset.label = "Expires / status";
    status.append(node(doc, "span", "status-label"), node(doc, "span", "status-expiry"));
    paintStatus(status, item.state, item.record.expiresAt);
    const created = node(doc, "td", "", new Date(item.record.registeredAt).toLocaleDateString()); created.dataset.label = "Created";
    const controls = node(doc, "td", "sender-row-actions");
    const copy = node(doc, "button", "button button-secondary tc-button tc-button--compact", "Copy link") as HTMLButtonElement; copy.type = "button"; copy.setAttribute("aria-label", `Copy link for ${safeName(item.record)}`); copy.addEventListener("click", () => { copy.disabled = true; void options.history.show(item.record.shareId, true).then((view) => { if (view.link === undefined) throw new Error("share-link-unavailable"); return copyWithFallback(view.link); }).then(() => { live.textContent = "Link copied."; }).catch(() => { live.textContent = "Copy failed. Try again after allowing clipboard access."; }).finally(() => { copy.disabled = false; }); });
    const open = node(doc, "button", "button button-secondary tc-button tc-button--compact", "Open") as HTMLButtonElement; open.type = "button"; open.setAttribute("aria-label", `Open ${safeName(item.record)}`); open.addEventListener("click", () => { open.disabled = true; void options.history.show(item.record.shareId, true).then((view) => { if (view.link === undefined) throw new Error("share-link-unavailable"); openSenderViewer(view.link, live); }).catch(() => { live.textContent = "The share link could not be opened. Try again."; }).finally(() => { open.disabled = false; }); });
    itemCell.dataset.label = "Item"; controls.dataset.label = "Actions"; row.tabIndex = -1; controls.append(open, copy);
    const handle: RowHandle = { item, status, controls };
    rows.set(item.record.shareId, handle);
    if (item.state !== "revoked") {
      const revoke = node(doc, "button", "button button-secondary tc-button tc-button--compact sender-revoke", "Revoke") as HTMLButtonElement; revoke.type = "button"; revoke.setAttribute("aria-label", `Revoke ${safeName(item.record)}`);
      handle.revoke = revoke;
      if (item.record.enforcementDelegationCid === undefined && item.record.ownerDelegationCid === undefined) {
        // Imported bearer links may not have a revocation authority.
        revoke.disabled = true;
        revoke.title = "This saved link can't be revoked because its revocation authority is missing.";
        revoke.classList.add("sender-revoke-unavailable");
      } else {
        revoke.addEventListener("click", () => { void revokeRow(item, revoke, status, controls); });
      }
      controls.append(revoke);
      // A revoke still open from before this view was mounted: show it, never an enabled button.
      const running = activeFlight(flightKey(options.session.address, item.record.shareId));
      if (running !== undefined) followFlight(running, revoke, status, controls);
    }
    row.append(itemCell, recipient, access, status, created, controls); body.append(row); pageRows.push(row);
  };
  /** What the node says overrides a saved "Ready": a share revoked or expired elsewhere is shown as such. */
  const applyNodeState = (handle: RowHandle, status: NodeShareStatus): void => {
    const kind = handle.status.dataset.kind;
    // A revoke running here owns the row until it ends; a revoked row stays revoked.
    if (kind === "pending" || kind === "revoked" || activeFlight(flightKey(options.session.address, handle.item.record.shareId)) !== undefined) return;
    if (status.state === "revoked") {
      paintStatus(handle.status, "revoked", handle.item.record.expiresAt);
      handle.revoke?.remove();
    } else if (status.state === "expired" && kind === "ready") {
      paintStatus(handle.status, "expired", handle.item.record.expiresAt, earlierEnd(status.expiredAt, handle.item.record.expiresAt));
    }
  };
  let checking = false;
  let queued = false;
  let lastCheck = 0;
  /** TC-1584. Asks the owner's node for each share's state. A share it cannot confirm is not shown as confirmed. */
  const checkStatus = async (): Promise<void> => {
    const reader = options.statusReader;
    if (reader === undefined || rows.size === 0 || scope.signal.aborted) return;
    if (checking) { queued = true; return; }
    checking = true; lastCheck = Date.now();
    freshness.hidden = false; freshness.textContent = FRESHNESS_CHECKING; recheck.disabled = true;
    let states: ReadonlyMap<string, NodeShareStatus> = new Map();
    let timedOut = false;
    // One bounded ask: a node that does not answer in time leaves every share unconfirmed, and the sender can ask again. Signing out or leaving the library ends it too.
    const request = new AbortController();
    const cancel = (): void => request.abort();
    scope.signal.addEventListener("abort", cancel, { once: true });
    let timer: number | undefined;
    const deadline = new Promise<"timeout">((resolve) => { timer = window.setTimeout(() => resolve("timeout"), STATUS_CHECK_TIMEOUT_MS); });
    try {
      const running = reader([...rows.values()].map((handle) => handle.item.record), request.signal);
      // An answer that arrives after the deadline is not read; a rejection nobody waits for is not an error.
      running.catch(() => undefined);
      const answer = await Promise.race([running, deadline]);
      if (answer === "timeout") timedOut = true; else states = answer;
    } catch { /* every share stays unconfirmed */ } finally {
      window.clearTimeout(timer); request.abort(); scope.signal.removeEventListener("abort", cancel);
      checking = false;
    }
    // Signed out, or the library was mounted again: nothing here may change.
    if (scope.signal.aborted) return;
    let unconfirmed = 0;
    for (const [shareId, handle] of rows) {
      const status = states.get(shareId) ?? { state: "unknown" };
      applyNodeState(handle, status);
      if (status.state === "unknown" && handle.status.dataset.kind !== "revoked") unconfirmed += 1;
    }
    freshness.textContent = unconfirmed === 0 ? freshnessConfirmed(new Date()) : timedOut ? FRESHNESS_TIMEOUT : FRESHNESS_UNCONFIRMED;
    recheck.textContent = unconfirmed === 0 ? CHECK_STATUS_LABEL : CHECK_AGAIN_LABEL; recheck.disabled = false;
    // Rows added while the node was being asked (a page of "Load more") get their answer now.
    if (queued) { queued = false; void checkStatus(); }
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
      if (page.items.length > 0) void checkStatus();
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
  recheck.addEventListener("click", () => { void checkStatus(); });
  // A revoke made on the account site or the CLI while this tab was in the background shows up when the sender comes back.
  const onReturn = (): void => { if (shell.isConnected && doc.visibilityState !== "hidden" && Date.now() - lastCheck > FOCUS_RECHECK_MS) void checkStatus(); };
  window.addEventListener("focus", onReturn, { signal: scope.signal });
  doc.addEventListener("visibilitychange", onReturn, { signal: scope.signal });
  void load(false);
}

function openSenderViewer(url: string, live: HTMLElement): void {
  try { window.open(url, "_self", "noreferrer"); } catch { live.textContent = "The viewer could not be opened."; }
}
