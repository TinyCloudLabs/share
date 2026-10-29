/**
 * DOM for the apps page. Everything that comes from the catalog or a manifest
 * is set with textContent (or a validated https href); there is no innerHTML,
 * so Trusted Types can stay required for scripts. Sheet copy is fixed text plus those same textContent values; it adds no markup path.
 */
import { type AccessItem, unsupportedManifest } from "./access.ts";
import { type Availability, type CatalogEntry, availabilityOf, versionLabel } from "./catalog.ts";
import { consentFor } from "./consent.ts";
import { InlinePanel, type PanelAction } from "./inline-panel.ts";
import { runnerHref } from "./install-plan.ts";
import { loadManifest } from "./manifest.ts";
import { possessive } from "./possessive.ts";
import { RepairError, type RepairOutcome, type RepairPorts, type RepairProgress, runRepair } from "./repair.ts";
import { createRepairPorts } from "./repair-session.ts";
import { type UninstallFailure, UninstallError, uninstallPlan } from "./uninstall-plan.ts";
import { type UninstallPorts, type UninstallProgress, type UninstallResult, runUninstall } from "./uninstall.ts";
import { createUninstallPorts } from "./uninstall-session.ts";

type Child = Node | string;

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, className: string | null, children: Child[] = [], attrs: Record<string, string> = {}): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className !== null) node.className = className;
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
  for (const child of children) node.append(typeof child === "string" ? document.createTextNode(child) : child);
  return node;
}

function dataRow(label: string, value: Child): HTMLElement {
  return el("div", "tc-data-row", [el("dt", "tc-data-row__label", [label]), el("dd", "tc-data-row__value apps-value", [value])]);
}

function sourceLink(repo: string): Child {
  // Catalog values are checked by the catalog test; refuse anything but https here too.
  if (!/^https:\/\/[^\s]+$/.test(repo)) return repo;
  return el("a", null, [repo.replace(/^https:\/\//, "")], { href: repo, rel: "noreferrer noopener", target: "_blank" });
}

function accessList(items: AccessItem[]): HTMLElement {
  return el("ul", "apps-access", items.map((item) => el("li", "apps-access__item", [
    el("p", item.description === null ? "apps-access__text apps-access__text--missing" : "apps-access__text", [item.description ?? "The app gave no description for this."]),
    el("p", "apps-access__meta", [
      el("span", "tc-badge", [item.service]),
      ...(item.space === null ? [] : [el("span", "apps-access__actions", [`space: ${item.space}`])]),
      el("code", null, [item.target]),
      el("span", "apps-access__actions", [item.actions.join(", ")]),
    ]),
  ])));
}

export function accessSection(title: string, empty: string, items: AccessItem[]): HTMLElement {
  return el("section", "apps-section", [el("h3", null, [title]), items.length === 0 ? el("p", "apps-muted", [empty]) : accessList(items)]);
}

function skeleton(): HTMLElement {
  return el("div", "apps-skeleton", [
    el("div", "tc-skeleton apps-skeleton__line apps-skeleton__line--short"),
    el("div", "tc-skeleton apps-skeleton__line"),
    el("div", "tc-skeleton apps-skeleton__line"),
    el("div", "tc-skeleton apps-skeleton__line apps-skeleton__line--short"),
  ], { "aria-hidden": "true" });
}

const MANIFEST_MISMATCH = "This app's manifest doesn't match the catalog, so what it can do isn't shown.";
const MANIFEST_UNAVAILABLE = "Couldn't load this app's manifest. Close this panel and open it again to retry.";

/** Fills `target` with the app's access lists, or an honest failure; never partial manifest data. */
async function renderAccess(entry: CatalogEntry, catalog: readonly CatalogEntry[], target: HTMLElement): Promise<void> {
  target.setAttribute("aria-busy", "true");
  target.replaceChildren(skeleton());
  const result = await loadManifest(entry);
  if (!target.isConnected) return;
  target.removeAttribute("aria-busy");
  if (!result.ok) {
    target.replaceChildren(el("p", "tc-status tc-status--danger", [result.reason === "mismatch" ? MANIFEST_MISMATCH : MANIFEST_UNAVAILABLE], { role: "alert" }));
    return;
  }
  const unsupported = unsupportedManifest(result.manifest);
  if (unsupported !== null) {
    target.replaceChildren(el("p", "tc-status tc-status--danger", [`This app's manifest asks for something this page can't describe (${unsupported}), so what it can do isn't shown and it can't be opened.`], { role: "alert" }));
    return;
  }
  const consent = consentFor(entry, result.manifest, catalog);
  target.replaceChildren(
    ...noticeList(consent.notices),
    accessSection("It can read", "Nothing.", consent.runtime.read),
    accessSection("It can change", "Nothing. This app can't change your data.", consent.runtime.change),
  );
}

/** The app's plain statements (SQL changes, reads of another app). */
export function noticeList(notices: readonly string[]): HTMLElement[] {
  return notices.length === 0 ? [] : [el("ul", "apps-notes apps-notes--strong", notices.map((notice) => el("li", null, [notice])))];
}

/** The notice for an entry that cannot be opened: the heading says whether the state is temporary, the reason is the text. */
function unavailableNotice(availability: Extract<Availability, { available: false }>): HTMLElement {
  return el("div", "tc-status tc-status--warning apps-notice apps-unavailable", [el("strong", null, [availability.temporary ? "Temporarily unavailable" : "Unavailable"]), el("span", null, [availability.reason])]);
}

function provenance(entry: CatalogEntry): HTMLElement {
  const files = el("details", "apps-files", [
    el("summary", null, [`Pinned files (${entry.bundle.files.length})`]),
    el("dl", "apps-rows", entry.bundle.files.map((file) => dataRow(`${file.path} · ${file.size} bytes`, file.sha256))),
  ]);
  return el("section", "apps-section", [
    el("h3", null, ["Where it comes from"]),
    el("dl", "apps-rows", [
      dataRow("App ID", entry.app_id),
      dataRow("Publisher", entry.publisher.name),
      dataRow("Source", sourceLink(entry.source.repo)),
      dataRow("Version", versionLabel(entry)),
      dataRow("Commit", entry.source.commit),
      dataRow("Bundle checksum", entry.bundle.digest),
    ]),
    files,
  ]);
}

function sheetHeader(kicker: string, title: string, entry: CatalogEntry, close: () => void): HTMLElement {
  const closeButton = el("button", "tc-button tc-button--compact apps-button", ["Close"], { type: "button", "aria-label": `Close details for ${entry.name}` });
  closeButton.addEventListener("click", close);
  return el("header", "apps-sheet__header", [
    el("div", "apps-sheet__heading", [el("p", "apps-kicker", [kicker]), el("h2", null, [title], { id: "sheet-title" })]),
    closeButton,
  ]);
}

// ---------------------------------------------------------------------------
// Details

function detailsContent(entry: CatalogEntry, catalog: readonly CatalogEntry[], close: () => void, uninstall: () => void): { header: HTMLElement; body: HTMLElement; footer: HTMLElement } {
  const header = sheetHeader(`by ${entry.publisher.name}`, entry.name, entry, close);
  const access = el("div", "apps-access-region", [], { "aria-live": "polite" });
  const availability = availabilityOf(entry);
  const body = el("div", "apps-sheet__body", [...(availability.available ? [] : [unavailableNotice(availability)]), el("p", "apps-sheet__lede", [entry.description]), access, provenance(entry)]);
  const uninstallNote = el("p", "apps-muted", ["Also deletes notes you edited."], { id: "apps-uninstall-note" });
  const uninstallNow = el("button", "tc-button apps-button", ["Uninstall"], { type: "button", "aria-label": `Uninstall ${entry.name}`, "aria-describedby": "apps-uninstall-note" });
  uninstallNow.addEventListener("click", uninstall);
  const open = availability.available
    ? el("a", "tc-button tc-button--primary apps-button", ["Open"], { href: runnerHref(entry.app_id), "aria-label": `Open ${entry.name}` })
    : el("button", "tc-button tc-button--primary apps-button", ["Open"], { type: "button", disabled: "", "aria-label": `Open ${entry.name}` });
  const footer = el("footer", "apps-sheet__footer", [open, uninstallNow, uninstallNote]);
  void renderAccess(entry, catalog, access);
  return { header, body, footer };
}


// ---------------------------------------------------------------------------
// Repair

function repairFailureText(entry: CatalogEntry, error: RepairError): string {
  switch (error.reason) {
    case "cancelled": return "Sign-in cancelled. Nothing was changed.";
    case "timeout": return "OpenKey didn't answer in time. Nothing was changed. Try again.";
    case "busy": return "Another OpenKey request is waiting. Finish or cancel it, then try again.";
    case "wrong-account": return "That approval came from a different account than the one signed in. Nothing was changed.";
    case "tampered": return `${possessive(entry.name)} files don't match the catalog, so nothing was changed. Nothing was written to your TinyCloud.`;
    case "disabled": return "This app isn't available right now. Nothing was changed.";
    case "unavailable": return `Couldn't load ${possessive(entry.name)} files. Nothing was changed. Try again.`;
    case "write-failed": return `Not repaired yet: ${error.written.length} files were replaced. Your data was not touched; try again to finish.`;
    default: return "We couldn't repair this app. Nothing was changed. Try again.";
  }
}

function repairProgressText(entry: CatalogEntry, progress: RepairProgress): string {
  switch (progress.phase) {
    case "checking": return `Checking ${possessive(entry.name)} files against the catalog…`;
    case "signing-in": return "Opening OpenKey…";
    case "approval": return `Approve in the OpenKey window to repair ${entry.name}`;
    case "repairing": return `Repairing ${entry.name}… ${progress.done} of ${progress.total} files`;
  }
}


function uninstallProgressText(entry: CatalogEntry, progress: UninstallProgress): string {
  switch (progress.phase) {
    case "signing-in": return `Uninstalling ${entry.name}…`;
    case "approval": return `Approve in the OpenKey window to remove ${entry.name}`;
    case "checking": return `Uninstalling ${entry.name}…`;
    case "removing": return `Uninstalling ${entry.name}… ${progress.done} of ${progress.total} files`;
    case "registry": return `Uninstalling ${entry.name}…`;
  }
}

function uninstallFailureText(entry: CatalogEntry, reason: UninstallFailure | "registry"): string {
  switch (reason) {
    case "registry": return "The app was removed; its entry in your account list couldn't be updated; try again.";
    case "cancelled": return "Sign-in cancelled. Nothing was changed.";
    case "timeout": return "OpenKey didn't answer in time. Nothing was changed. Try again.";
    case "busy": return "Another OpenKey request is waiting. Finish or cancel it, then try again.";
    case "wrong-account": return "That approval came from a different account than the one signed in. Nothing was changed.";
    case "truncated": return `${possessive(entry.name)} file list is too long to check at once. Nothing was deleted. Try again.`;
    case "refused": return "Stopped: this app id or file path isn't one uninstall will touch. Nothing outside the app's folders was removed.";
    case "write-failed": return `Some of ${possessive(entry.name)} files couldn't be removed. Try again to finish.`;
    case "not-started": return "Couldn't start the uninstall. Nothing was changed. Try again.";
    case "failed": return `Couldn't finish removing ${entry.name}. Try again to finish.`;
  }
}

/**
 * `UninstallPorts` for one uninstall run: once the person cancels, nothing new starts (no OpenKey window), a session
 * that arrives late is closed, and no list, delete or registry call is made. The sign-in and the deletes are the real ones.
 */
export function guardedUninstallPorts(ports: UninstallPorts, cancelled: () => boolean): UninstallPorts {
  return {
    openSession: async (plan, hooks) => {
      if (cancelled()) throw new UninstallError("cancelled");
      const session = await ports.openSession(plan, hooks);
      if (cancelled()) {
        await Promise.resolve(session.dispose()).catch(() => undefined);
        throw new UninstallError("cancelled");
      }
      const refuse = (): void => { if (cancelled()) throw new UninstallError("cancelled"); };
      return {
        list: async (prefix, cursor) => { refuse(); return session.list(prefix, cursor); },
        del: async (key) => { refuse(); return session.del(key); },
        removeRegistry: async (appId) => { refuse(); return session.removeRegistry(appId); },
        dispose: () => session.dispose(),
      };
    },
  };
}

export interface MountOptions {
  /** The repair flow's sign-in and node. Created when Repair is clicked. */
  repairPorts?: () => RepairPorts;
  /** The uninstall flow's sign-in and node. Created when Uninstall is clicked; the default loads OpenKey and the SDK then. */
  uninstallPorts?: () => UninstallPorts;
}

export interface MountedApps {
  /** Offers repair for an app (`/apps/#repair=<app_id>`). Returns false when the catalog has no such app. */
  openRepair(appId: string): boolean;
  /** Opens the details sheet for an app (`/apps/#uninstall=<app_id>`). Returns false when the catalog has no such app. */
  openUninstall(appId: string): boolean;
}

/**
 * `RepairPorts` for one repair run: once the person cancels, nothing new starts (no OpenKey window), a session that
 * arrives late is closed, and no file is written, listed or removed. The sign-in and the writes are the real ones.
 */
function guardedRepairPorts(ports: RepairPorts, cancelled: () => boolean): RepairPorts {
  return {
    ...ports,
    openSession: async (manifest, hooks) => {
      if (cancelled()) throw new RepairError("cancelled");
      const session = await ports.openSession(manifest, hooks);
      if (cancelled()) {
        await Promise.resolve(session.dispose()).catch(() => undefined);
        throw new RepairError("cancelled");
      }
      const refuse = (): void => { if (cancelled()) throw new RepairError("cancelled"); };
      return {
        put: async (key, bytes, contentType) => { refuse(); return session.put(key, bytes, contentType); },
        list: async (prefix) => { refuse(); return session.list(prefix); },
        del: async (key) => { refuse(); return session.del(key); },
        dispose: () => session.dispose(),
      };
    },
  };
}

export function mountApps(list: HTMLElement, sheet: HTMLDialogElement, entries: CatalogEntry[], options: MountOptions = {}): MountedApps {
  const repairPorts = options.repairPorts ?? createRepairPorts;
  const currentEntries: CatalogEntry[] = [];
  const seenIds = new Set<string>();
  for (const entry of entries) {
    if (seenIds.has(entry.app_id)) continue;
    seenIds.add(entry.app_id);
    currentEntries.push(entry);
  }
  const uninstallPortsFor = options.uninstallPorts ?? createUninstallPorts;
  let opener: HTMLElement | null = null;
  const cards = new Map<string, HTMLElement>();
  /** The inline panel under each card, with what stops it listening to its run. */
  const panels = new Map<string, { panel: InlinePanel; release: () => void }>();
  const close = (): void => { sheet.close(); };
  sheet.addEventListener("close", () => {
    // `close` is dispatched after the dialog closed: a sheet reopened in the meantime (a quick click on another Install) is not the one that closed.
    if (sheet.open) return;
    sheet.replaceChildren();
    opener?.focus();
    opener = null;
  });
  // A click on the backdrop lands on the dialog element itself, outside its content.
  sheet.addEventListener("click", (event) => { if (event.target === sheet) close(); });

  /**
   * Closes the modal sheet for good, without giving focus back to the button that opened it (the inline panel takes
   * focus). A run starts only after this, so nothing modal is on the page when OpenKey's window opens.
   */
  const leaveSheet = (): void => {
    opener = null;
    if (sheet.open) sheet.close();
  };

  /** A fresh panel under the card for `appId`, replacing any earlier one. */
  const freshPanel = (appId: string, label: string): InlinePanel => {
    const earlier = panels.get(appId);
    earlier?.release();
    earlier?.panel.remove();
    const panel = new InlinePanel(label);
    cards.get(appId)?.append(panel.root);
    panels.set(appId, { panel, release: () => undefined });
    return panel;
  };
  const dismiss = (appId: string): void => {
    const current = panels.get(appId);
    current?.release();
    current?.panel.remove();
    panels.delete(appId);
    cards.get(appId)?.querySelector<HTMLElement>(".apps-card__actions button")?.focus();
  };

  /** One repair at a time per app: a second Repair joins the running one. */
  const repairing = new Set<string>();
  const runRepairInline = (entry: CatalogEntry): void => {
    leaveSheet();
    if (repairing.has(entry.app_id)) {
      panels.get(entry.app_id)?.panel.focus();
      return;
    }
    repairing.add(entry.app_id);
    const panel = freshPanel(entry.app_id, `Repair ${entry.name}`);
    let cancelled = false;
    let running = true;
    const cancel = (): void => {
      if (!running) return;
      cancelled = true;
      running = false;
      repairing.delete(entry.app_id);
      panel.onEscape = undefined;
      panel.say("Repair cancelled. Files already replaced are kept; repairing again finishes the rest. If an OpenKey window is still open, close it.", "neutral", { actions: [{ label: "Try again", primary: true, onClick: () => runRepairInline(entry) }, { label: "Dismiss", onClick: () => dismiss(entry.app_id) }] });
    };
    const working = (message: string): void => {
      if (cancelled) return;
      panel.onEscape = cancel;
      panel.say(message, "info", { actions: [{ label: "Cancel", onClick: cancel }] });
    };
    working(repairProgressText(entry, { phase: "checking" }));
    panel.focus();
    void runRepair(entry, guardedRepairPorts(repairPorts(), () => cancelled), (progress) => working(repairProgressText(entry, progress))).then(
      (outcome: RepairOutcome) => {
        if (cancelled) return;
        running = false;
        repairing.delete(entry.app_id);
        panel.onEscape = undefined;
        panel.say(`Repaired. ${outcome.written.length} ${outcome.written.length === 1 ? "file was" : "files were"} replaced${outcome.removed.length === 0 ? "" : ` and ${outcome.removed.length} other ${outcome.removed.length === 1 ? "file was" : "files were"} removed`}. Your data was not touched.`, "success", { actions: [{ label: `Open ${entry.name}`, href: runnerHref(entry.app_id) }, { label: "Done", primary: true, onClick: () => dismiss(entry.app_id) }] });
      },
      (error: unknown) => {
        if (cancelled) return;
        running = false;
        repairing.delete(entry.app_id);
        panel.onEscape = undefined;
        panel.say(repairFailureText(entry, error instanceof RepairError ? error : new RepairError("failed", { cause: error })), "danger", { actions: [{ label: "Try again", primary: true, onClick: () => runRepairInline(entry) }, { label: "Dismiss", onClick: () => dismiss(entry.app_id) }] });
      },
    );
  };

  /** Repair from `/apps/#repair=<app_id>`: the inline panel with one Repair action. No sheet, so the OpenKey window is not under a modal. */
  const offerRepair = (entry: CatalogEntry): void => {
    leaveSheet();
    if (repairing.has(entry.app_id)) {
      panels.get(entry.app_id)?.panel.focus();
      return;
    }
    const availability = availabilityOf(entry);
    const panel = freshPanel(entry.app_id, `Repair ${entry.name}`);
    if (availability.available) {
      panel.say("This replaces your edited code. Your data is untouched.", "neutral", { actions: [{ label: "Repair", primary: true, onClick: () => runRepairInline(entry) }, { label: "Dismiss", onClick: () => dismiss(entry.app_id) }] });
    } else {
      panel.say(availability.reason, "danger", { actions: [{ label: "Dismiss", onClick: () => dismiss(entry.app_id) }] });
    }
    panel.focus();
  };

  /** One uninstall at a time per app; a second Remove joins the running one, as for repair. */
  const uninstalling = new Set<string>();
  const runUninstallInline = (entry: CatalogEntry): void => {
    leaveSheet();
    if (uninstalling.has(entry.app_id)) {
      panels.get(entry.app_id)?.panel.focus();
      return;
    }
    uninstalling.add(entry.app_id);
    const panel = freshPanel(entry.app_id, `Uninstall ${entry.name}`);
    let cancelled = false;
    let running = true;
    const stop = (): void => {
      running = false;
      uninstalling.delete(entry.app_id);
      panel.onEscape = undefined;
    };
    const retryOrDismiss: PanelAction[] = [{ label: "Try again", primary: true, onClick: () => runUninstallInline(entry) }, { label: "Dismiss", onClick: () => dismiss(entry.app_id) }];
    const cancel = (): void => {
      if (!running) return;
      cancelled = true;
      stop();
      panel.say("Uninstall cancelled. Files already removed stay removed; uninstalling again finishes the rest. If an OpenKey window is still open, close it.", "neutral", { actions: retryOrDismiss });
    };
    const working = (message: string): void => {
      if (cancelled) return;
      panel.onEscape = cancel;
      panel.say(message, "info", { actions: [{ label: "Cancel", onClick: cancel }] });
    };
    working(uninstallProgressText(entry, { phase: "signing-in" }));
    panel.focus();
    void runUninstall(uninstallPlan(entry), guardedUninstallPorts(uninstallPortsFor(), () => cancelled), (progress) => working(uninstallProgressText(entry, progress))).then(
      (result: UninstallResult) => {
        if (cancelled) return;
        stop();
        if (result.registry === "failed") {
          panel.say(uninstallFailureText(entry, "registry"), "danger", { actions: retryOrDismiss });
          return;
        }
        if (result.removed === 0) {
          panel.say(`Nothing to remove: ${entry.name} had no app files on this account. Your app data and settings are kept.`, "success", { actions: [{ label: "Dismiss", onClick: () => dismiss(entry.app_id) }] });
          return;
        }
        panel.say(`Removed ${possessive(entry.name)} app files and agent notes. Your app data and settings are kept. Open ${entry.name} again to restore it.`, "success", { actions: [{ label: "Dismiss", onClick: () => dismiss(entry.app_id) }] });
      },
      (error: unknown) => {
        if (cancelled) return;
        stop();
        panel.say(uninstallFailureText(entry, error instanceof UninstallError ? error.reason : "failed"), "danger", { actions: retryOrDismiss });
      },
    );
  };

  const show = (entry: CatalogEntry): void => {
    const { header, body, footer } = detailsContent(entry, entries, close, () => runUninstallInline(entry));
    sheet.replaceChildren(header, body, footer);
    if (!sheet.open) sheet.showModal();
  };

  const mounted: MountedApps = {
    openRepair(appId): boolean {
      const entry = currentEntries.find((candidate) => candidate.app_id === appId);
      if (entry === undefined) return false;
      offerRepair(entry);
      return true;
    },
    openUninstall(appId): boolean {
      const entry = currentEntries.find((candidate) => candidate.app_id === appId);
      if (entry === undefined) return false;
      show(entry);
      return true;
    },
  };
  if (currentEntries.length === 0) {
    list.replaceWith(el("p", "apps-empty", ["No apps are listed yet."]));
    return mounted;
  }
  for (const entry of currentEntries) {
    const details = el("button", "tc-button apps-button", ["Details"], { type: "button", "aria-label": `Details for ${entry.name}` });
    details.addEventListener("click", () => { opener = details; show(entry); });
    const availability = availabilityOf(entry);
    // A card that cannot open shows Open as a disabled button; the reason is shown on the card.
    const open = availability.available
      ? el("a", "tc-button tc-button--primary apps-button", ["Open"], { href: runnerHref(entry.app_id), "aria-label": `Open ${entry.name}` })
      : el("button", "tc-button tc-button--primary apps-button", ["Open"], { type: "button", disabled: "", "aria-label": `Open ${entry.name}` });
    const card = el("li", "apps-card tc-panel", [
      el("h2", "apps-card__name", [entry.name]),
      el("p", "apps-card__meta", [`${entry.publisher.name} · ${versionLabel(entry)}`]),
      el("p", "apps-card__description", [entry.description]),
      ...(availability.available ? [] : [unavailableNotice(availability)]),
      el("div", "apps-card__actions", [open, details]),
    ]);
    cards.set(entry.app_id, card);
    list.append(card);
  }
  return mounted;
}
