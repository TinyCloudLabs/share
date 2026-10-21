/**
 * DOM for the apps page. Everything that comes from the catalog or a manifest
 * is set with textContent (or a validated https href); there is no innerHTML,
 * so Trusted Types can stay required for scripts. Sheet copy is fixed text plus those same textContent values; it adds no markup path.
 */
import { type AccessItem, unsupportedManifest } from "./access.ts";
import { type CatalogEntry, availabilityOf, versionLabel } from "./catalog.ts";
import { SAMPLE_NOTICE, consentFor } from "./consent.ts";
import { InlinePanel, type PanelAction } from "./inline-panel.ts";
import { firstOpenLines } from "./first-open.ts";
import { runnerHref } from "./install-plan.ts";
import { loadManifest } from "./manifest.ts";
import { RepairError, type RepairOutcome, type RepairPorts, type RepairProgress, repairWrites, runRepair } from "./repair.ts";
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
    ...(entry.sample === true ? [sampleNotice()] : []),
    ...noticeList(consent.notices),
    accessSection("It can read", "Nothing.", consent.runtime.read),
    accessSection("It can change", "Nothing. This app can't change your data.", consent.runtime.change),
  );
}

/** The app's plain statements (SQL changes, reads of another app); the sample notice has its own banner. */
export function noticeList(notices: readonly string[]): HTMLElement[] {
  const own = notices.filter((notice) => notice !== SAMPLE_NOTICE);
  return own.length === 0 ? [] : [el("ul", "apps-notes apps-notes--strong", own.map((notice) => el("li", null, [notice])))];
}

/** The kill switch's banner: fixed heading, the catalog's reason as text. */
function unavailableNotice(reason: string): HTMLElement {
  return el("div", "tc-status tc-status--warning apps-notice apps-unavailable", [el("strong", null, ["Temporarily unavailable"]), el("span", null, [reason])]);
}

function sampleNotice(): HTMLElement {
  return el("p", "tc-status tc-status--warning apps-notice", [SAMPLE_NOTICE]);
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
  const disclosure = el("section", "apps-section", [el("h3", null, ["Before you open it"]), el("ul", "apps-notes", firstOpenLines(entry).map((line) => el("li", null, [line])))]);
  const body = el("div", "apps-sheet__body", [...(availability.available ? [] : [unavailableNotice(availability.reason)]), el("p", "apps-sheet__lede", [entry.description]), disclosure, access, provenance(entry)]);
  const open = el("a", "tc-button tc-button--primary apps-button", ["Open"], { href: runnerHref(entry.app_id), "aria-label": `Open ${entry.name}` });
  const uninstallNow = el("button", "tc-button apps-button", ["Uninstall"], { type: "button", "aria-label": `Uninstall ${entry.name}` });
  uninstallNow.addEventListener("click", uninstall);
  const footer = el("footer", "apps-sheet__footer", [open, el("p", "apps-muted", [availability.available ? "Opening checks the app's files before anything is saved." : "Opening is switched off for this app."]), uninstallNow]);
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
    case "tampered": return `${entry.name}'s files don't match the catalog, so nothing was changed. Nothing was written to your TinyCloud.`;
    case "disabled": return "This app is temporarily unavailable. Nothing was changed.";
    case "unavailable": return `Couldn't load ${entry.name}'s files. Nothing was changed. Try again.`;
    case "write-failed": return `Not repaired yet: ${error.written.length} files were replaced. Your data was not touched; try again to finish.`;
    default: return "We couldn't repair this app. Nothing was changed. Try again.";
  }
}

function repairProgressText(entry: CatalogEntry, progress: RepairProgress): string {
  switch (progress.phase) {
    case "checking": return `Checking ${entry.name}'s files against the catalog…`;
    case "signing-in": return "Opening OpenKey…";
    case "approval": return `Approve in the OpenKey window to repair ${entry.name}`;
    case "repairing": return `Repairing ${entry.name}… ${progress.done} of ${progress.total} files`;
  }
}

/** The repair sheet: what Repair replaces, what it leaves alone, then Continue (which closes the sheet; see inline-panel.ts). One approval. */
function repairContent(entry: CatalogEntry, onContinue: () => void, close: () => void): { header: HTMLElement; body: HTMLElement; footer: HTMLElement } {
  const header = sheetHeader("Repair", `Repair ${entry.name}`, entry, close);
  const availability = availabilityOf(entry);
  const writes = repairWrites(entry);
  const body = el("div", "apps-sheet__body", [
    ...(availability.available ? [] : [unavailableNotice(availability.reason)]),
    el("section", "apps-section", [
      el("h3", null, ["What repairing does"]),
      el("ul", "apps-notes", [
        el("li", null, [`Replaces the app's code files with the pinned version, under ${entry.app_id}/app/ (${writes.length} files, the manifest included).`]),
        el("li", null, ["Removes any other file in that folder."]),
        el("li", null, ["Your data is untouched: its databases, settings and notes are not read or changed."]),
        el("li", null, ["One OpenKey approval, for 15 minutes, to put, delete and list in that one folder. Nothing stays signed in afterwards."]),
      ]),
      el("details", "apps-files", [el("summary", null, [`Files it writes (${writes.length})`]), el("ul", "apps-notes", writes.map((write) => el("li", null, [el("code", null, [write.key])])))]),
    ]),
  ]);
  const actions = el("div", "apps-install-actions", []);
  const footer = el("footer", "apps-sheet__footer", [actions]);
  const button = (label: string, className: string, onClick: () => void, disabled = false): HTMLButtonElement => {
    const node = el("button", `${className} apps-button`, [label], { type: "button" });
    node.disabled = disabled;
    node.addEventListener("click", onClick);
    return node;
  };
  actions.replaceChildren(button("Continue", "tc-button tc-button--primary", onContinue, !availability.available), button("Not now", "tc-button", close));
  return { header, body, footer };
}

/** The uninstall confirm: what goes, what stays, and that open app tabs stay open. Nothing runs until Remove app. */
function uninstallContent(entry: CatalogEntry, onConfirm: () => void, close: () => void): { header: HTMLElement; body: HTMLElement; footer: HTMLElement } {
  const header = sheetHeader("Uninstall", `Remove ${entry.name}`, entry, close);
  const { rows } = uninstallPlan(entry);
  const body = el("div", "apps-sheet__body", [
    el("p", "apps-sheet__lede", [`Remove ${entry.name}'s app files and agent notes? Your app data, settings and files outside those folders stay. Notes you've edited in the app's knowledge folder will be removed. Close any open app tabs first.`]),
    accessList([...rows.change, ...rows.read]),
  ], { tabindex: "0" });
  const remove = el("button", "tc-button tc-button--primary apps-button", ["Remove app"], { type: "button" });
  remove.addEventListener("click", onConfirm);
  const keep = el("button", "tc-button apps-button", ["Keep app"], { type: "button" });
  keep.addEventListener("click", close);
  const footer = el("footer", "apps-sheet__footer apps-sheet__footer--install", [remove, keep]);
  return { header, body, footer };
}

function uninstallProgressText(entry: CatalogEntry, progress: UninstallProgress): string {
  switch (progress.phase) {
    case "signing-in": return "Opening OpenKey…";
    case "approval": return `Approve in the OpenKey window to remove ${entry.name}`;
    case "checking": return `Checking ${entry.name}'s files…`;
    case "removing": return `Removing ${entry.name}… ${progress.done} of ${progress.total} files`;
    case "registry": return "Updating your account list…";
  }
}

function uninstallFailureText(entry: CatalogEntry, reason: UninstallFailure | "registry"): string {
  switch (reason) {
    case "registry": return "The app was removed; its entry in your account list couldn't be updated; try again.";
    case "cancelled": return "Sign-in cancelled. Nothing was changed.";
    case "timeout": return "OpenKey didn't answer in time. Nothing was changed. Try again.";
    case "busy": return "Another OpenKey request is waiting. Finish or cancel it, then try again.";
    case "wrong-account": return "That approval came from a different account than the one signed in. Nothing was changed.";
    case "truncated": return `${entry.name}'s file list is too long to check at once. Nothing was deleted. Try again.`;
    case "refused": return "Stopped: this app id or file path isn't one uninstall will touch. Nothing outside the app's folders was removed.";
    case "write-failed": return `Some of ${entry.name}'s files couldn't be removed. Try again to finish.`;
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
  /** The repair flow's sign-in and node. Created when Repair's Continue is clicked. */
  repairPorts?: () => RepairPorts;
  /** The uninstall flow's sign-in and node. Created when Remove app is clicked; the default loads OpenKey and the SDK then. */
  uninstallPorts?: () => UninstallPorts;
}

export interface MountedApps {
  /** Opens the repair sheet for an app (`/apps/#repair=<app_id>`). Returns false when the catalog has no such app. */
  openRepair(appId: string): boolean;
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

  /** One repair at a time per app: a second Continue joins the running one. */
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
        panel.say(`Removed ${entry.name}'s app files and agent notes. Your app data and settings are kept. Open ${entry.name} again to restore it.`, "success", { actions: [{ label: "Dismiss", onClick: () => dismiss(entry.app_id) }] });
      },
      (error: unknown) => {
        if (cancelled) return;
        stop();
        panel.say(uninstallFailureText(entry, error instanceof UninstallError ? error.reason : "failed"), "danger", { actions: retryOrDismiss });
      },
    );
  };

  const show = (entry: CatalogEntry, mode: "details" | "repair" | "uninstall"): void => {
    if (mode === "uninstall") {
      const content = uninstallContent(entry, () => runUninstallInline(entry), close);
      sheet.replaceChildren(content.header, content.body, content.footer);
    } else if (mode === "repair") {
      const content = repairContent(entry, () => runRepairInline(entry), close);
      sheet.replaceChildren(content.header, content.body, content.footer);
    } else {
      const { header, body, footer } = detailsContent(entry, entries, close, () => show(entry, "uninstall"));
      sheet.replaceChildren(header, body, footer);
    }
    if (!sheet.open) sheet.showModal();
  };

  const mounted: MountedApps = {
    openRepair(appId): boolean {
      const entry = entries.find((candidate) => candidate.app_id === appId);
      if (entry === undefined) return false;
      show(entry, "repair");
      return true;
    },
  };
  if (entries.length === 0) {
    list.replaceWith(el("p", "apps-empty", ["No apps are listed yet."]));
    return mounted;
  }
  for (const entry of entries) {
    const details = el("button", "tc-button apps-button", ["Details"], { type: "button", "aria-label": `Details for ${entry.name}` });
    details.addEventListener("click", () => { opener = details; show(entry, "details"); });
    const availability = availabilityOf(entry);
    // A disabled entry still links to the runner: the runner page refuses it there, before any sign-in opens.
    const open = el("a", "tc-button tc-button--primary apps-button", ["Open"], { href: runnerHref(entry.app_id), "aria-label": `Open ${entry.name}` });
    const card = el("li", "apps-card tc-panel", [
      el("h2", "apps-card__name", [entry.name]),
      el("p", "apps-card__meta", [`${entry.publisher.name} · ${versionLabel(entry)}`, ...(entry.sample === true ? [" ", el("span", "tc-badge apps-badge", ["Sample"])] : [])]),
      el("p", "apps-card__description", [entry.description]),
      ...(availability.available ? [] : [unavailableNotice(availability.reason)]),
      el("div", "apps-card__actions", [open, details]),
    ]);
    cards.set(entry.app_id, card);
    list.append(card);
  }
  return mounted;
}
