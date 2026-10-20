/**
 * DOM for the apps page. Everything that comes from the catalog or a manifest
 * is set with textContent (or a validated https href); there is no innerHTML,
 * so Trusted Types can stay required for scripts. The install sheet's words are
 * fixed text plus those same textContent values; it adds no markup path.
 */
import { type AccessItem, type AccessSummary } from "./access.ts";
import { type CatalogEntry, versionLabel } from "./catalog.ts";
import { SAMPLE_NOTICE, consentFor } from "./consent.ts";
import { type InstallFlight, flightFor, startInstall } from "./install-flight.ts";
import type { InstallError, InstallPorts } from "./install.ts";
import { createInstallPorts } from "./install-session.ts";
import { installerAccess, installerManifest, runnerHref } from "./install-plan.ts";
import { loadManifest } from "./manifest.ts";

type Child = Node | string;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, className: string | null, children: Child[] = [], attrs: Record<string, string> = {}): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className !== null) node.className = className;
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
  for (const child of children) node.append(typeof child === "string" ? document.createTextNode(child) : child);
  return node;
}

const INSTALL_NOTE_ID = "install-note";
/** The runner (`/apps/run`) is the next slice. Until it exists the Open control says so instead of linking to a missing page. */
const RUNNER_AVAILABLE = false;

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

function accessSection(title: string, empty: string, items: AccessItem[]): HTMLElement {
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
  const consent = consentFor(entry, result.manifest, catalog);
  target.replaceChildren(
    ...(entry.sample === true ? [sampleNotice()] : []),
    ...noticeList(consent.notices),
    accessSection("It can read", "Nothing.", consent.runtime.read),
    accessSection("It can change", "Nothing. This app can't change your data.", consent.runtime.change),
  );
}

/** The app's plain statements (SQL changes, reads of another app); the sample notice has its own banner. */
function noticeList(notices: readonly string[]): HTMLElement[] {
  const own = notices.filter((notice) => notice !== SAMPLE_NOTICE);
  return own.length === 0 ? [] : [el("ul", "apps-notes apps-notes--strong", own.map((notice) => el("li", null, [notice])))];
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
  const closeButton = el("button", "tc-button tc-button--compact apps-button", ["Close"], { type: "button", "aria-label": `Close ${title.startsWith("Install") ? "install" : "details"} for ${entry.name}` });
  closeButton.addEventListener("click", close);
  return el("header", "apps-sheet__header", [
    el("div", "apps-sheet__heading", [el("p", "apps-kicker", [kicker]), el("h2", null, [title], { id: "sheet-title" })]),
    closeButton,
  ]);
}

// ---------------------------------------------------------------------------
// Install

const OPEN_NOT_YET = "Opening installed apps is coming next. Installing saves the app to your TinyCloud now; you can open it from here when that ships.";

/** What the install sheet says about the sign-in, from the same resolved request the sign-in makes. */
function signInSection(entry: CatalogEntry): HTMLElement {
  const { app, registry } = installerAccess(installerManifest({ app_id: entry.app_id, name: entry.name, description: entry.description }));
  return el("section", "apps-section", [
    el("h3", null, ["What this sign-in allows"]),
    el("p", null, ["You approve once in OpenKey. For the next hour, Share can then:"]),
    accessList([...app.change, ...app.read]),
    el("p", null, [`Share also updates your account's list of apps so ${entry.name} shows up there. Other than that list, the sign-in can't read or change anything else in your TinyCloud. The exact list:`]),
    el("details", "apps-files", [
      el("summary", null, ["Account list permissions"]),
      accessList([...registry.read, ...registry.change]),
    ]),
  ]);
}

function whatInstallDoes(entry: CatalogEntry): HTMLElement {
  const lines = [
    `Saves ${entry.name}'s files into your TinyCloud: its code under ${entry.app_id}/app/ and notes for agents under ${entry.app_id}/knowledge/.`,
    "Files you already have there are kept, never replaced.",
    `Adds ${entry.name} to your list of apps.`,
    "Gives the app no standing access: no keys, no permissions to keep, nothing running in the background.",
  ];
  return el("section", "apps-section", [el("h3", null, ["What installing does"]), el("ul", "apps-notes", lines.map((line) => el("li", null, [line])))]);
}

function runtimeSection(entry: CatalogEntry, runtime: AccessSummary, notices: string[]): HTMLElement {
  return el("section", "apps-section", [
    el("h3", null, [`When you open ${entry.name}`]),
    el("p", null, [`None of this is granted now. ${entry.name} asks for it with its own sign-in each time you open it.`]),
    ...noticeList(notices),
    accessSection("It can read", "Nothing.", runtime.read),
    accessSection("It can change", "Nothing. This app can't change your data.", runtime.change),
    el("p", "apps-muted", [OPEN_NOT_YET]),
  ]);
}

/** The pre-consent body: only ever drawn from the sha256-verified catalog manifest. */
async function renderConsent(entry: CatalogEntry, catalog: readonly CatalogEntry[], target: HTMLElement): Promise<boolean> {
  target.setAttribute("aria-busy", "true");
  target.replaceChildren(skeleton());
  const result = await loadManifest(entry);
  if (!target.isConnected) return false;
  target.removeAttribute("aria-busy");
  if (!result.ok) {
    target.replaceChildren(el("p", "tc-status tc-status--danger", [result.reason === "mismatch" ? "This app's manifest doesn't match the catalog, so it can't be installed." : MANIFEST_UNAVAILABLE], { role: "alert" }));
    return false;
  }
  const consent = consentFor(entry, result.manifest, catalog);
  target.replaceChildren(
    ...(entry.sample === true ? [sampleNotice()] : []),
    whatInstallDoes(entry),
    signInSection(entry),
    runtimeSection(entry, consent.runtime, consent.notices),
  );
  return true;
}

interface StatusText {
  message: string;
  /** A person's own choice, an unanswered window or a second request is a quiet note, not an alert. */
  tone: "progress" | "success" | "neutral" | "danger";
}

function failureText(entry: CatalogEntry, error: InstallError): StatusText {
  switch (error.reason) {
    case "cancelled": return { message: "Sign-in cancelled. Nothing was installed.", tone: "neutral" };
    case "timeout": return { message: "OpenKey didn't answer in time. Nothing was installed. Try again.", tone: "neutral" };
    case "busy": return { message: "Another OpenKey request is waiting. Finish or cancel it, then try again.", tone: "neutral" };
    case "wrong-account": return { message: "That approval came from a different account than the one signed in. Nothing was installed.", tone: "danger" };
    case "tampered": return { message: `${entry.name}'s files don't match the catalog, so nothing was installed. Nothing was written to your TinyCloud.`, tone: "danger" };
    case "catalog": return { message: "This catalog entry isn't valid, so nothing was installed. Nothing was written to your TinyCloud.", tone: "danger" };
    case "unavailable": return { message: `Couldn't load ${entry.name}'s files. Nothing was installed. Try again.`, tone: "danger" };
    case "write-failed": return { message: `Not installed yet: ${error.written.length} of ${error.total} files were saved. What was saved is kept; try again to finish.`, tone: "danger" };
    default: return { message: "We couldn't install this app. Nothing was installed. Try again.", tone: "danger" };
  }
}

function statusFor(entry: CatalogEntry, flight: InstallFlight): StatusText {
  const state = flight.state;
  switch (state.phase) {
    case "checking": return { message: `Checking ${entry.name}'s files against the catalog…`, tone: "progress" };
    case "signing-in": return { message: "Opening OpenKey…", tone: "progress" };
    case "approval": return { message: `Approve in the OpenKey window to install ${entry.name}`, tone: "progress" };
    case "installing": return { message: `Installing ${entry.name}… ${state.done} of ${state.total} files`, tone: "progress" };
    case "registering": return { message: `Adding ${entry.name} to your apps…`, tone: "progress" };
    case "failed": return failureText(entry, state.error);
    case "installed": {
      const { outcome } = state;
      if (outcome.kind === "already") return { message: "Already installed: your copy is kept.", tone: "success" };
      const kept = outcome.kept.length === 0 ? "" : ` ${outcome.kept.length} ${outcome.kept.length === 1 ? "file" : "files"} you already had ${outcome.kept.length === 1 ? "was" : "were"} kept.`;
      const listed = outcome.listed ? "" : " Your apps list is still updating.";
      return { message: `Installed.${kept}${listed}`, tone: "success" };
    }
  }
}

function openControl(entry: CatalogEntry): HTMLElement {
  if (RUNNER_AVAILABLE) return el("a", "tc-button tc-button--primary apps-button", [`Open ${entry.name}`], { href: runnerHref(entry.app_id) });
  const button = el("button", "tc-button apps-button", [`Open ${entry.name}`], { type: "button", disabled: "" });
  button.disabled = true;
  return button;
}

/** The install sheet: the pre-consent text, then the live state of this app's install. */
function installContent(entry: CatalogEntry, catalog: readonly CatalogEntry[], ports: () => InstallPorts, close: () => void): { header: HTMLElement; body: HTMLElement; footer: HTMLElement; detach: () => void } {
  const header = sheetHeader("Install", `Install ${entry.name} to your TinyCloud`, entry, close);
  const consentBody = el("div", "apps-access-region", [], { "aria-live": "polite" });
  const body = el("div", "apps-sheet__body", [consentBody]);
  const status = el("div", "apps-install-status", [], { "aria-live": "polite" });
  const actions = el("div", "apps-install-actions", []);
  const footer = el("footer", "apps-sheet__footer apps-sheet__footer--install", [status, actions]);
  let consentLoaded = false;

  const button = (label: string, className: string, onClick: () => void, disabled = false): HTMLButtonElement => {
    const node = el("button", `${className} apps-button`, [label], { type: "button" });
    node.disabled = disabled;
    node.addEventListener("click", onClick);
    return node;
  };

  const begin = (): void => {
    // A second click while an install is running joins it: one flight per app, one sign-in.
    const flight = startInstall(entry, ports);
    attach(flight);
  };

  let current: InstallFlight | undefined;
  const repaint = (): void => {
    const flight = current;
    if (flight === undefined) {
      status.replaceChildren();
      actions.replaceChildren(button("Continue", "tc-button tc-button--primary", begin, !consentLoaded), button("Not now", "tc-button", close));
      return;
    }
    const text = statusFor(entry, flight);
    const line = el("p", `tc-status tc-status--${text.tone === "progress" || text.tone === "neutral" ? "info" : text.tone} apps-install-line`, [text.message], text.tone === "danger" ? { role: "alert" } : {});
    const parts: HTMLElement[] = [line];
    const state = flight.state;
    if (state.phase === "failed" && state.error.written.length > 0) {
      parts.push(el("details", "apps-files", [el("summary", null, [`Saved so far (${state.error.written.length})`]), el("ul", "apps-notes", state.error.written.map((key) => el("li", null, [el("code", null, [key])])))]));
    }
    if (state.phase === "installed") parts.push(el("p", "apps-muted", [RUNNER_AVAILABLE ? "" : OPEN_NOT_YET]));
    status.replaceChildren(...parts);
    if (flight.active) actions.replaceChildren(button("Installing…", "tc-button tc-button--primary", () => undefined, true), button("Close", "tc-button", close));
    else if (state.phase === "installed") actions.replaceChildren(openControl(entry), button("Done", "tc-button tc-button--primary", close));
    else actions.replaceChildren(button("Try again", "tc-button tc-button--primary", begin), button("Close", "tc-button", close));
  };

  const attach = (flight: InstallFlight): void => {
    current?.subscribers.delete(repaint);
    current = flight;
    flight.subscribers.add(repaint);
    repaint();
  };

  // Reopening the sheet while an install runs (or after it ended) shows that install, not a fresh Continue.
  const existing = flightFor(entry.app_id);
  if (existing !== undefined) attach(existing);
  else repaint();
  void renderConsent(entry, catalog, consentBody).then((loaded) => {
    consentLoaded = loaded;
    if (current === undefined) repaint();
  });
  return { header, body, footer, detach: () => { current?.subscribers.delete(repaint); } };
}

// ---------------------------------------------------------------------------
// Details

function detailsContent(entry: CatalogEntry, catalog: readonly CatalogEntry[], close: () => void, install: () => void): { header: HTMLElement; body: HTMLElement; footer: HTMLElement } {
  const header = sheetHeader(`by ${entry.publisher.name}`, entry.name, entry, close);
  const access = el("div", "apps-access-region", [], { "aria-live": "polite" });
  const body = el("div", "apps-sheet__body", [el("p", "apps-sheet__lede", [entry.description]), access, provenance(entry)]);
  const installNow = el("button", "tc-button tc-button--primary apps-button", ["Install"], { type: "button", "aria-label": `Install ${entry.name}`, "aria-describedby": INSTALL_NOTE_ID });
  installNow.addEventListener("click", install);
  const footer = el("footer", "apps-sheet__footer", [installNow, el("p", "apps-muted", ["You'll see what it asks for before anything is saved."])]);
  void renderAccess(entry, catalog, access);
  return { header, body, footer };
}

export interface MountOptions {
  /** The install flow's sign-in and node. Created when Install is clicked; the default loads OpenKey and the SDK then. */
  ports?: () => InstallPorts;
}

export function mountApps(list: HTMLElement, sheet: HTMLDialogElement, entries: CatalogEntry[], options: MountOptions = {}): void {
  const ports = options.ports ?? createInstallPorts;
  let opener: HTMLElement | null = null;
  let detach: (() => void) | undefined;
  const close = (): void => { sheet.close(); };
  sheet.addEventListener("close", () => {
    // An install in progress keeps running; only this sheet's view of it goes away.
    detach?.();
    detach = undefined;
    sheet.replaceChildren();
    opener?.focus();
    opener = null;
  });
  // A click on the backdrop lands on the dialog element itself, outside its content.
  sheet.addEventListener("click", (event) => { if (event.target === sheet) close(); });

  const show = (entry: CatalogEntry, mode: "details" | "install"): void => {
    detach?.();
    detach = undefined;
    if (mode === "install") {
      const content = installContent(entry, entries, ports, close);
      detach = content.detach;
      sheet.replaceChildren(content.header, content.body, content.footer);
    } else {
      const { header, body, footer } = detailsContent(entry, entries, close, () => show(entry, "install"));
      sheet.replaceChildren(header, body, footer);
    }
    if (!sheet.open) sheet.showModal();
  };

  if (entries.length === 0) {
    list.replaceWith(el("p", "apps-empty", ["No apps are listed yet."]));
    return;
  }
  for (const entry of entries) {
    const details = el("button", "tc-button apps-button", ["Details"], { type: "button", "aria-label": `Details for ${entry.name}` });
    details.addEventListener("click", () => { opener = details; show(entry, "details"); });
    const install = el("button", "tc-button tc-button--primary apps-button", ["Install"], { type: "button", "aria-label": `Install ${entry.name}`, "aria-describedby": INSTALL_NOTE_ID });
    install.addEventListener("click", () => { opener = install; show(entry, "install"); });
    list.append(el("li", "apps-card tc-panel", [
      el("h2", "apps-card__name", [entry.name]),
      el("p", "apps-card__meta", [`${entry.publisher.name} · ${versionLabel(entry)}`, ...(entry.sample === true ? [" ", el("span", "tc-badge apps-badge", ["Sample"])] : [])]),
      el("p", "apps-card__description", [entry.description]),
      el("div", "apps-card__actions", [details, install]),
    ]));
  }
}
