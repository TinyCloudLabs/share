/**
 * DOM for the apps page. Everything that comes from the catalog or a manifest
 * is set with textContent (or a validated https href); there is no innerHTML,
 * so Trusted Types can stay required for scripts.
 */
import { type AccessItem, type AccessSummary, summarizeAccess } from "./access.ts";
import { type CatalogEntry, versionLabel } from "./catalog.ts";
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

/** Install is not wired up yet; the control exists so the page shows where it will be. */
function installButton(): HTMLButtonElement {
  const button = el("button", "tc-button tc-button--primary apps-button", ["Install"], { type: "button", "aria-describedby": INSTALL_NOTE_ID });
  button.disabled = true;
  return button;
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
      el("code", null, [item.target]),
      el("span", "apps-access__actions", [item.actions.join(", ")]),
    ]),
  ])));
}

function accessSection(title: string, empty: string, items: AccessItem[]): HTMLElement {
  return el("section", "apps-section", [el("h3", null, [title]), items.length === 0 ? el("p", "apps-muted", [empty]) : accessList(items)]);
}

function secretsSection(secrets: AccessSummary["secrets"]): HTMLElement | null {
  if (secrets.length === 0) return null;
  return el("section", "apps-section", [
    el("h3", null, ["Secrets it uses"]),
    el("ul", "apps-access", secrets.map((secret) => el("li", "apps-access__item", [
      el("p", secret.description === null ? "apps-access__text apps-access__text--missing" : "apps-access__text", [secret.description ?? "The app gave no description for this."]),
      el("p", "apps-access__meta", [el("code", null, [secret.name]), el("span", "apps-access__actions", [secret.required ? "required" : "optional"])]),
    ]))),
  ]);
}

function skeleton(): HTMLElement {
  return el("div", "apps-skeleton", [
    el("div", "tc-skeleton apps-skeleton__line apps-skeleton__line--short"),
    el("div", "tc-skeleton apps-skeleton__line"),
    el("div", "tc-skeleton apps-skeleton__line"),
    el("div", "tc-skeleton apps-skeleton__line apps-skeleton__line--short"),
  ], { "aria-hidden": "true" });
}

/** Fills `target` with the app's access lists, or an honest failure; never partial manifest data. */
async function renderAccess(entry: CatalogEntry, target: HTMLElement): Promise<void> {
  target.setAttribute("aria-busy", "true");
  target.replaceChildren(skeleton());
  const result = await loadManifest(entry);
  if (!target.isConnected) return;
  target.removeAttribute("aria-busy");
  if (!result.ok) {
    const message = result.reason === "mismatch"
      ? "This app's manifest doesn't match the catalog, so what it can do isn't shown."
      : "Couldn't load this app's manifest. Close this panel and open it again to retry.";
    target.replaceChildren(el("p", "tc-status tc-status--danger", [message], { role: "alert" }));
    return;
  }
  const summary = summarizeAccess(result.manifest);
  const secrets = secretsSection(summary.secrets);
  target.replaceChildren(
    accessSection("It can read", "Nothing.", summary.read),
    accessSection("It can change", "Nothing. This app can't change your data.", summary.change),
    ...(secrets === null ? [] : [secrets]),
  );
}

function sheetContent(entry: CatalogEntry, close: () => void): { header: HTMLElement; body: HTMLElement; footer: HTMLElement } {
  const closeButton = el("button", "tc-button tc-button--compact apps-button", ["Close"], { type: "button", "aria-label": `Close details for ${entry.name}` });
  closeButton.addEventListener("click", close);
  const header = el("header", "apps-sheet__header", [
    el("div", "apps-sheet__heading", [el("p", "apps-kicker", [`by ${entry.publisher.name}`]), el("h2", null, [entry.name], { id: "sheet-title" })]),
    closeButton,
  ]);

  const access = el("div", "apps-access-region", [], { "aria-live": "polite" });
  const files = el("details", "apps-files", [
    el("summary", null, [`Pinned files (${entry.bundle.files.length})`]),
    el("dl", "apps-rows", entry.bundle.files.map((file) => dataRow(`${file.path} · ${file.size} bytes`, file.sha256))),
  ]);
  const body = el("div", "apps-sheet__body", [
    el("p", "apps-sheet__lede", [entry.description]),
    access,
    el("section", "apps-section", [
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
    ]),
  ]);
  const footer = el("footer", "apps-sheet__footer", [installButton(), el("p", "apps-muted", ["Install isn't available yet."])]);
  void renderAccess(entry, access);
  return { header, body, footer };
}

export function mountApps(list: HTMLElement, sheet: HTMLDialogElement, entries: CatalogEntry[]): void {
  let opener: HTMLElement | null = null;
  const close = (): void => { sheet.close(); };
  sheet.addEventListener("close", () => {
    sheet.replaceChildren();
    opener?.focus();
    opener = null;
  });
  // A click on the backdrop lands on the dialog element itself, outside its content.
  sheet.addEventListener("click", (event) => { if (event.target === sheet) close(); });

  if (entries.length === 0) {
    list.replaceWith(el("p", "apps-empty", ["No apps are listed yet."]));
    return;
  }
  for (const entry of entries) {
    const details = el("button", "tc-button apps-button", ["Details"], { type: "button", "aria-label": `Details for ${entry.name}` });
    details.addEventListener("click", () => {
      opener = details;
      const { header, body, footer } = sheetContent(entry, close);
      sheet.replaceChildren(header, body, footer);
      sheet.showModal();
    });
    list.append(el("li", "apps-card tc-panel", [
      el("h2", "apps-card__name", [entry.name]),
      el("p", "apps-card__meta", [`${entry.publisher.name} · ${versionLabel(entry)}`]),
      el("p", "apps-card__description", [entry.description]),
      el("div", "apps-card__actions", [details, installButton()]),
    ]));
  }
}
