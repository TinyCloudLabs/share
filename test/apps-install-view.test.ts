import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { type CatalogEntry, catalog } from "../src/apps/catalog.ts";
import { resetInstallFlights } from "../src/apps/install-flight.ts";
import { INSTALL_EXPIRY_MS, INSTALL_SESSION_LABEL } from "../src/apps/install-plan.ts";
import { InstallError, type InstallPorts, type InstallSession, type PutResult } from "../src/apps/install.ts";
import { mountApps } from "../src/apps/view.ts";

const HEALTH = "xyz.tinycloud.sample.healthlog";
const RECIPES = "xyz.tinycloud.sample.recipes";
const HOSTILE = "<img src=x onerror=\"window.__pwned=1\">";

const nodeArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
  const copy = Buffer.from(bytes);
  return copy.buffer.slice(copy.byteOffset, copy.byteOffset + copy.byteLength) as ArrayBuffer;
};

/** Serves the committed bundle files; a path in `tampered` gets different bytes. */
function stubBundleFetch(tampered: string[] = []): ReturnType<typeof vi.fn> {
  const stub = vi.fn(async (url: string) => {
    const bytes = readFileSync(join("public", url));
    const served = tampered.some((path) => url.endsWith(path)) ? Buffer.concat([bytes, Buffer.from("\n")]) : bytes;
    return { ok: true, status: 200, arrayBuffer: async () => nodeArrayBuffer(served) };
  });
  vi.stubGlobal("fetch", stub);
  return stub;
}

const entry = (appId: string): CatalogEntry => {
  const found = catalog.apps.find((app) => app.app_id === appId);
  if (found === undefined) throw new Error(appId);
  return found;
};

/** A node whose puts the test releases one by one, so each state is observable. */
function controlledPorts(options: { existing?: Set<string>; failAt?: number } = {}) {
  const sessions: number[] = [];
  const puts: string[] = [];
  const modalAtSignIn: boolean[] = [];
  const disposed: number[] = [];
  const gate: { approval?: (open: boolean) => void; release?: () => void } = {};
  const ports: InstallPorts = {
    fetch: async (url) => ({ ok: true, status: 200, arrayBuffer: async () => nodeArrayBuffer(readFileSync(join("public", url))) }),
    openSession: async (_manifest, hooks) => {
      sessions.push(1);
      // The sheet must not be a modal dialog while OpenKey's window opens: it would sit above the window.
      modalAtSignIn.push(sheet.hasAttribute("open"));
      gate.approval = hooks.approval;
      hooks.approval(true);
      await new Promise<void>((resolve) => { gate.release = resolve; });
      hooks.approval(false);
      const session: InstallSession = {
        put: async (key): Promise<PutResult> => {
          puts.push(key);
          if (options.failAt === puts.length) throw new Error("boom");
          return options.existing?.has(key) === true ? "exists" : "created";
        },
        confirmListed: async () => true,
        dispose: () => { disposed.push(1); },
      };
      return session;
    },
  };
  return { ports, sessions, puts, gate, modalAtSignIn, disposed };
}

let list: HTMLElement;
let sheet: HTMLDialogElement;
beforeEach(() => {
  resetInstallFlights();
  document.body.innerHTML = "<ul id=list></ul><dialog id=sheet></dialog>";
  list = document.querySelector<HTMLElement>("#list") as HTMLElement;
  sheet = document.querySelector<HTMLDialogElement>("#sheet") as HTMLDialogElement;
  sheet.showModal = () => { sheet.setAttribute("open", ""); };
  Object.defineProperty(sheet, "open", { configurable: true, get: () => sheet.hasAttribute("open") });
  sheet.close = () => { sheet.removeAttribute("open"); sheet.dispatchEvent(new Event("close")); };
  Reflect.deleteProperty(window, "__pwned");
});

const buttons = (root: ParentNode, label: string): HTMLButtonElement[] => [...root.querySelectorAll("button")].filter((button) => button.textContent === label);
const cardInstall = (appId: string): HTMLButtonElement => {
  const index = catalog.apps.findIndex((app) => app.app_id === appId);
  const found = list.children[index]?.querySelectorAll("button")[1];
  if (found === undefined) throw new Error(appId);
  return found;
};
const loaded = async (): Promise<void> => { await vi.waitFor(() => expect(sheet.querySelector("[aria-busy]")).toBeNull()); await vi.waitFor(() => expect(buttons(sheet, "Continue")[0]?.disabled).toBe(false)); };
/** The inline panel under the card: where an install reports, because the sheet is closed (not modal) while OpenKey's window is up. */
const status = (): string => list.querySelector(".apps-install-panel .apps-install-line")?.textContent ?? "";
const panel = (): HTMLElement | null => list.querySelector<HTMLElement>(".apps-install-panel");
const panelButtons = (label: string): HTMLButtonElement[] => [...list.querySelectorAll(".apps-install-panel button")].filter((node) => node.textContent === label) as HTMLButtonElement[];

describe("the install sheet before anything is signed", () => {
  it("states the sample notice, the SQL notice and what the sign-in grants, from the verified manifest only", async () => {
    stubBundleFetch();
    mountApps(list, sheet, catalog.apps, { ports: () => controlledPorts().ports });
    cardInstall(HEALTH).click();
    await loaded();
    const text = sheet.textContent ?? "";
    expect(sheet.querySelector("h2")?.textContent).toBe("Install Health Log (sample) to your TinyCloud");
    expect(text).toContain("Sample app: use throwaway data only.");
    expect(text).toContain("This app can change or delete its own tables.");
    expect(text).toContain(`${HEALTH}/app/`);
    expect(text).toContain(`${HEALTH}/knowledge/`);
    expect(text).toContain("Files you already have there are kept, never replaced.");
    expect(text).toContain("None of this is granted now.");
    expect(text).not.toContain("coming next");
    // The installer's grants are the two put-only folders, shown with the account list's own permissions.
    expect(text).toContain("Account list permissions");
    expect(buttons(sheet, "Continue")).toHaveLength(1);
    expect(buttons(sheet, "Not now")).toHaveLength(1);
  });

  it("says how long the session lasts, and that number is the one the session is signed for", async () => {
    stubBundleFetch();
    mountApps(list, sheet, catalog.apps, { ports: () => controlledPorts().ports });
    cardInstall(HEALTH).click();
    await loaded();
    // Read the number back from the rendered sentence: a literal in the view or a changed constant alone makes this fail.
    const said = /For the next (\d+) minutes?, Share can then:/.exec(sheet.textContent ?? "");
    expect(said, "the sheet states the session length").not.toBeNull();
    expect(Number(said?.[1]) * 60_000).toBe(INSTALL_EXPIRY_MS);
    expect(sheet.textContent).toContain(`For the next ${INSTALL_SESSION_LABEL}, Share can then:`);
  });

  it("lists a cross-app read as a whole-database read", async () => {
    stubBundleFetch();
    mountApps(list, sheet, catalog.apps, { ports: () => controlledPorts().ports });
    cardInstall(RECIPES).click();
    await loaded();
    expect(sheet.textContent).toContain("This app can read Health Log (sample)'s database (whole database).");
    expect(sheet.textContent).toContain("Sample app: use throwaway data only.");
  });

  it("a manifest the page cannot describe (a delegate DID) cannot be installed, and says why", async () => {
    const manifest = { ...JSON.parse(readFileSync(join("public", entry(HEALTH).bundle.root, "manifest.json"), "utf8")), did: "did:key:z6MkexampleexampleexampleexampleexampleexampleABC" };
    const bytes = Buffer.from(JSON.stringify(manifest));
    const sha = createHash("sha256").update(bytes).digest("hex");
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: true, status: 200, arrayBuffer: async () => nodeArrayBuffer(bytes) })));
    mountApps(list, sheet, [{ ...entry(HEALTH), app_id: "t.delegate", manifest: { path: "manifest.json", sha256: sha } }], { ports: () => { throw new Error("never"); } });
    list.querySelectorAll("button")[1]?.click();
    await vi.waitFor(() => expect(sheet.querySelector("[role=alert]")?.textContent).toContain("can't describe"));
    expect(sheet.querySelector("[role=alert]")?.textContent).toContain("did");
    expect(buttons(sheet, "Continue")[0]?.disabled).toBe(true);
  });

  it("a manifest that does not match the catalog cannot be installed", async () => {
    stubBundleFetch(["manifest.json"]);
    // A distinct app id: a manifest that verified in an earlier test is cached by app id.
    mountApps(list, sheet, [{ ...entry(HEALTH), app_id: "t.mismatch" }], { ports: () => { throw new Error("never"); } });
    list.querySelectorAll("button")[1]?.click();
    await vi.waitFor(() => expect(sheet.querySelector("[role=alert]")?.textContent).toContain("doesn't match the catalog"));
    expect(buttons(sheet, "Continue")[0]?.disabled).toBe(true);
  });

  it("sets catalog text as text in the install sheet", async () => {
    const base = entry(HEALTH);
    const hostile: CatalogEntry = { ...base, name: HOSTILE };
    stubBundleFetch();
    mountApps(list, sheet, [hostile], { ports: () => controlledPorts().ports });
    list.querySelectorAll("button")[1]?.click();
    await vi.waitFor(() => expect(sheet.querySelector("h2")?.textContent).toBe(`Install ${HOSTILE} to your TinyCloud`));
    expect(sheet.querySelectorAll("img, script, iframe, svg")).toHaveLength(0);
    expect((window as unknown as Record<string, unknown>).__pwned).toBeUndefined();
  });
});

describe("the states of an install", () => {
  it("Continue closes the sheet FIRST; progress, approval and the result are inline; a double click is one sign-in; Open links to the runner", async () => {
    stubBundleFetch();
    const node = controlledPorts();
    const portsFactory = vi.fn(() => node.ports);
    mountApps(list, sheet, catalog.apps, { ports: portsFactory });
    cardInstall(HEALTH).click();
    await loaded();
    expect(sheet.hasAttribute("open")).toBe(true);
    const continueButton = buttons(sheet, "Continue")[0] as HTMLButtonElement;
    continueButton.click();
    // Nothing modal is left on the page: the dialog is closed before the sign-in is even asked for.
    expect(sheet.hasAttribute("open")).toBe(false);
    continueButton.click();
    await vi.waitFor(() => expect(status()).toContain("Approval 1 of up to 4: approve in the OpenKey window to install Health Log (sample)"));
    expect(node.sessions).toHaveLength(1);
    expect(node.modalAtSignIn).toEqual([false]);
    expect(portsFactory).toHaveBeenCalledTimes(1); // the second click joined the running flight
    // A live region under the card, holding focus, with a visible Cancel.
    expect(panel()?.closest(".apps-card")).not.toBeNull();
    expect(panel()?.querySelector(".apps-install-status")?.getAttribute("role")).toBe("status");
    expect(panel()?.querySelector(".apps-install-status")?.getAttribute("aria-live")).toBe("polite");
    expect(document.activeElement).toBe(panel());
    expect(panelButtons("Cancel")).toHaveLength(1);

    node.gate.release?.();
    await vi.waitFor(() => expect(status()).toContain("Installed."));
    expect(node.puts.at(-1)).toBe(`${HEALTH}/app/install.json`);
    expect(node.sessions).toHaveLength(1);
    expect(node.disposed).toHaveLength(1);
    // Open is a link to the runner, with the app id in the fragment.
    expect(panel()?.textContent).not.toContain("coming next");
    expect(panel()?.querySelector(`a[href='/apps/run#${HEALTH}']`)?.textContent).toBe("Open Health Log (sample)");
    panelButtons("Done")[0]?.click();
    expect(panel()).toBeNull();
  });

  it("Cancel while the OpenKey window is open says so at once; a late approval writes nothing and closes the session", async () => {
    stubBundleFetch();
    const node = controlledPorts();
    mountApps(list, sheet, catalog.apps, { ports: () => node.ports });
    cardInstall(HEALTH).click();
    await loaded();
    buttons(sheet, "Continue")[0]?.click();
    await vi.waitFor(() => expect(status()).toContain("Approval 1 of up to 4"));
    panelButtons("Cancel")[0]?.click();
    expect(status()).toBe("Install cancelled. Nothing was installed. If an OpenKey window is still open, close it.");
    expect(panel()?.querySelector("[role=alert]")).toBeNull();
    expect(panelButtons("Try again")).toHaveLength(1);
    // The person approves in the window anyway: the session is closed and nothing is written.
    node.gate.release?.();
    await vi.waitFor(() => expect(node.disposed).toHaveLength(1));
    expect(node.puts).toEqual([]);
    expect(status()).toContain("Install cancelled");
  });

  it("Cancel before OpenKey was asked for opens no window at all", async () => {
    stubBundleFetch();
    const node = controlledPorts();
    mountApps(list, sheet, catalog.apps, { ports: () => node.ports });
    cardInstall(HEALTH).click();
    await loaded();
    buttons(sheet, "Continue")[0]?.click();
    // The files are still being checked: cancel now.
    panelButtons("Cancel")[0]?.click();
    await new Promise((done) => setTimeout(done, 50));
    expect(node.sessions).toHaveLength(0);
    expect(status()).toBe("Install cancelled. Nothing was installed.");
  });

  it("Escape in the panel cancels while it runs", async () => {
    stubBundleFetch();
    const node = controlledPorts();
    mountApps(list, sheet, catalog.apps, { ports: () => node.ports });
    cardInstall(HEALTH).click();
    await loaded();
    buttons(sheet, "Continue")[0]?.click();
    await vi.waitFor(() => expect(status()).toContain("Approval 1 of up to 4"));
    panel()?.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    expect(status()).toContain("Install cancelled");
    // Once it has ended Escape does nothing more.
    panel()?.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    expect(panel()).not.toBeNull();
  });

  it("pressing Install again while it runs shows the running install and opens no second sheet", async () => {
    stubBundleFetch();
    const node = controlledPorts();
    const portsFactory = vi.fn(() => node.ports);
    mountApps(list, sheet, catalog.apps, { ports: portsFactory });
    cardInstall(HEALTH).click();
    await loaded();
    buttons(sheet, "Continue")[0]?.click();
    await vi.waitFor(() => expect(status()).toContain("Approval 1 of up to 4"));
    cardInstall(HEALTH).click();
    expect(sheet.hasAttribute("open")).toBe(false);
    expect(document.activeElement).toBe(panel());
    expect(node.sessions).toHaveLength(1);
    node.gate.release?.();
    await vi.waitFor(() => expect(status()).toContain("Installed."));
  });

  it("says Already installed: your copy is kept when everything is there", async () => {
    stubBundleFetch();
    const base = entry(HEALTH);
    const existing = new Set([...base.bundle.files.map((file) => (file.path.startsWith("knowledge/") ? `${HEALTH}/${file.path}` : `${HEALTH}/app/${file.path}`)), `${HEALTH}/app/install.json`]);
    const node = controlledPorts({ existing });
    mountApps(list, sheet, catalog.apps, { ports: () => node.ports });
    cardInstall(HEALTH).click();
    await loaded();
    buttons(sheet, "Continue")[0]?.click();
    await vi.waitFor(() => expect(node.gate.release).toBeDefined());
    node.gate.release?.();
    await vi.waitFor(() => expect(status()).toContain("Already installed: your copy is kept."));
  });

  it("reports what was saved when a write fails and offers Try again, inline", async () => {
    stubBundleFetch();
    const node = controlledPorts({ failAt: 4 });
    mountApps(list, sheet, catalog.apps, { ports: () => node.ports });
    cardInstall(HEALTH).click();
    await loaded();
    buttons(sheet, "Continue")[0]?.click();
    await vi.waitFor(() => expect(node.gate.release).toBeDefined());
    node.gate.release?.();
    await vi.waitFor(() => expect(status()).toContain("Not installed yet: 3 of 15 files were saved."));
    expect(panel()?.querySelector(".apps-install-status [role=alert]")).not.toBeNull();
    expect(panel()?.querySelector(".apps-install-status details")?.textContent).toContain(`${HEALTH}/`);
    expect(panelButtons("Try again")).toHaveLength(1);
    expect(panel()?.textContent).not.toContain("Installed.");
    // Dismiss, reopen: a fresh consent, not the old result.
    panelButtons("Dismiss")[0]?.click();
    expect(panel()).toBeNull();
    cardInstall(HEALTH).click();
    await loaded();
    expect(buttons(sheet, "Continue")).toHaveLength(1);
  });

  it("a tampered bundle says so and nothing was written", async () => {
    stubBundleFetch();
    const node = controlledPorts();
    // The manifest is untouched, so the sheet loads; the other file differs from the catalog.
    mountApps(list, sheet, catalog.apps, { ports: () => ({ ...node.ports, fetch: async (url) => ({ ok: true, status: 200, arrayBuffer: async () => nodeArrayBuffer(Buffer.concat([readFileSync(join("public", url)), url.endsWith("knowledge/app.md") ? Buffer.from("x") : Buffer.alloc(0)])) }) }) });
    cardInstall(HEALTH).click();
    await loaded();
    buttons(sheet, "Continue")[0]?.click();
    await vi.waitFor(() => expect(status()).toContain("files don't match the catalog, so nothing was installed"));
    expect(node.sessions).toHaveLength(0);
    expect(node.puts).toEqual([]);
  });

  it("a cancelled sign-in (in OpenKey's own window) is a quiet note, not an alert", async () => {
    stubBundleFetch();
    const node = controlledPorts();
    const ports: InstallPorts = { ...node.ports, openSession: async () => { throw new InstallError("cancelled"); } };
    mountApps(list, sheet, catalog.apps, { ports: () => ports });
    cardInstall(HEALTH).click();
    await loaded();
    buttons(sheet, "Continue")[0]?.click();
    await vi.waitFor(() => expect(status()).toContain("Sign-in cancelled. Nothing was installed."));
    expect(panel()?.querySelector(".apps-install-status [role=alert]")).toBeNull();
  });
});

describe("the kill switch on the page", () => {
  const HOSTILE_REASON = "<img src=x onerror=\"window.__pwned=1\"> Pulled while a problem is looked into.";
  const off = (): CatalogEntry => ({ ...entry(HEALTH), disabled: true, disabledReason: HOSTILE_REASON });

  it("shows 'Temporarily unavailable' and the reason as text on the card, with Install disabled", () => {
    const fetchSpy = stubBundleFetch();
    mountApps(list, sheet, [off(), entry(RECIPES)], { ports: () => { throw new Error("never"); } });
    const [first, second] = [...list.children] as HTMLElement[];
    expect(first?.textContent).toContain("Temporarily unavailable");
    expect(first?.textContent).toContain(HOSTILE_REASON);
    expect(first?.querySelectorAll("img, script, iframe, svg")).toHaveLength(0);
    expect((window as unknown as Record<string, unknown>).__pwned).toBeUndefined();
    expect(buttons(first as HTMLElement, "Install")[0]?.disabled).toBe(true);
    expect(buttons(first as HTMLElement, "Details")[0]?.disabled).toBe(false);
    // The other card is untouched.
    expect(second?.textContent).not.toContain("Temporarily unavailable");
    expect(buttons(second as HTMLElement, "Install")[0]?.disabled).toBe(false);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("the details sheet says so and its Install is disabled", async () => {
    stubBundleFetch();
    mountApps(list, sheet, [off()], { ports: () => { throw new Error("never"); } });
    list.querySelector<HTMLButtonElement>("button")?.click();
    await vi.waitFor(() => expect(sheet.querySelector("[aria-busy]")).toBeNull());
    expect(sheet.textContent).toContain("Temporarily unavailable");
    expect(sheet.textContent).toContain(HOSTILE_REASON);
    expect(buttons(sheet, "Install")[0]?.disabled).toBe(true);
  });

  it("even a forced click opens no install: no manifest fetch, no Continue, no ports, no OpenKey", () => {
    const fetchSpy = stubBundleFetch();
    const makePorts = vi.fn(() => { throw new Error("the install ports must not be created"); });
    mountApps(list, sheet, [off()], { ports: makePorts });
    const install = buttons(list, "Install")[0] as HTMLButtonElement;
    install.disabled = false; // what a script or a stale button could do
    install.click();
    expect(sheet.textContent).toContain("Temporarily unavailable");
    expect(sheet.textContent).toContain("can't be installed right now");
    expect(buttons(sheet, "Continue")).toHaveLength(0);
    expect(makePorts).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
