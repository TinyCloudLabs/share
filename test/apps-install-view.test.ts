import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { type CatalogEntry, catalog } from "../src/apps/catalog.ts";
import { resetInstallFlights } from "../src/apps/install-flight.ts";
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
    return { ok: true, status: 200, headers: new Headers(), arrayBuffer: async () => nodeArrayBuffer(served) };
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
  const gate: { approval?: (open: boolean) => void; release?: () => void } = {};
  const ports: InstallPorts = {
    fetch: async (url) => ({ ok: true, status: 200, headers: new Headers(), arrayBuffer: async () => nodeArrayBuffer(readFileSync(join("public", url))) }),
    openSession: async (_manifest, hooks) => {
      sessions.push(1);
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
        dispose: () => undefined,
      };
      return session;
    },
  };
  return { ports, sessions, puts, gate };
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
const status = (): string => sheet.querySelector(".apps-install-status")?.textContent ?? "";

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
    expect(text).toContain("Opening installed apps is coming next.");
    // The installer's grants are the two put-only folders, shown with the account list's own permissions.
    expect(text).toContain("Account list permissions");
    expect(buttons(sheet, "Continue")).toHaveLength(1);
    expect(buttons(sheet, "Not now")).toHaveLength(1);
  });

  it("lists a cross-app read as a whole-database read", async () => {
    stubBundleFetch();
    mountApps(list, sheet, catalog.apps, { ports: () => controlledPorts().ports });
    cardInstall(RECIPES).click();
    await loaded();
    expect(sheet.textContent).toContain("This app can read Health Log (sample)'s database (whole database).");
    expect(sheet.textContent).toContain("Sample app: use throwaway data only.");
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
  it("goes pending approval, installing, installed; a double click is one sign-in; Open is not offered yet", async () => {
    stubBundleFetch();
    const node = controlledPorts();
    const portsFactory = vi.fn(() => node.ports);
    mountApps(list, sheet, catalog.apps, { ports: portsFactory });
    cardInstall(HEALTH).click();
    await loaded();
    const continueButton = buttons(sheet, "Continue")[0] as HTMLButtonElement;
    continueButton.click();
    continueButton.click();
    await vi.waitFor(() => expect(status()).toContain("Approve in the OpenKey window to install Health Log (sample)"));
    expect(node.sessions).toHaveLength(1);
    expect(portsFactory).toHaveBeenCalledTimes(1); // the second click joined the running flight
    expect(sheet.querySelector(".apps-install-status")?.getAttribute("aria-live")).toBe("polite");
    expect(buttons(sheet, "Installing…")[0]?.disabled).toBe(true);

    node.gate.release?.();
    await vi.waitFor(() => expect(status()).toContain("Installed."));
    expect(node.puts.at(-1)).toBe(`${HEALTH}/app/install.json`);
    expect(node.sessions).toHaveLength(1);
    // The runner is the next slice: say so, and do not link to it.
    expect(sheet.textContent).toContain("Opening installed apps is coming next.");
    expect(buttons(sheet, "Open Health Log (sample)")[0]?.disabled).toBe(true);
    expect(sheet.querySelector("a[href^='/apps/run']")).toBeNull();
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

  it("reports what was saved when a write fails, offers Try again, and reopening shows the same flight", async () => {
    stubBundleFetch();
    const node = controlledPorts({ failAt: 4 });
    mountApps(list, sheet, catalog.apps, { ports: () => node.ports });
    cardInstall(HEALTH).click();
    await loaded();
    buttons(sheet, "Continue")[0]?.click();
    await vi.waitFor(() => expect(node.gate.release).toBeDefined());
    node.gate.release?.();
    await vi.waitFor(() => expect(status()).toContain("Not installed yet: 3 of 15 files were saved."));
    expect(sheet.querySelector(".apps-install-status [role=alert]")).not.toBeNull();
    expect(sheet.querySelector(".apps-install-status details")?.textContent).toContain(`${HEALTH}/`);
    expect(buttons(sheet, "Try again")).toHaveLength(1);
    expect(sheet.textContent).not.toContain("Installed.");

    // Close and reopen: the sheet shows how that install ended, not a fresh Continue.
    sheet.close();
    cardInstall(HEALTH).click();
    await vi.waitFor(() => expect(status()).toContain("Not installed yet"));
    expect(buttons(sheet, "Continue")).toHaveLength(0);
  });

  it("a tampered bundle says so and nothing was written", async () => {
    stubBundleFetch();
    const node = controlledPorts();
    // The manifest is untouched, so the sheet loads; the other file differs from the catalog.
    mountApps(list, sheet, catalog.apps, { ports: () => ({ ...node.ports, fetch: async (url) => ({ ok: true, status: 200, headers: new Headers(), arrayBuffer: async () => nodeArrayBuffer(Buffer.concat([readFileSync(join("public", url)), url.endsWith("knowledge/app.md") ? Buffer.from("x") : Buffer.alloc(0)])) }) }) });
    cardInstall(HEALTH).click();
    await loaded();
    buttons(sheet, "Continue")[0]?.click();
    await vi.waitFor(() => expect(status()).toContain("files don't match the catalog, so nothing was installed"));
    expect(node.sessions).toHaveLength(0);
    expect(node.puts).toEqual([]);
  });

  it("a cancelled sign-in is a quiet note, not an alert", async () => {
    stubBundleFetch();
    const node = controlledPorts();
    const ports: InstallPorts = { ...node.ports, openSession: async () => { throw new InstallError("cancelled"); } };
    mountApps(list, sheet, catalog.apps, { ports: () => ports });
    cardInstall(HEALTH).click();
    await loaded();
    buttons(sheet, "Continue")[0]?.click();
    await vi.waitFor(() => expect(status()).toContain("Sign-in cancelled. Nothing was installed."));
    expect(sheet.querySelector(".apps-install-status [role=alert]")).toBeNull();
  });
});
