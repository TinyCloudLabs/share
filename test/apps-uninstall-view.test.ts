import { beforeEach, describe, expect, it, vi } from "vitest";

import { catalog } from "../src/apps/catalog.ts";
import { mountApps } from "../src/apps/view.ts";
import { UninstallError } from "../src/apps/uninstall-plan.ts";
import type { UninstallPorts, UninstallSession } from "../src/apps/uninstall.ts";

const HEALTH = "xyz.tinycloud.sample.healthlog";
const entry = catalog.apps.find((candidate) => candidate.app_id === HEALTH)!;

let list: HTMLElement;
let sheet: HTMLDialogElement;
beforeEach(() => {
  document.body.innerHTML = "<ul id=list></ul><dialog id=sheet></dialog>";
  list = document.querySelector<HTMLElement>("#list") as HTMLElement;
  sheet = document.querySelector<HTMLDialogElement>("#sheet") as HTMLDialogElement;
  sheet.showModal = () => { sheet.setAttribute("open", ""); };
  sheet.close = () => { sheet.removeAttribute("open"); sheet.dispatchEvent(new Event("close")); };
});

interface FakeUninstall {
  ports: UninstallPorts;
  opened: number;
  removedRegistry: string[];
  deleted: string[];
  disposed: number;
}

/** Ports whose session lists nothing (so the run only does the registry step) unless a case overrides it. */
function fakeUninstall(options: { openFails?: UninstallError; registryFails?: boolean } = {}): FakeUninstall {
  const state: FakeUninstall = {
    ports: undefined as unknown as UninstallPorts,
    opened: 0,
    removedRegistry: [],
    deleted: [],
    disposed: 0,
  };
  state.ports = {
    async openSession(): Promise<UninstallSession> {
      state.opened += 1;
      if (options.openFails !== undefined) throw options.openFails;
      return {
        list: async () => ({ keys: [], truncated: false }),
        del: async (key) => { state.deleted.push(key); },
        removeRegistry: async (appId) => {
          if (options.registryFails === true) throw new Error("uninstall-registry-failed:NETWORK_ERROR");
          state.removedRegistry.push(appId);
        },
        dispose: async () => { state.disposed += 1; },
      };
    },
  };
  return state;
}

const sheetButton = (label: string): HTMLButtonElement | undefined =>
  [...sheet.querySelectorAll("button")].find((node) => node.textContent === label);
const line = (): string => list.querySelector(".apps-install-panel .apps-install-line")?.textContent ?? "";

/** Card → Details → Uninstall: the confirm sheet is open with nothing run yet. */
function openConfirm(uninstall: FakeUninstall): void {
  mountApps(list, sheet, catalog.apps, { uninstallPorts: () => uninstall.ports });
  list.querySelector<HTMLButtonElement>(`button[aria-label='Details for ${entry.name}']`)!.click();
  sheet.querySelector<HTMLButtonElement>(`button[aria-label='Uninstall ${entry.name}']`)!.click();
}

describe("the uninstall confirm sheet", () => {
  it("says what goes, what stays and to close app tabs, and runs nothing until Remove app", () => {
    const node = fakeUninstall();
    openConfirm(node);
    const text = sheet.textContent ?? "";
    expect(text).toContain(`Remove ${entry.name}`);
    expect(text).toContain(`Remove ${entry.name}'s app files and agent notes?`);
    expect(text).toContain("Your app data, settings and files outside those folders stay.");
    expect(text).toContain("Notes you've edited in the app's knowledge folder will be removed.");
    expect(text).toContain("Close any open app tabs first.");
    expect(sheetButton("Remove app")).toBeDefined();
    expect(sheetButton("Keep app")).toBeDefined();
    expect(node.opened).toBe(0);
  });

  it("names the capabilities/read grant for the applications and account spaces, worded as the install sheet words it", () => {
    const node = fakeUninstall();
    openConfirm(node);
    const sentence = "See which permissions it has been given in this space (added automatically).";
    expect((sheet.textContent ?? "").split(sentence).length - 1).toBe(2);
    expect(sheet.textContent).toContain("space: account");
    expect(node.opened).toBe(0);
  });

  it("Keep app closes the sheet and touches no session", () => {
    const node = fakeUninstall();
    openConfirm(node);
    sheetButton("Keep app")!.click();
    expect(sheet.hasAttribute("open")).toBe(false);
    expect(node.opened).toBe(0);
    expect(list.querySelector(".apps-install-panel")).toBeNull();
  });
});

describe("the uninstall run", () => {
  it("Remove app runs once and reports the files and agent notes removed, with app data kept", async () => {
    const node = fakeUninstall();
    openConfirm(node);
    sheetButton("Remove app")!.click();
    await vi.waitFor(() => expect(line()).toMatch(/^Removed /));
    expect(node.opened).toBe(1);
    expect(node.removedRegistry).toEqual([HEALTH]);
    expect(node.disposed).toBe(1);
    expect(line()).toContain("Your app data and settings are kept.");
    expect(line()).toContain(`Install ${entry.name} again to restore it.`);
  });

  it("a failed registry step says the files are gone and offers Try again", async () => {
    const node = fakeUninstall({ registryFails: true });
    openConfirm(node);
    sheetButton("Remove app")!.click();
    await vi.waitFor(() => expect(line()).toBe("The app was removed; its entry in your account list couldn't be updated; try again."));
    const actions = [...list.querySelectorAll(".apps-install-panel button")].map((button) => button.textContent);
    expect(actions).toContain("Try again");
    expect(actions).toContain("Dismiss");
  });

  it("a wrong-account approval reports that nothing changed", async () => {
    const node = fakeUninstall({ openFails: new UninstallError("wrong-account") });
    openConfirm(node);
    sheetButton("Remove app")!.click();
    await vi.waitFor(() => expect(line()).toContain("Nothing was changed."));
    expect(line()).toContain("different account");
    expect(node.removedRegistry).toEqual([]);
  });
});
