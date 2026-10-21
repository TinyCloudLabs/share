import { beforeEach, describe, expect, it, vi } from "vitest";

import { catalog } from "../src/apps/catalog.ts";
import { guardedUninstallPorts, mountApps } from "../src/apps/view.ts";
import { UninstallError, uninstallPlan } from "../src/apps/uninstall-plan.ts";
import type { UninstallPorts, UninstallSession } from "../src/apps/uninstall.ts";
import { runUninstall } from "../src/apps/uninstall.ts";

const HEALTH = "xyz.tinycloud.sample.healthlog";
const entry = catalog.apps.find((candidate) => candidate.app_id === HEALTH)!;
const plan = uninstallPlan(entry);

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
function fakeUninstall(options: { openFails?: UninstallError; registryFails?: boolean; keys?: string[] } = {}): FakeUninstall {
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
        list: async () => ({ keys: options.keys ?? [], truncated: false }),
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

  it("makes the confirm body keyboard-focusable, so a long delete list can be scrolled", () => {
    openConfirm(fakeUninstall());
    expect(sheet.querySelector(".apps-sheet__body")?.getAttribute("tabindex")).toBe("0");
  });

  it("lists every delete the session will sign, taken from the same plan as the request", () => {
    openConfirm(fakeUninstall());
    const items = [...sheet.querySelectorAll<HTMLElement>(".apps-access__item")];
    // Every row the plan gives (the destructive grants and the reads) is on the sheet, once each.
    expect(items).toHaveLength(plan.rows.change.length + plan.rows.read.length);
    for (const change of plan.rows.change) {
      const item = items.find((node) => node.querySelector(".apps-access__text")?.textContent === change.description);
      expect(item).toBeDefined();
      expect(item!.textContent).toContain("del");
    }
    expect(plan.rows.change.map((row) => row.actions)).toEqual([["del"], ["del"], ["del"]]);
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
    const node = fakeUninstall({ keys: [`${HEALTH}/app/a.js`] });
    openConfirm(node);
    sheetButton("Remove app")!.click();
    await vi.waitFor(() => expect(line()).toMatch(/^Removed /));
    expect(node.opened).toBe(1);
    expect(node.removedRegistry).toEqual([HEALTH]);
    expect(node.disposed).toBe(1);
    expect(line()).toContain("Your app data and settings are kept.");
    expect(line()).toContain(`Open ${entry.name} again to restore it.`);
  });

  it("says nothing was there to remove when no app files were listed, and still removes the registry entry", async () => {
    const node = fakeUninstall();
    openConfirm(node);
    sheetButton("Remove app")!.click();
    await vi.waitFor(() => expect(line()).toMatch(/^Nothing to remove: /));
    expect(node.deleted).toEqual([]);
    expect(node.removedRegistry).toEqual([HEALTH]);
  });

  it("a failed registry step says the files are gone and offers Try again", async () => {
    const node = fakeUninstall({ registryFails: true });
    openConfirm(node);
    sheetButton("Remove app")!.click();
    await vi.waitFor(() => expect(line()).toBe("The app was removed; its entry in your account list couldn't be updated; try again."));
    expect(list.querySelector('[role="alert"]')?.textContent).toBe("The app was removed; its entry in your account list couldn't be updated; try again.");
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

function sessionStub(overrides: Partial<UninstallSession> = {}): UninstallSession {
  return {
    list: async () => ({ keys: [], truncated: false }),
    del: async () => undefined,
    removeRegistry: async () => undefined,
    dispose: async () => undefined,
    ...overrides,
  };
}

describe("cancelling the uninstall", () => {
  const hooks = { approval: vi.fn() };

  it("refuses to open a session once cancelled, and never reaches OpenKey", async () => {
    const openSession = vi.fn(async () => sessionStub());
    const guarded = guardedUninstallPorts({ openSession }, () => true);
    await expect(guarded.openSession(plan, hooks)).rejects.toMatchObject({ reason: "cancelled" });
    expect(openSession).not.toHaveBeenCalled();
  });

  it("disposes a session that resolves after cancel, and does not return it", async () => {
    let cancelled = false;
    const dispose = vi.fn(async () => undefined);
    const guarded = guardedUninstallPorts({ openSession: async () => { cancelled = true; return sessionStub({ dispose }); } }, () => cancelled);
    await expect(guarded.openSession(plan, hooks)).rejects.toMatchObject({ reason: "cancelled" });
    expect(dispose).toHaveBeenCalledTimes(1);
  });

  it("refuses list, del and registry removal once cancelled", async () => {
    let cancelled = false;
    const inner = {
      list: vi.fn(async () => ({ keys: [], truncated: false })),
      del: vi.fn(async () => undefined),
      removeRegistry: vi.fn(async () => undefined),
    };
    const session = await guardedUninstallPorts({ openSession: async () => sessionStub(inner) }, () => cancelled).openSession(plan, hooks);
    cancelled = true;
    await expect(session.list(`${HEALTH}/app/`)).rejects.toMatchObject({ reason: "cancelled" });
    await expect(session.del(`${HEALTH}/app/a.js`)).rejects.toMatchObject({ reason: "cancelled" });
    await expect(session.removeRegistry(HEALTH)).rejects.toMatchObject({ reason: "cancelled" });
    expect(inner.list).not.toHaveBeenCalled();
    expect(inner.del).not.toHaveBeenCalled();
    expect(inner.removeRegistry).not.toHaveBeenCalled();
  });

  it("a cancel while the first delete is pending stops before the next delete", async () => {
    let cancelled = false;
    const deleted: string[] = [];
    const session = sessionStub({
      list: async () => ({ keys: [`${HEALTH}/app/a.js`, `${HEALTH}/app/b.js`], truncated: false }),
      del: async (key) => { deleted.push(key); cancelled = true; },
    });
    // The guard refuses the second delete; the run reports that as a failed delete, and the view ignores it after Cancel.
    await expect(runUninstall(plan, guardedUninstallPorts({ openSession: async () => session }, () => cancelled), () => undefined)).rejects.toBeInstanceOf(UninstallError);
    expect(deleted).toEqual([`${HEALTH}/app/a.js`]);
  });
});
