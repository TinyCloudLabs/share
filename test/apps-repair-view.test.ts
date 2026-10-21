import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { catalog } from "../src/apps/catalog.ts";
import { RepairError, type RepairPorts, type RepairSession } from "../src/apps/repair.ts";
import { mountApps } from "../src/apps/view.ts";

const HEALTH = "xyz.tinycloud.sample.healthlog";
const entry = catalog.apps.find((candidate) => candidate.app_id === HEALTH)!;
const nodeBuffer = (bytes: Uint8Array): ArrayBuffer => { const copy = Buffer.from(bytes); return copy.buffer.slice(copy.byteOffset, copy.byteOffset + copy.byteLength) as ArrayBuffer; };

let list: HTMLElement;
let sheet: HTMLDialogElement;
beforeEach(() => {
  document.body.innerHTML = "<ul id=list></ul><dialog id=sheet></dialog>";
  list = document.querySelector<HTMLElement>("#list") as HTMLElement;
  sheet = document.querySelector<HTMLDialogElement>("#sheet") as HTMLDialogElement;
  sheet.showModal = () => { sheet.setAttribute("open", ""); };
  sheet.close = () => { sheet.removeAttribute("open"); sheet.dispatchEvent(new Event("close")); };
  vi.stubGlobal("fetch", vi.fn(async (url: string) => ({ ok: true, arrayBuffer: async () => nodeBuffer(new Uint8Array(readFileSync(join("public", String(url))))) })));
});
afterEach(() => { vi.unstubAllGlobals(); });

/** Repair reports in the inline panel under the card. No sheet is involved. */
const panelButtons = (label: string): HTMLButtonElement[] => [...list.querySelectorAll(".apps-install-panel button")].filter((node) => node.textContent === label) as HTMLButtonElement[];
const line = (): string => list.querySelector(".apps-install-panel .apps-install-line")?.textContent ?? "";

function ports(options: { fail?: RepairError; hold?: boolean } = {}): { ports: RepairPorts; puts: string[]; sessions: number; disposed: number; sheetOpenAtSignIn: boolean[]; release: () => void } {
  let release: () => void = () => undefined;
  const state = { puts: [] as string[], sessions: 0, disposed: 0, sheetOpenAtSignIn: [] as boolean[], release: () => release(), ports: undefined as unknown as RepairPorts };
  state.ports = {
    async openSession(_manifest, hooks): Promise<RepairSession> {
      state.sessions += 1;
      state.sheetOpenAtSignIn.push(sheet.hasAttribute("open"));
      if (options.fail !== undefined) throw options.fail;
      hooks.approval(true);
      if (options.hold === true) await new Promise<void>((resolve) => { release = resolve; });
      hooks.approval(false);
      return { put: async (key) => { state.puts.push(key); }, list: async () => [], del: async () => undefined, dispose: () => { state.disposed += 1; } };
    },
  };
  return state;
}

describe("repair from the inline panel", () => {
  it("opens an inline panel that says what it replaces and what it leaves alone, and writes nothing until Repair", () => {
    const node = ports();
    const mounted = mountApps(list, sheet, catalog.apps, { repairPorts: () => node.ports });
    expect(mounted.openRepair(HEALTH)).toBe(true);
    expect(sheet.hasAttribute("open")).toBe(false);
    const text = list.querySelector(".apps-install-panel")?.textContent ?? "";
    expect(text).toContain("Replaces the app's code files with the pinned version");
    expect(text).toContain("Your data is untouched");
    expect(panelButtons("Repair")).toHaveLength(1);
    expect(node.sessions).toBe(0);
    expect(mounted.openRepair("com.example.nothing")).toBe(false);
  });

  it("Repair signs in with the sheet closed, reports inline, then offers Open (a link to the runner)", async () => {
    const node = ports();
    const mounted = mountApps(list, sheet, catalog.apps, { repairPorts: () => node.ports });
    mounted.openRepair(HEALTH);
    panelButtons("Repair")[0]!.click();
    await vi.waitFor(() => expect(line()).toMatch(/^Repaired\./));
    expect(node.sessions).toBe(1);
    expect(node.sheetOpenAtSignIn).toEqual([false]);
    expect(node.puts.length).toBeGreaterThan(3);
    expect(node.puts.every((key) => key.startsWith(`${HEALTH}/app/`))).toBe(true);
    expect(line()).toContain("Your data was not touched.");
    expect(list.querySelector(`.apps-install-panel a[href='/apps/run#${HEALTH}']`)?.textContent).toBe(`Open ${entry.name}`);
    panelButtons("Done")[0]!.click();
    expect(list.querySelector(".apps-install-panel")).toBeNull();
  });

  it("Cancel while the OpenKey window is open stops the repair: nothing is written and the late session is closed", async () => {
    const node = ports({ hold: true });
    const mounted = mountApps(list, sheet, catalog.apps, { repairPorts: () => node.ports });
    mounted.openRepair(HEALTH);
    panelButtons("Repair")[0]!.click();
    await vi.waitFor(() => expect(node.sessions).toBe(1));
    expect(panelButtons("Cancel")).toHaveLength(1);
    panelButtons("Cancel")[0]!.click();
    expect(line()).toMatch(/^Repair cancelled\./);
    node.release(); // the person approves in the window anyway
    await vi.waitFor(() => expect(node.disposed).toBe(1));
    expect(node.puts).toEqual([]);
    expect(line()).toMatch(/^Repair cancelled\./);
  });

  it("a cancelled approval is a plain message with Try again, and nothing was written", async () => {
    const node = ports({ fail: new RepairError("cancelled") });
    const mounted = mountApps(list, sheet, catalog.apps, { repairPorts: () => node.ports });
    mounted.openRepair(HEALTH);
    panelButtons("Repair")[0]!.click();
    await vi.waitFor(() => expect(line()).toBe("Sign-in cancelled. Nothing was changed."));
    expect(list.querySelector(".apps-install-panel [role=alert]")).not.toBeNull();
    expect(panelButtons("Try again")).toHaveLength(1);
    expect(node.puts).toEqual([]);
  });

  it("a disabled app shows its reason with Dismiss only: there is no Repair action", () => {
    const off = { ...entry, disabled: true as const, disabledReason: "Paused." };
    const mounted = mountApps(list, sheet, [off], { repairPorts: () => ports().ports });
    expect(mounted.openRepair(HEALTH)).toBe(true);
    expect(panelButtons("Repair")).toHaveLength(0);
    expect(panelButtons("Dismiss")).toHaveLength(1);
    expect(list.querySelector(".apps-install-panel")?.textContent).toContain("Paused.");
  });
});
