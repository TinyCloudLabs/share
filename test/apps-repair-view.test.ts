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

const buttons = (label: string): HTMLButtonElement[] => [...sheet.querySelectorAll("button")].filter((node) => node.textContent === label);
const line = (): string => sheet.querySelector(".apps-install-line")?.textContent ?? "";

function ports(options: { fail?: RepairError } = {}): { ports: RepairPorts; puts: string[]; sessions: number } {
  const state = { puts: [] as string[], sessions: 0, ports: undefined as unknown as RepairPorts };
  state.ports = {
    async openSession(_manifest, hooks): Promise<RepairSession> {
      state.sessions += 1;
      if (options.fail !== undefined) throw options.fail;
      hooks.approval(true); hooks.approval(false);
      return { put: async (key) => { state.puts.push(key); }, list: async () => [], del: async () => undefined, dispose: () => undefined };
    },
  };
  return state;
}

describe("the repair sheet (the install sheet in repair mode)", () => {
  it("says what it replaces and what it leaves alone, and writes nothing until Continue", () => {
    const node = ports();
    const mounted = mountApps(list, sheet, catalog.apps, { repairPorts: () => node.ports });
    expect(mounted.openRepair(HEALTH)).toBe(true);
    expect(sheet.hasAttribute("open")).toBe(true);
    const text = sheet.textContent ?? "";
    expect(text).toContain(`Repair ${entry.name}`);
    expect(text).toContain("Replaces the app's code files with the pinned version");
    expect(text).toContain("Your data is untouched");
    expect(text).toContain(`${HEALTH}/app/`);
    expect(buttons("Continue")).toHaveLength(1);
    expect(node.sessions).toBe(0);
    expect(mounted.openRepair("com.example.nothing")).toBe(false);
  });

  it("Continue repairs with one sign-in, then offers Open (a link to the runner)", async () => {
    const node = ports();
    const mounted = mountApps(list, sheet, catalog.apps, { repairPorts: () => node.ports });
    mounted.openRepair(HEALTH);
    buttons("Continue")[0]!.click();
    buttons("Continue")[0]?.click();
    await vi.waitFor(() => expect(line()).toMatch(/^Repaired\./));
    expect(node.sessions).toBe(1);
    expect(node.puts.length).toBeGreaterThan(3);
    expect(node.puts.every((key) => key.startsWith(`${HEALTH}/app/`))).toBe(true);
    expect(line()).toContain("Your data was not touched.");
    expect(sheet.querySelector(`a[href='/apps/run#${HEALTH}']`)?.textContent).toBe(`Open ${entry.name}`);
  });

  it("a cancelled approval is a plain message with Try again, and nothing was written", async () => {
    const node = ports({ fail: new RepairError("cancelled") });
    const mounted = mountApps(list, sheet, catalog.apps, { repairPorts: () => node.ports });
    mounted.openRepair(HEALTH);
    buttons("Continue")[0]!.click();
    await vi.waitFor(() => expect(line()).toBe("Sign-in cancelled. Nothing was changed."));
    expect(sheet.querySelector(".apps-install-status [role=alert]")).not.toBeNull();
    expect(buttons("Try again")).toHaveLength(1);
    expect(node.puts).toEqual([]);
  });

  it("a disabled app cannot be repaired: Continue is off", () => {
    const off = { ...entry, disabled: true as const, disabledReason: "Paused." };
    const mounted = mountApps(list, sheet, [off], { repairPorts: () => ports().ports });
    mounted.openRepair(HEALTH);
    expect(buttons("Continue")[0]?.disabled).toBe(true);
    expect(sheet.textContent).toContain("Paused.");
  });
});
