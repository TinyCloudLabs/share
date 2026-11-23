import { createHash } from "node:crypto";
import * as sdk from "@tinycloud/sdk-core";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

import type { CatalogEntry } from "../src/apps/catalog.ts";
import { applyAppsHash } from "../src/apps/hash-route.ts";
import { runnerHref } from "../src/apps/install-plan.ts";
import { mountRunner } from "../src/apps/run-view.ts";
import type { RunPorts, RunSession } from "../src/apps/run.ts";
import type { UninstallSession } from "../src/apps/uninstall.ts";
import { mountApps } from "../src/apps/view.ts";

const appId = "test.unlisted";
const path = "apps/xyz.tinycloud.share/" + appId + "/seal-v1";
const keys = [{ path, abilities: ["decrypt", "key.create"] }];
const manifest = {
  manifest_version: 1, app_id: appId, name: "Workshop Notebook",
  description: "Keep workshop notes.", defaults: false, space: "applications",
  keys_app_id: "xyz.tinycloud.share", keys,
  permissions: [{ service: "tinycloud.kv", path: "notes/", actions: ["get", "put"] }],
};
const bytes = new TextEncoder().encode(JSON.stringify(manifest));
const sha256 = createHash("sha256").update(bytes).digest("hex");

function fixture(id: string, name: string, digest: string): CatalogEntry {
  return {
    app_id: id, name, description: manifest.description,
    publisher: { name: "Fixture" },
    source: { repo: "https://example.test/notebook", tag: null, commit: "a".repeat(40) },
    manifest: { path: "manifest.json", sha256 },
    bundle: {
      root: "/apps/b/" + digest + "/", digest,
      files: [
        { path: "manifest.json", sha256, size: bytes.length },
        { path: "app.jsx", sha256: "b".repeat(64), size: 12 },
      ],
    },
    knowledge: null,
  };
}

const current = { ...fixture(appId, manifest.name, "c".repeat(64)), unlisted: true as const };
const previous = fixture(appId, "Earlier Notebook", "d".repeat(64));
const listed = fixture("test.listed", "Public Notebook", "e".repeat(64));

let host: HTMLElement;
let list: HTMLElement;
let sheet: HTMLDialogElement;

beforeEach(() => {
  document.body.innerHTML = '<main tabindex="-1"><ul></ul></main><dialog></dialog>';
  host = document.querySelector("main")!;
  list = host.querySelector("ul")!;
  sheet = document.querySelector("dialog")!;
  sheet.showModal = () => { sheet.open = true; };
  sheet.close = () => { sheet.open = false; sheet.dispatchEvent(new Event("close")); };
  vi.stubGlobal("fetch", vi.fn(async () => ({
    ok: true,
    arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  })));
});
afterEach(() => vi.unstubAllGlobals());

function button(scope: ParentNode, label: string): HTMLButtonElement {
  const match = [...scope.querySelectorAll("button")].find((node) => node.textContent === label);
  if (!match) throw new Error("Expected a button labelled " + label);
  return match;
}

it("omits an unlisted current version and does not fall back to its earlier card", () => {
  mountApps(list, sheet, [current, previous, listed]);
  expect([...list.querySelectorAll(".apps-card__name")].map((node) => node.textContent)).toEqual([listed.name]);
  expect(list.querySelector("a")?.getAttribute("href")).toBe(runnerHref(listed.app_id));
});

it("keeps linked Repair and Uninstall panels visible when all cards are unlisted", async () => {
  const repair = vi.fn(() => { throw new Error("Opening a hash must not start repair"); });
  let resolveSession!: (session: UninstallSession) => void;
  const pending = new Promise<UninstallSession>((resolve) => { resolveSession = resolve; });
  const openSession = vi.fn(() => pending);
  const mounted = mountApps(list, sheet, [current], {
    repairPorts: repair,
    uninstallPorts: () => ({ openSession }),
  });

  expect(host.querySelector(".apps-card")).toBeNull();
  expect(host.querySelector(".apps-empty")?.textContent).toBe("No apps are listed yet.");
  expect(applyAppsHash(mounted, "#repair=" + appId)).toBe(true);
  const repairPanel = host.querySelector(".apps-install-panel")!;
  expect(button(repairPanel, "Repair").disabled).toBe(false);
  expect(repair).not.toHaveBeenCalled();
  button(repairPanel, "Dismiss").click();
  expect(document.activeElement).toBe(host);

  expect(applyAppsHash(mounted, "#uninstall=" + appId)).toBe(true);
  expect(sheet.open).toBe(true);
  expect(openSession).not.toHaveBeenCalled();
  button(sheet, "Uninstall").click();
  expect(sheet.open).toBe(false);
  expect(openSession).toHaveBeenCalledOnce();
  const uninstallPanel = host.querySelector(".apps-install-panel")!;
  expect(uninstallPanel.textContent).toContain("Uninstalling " + manifest.name);
  button(uninstallPanel, "Cancel").click();
  const listFiles = vi.fn();
  const del = vi.fn();
  const removeRegistry = vi.fn();
  const dispose = vi.fn(async () => {});
  resolveSession({ list: listFiles, del, removeRegistry, dispose });
  await vi.waitFor(() => expect(dispose).toHaveBeenCalledOnce());
  expect(listFiles).not.toHaveBeenCalled();
  expect(del).not.toHaveBeenCalled();
  expect(removeRegistry).not.toHaveBeenCalled();
  expect(host.querySelector(".apps-card")).toBeNull();
});

function runnerPorts(entry: CatalogEntry) {
  const prepare = vi.fn<RunPorts["prepare"]>(async () => ({
    bundle: { files: [], manifest },
    manifest: { ok: true, manifest },
  }));
  const signIn = vi.fn<RunPorts["signIn"]>(() => new Promise<RunSession>(() => {}));
  const ports: RunPorts = {
    catalog: [entry],
    prepare,
    signIn,
    loadCatalogManifest: async () => ({ ok: true, manifest }),
    sdk: async () => sdk,
  };
  return { ports, prepare, signIn };
}

it("opens the direct link with the same disclosure and one exact key before owner approval", async () => {
  const idFromLink = new URL(runnerHref(appId), "https://example.test").hash.slice(1);
  const { ports, prepare, signIn } = runnerPorts(current);
  const runner = mountRunner(host, { appId: idFromLink, ports });
  try {
    await vi.waitFor(() => expect(signIn).toHaveBeenCalledOnce());
    expect(prepare).toHaveBeenCalledWith(current);
    expect(signIn.mock.calls[0]?.[1].manifest.keys).toEqual(keys);
    expect(signIn.mock.calls[0]?.[1].scope.allowedRunnerKeyPath).toBe(path);
    expect(host.querySelector(".run-working")?.textContent).toContain(
      "Workshop Notebook can create one encryption key for its own data and use it to encrypt and open that data. The key stays in your TinyCloud if you remove Workshop Notebook.",
    );
  } finally {
    runner.destroy();
  }
});

it("disabling an unlisted entry still blocks direct Open", async () => {
  const { ports, prepare, signIn } = runnerPorts({
    ...current, disabled: true, disabledReason: "Proof paused.",
  });
  const runner = mountRunner(host, { appId, ports });
  try {
    await vi.waitFor(() => expect(host.querySelector(".run-screen__title")?.textContent).toBe(
      "This app is temporarily unavailable",
    ));
    expect(prepare).not.toHaveBeenCalled();
    expect(signIn).not.toHaveBeenCalled();
  } finally {
    runner.destroy();
  }
});
