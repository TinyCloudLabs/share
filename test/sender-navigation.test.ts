/**
 * TC-305. The sender router had no coverage past the sign-in wall.
 *
 * `test/sender-router.test.ts` exercises `routeFor()` and the unauthenticated
 * entry gate, and deliberately never gets a session — so everything the router
 * exists to do (react to a hash change, survive browser Back, and drop a stale
 * dynamically-imported view) was untested. Those are exactly the two defects
 * the reviewer named: broken browser Back, and the dynamic-import render race.
 *
 * This file boots the REAL `src/share/main.ts` with a session. The only things
 * replaced are the module boundaries the router hands off to: the OpenKey
 * ceremony, the TinyCloud client, the capability read, and the two views —
 * each view mock records that it was mounted and with which route. The router
 * itself, the route table, the hashchange wiring and the render token are the
 * shipped code.
 */
import { beforeAll, describe, expect, it, vi } from "vitest";

const views = vi.hoisted(() => ({
  library: [] as string[],
  composer: [] as string[],
  /** Mount order across both views, so a stale view landing last is visible. */
  order: [] as string[],
}));

vi.mock("../src/share/openkey-session.js", () => ({
  authenticateWithOpenKey: async () => ({ address: "0x1234567890abcdef1234567890abcdef12345678", openkey: {}, auth: {} }),
  createTinyCloudClient: async () => ({ vault: {}, spaceId: "share", did: "did:pkh:eip155:1:0xabc" }),
  createTinyCloudUploader: async () => async () => undefined,
  MAX_SHARE_FILE_BYTES: 100 * 1024 * 1024,
}));

vi.mock("../src/share/capability-list.js", () => ({
  loadAuthenticatedCapabilities: async () => [],
  parseCapabilityList: () => [],
}));

vi.mock("../src/email-share/config.js", async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  loadSharePublicConfig: async () => ({
    version: "tinycloud.share-email-claim/config-v1",
    shareOrigin: "https://share.tinycloud.xyz",
    registryOrigin: "https://registry.tinycloud.xyz",
    nodeOrigin: "https://tee.node.tinycloud.xyz",
    credentialsOrigin: "https://witness.credentials.org",
    nodeAudience: "did:web:tee.node.tinycloud.xyz",
    enforcerDid: "did:web:tee.node.tinycloud.xyz",
    nodeEnabled: true,
  }),
}));

vi.mock("../src/share/sender-history.js", () => ({
  SenderHistoryRepository: class { constructor(_vault: unknown) {} },
  createSenderHistoryRecord: async (record: unknown) => record,
}));

vi.mock("../src/share/sender-home.js", () => ({
  mountSenderHome: (root: HTMLElement) => {
    views.library.push(window.location.hash);
    views.order.push("library");
    root.replaceChildren();
    const marker = document.createElement("div");
    marker.className = "sender-home";
    root.append(marker);
  },
}));

vi.mock("../src/share/composer.js", () => ({
  mountShareComposer: (root: HTMLElement) => {
    views.composer.push(window.location.hash);
    views.order.push("composer");
    root.replaceChildren();
    const marker = document.createElement("form");
    marker.className = "composer-form";
    root.append(marker);
  },
  copySelectedSource: async () => undefined,
  emailDomainOf: (value: string) => value,
}));

/** Let every pending dynamic import and its `.then` chain settle. */
async function settle(): Promise<void> {
  for (let index = 0; index < 12; index += 1) await Promise.resolve();
  await new Promise((resolve) => setTimeout(resolve, 0));
}

function mounted(): "library" | "composer" | "signin" | "none" {
  if (document.querySelector(".composer-form") !== null) return "composer";
  if (document.querySelector(".sender-home") !== null) return "library";
  if (document.querySelector(".auth-shell") !== null) return "signin";
  return "none";
}

/** Navigate and wait for the router to settle on the expected view. */
async function arriveAt(kind: "library" | "composer", hash: string): Promise<void> {
  await vi.waitFor(() => {
    expect(window.location.hash).toBe(hash);
    expect(mounted()).toBe(kind);
  });
}

beforeAll(async () => {
  document.body.innerHTML = '<div id="share-app"></div>';
  window.history.replaceState(null, "", "/share.html");
  // Same-origin reads only; a 401 keeps the resumable probe out of the way so
  // the cold sign-in wall is what we drive.
  vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 401 })));
  await import("../src/share/main.js");
  await settle();
  // Complete the sign-in ceremony through the real wall.
  document.querySelector<HTMLFormElement>("form.auth-form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() => expect(mounted()).toBe("library"));
});

describe("sender app — the router past the sign-in wall", () => {
  it("lands on the library and normalizes the address to the library route", () => {
    expect(mounted()).toBe("library");
    expect(window.location.hash).toBe("#/library");
  });

  it("mounts the composer when the sender navigates to #/new", async () => {
    window.location.hash = "#/new";
    await arriveAt("composer", "#/new");
  });

  /**
   * The defect the router exists to prevent, and the one a `routeFor()` unit
   * test cannot see: pressing browser Back from the composer must return to the
   * library instead of leaving the sender stranded or dropping them back at the
   * sign-in wall. jsdom implements a real session history, so this is the
   * actual Back button, not a synthesized event.
   */
  it("returns to the library on browser Back, and forward again", async () => {
    window.location.hash = "#/library";
    await arriveAt("library", "#/library");
    window.location.hash = "#/new";
    await arriveAt("composer", "#/new");

    window.history.back();
    await arriveAt("library", "#/library");
    // Never falls back through to the entry gate.
    expect(document.querySelector(".auth-shell")).toBeNull();

    window.history.forward();
    await arriveAt("composer", "#/new");

    window.history.back();
    await arriveAt("library", "#/library");
  });

  it("treats an unknown route as the library without leaving the shell", async () => {
    window.location.hash = "#/anything-else";
    await arriveAt("library", "#/anything-else");
    window.location.hash = "#/library";
    await arriveAt("library", "#/library");
  });
});

describe("sender app — the dynamic-import render race", () => {
  /**
   * Both views are dynamic imports, and the composer awaits THREE of them while
   * the library awaits one — so a fast Back/Forward reliably lets the composer's
   * import chain resolve after the library has already mounted. Without the
   * render token, that stale mount lands last and the sender ends up looking at
   * the composer they just navigated away from.
   *
   * This drives the two route changes back to back with no await between them,
   * which is what a fast Back does, and asserts on mount ORDER — the stale view
   * must never be the last thing mounted, and here must never mount at all.
   */
  it("drops the losing view when a newer route is entered before its import resolves", async () => {
    window.location.hash = "#/library";
    await settle();
    views.library.length = 0;
    views.composer.length = 0;
    views.order.length = 0;

    window.location.hash = "#/new";
    window.dispatchEvent(new HashChangeEvent("hashchange"));
    window.location.hash = "#/library";
    window.dispatchEvent(new HashChangeEvent("hashchange"));
    await settle();

    expect(views.composer).toEqual([]);
    expect(views.order.at(-1)).toBe("library");
    expect(mounted()).toBe("library");
    expect(window.location.hash).toBe("#/library");
  });

  it("keeps the newest route when the sender lands on the composer last", async () => {
    window.location.hash = "#/library";
    await settle();
    views.order.length = 0;

    window.dispatchEvent(new HashChangeEvent("hashchange"));
    window.location.hash = "#/new";
    window.dispatchEvent(new HashChangeEvent("hashchange"));
    await settle();

    expect(views.order.at(-1)).toBe("composer");
    expect(mounted()).toBe("composer");
  });
});
