import { beforeAll, describe, expect, it, vi } from "vitest";

/**
 * The sender app is one shell with a hash router. These tests cover the route
 * table and the entry gate; the two views are covered by their own suites.
 */
let routeFor: (hash: string) => "library" | "composer";

beforeAll(async () => {
  document.body.innerHTML = '<div id="share-app"></div>';
  // No live share session: the entry gate must land on sign-in, and the
  // OpenKey probe must never be reached.
  vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 401 })));
  ({ routeFor } = await import("../src/share/main.js"));
  await new Promise((resolve) => setTimeout(resolve, 0));
});

describe("sender route table", () => {
  it("treats the library as home and #/new as the composer", () => {
    expect(routeFor("#/library")).toBe("library");
    expect(routeFor("#/new")).toBe("composer");
    expect(routeFor("#/new/access")).toBe("composer");
    expect(routeFor("")).toBe("library");
    expect(routeFor("#/anything-else")).toBe("library");
  });
});

describe("sender entry gate", () => {
  it("renders sign-in when no session can be restored, and never fabricates one", () => {
    expect(document.querySelector(".auth-shell")).not.toBeNull();
    expect(document.querySelector(".sender-home")).toBeNull();
    expect(document.querySelector(".auth-copy")?.textContent).toBe("Sign in with Face ID or Touch ID. No password.");
  });

  it("probes for an existing session with a credentialed read, before showing the wall", () => {
    const calls = (globalThis.fetch as unknown as { mock: { calls: readonly (readonly unknown[])[] } }).mock.calls;
    expect(calls.some(([url]) => url === "/api/share/capabilities")).toBe(true);
  });

  it("does not react to hash changes until a session exists", () => {
    window.location.hash = "#/new";
    window.dispatchEvent(new HashChangeEvent("hashchange"));
    expect(document.querySelector(".composer-form")).toBeNull();
    expect(document.querySelector(".auth-shell")).not.toBeNull();
  });
});
