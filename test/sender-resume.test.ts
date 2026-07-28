import { beforeAll, describe, expect, it, vi } from "vitest";

const resumableCopy = "Your sharing session on this device is still active. Continue to pick up where you left off.";

describe("sender resumable-session entry gate", () => {
  let calls: readonly (readonly unknown[])[];

  beforeAll(async () => {
    document.body.innerHTML = '<div id="share-app"></div>';
    const fetch = vi.fn(async (url: string | URL | Request) => {
      if (url === "/api/share/capabilities") return new Response(null, { status: 200 });
      if (/^https?:\/\//.test(String(url))) throw new TypeError("Failed to fetch");
      throw new Error(`Unexpected fetch: ${String(url)}`);
    });
    vi.stubGlobal("fetch", fetch);
    calls = fetch.mock.calls;

    await import("../src/share/main.js");
    await new Promise((resolve) => setTimeout(resolve, 0));
    await new Promise((resolve) => setTimeout(resolve, 0));
  });

  it("uses the server-validated share session without a cross-origin probe", () => {
    expect(document.querySelector("h2")?.textContent).toBe("Welcome back");
    expect(document.querySelector(".auth-copy")?.textContent).toBe(resumableCopy);
    expect(document.querySelector("button[type=submit]")?.textContent).toBe("Continue");
    expect(calls.every(([url]) => !String(url).startsWith("http"))).toBe(true);
  });
});
