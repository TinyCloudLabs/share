import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { beforeAll, describe, expect, it, vi } from "vitest";

import { securityHeadersForPath, type ShareTrustBundle } from "../src/host/trust-bundle.js";

/**
 * The sender app is one shell with a hash router. These tests cover the route
 * table, the entry gate, and the CSP boundary the boot path has to live inside.
 * Navigation past the wall — browser Back and the dynamic-import render race —
 * is covered by test/sender-navigation.test.ts, which boots with a session.
 */
let routeFor: (hash: string) => "library" | "composer";

/** Vitest runs with the repo root as its root, so shipped files are read from there. */
function repoFile(relative: string): string {
  return readFileSync(resolve(process.cwd(), relative), "utf8");
}

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
    // TC-302: the probe that shipped broken made a SECOND, cross-origin read.
    // Nothing on the boot path may leave this origin.
    expect(calls.filter(([url]) => /^https?:\/\//i.test(String(url)))).toEqual([]);
  });

  it("does not react to hash changes until a session exists", () => {
    window.location.hash = "#/new";
    window.dispatchEvent(new HashChangeEvent("hashchange"));
    expect(document.querySelector(".composer-form")).toBeNull();
    expect(document.querySelector(".auth-shell")).not.toBeNull();
  });
});

/**
 * TC-305 / TC-302. The defect that shipped was not a logic bug the DOM could
 * show: `detectResumableSession` issued a credentialed read of
 * `https://openkey.so/api/auth/session`, which BOTH production content security
 * policies omit from `connect-src`, so in production the probe was blocked and
 * always returned false. A jsdom test cannot enforce a CSP — jsdom has no CSP
 * engine, and the mocked `fetch` in the suite above will happily answer any
 * origin — so no amount of driving the app at this layer reproduces it.
 *
 * What IS checkable here is the invariant the defect violated: every absolute
 * origin the sender's boot path hardcodes must be authorized by both shipped
 * CSP sources. That is a static property of the two policies and the boot
 * modules, and it goes red the moment a cross-origin fetch target is
 * reintroduced. The runtime half — "the boot path made no cross-origin
 * request" — is asserted above and in test/sender-resume.test.ts.
 */
describe("sender boot path stays inside the shipped content security policy (TC-302)", () => {
  /** The modules that run before the sender has pressed anything. */
  const BOOT_MODULES = ["src/share/main.ts", "src/share/capability-list.ts"] as const;

  const PRODUCTION_BUNDLE = {
    public: {
      nodeOrigin: "https://tee.node.tinycloud.xyz",
      credentialsOrigin: "https://witness.credentials.org",
      registryOrigin: "https://registry.tinycloud.xyz",
    },
  } as unknown as ShareTrustBundle;

  function connectSrc(policy: string): string[] {
    const directive = policy.split(";").map((part) => part.trim()).find((part) => part.startsWith("connect-src"));
    expect(directive, `connect-src missing from: ${policy}`).toBeDefined();
    return directive!.split(/\s+/).slice(1);
  }

  function stripComments(source: string): string {
    return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, "$1");
  }

  /** Every absolute http(s) origin a module hardcodes, comments excluded. */
  function hardcodedOrigins(source: string): string[] {
    const found = stripComments(source).match(/https?:\/\/[^\s"'`)]+/g) ?? [];
    return [...new Set(found.map((url) => { try { return new URL(url).origin; } catch { return url; } }))];
  }

  function authorizes(allowed: readonly string[], origin: string): boolean {
    return allowed.includes(origin) || allowed.some((entry) => entry.endsWith(":*") && origin.startsWith(entry.slice(0, -2)));
  }

  const metaPolicy = /content="([^"]*)"/.exec(/<meta http-equiv="Content-Security-Policy"[^>]*>/.exec(repoFile("share.html"))![0])![1]!;
  const headerPolicy = securityHeadersForPath(PRODUCTION_BUNDLE, "/share.html")["Content-Security-Policy"]!;

  it("reads a real connect-src from both shipped policy sources", () => {
    // Guards the two parsers below: a policy that stopped being found would
    // otherwise make every assertion in this block vacuously true.
    expect(connectSrc(metaPolicy)).toContain("'self'");
    expect(connectSrc(headerPolicy)).toContain("'self'");
    expect(connectSrc(metaPolicy).length).toBeGreaterThan(1);
    expect(connectSrc(headerPolicy).length).toBeGreaterThan(1);
  });

  it("detects a cross-origin fetch target when one is present", () => {
    // Proves the scanner is not a no-op. This is the exact line TC-302 removed.
    const reintroduced = `const ok = await fetch("https://openkey.so/api/auth/session", { credentials: "include" });`;
    expect(hardcodedOrigins(reintroduced)).toEqual(["https://openkey.so"]);
    expect(authorizes(connectSrc(metaPolicy), "https://openkey.so")).toBe(false);
    expect(authorizes(connectSrc(headerPolicy), "https://openkey.so")).toBe(false);
    // …and it ignores prose. The comment explaining TC-302 must not trip it.
    expect(hardcodedOrigins(`// see https://openkey.so/api/auth/session for why\nconst x = 1;`)).toEqual([]);
  });

  it("hardcodes no boot-path origin that either policy would block", () => {
    const blocked = BOOT_MODULES.flatMap((module) =>
      hardcodedOrigins(repoFile(module))
        .filter((origin) => !authorizes(connectSrc(metaPolicy), origin) || !authorizes(connectSrc(headerPolicy), origin))
        .map((origin) => `${module} fetches ${origin}, which connect-src does not allow`));
    expect(blocked).toEqual([]);
  });

  it("keeps the meta policy and the served header agreeing on every allowed origin", () => {
    // Two sources of truth for one boundary. TC-302's probe was blocked by
    // BOTH; a fix that widened only one would be a production-only failure.
    for (const origin of connectSrc(headerPolicy).filter((entry) => entry.startsWith("http"))) {
      expect(authorizes(connectSrc(metaPolicy), origin), `${origin} is served but missing from share.html`).toBe(true);
    }
  });
});
