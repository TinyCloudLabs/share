import { describe, expect, it } from "vitest";

import {
  COURIER_APP_ID,
  REGRANT_LEAD_MS,
  createNonce,
  isEmbeddedMode,
  parentOriginFromReferrer,
  parseParentMessage,
  startEmbedController,
  type EmbedHandlers,
  type EmbedWindow,
  type GrantMessage,
} from "../src/courier/one-embed.js";

const ONE = "https://tinycloud.one";
const ORIGINS = [ONE];
const NOW = 1_800_000_000_000;

interface Posted { message: Record<string, unknown>; targetOrigin: string }

function setup(options: { referrer?: string; search?: string; origins?: readonly string[]; embedded?: boolean } = {}) {
  const posted: Posted[] = [];
  const parent = { postMessage: (message: Record<string, unknown>, targetOrigin: string) => { posted.push({ message, targetOrigin }); } };
  let listener: ((event: MessageEvent) => void) | undefined;
  const win = {
    parent: options.embedded === false ? undefined : parent,
    location: { search: options.search ?? "?embed=one" },
    document: { referrer: options.referrer ?? `${ONE}/` },
    addEventListener: (_type: "message", fn: (event: MessageEvent) => void) => { listener = fn; },
    removeEventListener: () => { listener = undefined; },
  };
  if (options.embedded === false) win.parent = win as never;
  const calls: string[] = [];
  const grants: GrantMessage[] = [];
  const handlers: EmbedHandlers = {
    onGrant: (grant) => { calls.push("grant"); grants.push(grant); },
    onDenied: () => { calls.push("denied"); },
    onRevoke: () => { calls.push("revoke"); },
    onTheme: (theme) => { calls.push(`theme:${theme}`); },
  };
  let clock = NOW;
  const timers: { fn: () => void; ms: number; live: boolean }[] = [];
  let counter = 0;
  const controller = startEmbedController({
    win: win as unknown as EmbedWindow,
    handlers,
    origins: options.origins ?? ORIGINS,
    now: () => clock,
    nonce: () => `nonce-${++counter}`,
    setTimer: (fn, ms) => { const entry = { fn, ms, live: true }; timers.push(entry); return entry; },
    clearTimer: (timer) => { const entry = timers.find((candidate) => candidate === timer); if (entry !== undefined) entry.live = false; },
  });
  const deliver = (data: unknown, from: { origin?: string; source?: unknown } = {}): void => {
    listener?.({ data, origin: from.origin ?? ONE, source: "source" in from ? from.source : parent } as unknown as MessageEvent);
  };
  const grantMessage = (nonce: string, expiresAt = NOW + 3_600_000) => ({
    v: 1, type: "tc-embed/grant", nonce, expiresAt, theme: "dark",
    grants: [{ spaceId: "tinycloud:pkh:eip155:1:0xabc:agents", delegation: { cid: "x" }, cid: "bafy" }],
  });
  return { controller, posted, deliver, calls, grants, grantMessage, parent, timers, advance: (ms: number) => { clock += ms; }, listening: () => listener !== undefined };
}

describe("embedded mode and the parent origin", () => {
  it("needs a parent window AND embed=one", () => {
    const self = { location: { search: "?embed=one" } } as { parent: unknown; location: { search: string } };
    self.parent = self;
    expect(isEmbeddedMode(self)).toBe(false);
    expect(isEmbeddedMode({ parent: {}, location: { search: "" } })).toBe(false);
    expect(isEmbeddedMode({ parent: {}, location: { search: "?embed=other" } })).toBe(false);
    expect(isEmbeddedMode({ parent: {}, location: { search: "?embed=one" } })).toBe(true);
  });

  it("takes the parent from the referrer and only when it is an exact One origin", () => {
    expect(parentOriginFromReferrer(`${ONE}/apps/courier?x=1`, ORIGINS)).toBe(ONE);
    for (const referrer of ["", "not a url", "https://tinycloud.one.evil.example/", "http://tinycloud.one/", "https://evil.example/https://tinycloud.one/", "https://feat-one-apps.tinychat.pages.dev/", "https://localhost:5190/", "https://sub.tinycloud.one/"]) {
      expect(parentOriginFromReferrer(referrer, ORIGINS), referrer).toBeNull();
    }
  });

  it("starts nothing, and posts nothing, outside embedded mode or under a foreign parent", () => {
    for (const options of [{ embedded: false }, { search: "" }, { referrer: "https://evil.example/" }, { referrer: "" }]) {
      const run = setup(options);
      expect(run.controller, JSON.stringify(options)).toBeNull();
      expect(run.listening()).toBe(false);
      expect(run.posted).toEqual([]);
    }
  });

  it("makes 16 random bytes into a base64url nonce", () => {
    const nonce = createNonce();
    expect(nonce).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(createNonce()).not.toBe(nonce);
  });
});

describe("the controller", () => {
  it("posts hello to the exact One origin, never '*', carrying only the contract's fields", () => {
    const run = setup();
    run.controller?.hello("did:key:z6Mkabc#z6Mkabc");
    run.controller?.request([{ service: "tinycloud.kv", space: "agents", path: "xyz.tinycloud.courier/", actions: ["tinycloud.kv/get"] }]);
    expect(run.posted).toHaveLength(2);
    for (const entry of run.posted) {
      expect(entry.targetOrigin).toBe(ONE);
      expect(entry.targetOrigin).not.toBe("*");
    }
    expect(run.posted[0]?.message).toEqual({ v: 1, type: "tc-embed/hello", appId: COURIER_APP_ID, sessionDid: "did:key:z6Mkabc#z6Mkabc", nonce: "nonce-1" });
    expect(Object.keys(run.posted[1]?.message ?? {}).sort()).toEqual(["nonce", "permissions", "type", "v"]);
  });

  it("accepts a grant that echoes the latest nonce, from window.parent at the exact origin", () => {
    const run = setup();
    run.controller?.hello("did:key:z6Mkabc");
    run.deliver(run.grantMessage("nonce-1"));
    expect(run.calls).toEqual(["grant", "theme:dark"]);
    expect(run.grants[0]?.grants[0]?.spaceId).toBe("tinycloud:pkh:eip155:1:0xabc:agents");
    expect(run.controller?.grant()?.nonce).toBe("nonce-1");
  });

  it("ignores a grant from a foreign origin, a foreign window or a stale nonce", () => {
    const run = setup();
    run.controller?.hello("did:key:z6Mkabc");
    run.controller?.hello("did:key:z6Mkabc"); // nonce-2 is now the latest
    run.deliver(run.grantMessage("nonce-2"), { origin: "https://evil.example" });
    run.deliver(run.grantMessage("nonce-2"), { origin: "https://tinycloud.one.evil.example" });
    run.deliver(run.grantMessage("nonce-2"), { source: { postMessage: () => undefined } });
    run.deliver(run.grantMessage("nonce-2"), { source: null });
    run.deliver(run.grantMessage("nonce-1"));
    run.deliver(run.grantMessage("never-sent"));
    expect(run.calls).toEqual([]);
    expect(run.controller?.grant()).toBeNull();
  });

  it("ignores a grant before any hello, an expired grant and a malformed one", () => {
    const run = setup();
    run.deliver(run.grantMessage("nonce-1"));
    run.controller?.hello("did:key:z6Mkabc");
    run.deliver(run.grantMessage("nonce-1", NOW));
    run.deliver({ ...run.grantMessage("nonce-1"), expiresAt: "soon" });
    run.deliver({ ...run.grantMessage("nonce-1"), grants: [] });
    run.deliver({ ...run.grantMessage("nonce-1"), grants: [{ spaceId: "s", cid: "c" }] });
    run.deliver({ ...run.grantMessage("nonce-1"), v: 2 });
    expect(run.calls).toEqual([]);
  });

  it("ignores denied and theme messages from a foreign origin or window; denied needs the latest nonce", () => {
    const run = setup();
    run.controller?.request([]);
    run.deliver({ v: 1, type: "tc-embed/denied", nonce: "nonce-1" }, { origin: "https://evil.example" });
    run.deliver({ v: 1, type: "tc-embed/denied", nonce: "nonce-1" }, { source: {} });
    run.deliver({ v: 1, type: "tc-embed/denied", nonce: "stale" });
    run.deliver({ v: 1, type: "tc-embed/theme", theme: "light" }, { origin: "https://evil.example" });
    run.deliver({ v: 1, type: "tc-embed/theme", theme: "light" }, { source: {} });
    expect(run.calls).toEqual([]);
    run.deliver({ v: 1, type: "tc-embed/denied", nonce: "nonce-1" });
    run.deliver({ v: 1, type: "tc-embed/theme", theme: "light" });
    expect(run.calls).toEqual(["denied", "theme:light"]);
  });

  it("ignores a revoke from a foreign origin or window", () => {
    const run = setup();
    run.controller?.hello("did:key:z6Mkabc");
    run.deliver(run.grantMessage("nonce-1"));
    run.deliver({ v: 1, type: "tc-embed/revoke" }, { origin: "https://evil.example" });
    run.deliver({ v: 1, type: "tc-embed/revoke" }, { source: {} });
    expect(run.controller?.grant()).not.toBeNull();
    expect(run.calls.filter((call) => call === "revoke")).toEqual([]);
  });

  it("clears the grant on revoke, and a later grant is dropped until hello is sent again", () => {
    const run = setup();
    run.controller?.hello("did:key:z6Mkabc");
    run.deliver(run.grantMessage("nonce-1"));
    run.deliver({ v: 1, type: "tc-embed/revoke" });
    expect(run.calls).toEqual(["grant", "theme:dark", "revoke"]);
    expect(run.controller?.grant()).toBeNull();
    run.deliver(run.grantMessage("nonce-1"));
    expect(run.calls).toEqual(["grant", "theme:dark", "revoke"]);
    run.controller?.hello("did:key:z6Mkabc");
    run.deliver(run.grantMessage("nonce-2"));
    expect(run.controller?.grant()?.nonce).toBe("nonce-2");
  });

  it("reports no grant once it has expired", () => {
    const run = setup();
    run.controller?.hello("did:key:z6Mkabc");
    run.deliver(run.grantMessage("nonce-1", NOW + 1000));
    expect(run.controller?.grant()).not.toBeNull();
    run.advance(1000);
    expect(run.controller?.grant()).toBeNull();
  });

  it("repeats hello with the same sessionDid and a fresh nonce about 5.5 minutes before expiry, and not after revoke", () => {
    const run = setup();
    run.controller?.hello("did:key:z6Mkabc");
    run.deliver(run.grantMessage("nonce-1"));
    const timer = run.timers.at(-1);
    expect(timer?.ms).toBe(3_600_000 - REGRANT_LEAD_MS);
    timer?.fn();
    expect(run.posted).toHaveLength(2);
    expect(run.posted[1]?.message).toMatchObject({ type: "tc-embed/hello", sessionDid: "did:key:z6Mkabc", nonce: "nonce-2" });
    expect(run.posted[1]?.targetOrigin).toBe(ONE);
    // The new grant answers the repeat hello; the old nonce no longer does.
    run.deliver(run.grantMessage("nonce-1"));
    expect(run.calls.filter((call) => call === "grant")).toHaveLength(1);
    run.deliver(run.grantMessage("nonce-2"));
    expect(run.calls.filter((call) => call === "grant")).toHaveLength(2);
    // Revoke cancels the pending repeat.
    const pending = run.timers.at(-1);
    run.deliver({ v: 1, type: "tc-embed/revoke" });
    expect(pending?.live).toBe(false);
  });

  it("stop() removes the listener and the timer", () => {
    const run = setup();
    run.controller?.hello("did:key:z6Mkabc");
    run.deliver(run.grantMessage("nonce-1"));
    const pending = run.timers.at(-1);
    run.controller?.stop();
    expect(run.listening()).toBe(false);
    expect(pending?.live).toBe(false);
    expect(run.controller?.grant()).toBeNull();
  });
});

describe("parseParentMessage", () => {
  it("rejects wrong versions, unknown types and non-objects", () => {
    for (const data of [null, "x", 1, [], {}, { v: 2, type: "tc-embed/revoke" }, { v: 1, type: "tc-embed/other" }, { v: 1, type: "tc-embed/theme", theme: "blue" }]) {
      expect(parseParentMessage(data)).toBeNull();
    }
  });
});
