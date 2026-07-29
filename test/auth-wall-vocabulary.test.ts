import { beforeEach, describe, expect, it, vi } from "vitest";
import { fail, SENDER_FAILURE } from "../src/share/sender-failure.js";

/**
 * TC-335. The sign-in wall used to render `error.message` straight into
 * `.auth-status`. Everything that can reject there — `openkey-session.ts`'s own
 * throws, the OpenKey SDK, and the whole Web SDK bootstrap — speaks protocol
 * vocabulary. This suite pins the wall to human copy.
 */

const state = vi.hoisted(() => ({ error: undefined as unknown }));

vi.mock("../src/share/openkey-session.js", () => ({
  authenticateWithOpenKey: async () => { throw state.error; },
  createTinyCloudClient: async () => { throw state.error; },
  createTinyCloudUploader: async () => { throw state.error; },
  MAX_SHARE_FILE_BYTES: 100 * 1024 * 1024,
}));

/**
 * The banned list from the UX critique §5. `DID`, `CID` and `KV` are matched
 * case-sensitively on purpose: a case-insensitive `\bdid\b` also matches the
 * ordinary English "didn't", and `\bcid\b` matches "lucid".
 */
const BANNED: ReadonlyArray<readonly [string, RegExp]> = [
  ["capability", /capabilit/i],
  ["delegation", /delegat/i],
  ["DID", /\bDID\b/],
  ["space", /\bspaces?\b/i],
  ["bearer", /\bbearer\b/i],
  ["policy", /\bpolic(?:y|ies)\b/i],
  ["envelope", /\benvelopes?\b/i],
  ["CID", /\bCID\b/],
  ["KV", /\bKV\b/],
  ["registry", /\bregistr(?:y|ies)\b/i],
  ["matcher", /\bmatchers?\b/i],
  ["attenuation", /attenuat/i],
  ["nonce", /\bnonces?\b/i],
  ["claim", /\bclaims?\b/i],
  ["credential", /\bcredentials?\b/i],
  ["epoch", /\bepochs?\b/i],
  ["invocation", /\binvocations?\b/i],
  ["Node", /\bnode\b/i],
];

function bannedWordsIn(value: string): readonly string[] {
  return BANNED.filter(([, pattern]) => pattern.test(value)).map(([word]) => word);
}

async function signInFailingWith(error: unknown): Promise<HTMLElement> {
  state.error = error;
  vi.resetModules();
  document.body.innerHTML = '<div id="share-app"></div>';
  await import("../src/share/main.js");
  await new Promise((resolve) => setTimeout(resolve, 0));
  const root = document.getElementById("share-app")!;
  root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  for (let tick = 0; tick < 4; tick += 1) await new Promise((resolve) => setTimeout(resolve, 0));
  return root;
}

describe("sign-in wall failure copy (TC-335)", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 401 })));
    vi.spyOn(console, "debug").mockImplementation(() => undefined);
  });

  it("maps the tagged unauthorized-account rejection to human copy instead of printing its detail", async () => {
    // The detail openkey-session.ts carries for the log; the wall must not show it.
    const raw = "OpenKey account does not control an authorized sharing space";
    const root = await signInFailingWith(fail("account", raw));
    const status = root.querySelector(".auth-status")!;

    expect(status.textContent).toBe("Your account isn't set up for sharing yet. Contact support.");
    expect(status.textContent).not.toContain(raw);
    expect(bannedWordsIn(root.textContent ?? "")).toEqual([]);
  });

  it("does not print untagged SDK failures that reach the wall through bootstrap", async () => {
    const raw = "delegation capability for space did:key:z6Mk rejected by the Node: policy envelope CID mismatch in the KV registry";
    const root = await signInFailingWith(new Error(raw));
    const status = root.querySelector(".auth-status")!;

    expect(status.textContent).toBe("Sign-in could not be completed. Try again.");
    expect(bannedWordsIn(root.textContent ?? "")).toEqual([]);
  });

  it("re-enables the sign-in button so the wall stays usable after a failure", async () => {
    const root = await signInFailingWith(new Error("boom"));
    expect(root.querySelector<HTMLButtonElement>("button[type=submit]")!.disabled).toBe(false);
  });

  it("keeps the raw error for the hermetic harness and console only", async () => {
    const raw = "policy envelope CID mismatch";
    const error = new Error(raw);
    await signInFailingWith(error);
    expect(console.debug).toHaveBeenCalledWith("tinycloud share: sign-in failed", error);
  });

  it("keeps the sign-in progress messages rendered into the wall free of protocol vocabulary", async () => {
    // These strings reach the same `.auth-status` node through `onStatus`, but
    // only during a real OpenKey ceremony, so they are pinned at the source.
    const { readFile } = await import("node:fs/promises");
    const { resolve } = await import("node:path");
    const source = await readFile(resolve(process.cwd(), "src/share/openkey-session.ts"), "utf8");
    const messages = [...source.matchAll(/onStatus\("([^"]*)"\)/g)].map((match) => match[1]!);
    expect(messages.length).toBeGreaterThan(0);
    for (const message of messages) expect(bannedWordsIn(message), message).toEqual([]);
  });

  it("holds every sender failure string free of protocol vocabulary", () => {
    for (const [kind, message] of Object.entries(SENDER_FAILURE)) {
      expect(bannedWordsIn(message), `${kind}: ${message}`).toEqual([]);
    }
  });
});
