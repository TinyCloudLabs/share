// @vitest-environment jsdom
/**
 * TC-1610. The node answers 401 to a KV key with a space or a non-ASCII
 * character, so the composer stores a file under a URI-safe name (the same rule
 * as `tc share publish`) and keeps the name the sender chose for display.
 * The composer runs for real; only the SDK publish call, the public config and
 * the owner's TinyCloud are replaced.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import type { OpenKeyShareSession, ShareTinyCloud } from "../src/share/openkey-session.js";
import { safeStorageFilename, storageFilenameFor, uniqueStoragePaths } from "../src/share/composer-storage-name.js";
import { SENDER_FAILURE } from "../src/share/sender-failure.js";
import { ISSUER_DID, mockLinks, signWithIssuer } from "./fixtures/link-material.js";

const state = vi.hoisted(() => ({ published: [] as Array<Record<string, unknown>> }));
vi.mock("@tinycloud/share-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@tinycloud/share-sdk")>()),
  publishAddressedShare: vi.fn(async (options: Record<string, unknown> & { readonly contentSource: unknown; readonly onDeliveryMaterial: (material: unknown) => void }) => {
    // The size check runs the builder first, with the longest stand-in key version; only the real publish is recorded.
    if ((options.contentSource as { keyVersion?: number }).keyVersion !== 4_294_967_295) state.published.push(options);
    const { sealedEnvelope, envelopeKey, shareCid } = await (await import("./fixtures/link-material.js")).sealedMaterial();
    options.onDeliveryMaterial({ envelope: { version: 3 }, sealedEnvelope, envelopeKey, shareCid });
    return { url: "unused", link: { cid: shareCid }, metadata: { expiresAt: new Date(Date.now() + 7 * 86_400_000).toISOString() } };
  }),
  historyRecordForPublishedShare: vi.fn(() => ({ id: "record" })),
}));
vi.mock("../src/email-share/config.js", () => ({
  loadSharePublicConfig: async () => ({ shareOrigin: "https://share.tinycloud.xyz", registryOrigin: "https://registry.example", credentialsOrigin: "https://witness.example" }),
}));

const { mountShareComposer, uploadSelectedFiles } = await import("../src/share/composer.js");

afterEach(() => { document.body.replaceChildren(); state.published.length = 0; vi.clearAllMocks(); });

const SPACE_ID = "tinycloud:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678:applications";
const flush = (): Promise<void> => new Promise((resolve) => setTimeout(resolve, 0));

function owner() {
  const put = vi.fn(async (_path: string, _bytes: Uint8Array) => ({ ok: true }));
  const generate = vi.fn(async () => ({ ok: true as const, data: { token: "tc1:bearer", delegation: { cid: "bafy-delegation" }, expiresAt: new Date("2030-01-01T00:00:00.000Z") } }));
  const tinycloud = {
    spaceId: SPACE_ID,
    credentialHolderDid: ISSUER_DID,
    activeNodeIdentity: async () => ({ origin: "https://node.example", nodeDid: "did:key:z6MkOwnerNode" }),
    publishActiveNodeLocation: async () => undefined,
    encryption: { encryptToNetwork: async () => ({ ok: true, data: { v: 1, networkId: "urn:tinycloud:encryption:owner:default", alg: "x25519-aes256gcm/v1", keyVersion: 1, encryptedSymmetricKey: "wrapped", encryptedSymmetricKeyHash: "a".repeat(64), ciphertext: "AA" } }) },
    kvForSpace: () => ({ put }),
    sharing: { generate, decodeLink: () => ({ path: "p", spaceId: SPACE_ID }), receive: async () => ({ ok: false as const, error: { message: "unused" } }) },
    signSessionBytes: signWithIssuer,
    createUnifiedOwnerRoot: vi.fn(),
    registerPolicy: vi.fn(),
  } as unknown as ShareTinyCloud;
  return { put, tinycloud };
}

/** Picks `name` and creates the link for `audience`; resolves to what the composer saved and what it showed. */
async function create(name: string, audience: "bearer" | "exactEmail") {
  const { put, tinycloud } = owner();
  const saved: Array<{ readonly record?: { readonly filename?: string; readonly resource: { readonly path: string } } }> = [];
  const root = document.createElement("div"); document.body.append(root);
  mountShareComposer(root, {
    fetchFn: mockLinks().fetchFn,
    openKeyAddress: "0x1234567890abcdef", origin: "https://share.tinycloud.xyz", onBack: () => undefined, session: {} as OpenKeyShareSession, tinycloud,
    persistShare: async ({ share }) => { saved.push(share as never); },
  });
  const choice = root.querySelector<HTMLInputElement>(`input[name=recipient][value=${audience}]`)!;
  choice.checked = true; choice.dispatchEvent(new Event("change", { bubbles: true }));
  if (audience === "exactEmail") {
    const value = root.querySelector<HTMLInputElement>("input[name=recipient-value]")!;
    value.value = "reader@example.com"; value.dispatchEvent(new Event("input", { bubbles: true }));
  }
  const file = root.querySelector<HTMLInputElement>("input[type=file]")!;
  Object.defineProperty(file, "files", { configurable: true, value: [new File(["notes"], name, { type: "text/markdown" })] });
  file.dispatchEvent(new Event("change", { bubbles: true }));
  const picked = root.querySelector<HTMLElement>(".composer-status")!.textContent ?? "";
  root.querySelector<HTMLFormElement>("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await vi.waitFor(() => expect(root.querySelector<HTMLElement>(".composer-status")?.dataset.state).not.toBe("encrypting"));
  await flush();
  return { put, saved, picked, status: root.querySelector<HTMLElement>(".composer-status")! };
}

const last = (path: string): string => path.split("/").at(-1)!;

describe("TC-1610 the stored name of one file", () => {
  it.each([
    ["report.md", "report.md"],
    ["Q3.v2_final-draft.html", "Q3.v2_final-draft.html"],
    ["q3 report.md", "q3-report.md"],
    ["über.md", "uber.md"],
    ["Résumé 東京.md", "Resume.md"],
    ["😀 notes.md", "notes.md"],
    ["📄.md", "share.md"],
    ["東京.html", "share.html"],
    [".hidden.md", "hidden.md"],
    [".env", "share.env"],
    ["a..b.md", "a.b.md"],
    ["no extension here", "no-extension-here"],
    ["notes.md~", "notes-md"],
    ["Edge test (A) - read.md", "Edge-test-A-read.md"],
  ])("%s is stored as %s", (display, stored) => {
    expect(safeStorageFilename(display)).toBe(stored);
    expect(storageFilenameFor(display)).toBe(stored);
  });

  it("shortens a 200-character name to a safe one that keeps its extension", () => {
    const stored = storageFilenameFor(`${"a".repeat(196)}.md`);
    expect(stored).toBe(`${"a".repeat(100)}.md`);
    expect(stored).toMatch(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
  });

  it("never yields a key the node would refuse, whatever the name", () => {
    for (const name of ["a b", "ü", "😀", "x".repeat(300), "a\u00a0b.md", "ａｂ.md", "..hidden", "a.b.c d.md", "-lead.md", "trail-.md", "tab\there.md"].filter((candidate) => !/[\t]/.test(candidate))) {
      expect(storageFilenameFor(name)).toMatch(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
      expect(storageFilenameFor(name)).not.toContain("..");
    }
  });

  it.each(["..", ".", "a/b.md", "a\\b.md", "bad\u202ename.md", "tab\there.md", ""])("refuses %j with the ordinary 'can't be shared' error rather than rewriting it", (name) => {
    expect(() => storageFilenameFor(name)).toThrow(expect.objectContaining({ kind: "filename" }));
  });
});

describe("TC-1610 names that land in one folder", () => {
  it("gives two files that would share a stored name a numeric suffix, compared without regard to case", () => {
    expect(uniqueStoragePaths(["a b.md", "a-b.md", "A B.md", "c.md"])).toEqual(["a-b.md", "a-b-2.md", "A-B-3.md", "c.md"]);
  });

  it("names every folder segment safely, and keeps the same file in different folders apart", () => {
    expect(uniqueStoragePaths(["my notes/q3 report.md", "my notes/q3-report.md", "other/q3 report.md"])).toEqual(["my-notes/q3-report.md", "my-notes/q3-report-2.md", "other/q3-report.md"]);
  });

  it("keeps a suffixed name inside 128 characters", () => {
    const long = "b".repeat(125);
    const [first, second] = uniqueStoragePaths([`${long} x.md`, `${long}-x.md`]);
    expect(first).not.toBe(second);
    expect(second!.length).toBeLessThanOrEqual(128);
  });

  it("uploads a folder under the stored names and never overwrites a sibling", async () => {
    const { put, tinycloud } = owner();
    await uploadSelectedFiles(tinycloud, SPACE_ID, "shares/folder", "prefix", [new File(["1"], "a b.md"), new File(["2"], "a-b.md"), new File(["3"], "über.md")]);
    expect(put.mock.calls.map(([path]) => path)).toEqual(["shares/folder/a-b.md", "shares/folder/a-b-2.md", "shares/folder/uber.md"]);
  });
});

describe("TC-1610 the composer stores under the safe name and shows the name the sender chose", () => {
  it.each([["q3 report.md", "q3-report.md"], ["über.md", "uber.md"], ["😀 notes.md", "notes.md"], [`${"x".repeat(196)}.md`, `${"x".repeat(100)}.md`], ["a..b.md", "a.b.md"]])("link share of %s: key ends in %s, the saved record keeps the display name", async (display, stored) => {
    const { put, saved, status } = await create(display, "bearer");
    expect(status.dataset.state).toBe("created");
    expect(put).toHaveBeenCalledTimes(1);
    const key = put.mock.calls[0]![0];
    expect(last(key)).toBe(stored);
    expect(key).toMatch(/^xyz\.tinycloud\.share\/shares\/[0-9a-f-]{36}\/[A-Za-z0-9][A-Za-z0-9._-]*$/);
    expect(saved[0]!.record?.filename).toBe(display);
    expect(last(saved[0]!.record!.resource.path)).toBe(stored);
  });

  it.each([["q3 report.md", "q3-report.md"], ["über.md", "uber.md"], ["😀 notes.md", "notes.md"]])("addressed share of %s: key ends in %s, the signed display filename is the original", async (display, stored) => {
    const { put, status } = await create(display, "exactEmail");
    expect(status.dataset.state).toBe("created");
    expect(put).toHaveBeenCalledTimes(1);
    expect(last(put.mock.calls[0]![0])).toBe(stored);
    expect(state.published).toHaveLength(1);
    expect(state.published[0]!.filename).toBe(display.normalize("NFC"));
    expect(last((state.published[0]!.resource as { path: string }).path)).toBe(stored);
  });

  it("a name that cannot be shared at all is refused with the 'rename it' message and nothing is stored", async () => {
    for (const audience of ["bearer", "exactEmail"] as const) {
      const { put, saved, picked } = await create("..", audience);
      // Refused when the file is picked, before anything is encrypted or stored.
      expect(picked).toContain(SENDER_FAILURE.filename);
      expect(put).not.toHaveBeenCalled();
      expect(saved).toHaveLength(0);
    }
    expect(state.published).toHaveLength(0);
  });
});
