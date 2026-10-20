// @vitest-environment jsdom
import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { resetRevokeFlights, withWalletApproval } from "../src/share/revoke-flight.js";
import { savedCopyName, writeSavedCopy } from "../src/share/saved-copy.js";
import { createSaveToTinyCloud, SaveCopyError, type SaveProgress } from "../src/viewer/save-copy.js";

type PutResult = { ok: true } | { ok: false; error: { code: string } };

const state = vi.hoisted(() => ({
  signIn: vi.fn(),
  taken: undefined as undefined | (() => string | undefined),
  putFails: undefined as undefined | { code: string },
}));

vi.mock("../src/share/openkey-session.js", () => ({
  FILES_FOR_YOU_SPACE: "files-for-you",
  FILES_FOR_YOU_PREFIX: "v1/",
  saveCopyManifest: () => ({ app_id: "xyz.tinycloud.share", permissions: [{ service: "tinycloud.kv", space: "files-for-you", path: "v1/", actions: ["get", "put", "list"], skipPrefix: true }] }),
  takeWalletApprovalFailure: () => state.taken?.(),
  signInWithManifest: (options: unknown) => state.signIn(options),
}));

const CONFIG = { shareOrigin: "https://share.tinycloud.xyz", senderBootstrapNodeOrigin: "https://tee.node.tinycloud.xyz", registryOrigin: "https://registry.tinycloud.xyz" } as never;
const sha256 = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");
const COPY = { bytes: Uint8Array.from([0, 0x23, 0x20, 0xff, 0x0a, 0x80]), filename: "report.md", mediaType: "text/markdown;charset=utf-8" };

/** A KV that behaves like a node's create-only put: a taken key answers a precondition failure. */
function fakeKv(taken: readonly string[] = []) {
  const existing = new Set(taken);
  const puts: Array<{ key: string; value: Uint8Array; options: Record<string, unknown> }> = [];
  return {
    puts,
    existing,
    put: async (key: string, value: Uint8Array, options: Record<string, unknown>): Promise<PutResult> => {
      puts.push({ key, value, options });
      if (state.putFails !== undefined) return { ok: false, error: state.putFails };
      if (options.ifNoneMatch === "*" && existing.has(key)) return { ok: false, error: { code: "KV_PRECONDITION_FAILED" } };
      existing.add(key);
      return { ok: true };
    },
  };
}

beforeEach(() => {
  state.signIn.mockReset();
  state.taken = undefined;
  state.putFails = undefined;
  resetRevokeFlights();
});

describe("saved copy names", () => {
  it.each([
    ["report.md", 1, "report.md"],
    ["report.md", 2, "report (2).md"],
    ["report.md", 10, "report (10).md"],
    ["a.b.c.html", 3, "a.b.c (3).html"],
    ["README", 2, "README (2)"],
    [".hidden", 2, ".hidden (2)"],
  ])("%s attempt %i is %s", (name, attempt, expected) => {
    expect(savedCopyName(name, attempt)).toBe(expected);
  });
});

describe("writing the copy", () => {
  it("writes exactly the received bytes under files-for-you/v1/<name>, create-only, with the given media type", async () => {
    const kv = fakeKv();
    const saved = await writeSavedCopy(kv as never, COPY);
    expect(saved).toEqual({ key: "v1/report.md", path: "files-for-you/v1/report.md" });
    expect(kv.puts).toHaveLength(1);
    expect(sha256(kv.puts[0]!.value)).toBe(sha256(COPY.bytes));
    expect(kv.puts[0]!.value).toBe(COPY.bytes);
    expect(kv.puts[0]!.options).toEqual({ contentType: "text/markdown;charset=utf-8", ifNoneMatch: "*" });
  });

  it("never replaces an earlier copy: a taken name gets the next free suffix", async () => {
    const kv = fakeKv(["v1/report.md", "v1/report (2).md"]);
    const saved = await writeSavedCopy(kv as never, COPY);
    expect(saved.path).toBe("files-for-you/v1/report (3).md");
    expect(kv.puts.map((put) => put.key)).toEqual(["v1/report.md", "v1/report (2).md", "v1/report (3).md"]);
    // The earlier copies are untouched: only the free key was ever written.
    expect([...kv.existing].sort()).toEqual(["v1/report (2).md", "v1/report (3).md", "v1/report.md"]);
  });

  it("saving twice makes two copies", async () => {
    const kv = fakeKv();
    expect((await writeSavedCopy(kv as never, COPY)).key).toBe("v1/report.md");
    expect((await writeSavedCopy(kv as never, COPY)).key).toBe("v1/report (2).md");
  });

  it("stops on a write that failed for another reason, without retrying under a new name", async () => {
    const kv = fakeKv();
    state.putFails = { code: "KV_WRITE_FAILED" };
    await expect(writeSavedCopy(kv as never, COPY)).rejects.toThrow("saved-copy-write-failed:KV_WRITE_FAILED");
    expect(kv.puts).toHaveLength(1);
  });

  it("gives up when every name is taken instead of looping", async () => {
    const kv = { put: async (): Promise<PutResult> => ({ ok: false, error: { code: "KV_PRECONDITION_FAILED" } }) };
    await expect(writeSavedCopy(kv as never, COPY)).rejects.toThrow("saved-copy-no-free-name");
  });

  it.each(["../x.md", "a/b.md", "a\\b.md", "x\u0000.md", ""])("refuses the unsafe name %j before writing anything", async (filename) => {
    const kv = fakeKv();
    await expect(writeSavedCopy(kv as never, { ...COPY, filename })).rejects.toThrow("saved-copy-unsafe-name");
    expect(kv.puts).toEqual([]);
  });
});

describe("Save a copy from the viewer", () => {
  it("calls nothing until it is invoked", () => {
    createSaveToTinyCloud(CONFIG);
    expect(state.signIn).not.toHaveBeenCalled();
  });

  it("signs in with the save manifest, hosts files-for-you, and writes the exact bytes the viewer holds", async () => {
    const kv = fakeKv();
    state.signIn.mockResolvedValue({ tinycloud: { kvForSpace: (spaceId: string) => (spaceId === "space-of-files-for-you" ? kv : undefined) }, spaces: { account: "account", "files-for-you": "space-of-files-for-you" } });

    const result = await createSaveToTinyCloud(CONFIG)(COPY, { approval: () => undefined });

    expect(result).toEqual({ path: "files-for-you/v1/report.md" });
    const [options] = state.signIn.mock.calls[0]!;
    expect(options.config).toBe(CONFIG);
    expect(options.hostSpaces).toEqual(["files-for-you"]);
    // Only the private copies area is requested.
    expect(options.manifest.permissions).toEqual([{ service: "tinycloud.kv", space: "files-for-you", path: "v1/", actions: ["get", "put", "list"], skipPrefix: true }]);
    expect(sha256(kv.puts[0]!.value)).toBe(sha256(COPY.bytes));
  });

  it("reports an open approval while OpenKey waits, one at a time", async () => {
    const seen: boolean[] = [];
    let second: Promise<unknown> | undefined;
    state.signIn.mockImplementation(async (options: { guardApproval: <T>(wait: () => Promise<T>) => Promise<T> }) => {
      await options.guardApproval(async () => {
        // While one approval is open, a second one is refused, not queued.
        second = options.guardApproval(async () => "second").catch((error: unknown) => error);
        await second;
      });
      return { tinycloud: { kvForSpace: () => fakeKv() }, spaces: { "files-for-you": "space" } };
    });
    await createSaveToTinyCloud(CONFIG)(COPY, { approval: (open) => seen.push(open) });
    expect(seen).toEqual([true, false]);
    expect((await second as Error).message).toBe("revoke-another-approval");
  });

  it.each([
    ["an approval left open past 60 seconds", "timeout"],
  ] as const)("%s ends as %s", async (_label, reason) => {
    vi.useFakeTimers();
    try {
      const progress: SaveProgress = { approval: () => undefined };
      state.signIn.mockImplementation(async (options: { guardApproval: <T>(wait: () => Promise<T>) => Promise<T> }) => {
        await options.guardApproval(() => new Promise<never>(() => undefined));
      });
      const running = createSaveToTinyCloud(CONFIG)(COPY, progress).catch((error: unknown) => error);
      await vi.advanceTimersByTimeAsync(60_000);
      const error = await running;
      expect(error).toBeInstanceOf(SaveCopyError);
      expect((error as SaveCopyError).reason).toBe(reason);
    } finally {
      vi.useRealTimers();
    }
  });

  it("frees the approval slot after a timeout, so the next try can ask again", async () => {
    vi.useFakeTimers();
    try {
      state.signIn.mockImplementationOnce(async (options: { guardApproval: <T>(wait: () => Promise<T>) => Promise<T> }) => {
        await options.guardApproval(() => new Promise<never>(() => undefined));
      });
      const first = createSaveToTinyCloud(CONFIG)(COPY, { approval: () => undefined }).catch((error: unknown) => error);
      await vi.advanceTimersByTimeAsync(60_000);
      await first;
      await expect(withWalletApproval({ setApproval: () => undefined }, async () => "free")).resolves.toBe("free");
    } finally {
      vi.useRealTimers();
    }
  });

  it("names a cancelled approval from what OpenKey said, because the SDK folds that into '[object Object]'", async () => {
    state.signIn.mockImplementation(async (options: { onClient: (client: object) => void }) => {
      options.onClient({});
      throw new Error("[object Object]");
    });
    state.taken = () => "cancelled";
    const error = await createSaveToTinyCloud(CONFIG)(COPY, { approval: () => undefined }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(SaveCopyError);
    expect((error as SaveCopyError).reason).toBe("cancelled");
  });

  it("names an approval from another account", async () => {
    state.signIn.mockImplementation(async (options: { onClient: (client: object) => void }) => {
      options.onClient({});
      throw new Error("wallet-approval-wrong-account");
    });
    state.taken = () => "wrong-account";
    const error = await createSaveToTinyCloud(CONFIG)(COPY, { approval: () => undefined }).catch((caught: unknown) => caught);
    expect((error as SaveCopyError).reason).toBe("wrong-account");
  });

  it("any other failure is a plain 'failed', and the thrown error carries no response text", async () => {
    state.signIn.mockRejectedValue(new Error("403 {\"secret\":\"tc500-secret-marker\"}"));
    const error = await createSaveToTinyCloud(CONFIG)(COPY, { approval: () => undefined }).catch((caught: unknown) => caught);
    expect((error as SaveCopyError).reason).toBe("failed");
    expect((error as SaveCopyError).message).toBe("save-copy-failed");
  });

  it("a write that fails after sign-in is a plain failure too", async () => {
    state.putFails = { code: "KV_WRITE_FAILED" };
    state.signIn.mockResolvedValue({ tinycloud: { kvForSpace: () => fakeKv() }, spaces: { "files-for-you": "space" } });
    const error = await createSaveToTinyCloud(CONFIG)(COPY, { approval: () => undefined }).catch((caught: unknown) => caught);
    expect((error as SaveCopyError).reason).toBe("failed");
  });

  it("writes no storage and logs nothing", async () => {
    const logs = [vi.spyOn(console, "log"), vi.spyOn(console, "debug"), vi.spyOn(console, "info"), vi.spyOn(console, "warn"), vi.spyOn(console, "error")].map((spy) => spy.mockImplementation(() => undefined));
    state.signIn.mockResolvedValue({ tinycloud: { kvForSpace: () => fakeKv() }, spaces: { "files-for-you": "space" } });
    await createSaveToTinyCloud(CONFIG)(COPY, { approval: () => undefined });
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    for (const spy of logs) expect(spy).not.toHaveBeenCalled();
  });
});
