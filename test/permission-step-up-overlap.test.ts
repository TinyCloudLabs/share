import { beforeEach, describe, expect, it, vi } from "vitest";
import { requestInOpenKey } from "../src/share/permission-step-up.js";

const observed = vi.hoisted(() => ({ failure: undefined as "cancelled" | undefined }));
vi.mock("../src/share/openkey-session.js", () => ({ takeWalletApprovalFailure: () => observed.failure }));

const FIRST = [{ service: "tinycloud.encryption", path: "urn:tinycloud:encryption:x:default", actions: ["network.create"], skipPrefix: true }];
const SECOND = [{ service: "tinycloud.encryption", path: "urn:tinycloud:encryption:x:default", actions: ["decrypt"], skipPrefix: true }];

beforeEach(() => { observed.failure = undefined; });

interface Pending { readonly resolve: (approved: boolean) => void; readonly reject: (error: unknown) => void; readonly seen: Array<unknown> }

/** A client whose requests stay open until the test settles them, and which records the window handler each one found. */
function holdingClient(initialHooks?: unknown) {
  const pending: Pending[] = [];
  const started = vi.fn();
  const tinycloud: { _testHooks?: unknown; requestPermissions: (...args: unknown[]) => Promise<{ approved: boolean }>; hasPermissions: () => boolean } = {
    requestPermissions: (..._args) => {
      // Executor form: the Node 20 test runtime has no Promise.withResolvers.
      return new Promise<{ approved: boolean }>((resolve, reject) => {
        pending.push({ resolve: (approved) => resolve({ approved }), reject, seen: [tinycloud._testHooks] });
        started();
      });
    },
    hasPermissions: () => false,
  };
  if (initialHooks !== undefined) tinycloud._testHooks = initialHooks;
  return { tinycloud, pending, started };
}

const answers = (hooks: unknown): Promise<unknown> => Reflect.get(Object(hooks), "showModal")();

describe("step-ups that overlap", () => {
  it("the second waits for the first, and the handler is exactly as it started once both are done (first settles first)", async () => {
    const original = { keep: true };
    const { tinycloud, pending, started } = holdingClient(original);
    const first = requestInOpenKey(tinycloud as never, FIRST);
    const second = requestInOpenKey(tinycloud as never, SECOND);
    await vi.waitFor(() => expect(started).toHaveBeenCalledTimes(1));
    expect(pending).toHaveLength(1);
    // While the first is open it holds the auto-approving handler, and the second has not touched the field.
    await expect(answers(tinycloud._testHooks)).resolves.toEqual({ approved: true });
    expect(Reflect.get(Object(tinycloud._testHooks), "keep")).toBe(true);

    pending[0]!.resolve(true);
    await expect(first).resolves.toBe(true);
    await vi.waitFor(() => expect(started).toHaveBeenCalledTimes(2));
    // The second saw the original handler as its "previous", not the first's.
    pending[1]!.resolve(true);
    await expect(second).resolves.toBe(true);
    expect(tinycloud._testHooks).toBe(original);
  });

  it("is restored when the first fails and the second succeeds, and the failure does not block the second", async () => {
    const original = { keep: true };
    const { tinycloud, pending, started } = holdingClient(original);
    const first = requestInOpenKey(tinycloud as never, FIRST);
    const second = requestInOpenKey(tinycloud as never, SECOND);
    const firstOutcome = first.then(() => "resolved", (error: Error) => error.message);
    await vi.waitFor(() => expect(started).toHaveBeenCalledTimes(1));
    pending[0]!.reject(new Error("boom"));
    await expect(firstOutcome).resolves.toBe("boom");
    await vi.waitFor(() => expect(started).toHaveBeenCalledTimes(2));
    expect(pending[1]!.seen[0]).not.toBe(pending[0]!.seen[0]);
    pending[1]!.resolve(true);
    await expect(second).resolves.toBe(true);
    expect(tinycloud._testHooks).toBe(original);
  });

  it("is restored when the first succeeds and the second fails or is cancelled", async () => {
    const original = { keep: true };
    const { tinycloud, pending, started } = holdingClient(original);
    const first = requestInOpenKey(tinycloud as never, FIRST);
    const second = requestInOpenKey(tinycloud as never, SECOND);
    await vi.waitFor(() => expect(started).toHaveBeenCalledTimes(1));
    pending[0]!.resolve(true);
    await expect(first).resolves.toBe(true);
    await vi.waitFor(() => expect(started).toHaveBeenCalledTimes(2));
    observed.failure = "cancelled";
    pending[1]!.reject({ code: "USER_CANCELLED" });
    await expect(second).resolves.toBe(false);
    expect(tinycloud._testHooks).toBe(original);
  });

  it("leaves no handler behind when there was none", async () => {
    const { tinycloud, pending, started } = holdingClient();
    expect("_testHooks" in tinycloud).toBe(false);
    const first = requestInOpenKey(tinycloud as never, FIRST);
    const second = requestInOpenKey(tinycloud as never, SECOND);
    await vi.waitFor(() => expect(started).toHaveBeenCalledTimes(1));
    pending[0]!.resolve(true);
    await first;
    await vi.waitFor(() => expect(started).toHaveBeenCalledTimes(2));
    pending[1]!.resolve(true);
    await second;
    expect(tinycloud._testHooks).toBeUndefined();
  });

  it("each request sees the auto-approving handler while it is open, and the second never sees the first's in `previous`", async () => {
    const original = { keep: true };
    const { tinycloud, pending, started } = holdingClient(original);
    const first = requestInOpenKey(tinycloud as never, FIRST);
    const second = requestInOpenKey(tinycloud as never, SECOND);
    await vi.waitFor(() => expect(started).toHaveBeenCalledTimes(1));
    pending[0]!.resolve(true);
    await first;
    await vi.waitFor(() => expect(started).toHaveBeenCalledTimes(2));
    for (const entry of pending) await expect(answers(entry.seen[0])).resolves.toEqual({ approved: true });
    // The second's handler was built on the original, not stacked on the first's.
    expect(Reflect.get(Object(pending[1]!.seen[0]), "keep")).toBe(true);
    expect(pending[1]!.seen[0]).not.toBe(pending[0]!.seen[0]);
    pending[1]!.resolve(true);
    await second;
    expect(tinycloud._testHooks).toBe(original);
  });
});
