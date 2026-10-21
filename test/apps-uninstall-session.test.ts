import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Mock } from "vitest";

import { INSTALL_SPACE } from "../src/apps/install-plan.ts";
import { createUninstallPorts } from "../src/apps/uninstall-session.ts";
import { ACCOUNT_SPACE, LIST_PAGE_LIMIT, UNINSTALL_IDENTITY_ID, UninstallError, uninstallPlan, uninstallScope } from "../src/apps/uninstall-plan.ts";

const mocks = vi.hoisted(() => ({
  signInWithManifest: vi.fn(),
  takeWalletApprovalFailure: vi.fn((): string | undefined => undefined),
  loadSharePublicConfig: vi.fn(async () => ({ publicConfig: true })),
}));

vi.mock("../src/share/openkey-session.js", () => ({
  signInWithManifest: mocks.signInWithManifest,
  takeWalletApprovalFailure: mocks.takeWalletApprovalFailure,
}));
vi.mock("../src/email-share/config.js", () => ({ loadSharePublicConfig: mocks.loadSharePublicConfig }));

type Reply = { ok: true; data?: unknown } | { ok: false; error: { code: string } };

interface FakeKv {
  list: Mock;
  delete: Mock;
}

interface FakeTinyCloud {
  kv: FakeKv;
  remove: Mock;
  tinycloud: { kvForSpace: Mock; account: { applications: { remove: Mock } } };
}

interface FakeHandle {
  tinycloud: FakeTinyCloud["tinycloud"];
  spaces: Record<string, string>;
  dispose: Mock;
}

function fakeTinyCloud(replies: { list?: Reply; del?: Reply; remove?: Reply } = {}): FakeTinyCloud {
  const kv: FakeKv = {
    list: vi.fn(async () => replies.list ?? { ok: true, data: { keys: [], truncated: false } }),
    delete: vi.fn(async () => replies.del ?? { ok: true }),
  };
  const remove = vi.fn(async () => replies.remove ?? { ok: true, data: undefined });
  return {
    kv,
    remove,
    tinycloud: { kvForSpace: vi.fn(() => kv), account: { applications: { remove } } },
  };
}

function signedIn(
  tc: FakeTinyCloud,
  spaces: Record<string, string> = { [INSTALL_SPACE]: "space-install", [ACCOUNT_SPACE]: "space-account" },
): FakeHandle {
  return { tinycloud: tc.tinycloud, spaces, dispose: vi.fn(async () => undefined) };
}

const app = { app_id: "todo", name: "Todo" };
const plan = uninstallPlan(app);
const hooks = { approval: vi.fn() };

beforeEach(() => {
  vi.clearAllMocks();
  mocks.takeWalletApprovalFailure.mockReturnValue(undefined);
});

describe("createUninstallPorts: sign-in", () => {
  it("signs in as the maintenance identity, scoped to the sheet, without the apps-list grants", async () => {
    const tc = fakeTinyCloud();
    const handle = signedIn(tc);
    mocks.signInWithManifest.mockResolvedValue(handle);

    const session = await createUninstallPorts().openSession(plan, hooks);

    expect(mocks.signInWithManifest).toHaveBeenCalledTimes(1);
    const args = mocks.signInWithManifest.mock.calls[0]?.[0];
    if (args === undefined) throw new Error("the sign-in was not called");
    expect(args.manifest.app_id).toBe(UNINSTALL_IDENTITY_ID);
    expect(args.manifest.prefix).toBe("todo");
    expect(args.includeAccountRegistryPermissions).toBe(false);
    expect(args.hostSpaces).toEqual([INSTALL_SPACE, ACCOUNT_SPACE]);
    expect(args).toMatchObject(uninstallScope("todo"));

    await session.dispose();
    expect(handle.dispose).toHaveBeenCalledTimes(1);
  });

  it("fails and disposes when the account space is not hosted", async () => {
    const tc = fakeTinyCloud();
    const handle = signedIn(tc, { [INSTALL_SPACE]: "space-install" });
    mocks.signInWithManifest.mockResolvedValue(handle);

    await expect(createUninstallPorts().openSession(plan, hooks)).rejects.toMatchObject({ reason: "failed" });
    expect(handle.dispose).toHaveBeenCalledTimes(1);
  });

  it("reports the wallet's refusal as the failure reason", async () => {
    mocks.signInWithManifest.mockImplementation(async (args: { onClient(client: unknown): void }) => {
      args.onClient({});
      throw new Error("openkey-rejected");
    });
    mocks.takeWalletApprovalFailure.mockReturnValue("wrong-account");

    await expect(createUninstallPorts().openSession(plan, hooks)).rejects.toMatchObject({ reason: "wrong-account" });
  });

  it("maps an approval window that was abandoned to timeout", async () => {
    mocks.signInWithManifest.mockImplementation(async (args: { guardApproval(wait: () => Promise<unknown>): Promise<unknown> }) => {
      await expect(args.guardApproval(async () => { throw new Error("revoke-approval-abandoned"); })).rejects.toThrow();
      throw new Error("openkey-rejected");
    });

    await expect(createUninstallPorts().openSession(plan, hooks)).rejects.toMatchObject({ reason: "timeout" });
  });

  it("a sign-in failure with nothing else known is a plain failure", async () => {
    mocks.signInWithManifest.mockRejectedValue(new Error("network"));
    const error = await createUninstallPorts().openSession(plan, hooks).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(UninstallError);
    expect((error as UninstallError).reason).toBe("failed");
  });
});

describe("createUninstallPorts: folder listing and deletes", () => {
  it("maps a listing page and passes the page size and cursor on", async () => {
    const tc = fakeTinyCloud({ list: { ok: true, data: { keys: ["todo/app/a"], truncated: true, nextCursor: "n1" } } });
    mocks.signInWithManifest.mockResolvedValue(signedIn(tc));
    const session = await createUninstallPorts().openSession(plan, hooks);

    await expect(session.list("todo/app/")).resolves.toEqual({ keys: ["todo/app/a"], truncated: true, nextCursor: "n1" });
    expect(tc.kv.list).toHaveBeenCalledWith({ prefix: "todo/app/", limit: LIST_PAGE_LIMIT });

    await session.list("todo/app/", "n1");
    expect(tc.kv.list).toHaveBeenLastCalledWith({ prefix: "todo/app/", limit: LIST_PAGE_LIMIT, cursor: "n1" });
  });

  it("a key that is already gone counts as deleted", async () => {
    const tc = fakeTinyCloud({ del: { ok: false, error: { code: "KV_NOT_FOUND" } } });
    mocks.signInWithManifest.mockResolvedValue(signedIn(tc));
    const session = await createUninstallPorts().openSession(plan, hooks);
    await expect(session.del("todo/app/a")).resolves.toBeUndefined();
  });

  it("any other delete failure rejects", async () => {
    const tc = fakeTinyCloud({ del: { ok: false, error: { code: "KV_WRITE_FAILED" } } });
    mocks.signInWithManifest.mockResolvedValue(signedIn(tc));
    const session = await createUninstallPorts().openSession(plan, hooks);
    await expect(session.del("todo/app/a")).rejects.toThrow("uninstall-delete-failed:KV_WRITE_FAILED");
  });
});

describe("createUninstallPorts: registry removal", () => {
  it("removes the app's entry by its id", async () => {
    const tc = fakeTinyCloud();
    mocks.signInWithManifest.mockResolvedValue(signedIn(tc));
    const session = await createUninstallPorts().openSession(plan, hooks);
    await session.removeRegistry("todo");
    expect(tc.remove).toHaveBeenCalledWith("todo");
  });

  it("an entry that is already gone counts as removed", async () => {
    const tc = fakeTinyCloud({ remove: { ok: false, error: { code: "KV_NOT_FOUND" } } });
    mocks.signInWithManifest.mockResolvedValue(signedIn(tc));
    const session = await createUninstallPorts().openSession(plan, hooks);
    await expect(session.removeRegistry("todo")).resolves.toBeUndefined();
  });

  it("any other registry failure rejects, so the run reports the entry as not removed", async () => {
    const tc = fakeTinyCloud({ remove: { ok: false, error: { code: "NETWORK_ERROR" } } });
    mocks.signInWithManifest.mockResolvedValue(signedIn(tc));
    const session = await createUninstallPorts().openSession(plan, hooks);
    await expect(session.removeRegistry("todo")).rejects.toThrow("uninstall-registry-failed:NETWORK_ERROR");
  });
});

describe("createUninstallPorts: the request before OpenKey", () => {
  /** The plan with its `app/` grant widened to `put`: the signed request would exceed the sheet. */
  const widened = (): typeof plan => ({
    ...plan,
    manifest: {
      ...plan.manifest,
      permissions: (plan.manifest.permissions ?? []).map((permission) => (permission.path === "app/" ? { ...permission, actions: ["list", "del", "put"] } : permission)),
    } as typeof plan.manifest,
  });

  it("stops when the composed request grants more than the sheet lists, before OpenKey opens", async () => {
    await expect(createUninstallPorts().openSession(widened(), hooks)).rejects.toMatchObject({ reason: "not-started", cause: expect.objectContaining({ message: "uninstall-request-differs-from-sheet" }) });
    expect(mocks.signInWithManifest).not.toHaveBeenCalled();
  });

  it("stops when the request would delegate to another DID, before OpenKey opens", async () => {
    const delegated = { ...plan, manifest: { ...plan.manifest, did: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" } as typeof plan.manifest };
    await expect(createUninstallPorts().openSession(delegated, hooks)).rejects.toMatchObject({ reason: "not-started", cause: expect.objectContaining({ message: "uninstall-request-delegates" }) });
    expect(mocks.signInWithManifest).not.toHaveBeenCalled();
  });

  it("signs in with the uninstall's own scope, a 15-minute window, and no account creation", async () => {
    mocks.signInWithManifest.mockResolvedValue(signedIn(fakeTinyCloud()));
    await createUninstallPorts().openSession(plan, hooks);
    expect(mocks.signInWithManifest).toHaveBeenCalledWith(
      expect.objectContaining({
        manifest: plan.manifest,
        allowedSpaces: [INSTALL_SPACE, ACCOUNT_SPACE],
        allowedActions: ["list", "del"],
        expiry: 15 * 60 * 1000,
        autoCreateSpace: false,
        includeAccountRegistryPermissions: false,
        sessionPrefix: "tinycloud-share-uninstall",
      }),
    );
  });
});
