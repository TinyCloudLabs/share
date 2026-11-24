import * as sdk from "@tinycloud/sdk-core";
import { beforeEach, expect, it, vi } from "vitest";

import { catalog } from "../src/apps/catalog.ts";
import { RunError, installRecordPlan } from "../src/apps/run.ts";
import { createRunPorts } from "../src/apps/run-session.ts";
import { signInWithManifest } from "../src/share/openkey-session.ts";

vi.mock("../src/share/openkey-session.ts", () => ({ signInWithManifest: vi.fn(), takeWalletApprovalFailure: () => undefined }));
vi.mock("../src/email-share/config.js", () => ({ loadSharePublicConfig: async () => ({ shareOrigin: "https://share.tinycloud.xyz" }) }));
vi.mock("@tinycloud/web-sdk", () => ({
  BrowserSessionStorage: class {
    activeAddressForRenewal() { return undefined; }
  },
}));

const entry = catalog.apps[0]!;
const failedSignIn = (): Promise<unknown> => createRunPorts().signIn(entry, installRecordPlan(entry), { approval: vi.fn() }).then(() => undefined, (error: unknown) => error);

beforeEach(() => {
  vi.mocked(signInWithManifest).mockReset();
});

it("a sign-in the SDK refuses because the account isn't set up fails as setup-required with the SDK's setup address", async () => {
  const refusal = new sdk.AccountSetupRequiredError();
  vi.mocked(signInWithManifest).mockRejectedValueOnce(refusal);
  const failure = await failedSignIn();
  expect(failure).toBeInstanceOf(RunError);
  expect(failure).toMatchObject({ reason: "setup-required", detail: refusal.setupUrl, cause: refusal });
});

it("an OpenKey refusal (a plain { code, message } object) keeps its code and message as the detail, and nothing else", async () => {
  const refusal = { code: "TERMS_NOT_ACCEPTED", message: "Accept OpenKey's terms first", token: "secret-token-value", key: "0xprivate" };
  vi.mocked(signInWithManifest).mockRejectedValueOnce(refusal);
  const failure = await failedSignIn();
  expect(failure).toBeInstanceOf(RunError);
  expect(failure).toMatchObject({ reason: "failed", detail: "TERMS_NOT_ACCEPTED: Accept OpenKey's terms first" });
  expect((failure as RunError).detail).not.toMatch(/secret-token-value|0xprivate/);
});

it("caps a long refusal message at 200 characters", async () => {
  vi.mocked(signInWithManifest).mockRejectedValueOnce({ code: "UNKNOWN", message: "x".repeat(1000) });
  const failure = await failedSignIn() as RunError;
  expect(failure.detail).toHaveLength(200);
  expect(failure.detail).toMatch(/^UNKNOWN: x+…$/);
});
