import * as sdk from "@tinycloud/sdk-core";
import { expect, it, vi } from "vitest";

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

it("a sign-in the SDK refuses because the account isn't set up fails as setup-required with the SDK's setup address", async () => {
  const refusal = new sdk.AccountSetupRequiredError();
  vi.mocked(signInWithManifest).mockRejectedValueOnce(refusal);
  const entry = catalog.apps[0]!;
  const failure = await createRunPorts().signIn(entry, installRecordPlan(entry), { approval: vi.fn() }).then(() => undefined, (error: unknown) => error);
  expect(failure).toBeInstanceOf(RunError);
  expect(failure).toMatchObject({ reason: "setup-required", detail: refusal.setupUrl, cause: refusal });
});
