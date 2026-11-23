// @vitest-environment node
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import * as sdk from "@tinycloud/sdk-core";
import { expect, it, vi } from "vitest";

import { runnerHref } from "../src/apps/install-plan.ts";
import { createRunPorts } from "../src/apps/run-session.ts";
import { openApp, RunError } from "../src/apps/run.ts";

it("the Contacts direct link resolves its pinned release and reaches owner approval", async () => {
  const appId = "xyz.tinycloud.tinyapps.contacts";
  const url = new URL(runnerHref(appId), "http://localhost");
  expect(url.pathname).toBe("/apps/run");
  vi.stubGlobal("fetch", async (path: string) => {
    expect(path).toMatch(/^\/apps\/b\/[a-f0-9]{64}\//);
    const bytes = await readFile(join("public", path));
    return new Response(new Uint8Array(bytes));
  });
  const cancelled = new RunError("cancelled");
  const signIn = vi.fn(async () => { throw cancelled; });
  const report = vi.fn();
  try {
    await expect(openApp(decodeURIComponent(url.hash.slice(1)), {
      ...createRunPorts(),
      hasPersistedSession: async () => false,
      sdk: async () => sdk,
      signIn,
    }, report)).rejects.toBe(cancelled);
    expect(signIn).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ app_id: appId, publisher: { name: "TinyCloud" } }),
      expect.objectContaining({
        scope: expect.objectContaining({ allowedRunnerKeyPath: "apps/xyz.tinycloud.share/" + appId + "/seal-v1" }),
      }),
      expect.any(Object),
    );
    expect(report).toHaveBeenCalledWith(expect.objectContaining({ phase: "disclosing" }));
  } finally {
    vi.unstubAllGlobals();
  }
});
