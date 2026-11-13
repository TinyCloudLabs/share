// @vitest-environment node
/** Hermetic Share sessions run through the development server. Details: TC-2872 */
import { afterEach, expect, it, vi } from "vitest";
import { resolveConfig } from "vite";

afterEach(() => vi.unstubAllEnvs());

it("refuses a production build with hermetic routing enabled", async () => {
  vi.stubEnv("VITE_SHARE_HERMETIC", "true");
  await expect(resolveConfig({}, "build", "production")).rejects.toThrow("Hermetic Share runs require the development server");
});

it("permits ordinary production configuration", async () => {
  vi.stubEnv("VITE_SHARE_HERMETIC", "false");
  expect((await resolveConfig({}, "build", "production")).command).toBe("build");
});

it("permits a hermetic development server", async () => {
  vi.stubEnv("VITE_SHARE_HERMETIC", "true");
  expect((await resolveConfig({}, "serve", "development")).command).toBe("serve");
});
