import { defineConfig } from "vitest/config";

/**
 * Vitest config for the VIEWER tests only (test/). Deliberately NOT named
 * vitest.config.ts: vitest resolves config by walking up from the cwd, so an
 * auto-discovered root config would hijack the stage-1/2 package suites
 * (node environment, their own test dirs). The root `npm test` passes
 * --config explicitly; the packages keep their defaults:
 *   npm run -w @tinycloud/share-envelope test
 *   npm run -w @tinycloud/share-registry test
 */
export default defineConfig({
  test: {
    environment: "jsdom",
    include: ["test/**/*.test.ts"],
    setupFiles: ["test/setup.ts"],
  },
});
