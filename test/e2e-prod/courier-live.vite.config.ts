/**
 * The smoke's build: the repo's own vite config plus the seed page as an extra
 * input. Used only by courier-live-smoke.mjs; the deployed build has no seed page.
 */
import { fileURLToPath } from "node:url";
import type { ConfigEnv, UserConfig } from "vite";
import base from "../../vite.config.ts";

export default async function config(env: ConfigEnv): Promise<UserConfig> {
  const resolved = typeof base === "function" ? await base(env) : await base;
  const input = resolved.build?.rollupOptions?.input as Record<string, string>;
  return { ...resolved, build: { ...resolved.build, rollupOptions: { ...resolved.build?.rollupOptions, input: { ...input, courierSeed: fileURLToPath(new URL("../fixtures/courier-seed/index.html", import.meta.url)) } } } };
}
