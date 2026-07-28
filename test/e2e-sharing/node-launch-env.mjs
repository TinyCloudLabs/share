import { isAbsolute, join, relative, resolve } from "node:path";

// The launched tinycloud-node reads its double-underscore canonical env
// overrides (TINYCLOUD_STORAGE__DATADIR, TINYCLOUD_SHARE_EMAIL__ENABLED,
// TINYCLOUD_SHARE_EMAIL__TRUST_BUNDLE_PATH) ahead of its file/default
// config, which is otherwise resolved against the process cwd — the Node
// checkout the harness runs the binary from. Without the share-email
// overrides, Node boots with share_email.enabled=false, share_v2_runtime
// stays None, and /share/v2/readiness can only ever report route_version
// and body_limit true.
export function buildNodeLaunchEnv(tempRoot, trustBundlePath) {
  const resolvedRoot = resolve(tempRoot);
  const datadir = join(resolvedRoot, "node-data");
  if (!isAbsolute(trustBundlePath)) {
    throw new Error("trustBundlePath must be an absolute path");
  }
  const relativeToTempRoot = relative(resolvedRoot, trustBundlePath);
  if (relativeToTempRoot === "" || relativeToTempRoot.startsWith("..") || isAbsolute(relativeToTempRoot)) {
    throw new Error("trustBundlePath must resolve inside the harness tempRoot");
  }
  return {
    TINYCLOUD_STORAGE__DATADIR: datadir,
    TINYCLOUD_SHARE_EMAIL__ENABLED: "true",
    TINYCLOUD_SHARE_EMAIL__TRUST_BUNDLE_PATH: trustBundlePath,
  };
}
