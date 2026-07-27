import { join, resolve } from "node:path";

// The launched tinycloud-node reads its double-underscore canonical env
// override (TINYCLOUD_STORAGE__DATADIR) ahead of its default relative
// "./data" datadir, which is otherwise resolved against the process cwd —
// the Node checkout the harness runs the binary from.
export function buildNodeLaunchEnv(tempRoot) {
  const datadir = join(resolve(tempRoot), "node-data");
  return { TINYCLOUD_STORAGE__DATADIR: datadir };
}
