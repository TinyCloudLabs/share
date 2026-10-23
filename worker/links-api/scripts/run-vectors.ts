// Runs every service-level vector of the shared vector file on both storage adapters and prints the counts.
//   node scripts/run-vectors.ts [--vectors <path>]
// Exit code 1 when the pin does not match or any vector fails.
import { createD1Adapter, createSqliteAdapter } from "../test/support/adapters.ts";
import {
  READER_SIDE_GROUPS,
  VECTORS_SHA256,
  fileSha256,
  loadVectors,
  runServiceVectors,
  summarize,
  vectorsPath,
  type VectorResult,
} from "../test/support/vectors.ts";

const flag = process.argv.indexOf("--vectors");
const path = flag >= 0 && process.argv[flag + 1] ? process.argv[flag + 1] : undefined;
const target = path ?? vectorsPath();
const sha = fileSha256(target);
const pinOk = path === undefined ? sha === VECTORS_SHA256 : true;
console.log(`vectors file: ${path ?? "test/vectors/short-links-api-vectors.json (committed copy)"}`);
console.log(`sha256: ${sha}`);
console.log(path === undefined ? `pin ${VECTORS_SHA256}: ${pinOk ? "MATCH" : "MISMATCH"}` : "pin: not checked for an external file");

const vectors = loadVectors(target);
let failed = !pinOk;
const all: Record<string, VectorResult[]> = {};
for (const create of [createSqliteAdapter, createD1Adapter]) {
  const adapter = await create();
  const results = await runServiceVectors(vectors, adapter);
  all[adapter.name] = results;
  console.log(`\n== adapter: ${adapter.name} ==`);
  for (const [group, { total, passed }] of Object.entries(summarize(results))) {
    console.log(`${group.padEnd(30)} ${passed}/${total}`);
  }
  const bad = results.filter((r) => !r.ok);
  console.log(`total ${results.length - bad.length}/${results.length} pass`);
  for (const r of bad) {
    console.log(`  FAIL [${r.group}] ${r.name}: expected ${JSON.stringify(r.expected)} got ${JSON.stringify(r.got)}`);
  }
  failed ||= bad.length > 0;
  await adapter.close();
}
const same = JSON.stringify(all["sqlite"]?.map((r) => [r.group, r.name, r.ok])) === JSON.stringify(all["d1"]?.map((r) => [r.group, r.name, r.ok]));
console.log(`\nidentical results on both adapters: ${same}`);
console.log(`not run here (reader-side groups; of records only the 6 size-boundary vectors are run): ${READER_SIDE_GROUPS.join(", ")}`);
process.exit(failed || !same ? 1 : 0);
