#!/usr/bin/env node

import { readFile } from "node:fs/promises";

const source = await readFile(new URL("./integration.mjs", import.meta.url), "utf8");
const native = source.slice(source.indexOf("async function nativeGate"), source.indexOf("function spawnOwned"));
const production = source.slice(source.indexOf("async function productionGateHermetic"), source.indexOf("async function fixtureGate"));
const releasePositive = `${native}\n${production}`;
const forbidden = [
  ["tinycloud", "-node-n4-mounted-fixture"].join(""),
  ["email-claim", "-fixture"].join(""),
  ["compose_", "fixture_from_env"].join(""),
  ["mounted", "-fixture"].join(""),
  "SHARE_EMAIL_TRUSTED_NODE_ORIGIN",
  "SHARE_EMAIL_TRUSTED_NODE_AUDIENCE",
  "SHARE_EMAIL_TRUSTED_NODE_KID",
  "SHARE_EMAIL_TRUSTED_NODE_PUBLIC_KEY",
];
for (const marker of forbidden) {
  if (releasePositive.includes(marker)) throw new Error(`release-positive composition contains forbidden fixture/test control: ${marker}`);
}
for (const marker of [
  "tinycloud-node-production-e2e",
  "--features",
  "dstack",
  "opencredentials-witness",
  "waitForPort(credentialsPort",
  "SHARE_EMAIL_TRUST_BUNDLE_JSON",
  "RESEND_API_KEY",
]) {
  if (!releasePositive.includes(marker)) throw new Error(`release-positive composition is missing production startup assertion: ${marker}`);
}
if (!source.includes('waitForPort(port, "PostgreSQL")')) throw new Error("production PostgreSQL startup does not verify a listening process");
console.log("release-positive composition: production-only application startup checks passed");
