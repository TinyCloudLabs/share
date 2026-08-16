#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const workflow = readFileSync(new URL("../.github/workflows/share-api-phala-production.yml", import.meta.url), "utf8");
const compose = readFileSync(new URL("../compose.share-api.yml", import.meta.url), "utf8");

for (const fragment of [
  "workflow_run:",
  "workflows: [Share API image]",
  "branches: [main]",
  "workflow_dispatch:",
  "environment: production",
  "group: share-api-phala-production",
  "cancel-in-progress: false",
  "--cvm-id \"${PHALA_CVM_ID}\"",
  "gh attestation verify",
  "SHARE_RELEASE_PROVENANCE",
  "https://share.tinycloud.xyz/health/readiness",
  "https://share.tinycloud.xyz/.well-known/tinycloud-share/config.json",
  "api/share/auth/openkey/nonce",
]) assert.ok(workflow.includes(fragment), `missing production deploy guard: ${fragment}`);

assert.match(workflow, /github\.event\.workflow_run\.conclusion == 'success'/);
assert.match(workflow, /github\.event\.workflow_run\.head_branch == github\.event\.repository\.default_branch/);
assert.match(compose, /share-api-state:\/var\/lib\/tinycloud\/share/);
assert.match(workflow, /target image.*state == "running"/s);
assert.doesNotMatch(workflow, /phala "\$\{DEPLOY_ARGS\[@\]\}"[^\n]*-e/);
assert.doesNotMatch(workflow, /DEPLOY_ARGS\+=\(-e /);
console.log("share Phala production workflow guards: valid");
