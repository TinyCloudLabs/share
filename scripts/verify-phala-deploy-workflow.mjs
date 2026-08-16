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
  "share_commit:",
  "environment: production",
  "group: share-api-phala-production",
  "cancel-in-progress: false",
  "--cvm-id \"${PHALA_CVM_ID}\"",
  "gh attestation verify",
  "gh run download",
  "share-api-image-digest",
  "SHARE_RELEASE_PROVENANCE",
  "https://share.tinycloud.xyz/health/readiness",
  "https://share.tinycloud.xyz/.well-known/tinycloud-share/config.json",
  "api/share/auth/openkey/nonce",
]) assert.ok(workflow.includes(fragment), `missing production deploy guard: ${fragment}`);

assert.match(workflow, /github\.event\.workflow_run\.conclusion == 'success'/);
assert.match(workflow, /github\.event\.workflow_run\.head_branch == github\.event\.repository\.default_branch/);
assert.match(workflow, /\.commit == \$commit/);
assert.match(workflow, /git merge-base --is-ancestor/);
assert.match(workflow, /PHALA_CVM_ID: \$\{\{ vars\.PHALA_SHARE_API_CVM_ID \}\}/);
assert.doesNotMatch(workflow, /PHALA_API_KEY: \$\{\{ secrets\.PHALA_API_KEY \}\}/);
assert.doesNotMatch(workflow, /share-api:sha-\$\{IMAGE_WORKFLOW_SHA\}/);
assert.match(compose, /share-api-state:\/var\/lib\/tinycloud\/share/);
assert.match(workflow, /target image.*state == "running"/s);
assert.doesNotMatch(workflow, /phala "\$\{DEPLOY_ARGS\[@\]\}"[^\n]*-e/);
assert.doesNotMatch(workflow, /DEPLOY_ARGS\+=\(-e /);
console.log("share Phala production workflow guards: valid");
