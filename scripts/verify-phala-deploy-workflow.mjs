#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const workflow = readFileSync(
  new URL(
    "../.github/workflows/share-api-phala-production.yml",
    import.meta.url,
  ),
  "utf8",
);
const compose = readFileSync(
  new URL("../compose.share-api.yml", import.meta.url),
  "utf8",
);

for (const fragment of [
  "workflow_run:",
  "workflows: [Share API image]",
  "branches: [main]",
  "workflow_dispatch:",
  "share_commit:",
  "environment: production",
  "group: share-api-phala-production",
  "cancel-in-progress: false",
  '--cvm-id "${PHALA_CVM_ID}"',
  "gh attestation verify",
  "gh run download",
  "share-api-image-digest",
  "SHARE_RELEASE_PROVENANCE",
  "https://share.tinycloud.xyz/health/readiness",
  "https://share.tinycloud.xyz/.well-known/tinycloud-share/config.json",
  "api/share/auth/openkey/nonce",
])
  assert.ok(
    workflow.includes(fragment),
    `missing production deploy guard: ${fragment}`,
  );

assert.match(workflow, /github\.event\.workflow_run\.conclusion == 'success'/);
assert.match(
  workflow,
  /github\.event\.workflow_run\.head_branch == github\.event\.repository\.default_branch/,
);
assert.match(workflow, /\.commit == \$commit/);
assert.match(workflow, /git merge-base --is-ancestor/);
assert.match(workflow, /fetch-depth: 0/);
assert.match(
  workflow,
  /share_commit must be a protected-main 40-character SHA/,
);
assert.match(workflow, /git checkout --detach "\$\{SHARE_COMMIT\}"/);
assert.match(
  workflow,
  /gh attestation verify "oci:\/\/\$\{IMAGE\}" --repo "\$\{GITHUB_REPOSITORY\}" --signer-workflow "\$\{GITHUB_REPOSITORY\}\/.github\/workflows\/share-api-image\.yml" --source-digest "\$\{SHARE_COMMIT\}"/,
);
assert.match(workflow, /docker login ghcr\.io.*gh attestation verify/s);
assert.match(
  workflow,
  /- name: Select and attest immutable image\n\s+env:\n\s+GH_TOKEN: \$\{\{ github\.token \}\}/,
);
assert.match(
  workflow,
  /PHALA_CVM_ID: \$\{\{ vars\.PHALA_SHARE_API_CVM_ID \}\}/,
);
assert.match(
  workflow,
  /select\(\.name == "share-api" or \.names\[\]\? == "\/share-api" or \.names\[\]\? == "share-api"\)/,
);
assert.doesNotMatch(
  workflow,
  /PHALA_API_KEY: \$\{\{ secrets\.PHALA_API_KEY \}\}/,
);
assert.doesNotMatch(workflow, /share-api:sha-\$\{IMAGE_WORKFLOW_SHA\}/);
assert.match(compose, /share-api-state:\/var\/lib\/tinycloud\/share/);
assert.match(compose, /SHARE_TRUST_BUNDLE_SOURCE: committed/);
assert.doesNotMatch(compose, /SHARE_TRUST_BUNDLE_BASE64:/);
assert.match(
  workflow,
  /CLOUDFLARE_TUNNEL_TOKEN: \$\{\{ secrets\.CLOUDFLARE_TUNNEL_TOKEN \}\}/,
);
assert.match(
  workflow,
  /--env "CLOUDFLARE_TUNNEL_TOKEN=\$\{CLOUDFLARE_TUNNEL_TOKEN\}"/,
);
assert.match(
  workflow,
  /exact candidate image\/configuration.*public readiness contract as the health signal/s,
);
assert.match(workflow, /\.state == "running"/);
assert.match(
  workflow,
  /if \[ "\$target" -ge 1 \] && echo "\$readiness" \| jq -e '\.authReady == true and \(\.senderReady \| type == "boolean"\)'/,
);
assert.match(
  workflow,
  /\(\(keys \| sort\) == \["expiresAt", "nonce"\]\) and \(\.nonce \| test/,
);
assert.doesNotMatch(workflow, /phala "\$\{DEPLOY_ARGS\[@\]\}"[^\n]*-e/);
assert.doesNotMatch(workflow, /DEPLOY_ARGS\+=\(-e /);
assert.doesNotMatch(workflow, /--public-logs/);
assert.match(workflow, /phala deploy.*--no-public-logs/);
const imageWorkflow = readFileSync(
  new URL("../.github/workflows/share-api-image.yml", import.meta.url),
  "utf8",
);
assert.match(imageWorkflow, /- compose\.share-api\.yml/);
for (const action of [
  "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
  "docker/setup-buildx-action@e468171a9de216ec08956ac3ada2f0791b6bd435",
  "docker/login-action@9780b0c442fbb1117ed29e0efdff1e18412f7567",
  "docker/build-push-action@263435318d21b8e681c14492fe198d362a7d2c83",
  "actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be",
])
  assert.ok(
    imageWorkflow.includes(action),
    `image action is not commit pinned: ${action}`,
  );
console.log("share Phala production workflow guards: valid");
