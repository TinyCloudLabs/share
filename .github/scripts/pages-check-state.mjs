import { readFileSync } from 'node:fs';

const sha = process.argv[2];
if (!sha) throw new Error('Usage: pages-check-state.mjs <requested-sha>');

// Input: gh api --paginate --slurp .../check-runs?filter=all&per_page=100.
const pages = JSON.parse(readFileSync(0, 'utf8'));
if (!Array.isArray(pages) || pages.length === 0 || pages.some((page) =>
  !Array.isArray(page.check_runs) || !Number.isInteger(page.total_count) || page.total_count < 0
)) {
  throw new Error('Incomplete check-run response');
}
const checks = pages.flatMap((page) => page.check_runs);
if (pages.some((page) => checks.length < page.total_count)) {
  throw new Error('Incomplete check-run response');
}

let state = 'pending';
for (const check of checks) {
  // GitHub's Cloudflare Workers and Pages app; another app cannot satisfy the gate.
  if (check.app?.id !== 85455 || check.name !== 'Cloudflare Pages: share' || check.head_sha !== sha) continue;
  if (check.status !== 'completed' || check.conclusion === 'cancelled') continue;
  if (check.conclusion !== 'success') {
    state = 'failure';
    break;
  }
  state = 'success';
}
console.log(state);
