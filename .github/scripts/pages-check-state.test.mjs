import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const script = fileURLToPath(new URL('./pages-check-state.mjs', import.meta.url));
const sha = 'a'.repeat(40);
const otherSha = 'b'.repeat(40);
const requiredName = 'Cloudflare Pages: share';
const check = (overrides = {}) => ({
  name: requiredName,
  app: { id: 85455 },
  head_sha: sha,
  status: 'completed',
  conclusion: 'success',
  ...overrides,
});
const page = (check_runs, total_count = check_runs.length) => ({ check_runs, total_count });

function run(pages) {
  return spawnSync(process.execPath, [script, sha], {
    input: JSON.stringify(pages),
    encoding: 'utf8',
  });
}

function state(pages) {
  const result = run(pages);
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

for (const duplicate of [
  { status: 'completed', conclusion: 'cancelled' },
  { status: 'in_progress', conclusion: null },
]) {
  for (const first of [true, false]) {
    test(`success survives ${duplicate.status}/${duplicate.conclusion}, duplicate first=${first}`, () => {
      const checks = first ? [check(duplicate), check()] : [check(), check(duplicate)];
      assert.equal(state([page(checks)]), 'success');
    });
  }
}

test('a completed success is required, not merely an empty or unfinished set', () => {
  for (const checks of [[], [check({ conclusion: 'cancelled' })], [check({ status: 'in_progress', conclusion: null })]]) {
    assert.equal(state([page(checks)]), 'pending');
  }
});

for (const conclusion of ['failure', 'timed_out', 'action_required', 'startup_failure', 'stale', 'neutral', 'skipped']) {
  test(`${conclusion} blocks success even on an older paginated attempt`, () => {
    assert.equal(state([page([check()], 2), page([check({ conclusion })], 2)]), 'failure');
    assert.equal(state([page([check({ conclusion }), check()])]), 'failure');
  });
}

test('wrong-SHA success cannot satisfy the gate and wrong-SHA failure cannot reject it', () => {
  assert.equal(state([page([check({ head_sha: otherSha })])]), 'pending');
  assert.equal(state([page([check(), check({ head_sha: otherSha, conclusion: 'failure' })])]), 'success');
});

test('a different project or app cannot satisfy or reject the required Pages check', () => {
  for (const overrides of [{ name: `${requiredName}-usercontent` }, { app: { id: 1 } }]) {
    assert.equal(state([page([check(overrides)])]), 'pending');
    assert.equal(state([page([check(), check({ ...overrides, conclusion: 'failure' })])]), 'success');
  }
});

test('success on a later page is accepted despite a cancelled first attempt', () => {
  assert.equal(state([page([check({ conclusion: 'cancelled' })], 2), page([check()], 2)]), 'success');
});

test('an incomplete response cannot hide an older failure behind a success', () => {
  for (const pages of [[], [page([check()], 2)]]) {
    const result = run(pages);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Incomplete check-run response/);
  }
});
