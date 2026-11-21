import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const script = fileURLToPath(new URL('./pages-check-state.mjs', import.meta.url));
const sha = 'a'.repeat(40);
const otherSha = 'b'.repeat(40);
const requiredName = 'Cloudflare Pages: share';
let nextId = 1000;
const check = (overrides = {}) => ({
  id: nextId++,
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
  test(`${conclusion} on an older attempt does not veto a newer success`, () => {
    const older = check({ id: 1001, conclusion });
    const newer = check({ id: 1002 });
    assert.equal(state([page([newer], 2), page([older], 2)]), 'success');
    assert.equal(state([page([older], 2), page([newer], 2)]), 'success');
    assert.equal(state([page([older, newer])]), 'success');
  });
  test(`the newest completed ${conclusion} refuses an older success`, () => {
    const older = check({ id: 1001 });
    const newer = check({ id: 1002, conclusion });
    assert.equal(state([page([older], 2), page([newer], 2)]), 'failure');
    assert.equal(state([page([newer, older])]), 'failure');
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

test('creation IDs, not completion timestamps or page order, select the newest attempt', () => {
  const older = check({ id: 2001, conclusion: 'failure', completed_at: '2026-11-20T12:00:00Z' });
  const newer = check({ id: 2002, completed_at: '2026-11-20T11:00:00Z' });
  assert.equal(state([page([older], 2), page([newer], 2)]), 'success');
  assert.equal(state([page([newer, older])]), 'success');
  assert.equal(state([page([
    { ...older, conclusion: 'success' },
    { ...newer, conclusion: 'failure' },
  ])]), 'failure');
});

test('a newer unfinished attempt defers a completed failure until it finishes', () => {
  const older = check({ id: 3001, conclusion: 'failure' });
  const newer = check({ id: 3002, status: 'in_progress', conclusion: null });
  assert.equal(state([page([newer], 2), page([older], 2)]), 'pending');
  assert.equal(state([page([older, newer])]), 'pending');
  assert.equal(state([page([older, { ...newer, status: 'completed', conclusion: 'success' }])]), 'success');
  assert.equal(state([page([older, { ...newer, status: 'completed', conclusion: 'timed_out' }])]), 'failure');
  assert.equal(state([page([{ ...newer, id: 3000 }, older])]), 'failure');
});

test('unfinished checks for another SHA, name or app cannot defer failure', () => {
  for (const overrides of [
    { head_sha: otherSha },
    { name: `${requiredName}-other` },
    { app: { id: 1 } },
  ]) {
    assert.equal(state([page([
      check({ id: 4001, conclusion: 'failure' }),
      check({ id: 4002, status: 'queued', conclusion: null, ...overrides }),
    ])]), 'failure');
  }
});

test('cancelled attempts neither supersede failure nor provide a completed decision', () => {
  assert.equal(state([page([
    check({ id: 5001, conclusion: 'failure' }),
    check({ id: 5002, conclusion: 'cancelled' }),
  ])]), 'failure');
  assert.equal(state([page([
    check({ id: 5001, conclusion: 'cancelled' }),
    check({ id: 5002, status: 'queued', conclusion: null }),
  ])]), 'pending');
});

test('missing, noninteger, unsafe or nonpositive IDs fail closed for matching attempts', () => {
  for (const id of [undefined, null, '6002', 6002.5, 0, -1, Number.MAX_SAFE_INTEGER + 1]) {
    for (const status of ['completed', 'in_progress']) {
      const result = run([page([
        check({ id: 6001 }),
        check({ id, status, conclusion: status === 'completed' ? 'success' : null }),
      ])]);
      assert.notEqual(result.status, 0);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /Invalid check-run id/);
    }
  }
});

test('tied IDs fail closed even across pages or for unfinished attempts', () => {
  for (const status of ['completed', 'in_progress']) {
    const result = run([
      page([check({ id: 7001 })], 2),
      page([check({ id: 7001, status, conclusion: status === 'completed' ? 'failure' : null })], 2),
    ]);
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /Duplicate check-run id: 7001/);
  }
});

test('cancelled and unrelated attempts do not participate in ID validation', () => {
  assert.equal(state([page([
    check({ id: 8001 }),
    check({ id: 8001, conclusion: 'cancelled' }),
    check({ id: undefined, conclusion: 'cancelled' }),
    check({ id: undefined, head_sha: otherSha, conclusion: 'failure' }),
    check({ id: undefined, name: `${requiredName}-other`, conclusion: 'failure' }),
    check({ id: undefined, app: { id: 1 }, conclusion: 'failure' }),
  ])]), 'success');
});

test('every superseded completed non-success is logged on stderr only', () => {
  const conclusions = ['failure', 'timed_out', 'action_required', 'startup_failure', 'stale', 'neutral', 'skipped', null];
  const older = conclusions.map((conclusion, index) => check({ id: 9001 + index, conclusion }));
  const result = run([
    page([older[3], check({ id: 9011, conclusion: 'cancelled' }), ...older.slice(4)], 10),
    page([check({ id: 9010 }), ...older.slice(0, 3)], 10),
  ]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'success\n');
  const lines = result.stderr.trim().split('\n');
  assert.equal(lines.length, conclusions.length);
  for (const attempt of older) {
    assert.ok(lines.some((line) => line.includes(`id=${attempt.id} `) && line.includes(`conclusion=${attempt.conclusion}`)));
  }
  assert.doesNotMatch(result.stderr, /9011|cancelled/);
});

test('an unfinished replacement logs the superseded failure without changing pending stdout', () => {
  const result = run([page([
    check({ id: 10001, conclusion: 'failure' }),
    check({ id: 10002, status: 'queued', conclusion: null }),
  ])]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'pending\n');
  assert.match(result.stderr, /^Superseded check-run id=10001 conclusion=failure\n$/);
});

test('a completed attempt with an unknown or absent conclusion refuses', () => {
  for (const conclusion of [null, undefined, 'unknown']) {
    assert.equal(state([page([check({ conclusion })])]), 'failure');
  }
});

test('malformed pagination metadata fails closed', () => {
  for (const pages of [
    {},
    [{}],
    [{ check_runs: null, total_count: 0 }],
    [page([], -1)],
    [page([], '0')],
    [page([], 0.5)],
    [page([check()], 1), page([], 2)],
  ]) {
    const result = run(pages);
    assert.notEqual(result.status, 0);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /Incomplete check-run response/);
  }
});
