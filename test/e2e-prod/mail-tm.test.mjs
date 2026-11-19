import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fake } from "./mail-tm-fake.mjs";
import { adoptInbox, createInbox, deleteInboxes, openKeyCodeIn, readInboxFile, removeInboxFile, seenMail, waitForMail, writeInboxFile } from "./mail-tm.mjs";

const FAKE = new URL("./mail-tm-fake.mjs", import.meta.url).href;
const CLI = new URL("./mail-tm.mjs", import.meta.url).pathname;
/** The helper's command line in a child process whose fetch is the fake (no network). */
const cli = (...args) => spawnSync(process.execPath, ["--import", FAKE, CLI, ...args], { encoding: "utf8" });
test("a new inbox is private: qa in its name, a random password, and an id", async () => {
  const inbox = await createInbox("share-smoke");
  assert.match(inbox.address, /^tcqa-share-smoke-[0-9a-f]{12}@mail\.example$/);
  assert.ok(inbox.password.length >= 20);
  assert.ok(inbox.id && inbox.token);
});

test("a create whose first reply was lost (422 on the retry) is still our inbox", async () => {
  fake.createStatus = 500; // the first reply is a 5xx after the account was made; the retry answers 422
  try {
    const inbox = await createInbox("courier-smoke");
    assert.ok(inbox.id, "the inbox id comes from /me");
  } finally {
    fake.createStatus = 201;
  }
});

test("the OpenKey code is the single six-digit code in the mail, never another number", () => {
  assert.equal(openKeyCodeIn("Your verification code is 123456. Your verification code: 123456"), "123456");
  assert.equal(openKeyCodeIn("verification code 123456 and verification code 654321"), undefined);
  assert.equal(openKeyCodeIn("order 1234567 shipped"), undefined);
});

test("waitForMail takes the newest unused matching mail and marks it used", async () => {
  const inbox = adoptInbox({ address: [...fake.accounts.keys()][0], password: fake.accounts.get([...fake.accounts.keys()][0]).password });
  fake.messages = [
    { id: "m1", subject: "OpenKey code", createdAt: "2026-01-01T00:00:00Z", text: "verification code 111111" },
    { id: "m2", subject: "OpenKey code", createdAt: "2026-01-01T00:01:00Z", text: "verification code 222222" },
    { id: "m3", subject: "Something else", createdAt: "2026-01-01T00:02:00Z", text: "verification code 333333" },
  ];
  const used = new Set();
  assert.equal(await waitForMail(inbox, { subject: /openkey/i, extract: openKeyCodeIn, used, timeout: 1_000 }), "222222");
  assert.equal(await waitForMail(inbox, { subject: /openkey/i, extract: openKeyCodeIn, used, timeout: 1_000 }), "111111");
  await assert.rejects(waitForMail(inbox, { subject: /openkey/i, extract: openKeyCodeIn, used, timeout: 1, failure: "nothing new" }), /nothing new/);
});

test("an adopted inbox must be a qa test inbox", () => {
  assert.throws(() => adoptInbox({ address: "person@example.com", password: "x" }), /not a test inbox/);
  assert.throws(() => adoptInbox({ address: "qa-x@mail.example", password: "" }), /not a test inbox/);
});

test("seenMail lists the mail already there, and fails closed when the inbox can't be read", async () => {
  const address = [...fake.accounts.keys()][0];
  const inbox = adoptInbox({ address, password: fake.accounts.get(address).password });
  assert.deepEqual([...await seenMail(inbox)].sort(), ["m1", "m2", "m3"]);
  fake.listStatus = 500;
  try {
    await assert.rejects(seenMail(inbox), /could not be read/);
  } finally {
    fake.listStatus = 200;
  }
  await assert.rejects(seenMail(adoptInbox({ address: "qa-unknown-000000000000@mail.example", password: "p" })), /could not be read/);
});

test("a 401 never marks an inbox made in this process as gone", async () => {
  const inbox = await createInbox("share-smoke");
  inbox.token = "";
  fake.tokenRefusals = 1;
  await assert.rejects(seenMail(inbox), /could not be read/);
  assert.notEqual(inbox.gone, true);
  assert.equal(fake.tokenRefusals, 0, "a refused token for an inbox made here is not retried as if transient");
});

test("an inbox made here whose create reply was lost (no id) is never reported deleted on 401s", () => {
  // A fresh process (deleteInboxes runs once per process), on the fake: the create's first reply is
  // lost (5xx, then 422 on the retry), every token request is refused, and the inbox must count as
  // not deleted, with no delete call.
  const script = `
    import { fake } from ${JSON.stringify(FAKE)};
    import { createInbox, deleteInboxes } from ${JSON.stringify(new URL("./mail-tm.mjs", import.meta.url).href)};
    fake.createStatus = 500; fake.tokenRefusals = 99;
    await createInbox("share-smoke").catch(() => undefined);
    console.log(JSON.stringify({ ...(await deleteInboxes()), deleteCalls: fake.deleted.length }));`;
  const run = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), { deleted: 0, total: 1, deleteCalls: 0 });
});

test("an adopted inbox is gone only after two consecutive 401s; one refusal then a token is not gone", async () => {
  const address = [...fake.accounts.keys()][0];
  const inbox = adoptInbox({ address, password: fake.accounts.get(address).password });
  fake.tokenRefusals = 1;
  assert.ok((await seenMail(inbox)).size > 0);
  assert.notEqual(inbox.gone, true);
});

test("deleteInboxes deletes every inbox made or adopted, once; an inbox mail.tm no longer knows counts as gone", async () => {
  adoptInbox({ address: "qa-deleted-earlier-000000000000@mail.example", password: "p" });
  const first = await deleteInboxes();
  const again = await deleteInboxes();
  assert.equal(first, again);
  assert.equal(first.deleted, first.total);
  assert.equal(new Set(fake.deleted).size, fake.accounts.size);
});

test("the command line creates an inbox file without printing the address, and deletes inbox and file", () => {
  const directory = mkdtempSync("/var/tmp/mail-tm-test-");
  try {
    const path = join(directory, "inbox.json");
    const created = cli("create", path);
    assert.equal(created.status, 0);
    assert.deepEqual(JSON.parse(created.stdout), { created: true });
    const { address } = JSON.parse(readFileSync(path, "utf8"));
    assert.match(address, /^tcqa-recipient-gate-[0-9a-f]{12}@mail\.example$/);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.ok(!`${created.stdout}${created.stderr}`.includes(address));
    assert.match(cli("create", path).stdout, /must be a new file/);
    // A fresh process: the fake knows no such inbox (401), as for one deleted earlier; the file goes.
    const deleted = cli("delete", path);
    assert.equal(deleted.status, 0);
    assert.deepEqual(JSON.parse(deleted.stdout), { inboxDeleted: true, fileRemoved: true });
    assert.equal(existsSync(path), false);
    assert.match(cli("create", "/tmp/inbox.json").stdout, /under \/var\/tmp/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the inbox file is a new 0600 file under /var/tmp with only the address and password", () => {
  const directory = mkdtempSync("/var/tmp/mail-tm-test-");
  try {
    const path = join(directory, "inbox.json");
    writeInboxFile(path, { address: "qa-recipient-gate-000000000000@mail.example", password: "p", id: "i", token: "t" });
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.deepEqual(JSON.parse(readFileSync(path, "utf8")), { address: "qa-recipient-gate-000000000000@mail.example", password: "p" });
    assert.throws(() => writeInboxFile(path, { address: "qa-x@mail.example", password: "q" }), /must be a new file/);
    assert.equal(readInboxFile(path).address, "qa-recipient-gate-000000000000@mail.example");
    removeInboxFile(path);
    assert.equal(existsSync(path), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
  assert.throws(() => writeInboxFile("/tmp/inbox.json", { address: "qa-x@mail.example", password: "p" }), /under \/var\/tmp/);
});

test("an inbox file with looser permissions or other content is refused", () => {
  const directory = mkdtempSync("/var/tmp/mail-tm-test-");
  try {
    const loose = join(directory, "loose.json");
    writeFileSync(loose, JSON.stringify({ address: "qa-x@mail.example", password: "p" }));
    chmodSync(loose, 0o644);
    assert.throws(() => readInboxFile(loose), /0600/);
    const extra = join(directory, "extra.json");
    writeFileSync(extra, JSON.stringify({ address: "qa-x@mail.example", password: "p", note: "x" }), { mode: 0o600 });
    assert.throws(() => readInboxFile(extra), /not an inbox file/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("an aborted wait for mail stops polling and takes nothing", async () => {
  const address = [...fake.accounts.keys()][0];
  const inbox = adoptInbox({ address, password: fake.accounts.get(address).password });
  fake.messages = [{ id: "m9", subject: "OpenKey code", createdAt: "2026-01-01T00:09:00Z", text: "verification code 999999" }];
  const used = new Set();
  const stop = new AbortController();
  stop.abort(new Error("the wait for the code ended"));
  await assert.rejects(waitForMail(inbox, { subject: /openkey/i, extract: openKeyCodeIn, used, timeout: 1_000, signal: stop.signal }), /the wait for the code ended/);
  assert.equal(used.size, 0, "an aborted wait marks no mail used");
  assert.equal(await waitForMail(inbox, { subject: /openkey/i, extract: openKeyCodeIn, used, timeout: 1_000 }), "999999", "the code is still there for the next wait");
});
