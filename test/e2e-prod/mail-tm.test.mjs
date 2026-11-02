import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { adoptInbox, createInbox, deleteInboxes, openKeyCodeIn, readInboxFile, removeInboxFile, waitForMail, writeInboxFile } from "./mail-tm.mjs";

// A stand-in for api.mail.tm: one domain, accounts, tokens, messages, deletes.
const fake = { accounts: new Map(), messages: [], deleted: [], createStatus: 201, calls: [] };
globalThis.fetch = async (url, { method = "GET", body, headers = {} } = {}) => {
  const { pathname } = new URL(url);
  fake.calls.push(`${method} ${pathname}`);
  const json = (status, value) => new Response(value === undefined ? null : JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
  const sent = body ? JSON.parse(body) : {};
  const token = headers.authorization?.replace("Bearer ", "");
  if (pathname === "/domains") return json(200, { "hydra:member": [{ domain: "mail.example", isActive: true }] });
  if (pathname === "/accounts" && method === "POST") {
    if (fake.accounts.has(sent.address)) return json(422, { violations: [] });
    fake.accounts.set(sent.address, { id: `id-${fake.accounts.size + 1}`, password: sent.password });
    return json(fake.createStatus, fake.createStatus === 201 ? { id: fake.accounts.get(sent.address).id } : undefined);
  }
  if (pathname === "/token") {
    const account = fake.accounts.get(sent.address);
    return account?.password === sent.password ? json(200, { token: `t-${account.id}` }) : json(401, {});
  }
  const account = [...fake.accounts.values()].find((entry) => `t-${entry.id}` === token);
  if (account === undefined) return json(401, {});
  if (pathname === "/me") return json(200, { id: account.id });
  if (pathname === "/messages") return json(200, { "hydra:member": fake.messages.map(({ id, subject, createdAt }) => ({ id, subject, createdAt })) });
  if (pathname.startsWith("/messages/")) { const message = fake.messages.find((entry) => entry.id === pathname.slice(10)); return message ? json(200, message) : json(404, {}); }
  if (pathname.startsWith("/accounts/") && method === "DELETE") { fake.deleted.push(pathname.slice(10)); return json(204); }
  return json(404, {});
};

test("a new inbox is private: qa in its name, a random password, and an id", async () => {
  const inbox = await createInbox("share-smoke");
  assert.match(inbox.address, /^qa-share-smoke-[0-9a-f]{12}@mail\.example$/);
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

test("deleteInboxes deletes every inbox made or adopted, once", async () => {
  const first = await deleteInboxes();
  const again = await deleteInboxes();
  assert.equal(first, again);
  assert.equal(first.deleted, first.total);
  assert.equal(new Set(fake.deleted).size, fake.accounts.size);
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
