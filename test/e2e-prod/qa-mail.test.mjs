import { test } from "node:test";
import assert from "node:assert/strict";

// A stand-in for the QA mail Worker's read API as Share's token sees it (no network): a bearer
// token, an exact `recipient` on every call, the first queued message for that recipient, and a
// delete only of that recipient's message.
process.env.QA_MAIL_ADDRESS_SECRET = "test-address-secret-of-at-least-32-chars";
process.env.QA_MAIL_READ_TOKEN = "test-read-token";
const worker = { queue: [], calls: [], status: 0 };
globalThis.fetch = async (input, { method = "GET", headers = {} } = {}) => {
  const url = new URL(input);
  const recipient = url.searchParams.get("recipient");
  worker.calls.push(`${method} ${url.pathname}`);
  if (headers.authorization !== "Bearer test-read-token") return new Response(null, { status: 401 });
  if (!recipient) return new Response(null, { status: 400 });
  if (worker.status) return new Response(null, { status: worker.status });
  if (method === "GET" && url.pathname === "/v1/messages/next") {
    const message = worker.queue.find((entry) => entry.recipient === recipient);
    return message ? new Response(message.raw, { headers: { "x-qa-mail-id": message.id } }) : new Response(null, { status: 204 });
  }
  const index = worker.queue.findIndex((entry) => method === "DELETE" && url.pathname === `/v1/messages/${entry.id}` && entry.recipient === recipient);
  if (index < 0) return new Response(null, { status: 404 });
  worker.queue.splice(index, 1);
  return new Response(null, { status: 204 });
};
const { createInbox, deleteInboxes, openKeyCode, readMail, seenMail, waitForMail } = await import("./qa-mail.mjs");

const id = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const mime = (lines) => Buffer.from(lines.join("\r\n"));
const openKeyMail = (code, minute) => mime([
  "Received: from a8-31.smtp-out.amazonses.com (54.240.8.31) by mx.cloudflare.net id 20261121",
  `Date: Sat, 21 Nov 2026 12:0${minute}:00 +0000`,
  "From: OpenKey <noreply@openkey.so>",
  "Subject: =?UTF-8?Q?Your_OpenKey_verification_code?=",
  "Content-Type: multipart/alternative;",
  ' boundary="part-1"',
  "",
  "--part-1",
  "Content-Type: text/plain; charset=utf-8",
  "Content-Transfer-Encoding: quoted-printable",
  "",
  `Your verification code is ${code} =E2=80=94 it expires in 10 minu=`,
  "tes.",
  "--part-1",
  "Content-Type: text/html; charset=utf-8",
  "Content-Transfer-Encoding: quoted-printable",
  "",
  `<p>Your verification code:</p><p style=3D"font-size:32px">${code}</p>`,
  "--part-1--",
  "",
]);

test("QA mail's own check accepts a new inbox's address", async () => {
  const { address } = createInbox("share-smoke");
  // The Worker's check (tinycloud-dev tools/qa-mail/worker/src/index.mjs, mintedRecipient).
  const match = /^tcqa\+([a-z0-9](?:[a-z0-9-]{0,22}[a-z0-9])?)-([a-f0-9]{12})-([a-f0-9]{8})@qa-mail\.tinycloud\.xyz$/.exec(address);
  assert.ok(match, "the address is not in QA mail's format");
  assert.equal(match[1], "share-smoke");
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", encoder.encode(process.env.QA_MAIL_ADDRESS_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(`tcqa+${match[1]}-${match[2]}`)));
  assert.equal(match[3], [...digest].slice(0, 4).map((value) => value.toString(16).padStart(2, "0")).join(""));
  assert.notEqual(createInbox("share-smoke").address, address, "two inboxes with one label share an address");
});

test("an inbox needs both secrets and a label Share's token can read", () => {
  assert.throws(() => createInbox("courier-smoke"), /must start with share-/);
  assert.throws(() => createInbox("share-a-label-that-is-too-long"), /must start with share-/);
  const token = process.env.QA_MAIL_READ_TOKEN;
  delete process.env.QA_MAIL_READ_TOKEN;
  try {
    assert.throws(() => createInbox("share-smoke"), /QA_MAIL_ADDRESS_SECRET and QA_MAIL_READ_TOKEN must be set/);
  } finally {
    process.env.QA_MAIL_READ_TOKEN = token;
  }
});

test("a raw message gives its decoded subject, its date and the text of its parts, never its header fields", () => {
  const openKey = readMail(openKeyMail("123456", 1));
  assert.equal(openKey.subject, "Your OpenKey verification code");
  assert.equal(openKey.createdAt, "2026-11-21T12:01:00.000Z");
  assert.match(openKey.text, /Your verification code is 123456 — it expires in 10 minutes\./);
  assert.match(openKey.text, /Your verification code:\s+123456/);
  assert.doesNotMatch(openKey.text, /20261121|amazonses/);

  // An HTML-only message in base64, as a single part.
  const share = readMail(mime([
    "Message-ID: <0100019a12345678-87654321@email.amazonses.com>",
    "Subject: =?utf-8?B?WW91ciBjb2RlIOKAlCBUaW55Q2xvdWQgU2hhcmU=?=",
    "Content-Type: text/html; charset=UTF-8",
    "Content-Transfer-Encoding: base64",
    "",
    Buffer.from("<html><body><p>Your code is</p><p><b>12345678</b></p><a href=\"https://share.tinycloud.xyz/?a=1&amp;b=2\">Share</a></body></html>").toString("base64").replace(/.{40}/g, "$&\r\n"),
  ]));
  assert.equal(share.subject, "Your code — TinyCloud Share");
  assert.deepEqual([...share.text.matchAll(/(?<!\d)\d{8}(?!\d)/g)].map((match) => match[0]), ["12345678"]);
  assert.doesNotMatch(share.text, /<|&amp;/);
});

test("waitForMail takes the newest unused matching mail, marks it used, and deletes what it read from QA mail", async () => {
  const inbox = createInbox("share-smoke");
  const other = { id: id(9), recipient: "tcqa+share-smoke-000000000000-00000000@qa-mail.tinycloud.xyz", raw: openKeyMail("999999", 9) };
  worker.queue.push(
    { id: id(1), recipient: inbox.address, raw: openKeyMail("111111", 1) },
    other,
    { id: id(2), recipient: inbox.address, raw: openKeyMail("222222", 2) },
    { id: id(3), recipient: inbox.address, raw: mime(["Subject: Something else", "", "verification code 333333"]) },
  );
  const used = new Set();
  assert.equal(await openKeyCode(inbox, { used, timeout: 1_000 }), "222222");
  assert.equal(await openKeyCode(inbox, { used, timeout: 1_000 }), "111111");
  await assert.rejects(openKeyCode(inbox, { used, timeout: 1 }), /no OpenKey code arrived/);
  assert.deepEqual(worker.queue, [other], "only this inbox's mail is deleted");
});

test("seenMail lists the mail already there, and fails closed when the inbox can't be read", async () => {
  const inbox = createInbox("share-enc-recipient");
  worker.queue.push({ id: id(11), recipient: inbox.address, raw: openKeyMail("111111", 1) });
  const earlier = await seenMail(inbox);
  assert.deepEqual([...earlier], [id(11)]);
  worker.queue.push({ id: id(12), recipient: inbox.address, raw: openKeyMail("222222", 2) });
  assert.equal(await openKeyCode(inbox, { used: earlier, timeout: 1_000 }), "222222", "a wait after seenMail takes only newer mail");
  worker.status = 500;
  try {
    await assert.rejects(seenMail(inbox), /could not be read/);
  } finally {
    worker.status = 0;
  }
});

test("an aborted wait for mail stops polling and takes nothing", async () => {
  const inbox = createInbox("share-smoke");
  worker.queue.push({ id: id(21), recipient: inbox.address, raw: openKeyMail("999999", 9) });
  const used = new Set();
  const stop = new AbortController();
  stop.abort(new Error("the wait for the code ended"));
  await assert.rejects(waitForMail(inbox, { extract: () => "x", used, timeout: 1_000, signal: stop.signal }), /the wait for the code ended/);
  assert.equal(used.size, 0, "an aborted wait marks no mail used");
  assert.equal(await openKeyCode(inbox, { used, timeout: 1_000 }), "999999", "the code is still there for the next wait");
});

// Last: deleteInboxes runs once per process.
test("deleteInboxes deletes the mail still queued for every inbox made here, and no one else's", async () => {
  const left = createInbox("share-enc-sender");
  worker.queue.push({ id: id(31), recipient: left.address, raw: openKeyMail("123456", 1) });
  const first = await deleteInboxes();
  assert.equal(first.deleted, first.total);
  assert.deepEqual(worker.queue.map((entry) => entry.id), [id(9)], "the unread mail was not deleted, or another recipient's was");
  assert.equal(await deleteInboxes(), first);
});

test("an inbox whose mail QA mail did not delete is reported as not deleted", async () => {
  // A fresh process (deleteInboxes runs once per process) whose QA mail answers 500.
  const { spawnSync } = await import("node:child_process");
  const script = `
    globalThis.fetch = async () => new Response(null, { status: 500 });
    const { createInbox, deleteInboxes } = await import(${JSON.stringify(new URL("./qa-mail.mjs", import.meta.url).href)});
    createInbox("share-smoke");
    console.log(JSON.stringify(await deleteInboxes()));`;
  const run = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  assert.deepEqual(JSON.parse(run.stdout), { deleted: 0, total: 1 });
});
