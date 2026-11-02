// Private per-run test inboxes (mail.tm) for the production smokes and the recipient gate.
// Each inbox has "qa" in its name and a random password held in memory; every inbox a process
// made or adopted is deleted by deleteInboxes(), which deleteInboxesOnStop() also runs on
// SIGINT/SIGTERM. Nothing here prints an address, password, link or code.
//
// The recipient gate's inbox is made before the sender mails the invitation, so it lives in a
// 0600 file under /var/tmp (address and password only; private-file.mjs's checks):
//   node test/e2e-prod/mail-tm.mjs create /var/tmp/<dir>/inbox.json   # a new inbox and its file
//   node test/e2e-prod/mail-tm.mjs delete /var/tmp/<dir>/inbox.json   # the inbox, then the file
import { randomBytes } from "node:crypto";
import { closeSync, lstatSync, readFileSync, unlinkSync, writeSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { openPrivateFile, recheckDirectory, varTmpPath } from "./private-file.mjs";

export const MAIL_TM = "https://api.mail.tm";
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

/** One mail.tm call; retries a timeout, a transport error, 429 and 5xx. Resolves to the last response, or undefined. */
export async function mailTm(path, { method = "GET", body, token, attempts = 4 } = {}) {
  let response;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    response = await fetch(`${MAIL_TM}${path}`, {
      method,
      signal: AbortSignal.timeout(15_000),
      headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    }).catch(() => undefined);
    if (response && response.status !== 429 && response.status < 500) return response;
    if (attempt < attempts) await sleep(3_000 * attempt);
  }
  return response;
}

/** A mail.tm call's JSON, or undefined (a refused, failed or non-JSON reply). */
export async function mailTmJson(path, options) {
  const response = await mailTm(path, options);
  if (!response?.ok) return undefined;
  return response.json().catch(() => undefined);
}

// A 401 means mail.tm refuses the address and password: an inbox deleted earlier answers so, but so
// would a wrong password. An inbox made in this process (it has an id) is never taken as gone; it
// just gets no token. An adopted inbox (an inbox file's) is gone only after two consecutive 401s.
async function inboxToken(inbox) {
  let refusals = 0;
  for (let attempt = 1; attempt <= 4 && !inbox.token && !inbox.gone; attempt++) {
    const response = await mailTm("/token", { method: "POST", body: { address: inbox.address, password: inbox.password } });
    if (response?.status === 401) {
      if (inbox.id) break;
      if (++refusals >= 2) { inbox.gone = true; break; }
    } else {
      refusals = 0;
      inbox.token = (response?.ok ? (await response.json().catch(() => undefined))?.token : undefined) ?? "";
    }
    if (!inbox.token && attempt < 4) await sleep(3_000 * attempt);
  }
  return inbox.token;
}

/** Every inbox this process made or adopted; deleteInboxes() deletes them all. */
const inboxes = [];

/** A new private inbox, `qa-<label>-<random>@<a mail.tm domain>`. */
export async function createInbox(label) {
  const domains = await mailTmJson("/domains");
  const domain = (domains?.["hydra:member"] ?? []).find((entry) => entry.isActive)?.domain;
  if (!domain) throw new Error("mail.tm offered no active domain");
  const inbox = { address: `qa-${label}-${randomBytes(6).toString("hex")}@${domain}`, password: randomBytes(18).toString("base64url"), id: "", token: "" };
  inboxes.push(inbox);
  const created = await mailTm("/accounts", { method: "POST", body: { address: inbox.address, password: inbox.password } });
  if (created?.status === 201) inbox.id = (await created.json().catch(() => ({}))).id ?? "";
  // A retried create whose first reply was lost answers 422 (the address exists): it is still ours, with our password.
  else if (created?.status !== 422) throw new Error(`mail.tm refused the inbox (HTTP ${created?.status ?? "no reply"})`);
  if (!(await inboxToken(inbox))) throw new Error("mail.tm gave no inbox token");
  if (!inbox.id) inbox.id = (await mailTmJson("/me", { token: inbox.token }))?.id ?? "";
  if (!inbox.id) throw new Error("mail.tm did not say which inbox was created");
  return inbox;
}

/** An inbox made earlier (an inbox file's address and password); it is deleted with the others. */
export function adoptInbox({ address, password }) {
  if (typeof address !== "string" || !/^qa-[\w-]+@[\w.-]+$/.test(address) || typeof password !== "string" || password === "") {
    throw new Error("not a test inbox");
  }
  const inbox = { address, password, id: "", token: "" };
  inboxes.push(inbox);
  return inbox;
}

/** A message's text and its HTML as text (tags removed, &amp; decoded), or undefined if unreadable. */
async function messageText(inbox, id) {
  const full = await mailTmJson(`/messages/${id}`, { token: inbox.token, attempts: 2 });
  if (!full) return undefined;
  return `${full.text ?? ""}\n${[].concat(full.html ?? []).join(" ").replace(/<[^>]+>/g, " ")}`.replaceAll("&amp;", "&");
}

/**
 * Polls `inbox` until a message not in `used`, whose subject matches `subject`, yields a value from
 * `extract(text, message)`; marks it used and returns the value. Failed or unreadable polls are
 * retried until the deadline. `onMessage(message, value)` sees each message read.
 */
export async function waitForMail(inbox, { subject = /./, extract, used = new Set(), timeout = 150_000, onMessage, failure = "the expected mail did not arrive in the test inbox" }) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (inbox.token || await inboxToken(inbox)) {
      const list = await mailTmJson("/messages", { token: inbox.token, attempts: 2 });
      const fresh = (list?.["hydra:member"] ?? []).filter((entry) => subject.test(entry.subject ?? "") && !used.has(entry.id))
        .sort((a, b) => Date.parse(b.createdAt ?? 0) - Date.parse(a.createdAt ?? 0));
      for (const message of fresh) {
        const text = await messageText(inbox, message.id);
        if (text === undefined) continue;
        const value = extract(text, message);
        onMessage?.(message, value);
        if (value !== undefined) { used.add(message.id); return value; }
      }
    }
    await sleep(4_000);
  }
  throw new Error(failure);
}

/** The ids of the messages already in `inbox` (so a later wait takes only newer mail). Throws if the list can't be read. */
export async function seenMail(inbox) {
  if (!inbox.token) await inboxToken(inbox);
  const list = inbox.token ? await mailTmJson("/messages", { token: inbox.token, attempts: 2 }) : undefined;
  if (!Array.isArray(list?.["hydra:member"])) throw new Error("the test inbox could not be read");
  return new Set(list["hydra:member"].map((entry) => entry.id));
}

/** The single six-digit code in an OpenKey code mail (the mail repeats it; another six-digit run is not it). */
export function openKeyCodeIn(text) {
  const codes = new Set([...text.matchAll(/verification code[^0-9]{0,80}(\d{6})(?!\d)/gi)].map((match) => match[1]));
  return codes.size === 1 ? [...codes][0] : undefined;
}

/** The next OpenKey sign-in code mailed to `inbox`. */
export const openKeyCode = (inbox, options = {}) =>
  waitForMail(inbox, { subject: /openkey/i, extract: openKeyCodeIn, failure: "no OpenKey code arrived in the test inbox", ...options });

let deleting;
/** Deletes every inbox made or adopted here (once; later calls share the result): `{ deleted, total }`. */
export function deleteInboxes() {
  deleting ??= (async () => {
    let deleted = 0;
    for (const inbox of inboxes) {
      try {
        if (!inbox.token) await inboxToken(inbox);
        if (inbox.gone) { deleted++; continue; }
        if (!inbox.id && inbox.token) inbox.id = (await mailTmJson("/me", { token: inbox.token }))?.id ?? "";
        const response = inbox.id && inbox.token ? await mailTm(`/accounts/${inbox.id}`, { method: "DELETE", token: inbox.token }) : undefined;
        // 404: already gone.
        if (response?.status === 204 || response?.status === 404) deleted++;
      } catch {}
    }
    return { deleted, total: inboxes.length };
  })();
  return deleting;
}

let stopping = false;
/**
 * On SIGINT/SIGTERM (a stopped run skips `finally`): runs `before` (synchronous), deletes the
 * inboxes, runs `after(result)` (synchronous), then exits 130/143.
 */
export function deleteInboxesOnStop({ before, after } = {}) {
  for (const signal of ["SIGTERM", "SIGINT"]) {
    process.once(signal, () => {
      if (stopping) return;
      stopping = true;
      try { before?.(); } catch {}
      void deleteInboxes().then((result) => { try { after?.(result); } catch {} }).finally(() => process.exit(signal === "SIGINT" ? 130 : 143));
    });
  }
}

const FILE = "TC500_E2E_RECIPIENT_INBOX";

/** Writes a new 0600 inbox file (address and password only) at a /var/tmp path. */
export function writeInboxFile(path, inbox) {
  const fd = openPrivateFile(varTmpPath(path, FILE), FILE, "create");
  try { writeSync(fd, `${JSON.stringify({ address: inbox.address, password: inbox.password })}\n`); } finally { closeSync(fd); }
}

/** Reads an inbox file (0600, under /var/tmp) and adopts its inbox. */
export function readInboxFile(path) {
  const fd = openPrivateFile(varTmpPath(path, FILE), FILE, "read");
  let parsed;
  try { parsed = JSON.parse(readFileSync(fd, "utf8")); } catch { parsed = undefined; } finally { closeSync(fd); }
  if (parsed === null || typeof parsed !== "object" || Object.keys(parsed).sort().join() !== "address,password") throw new Error(`${FILE} is not an inbox file`);
  return adoptInbox(parsed);
}

/** Removes an inbox file (after its inbox is deleted). */
export function removeInboxFile(path) {
  const checked = varTmpPath(path, FILE);
  closeSync(openPrivateFile(checked, FILE, "read"));
  recheckDirectory(checked, FILE);
  unlinkSync(checked);
}

// The recipient gate's operator steps: `create <file>` before the sender step, `delete <file>` if
// the gate did not run (the gate deletes the inbox and the file itself). Prints no address.
if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [command, path] = process.argv.slice(2);
  let result;
  try {
    if (command === "create" && path) {
      // Refused again by the exclusive create; checked first so no inbox is made for nothing.
      if (lstatSync(varTmpPath(path, FILE), { throwIfNoEntry: false }) !== undefined) throw new Error(`${FILE} already exists; it must be a new file`);
      deleteInboxesOnStop();
      const inbox = await createInbox("recipient-gate");
      try { writeInboxFile(path, inbox); } catch (error) { await deleteInboxes(); throw error; }
      result = { created: true };
    } else if (command === "delete" && path) {
      readInboxFile(path);
      const { deleted, total } = await deleteInboxes();
      if (deleted === total) removeInboxFile(path);
      result = { inboxDeleted: deleted === total, fileRemoved: deleted === total };
    } else {
      result = { error: "usage: node test/e2e-prod/mail-tm.mjs create|delete /var/tmp/<dir>/<file>" };
    }
  } catch (error) {
    result = { error: String(error?.message ?? error).replace(/[\w.+-]+@[\w.-]+/g, "<email>").slice(0, 200) };
  }
  console.log(JSON.stringify(result));
  process.exit(result.error || result.inboxDeleted === false ? 1 : 0);
}
