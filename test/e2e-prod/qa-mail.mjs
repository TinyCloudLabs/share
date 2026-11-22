// Private per-run test inboxes on TinyCloud's own QA mail (qa-mail.tinycloud.xyz) for the production smokes.
// An inbox is a signed address made in memory from QA_MAIL_ADDRESS_SECRET:
//   tcqa+<label>-<12 random hex>-<8 hex tag>@qa-mail.tinycloud.xyz
// QA mail keeps mail for such an address only when OpenKey or TinyCloud Share sent it, for one hour,
// and hands it out one message at a time to the holder of QA_MAIL_READ_TOKEN. Share's token reads
// only addresses whose label starts with `share-`, and only by exact address. A message is deleted
// from QA mail as soon as it is read; deleteInboxes() deletes whatever is still queued for every
// inbox made here, and deleteInboxesOnStop() also runs it on SIGINT/SIGTERM. Nothing here prints an
// address, a code, a message or the token.
import { createHmac, randomBytes } from "node:crypto";

export const QA_MAIL = "https://qa-mail.skgbafa.workers.dev";
const DOMAIN = "qa-mail.tinycloud.xyz";
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

/** Every inbox this process made; deleteInboxes() empties them all. */
const inboxes = [];

/** A new private inbox, `tcqa+<label>-<random>-<tag>@qa-mail.tinycloud.xyz`. `label` is `share-…`, 24 characters at most. */
export function createInbox(label) {
  const secret = process.env.QA_MAIL_ADDRESS_SECRET ?? "";
  if (secret.length < 32 || !process.env.QA_MAIL_READ_TOKEN) throw new Error("QA_MAIL_ADDRESS_SECRET and QA_MAIL_READ_TOKEN must be set");
  if (!/^share-[a-z0-9-]{0,17}[a-z0-9]$/.test(label)) throw new Error("a test inbox's label must start with share-");
  const stem = `tcqa+${label}-${randomBytes(6).toString("hex")}`;
  const inbox = { address: `${stem}-${createHmac("sha256", secret).update(stem).digest("hex").slice(0, 8)}@${DOMAIN}`, messages: [], deleted: new Set() };
  inboxes.push(inbox);
  return inbox;
}

/** One QA mail call for `inbox`: the next queued message, or the delete of message `id`. Resolves to the response, or undefined. */
function qaMail(inbox, id) {
  return fetch(`${QA_MAIL}/v1/messages/${id ?? "next"}?recipient=${encodeURIComponent(inbox.address)}`, {
    method: id ? "DELETE" : "GET",
    signal: AbortSignal.timeout(15_000),
    headers: { authorization: `Bearer ${process.env.QA_MAIL_READ_TOKEN}` },
  }).catch(() => undefined);
}

const decode = (bytes, charset = "utf-8") => { try { return new TextDecoder(charset).decode(bytes); } catch { return new TextDecoder().decode(bytes); } };
const quotedPrintable = (text) => Buffer.from(text.replace(/=\r?\n/g, "").replace(/=([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16))), "latin1");

/** A raw message or MIME part: its header fields (lower-case names, unfolded, the first of each) and its body bytes. */
function split(raw) {
  const end = /^\r?\n|\r?\n\r?\n/.exec(raw.toString("latin1"));
  const headers = new Map();
  for (const field of raw.toString("latin1", 0, end?.index).replace(/\r?\n[ \t]+/g, " ").split(/\r?\n/)) {
    const colon = field.indexOf(":");
    const name = field.slice(0, colon).trim().toLowerCase();
    if (colon > 0 && !headers.has(name)) headers.set(name, field.slice(colon + 1).trim());
  }
  return { headers, body: end ? raw.subarray(end.index + end[0].length) : Buffer.alloc(0) };
}

/** The text of a raw message or MIME part: its text parts, and its HTML parts with the tags removed. */
function textOf(raw, depth = 0) {
  const { headers, body } = split(raw);
  const type = headers.get("content-type") ?? "text/plain";
  const parameter = (name) => { const match = new RegExp(`;\\s*${name}\\s*=\\s*(?:"([^"]*)"|([^;\\s]*))`, "i").exec(type); return match?.[1] ?? match?.[2]; };
  if (/^multipart\//i.test(type)) {
    const boundary = parameter("boundary");
    if (!boundary || depth > 4) return "";
    const delimiter = new RegExp(`(?:^|\\r?\\n)--${boundary.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?:--)?[ \\t]*(?:\\r?\\n|$)`);
    // Before the first delimiter is the preamble, which is not a part.
    return body.toString("latin1").split(delimiter).slice(1).map((part) => textOf(Buffer.from(part, "latin1"), depth + 1)).join("\n");
  }
  if (!/^text\//i.test(type)) return "";
  const encoding = (headers.get("content-transfer-encoding") ?? "").toLowerCase();
  const bytes = encoding === "base64" ? Buffer.from(body.toString("latin1"), "base64") : encoding === "quoted-printable" ? quotedPrintable(body.toString("latin1")) : body;
  const text = decode(bytes, parameter("charset"));
  return /^text\/html/i.test(type) ? text.replace(/<[^>]+>/g, " ") : text;
}

/** A raw message as `{ subject, createdAt, text }`: the decoded Subject, the Date as ISO (now, if unreadable), and the text (&amp; decoded). */
export function readMail(raw) {
  const { headers } = split(raw);
  const subject = (headers.get("subject") ?? "").replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=(?:\s+(?==\?))?/gi, (_, charset, encoding, data) =>
    decode(encoding.toLowerCase() === "b" ? Buffer.from(data, "base64") : quotedPrintable(data.replaceAll("_", " ")), charset));
  const sent = Date.parse(headers.get("date") ?? "");
  return { subject, createdAt: new Date(Number.isNaN(sent) ? Date.now() : sent).toISOString(), text: textOf(raw).replaceAll("&amp;", "&") };
}

/**
 * Moves the mail queued for `inbox` into `inbox.messages`, deleting each message from QA mail once
 * read. True when QA mail has nothing more to give for now; false when a call failed.
 */
async function collect(inbox) {
  for (let read = 0; read < 20; read++) {
    const response = await qaMail(inbox);
    if (response?.status === 204) return true;
    const id = response?.status === 200 ? response.headers.get("x-qa-mail-id") ?? "" : "";
    if (!/^[0-9a-f-]{36}$/.test(id)) return false;
    // QA mail's list can lag a delete: a message deleted earlier is not there to read again.
    if (inbox.deleted.has(id)) return true;
    if (!inbox.messages.some((message) => message.id === id)) {
      const raw = await response.arrayBuffer().catch(() => undefined);
      if (raw === undefined) return false;
      inbox.messages.push({ id, ...readMail(Buffer.from(raw)) });
    }
    const gone = await qaMail(inbox, id);
    // 404: already gone.
    if (gone?.status !== 204 && gone?.status !== 404) return false;
    inbox.deleted.add(id);
  }
  return false;
}

/**
 * Polls `inbox` until a message not in `used`, whose subject matches `subject`, yields a value from
 * `extract(text, message)`; marks it used and returns the value. Failed polls are retried until the
 * deadline. `onMessage(message, value)` sees each message tried. An aborted `signal` stops the
 * polling (rejects with its reason) and marks nothing used.
 */
export async function waitForMail(inbox, { subject = /./, extract, used = new Set(), timeout = 150_000, onMessage, signal, failure = "the expected mail did not arrive in the test inbox" }) {
  const deadline = Date.now() + timeout;
  const stopped = () => { if (signal?.aborted) throw signal.reason ?? new Error("stopped"); };
  while (Date.now() < deadline) {
    stopped();
    await collect(inbox);
    const fresh = inbox.messages.filter((entry) => subject.test(entry.subject) && !used.has(entry.id))
      .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
    for (const message of fresh) {
      const value = extract(message.text, message);
      onMessage?.(message, value);
      if (value !== undefined) { stopped(); used.add(message.id); return value; }
    }
    await sleep(Math.min(5_000, Math.max(0, deadline - Date.now())));
    stopped();
  }
  throw new Error(failure);
}

/** The ids of the messages already in `inbox` (so a later wait takes only newer mail). Throws if the inbox can't be read. */
export async function seenMail(inbox) {
  if (!(await collect(inbox))) throw new Error("the test inbox could not be read");
  return new Set(inbox.messages.map((entry) => entry.id));
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
/** Deletes the mail still queued for every inbox made here (once; later calls share the result): `{ deleted, total }` counts inboxes. */
export function deleteInboxes() {
  deleting ??= (async () => {
    let deleted = 0;
    for (const inbox of inboxes) if (await collect(inbox)) deleted++;
    return { deleted, total: inboxes.length };
  })();
  return deleting;
}

let stopping = false;
/**
 * On SIGINT/SIGTERM (a stopped run skips `finally`): runs `before` (synchronous), deletes the
 * inboxes' mail, runs `after(result)` (synchronous), then exits 130/143.
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
