/**
 * Mailinator public-inbox reader.
 *
 * The public domain's inbox API is unauthenticated, which is what makes an
 * unattended run possible: the harness picks an address, and can then read the
 * mail that actually arrived rather than asserting that it called a sender.
 *
 * Only ever use `@mailinator.com` addresses from this harness. Nothing here
 * should be able to send to a real person.
 */

// Both hosts serve the same unauthenticated public-inbox API and both return
// intermittent 500s; try them in turn rather than treating one 500 as failure.
const API_HOSTS = ["https://api.mailinator.com", "https://www.mailinator.com"];
const API_PATH = "/api/v2/domains/public";

/** A fresh, unique public inbox. `prefix` keeps our traffic identifiable. */
export function newInbox(prefix = "tcshare") {
  const id = `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  return { inbox: id, address: `${id}@mailinator.com` };
}

async function getJson(path) {
  let last;
  for (const host of API_HOSTS) {
    const url = `${host}${API_PATH}${path}`;
    try {
      const response = await fetch(url, { headers: { accept: "application/json", "user-agent": "Mozilla/5.0" } });
      if (response.ok) return response.json();
      last = new Error(`mailinator ${response.status} for ${url}`);
    } catch (error) {
      last = error;
    }
  }
  throw last;
}

/** Every message currently in `inbox`, newest first. */
export async function listMessages(inbox) {
  const body = await getJson(`/inboxes/${encodeURIComponent(inbox)}`);
  return body.msgs ?? [];
}

/** The full message, including parts, for a message id returned by `listMessages`. */
export async function fetchMessage(inbox, messageId) {
  return getJson(`/inboxes/${encodeURIComponent(inbox)}/messages/${encodeURIComponent(messageId)}`);
}

/** All text of a fetched message: subject plus every part body. */
export function messageText(message) {
  const parts = (message.parts ?? []).map((part) => part.body ?? "").join("\n");
  return `${message.subject ?? ""}\n${parts}`;
}

/**
 * Poll until a message satisfying `predicate(message, text)` lands, or the
 * deadline passes. Returns `{ message, text }`. `predicate` receives the fully
 * fetched message, so it can look at bodies, not just headers.
 */
export async function waitForMessage(inbox, predicate, { timeoutMs = 180_000, intervalMs = 5_000, log = () => {} } = {}) {
  const deadline = Date.now() + timeoutMs;
  const seen = new Set();
  while (Date.now() < deadline) {
    let messages = [];
    try {
      messages = await listMessages(inbox);
    } catch (error) {
      log(`[mailinator] list failed: ${error.message}`);
    }
    for (const summary of messages) {
      if (seen.has(summary.id)) continue;
      seen.add(summary.id);
      log(`[mailinator] from=${summary.from} subject=${JSON.stringify(summary.subject)}`);
      const message = await fetchMessage(inbox, summary.id).catch((error) => {
        log(`[mailinator] fetch ${summary.id} failed: ${error.message}`);
        return undefined;
      });
      if (message === undefined) continue;
      const text = messageText(message);
      if (predicate(message, text)) return { message, text };
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(`no matching mail arrived in ${inbox} within ${timeoutMs}ms`);
}

/** The first standalone six-digit group in a message — OpenKey's sign-in OTP. */
export function extractOtp(text) {
  const stripped = text.replace(/<[^>]+>/g, " ").replace(/&[a-z]+;/gi, " ");
  const match = stripped.match(/\b(\d{6})\b/);
  return match === null ? undefined : match[1];
}

/** Every https URL in a message body, de-duplicated, in order of appearance. */
export function extractUrls(text) {
  const decoded = text
    .replace(/=\r?\n/g, "")
    .replace(/=3D/g, "=")
    .replace(/&amp;/g, "&");
  const matches = decoded.match(/https:\/\/[^\s"'<>)\]]+/g) ?? [];
  return [...new Set(matches)];
}
