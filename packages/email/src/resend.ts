/**
 * The Resend transport.
 *
 * Mirrors `opencredentials::flow::resend_client` — same endpoint, same
 * `Idempotency-Key` header, same bounded response read, and the same rule
 * that the provider's response body is never surfaced: it can echo back
 * recipient PII, so only the numeric status ever leaves this module.
 */

const DEFAULT_ENDPOINT = "https://api.resend.com/emails";
const MAX_RESPONSE_BODY_BYTES = 16 * 1024;

export interface ResendMessage {
  readonly to: string;
  readonly subject: string;
  readonly html: string;
  readonly text: string;
  /** Sent as the provider's `Idempotency-Key`, so a retried POST cannot duplicate a send. */
  readonly idempotencyKey: string;
}

export interface ResendConfig {
  readonly apiKey: string;
  /** `TinyCloud Share <invite@share.tinycloud.xyz>`. Never caller-supplied. */
  readonly from: string;
  readonly endpoint?: string;
  readonly fetchFn?: typeof fetch;
}

export type ResendResult =
  | { readonly ok: true; readonly providerMessageId: string }
  | { readonly ok: false; readonly status: number | null };

export async function sendViaResend(
  message: ResendMessage,
  config: ResendConfig,
): Promise<ResendResult> {
  const fetchFn = config.fetchFn ?? fetch;
  let response: Response;
  try {
    response = await fetchFn(config.endpoint ?? DEFAULT_ENDPOINT, {
      method: "POST",
      // `manual`, not `error`. The intent is the same — never follow a redirect,
      // so a moved endpoint can never re-send the message somewhere else — but
      // the Workers runtime does not implement `error` and throws on the call:
      //
      //   TypeError: Invalid redirect value, must be one of "follow" or
      //   "manual" ("error" won't be implemented since it does not make sense
      //   at the edge; use "manual" and check the response status code).
      //
      // It throws *before any network I/O*, so this module returned
      // `{ok: false, status: null}` for every send and the Worker answered a
      // flat `502 provider-unavailable`. Every row in the D1 ledger was
      // `failed` with a null message id: this Worker had never delivered a
      // single message. `redirect: "error"` came over from
      // `opencredentials::flow::resend_client`, where reqwest's
      // `Policy::none()` means exactly this and is supported.
      //
      // With `manual` a 3xx arrives as an ordinary response and is refused by
      // the `!response.ok` check below, which is the behaviour `error` was
      // reached for.
      redirect: "manual",
      headers: {
        authorization: `Bearer ${config.apiKey}`,
        "content-type": "application/json",
        "idempotency-key": message.idempotencyKey,
      },
      body: JSON.stringify({
        from: config.from,
        to: [message.to],
        subject: message.subject,
        html: message.html,
        text: message.text,
      }),
    });
  } catch {
    return { ok: false, status: null };
  }
  if (!response.ok) return { ok: false, status: response.status };
  let parsed: unknown;
  try {
    const body = await response.text();
    if (body.length > MAX_RESPONSE_BODY_BYTES) return { ok: false, status: response.status };
    parsed = JSON.parse(body);
  } catch {
    return { ok: false, status: response.status };
  }
  const id = (parsed as { id?: unknown } | null)?.id;
  if (typeof id !== "string" || id.length === 0 || id.length > 256) {
    return { ok: false, status: response.status };
  }
  return { ok: true, providerMessageId: id };
}
