/**
 * `POST /share/v2` — send one authorized share invitation.
 *
 * Sibling of `@tinycloud/share-registry`: same account, same deploy path,
 * same "a signed contract, not a session, is the authority" model.
 *
 * NOTHING IS LOGGED. The share URL carries the decryption key in its
 * fragment, so it is a secret; the recipient address is PII; the Resend key
 * is a credential. There is no `console` call anywhere in this package, and a
 * test asserts that stays true. Callers learn what happened from the
 * response body, and operators from the `share_email_deliveries` table.
 */

import {
  digest,
  parseDeliveryRequest,
  refuse,
  verifyDeliveryAuthorization,
  type DeliveryTrust,
  type Refusal,
  type RefusalReason,
} from "./protocol.js";
import { renderInvitationEmail, type SenderTrust } from "./email.js";
import { sendViaResend } from "./resend.js";
import { finalizeDelivery, reserveDelivery, type D1DatabaseLike } from "./store.js";

export interface EmailEnv {
  /** D1 binding holding the idempotency ledger. */
  readonly DELIVERIES: D1DatabaseLike;
  /** Secret. */
  readonly RESEND_API_KEY?: string;
  /** `TinyCloud Share <invite@share.tinycloud.xyz>`. */
  readonly EMAIL_FROM?: string;
  /** The Node's enrolled invitation key id and raw base64url public key. */
  readonly NODE_INVITATION_KID?: string;
  readonly NODE_INVITATION_PUBLIC_KEY?: string;
  readonly NODE_ORIGIN?: string;
  /** The audience the Node stamps into `openCredentialsAudience`. */
  readonly DELIVERY_AUDIENCE?: string;
  readonly SHARE_ORIGIN?: string;
  /** Test seam only; production leaves this unset and uses api.resend.com. */
  readonly RESEND_ENDPOINT?: string;
}

const MAX_BODY_BYTES = 64 * 1024;

const STATUS: Record<RefusalReason, number> = {
  "configuration-unavailable": 503,
  malformed: 400,
  "share-url-invalid": 400,
  untrusted: 401,
  expired: 403,
  replayed: 409,
  "in-flight": 409,
  "store-unavailable": 503,
  "provider-unavailable": 502,
};

function cors(shareOrigin: string): Record<string, string> {
  return {
    "access-control-allow-origin": shareOrigin,
    "access-control-allow-methods": "POST,OPTIONS",
    "access-control-allow-headers": "content-type,accept",
    "access-control-max-age": "86400",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "referrer-policy": "no-referrer",
    vary: "Origin",
  };
}

/** CORS from whatever share origin is configured, or none if there isn't one. */
function corsFromEnv(env: EmailEnv): Record<string, string> {
  const shareOrigin = env.SHARE_ORIGIN;
  return typeof shareOrigin === "string" && shareOrigin.startsWith("https://") ? cors(shareOrigin) : {};
}

function json(status: number, body: unknown, headers: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...headers, "content-type": "application/json", "cache-control": "no-store" },
  });
}

/**
 * Every piece of configuration this Worker needs, or nothing. Absent or
 * malformed configuration is a refusal, never a default — in particular
 * there is no built-in node key, because production currently publishes a
 * development fixture as `nodeInvitationPublicKey` (TC-359/TC-369) and
 * baking any key in here would make that fixture permanently trusted.
 */
function configure(env: EmailEnv): { readonly trust: DeliveryTrust; readonly apiKey: string; readonly from: string } | Refusal {
  const {
    NODE_INVITATION_KID: kid,
    NODE_INVITATION_PUBLIC_KEY: publicKey,
    NODE_ORIGIN: nodeOrigin,
    DELIVERY_AUDIENCE: deliveryAudience,
    SHARE_ORIGIN: shareOrigin,
    RESEND_API_KEY: apiKey,
    EMAIL_FROM: from,
  } = env;
  if (
    typeof kid !== "string" || kid.length === 0 ||
    typeof publicKey !== "string" || publicKey.length === 0 ||
    typeof nodeOrigin !== "string" || nodeOrigin.length === 0 ||
    typeof deliveryAudience !== "string" || deliveryAudience.length === 0 ||
    typeof shareOrigin !== "string" || shareOrigin.length === 0 ||
    typeof apiKey !== "string" || apiKey.length === 0 ||
    typeof from !== "string" || from.length === 0 ||
    env.DELIVERIES === undefined || env.DELIVERIES === null
  ) {
    return refuse("configuration-unavailable");
  }
  return {
    trust: {
      nodeInvitationKid: kid,
      nodeInvitationPublicKey: publicKey,
      nodeOrigin,
      deliveryAudience,
      shareOrigin,
    },
    apiKey,
    from,
  };
}

/**
 * Reads at most `MAX_BODY_BYTES`, and stops reading the moment the bound is
 * crossed. This endpoint is reachable by anyone, so it must never buffer a
 * body it has not agreed to accept.
 */
async function readJsonBounded(request: Request): Promise<unknown | null> {
  const declared = request.headers.get("content-length");
  if (declared !== null && !(Number(declared) >= 0 && Number(declared) <= MAX_BODY_BYTES)) return null;
  const stream = request.body;
  if (stream === null) return null;
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value === undefined) continue;
    total += value.byteLength;
    if (total > MAX_BODY_BYTES) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(body)) as unknown;
  } catch {
    return null;
  }
}

async function deliver(request: Request, env: EmailEnv): Promise<Response> {
  const configured = configure(env);
  if ("ok" in configured) {
    // `SHARE_ORIGIN` may still be present even when a secret is not, and a
    // browser that cannot read the reason cannot report it.
    return json(STATUS[configured.reason], { error: configured.reason }, corsFromEnv(env));
  }
  const { trust, apiKey, from } = configured;
  const headers = cors(trust.shareOrigin);
  const deny = (reason: RefusalReason): Response => json(STATUS[reason], { error: reason }, headers);

  const origin = request.headers.get("origin");
  // Not a security boundary — a non-browser caller simply omits `Origin`.
  // The Node's signature is the boundary; this only keeps other websites
  // from driving the endpoint with a user's browser.
  if (origin !== null && origin !== trust.shareOrigin) {
    return json(403, { error: "origin-not-allowed" }, headers);
  }

  const body = await readJsonBounded(request);
  if (body === null) return deny("malformed");
  const parsed = parseDeliveryRequest(body);
  if (parsed === null) return deny("malformed");

  const now = Date.now();
  const verified = await verifyDeliveryAuthorization(parsed, trust, now);
  if (!verified.ok) return deny(verified.reason);

  const { authorization } = verified;
  const at = new Date(now).toISOString();
  const reserved = await reserveDelivery(env.DELIVERIES, {
    idempotencyKey: authorization.idempotencyKey,
    shareCid: authorization.shareCid,
    recipientDigest: await digest(authorization.deliveryEmail.toLowerCase()),
    at,
  });
  if (reserved.outcome === "unavailable") return deny("store-unavailable");
  if (reserved.outcome === "in-flight") return deny("in-flight");
  if (reserved.outcome === "replayed") return deny("replayed");
  if (reserved.outcome === "duplicate") {
    return json(
      200,
      {
        status: "duplicate",
        idempotencyKey: authorization.idempotencyKey,
        providerMessageId: reserved.providerMessageId,
      },
      headers,
    );
  }

  const message = renderInvitationEmail({
    magicUrl: authorization.shareUrl,
    documentName: authorization.documentName,
    senderTrust: authorization.senderTrust as SenderTrust,
    expiresAt: authorization.shareExpiresAt,
    reportAbuseUrl: `${trust.shareOrigin}/report?t=${encodeURIComponent(authorization.reportAbuseToken)}`,
  });

  const sent = await sendViaResend(
    {
      to: authorization.deliveryEmail,
      subject: message.subject,
      html: message.html,
      text: message.text,
      idempotencyKey: authorization.idempotencyKey,
    },
    {
      apiKey,
      from,
      ...(env.RESEND_ENDPOINT === undefined ? {} : { endpoint: env.RESEND_ENDPOINT }),
    },
  );

  await finalizeDelivery(env.DELIVERIES, {
    idempotencyKey: authorization.idempotencyKey,
    status: sent.ok ? "sent" : "failed",
    providerMessageId: sent.ok ? sent.providerMessageId : null,
    at: new Date().toISOString(),
  });
  if (!sent.ok) {
    // The provider's numeric status, and nothing else. `resend.ts` already
    // draws this line — the response BODY can echo the recipient address, the
    // status cannot. Without it a provider refusal is indistinguishable from
    // every other provider refusal: production answered a plain `502
    // provider-unavailable` for every send, the D1 ledger recorded `failed`
    // with a null message id, and there was no way to tell an unverified
    // sending domain (403) from a bad key (401) or a rate limit (429) short of
    // redeploying the Worker (TC-444).
    return json(
      STATUS["provider-unavailable"],
      { error: "provider-unavailable", providerStatus: sent.status },
      headers,
    );
  }

  return json(
    202,
    {
      status: "sent",
      idempotencyKey: authorization.idempotencyKey,
      providerMessageId: sent.providerMessageId,
    },
    headers,
  );
}

const worker = {
  async fetch(request: Request, env: EmailEnv): Promise<Response> {
    const url = new URL(request.url);
    const configured = configure(env);
    const headers = "ok" in configured ? corsFromEnv(env) : cors(configured.trust.shareOrigin);

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (request.method === "GET" && url.pathname === "/health/readiness") {
      // Presence only — never the values.
      return json(200, { ready: !("ok" in configured) }, headers);
    }
    if (request.method === "POST" && url.pathname === "/share/v2") return deliver(request, env);
    return json(404, { error: "not-found" }, headers);
  },
};

export default worker;
