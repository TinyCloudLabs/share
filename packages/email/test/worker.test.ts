import { ed25519 } from "@noble/curves/ed25519";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { canonicalize } from "@tinycloud/share-envelope";
import { DELIVERY_AUTHORIZATION_DOMAIN } from "../src/protocol.js";
import { renderInvitationEmail } from "../src/email.js";
import type { D1DatabaseLike, D1PreparedStatementLike } from "../src/store.js";
import worker, { type EmailEnv } from "../src/worker.js";

const SHARE_ORIGIN = "https://share.tinycloud.xyz";
const NODE_ORIGIN = "https://node.tinycloud.xyz";
const NODE_AUDIENCE = "did:web:node.tinycloud.xyz";
const KID = `${NODE_AUDIENCE}#invitation-key-1`;
const AUDIENCE = "https://witness.credentials.org";
const RESEND_ENDPOINT = "https://resend.test/emails";
const CID = "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4";
const KEY_FRAGMENT = `${"A".repeat(42)}E`;
const SHARE_URL = `${SHARE_ORIGIN}/s/${CID}#k=${KEY_FRAGMENT}`;
const RECIPIENT = "recipient@example.com";

const nodePrivateKey = new Uint8Array(32).fill(11);
const nodePublicKey = ed25519.getPublicKey(nodePrivateKey);
const otherPrivateKey = new Uint8Array(32).fill(12);

const b64 = (value: Uint8Array): string => Buffer.from(value).toString("base64url");

function authorizationBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Date.now();
  return {
    type: "TinyCloudShareDeliveryAuthorization",
    version: 2,
    jti: b64(new Uint8Array(16).fill(3)),
    shareCid: CID,
    shareId: "share-1",
    registrationCid: "bafkreigistration",
    delegationCid: "bafkreidelegation",
    enforcementDelegationCid: "bafkreienforcement",
    envelopeCid: "bafkreienvelope",
    policyCid: "bafkreipolicy",
    nodeAudience: NODE_AUDIENCE,
    targetOrigin: NODE_ORIGIN,
    openCredentialsAudience: AUDIENCE,
    holder: "did:key:z6MkHolder",
    recipientMatcher: { kind: "exactEmail", value: RECIPIENT },
    deliveryEmail: RECIPIENT,
    shareUrl: SHARE_URL,
    returnOrigin: SHARE_ORIGIN,
    documentName: "Quarterly report.pdf",
    senderDid: "did:key:z6MkSender",
    senderTrust: "verified",
    contentSource: { kind: "kv", spaceId: "tinycloud:pkh:eip155:1:0xabc:default", path: "reports/q3" },
    contentSourceDigest: b64(new Uint8Array(32).fill(9)),
    shareExpiresAt: new Date(now + 7 * 24 * 60 * 60 * 1000).toISOString(),
    issuedAt: new Date(now).toISOString(),
    reportAbuseToken: b64(new Uint8Array(16).fill(3)),
    actions: ["read"],
    resource: "reports/q3",
    authorityMaterialHandle: "bafkreigistration",
    authorityMaterialDigest: b64(new Uint8Array(32).fill(8)),
    requestBodyDigest: b64(new Uint8Array(32).fill(7)),
    idempotencyKey: b64(new Uint8Array(16).fill(3)),
    expiresAt: new Date(now + 4 * 60 * 1000).toISOString(),
    dataAuthority: false,
    ...overrides,
  };
}

function sign(
  body: Record<string, unknown>,
  privateKey: Uint8Array = nodePrivateKey,
  kid: string = KID,
): { authorization: Record<string, unknown>; proof: Record<string, unknown>; shareUrl: string } {
  const message = new TextEncoder().encode(`${DELIVERY_AUTHORIZATION_DOMAIN}${canonicalize(body)}`);
  return {
    authorization: body,
    proof: { alg: "EdDSA", kid, signature: b64(ed25519.sign(message, privateKey)) },
    shareUrl: String(body.shareUrl),
  };
}

interface Row {
  idempotency_key: string;
  share_cid: string;
  recipient_digest: string;
  status: string;
  provider_message_id: string | null;
  created_at: string;
  updated_at: string;
}

/** In-memory stand-in with the same atomic insert-or-conflict semantics as D1. */
function database(options: { failing?: boolean } = {}): D1DatabaseLike & { rows: Map<string, Row> } {
  const rows = new Map<string, Row>();
  const statement = (query: string): D1PreparedStatementLike => {
    let args: unknown[] = [];
    const self: D1PreparedStatementLike = {
      bind(...values: unknown[]) {
        args = values;
        return self;
      },
      async first<T = Record<string, unknown>>(): Promise<T | null> {
        if (options.failing === true) throw new Error("D1_ERROR");
        if (query.startsWith("INSERT")) {
          const key = String(args[0]);
          if (rows.has(key)) return null;
          rows.set(key, {
            idempotency_key: key,
            share_cid: String(args[1]),
            recipient_digest: String(args[2]),
            status: "pending",
            provider_message_id: null,
            created_at: String(args[3]),
            updated_at: String(args[3]),
          });
          return { idempotency_key: key } as T;
        }
        const existing = rows.get(String(args[0]));
        return existing === undefined ? null : (existing as unknown as T);
      },
      async run() {
        if (options.failing === true) throw new Error("D1_ERROR");
        const existing = rows.get(String(args[0]));
        if (existing !== undefined && existing.status === "pending") {
          existing.status = String(args[1]);
          existing.provider_message_id = args[2] === null ? null : String(args[2]);
          existing.updated_at = String(args[3]);
        }
        return undefined;
      },
    };
    return self;
  };
  return { rows, prepare: statement };
}

function env(overrides: Partial<EmailEnv> = {}): EmailEnv & { DELIVERIES: ReturnType<typeof database> } {
  return {
    DELIVERIES: database(),
    RESEND_API_KEY: "re_test_key",
    EMAIL_FROM: "TinyCloud Share <invite@share.tinycloud.xyz>",
    NODE_INVITATION_KID: KID,
    NODE_INVITATION_PUBLIC_KEY: b64(nodePublicKey),
    NODE_ORIGIN,
    DELIVERY_AUDIENCE: AUDIENCE,
    SHARE_ORIGIN,
    RESEND_ENDPOINT,
    ...overrides,
  } as EmailEnv & { DELIVERIES: ReturnType<typeof database> };
}

function post(payload: unknown, origin: string | null = SHARE_ORIGIN): Request {
  return new Request(`${SHARE_ORIGIN.replace("share", "email")}/share/v2`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(origin === null ? {} : { origin }),
    },
    body: JSON.stringify(payload),
  });
}

let provider: ReturnType<typeof vi.fn>;

beforeEach(() => {
  provider = vi.fn(async () => new Response(JSON.stringify({ id: "msg_live_1" }), { status: 200 }));
  vi.stubGlobal("fetch", provider);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("authorized delivery", () => {
  it("sends exactly one invitation for a Node-signed authorization", async () => {
    const environment = env();
    const response = await worker.fetch(post(sign(authorizationBody())), environment);
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({
      status: "sent",
      idempotencyKey: b64(new Uint8Array(16).fill(3)),
      providerMessageId: "msg_live_1",
    });
    expect(provider).toHaveBeenCalledTimes(1);

    const [endpoint, init] = provider.mock.calls[0] as [string, RequestInit];
    expect(endpoint).toBe(RESEND_ENDPOINT);
    const headers = init.headers as Record<string, string>;
    expect(headers.authorization).toBe("Bearer re_test_key");
    expect(headers["idempotency-key"]).toBe(b64(new Uint8Array(16).fill(3)));
    const sent = JSON.parse(String(init.body)) as Record<string, unknown>;
    expect(sent.to).toEqual([RECIPIENT]);
    expect(sent.from).toBe("TinyCloud Share <invite@share.tinycloud.xyz>");
    expect(sent.subject).toBe("Quarterly report.pdf was shared with you");
    expect(String(sent.html)).toContain(SHARE_URL);
    expect(String(sent.text)).toContain(SHARE_URL);
  });

  it("refuses to send the same authorization twice and reports the first result", async () => {
    const environment = env();
    const payload = sign(authorizationBody());
    expect((await worker.fetch(post(payload), environment)).status).toBe(202);

    const replayed = await worker.fetch(post(payload), environment);
    expect(replayed.status).toBe(200);
    expect(await replayed.json()).toEqual({
      status: "duplicate",
      idempotencyKey: b64(new Uint8Array(16).fill(3)),
      providerMessageId: "msg_live_1",
    });
    expect(provider).toHaveBeenCalledTimes(1);
  });

  it("refuses a replay after a provider failure rather than risking a duplicate", async () => {
    const environment = env();
    provider.mockResolvedValueOnce(new Response("{}", { status: 429 }));
    const payload = sign(authorizationBody());

    const failed = await worker.fetch(post(payload), environment);
    expect(failed.status).toBe(502);
    // The provider's numeric status is surfaced, and only the status — never
    // its body, which can echo the recipient address. Without it every provider
    // refusal is indistinguishable from outside the Worker, which is what made
    // an unverified Resend sending domain look like an unexplained 502.
    expect(await failed.json()).toEqual({ error: "provider-unavailable", providerStatus: 429 });
    expect([...environment.DELIVERIES.rows.values()][0]?.status).toBe("failed");

    const retried = await worker.fetch(post(payload), environment);
    expect(retried.status).toBe(409);
    expect(await retried.json()).toEqual({ error: "replayed" });
    expect(provider).toHaveBeenCalledTimes(1);
  });
});

describe("fail closed", () => {
  it("refuses when the trusted node key, audience, sender, or provider key is unset", async () => {
    for (const key of [
      "NODE_INVITATION_KID",
      "NODE_INVITATION_PUBLIC_KEY",
      "NODE_ORIGIN",
      "DELIVERY_AUDIENCE",
      "SHARE_ORIGIN",
      "RESEND_API_KEY",
      "EMAIL_FROM",
    ] as const) {
      const environment = env();
      delete (environment as unknown as Record<string, unknown>)[key];
      const response = await worker.fetch(post(sign(authorizationBody())), environment);
      expect(response.status, key).toBe(503);
      expect(await response.json()).toEqual({ error: "configuration-unavailable" });
    }
    expect(provider).not.toHaveBeenCalled();
  });

  it("never falls back to accepting an unverifiable authorization", async () => {
    // Signed by a key that is not the enrolled one.
    const wrongKey = await worker.fetch(
      post(sign(authorizationBody(), otherPrivateKey)),
      env(),
    );
    expect(wrongKey.status).toBe(401);
    expect(await wrongKey.json()).toEqual({ error: "untrusted" });

    // Correctly signed, but presented under a different key id.
    const wrongKid = await worker.fetch(
      post(sign(authorizationBody(), nodePrivateKey, `${NODE_AUDIENCE}#invitation-key-2`)),
      env(),
    );
    expect(wrongKid.status).toBe(401);

    // Signed, then tampered with: the recipient is swapped after signing.
    const tampered = sign(authorizationBody());
    tampered.authorization.deliveryEmail = "attacker@example.com";
    expect((await worker.fetch(post(tampered), env())).status).toBe(401);

    // No proof at all.
    const unsigned = await worker.fetch(
      post({ authorization: authorizationBody(), shareUrl: SHARE_URL }),
      env(),
    );
    expect(unsigned.status).toBe(400);

    expect(provider).not.toHaveBeenCalled();
  });

  it("pins all three audiences independently", async () => {
    for (const overrides of [
      { openCredentialsAudience: "https://attacker.example" },
      { openCredentialsAudience: NODE_AUDIENCE },
      { returnOrigin: "https://attacker.example" },
      { targetOrigin: "https://attacker.example" },
      { nodeAudience: "did:web:attacker.example" },
    ]) {
      const response = await worker.fetch(post(sign(authorizationBody(overrides))), env());
      expect(response.status, JSON.stringify(overrides)).toBe(401);
      expect(await response.json()).toEqual({ error: "untrusted" });
    }
    expect(provider).not.toHaveBeenCalled();
  });

  it("refuses an expired or over-long-lived authorization", async () => {
    const expired = await worker.fetch(
      post(sign(authorizationBody({ expiresAt: new Date(Date.now() - 1_000).toISOString() }))),
      env(),
    );
    expect(expired.status).toBe(403);
    expect(await expired.json()).toEqual({ error: "expired" });

    const tooLong = await worker.fetch(
      post(sign(authorizationBody({ expiresAt: new Date(Date.now() + 10 * 60_000).toISOString() }))),
      env(),
    );
    expect(tooLong.status).toBe(403);

    const shareAlreadyOver = await worker.fetch(
      post(sign(authorizationBody({ shareExpiresAt: new Date(Date.now() - 1_000).toISOString() }))),
      env(),
    );
    expect(shareAlreadyOver.status).toBe(403);

    expect(provider).not.toHaveBeenCalled();
  });

  it("refuses any share URL that is not the exact canonical share-origin shape", async () => {
    for (const shareUrl of [
      `https://attacker.example/s/${CID}#k=${KEY_FRAGMENT}`,
      `http://share.tinycloud.xyz/s/${CID}#k=${KEY_FRAGMENT}`,
      `${SHARE_ORIGIN}/s/${CID}`,
      `${SHARE_ORIGIN}/s/${CID}#v=2&p=AAAA`,
      `${SHARE_ORIGIN}/s/${CID}#k=${KEY_FRAGMENT}&x=1`,
      `${SHARE_ORIGIN}/s/not-a-cid#k=${KEY_FRAGMENT}`,
    ]) {
      const response = await worker.fetch(post(sign(authorizationBody({ shareUrl }))), env());
      expect(response.status, shareUrl).toBe(400);
      expect(await response.json()).toEqual({ error: "share-url-invalid" });
    }
    expect(provider).not.toHaveBeenCalled();
  });

  it("refuses a delivered URL that differs from the signed one", async () => {
    const payload = sign(authorizationBody());
    const response = await worker.fetch(
      post({ ...payload, shareUrl: `${SHARE_ORIGIN}/s/${CID}#k=${"B".repeat(42)}E` }),
      env(),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "malformed" });
    expect(provider).not.toHaveBeenCalled();
  });

  it("refuses a recipient the share's own matcher does not admit", async () => {
    for (const overrides of [
      { recipientMatcher: { kind: "exactEmail", value: "someone-else@example.com" } },
      { recipientMatcher: { kind: "emailDomain", value: "other.example" } },
      { recipientMatcher: { kind: "bearer" } },
      { deliveryEmail: "not-an-email" },
    ]) {
      const response = await worker.fetch(post(sign(authorizationBody(overrides))), env());
      expect(response.status, JSON.stringify(overrides)).toBe(400);
      expect(await response.json()).toEqual({ error: "malformed" });
    }
    expect(provider).not.toHaveBeenCalled();
  });

  it("refuses an authorization with unexpected or missing fields", async () => {
    const extra = authorizationBody();
    extra.somethingElse = true;
    expect((await worker.fetch(post(sign(extra)), env())).status).toBe(400);

    const missing = authorizationBody();
    delete missing.holder;
    expect((await worker.fetch(post(sign(missing)), env())).status).toBe(400);

    const claimsAuthority = await worker.fetch(
      post(sign(authorizationBody({ dataAuthority: true }))),
      env(),
    );
    expect(claimsAuthority.status).toBe(401);

    expect(provider).not.toHaveBeenCalled();
  });

  it("refuses to send when the idempotency ledger is unavailable", async () => {
    const environment = env({ DELIVERIES: database({ failing: true }) });
    const response = await worker.fetch(post(sign(authorizationBody())), environment);
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "store-unavailable" });
    expect(provider).not.toHaveBeenCalled();
  });

  it("refuses an oversized body, declared or streamed", async () => {
    const declared = await worker.fetch(
      new Request("https://email.tinycloud.xyz/share/v2", {
        method: "POST",
        headers: { origin: SHARE_ORIGIN, "content-type": "application/json", "content-length": "9999999" },
        body: "{}",
      }),
      env(),
    );
    expect(declared.status).toBe(400);

    const streamed = await worker.fetch(
      new Request("https://email.tinycloud.xyz/share/v2", {
        method: "POST",
        headers: { origin: SHARE_ORIGIN, "content-type": "application/json" },
        body: new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new Uint8Array(64 * 1024 + 1));
            controller.close();
          },
        }),
        // undici requires duplex for a streaming request body.
        duplex: "half",
      } as RequestInit),
      env(),
    );
    expect(streamed.status).toBe(400);
    expect(provider).not.toHaveBeenCalled();
  });

  it("refuses browser calls from any other origin, and unknown routes", async () => {
    const foreign = await worker.fetch(post(sign(authorizationBody()), "https://evil.example"), env());
    expect(foreign.status).toBe(403);
    expect(await foreign.json()).toEqual({ error: "origin-not-allowed" });

    const unknown = await worker.fetch(new Request("https://email.tinycloud.xyz/anything"), env());
    expect(unknown.status).toBe(404);
    expect(provider).not.toHaveBeenCalled();
  });
});

describe("secrets and PII", () => {
  it("never writes the share URL, key fragment, or address to storage or a response", async () => {
    const environment = env();
    const response = await worker.fetch(post(sign(authorizationBody())), environment);
    const body = await response.text();
    const stored = JSON.stringify([...environment.DELIVERIES.rows.values()]);
    for (const secret of [SHARE_URL, KEY_FRAGMENT, RECIPIENT, "re_test_key"]) {
      expect(body).not.toContain(secret);
      expect(stored).not.toContain(secret);
    }
    expect(stored).toContain(CID);
  });

  it("emits no log line at all, on success or refusal", async () => {
    const spies = (["log", "info", "warn", "error", "debug", "trace"] as const).map((method) =>
      vi.spyOn(console, method).mockImplementation(() => undefined),
    );
    await worker.fetch(post(sign(authorizationBody())), env());
    await worker.fetch(post(sign(authorizationBody(), otherPrivateKey)), env());
    await worker.fetch(post(sign(authorizationBody())), env({ DELIVERIES: database({ failing: true }) }));
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
  });

  it("declares no cache and a no-referrer policy so intermediaries keep nothing", async () => {
    const response = await worker.fetch(post(sign(authorizationBody())), env());
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    expect(response.headers.get("access-control-allow-origin")).toBe(SHARE_ORIGIN);
  });
});

describe("invitation rendering", () => {
  it("escapes every interpolated value and links only the share and abuse URLs", () => {
    const rendered = renderInvitationEmail({
      magicUrl: SHARE_URL,
      documentName: `<script>alert(1)</script>`,
      senderTrust: "unverified",
      expiresAt: "2026-08-01T00:00:00Z",
      reportAbuseUrl: `${SHARE_ORIGIN}/report?t=abc`,
    });
    expect(rendered.subject).toBe("<script>alert(1)</script> was shared with you");
    expect(rendered.html).not.toContain("<script>");
    expect(rendered.html).toContain("&lt;script&gt;");
    expect(rendered.html).toContain("Unverified sender");
    expect(rendered.html.match(/href="/g)).toHaveLength(2);
    expect(rendered.html).toContain(SHARE_URL);
    expect(rendered.text).toContain("2026-08-01T00:00:00Z");
    // The claim ceremony is out of scope: no code is offered today.
    expect(rendered.html).not.toContain("Or enter this code");
  });

  it("has the slot the claim ceremony will use, without shipping it", () => {
    const rendered = renderInvitationEmail({
      magicUrl: `${SHARE_URL}&i=invitation&c=secret`,
      documentName: "Report.pdf",
      senderTrust: "verified",
      expiresAt: "2026-08-01T00:00:00Z",
      reportAbuseUrl: `${SHARE_ORIGIN}/report?t=abc`,
      otp: "123456",
    });
    expect(rendered.html).toContain("Or enter this code: <strong>123456</strong>");
    expect(rendered.text).toContain("Never send this code to anyone");
  });
});

describe("readiness", () => {
  it("reports whether it is provisioned without revealing any value", async () => {
    const ready = await worker.fetch(
      new Request("https://email.tinycloud.xyz/health/readiness"),
      env(),
    );
    expect(await ready.json()).toEqual({ ready: true });

    const unset = env();
    delete (unset as unknown as Record<string, unknown>).NODE_INVITATION_PUBLIC_KEY;
    const notReady = await worker.fetch(
      new Request("https://email.tinycloud.xyz/health/readiness"),
      unset,
    );
    expect(await notReady.json()).toEqual({ ready: false });
  });
});
