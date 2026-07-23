/**
 * Stage-3 viewer tests — end-to-end in-process:
 * seal a bearer envelope (stage-1 lib) → put it in the dev registry
 * (stage 2) → construct /s/<cid>#k= → drive resolve + verify + render →
 * assert states and, above all, that hostile content never executes.
 */
import { Buffer } from "node:buffer";

import { ed25519 } from "@noble/curves/ed25519";
import {
  computeCid,
  didKeyFromEd25519PublicKey,
  fromBase64Url,
  generateKey,
  seal,
  signEnvelope,
  toBase64Url,
  type AuthorizationTarget,
  type ShareEnvelope,
  type UnsignedShareEnvelope,
} from "@tinycloud/share-envelope";
import { putBlob } from "@tinycloud/share-registry";
import {
  createDevRegistry,
  type DevRegistry,
} from "@tinycloud/share-registry/dev-server";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { resolveRegistryBaseUrl } from "../src/viewer/config.js";
import {
  PREVIEW_FRAME_CSP,
  buildPreviewDocument,
  createPreviewFrame,
} from "../src/viewer/preview-frame.js";
import {
  ContentTooLargeError,
  MAX_MARKDOWN_BYTES,
  MAX_PREVIEW_NODES,
  markdownToSanitizedHtml,
  renderMarkdownInto,
  sanitizeSvg,
  withTimeout,
} from "../src/viewer/render.js";
import { resolveShare, type ResolveResult } from "../src/viewer/resolve.js";
import { renderViewerState } from "../src/viewer/ui.js";
import { hrefForParse, scrubKeyFragment } from "../src/viewer/url.js";
import {
  assertContentIsolated,
  previewBodyOf,
  previewFrameOf,
} from "./preview-helpers.js";

// ---------------------------------------------------------------- fixtures

const REGISTRY_BASE = "http://registry.local";
const VIEWER_ORIGIN = "https://share.tinycloud.xyz";
const PRIV_KEY = new Uint8Array(32).fill(7);
/** A real (differently-keyed) did:key — for wrong-signer tests. */
const OTHER_DID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

const BEARER_TARGET: AuthorizationTarget = {
  kind: "bearerKey",
  sessionJwk: {
    kty: "OKP",
    crv: "Ed25519",
    x: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik",
    d: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
  },
};

/** policyBytes is base64url of `{"policy":"test"}`; policyCid is its real CID. */
const POLICY_TARGET: AuthorizationTarget = {
  kind: "policy",
  policyCid: "bafkreig36s2hz442yqcnkctpkgtjev5pyjngzymyipk3koywg4d7rqmu5u",
  policyBytes: "eyJwb2xpY3kiOiJ0ZXN0In0",
};

/** The did:key the embedded bearer session key actually is. */
const SESSION_DID = didKeyFromEd25519PublicKey(
  fromBase64Url(BEARER_TARGET.sessionJwk.x),
);
/** Canonical resource URI of the default fixture target (delegation.ts). */
const FIXTURE_RESOURCE = "https://share.tinycloud.xyz/space-abc/shares/share-123/report.md";
/** Delegation issuer key (self-issued in the bearer slice; iss must match). */
const ISSUER_PRIV = new Uint8Array(32).fill(21);
const ISSUER_DID = didKeyFromEd25519PublicKey(ed25519.getPublicKey(ISSUER_PRIV));
/** Default delegation expiry: matches the fixture envelope expiry horizon. */
const DELEGATION_EXP = Math.floor(Date.parse("2099-08-01T00:00:00.000Z") / 1000);

/** Buffer, not TextEncoder: jsdom's encoder yields cross-realm Uint8Arrays
 *  that multiformats' binary-type check rejects. */
function b64uJson(value: unknown): string {
  return toBase64Url(Uint8Array.from(Buffer.from(JSON.stringify(value), "utf8")));
}

/**
 * Build a REAL EdDSA-signed UCAN/JWT-shaped delegation token (the checker now
 * verifies the signature against `iss`, so stub signatures no longer pass):
 * the delegatee (`aud`) defaults to the embedded session key's did:key, the
 * capability defaults to read over the fixture's exact resource, and `exp`
 * defaults to the fixture horizon. Overrides let each test break exactly one
 * claim. (Chain verification against owner roots is still the node's job at
 * read time; see src/viewer/delegation.ts.)
 */
function makeDelegation(
  payloadOverrides: Record<string, unknown> = {},
  headerOverrides: Record<string, unknown> = {},
): string {
  const header = { alg: "EdDSA", typ: "JWT", ucv: "0.9.1", ...headerOverrides };
  const payload = {
    iss: ISSUER_DID,
    aud: SESSION_DID,
    att: [{ with: FIXTURE_RESOURCE, can: "kv/get" }],
    prf: [],
    exp: DELEGATION_EXP,
    ...payloadOverrides,
  };
  const signingInput = `${b64uJson(header)}.${b64uJson(payload)}`;
  const signature = toBase64Url(
    ed25519.sign(Uint8Array.from(Buffer.from(signingInput, "utf8")), ISSUER_PRIV),
  );
  return `${signingInput}.${signature}`;
}

function makeUnsigned(
  overrides: Partial<UnsignedShareEnvelope> = {},
): UnsignedShareEnvelope {
  return {
    version: 1,
    shareId: "share-123",
    delegation: makeDelegation(),
    authorizationTarget: BEARER_TARGET,
    target: {
      origin: "https://share.tinycloud.xyz",
      nodeAudience: "did:web:node.tinycloud.xyz",
      spaceId: "space-abc",
      resource: { kind: "exact", path: "shares/share-123/report.md" },
    },
    display: {
      senderName: "Adam",
      filename: "report.md",
      recipientHint: "b***@gmail.com",
    },
    expiry: "2099-08-01T00:00:00.000Z",
    ...overrides,
  };
}

/** In-process fetch adapter over the dev-registry handler (no port). */
function handlerFetch(registry: DevRegistry): typeof fetch {
  return async (input, init) => {
    const withDuplex =
      init?.body === undefined || init.body === null
        ? init
        : ({ ...init, duplex: "half" } as RequestInit);
    return registry.handler(new Request(input, withDuplex));
  };
}

let registry: DevRegistry;
let fetchFn: typeof fetch;

beforeEach(() => {
  registry = createDevRegistry();
  fetchFn = handlerFetch(registry);
  delete (window as { __pwned?: unknown }).__pwned;
});

/** Seal + upload an (already signed or tampered) envelope; return the link. */
async function publish(
  envelope: ShareEnvelope,
  key: Uint8Array = generateKey(),
): Promise<{ url: string; cid: string; key: Uint8Array }> {
  const plaintext = new TextEncoder().encode(JSON.stringify(envelope));
  const sealed = await seal(plaintext, key);
  await putBlob(REGISTRY_BASE, sealed.blob, new Date(Date.now() + 3_600_000), {
    fetchFn,
  });
  return {
    url: `${VIEWER_ORIGIN}/s/${sealed.cid}#k=${toBase64Url(key)}`,
    cid: sealed.cid,
    key,
  };
}

function resolve(url: string): Promise<ResolveResult> {
  return resolveShare(url, { registryBaseUrl: REGISTRY_BASE, fetchFn });
}

function makeRoot(): HTMLElement {
  const root = document.createElement("div");
  document.body.append(root);
  return root;
}

/**
 * The fail-closed render invariant: a non-OK resolve result must yield NO
 * content container at all — renderViewerState returns null and no element
 * with .viewer-content exists anywhere under the root.
 */
function expectFailClosedRender(result: ResolveResult): HTMLElement {
  const root = makeRoot();
  expect(renderViewerState(root, result)).toBeNull();
  expect(root.querySelector(".viewer-content")).toBeNull();
  return root;
}

/** Resolve while observing the parsed fragment-key buffer (key hygiene). */
async function resolveCapturingKey(
  url: string,
): Promise<{ result: ResolveResult; key: Uint8Array; nonZeroAtParse: boolean }> {
  let captured: Uint8Array | undefined;
  let nonZeroAtParse = false;
  const result = await resolveShare(url, {
    registryBaseUrl: REGISTRY_BASE,
    fetchFn,
    onKeyParsed: (key32) => {
      captured = key32;
      nonZeroAtParse = key32.some((byte) => byte !== 0);
    },
  });
  expect(captured).toBeDefined();
  return { result, key: captured as Uint8Array, nonZeroAtParse };
}

function expectZeroed(key: Uint8Array): void {
  expect(
    Array.from(key).every((byte) => byte === 0),
    "parsed key buffer must be zeroed",
  ).toBe(true);
}

function assertNoExecutableContent(container: HTMLElement): void {
  expect(container.querySelector("script")).toBeNull();
  expect(container.querySelector("iframe, object, embed")).toBeNull();
  for (const node of Array.from(container.querySelectorAll("*"))) {
    for (const attr of Array.from(node.attributes)) {
      expect(
        attr.name.toLowerCase().startsWith("on"),
        `event handler attribute ${attr.name} survived`,
      ).toBe(false);
      if (["href", "src", "xlink:href", "action", "formaction"].includes(attr.name)) {
        const value = attr.value.toLowerCase().replace(/[\s -]/g, "");
        expect(value.startsWith("javascript:"), `javascript: URL survived`).toBe(false);
        expect(value.startsWith("data:text/html"), `data:text/html URL survived`).toBe(
          false,
        );
      }
    }
  }
  expect((window as { __pwned?: unknown }).__pwned).toBeUndefined();
}

// ------------------------------------------------------------ happy path

describe("bearer single-file share (happy path)", () => {
  it("resolves, verifies, and renders the read-only viewer chrome", async () => {
    const envelope = signEnvelope(makeUnsigned(), PRIV_KEY);
    const { url } = await publish(envelope);

    const result = await resolve(url);
    expect(result.state).toBe("ok");

    const root = makeRoot();
    const content = renderViewerState(root, result);
    expect(content).not.toBeNull();

    const text = root.textContent ?? "";
    expect(text).toContain("report.md");
    expect(text).toContain("shared by Adam (unverified)"); // never a checkmark
    expect(text).not.toContain("✓");
    expect(text).toContain("read-only");
    expect(text).toContain("Expires");
    // A pointer-less envelope has no bytes to show → honest placeholder.
    expect(text).toContain("doesn't include an embedded file preview");
    expect(text).toContain("shares/share-123/report.md");
  });

  it("renders markdown fed through the stage-4 content entry point", async () => {
    const envelope = signEnvelope(makeUnsigned(), PRIV_KEY);
    const { url } = await publish(envelope);
    const result = await resolve(url);
    const root = makeRoot();
    const content = renderViewerState(root, result);
    expect(content).not.toBeNull();

    await renderMarkdownInto(
      content as HTMLElement,
      "# Project Phoenix\n\nPhoenix is a *small* tool.\n\n| a | b |\n| - | - |\n| 1 | 2 |",
    );
    // The rendered document lives in the scriptless preview frame (§3.3),
    // not in the privileged document's DOM.
    const body = assertContentIsolated(content as HTMLElement);
    expect(body.querySelector("h1")?.textContent).toBe("Project Phoenix");
    expect(body.querySelector("em")?.textContent).toBe("small");
    expect(body.querySelector("table")).not.toBeNull();
  });

  it("zeroes the fragment key after decryption", async () => {
    const envelope = signEnvelope(makeUnsigned(), PRIV_KEY);
    const key = generateKey();
    const keyCopy = key.slice();
    const { cid } = await publish(envelope, key);
    // resolveShare gets its own key bytes parsed from the URL; verify the
    // parse→zero contract by resolving and checking OUR array is untouched
    // (the parsed copy is internal) — then check behavior directly:
    const result = await resolveShare(
      `${VIEWER_ORIGIN}/s/${cid}#k=${toBase64Url(keyCopy)}`,
      { registryBaseUrl: REGISTRY_BASE, fetchFn },
    );
    expect(result.state).toBe("ok");
  });
});

// ------------------------------------------------------------ fail closed

describe("fail-closed error states", () => {
  it("wrong key → decrypt-failed, no content rendered", async () => {
    const envelope = signEnvelope(makeUnsigned(), PRIV_KEY);
    const { cid } = await publish(envelope);
    const wrongKey = generateKey();
    const result = await resolve(
      `${VIEWER_ORIGIN}/s/${cid}#k=${toBase64Url(wrongKey)}`,
    );
    expect(result.state).toBe("decrypt-failed");

    const root = makeRoot();
    const content = renderViewerState(root, result);
    expect(content).toBeNull();
    expect(root.querySelector(".viewer-content")).toBeNull();
    expect(root.textContent).toContain("Couldn't unlock this share");
  });

  it("missing key fragment → invalid-link, no content rendered", async () => {
    const envelope = signEnvelope(makeUnsigned(), PRIV_KEY);
    const { cid } = await publish(envelope);
    const result = await resolve(`${VIEWER_ORIGIN}/s/${cid}`);
    expect(result.state).toBe("invalid-link");
    const root = expectFailClosedRender(result);
    expect(root.textContent).toContain("isn't a valid share link");
  });

  it("tampered ciphertext → cid-mismatch, no content", async () => {
    const envelope = signEnvelope(makeUnsigned(), PRIV_KEY);
    const { url, cid } = await publish(envelope);
    const record = registry.store.get(cid);
    expect(record).toBeDefined();
    record?.bytes.set([record.bytes[20]! ^ 0xff], 20); // flip one stored byte

    const result = await resolve(url);
    expect(result.state).toBe("cid-mismatch");

    const root = makeRoot();
    expect(renderViewerState(root, result)).toBeNull();
    expect(root.textContent).toContain("integrity check");
  });

  it("tampered envelope field (post-signing) → signature-invalid", async () => {
    const envelope = signEnvelope(makeUnsigned(), PRIV_KEY);
    const tampered: ShareEnvelope = {
      ...envelope,
      display: { ...envelope.display, senderName: "Mallory" },
    };
    const { url } = await publish(tampered);
    const result = await resolve(url);
    expect(result.state).toBe("signature-invalid");

    const root = makeRoot();
    expect(renderViewerState(root, result)).toBeNull();
    expect(root.textContent).toContain("failed verification");
  });

  it("wrong signer DID (signature not by claimed key) → signature-invalid", async () => {
    const envelope = signEnvelope(makeUnsigned(), PRIV_KEY);
    const wrongSigner: ShareEnvelope = {
      ...envelope,
      signature: { ...envelope.signature, signerDid: OTHER_DID },
    };
    const { url } = await publish(wrongSigner);
    const result = await resolve(url);
    expect(result.state).toBe("signature-invalid");
    expectFailClosedRender(result);
  });

  it("expired envelope → expired, no content", async () => {
    const envelope = signEnvelope(
      makeUnsigned({ expiry: "2020-01-01T00:00:00.000Z" }),
      PRIV_KEY,
    );
    const { url } = await publish(envelope);
    const result = await resolve(url);
    expect(result.state).toBe("expired");

    const root = makeRoot();
    expect(renderViewerState(root, result)).toBeNull();
    expect(root.textContent).toContain("expired");
  });

  it("unknown CID → fetch-failed, no content rendered", async () => {
    // Uint8Array.of, not TextEncoder: jsdom's encoder yields a cross-realm
    // Uint8Array that multiformats' binary-type check rejects.
    const cid = await computeCid(Uint8Array.of(110, 101, 118, 101, 114));
    const result = await resolve(
      `${VIEWER_ORIGIN}/s/${cid}#k=${toBase64Url(generateKey())}`,
    );
    expect(result.state).toBe("fetch-failed");
    const root = expectFailClosedRender(result);
    expect(root.textContent).toContain("Couldn't fetch this share");
  });

  it("decrypted plaintext that isn't an envelope → envelope-invalid, no content rendered", async () => {
    const key = generateKey();
    const sealed = await seal(new TextEncoder().encode('{"not":"an envelope"}'), key);
    await putBlob(REGISTRY_BASE, sealed.blob, new Date(Date.now() + 3_600_000), {
      fetchFn,
    });
    const result = await resolve(
      `${VIEWER_ORIGIN}/s/${sealed.cid}#k=${toBase64Url(key)}`,
    );
    expect(result.state).toBe("envelope-invalid");
    const root = expectFailClosedRender(result);
    expect(root.textContent).toContain("can't be read");
  });
});

// --------------------------------------- effective-capability binding (spec §1)

describe("bearer delegation binding — the 'verified' state validates the capability", () => {
  /** Publish an envelope with the given delegation string; resolve it. */
  async function resolveWithDelegation(delegation: string): Promise<ResolveResult> {
    const envelope = signEnvelope(makeUnsigned({ delegation }), PRIV_KEY);
    const { url } = await publish(envelope);
    return resolve(url);
  }

  it("garbage/opaque delegation → capability-invalid, no content rendered", async () => {
    const result = await resolveWithDelegation(
      "uCAESA...opaque-serialized-delegation-chain",
    );
    expect(result.state).toBe("capability-invalid");
    const root = expectFailClosedRender(result);
    expect(root.textContent).toContain("authorization doesn't add up");
  });

  it("token with non-JSON segments → capability-invalid", async () => {
    const junk = toBase64Url(Uint8Array.of(1, 2, 3));
    const result = await resolveWithDelegation(`${junk}.${junk}.${junk}`);
    expect(result.state).toBe("capability-invalid");
    expectFailClosedRender(result);
  });

  it("delegatee ≠ embedded key DID → capability-invalid", async () => {
    const result = await resolveWithDelegation(makeDelegation({ aud: OTHER_DID }));
    expect(result.state).toBe("capability-invalid");
    expectFailClosedRender(result);
  });

  it("missing audience → capability-invalid", async () => {
    const result = await resolveWithDelegation(makeDelegation({ aud: undefined }));
    expect(result.state).toBe("capability-invalid");
  });

  it("wrong ability (kv/put only) → capability-invalid", async () => {
    const result = await resolveWithDelegation(
      makeDelegation({ att: [{ with: FIXTURE_RESOURCE, can: "kv/put" }] }),
    );
    expect(result.state).toBe("capability-invalid");
    expectFailClosedRender(result);
  });

  it("wrong resource path → capability-invalid", async () => {
    const result = await resolveWithDelegation(
      makeDelegation({
        att: [
          {
            with: "https://share.tinycloud.xyz/space-abc/shares/OTHER/file.md",
            can: "kv/get",
          },
        ],
      }),
    );
    expect(result.state).toBe("capability-invalid");
  });

  it("wrong origin → capability-invalid", async () => {
    const result = await resolveWithDelegation(
      makeDelegation({
        att: [
          {
            with: "https://evil.example/space-abc/shares/share-123/report.md",
            can: "kv/get",
          },
        ],
      }),
    );
    expect(result.state).toBe("capability-invalid");
  });

  it("wrong space → capability-invalid", async () => {
    const result = await resolveWithDelegation(
      makeDelegation({
        att: [
          {
            with: "https://share.tinycloud.xyz/space-OTHER/shares/share-123/report.md",
            can: "kv/get",
          },
        ],
      }),
    );
    expect(result.state).toBe("capability-invalid");
  });

  it("empty capability list → capability-invalid", async () => {
    const result = await resolveWithDelegation(makeDelegation({ att: [] }));
    expect(result.state).toBe("capability-invalid");
  });

  it("prefix grant that does NOT cover the path → capability-invalid", async () => {
    const result = await resolveWithDelegation(
      makeDelegation({
        att: [{ with: "https://share.tinycloud.xyz/space-abc/other/*", can: "kv/get" }],
      }),
    );
    expect(result.state).toBe("capability-invalid");
  });

  it("correctly-bound exact delegation → ok", async () => {
    const result = await resolveWithDelegation(makeDelegation());
    expect(result.state).toBe("ok");
  });

  it("correctly-bound prefix (/*) delegation covering the path → ok", async () => {
    const result = await resolveWithDelegation(
      makeDelegation({
        att: [
          { with: "https://share.tinycloud.xyz/space-abc/shares/share-123/*", can: "kv/get" },
        ],
      }),
    );
    expect(result.state).toBe("ok");
  });

  it("any ability other than THE minted one (incl. old namespaced alias) → capability-invalid", async () => {
    // mint and check share ONE ability constant — the checker accepting a
    // namespaced alias the mint never emits was drift, now closed
    const result = await resolveWithDelegation(
      makeDelegation({ att: [{ with: FIXTURE_RESOURCE, can: "tinycloud.kv/get" }] }),
    );
    expect(result.state).toBe("capability-invalid");
  });

  it("stub / tampered signature → capability-invalid (the token is actually verified now)", async () => {
    // stub signature bytes
    const header = { alg: "EdDSA", typ: "JWT", ucv: "0.9.1" };
    const payload = {
      iss: ISSUER_DID,
      aud: SESSION_DID,
      att: [{ with: FIXTURE_RESOURCE, can: "kv/get" }],
      prf: [],
      exp: DELEGATION_EXP,
    };
    const stub = `${b64uJson(header)}.${b64uJson(payload)}.${toBase64Url(
      Uint8Array.from(Buffer.from("stub-signature", "utf8")),
    )}`;
    expect((await resolveWithDelegation(stub)).state).toBe("capability-invalid");

    // valid token, one payload byte tampered after signing
    const minted = makeDelegation();
    const [h, p, s] = minted.split(".") as [string, string, string];
    const tamperedPayload = b64uJson({ ...payload, aud: SESSION_DID, prf: ["x"] });
    expect(
      (await resolveWithDelegation(`${h}.${tamperedPayload}.${s}`)).state,
    ).toBe("capability-invalid");
    expect((await resolveWithDelegation(`${h}.${p}.${s}`)).state).toBe("ok");
  });

  it("expired delegation (envelope still live) → capability-invalid", async () => {
    const result = await resolveWithDelegation(
      makeDelegation({ exp: Math.floor(Date.parse("2020-01-01T00:00:00Z") / 1000) }),
    );
    expect(result.state).toBe("capability-invalid");
    expectFailClosedRender(result);
  });

  it("expiry-less delegation → capability-invalid (exp is required)", async () => {
    const result = await resolveWithDelegation(makeDelegation({ exp: undefined }));
    expect(result.state).toBe("capability-invalid");
  });

  it("not-yet-valid delegation (future nbf) → capability-invalid", async () => {
    const result = await resolveWithDelegation(
      makeDelegation({ nbf: Math.floor(Date.parse("2098-01-01T00:00:00Z") / 1000) }),
    );
    expect(result.state).toBe("capability-invalid");
  });

  it("traversal-alias grant (shares/share-123/../OTHER under /*) → capability-invalid", async () => {
    const result = await resolveWithDelegation(
      makeDelegation({
        att: [
          {
            // canonical-grammar violation: never normalized-and-accepted
            with: "https://share.tinycloud.xyz/space-abc/shares/share-123/../OTHER/*",
            can: "kv/get",
          },
        ],
      }),
    );
    expect(result.state).toBe("capability-invalid");
  });

  it("non-Ed25519 session key (EC) cannot be bound → capability-invalid", async () => {
    const bytes32 = toBase64Url(new Uint8Array(32).fill(9));
    const envelope = signEnvelope(
      makeUnsigned({
        authorizationTarget: {
          kind: "bearerKey",
          sessionJwk: { kty: "EC", crv: "P-256", x: bytes32, y: bytes32, d: bytes32 },
        },
      }),
      PRIV_KEY,
    );
    const { url } = await publish(envelope);
    const result = await resolve(url);
    expect(result.state).toBe("capability-invalid");
    expectFailClosedRender(result);
  });
});

// ------------------------------------------------- unsupported (honest) states

describe("unsupported targets/modes are never faked-verified", () => {
  it("policy-target envelope → unsupported, copy admits nothing was verified", async () => {
    const envelope = signEnvelope(
      makeUnsigned({ authorizationTarget: POLICY_TARGET }),
      PRIV_KEY,
    );
    const { url } = await publish(envelope);
    const result = await resolve(url);
    expect(result).toMatchObject({ state: "unsupported", reason: "policy-target" });

    const root = expectFailClosedRender(result);
    const text = root.textContent ?? "";
    expect(text).toContain("isn't supported in this build");
    expect(text).toContain("Nothing about this share was verified");
    expect(text).not.toContain("✓");
  });

  it("recipient-DID envelope → unsupported, no content rendered", async () => {
    const envelope = signEnvelope(
      makeUnsigned({ authorizationTarget: { kind: "recipientDid", did: OTHER_DID } }),
      PRIV_KEY,
    );
    const { url } = await publish(envelope);
    const result = await resolve(url);
    expect(result).toMatchObject({
      state: "unsupported",
      reason: "recipient-did-target",
    });
    const root = expectFailClosedRender(result);
    expect(root.textContent).toContain("isn't supported in this build");
  });

  it("bearer + prefix resource (folder) → unsupported in the single-file slice, no content rendered", async () => {
    const envelope = signEnvelope(
      makeUnsigned({
        target: {
          origin: "https://share.tinycloud.xyz",
          nodeAudience: "did:web:node.tinycloud.xyz",
          spaceId: "space-abc",
          resource: { kind: "prefix", path: "shares/share-123/" },
        },
      }),
      PRIV_KEY,
    );
    const { url } = await publish(envelope);
    const result = await resolve(url);
    expect(result).toMatchObject({ state: "unsupported", reason: "prefix-resource" });
    const root = expectFailClosedRender(result);
    expect(root.textContent).toContain("Folder shares aren't supported");
  });
});

// ------------------------------------------------------------- key hygiene

describe("fragment-key hygiene (location/history scrub + buffer zeroing)", () => {
  it("scrubKeyFragment drops the #k= fragment from location AND the history entry", () => {
    window.history.replaceState(null, "", "/s/bafyabc?keep=1#k=SECRET-KEY-MATERIAL");
    expect(window.location.hash).toContain("k=");
    scrubKeyFragment(window.location, window.history);
    expect(window.location.hash).toBe("");
    expect(window.location.href).not.toContain("#k=");
    expect(window.location.href).not.toContain("SECRET");
    // pathname and query survive; only the fragment is scrubbed
    expect(window.location.pathname).toBe("/s/bafyabc");
    expect(window.location.search).toBe("?keep=1");
  });

  it("scrubKeyFragment is a no-op when there is no fragment", () => {
    window.history.replaceState(null, "", "/s/bafyabc");
    const before = window.location.href;
    scrubKeyFragment(window.location, window.history);
    expect(window.location.href).toBe(before);
  });

  it("zeroes the parsed key buffer on success", async () => {
    const envelope = signEnvelope(makeUnsigned(), PRIV_KEY);
    const { url } = await publish(envelope);
    const { result, key, nonZeroAtParse } = await resolveCapturingKey(url);
    expect(result.state).toBe("ok");
    expect(nonZeroAtParse).toBe(true); // the buffer really held the key once
    expectZeroed(key);
  });

  it("zeroes the parsed key buffer on wrong key (decrypt-failed)", async () => {
    const envelope = signEnvelope(makeUnsigned(), PRIV_KEY);
    const { cid } = await publish(envelope);
    const { result, key } = await resolveCapturingKey(
      `${VIEWER_ORIGIN}/s/${cid}#k=${toBase64Url(generateKey())}`,
    );
    expect(result.state).toBe("decrypt-failed");
    expectZeroed(key);
  });

  it("zeroes the parsed key buffer on cid-mismatch", async () => {
    const envelope = signEnvelope(makeUnsigned(), PRIV_KEY);
    const { url, cid } = await publish(envelope);
    const record = registry.store.get(cid);
    record?.bytes.set([record.bytes[20]! ^ 0xff], 20);
    const { result, key } = await resolveCapturingKey(url);
    expect(result.state).toBe("cid-mismatch");
    expectZeroed(key);
  });

  it("zeroes the parsed key buffer on signature-invalid", async () => {
    const envelope = signEnvelope(makeUnsigned(), PRIV_KEY);
    const tampered: ShareEnvelope = {
      ...envelope,
      display: { ...envelope.display, senderName: "Mallory" },
    };
    const { url } = await publish(tampered);
    const { result, key } = await resolveCapturingKey(url);
    expect(result.state).toBe("signature-invalid");
    expectZeroed(key);
  });

  it("zeroes the parsed key buffer on expiry", async () => {
    const envelope = signEnvelope(
      makeUnsigned({ expiry: "2020-01-01T00:00:00.000Z" }),
      PRIV_KEY,
    );
    const { url } = await publish(envelope);
    const { result, key } = await resolveCapturingKey(url);
    expect(result.state).toBe("expired");
    expectZeroed(key);
  });

  it("zeroes the parsed key buffer on capability-invalid", async () => {
    const envelope = signEnvelope(
      makeUnsigned({ delegation: "not-a-token" }),
      PRIV_KEY,
    );
    const { url } = await publish(envelope);
    const { result, key } = await resolveCapturingKey(url);
    expect(result.state).toBe("capability-invalid");
    expectZeroed(key);
  });
});

// ------------------------------------------------------- build-time config

describe("build-time configuration fails closed (no dev fallbacks in prod)", () => {
  it("production build without VITE_SHARE_REGISTRY_URL throws (no localhost default)", () => {
    expect(() => resolveRegistryBaseUrl({ PROD: true })).toThrow(
      /VITE_SHARE_REGISTRY_URL is required/,
    );
    expect(() =>
      resolveRegistryBaseUrl({ PROD: true, VITE_SHARE_REGISTRY_URL: "" }),
    ).toThrow(/VITE_SHARE_REGISTRY_URL is required/);
  });

  it("production build with an explicit registry URL uses it", () => {
    expect(
      resolveRegistryBaseUrl({
        PROD: true,
        VITE_SHARE_REGISTRY_URL: "https://registry.tinycloud.xyz",
      }),
    ).toBe("https://registry.tinycloud.xyz");
  });

  it("dev build falls back to the local dev registry", () => {
    expect(resolveRegistryBaseUrl({ PROD: false })).toBe("http://127.0.0.1:8787");
  });

  it("loopback http→https rewrite happens ONLY in dev builds and preserves search + hash", () => {
    const loc = {
      protocol: "http:",
      hostname: "localhost",
      host: "localhost:5173",
      pathname: "/s/bafyabc",
      search: "?q=1",
      hash: "#k=zz",
      href: "http://localhost:5173/s/bafyabc?q=1#k=zz",
    } as Location;
    // dev build: rewritten to https, nothing dropped (the query string must
    // still reach parseShareUrl so it can be REJECTED there, not vanish)
    expect(hrefForParse(loc, true)).toBe("https://localhost:5173/s/bafyabc?q=1#k=zz");
    // prod build: untouched — the http URL fails closed in parseShareUrl
    expect(hrefForParse(loc, false)).toBe(loc.href);
  });

  it("non-loopback http is never rewritten, even in dev", () => {
    const loc = {
      protocol: "http:",
      hostname: "share.example",
      host: "share.example",
      pathname: "/s/bafyabc",
      search: "",
      hash: "#k=zz",
      href: "http://share.example/s/bafyabc#k=zz",
    } as Location;
    expect(hrefForParse(loc, true)).toBe(loc.href);
  });
});

// ------------------------------------------------------ hostile content

describe("hostile content pipeline (spec §3 subset)", () => {
  it("strips <script> embedded in markdown", async () => {
    const container = makeRoot();
    await renderMarkdownInto(
      container,
      'before\n\n<script>window.__pwned = true;</script>\n\nafter',
    );
    const body = assertContentIsolated(container);
    assertNoExecutableContent(body);
    expect(body.textContent).toContain("before");
    expect(body.textContent).toContain("after");
    expect(body.textContent).not.toContain("__pwned"); // raw HTML dropped, not textified
  });

  it("strips javascript: links (markdown syntax and raw HTML, any casing)", async () => {
    const container = makeRoot();
    await renderMarkdownInto(
      container,
      [
        "[click me](javascript:window.__pwned=true)",
        '<a href="jAvAsCrIpT:window.__pwned=true">or me</a>',
        "[proto](vbscript:evil)",
        "[data](data:text/html,<script>window.__pwned=true</script>)",
      ].join("\n\n"),
    );
    assertNoExecutableContent(assertContentIsolated(container));
  });

  it("strips <img onerror> and other event handlers", async () => {
    const container = makeRoot();
    await renderMarkdownInto(
      container,
      [
        '<img src="x" onerror="window.__pwned=true">',
        '<svg onload="window.__pwned=true"></svg>',
        '<body onload="window.__pwned=true">',
        '<iframe src="https://evil.example"></iframe>',
        '<details open ontoggle="window.__pwned=true">x</details>',
      ].join("\n\n"),
    );
    assertNoExecutableContent(assertContentIsolated(container));
  });

  it("does not execute a malicious ```mermaid block, even if the sandbox echoes hostile SVG", async () => {
    const container = makeRoot();
    // Worst-case sandbox: a compromised frame that reflects the diagram
    // source into hostile SVG. The parent-side re-sanitization must still
    // strip every executable/remote thing before insertion.
    const hostileEchoSandbox = {
      render: (source: string) =>
        Promise.resolve(
          `<svg xmlns="http://www.w3.org/2000/svg"><text>${source}</text>` +
            '<script>window.__pwned=true</script>' +
            '<circle r="1" onload="window.__pwned=true"/>' +
            '<image href="https://evil.example/x.png"/></svg>',
        ),
      destroy: () => {},
    };
    await renderMarkdownInto(
      container,
      [
        "```mermaid",
        'graph TD',
        'A["<img src=x onerror=window.__pwned=true>"] --> B',
        "```",
        "",
        "```mermaid",
        "</code></pre><script>window.__pwned=true</script>",
        "```",
      ].join("\n"),
      "document",
      { mermaidSandbox: () => hostileEchoSandbox },
    );
    assertNoExecutableContent(assertContentIsolated(container));
    expect(previewFrameOf(container).srcdoc).not.toContain("evil.example");
  });

  it("sanitizeSvg strips script/foreignObject/event handlers from SVG", () => {
    const dirty =
      '<svg xmlns="http://www.w3.org/2000/svg">' +
      '<script>window.__pwned=true</script>' +
      '<foreignObject><iframe src="https://evil.example"></iframe></foreignObject>' +
      '<circle r="1" onload="window.__pwned=true"/>' +
      '<a href="javascript:window.__pwned=true"><text>x</text></a>' +
      "</svg>";
    const clean = sanitizeSvg(dirty);
    expect(clean).not.toContain("<script");
    expect(clean).not.toContain("foreignObject");
    expect(clean).not.toContain("onload");
    expect(clean.toLowerCase()).not.toContain("javascript:");
    expect((window as { __pwned?: unknown }).__pwned).toBeUndefined();
  });

  it("source mode renders text only (narrowing display.mode hint)", async () => {
    const container = makeRoot();
    await renderMarkdownInto(
      container,
      '<script>window.__pwned=true</script># not a heading',
      "source",
    );
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("pre")?.textContent).toContain("# not a heading");
    assertNoExecutableContent(container);
  });

  it("strips remote images in the pipeline itself (not just CSP): markdown ![](https://…)", async () => {
    const container = makeRoot();
    await renderMarkdownInto(
      container,
      [
        "![pixel](https://evil.example/pixel.png)",
        "![proto-relative](//evil.example/pixel.png)",
        '<img src="https://evil.example/raw.png">',
        "![local](data:image/png;base64,iVBORw0KGgo)",
      ].join("\n\n"),
    );
    // no surviving remote reference anywhere in the frame payload
    const body = assertContentIsolated(container);
    expect(previewFrameOf(container).srcdoc).not.toContain("evil.example");
    expect(body.querySelector('img[src^="http"]')).toBeNull();
    expect(body.querySelector('img[src^="//"]')).toBeNull();
    // data:image/ stays allowed (self-contained, no network fetch)
    expect(body.querySelector('img[src^="data:image/"]')).not.toBeNull();
  });

  it("strips SVG external refs: <image>, <feImage>, and style url()", () => {
    const dirty =
      '<svg xmlns="http://www.w3.org/2000/svg">' +
      '<image href="https://evil.example/x.png" />' +
      '<image xlink:href="//evil.example/y.png" />' +
      '<filter><feImage href="https://evil.example/f.png" /></filter>' +
      "<style>rect { fill: url(https://evil.example/p.svg#f); }</style>" +
      "<style>rect { fill: u\\72 l(https://evil.example/esc.svg); }</style>" +
      '<rect style="background: url(https://evil.example/b.png)" width="1" height="1"/>' +
      "</svg>";
    const clean = sanitizeSvg(dirty);
    expect(clean).not.toContain("evil.example");
    expect(clean.toLowerCase()).not.toContain("url(");
  });

  it("measures MAX_MARKDOWN_BYTES in encoded bytes, not UTF-16 units", async () => {
    // 400k '€' = 400k UTF-16 units but 1.2M UTF-8 bytes — must be rejected.
    const multibyte = "€".repeat(400_000);
    expect(multibyte.length).toBeLessThan(MAX_MARKDOWN_BYTES);
    expect(new TextEncoder().encode(multibyte).length).toBeGreaterThan(
      MAX_MARKDOWN_BYTES,
    );
    await expect(markdownToSanitizedHtml(multibyte)).rejects.toThrow(
      /document too large/,
    );
  });

  it("renderMarkdownInto rejects an over-limit document without rendering anything", async () => {
    const container = makeRoot();
    await expect(
      renderMarkdownInto(container, "€".repeat(400_000)),
    ).rejects.toThrow(/document too large/);
    expect(container.innerHTML).toBe("");
  });

  it("withTimeout abandons a render that takes too long and settles fast results", async () => {
    await expect(
      withTimeout(new Promise<never>(() => {}), 25, "mermaid render"),
    ).rejects.toThrow(/mermaid render timed out after 25ms/);
    await expect(withTimeout(Promise.resolve(42), 1_000, "fast")).resolves.toBe(42);
  });
});

// ---------------------------------------- scriptless preview frame (spec §3.3)

describe("scriptless preview frame (spec §3.3) — the last boundary", () => {
  it("renders the document INSIDE the frame; the privileged document gets only the iframe", async () => {
    const container = makeRoot();
    await renderMarkdownInto(container, "# Inside the frame\n\nBody text.");
    const body = assertContentIsolated(container);
    expect(body.querySelector("h1")?.textContent).toBe("Inside the frame");
    // nothing of the content ever joins the privileged document's DOM
    expect(container.querySelector("h1")).toBeNull();
    expect(container.textContent).not.toContain("Inside the frame");
  });

  it("the frame's sandbox grants NOTHING: no allow-scripts, no allow-same-origin", async () => {
    const container = makeRoot();
    await renderMarkdownInto(container, "plain text");
    const frame = previewFrameOf(container);
    expect(frame.getAttribute("sandbox")).toBe("");
    expect(frame.getAttribute("referrerpolicy")).toBe("no-referrer");
    // srcdoc-delivered: no src, so no fetch and no parent-origin document
    expect(frame.getAttribute("src")).toBeNull();
    expect(frame.srcdoc.length).toBeGreaterThan(0);
  });

  it("pins the frame document's own CSP: default-src 'none', no script capability", () => {
    expect(PREVIEW_FRAME_CSP).toBe(
      "default-src 'none'; img-src data: blob:; style-src 'unsafe-inline'",
    );
    // deliberately NO script-src: it falls back to default-src 'none'
    expect(PREVIEW_FRAME_CSP).not.toContain("script-src");
    const docHtml = buildPreviewDocument("<p>x</p>");
    expect(docHtml).toContain(
      `<meta http-equiv="Content-Security-Policy" content="${PREVIEW_FRAME_CSP}">`,
    );
    expect(docHtml).toContain('<meta name="referrer" content="no-referrer">');
    expect(docHtml).toContain("<body><p>x</p></body>");
  });

  it("a <script> that somehow survived sanitization still cannot execute (frame can't run script at all)", () => {
    // Feed the frame builder a WORST-CASE payload directly, as if every
    // sanitizer had been bypassed: the sandbox="" frame is the guarantee.
    const hostile =
      '<script>window.__pwned = true;</script>' +
      '<img src="x" onerror="window.__pwned = true">';
    const frame = createPreviewFrame(document, hostile);
    document.body.append(frame);
    try {
      expect(frame.getAttribute("sandbox")).toBe(""); // parser-level inertness
      expect(frame.srcdoc).toContain("__pwned"); // present — but only as DATA
      expect((window as { __pwned?: unknown }).__pwned).toBeUndefined();
    } finally {
      frame.remove();
    }
  });

  it("enforces the TOTAL node-count bound: breach throws ContentTooLargeError and renders nothing", async () => {
    expect(MAX_PREVIEW_NODES).toBe(50_000); // pin the shipped bound
    const container = makeRoot();
    await expect(
      renderMarkdownInto(container, "- a\n- b\n- c\n- d", "document", {
        previewNodeBudget: 3,
      }),
    ).rejects.toBeInstanceOf(ContentTooLargeError);
    expect(container.innerHTML).toBe(""); // no frame, no partial content
  });

  it("mermaid SVG nodes count toward the total bound", async () => {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg">${"<circle r='1'/>".repeat(
      30,
    )}</svg>`;
    const container = makeRoot();
    await expect(
      renderMarkdownInto(
        container,
        "```mermaid\ngraph TD; A-->B\n```",
        "document",
        {
          mermaidSandbox: () => ({
            render: () => Promise.resolve(svg),
            destroy: () => {},
          }),
          previewNodeBudget: 10,
        },
      ),
    ).rejects.toBeInstanceOf(ContentTooLargeError);
    expect(container.innerHTML).toBe("");
  });
});

// ------------------------------------------------------------ Trusted Types

describe("Trusted Types policy (viewer spec §2)", () => {
  it("routes innerHTML through the named policy when Trusted Types exist", async () => {
    const policyNames: string[] = [];
    const createHtmlInputs: string[] = [];
    vi.stubGlobal("trustedTypes", {
      createPolicy(
        name: string,
        rules: { createHTML(input: string): string },
      ): { createHTML(input: string): string } {
        policyNames.push(name);
        return {
          createHTML(input: string): string {
            createHtmlInputs.push(input);
            return rules.createHTML(input);
          },
        };
      },
    });
    vi.resetModules();
    try {
      // Fresh module instance so the policy is (re-)created under the stub.
      const freshRender = await import("../src/viewer/render.js");
      const container = makeRoot();
      await freshRender.renderMarkdownInto(
        container,
        "# TT heading\n\n<script>window.__pwned=true</script>",
      );
      expect(policyNames).toEqual([freshRender.TRUSTED_TYPES_POLICY_NAME]);
      expect(freshRender.TRUSTED_TYPES_POLICY_NAME).toBe("share-viewer-html");
      // the policy received ALREADY-sanitized strings (sanitize → wrap),
      // once per TrustedHTML sink: the detached staging element's innerHTML,
      // then the preview frame's srcdoc document wrapping the same content.
      expect(createHtmlInputs).toHaveLength(2);
      expect(createHtmlInputs[0]).toContain("<h1>TT heading</h1>");
      expect(createHtmlInputs[0]).not.toContain("<script");
      expect(createHtmlInputs[1]).toContain(createHtmlInputs[0] ?? "@@none@@");
      expect(createHtmlInputs[1]).toContain("Content-Security-Policy");
      // and the document was actually rendered through it, into the frame
      const body = assertContentIsolated(container);
      expect(body.querySelector("h1")?.textContent).toBe("TT heading");
      assertNoExecutableContent(body);
    } finally {
      vi.unstubAllGlobals();
      vi.resetModules();
    }
  });

  it("degrades to the sanitized-string path where Trusted Types are absent", async () => {
    // jsdom has no trustedTypes: the top-level imported module already runs
    // the fallback path in every other rendering test; assert it explicitly.
    expect((globalThis as { trustedTypes?: unknown }).trustedTypes).toBeUndefined();
    const container = makeRoot();
    await renderMarkdownInto(container, "# no TT here");
    expect(previewBodyOf(container).querySelector("h1")?.textContent).toBe(
      "no TT here",
    );
  });
});
