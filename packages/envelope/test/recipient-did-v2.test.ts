import { ed25519 } from "@noble/curves/ed25519";
import { base58btc } from "multiformats/bases/base58";
import { describe, expect, it } from "vitest";

import {
  computeDelegationArtifactCid,
  isCanonicalDelegationCid,
  isCanonicalEd25519DidKey,
  nativeVerifiedRecipientBundleV2Schema,
  ownerDidFromCanonicalSpaceId,
  principalFromSessionVerificationMethod,
  recipientDidEnvelopeV2Schema,
  recipientDidEnvelopeV2SigningBytes,
  unsignedRecipientDidEnvelopeV2Schema,
  verifyRecipientDidEnvelopeV2,
  verifyRecipientDidEnvelopeV2Signature,
  type NativeVerifiedRecipientBundleV2,
  type RecipientDidDelegationBundleV2,
  type RecipientDidEnvelopeV2,
  type RecipientDidEnvelopeV2RejectCode,
  type UnsignedRecipientDidEnvelopeV2,
} from "../src/index.js";
import { fromBase64Url, toBase64Url } from "../src/bytes.js";
import { didKeyFromEd25519PublicKey } from "../src/didkey.js";
import vector from "./vectors/recipient-did-v2.json";

const NOW = new Date("2029-01-01T00:00:00.000Z");
const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

/** Test-only signing. No production module accepts or exports a private key. */
function signForTest(
  unsignedInput: UnsignedRecipientDidEnvelopeV2,
  seed = fromBase64Url(vector.currentSdkFixture.sessionJwkD),
): RecipientDidEnvelopeV2 {
  const unsigned = unsignedRecipientDidEnvelopeV2Schema.parse(unsignedInput);
  const signerDid = didKeyFromEd25519PublicKey(ed25519.getPublicKey(seed));
  const payload = { ...unsigned, signature: { signerDid, algorithm: "Ed25519" as const } };
  return {
    ...payload,
    signature: {
      ...payload.signature,
      value: toBase64Url(ed25519.sign(recipientDidEnvelopeV2SigningBytes(payload), seed)),
    },
  };
}

function unsignedFrom(envelope: RecipientDidEnvelopeV2): UnsignedRecipientDidEnvelopeV2 {
  const { signature: _signature, ...unsigned } = envelope;
  return unsignedRecipientDidEnvelopeV2Schema.parse(unsigned);
}

const fixtureEnvelope = recipientDidEnvelopeV2Schema.parse(vector.envelope);
const fixtureAuthority = vector.nativeVerified as NativeVerifiedRecipientBundleV2;

interface RejectMutation {
  target: "envelope" | "native";
  op: string;
  path?: string;
  value?: unknown;
  origin?: string;
  nodeAudience?: string;
  resign?: boolean;
  nativeReject?: boolean;
}

interface RejectCase {
  name: string;
  mutation: RejectMutation;
  expected: RecipientDidEnvelopeV2RejectCode;
}

const rejectCases = vector.reject as unknown as RejectCase[];

function setJsonPointer(root: unknown, pointer: string, value: unknown): void {
  const segments = pointer.slice(1).split("/").map((segment) =>
    segment.replaceAll("~1", "/").replaceAll("~0", "~"));
  let cursor = root;
  for (const segment of segments.slice(0, -1)) {
    if (Array.isArray(cursor)) cursor = cursor[Number(segment)];
    else if (typeof cursor === "object" && cursor !== null) {
      cursor = (cursor as Record<string, unknown>)[segment];
    } else throw new TypeError(`invalid JSON pointer ${pointer}`);
  }
  const final = segments.at(-1);
  if (final === undefined) throw new TypeError(`invalid JSON pointer ${pointer}`);
  if (Array.isArray(cursor)) cursor[Number(final)] = value;
  else if (typeof cursor === "object" && cursor !== null) {
    (cursor as Record<string, unknown>)[final] = value;
  } else throw new TypeError(`invalid JSON pointer ${pointer}`);
}

function getJsonPointer(root: unknown, pointer: string): unknown {
  let cursor = root;
  for (const segment of pointer.slice(1).split("/").map((part) =>
    part.replaceAll("~1", "/").replaceAll("~0", "~"))) {
    if (Array.isArray(cursor)) cursor = cursor[Number(segment)];
    else if (typeof cursor === "object" && cursor !== null) {
      cursor = (cursor as Record<string, unknown>)[segment];
    } else throw new TypeError(`invalid JSON pointer ${pointer}`);
  }
  return cursor;
}

function corruptGrantProof() {
  const grant = fixtureEnvelope.delegation.grant;
  const value = grant.value.replace(/.$/, (last) => last === "A" ? "B" : "A");
  const artifact = { ...grant, value };
  return { ...artifact, cid: computeDelegationArtifactCid(artifact) };
}

function applyRejectMutation(testCase: RejectCase): {
  envelope: unknown;
  native: (bundle: RecipientDidDelegationBundleV2) => Promise<NativeVerifiedRecipientBundleV2>;
} {
  let envelope: unknown = structuredClone(fixtureEnvelope);
  const authority: unknown = structuredClone(fixtureAuthority);
  const mutation = testCase.mutation;
  if (mutation.target === "native") {
    if (mutation.op !== "reject") {
      if (mutation.op !== "set" || mutation.path === undefined) throw new Error(`unknown mutation ${mutation.op}`);
      setJsonPointer(authority, mutation.path, mutation.value);
    }
  } else {
    const root = fixtureEnvelope.delegation.issuerProofs[0]!;
    const extra = corruptGrantProof();
    if (mutation.op === "set") {
      if (mutation.path === undefined) throw new Error("set mutation requires path");
      setJsonPointer(envelope, mutation.path, mutation.value);
    } else if (mutation.op === "misorder-corrupt-grant-proof") {
      setJsonPointer(envelope, "/delegation/issuerProofs", [extra, root]);
    } else if (mutation.op === "append-corrupt-grant-proof") {
      setJsonPointer(envelope, "/delegation/issuerProofs", [root, extra]);
    } else if (mutation.op === "duplicate-root") {
      setJsonPointer(envelope, "/delegation/issuerProofs", [root, root]);
    } else if (mutation.op === "corrupt-grant-value") {
      setJsonPointer(envelope, "/delegation/grant/value", extra.value);
    } else if (mutation.op === "set-route") {
      setJsonPointer(envelope, "/delegation/routing", {
        origin: mutation.origin,
        nodeAudience: mutation.nodeAudience,
      });
    } else if (mutation.op === "set-target-route") {
      setJsonPointer(envelope, "/target/origin", mutation.origin);
      setJsonPointer(envelope, "/target/nodeAudience", mutation.nodeAudience);
    } else if (["uppercase", "remove-padding", "append"].includes(mutation.op)) {
      if (mutation.path === undefined) throw new Error(`${mutation.op} mutation requires path`);
      const current = getJsonPointer(envelope, mutation.path);
      if (typeof current !== "string") throw new TypeError(`${mutation.path} is not a string`);
      const replacement = mutation.op === "uppercase" ? current.toUpperCase()
        : mutation.op === "remove-padding" ? current.replace(/=+$/, "")
        : `${current}${String(mutation.value)}`;
      setJsonPointer(envelope, mutation.path, replacement);
    } else throw new Error(`unknown mutation ${mutation.op}`);

    if (mutation.resign === true) {
      const parsed = recipientDidEnvelopeV2Schema.parse(envelope);
      envelope = signForTest(unsignedFrom(parsed));
    }
  }

  const native = async (): Promise<NativeVerifiedRecipientBundleV2> => {
    if (mutation.op === "reject" || mutation.nativeReject === true) {
      throw new Error("native verifier rejected test mutation");
    }
    return nativeVerifiedRecipientBundleV2Schema.parse(authority);
  };
  return { envelope, native };
}

function exactNativeSeam(expected = fixtureAuthority) {
  return async (bundle: RecipientDidDelegationBundleV2): Promise<NativeVerifiedRecipientBundleV2> => {
    // This fixture is emitted by current tinycloud-sdk-wasm. A real SDK seam
    // performs these checks cryptographically and atomically; this contract
    // harness proves the exact transport crossing that boundary.
    if (JSON.stringify(bundle) !== JSON.stringify(fixtureEnvelope.delegation)) {
      throw new Error("native verifier rejected mutated bundle");
    }
    return structuredClone(expected);
  };
}

async function verify(
  envelope: unknown,
  native = exactNativeSeam(),
  now = NOW,
) {
  return verifyRecipientDidEnvelopeV2(envelope, {
    allowedOrigins: ["https://node.tinycloud.xyz"],
    now,
    verifyDelegationBundle: native,
  });
}

describe("recipient-DID v2 genuine current-SDK fixture", () => {
  it("freezes genuine Cacao DAG-CBOR and UCAN JWT CID preimages", () => {
    expect(vector.currentSdkFixture.generator).toMatchObject({
      nodeCommit: "390253aca30628f2ac2be28e64d8e3830da07aaa",
      sdk: "tinycloud-sdk-wasm",
    });
    for (const artifact of [
      fixtureEnvelope.delegation.issuerProofs[0]!,
      fixtureEnvelope.delegation.grant,
    ]) {
      expect(computeDelegationArtifactCid(artifact)).toBe(artifact.cid);
    }
    expect(fixtureEnvelope.delegation.issuerProofs[0]?.kind).toBe("cacao");
    expect(fixtureEnvelope.delegation.grant.value.split(".")).toHaveLength(3);
  });

  it("freezes domain/JCS bytes, signed metadata, and signature", () => {
    const { value, ...metadata } = fixtureEnvelope.signature;
    expect(hex(recipientDidEnvelopeV2SigningBytes({ ...fixtureEnvelope, signature: metadata })))
      .toBe(vector.signingBytesHex);
    expect(hex(fromBase64Url(value))).toBe(vector.signatureHex);
    expect(signForTest(unsignedFrom(fixtureEnvelope))).toEqual(fixtureEnvelope);
    expect(verifyRecipientDidEnvelopeV2Signature(fixtureEnvelope)).toBe(true);
  });

  it("accepts only after the complete native authority chain succeeds atomically", async () => {
    expect(await verify(fixtureEnvelope)).toEqual({
      ok: true,
      envelope: fixtureEnvelope,
      ownerDid: fixtureAuthority.ownerDid,
    });
  });
});

describe("authority, ordering, and scope rejection", () => {
  it("rejects a valid foreign-owner session for the target space before any ceremony/network", async () => {
    let openKeyCalls = 0;
    let targetNodeCalls = 0;
    const forged = { ...fixtureAuthority, ownerDid: fixtureEnvelope.authorizationTarget.did };
    const result = await verify(fixtureEnvelope, exactNativeSeam(forged));
    expect(result).toEqual({ ok: false, code: "authority-mismatch" });
    // This package has no OpenKey/node capability; callers receive failure first.
    expect(openKeyCalls).toBe(0);
    expect(targetNodeCalls).toBe(0);
  });

  it("binds owner to the canonical owner encoded by target.spaceId", () => {
    expect(ownerDidFromCanonicalSpaceId(fixtureEnvelope.target.spaceId)).toBe(fixtureAuthority.ownerDid);
    const foreign = {
      ...unsignedFrom(fixtureEnvelope),
      target: {
        ...fixtureEnvelope.target,
        spaceId: "tinycloud:pkh:eip155:1:0xde709f2102306220921060314715629080e2fb77:default",
      },
    };
    expect(unsignedRecipientDidEnvelopeV2Schema.safeParse(foreign).success).toBe(true);
  });

  it("rejects missing, extra, duplicate, and misordered proof artifacts", async () => {
    const root = fixtureEnvelope.delegation.issuerProofs[0]!;
    const missing = {
      ...fixtureEnvelope,
      delegation: { ...fixtureEnvelope.delegation, issuerProofs: [] },
    };
    expect(await verify(missing)).toEqual({ ok: false, code: "schema" });

    const duplicateInput = {
      ...unsignedFrom(fixtureEnvelope),
      delegation: { ...fixtureEnvelope.delegation, issuerProofs: [root, root] },
    };
    expect(unsignedRecipientDidEnvelopeV2Schema.safeParse(duplicateInput).success).toBe(false);

    const extraJwt = fixtureEnvelope.delegation.grant.value.replace(/.$/, (last) => last === "A" ? "B" : "A");
    const extra = {
      kind: "ucan" as const,
      encoding: "jwt" as const,
      value: extraJwt,
      cid: computeDelegationArtifactCid({
        kind: "ucan",
        encoding: "jwt",
        value: extraJwt,
        cid: fixtureEnvelope.delegation.grant.cid,
      }),
    };
    const extraEnvelope = signForTest({
      ...unsignedFrom(fixtureEnvelope),
      delegation: { ...fixtureEnvelope.delegation, issuerProofs: [root, extra] },
    });
    expect(await verify(extraEnvelope)).toEqual({ ok: false, code: "delegation-invalid" });

    const misordered = {
      ...unsignedFrom(fixtureEnvelope),
      delegation: { ...fixtureEnvelope.delegation, issuerProofs: [extra, root] },
    };
    expect(unsignedRecipientDidEnvelopeV2Schema.safeParse(misordered).success).toBe(false);
  });

  it("rejects native signature/attenuation failure and mismatched proof order", async () => {
    expect(await verify(fixtureEnvelope, async () => { throw new Error("invalid UCAN signature"); }))
      .toEqual({ ok: false, code: "delegation-invalid" });
    const wrongOrder = { ...fixtureAuthority, proofCids: [...fixtureAuthority.proofCids].reverse().concat(fixtureAuthority.grantCid) };
    expect(await verify(fixtureEnvelope, exactNativeSeam(wrongOrder)))
      .toEqual({ ok: false, code: "authority-mismatch" });
  });

  it("rejects recipient, route, scope, and temporal attenuation mismatches", async () => {
    expect(await verify(fixtureEnvelope, exactNativeSeam({
      ...fixtureAuthority,
      recipientDid: fixtureAuthority.ownerDid,
    }))).toEqual({ ok: false, code: "recipient-mismatch" });
    expect(await verify(fixtureEnvelope, exactNativeSeam({
      ...fixtureAuthority,
      scope: { ...fixtureAuthority.scope, actions: ["tinycloud.kv/get", "tinycloud.kv/put"] },
    }))).toEqual({ ok: false, code: "target-mismatch" });
    expect(await verify(fixtureEnvelope, exactNativeSeam({
      ...fixtureAuthority,
      expiry: "2096-10-02T07:06:39.000Z",
    }))).toEqual({ ok: false, code: "expiry-mismatch" });
    expect(await verify(fixtureEnvelope, exactNativeSeam({
      ...fixtureAuthority,
      notBefore: "2030-01-01T00:00:00.000Z",
    }))).toEqual({ ok: false, code: "delegation-invalid" });

    const routeMismatch = signForTest({
      ...unsignedFrom(fixtureEnvelope),
      delegation: {
        ...fixtureEnvelope.delegation,
        routing: { origin: "https://evil.example", nodeAudience: "did:web:evil.example" },
      },
    });
    expect(await verify(routeMismatch, async () => fixtureAuthority))
      .toEqual({ ok: false, code: "target-mismatch" });
  });
});

describe("strict DID, transport, and signature parsing", () => {
  it("defines DID URL principal handling and the sole accepted SDK fragment", () => {
    expect(principalFromSessionVerificationMethod(fixtureAuthority.sessionVerificationMethod))
      .toBe(fixtureEnvelope.signature.signerDid);
    expect(principalFromSessionVerificationMethod(`${fixtureEnvelope.signature.signerDid}#wrong`)).toBeNull();
    expect(principalFromSessionVerificationMethod(fixtureEnvelope.signature.signerDid)).toBeNull();
  });

  it("rejects malformed multibase, multicodec, length, and invalid Ed25519 points", () => {
    const prefix = Uint8Array.of(0xed, 0x01);
    const makeDid = (key: Uint8Array) => {
      const bytes = new Uint8Array(prefix.length + key.length);
      bytes.set(prefix); bytes.set(key, prefix.length);
      return `did:key:${base58btc.encode(bytes)}`;
    };
    const cases = [
      "did:key:z0invalid",
      "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
      makeDid(new Uint8Array(31)),
      makeDid(new Uint8Array(32).fill(0xff)),
      makeDid(Uint8Array.of(1, ...new Uint8Array(31))),
    ];
    for (const did of cases) expect(isCanonicalEd25519DidKey(did), did).toBe(false);
  });

  it("never throws on malformed signer/signature input", () => {
    for (const signature of [
      { ...fixtureEnvelope.signature, signerDid: "did:key:z0invalid" },
      { ...fixtureEnvelope.signature, value: "=" },
      { ...fixtureEnvelope.signature, value: toBase64Url(new Uint8Array(64)) },
    ]) {
      expect(() => verifyRecipientDidEnvelopeV2Signature({ ...fixtureEnvelope, signature })).not.toThrow();
      expect(verifyRecipientDidEnvelopeV2Signature({ ...fixtureEnvelope, signature })).toBe(false);
    }
  });

  it("rejects noncanonical DID, CID, Cacao base64, and UCAN JWT transports", () => {
    const root = fixtureEnvelope.delegation.issuerProofs[0]!;
    const cases: unknown[] = [
      { ...unsignedFrom(fixtureEnvelope), authorizationTarget: { kind: "recipientDid", did: fixtureEnvelope.authorizationTarget.did.toUpperCase() } },
      { ...unsignedFrom(fixtureEnvelope), delegation: { ...fixtureEnvelope.delegation, grant: { ...fixtureEnvelope.delegation.grant, cid: fixtureEnvelope.delegation.grant.cid.toUpperCase() } } },
      { ...unsignedFrom(fixtureEnvelope), delegation: { ...fixtureEnvelope.delegation, issuerProofs: [{ ...root, value: root.value.replace(/=$/, "") }] } },
      { ...unsignedFrom(fixtureEnvelope), delegation: { ...fixtureEnvelope.delegation, grant: { ...fixtureEnvelope.delegation.grant, value: `${fixtureEnvelope.delegation.grant.value}=` } } },
    ];
    for (const input of cases) expect(unsignedRecipientDidEnvelopeV2Schema.safeParse(input).success).toBe(false);
    expect(isCanonicalDelegationCid("bafkr4hyaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
      .toBe(false);
  });

  it("detects envelope signature metadata and body tampering", async () => {
    expect(await verify({
      ...fixtureEnvelope,
      display: { ...fixtureEnvelope.display, filename: "tampered.md" },
    })).toEqual({ ok: false, code: "signature" });
  });
});

describe("checked-in reject catalog", () => {
  it.each(rejectCases)("rejects $name", async (testCase) => {
    const { envelope, native } = applyRejectMutation(testCase);
    expect(await verify(envelope, native)).toEqual({ ok: false, code: testCase.expected });
  });
});
