/**
 * Test-only helpers for building real {@link VerifiedEnvelopeInputs}
 * instances — via the actual sealed-envelope factory, never a cast or
 * plain-object shortcut.
 *
 * IMPORTANT KNOWN LIMITATION (see envelope-conformance.test.ts's
 * "fixture/package signing-scheme mismatch" block for the executable
 * proof): the frozen, manifest-pinned test/vectors/email-claim-v1
 * positive.json `sealedBlob`/`envelope`/`envelopeKey` fixtures are signed
 * by test/vectors/email-claim-v1/validate.mjs with DOMAIN-SEPARATED bytes
 * (`domain-string || JCS(message)`, e.g. `"xyz.tinycloud.share/envelope/v1\0"`).
 * The shipped `@tinycloud/share-envelope` package's `signEnvelope`/
 * `verifyEnvelope` (packages/envelope/src/sign.ts) sign/verify PLAIN
 * `JCS(unsigned)` with NO domain separation. These are two different,
 * mutually-incompatible signature schemes, so the frozen fixture's OWN
 * `sealedBlob` can never pass `verifyEnvelope` from the shipped package —
 * not a bug in this module, and not fixable here: fixing it needs either
 * the envelope package (out of scope: "envelope" is excluded from this
 * repair) or regenerated fixtures (out of scope: "fixture" files are
 * excluded). `test/vectors/email-claim-v1/domains.json` and `schemas.json`,
 * which the manifest itself references, are additionally missing from the
 * fixture directory entirely.
 *
 * {@link positiveUnsignedEnvelope} + {@link sealShippingCompatibleEnvelope} therefore reuse
 * the frozen fixture's exact plaintext field VALUES (policy, contentSource,
 * target, display, expiry, shareId — everything except the signature bytes
 * themselves) and re-sign/re-seal them with the shipped package's OWN
 * compatible signEnvelope/seal, so the real verifyCid → open → parse →
 * verifyEnvelope chain can still be exercised end to end against
 * fixture-sourced data.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  fromBase64Url,
  seal,
  signEnvelope,
  type UnsignedShareEnvelope,
} from "@tinycloud/share-envelope";

export const ISSUER_DID = "did:key:z6MktwtqAzuD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG7";
// build.mjs uses 0x44 repeated for the frozen sender. Reusing that seed with
// the shipping signEnvelope keeps the frozen issuerDid/policy semantics
// intact while deliberately producing a different, shipping-compatible
// sealed blob.
const TEST_SEED = new Uint8Array(32).fill(0x44);

const vectorsDir = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../test/vectors/email-claim-v1",
);

interface PositiveScenario {
  readonly kind: "kv" | "sql";
  readonly envelopeKey: string;
  readonly envelope: UnsignedShareEnvelope & { readonly signature: unknown };
}

let cachedScenarios: PositiveScenario[] | undefined;

function positiveScenarios(): PositiveScenario[] {
  if (cachedScenarios === undefined) {
    const positive = JSON.parse(
      readFileSync(resolve(vectorsDir, "positive.json"), "utf8"),
    ) as { scenarios: PositiveScenario[] };
    cachedScenarios = positive.scenarios;
  }
  return cachedScenarios;
}

/**
 * The frozen fixture's own UNSIGNED envelope body (shareId, delegation,
 * authorizationTarget with its policyCid/policyBytes, target, display,
 * expiry) for the given scenario — every field except the signature,
 * copied byte-for-byte from positive.json.
 */
export function positiveUnsignedEnvelope(kind: "kv" | "sql"): UnsignedShareEnvelope {
  const found = positiveScenarios().find((s) => s.kind === kind);
  if (!found) throw new Error(`missing positive fixture scenario: ${kind}`);
  const { signature: _signature, ...unsigned } = found.envelope;
  return unsigned;
}

type ShippingCompatibleSealedEnvelope = {
  readonly sealedBlob: Uint8Array;
  readonly shareCid: string;
  readonly fragmentKey: Uint8Array;
  readonly signerDid: string;
}

/**
 * Sign and seal the frozen positive envelope body with the shipping package.
 * The policy/body/key values come from the frozen scenario; only the
 * signature scheme and AEAD nonce differ from the byte-identical fixture.
 */
export async function sealShippingCompatibleEnvelope(
  unsigned: UnsignedShareEnvelope,
): Promise<ShippingCompatibleSealedEnvelope> {
  const envelope = signEnvelope(unsigned, TEST_SEED);
  const scenario = positiveScenarios().find(
    (candidate) => candidate.envelope.shareId === unsigned.shareId,
  );
  if (!scenario) throw new Error(`missing positive fixture key for ${unsigned.shareId}`);
  const fragmentKey = fromBase64Url(scenario.envelopeKey);
  const plaintext = new TextEncoder().encode(JSON.stringify(envelope));
  const { blob, cid } = await seal(plaintext, fragmentKey);
  return { sealedBlob: blob, shareCid: cid, fragmentKey, signerDid: envelope.signature.signerDid };
}

/** Build a nominal value through the production verification factory. */
export async function shippingVerifiedEnvelope(kind: "kv" | "sql") {
  return shippingVerifiedEnvelopeFrom(positiveUnsignedEnvelope(kind));
}

export async function shippingVerifiedEnvelopeFrom(unsigned: UnsignedShareEnvelope) {
  const sealed = await sealShippingCompatibleEnvelope(unsigned);
  const { VerifiedEnvelopeInputs } = await import("./invitation-input.js");
  return VerifiedEnvelopeInputs.fromSealedEnvelope({
    sealedBlob: sealed.sealedBlob,
    shareCid: sealed.shareCid,
    fragmentKey: sealed.fragmentKey,
    expectedSignerDid: sealed.signerDid,
  });
}
