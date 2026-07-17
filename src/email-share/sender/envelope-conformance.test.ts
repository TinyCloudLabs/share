/** Conformance checks pinned to manifest OPUK0AVTonxQIkx6jBdiiQmIRZN5n4tNm_OpDzIuoT0. */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";
import {
  fromBase64Url,
  parseShareUrl,
  shareEnvelopeSchema,
} from "@tinycloud/share-envelope";

import {
  assertSqlArgumentsDigest,
  createSqlSource,
  type SourceSql,
} from "./content-source.js";
import { canonicalDigest } from "./digest.js";
import { requestNodeAuthorization } from "./node-authorization-client.js";
import { prepareInvitationInputs } from "./invitation-input.js";
import { shippingVerifiedEnvelope } from "./envelope-fixture.test-support.js";

const PINNED_MANIFEST_DIGEST = "OPUK0AVTonxQIkx6jBdiiQmIRZN5n4tNm_OpDzIuoT0";
const vectorsDir = resolve(dirname(fileURLToPath(import.meta.url)), "../../../test/vectors/email-claim-v1");

type FrozenScenario = {
  readonly kind: "kv" | "sql";
  readonly shareCid: string;
  readonly envelopeKey: string;
  readonly sealedBlob: string;
  readonly envelope: unknown;
  readonly authorization: Record<string, unknown>;
};
type NegativeCase = { readonly id: string; readonly mutationData: Record<string, unknown> };

function readJson(name: string): unknown {
  return JSON.parse(readFileSync(resolve(vectorsDir, name), "utf8"));
}

const manifest = readJson("manifest.json") as { files: Record<string, string>; manifestDigest: string };
const positive = readJson("positive.json") as { scenarios: FrozenScenario[] };
const negative = readJson("negative.json") as { cases: NegativeCase[] };

function scenario(kind: "kv" | "sql"): FrozenScenario {
  const found = positive.scenarios.find((candidate) => candidate.kind === kind);
  if (!found) throw new Error(`missing positive scenario ${kind}`);
  return found;
}

function negativeCase(id: string): NegativeCase {
  const found = negative.cases.find((candidate) => candidate.id === id);
  if (!found) throw new Error(`missing negative vector ${id}`);
  return found;
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("email-claim-v1 manifest and serialized rows", () => {
  it("pins the manifest and negative bytes", async () => {
    const negativeBytes = readFileSync(resolve(vectorsDir, "negative.json"));
    expect(createHash("sha256").update(negativeBytes).digest("base64url")).toBe(
      manifest.files["negative.json"],
    );
    const { manifestDigest, ...manifestCore } = manifest;
    expect(await canonicalDigest(manifestCore)).toBe(manifestDigest);
    expect(manifestDigest).toBe(PINNED_MANIFEST_DIGEST);
  });

  it("parses the frozen serialized envelope row with the shipping schema", () => {
    expect(shareEnvelopeSchema.parse(scenario("kv").envelope)).toEqual(scenario("kv").envelope);
    expect(shareEnvelopeSchema.parse(scenario("sql").envelope)).toEqual(scenario("sql").envelope);
  });

  it("documents the frozen byte-identical blob at the S5 compatibility boundary", async () => {
    const frozen = scenario("kv");
    await expect(
      (async () => {
        const { VerifiedEnvelopeInputs } = await import("./invitation-input.js");
        return VerifiedEnvelopeInputs.fromSealedEnvelope({
          sealedBlob: fromBase64Url(frozen.sealedBlob),
          shareCid: frozen.shareCid,
          fragmentKey: fromBase64Url(frozen.envelopeKey),
          expectedSignerDid: "did:key:z6MktwtqAzuD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG7",
        });
      })(),
    ).rejects.toThrow(/signature verification failed/);
  });

  it("uses shipping sign/seal for positive factory coverage, not the frozen blob", async () => {
    const verified = await shippingVerifiedEnvelope("kv");
    const prepared = await prepareInvitationInputs(verified);
    expect(prepared.policyCid).toBe("bafkreiaqkcd56bhbn3zwcx7r5xdkle2nukcrhkvwwrcg4qqehk6q5hlwi4");
    expect(prepared.documentName).toBe("Project plan.md");
  });
});

describe("named negative rows through production sender parsers", () => {
  it("rejects share-url-noncanonical-k through parseShareUrl", () => {
    const row = negativeCase("share-url-noncanonical-k");
    const values = row.mutationData.valueByKind as { kv: string; sql: string };
    expect(() => parseShareUrl(values.kv, { expectedOrigin: "https://share.tinycloud.xyz" })).toThrow();
    expect(() => parseShareUrl(values.sql, { expectedOrigin: "https://share.tinycloud.xyz" })).toThrow();
  });

  it("rejects noncanonical-b64url-16-tail through the node response parser", async () => {
    const row = negativeCase("noncanonical-b64url-16-tail");
    const value = row.mutationData.value as string;
    const base = scenario("kv");
    const prepared = await prepareInvitationInputs(await shippingVerifiedEnvelope("kv"));
    await expect(
      requestNodeAuthorization("https://node.example/share/v1/invitations/authorize", prepared.authorizationRequest, {
        fetchFn: async () => jsonResponse(200, {
          authorization: { ...base.authorization, jti: value },
          proof: { alg: "EdDSA", kid: "did:web:node.example#invitation-key-1", signature: "jL6f77-Kddr2DlUWrSMtnQ8DHnKiR4NkvWmVS-6zvLMpKmsz7qllGICQ_DZiJmJEwCEShijWhOramvMA9ix9Bw" },
        }),
      }),
    ).rejects.toThrow();
  });

  it("rejects noncanonical-b64url-64-tail through the node response parser", async () => {
    const row = negativeCase("noncanonical-b64url-64-tail");
    const value = row.mutationData.value as string;
    const base = scenario("kv");
    const prepared = await prepareInvitationInputs(await shippingVerifiedEnvelope("kv"));
    await expect(
      requestNodeAuthorization("https://node.example/share/v1/invitations/authorize", prepared.authorizationRequest, {
        fetchFn: async () => jsonResponse(200, {
          authorization: base.authorization,
          proof: { alg: "EdDSA", kid: "did:web:node.example#invitation-key-1", signature: value },
        }),
      }),
    ).rejects.toThrow();
  });

  it("rejects wrong-source-digest through SQL source parsing and digest binding", async () => {
    const row = negativeCase("wrong-source-digest");
    const mutation = row.mutationData as { field: string; value: number };
    const source = await createSqlSource({
      space: "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
      database: "documents",
      path: "shared/plan",
      statement: "shared_document_by_id",
      arguments: { document_id: 123 },
    });
    const [, argumentName] = mutation.field.split(".");
    if (!argumentName) throw new Error("malformed source mutation row");
    const tampered: SourceSql = { ...source, arguments: { ...source.arguments, [argumentName]: mutation.value } };
    await expect(assertSqlArgumentsDigest(tampered)).rejects.toThrow(TypeError);
  });

  it("rejects document-name-over-200-utf8 through the node response parser", async () => {
    const row = negativeCase("document-name-over-200-utf8");
    const candidates = row.mutationData.candidateArtifactByKind as {
      kv: { message: Record<string, unknown> };
      sql: { message: Record<string, unknown> };
    };
    const prepared = await prepareInvitationInputs(await shippingVerifiedEnvelope("kv"));
    await expect(
      requestNodeAuthorization("https://node.example/share/v1/invitations/authorize", prepared.authorizationRequest, {
        fetchFn: async () => jsonResponse(200, {
          authorization: candidates.kv.message,
          proof: { alg: "EdDSA", kid: "did:web:node.example#invitation-key-1", signature: "jL6f77-Kddr2DlUWrSMtnQ8DHnKiR4NkvWmVS-6zvLMpKmsz7qllGICQ_DZiJmJEwCEShijWhOramvMA9ix9Bw" },
        }),
      }),
    ).rejects.toThrow();
  });
});
