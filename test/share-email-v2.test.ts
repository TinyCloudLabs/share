import { describe, expect, it } from "vitest";
import { canonicalDigest } from "../src/email-share/protocol.js";
import { canonicalize } from "@tinycloud/share-envelope";
import vectors from "./vectors/share-email-v2/vectors.json";

describe("Node share-email v2 canonical vectors", () => {
  it("matches the addressed delegation request digest", async () => {
    const vector = vectors.vectors.addressedDelegationRequest;
    expect(canonicalize(vector.body)).toBe(vector.canonicalJson);
    expect(await canonicalDigest(vector.body)).toBe(vector.requestBodyDigest);
  });

  it("matches the addressed invitation authorization request digest", async () => {
    const vector = vectors.vectors.invitationAuthorizationRequest;
    expect(canonicalize(vector.body)).toBe(vector.canonicalJson);
    expect(await canonicalDigest(vector.body)).toBe(vector.requestBodyDigest);
  });
});
