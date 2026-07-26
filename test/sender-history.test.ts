import { describe, expect, it } from "vitest";
import { createSenderHistoryRecord, validateSenderHistoryRecord } from "../src/share/sender-history.js";

const base = {
  id: "sender-entry-00000001",
  url: "https://share.tinycloud.xyz/s/bafkreigdyrzt2abcde#k=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  cid: "bafybeigdyrzt5example",
  format: "compact" as const,
  createdAt: "2026-07-24T12:00:00.000Z",
  expiresAt: "2026-07-31T12:00:00.000Z",
  name: "notes.md",
  mediaType: "text/markdown",
  sourceKind: "upload" as const,
  recipient: { kind: "bearer" as const },
  actions: ["read"] as const,
};

describe("sender history records", () => {
  it("canonicalizes and round-trips an exact link inside the record", async () => {
    const record = await createSenderHistoryRecord(base);
    expect(record.url).toBe(base.url);
    expect(record.urlDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(validateSenderHistoryRecord(record)).toEqual(record);
  });

  it("rejects unknown fields, invalid timestamps, and invalid recipient enums", () => {
    expect(() => validateSenderHistoryRecord({ ...base, type: "future", version: 1, urlDigest: "x" })).toThrow(/invalid/i);
    expect(() => validateSenderHistoryRecord({ ...base, type: "TinyCloudShareSenderHistory", version: 1, urlDigest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", createdAt: "not-a-time" })).toThrow(/invalid/i);
    expect(() => validateSenderHistoryRecord({ ...base, type: "TinyCloudShareSenderHistory", version: 1, urlDigest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", recipient: { kind: "exactEmail", value: "" } })).toThrow(/invalid/i);
  });

  it("bounds oversized URLs before persistence", () => {
    expect(() => validateSenderHistoryRecord({ ...base, type: "TinyCloudShareSenderHistory", version: 1, urlDigest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", url: `https://share.tinycloud.xyz/s/${"a".repeat(70_000)}` })).toThrow(/invalid/i);
  });
});
