import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { MAX_DEPTH, canonicalJson, requestHash } from "../src/courier/canonical.ts";
import { parseRequest, MAX_ACTION, MAX_REASON, MAX_RISK, MAX_SUMMARY, MAX_TARGET } from "../src/courier/model.ts";

/**
 * The contract shared with js-sdk packages/courier (test/vectors/request-fields.json, copied byte for byte): the CLI
 * and this view must accept and refuse exactly the same stored values, and hash exactly the same JSON.
 */
interface FieldRow { readonly name: string; readonly field: "summary" | "target"; readonly verb?: string; readonly value: unknown; readonly valid: boolean }
interface IdRow { readonly name: string; readonly value: string; readonly valid: boolean }
interface CanonicalRow { readonly name: string; readonly json: string; readonly canonical: string | null; readonly sha256?: string }
const vectors = JSON.parse(readFileSync("test/vectors/courier-request-fields.json", "utf8")) as { readonly limits: Record<string, number>; readonly fields: FieldRow[]; readonly ids: IdRow[] };
const canonicalVectors = JSON.parse(readFileSync("test/vectors/courier-canonical.json", "utf8")) as { readonly limits: Record<string, number>; readonly vectors: CanonicalRow[] };

const THREAD = "01J9ZC4K7T3QZ5W6M8R2N1B010";
const base = { id: "01J9ZC4K7T3QZ5W6M8R2N1B030", peer: "hunter", threadId: THREAD, taskId: "01J9ZC4K7T3QZ5W6M8R2N1B022", verb: "merge", target: "o/r#1", summary: "ok", action: "a", reason: "r", risk: "k", requestedBy: { owner: "did:pkh:x", agent: "did:key:y" }, status: "pending", createdAt: "2026-10-20T10:00:00Z", expiresAt: "2026-10-21T10:00:00Z" };

describe("the shared request-field vectors", () => {
  it("use the limits this view uses", () => {
    expect(vectors.limits).toMatchObject({ summary: MAX_SUMMARY, target: MAX_TARGET, action: MAX_ACTION, reason: MAX_REASON, risk: MAX_RISK, combiningRun: 0 });
    expect(canonicalVectors.limits).toMatchObject({ depth: MAX_DEPTH });
  });
  for (const row of vectors.ids) {
    // The request id, its thread id and its task id must all be ULIDs, written and read (the CLI refuses anything else).
    it(`ids: ${row.name} is ${row.valid ? "accepted" : "refused"}`, () => {
      expect(parseRequest(row.value, { ...base, id: row.value }) !== undefined, "id as the key's own id").toBe(row.valid);
      expect(parseRequest(base.id, { ...base, threadId: row.value }) !== undefined, "threadId").toBe(row.valid);
      expect(parseRequest(base.id, { ...base, taskId: row.value }) !== undefined, "taskId").toBe(row.valid);
    });
  }
  for (const row of vectors.fields) {
    it(`${row.field}: ${row.name} is ${row.valid ? "accepted" : "refused"} as stored`, () => {
      const request = row.field === "summary" ? { ...base, summary: row.value } : { ...base, verb: row.verb, target: row.value };
      const parsed = parseRequest(base.id, request);
      expect(parsed, "the request itself is still readable").toBeDefined();
      expect(parsed?.what !== undefined).toBe(row.valid);
      expect(parsed?.problem).toBe(row.valid ? undefined : "fields");
    });
  }
  for (const row of canonicalVectors.vectors) {
    it(`canonical JSON: ${row.name}`, async () => {
      if (row.canonical === null) {
        expect(() => canonicalJson(JSON.parse(row.json))).toThrow();
        return;
      }
      expect(canonicalJson(JSON.parse(row.json))).toBe(row.canonical);
      // the digest an approval carries is the SHA-256 of exactly that string
      if (row.sha256 !== undefined) expect(await requestHash(JSON.parse(row.json))).toBe(row.sha256);
    });
  }
});
