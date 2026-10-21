import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { noteFitsToSave, parseRequest, strictText } from "../src/courier/model.ts";
import { TEXT_UNICODE_VERSION } from "../src/courier/text-ranges.ts";
import { textVerdict, type TextField, type TextVerdict } from "../src/courier/text.ts";

interface Sample extends TextVerdictShape { readonly field: TextField; readonly value: unknown }
interface TextVerdictShape { readonly allowed: boolean; readonly reason: string | null }
const vectors = JSON.parse(readFileSync("test/vectors/courier-text-verdicts.json", "utf8")) as {
  readonly unicodeVersion: string;
  readonly ranges: readonly (readonly [number, number, number])[];
  readonly samples: readonly Sample[];
};
const fields: readonly TextField[] = ["summary", "multiline", "target"];
const base = { id: "01J9ZC4K7T3QZ5W6M8R2N1B030", peer: "hunter", threadId: "01J9ZC4K7T3QZ5W6M8R2N1B010", taskId: "01J9ZC4K7T3QZ5W6M8R2N1B022", verb: "merge", target: "o/r#1", summary: "ok", action: "a", reason: "r", risk: "k", requestedBy: { owner: "did:pkh:x", agent: "did:key:y" }, status: "pending", createdAt: "2026-10-20T10:00:00Z", expiresAt: "2026-10-21T10:00:00Z" };

describe("the shared frozen text verdicts", () => {
  it("checks every code point in every inclusive vector range for all three fields", () => {
    expect(TEXT_UNICODE_VERSION).toBe("15.0.0");
    expect(vectors.unicodeVersion).toBe(TEXT_UNICODE_VERSION);
    let next = 0;
    for (const [start, end, mask] of vectors.ranges) {
      expect(start).toBe(next);
      expect(end).toBeGreaterThanOrEqual(start);
      for (let cp = start; cp <= end; cp += 1) {
        for (const [index, field] of fields.entries()) {
          const actual = textVerdict(`a${String.fromCodePoint(cp)}a`, field);
          if (actual.allowed !== Boolean(mask & (1 << index))) throw new Error(`${field} differs at U+${cp.toString(16)}`);
        }
      }
      next = end + 1;
    }
    expect(next).toBe(0x110000);
  }, 30_000);

  for (const [index, row] of vectors.samples.entries()) {
    it(`full-string sample ${index}: ${row.field} / ${row.reason ?? "allowed"}`, () => {
      expect(textVerdict(row.value, row.field)).toEqual({ allowed: row.allowed, reason: row.reason } satisfies TextVerdictShape);
      if (row.field === "summary") {
        expect(parseRequest(base.id, { ...base, summary: row.value })?.what !== undefined).toBe(row.allowed);
      }
      if (row.field === "multiline") {
        expect(strictText(row.value, 2000, { lines: true }) !== undefined).toBe(row.allowed);
        for (const field of ["action", "reason", "risk"]) {
          expect(parseRequest(base.id, { ...base, [field]: row.value })?.problem === undefined, field).toBe(row.allowed);
        }
        if (typeof row.value === "string") expect(noteFitsToSave(row.value)).toBe(row.value === "" || row.allowed);
      }
    });
  }
  it("refuses non-string values with the shared reason", () => {
    expect(textVerdict(3, "summary")).toEqual({ allowed: false, reason: "not-string" } satisfies TextVerdict);
  });
});
