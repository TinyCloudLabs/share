import { describe, expect, it } from "vitest";

import { createKvSource, createSqlSource } from "./content-source.js";

const SPACE = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";

describe("createKvSource", () => {
  it("builds a strict KV source", () => {
    expect(createKvSource(SPACE, "documents/plan.md")).toEqual({
      kind: "kv",
      space: SPACE,
      path: "documents/plan.md",
      action: "tinycloud.kv/get",
    });
  });

  it("rejects a non-DID space", () => {
    expect(() => createKvSource("not-a-did", "documents/plan.md")).toThrow();
  });

  it("rejects a path with traversal segments", () => {
    expect(() => createKvSource(SPACE, "../secret")).toThrow();
  });

  it("rejects a path with a leading slash", () => {
    expect(() => createKvSource(SPACE, "/documents/plan.md")).toThrow();
  });
});

describe("createSqlSource", () => {
  it("builds a strict SQL source with a computed arguments digest", async () => {
    const source = await createSqlSource({
      space: SPACE,
      database: "documents",
      path: "shared/plan",
      statement: "shared_document_by_id",
      arguments: { document_id: 123 },
    });
    expect(source).toMatchObject({
      kind: "sql",
      space: SPACE,
      database: "documents",
      path: "shared/plan",
      statement: "shared_document_by_id",
      arguments: { document_id: 123 },
      action: "tinycloud.sql/read",
    });
    // Known digest from test/vectors/email-claim-v1/positive.json scenario "sql".
    expect(source.argumentsDigest).toBe("Wvt9ycf107Id2Qe58i0BnWykVBsdjhyS03P2psS0bSg");
  });

  it("rejects raw-SQL-shaped statement names", async () => {
    await expect(
      createSqlSource({
        space: SPACE,
        database: "documents",
        path: "shared/plan",
        statement: "SELECT * FROM documents",
        arguments: {},
      }),
    ).rejects.toThrow();
  });

  it("rejects fractional SQL arguments", async () => {
    await expect(
      createSqlSource({
        space: SPACE,
        database: "documents",
        path: "shared/plan",
        statement: "shared_document_by_id",
        arguments: { document_id: 1.5 },
      }),
    ).rejects.toThrow();
  });

  it("rejects negative-zero SQL arguments", async () => {
    await expect(
      createSqlSource({
        space: SPACE,
        database: "documents",
        path: "shared/plan",
        statement: "shared_document_by_id",
        arguments: { document_id: -0 },
      }),
    ).rejects.toThrow();
  });

  it("rejects more than 32 arguments", async () => {
    const arguments_: Record<string, number> = {};
    for (let i = 0; i < 33; i++) arguments_[`arg${i}`] = i;
    await expect(
      createSqlSource({
        space: SPACE,
        database: "documents",
        path: "shared/plan",
        statement: "shared_document_by_id",
        arguments: arguments_,
      }),
    ).rejects.toThrow();
  });
});
