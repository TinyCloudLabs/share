import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { classifySql } from "../src/apps/sql-class.ts";

describe("classifySql: one statement, one class", () => {
  it.each([
    ["SELECT 1", "read"],
    ["select * from meal where day = ?", "read"],
    ["SELECT 1;", "read"],
    ["  SELECT 1 ;  -- trailing comment", "read"],
    ["VALUES (1), (2)", "read"],
    ["WITH recent AS (SELECT * FROM meal) SELECT count(*) FROM recent", "read"],
    ["EXPLAIN QUERY PLAN SELECT * FROM meal", "read"],
    ["EXPLAIN SELECT 1", "read"],
    ["SELECT replace(name, 'a', 'b') FROM meal", "read"],
    ["SELECT 'DROP TABLE meal; --' AS note", "read"],
    ["SELECT \"update\" FROM t", "read"],
    ["INSERT INTO meal (name) VALUES (?)", "write"],
    ["INSERT OR REPLACE INTO meal (id, name) VALUES (1, 'x')", "write"],
    ["REPLACE INTO meal (id, name) VALUES (1, 'x')", "write"],
    ["UPDATE meal SET kcal = ? WHERE id = ?", "write"],
    ["DELETE FROM meal WHERE id = 1", "write"],
    ["WITH x AS (SELECT 1) INSERT INTO meal (kcal) SELECT * FROM x", "write"],
    ["WITH x AS (SELECT 1) DELETE FROM meal WHERE id IN x", "write"],
    ["CREATE TABLE IF NOT EXISTS meal (id INTEGER PRIMARY KEY)", "schema"],
    ["CREATE VIEW v AS SELECT 1", "schema"],
    ["DROP TABLE meal", "schema"],
    ["ALTER TABLE meal ADD COLUMN x TEXT", "schema"],
    ["REINDEX", "schema"],
  ])("%s -> %s", (text, expected) => {
    expect(classifySql(text)).toBe(expected);
  });

  it.each([
    ["empty", ""],
    ["blank", "   \n"],
    ["only a comment", "-- nothing"],
    ["two statements", "SELECT 1; SELECT 2"],
    ["a write hiding after a read", "SELECT 1; DROP TABLE meal"],
    ["a write after a comment-terminated read", "SELECT 1; -- ok\nDROP TABLE meal"],
    ["a ; in a block comment does not split, but an unterminated one is refused", "SELECT 1 /* ; "],
    ["unterminated string", "SELECT 'abc"],
    ["unterminated identifier", 'SELECT "abc'],
    ["PRAGMA", "PRAGMA table_info(meal)"],
    ["PRAGMA writable_schema", "PRAGMA writable_schema = 1"],
    ["ATTACH", "ATTACH DATABASE 'other.db' AS other"],
    ["DETACH", "DETACH other"],
    ["VACUUM", "VACUUM"],
    ["VACUUM INTO", "VACUUM INTO 'x.db'"],
    ["transaction control", "BEGIN"],
    ["COMMIT", "COMMIT"],
    ["ANALYZE", "ANALYZE"],
    ["WITH ... DROP", "WITH x AS (SELECT 1) DROP TABLE meal"],
    ["WITH ... CREATE", "WITH x AS (SELECT 1) CREATE TABLE y (a)"],
    ["EXPLAIN of a write", "EXPLAIN INSERT INTO meal (name) VALUES ('x')"],
    ["EXPLAIN of a pragma", "EXPLAIN PRAGMA table_info(meal)"],
    ["a trigger body", "CREATE TRIGGER t AFTER INSERT ON meal BEGIN DELETE FROM meal; END"],
    ["parenthesised first word", "(SELECT 1)"],
    ["starts with a digit", "1; DROP TABLE meal"],
    ["not a string", undefined],
    ["a number", 5],
    ["a NUL byte", "SELECT 1\0; DROP TABLE meal"],
  ])("refuses %s", (_name, text) => {
    expect(classifySql(text)).toBeNull();
  });

  it("refuses load_extension however it is written (review findings of kit #7)", () => {
    for (const text of [
      "SELECT load_extension('x')",
      "SELECT LOAD_EXTENSION('x')",
      'SELECT "load_extension"(\'x\')',
      "SELECT [load_extension]('x')",
      "SELECT `load_extension`('x')",
      'SELECT "Load_Extension"(\'x\')',
      'SELECT "load""x"(1), "load_extension" (\'x\')',
      "SELECT 1 WHERE load_extension('x')",
      "WITH x AS (SELECT load_extension('y')) SELECT * FROM x",
    ]) expect(classifySql(text), text).toBeNull();
    // As data it is only text.
    expect(classifySql("SELECT 'load_extension' AS word")).toBe("read");
  });

  it("refuses the characters SQLite does not treat as whitespace but JavaScript does (kit #7 finding b)", () => {
    for (const space of ["\u00a0", "\u2028", "\u2029", "\u3000", "\ufeff", "\u200b", "\u0085", "\v"]) {
      expect(classifySql(`SELECT 1;${space}DROP TABLE meal`), JSON.stringify(space)).toBeNull();
      expect(classifySql(`SELECT${space}1`), JSON.stringify(space)).toBeNull();
      expect(classifySql(`${space}DROP TABLE meal`), JSON.stringify(space)).toBeNull();
    }
    // Inside a literal or a comment they are data.
    expect(classifySql("SELECT 'a\u00a0b\u2028c' AS word")).toBe("read");
    expect(classifySql("SELECT 1 -- caf\u00e9\u00a0\n")).toBe("read");
    expect(classifySql('SELECT "caf\u00e9" FROM t')).toBe("read");
  });

  it("does not let a quoted keyword make a read out of a write", () => {
    expect(classifySql('"SELECT" 1')).toBeNull();
    expect(classifySql("DELETE FROM meal WHERE name = 'SELECT'")).toBe("write");
    expect(classifySql("SELECT 1 /* DROP TABLE meal */")).toBe("read");
  });

  it("accepts the statements the sample apps send", () => {
    for (const text of [
      "SELECT day, kcal, protein_g FROM day_card WHERE day = ?",
      "INSERT INTO meal (op_id, day, slot, name, kcal, logged_at) VALUES (?, ?, ?, ?, ?, ?)",
      "CREATE TABLE IF NOT EXISTS weight (id INTEGER PRIMARY KEY AUTOINCREMENT, kg REAL NOT NULL)",
      "CREATE VIEW IF NOT EXISTS day_card AS SELECT day, sum(kcal) AS kcal FROM meal GROUP BY day",
    ]) expect(classifySql(text)).not.toBeNull();
  });

  it("classifies the real schema files of the catalog's samples statement by statement as schema, never read or write", () => {
    // The apps run each CREATE as its own execute call: every one of them is a "schema" statement.
    const schema = readFileSync("public/apps/b/e807668820cd592646e21fc88f15aa30ab5fcec196bbdec0dafd52b12c343fa4/schema.sql", "utf8");
    const withoutComments = schema.replace(/--[^\n]*/g, "");
    const statements = withoutComments.split(/;\s*(?:\n|$)/).map((part) => part.trim()).filter((part) => part !== "" && !/\bTRIGGER\b/i.test(part));
    expect(statements.length).toBeGreaterThan(3);
    for (const statement of statements) expect(classifySql(statement), statement.slice(0, 60)).toBe("schema");
  });
});
