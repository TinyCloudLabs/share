import { describe, expect, it } from "vitest";

import { normalizeExactEmail } from "./email.js";

describe("normalizeExactEmail", () => {
  it("preserves the local part and lowercases the domain", () => {
    expect(normalizeExactEmail("Alice.O+Notes@EXAMPLE.COM")).toBe(
      "Alice.O+Notes@example.com",
    );
  });

  it("accepts a 64-byte local part", () => {
    const input = `${"a".repeat(64)}@example.com`;
    expect(normalizeExactEmail(input)).toBe(input);
  });

  it("accepts a total length of exactly 254 bytes", () => {
    const domain = `${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.${"e".repeat(60)}`;
    expect(normalizeExactEmail(`a@${domain}`)).toBe(`a@${domain}`);
  });

  const rejects: Array<[string, string]> = [
    ["leading whitespace", " Alice@example.com"],
    ["trailing whitespace", "Alice@example.com "],
    ["tab", "Alice@\texample.com"],
    ["newline", "Alice@example.com\n"],
    ["interior whitespace", "Alice Notes@example.com"],
    ["leading dot in local", ".Alice@example.com"],
    ["trailing dot in local", "Alice.@example.com"],
    ["repeated dot in local", "Alice..Notes@example.com"],
    ["empty local", "@example.com"],
    ["empty domain", "Alice@"],
    ["multiple @", "Alice@gmail.com@example.com"],
    ["quoted local", '"Alice"@example.com'],
    ["commented local", "Alice(comment)@example.com"],
    ["backslash in local", "Alice\\Bob@example.com"],
    ["angle-address form", "Alice <alice@example.com>"],
    ["unicode local", "álíce@example.com"],
    ["unicode domain", "Alice@bücher.example"],
    ["local over 64 bytes", `${"a".repeat(65)}@example.com`],
    ["label over 63 bytes", `Alice@${"a".repeat(64)}.com`],
    ["empty domain label", "Alice@example..com"],
    ["trailing domain dot", "Alice@example.com."],
    ["leading hyphen label", "Alice@-example.com"],
    ["trailing hyphen label", "Alice@example-.com"],
  ];

  for (const [name, input] of rejects) {
    it(`rejects ${name}`, () => {
      expect(normalizeExactEmail(input)).toBeNull();
    });
  }

  it("rejects a domain over 253 bytes", () => {
    const domain253 = `${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.${"e".repeat(61)}`;
    expect(normalizeExactEmail(`a@${domain253}x`)).toBeNull();
  });

  it("rejects a total length over 254 bytes", () => {
    const domain252 = `${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.${"e".repeat(60)}`;
    expect(normalizeExactEmail(`aa@${domain252}`)).toBeNull();
  });
});
