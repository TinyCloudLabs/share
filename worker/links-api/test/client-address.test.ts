import { describe, expect, it } from "vitest";
import { CLIENT_IP, addressHeader, clientAddressFor, get, makeIssuer, signedCreate, signedDelete, take } from "./support/client.ts";

const HEADER = "CF-Connecting-IP";
const NOW = Date.UTC(2026, 9, 24, 12, 0, 0);

describe("the test client's address header", () => {
  describe("clientAddressFor(base URL)", () => {
    it.each([
      ["http://127.0.0.1:8799", CLIENT_IP],
      ["http://localhost:8799", CLIENT_IP],
      ["http://[::1]:8799", CLIENT_IP],
      ["http://127.0.0.1", CLIENT_IP],
    ])("a local base %s sends the test address", (base, expected) => {
      expect(clientAddressFor(base)).toBe(expected);
    });

    it.each([
      "https://api.tinycloud.xyz",
      "https://api.tinycloud.xyz/",
      "https://example.com",
      "http://127.0.0.2:8811",
      "http://localhost.example.com",
      "https://127.0.0.1.example.com",
      "http://192.0.2.10:8787",
    ])("a non-local base %s sends no address", (base) => {
      expect(clientAddressFor(base)).toBeNull();
    });
  });

  describe("requests built by the helpers", () => {
    it("send the header by default, so in-process runs keep their per-address keys", async () => {
      const issuer = makeIssuer();
      expect((await signedCreate({ issuer, nowMs: NOW })).headers.get(HEADER)).toBe(CLIENT_IP);
      expect((await signedDelete({ issuer, id: "a".repeat(26), nowMs: NOW })).headers.get(HEADER)).toBe(CLIENT_IP);
      expect(get("a".repeat(26)).headers.get(HEADER)).toBe(CLIENT_IP);
      expect(take("a".repeat(26)).headers.get(HEADER)).toBe(CLIENT_IP);
    });

    it("send the address they are given", async () => {
      const issuer = makeIssuer();
      expect((await signedCreate({ issuer, nowMs: NOW, ip: "203.0.113.7" })).headers.get(HEADER)).toBe("203.0.113.7");
      expect((await signedDelete({ issuer, id: "a".repeat(26), nowMs: NOW, ip: "203.0.113.8" })).headers.get(HEADER)).toBe("203.0.113.8");
      expect(get("a".repeat(26), "203.0.113.9").headers.get(HEADER)).toBe("203.0.113.9");
      expect(take("a".repeat(26), "203.0.113.10").headers.get(HEADER)).toBe("203.0.113.10");
    });

    it("send no address header when the address is null, and keep every other header", async () => {
      const issuer = makeIssuer();
      const create = await signedCreate({ issuer, nowMs: NOW, ip: null, headers: { Origin: "https://share.tinycloud.xyz" } });
      expect(create.headers.has(HEADER)).toBe(false);
      expect(create.headers.get("Content-Type")).toBe("application/json");
      expect(create.headers.get("Origin")).toBe("https://share.tinycloud.xyz");
      const del = await signedDelete({ issuer, id: "a".repeat(26), nowMs: NOW, ip: null });
      expect(del.headers.has(HEADER)).toBe(false);
      expect(del.headers.get("Content-Type")).toBe("application/json");
      expect(get("a".repeat(26), null).headers.has(HEADER)).toBe(false);
      expect(take("a".repeat(26), null).headers.has(HEADER)).toBe(false);
    });

    it("send none for the live API's base URL and one for a local Worker's, as the smoke script chooses", async () => {
      const issuer = makeIssuer();
      const live = await signedCreate({ issuer, nowMs: NOW, ip: clientAddressFor("https://api.tinycloud.xyz") });
      const local = await signedCreate({ issuer, nowMs: NOW, ip: clientAddressFor("http://127.0.0.1:8799") });
      expect(live.headers.has(HEADER)).toBe(false);
      expect(local.headers.get(HEADER)).toBe(CLIENT_IP);
    });
  });

  it("addressHeader builds the one header or none", () => {
    expect(addressHeader("198.51.100.1")).toEqual({ [HEADER]: "198.51.100.1" });
    expect(addressHeader(null)).toEqual({});
  });
});
