import { describe, expect, it } from "vitest";

import { SAVE_FILE_NAME_MAX, SAVE_FILE_TYPES, checkSaveFile, fileSizeLabel } from "../src/apps/save-file.ts";
import { file } from "../src/artifact/jsx-runtime/app-module.ts";

const accepted = (args: Record<string, unknown>) => {
  const result = checkSaveFile(args);
  if (!result.ok) throw new Error(`refused: ${result.message}`);
  return result.file;
};
const refused = (args: Record<string, unknown>): string => {
  const result = checkSaveFile(args);
  if (result.ok) throw new Error(`accepted ${JSON.stringify(args).slice(0, 80)}`);
  return result.message;
};

describe("file.save: what the runner accepts", () => {
  it("takes the type from the extension when the app leaves it out", () => {
    expect(accepted({ name: "people.vcf", body: "BEGIN:VCARD\r\nEND:VCARD\r\n" }).type).toBe("text/vcard");
    expect(accepted({ name: "people.JSON", body: "{}" }).type).toBe("application/json");
    expect(accepted({ name: "notes.md", body: "# hi" }).type).toBe("text/markdown");
    expect(accepted({ name: "data.json", body: "{}" }).type).toBe("application/json");
    expect(accepted({ name: "readme.txt", body: "x" }).type).toBe("text/plain");
  });

  it("accepts an explicit type that agrees with the name, with spaces and non-ASCII letters in the name", () => {
    const file = accepted({ name: "Müller, Anna (2024).vcf", type: "text/vcard", body: "x" });
    expect(file).toMatchObject({ name: "Müller, Anna (2024).vcf", type: "text/vcard" });
  });

  it("holds a string as UTF-8 and copies bytes so the frame's buffer is not what gets saved", () => {
    expect([...accepted({ name: "a.txt", body: "é" }).bytes]).toEqual([0xc3, 0xa9]);
    const source = new Uint8Array([1, 2, 3]);
    const file = accepted({ name: "a.txt", body: source });
    source[0] = 9;
    expect([...file.bytes]).toEqual([1, 2, 3]);
  });

  it("allows a name of exactly the longest length", () => {
    expect(accepted({ name: `${"a".repeat(SAVE_FILE_NAME_MAX - 4)}.txt`, body: "x" }).name.length).toBe(SAVE_FILE_NAME_MAX);
  });
});

describe("file.save: what the runner refuses before the owner sees anything", () => {
  it.each([
    "../x.txt", "a/b.txt", "a\\b.txt", "C:evil.txt", "a:b.txt", "a*.txt", "a?.txt", 'a".txt', "<a>.txt", "a|b.txt",
    "a\u0000.txt", "a\n.txt", "a\u202egpj.txt", "a\u200b.txt", "\ufeffa.txt", "a\u2066.txt", "a\u2028b.txt", "a\u2029b.txt", "a\ud800b.txt", "a\udc00b.txt",
  ])("a name with a path, a character Windows refuses or a hidden character: %j", (name) => {
    expect(refused({ name, body: "x" })).toMatch(/file name/i);
  });

  it.each([".hidden.txt", "a.txt.", " a.txt", "a.txt ", "", "x".repeat(SAVE_FILE_NAME_MAX + 1)])("a name that starts or ends oddly, or is empty or too long: %j", (name) => {
    refused({ name, body: "x" });
  });

  it.each(["CON.txt", "nul.txt", "Com1.json", "LPT9.json", "aux.md", "prn.vcf", "COM\u00b9.txt", "LPT\u00b2.json", "CON .txt", "nul  .md", "\uff23\uff2f\uff2e.txt"])("a Windows device name, as Windows reads it: %j", (name) => {
    expect(refused({ name, body: "x" })).toMatch(/reserved/);
  });

  it.each(["page.html", "image.svg", "run.js", "tool.exe", "a.bat", "a.sh", "a.zip", "a.pdf", "a.xhtml", "a.hta", "noextension", "a.txt.exe", "people.csv", "a.CSV"])("a file that is not on the type list (CSV too: a spreadsheet runs =, +, - and @ cells): %s", (name) => {
    refused({ name, body: "x" });
  });

  it.each(["text/html", "image/svg+xml", "application/javascript", "text/javascript", "application/x-msdownload", "application/zip", "application/octet-stream", "text/vcard; charset=utf-8", "TEXT/PLAIN", "__proto__", "toString", "constructor"])("an explicit type outside the list: %s", (type) => {
    expect(refused({ name: "a.txt", type, body: "x" })).toMatch(/type/i);
  });

  it("a name that does not end with the extension of its explicit type, or is only the extension", () => {
    expect(refused({ name: "a.txt", type: "text/vcard", body: "x" })).toMatch(/\.vcf/);
    expect(refused({ name: ".txt", type: "text/plain", body: "x" })).toBeTruthy();
    expect(refused({ name: "txt", type: "text/plain", body: "x" })).toBeTruthy();
  });

  it("a body that is empty or neither text nor bytes", () => {
    expect(refused({ name: "a.txt", body: "" })).toMatch(/empty/);
    expect(refused({ name: "a.txt", body: new Uint8Array(0) })).toMatch(/empty/);
    for (const body of [1, null, undefined, {}, [1, 2], new Uint16Array(2), new ArrayBuffer(4)]) expect(refused({ name: "a.txt", body })).toMatch(/string or Uint8Array/);
  });

  it("a name or a type that is not a string", () => {
    for (const name of [1, null, undefined, ["a.txt"], {}]) expect(refused({ name, body: "x" })).toMatch(/string/);
    expect(refused({ name: "a.txt", type: 5, body: "x" })).toMatch(/string/);
  });

  it("no type on the list can name a file the desktop would run or render", () => {
    for (const [type, known] of Object.entries(SAVE_FILE_TYPES)) {
      expect(type).toMatch(/^(?:text\/(?:plain|vcard|markdown)|application\/json)$/);
      expect(known.extension).toMatch(/^\.(?:txt|vcf|md|json)$/);
    }
  });
});

describe("file size label", () => {
  it.each([[1, "1 byte"], [999, "999 bytes"], [1000, "1 KB"], [12_345, "12 KB"], [999_499, "999 KB"], [999_500, "1.0 MB"], [1_000_000, "1.0 MB"], [1_500_000, "1.5 MB"]])("%d is %s", (bytes, label) => {
    expect(fileSizeLabel(bytes)).toBe(label);
  });
});

describe("file.save in the app's client module", () => {
  it("resolves BAD_REQUEST, never throws, for options that cannot be read or are not { type }", async () => {
    const hostile = new Proxy({}, { ownKeys: () => { throw new Error("boom"); }, get: () => { throw new Error("boom"); } });
    for (const options of [hostile, "text/plain", ["type"], { type: "text/plain", extra: 1 }, { type: 5 }]) {
      await expect(file.save("a.txt", "x", options)).resolves.toMatchObject({ ok: false, error: { code: "BAD_REQUEST" } });
    }
    await expect(file.save(5, "x")).resolves.toMatchObject({ ok: false, error: { code: "BAD_REQUEST" } });
    await expect(file.save("a.txt", 5)).resolves.toMatchObject({ ok: false, error: { code: "BAD_REQUEST" } });
  });
});
