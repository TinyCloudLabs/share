/**
 * Text drawn on each page of a Chromium `page.pdf()` document, for print
 * regression checks without a PDF library. Handles what Chromium emits:
 * Flate-compressed content streams, Type0 fonts with Identity-H encoding and
 * ToUnicode CMaps, and hex strings shown with Tj/TJ. Anything else (literal
 * strings, text inside form XObjects, fonts without ToUnicode) yields no
 * text, so a check for expected words fails rather than passing vacuously.
 */
import { inflateSync } from "node:zlib";

function readObjects(pdf) {
  const objects = new Map();
  const source = pdf.toString("latin1");
  const pattern = /(\d+) 0 obj\b([\s\S]*?)endobj/g;
  for (const match of source.matchAll(pattern)) {
    const body = match[2];
    const streamAt = body.indexOf("stream");
    const dict = streamAt === -1 ? body : body.slice(0, streamAt);
    let stream;
    if (streamAt !== -1) {
      const start = match.index + match[0].indexOf(body) + streamAt + "stream".length;
      const dataStart = pdf[start] === 0x0d ? start + 2 : start + 1;
      const length = Number(/\/Length (\d+)/.exec(dict)?.[1]);
      const raw = pdf.subarray(dataStart, dataStart + length);
      stream = /\/FlateDecode/.test(dict) ? inflateSync(raw) : raw;
    }
    objects.set(Number(match[1]), { dict, stream });
  }
  return objects;
}

/** ToUnicode CMap → Map of hex code → text. */
function readCMap(source) {
  const map = new Map();
  const hexText = (hex) => String.fromCharCode(...(hex.match(/.{4}/g) ?? []).map((unit) => Number.parseInt(unit, 16)));
  for (const block of source.matchAll(/beginbfchar([\s\S]*?)endbfchar/g)) {
    for (const [, code, text] of block[1].matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/g)) map.set(code.toUpperCase(), hexText(text));
  }
  for (const block of source.matchAll(/beginbfrange([\s\S]*?)endbfrange/g)) {
    for (const [, low, high, text] of block[1].matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/g)) {
      const first = Number.parseInt(text, 16);
      for (let code = Number.parseInt(low, 16); code <= Number.parseInt(high, 16); code += 1) {
        map.set(code.toString(16).toUpperCase().padStart(low.length, "0"), String.fromCharCode(first + code - Number.parseInt(low, 16)));
      }
    }
  }
  return map;
}

/**
 * Text per page, in content order; each text object (BT…ET) on its own line,
 * NFKC-normalized. Accepts a Buffer or the Uint8Array page.pdf() returns.
 */
export function pdfPageTexts(pdf) {
  const objects = readObjects(Buffer.from(pdf.buffer, pdf.byteOffset, pdf.byteLength));
  const cmaps = new Map();
  const cmapFor = (fontRef) => {
    if (!cmaps.has(fontRef)) {
      const ref = /\/ToUnicode (\d+) 0 R/.exec(objects.get(fontRef)?.dict ?? "")?.[1];
      cmaps.set(fontRef, ref === undefined ? new Map() : readCMap(objects.get(Number(ref)).stream.toString("latin1")));
    }
    return cmaps.get(fontRef);
  };
  const pages = [];
  for (const { dict } of objects.values()) {
    if (!/\/Type \/Page\b/.test(dict)) continue;
    const fonts = new Map();
    const fontDict = /\/Font <<([^>]*)>>/.exec(dict)?.[1] ?? "";
    for (const [, name, ref] of fontDict.matchAll(/\/(\S+) (\d+) 0 R/g)) fonts.set(name, Number(ref));
    const contents = /\/Contents (\[[^\]]*\]|\d+ 0 R)/.exec(dict)?.[1] ?? "";
    let text = "";
    for (const [, ref] of contents.matchAll(/(\d+) 0 R/g)) {
      const content = objects.get(Number(ref)).stream.toString("latin1");
      let cmap = new Map();
      for (const [token, fontName, hex] of content.matchAll(/\/(\S+) [\d.]+ Tf|<([0-9A-Fa-f]*)>|\bET\b/g)) {
        if (token.endsWith("Tf")) cmap = cmapFor(fonts.get(fontName));
        else if (token === "ET") text += "\n";
        else for (const code of hex.toUpperCase().match(/.{4}/g) ?? []) text += cmap.get(code) ?? "";
      }
    }
    // NFKC folds the ligature glyphs Chromium emits (ﬁ, ﬂ, ﬀ) to plain letters.
    pages.push(text.normalize("NFKC"));
  }
  return pages;
}
